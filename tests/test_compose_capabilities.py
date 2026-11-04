import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {
    "app": {"CHOWN", "SETUID", "SETGID"},
    "worker": {"CHOWN", "SETUID", "SETGID"},
    "caddy": {"NET_BIND_SERVICE", "DAC_READ_SEARCH"},
}


def _services():
    """Split compose.yaml into per-service text blocks without a YAML dependency."""
    text = (ROOT / "compose.yaml").read_text()
    section = re.search(r"^services:\n(.*?)(?=^\S)", text, re.S | re.M)
    body = section.group(1)
    blocks = re.split(r"^  (?=[A-Za-z0-9_-]+:\s*$)", body, flags=re.M)
    services = {}
    for block in filter(None, blocks):
        name, _, rest = block.partition(":")
        services[name.strip()] = rest
    return services


def _flow_list(block, key):
    match = re.search(rf"^    {key}: \[([^\]]*)\]\s*$", block, re.M)
    assert match, f"{key} must be a one-line flow list"
    return [item.strip() for item in match.group(1).split(",") if item.strip()]


def test_every_service_drops_all_capabilities_and_adds_back_only_what_it_needs():
    services = _services()
    assert set(services) == set(ALLOWED)
    for name, block in services.items():
        assert _flow_list(block, "cap_drop") == ["ALL"], name
        assert set(_flow_list(block, "cap_add")) == ALLOWED[name], name
        assert "no-new-privileges:true" in _flow_list(block, "security_opt"), name
        assert not re.search(r"^    privileged:\s*true", block, re.M), name


def test_every_service_bounds_process_count():
    for name, block in _services().items():
        match = re.search(r"^    pids_limit:\s*(\d+)\s*$", block, re.M)
        assert match, f"{name} must set pids_limit"
        assert 256 <= int(match.group(1)) <= 4096, name


def test_every_service_bounds_memory_with_overridable_default():
    for name, block in _services().items():
        match = re.search(
            r"^    mem_limit:\s*\$\{MRPATCHY_[A-Z]+_MEM_LIMIT:-(\d+)([mg])\}\s*$", block, re.M
        )
        assert match, f"{name} must set an overridable mem_limit default"
        megabytes = int(match.group(1)) * (1024 if match.group(2) == "g" else 1)
        assert 256 <= megabytes <= 16384, name
