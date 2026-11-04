from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {
    "app": {"CHOWN", "SETUID", "SETGID"},
    "worker": {"CHOWN", "SETUID", "SETGID"},
    "caddy": {"NET_BIND_SERVICE", "DAC_READ_SEARCH"},
}


def _services():
    return yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]


def test_every_service_drops_all_capabilities_and_adds_back_only_what_it_needs():
    services = _services()
    assert set(services) == set(ALLOWED)
    for name, service in services.items():
        assert service.get("cap_drop") == ["ALL"], name
        assert set(service.get("cap_add", [])) == ALLOWED[name], name
        assert "no-new-privileges:true" in service["security_opt"], name
        assert not service.get("privileged"), name
