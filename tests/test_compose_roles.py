"""Role-split Compose files: compose.controller.yaml (app + Caddy) and compose.worker.yaml
(workers only). compose.yaml stays the complete single-machine installation."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKER_ENV_DIFF = (
    "      # Set only for a single instance; replicas default to distinct persistent generated identities.\n"
    "      MRPATCHY_WORKER_ID: ${MRPATCHY_WORKER_ID:-}\n",
    "      # Always empty here so replicas never share one ID, even when .env sets one. Each replica\n"
    "      # instead claims a distinct generated ID that persists on the app-data volume across upgrades.\n"
    '      MRPATCHY_WORKER_ID: ""\n',
)
APP_DEPENDENCY = "    depends_on:\n      app:\n        condition: service_healthy\n"


def _service_block(path, name):
    text = (ROOT / path).read_text()
    match = re.search(rf"^  {name}:\n(.*?)(?=^  \S|^\S|\Z)", text, re.S | re.M)
    assert match, f"{path} must define {name}"
    return match.group(0)


def _top_level_services(path):
    text = (ROOT / path).read_text()
    section = re.search(r"^services:\n(.*?)(?=^\S|\Z)", text, re.S | re.M)
    return re.findall(r"^  ([A-Za-z0-9_-]+):\s*$", section.group(1), re.M)


def test_worker_file_mirrors_compose_worker_without_local_app_dependency():
    base = _service_block("compose.yaml", "worker")
    assert APP_DEPENDENCY in base
    assert WORKER_ENV_DIFF[0] in base
    expected = base.replace(APP_DEPENDENCY, "").replace(*WORKER_ENV_DIFF)
    assert _service_block("compose.worker.yaml", "worker") == expected


def test_worker_file_has_no_web_tls_or_fixed_names():
    text = (ROOT / "compose.worker.yaml").read_text()
    assert _top_level_services("compose.worker.yaml") == ["worker"]
    for forbidden in ("depends_on", "ports:", "tls-config", "container_name", "caddy", "ADMIN_PASSWORD"):
        assert forbidden not in text, forbidden
    assert 'MRPATCHY_REQUIRE_CONTROLLER_STATE: "1"' in text
    volume = re.search(r"^  app-data:\n((?:    .*\n)+)", text, re.M).group(1)
    assert "external: true" in volume
    assert "${MRPATCHY_CONTROLLER_DATA_VOLUME:?" in volume


def test_controller_file_extends_only_app_and_caddy():
    text = (ROOT / "compose.controller.yaml").read_text()
    assert _top_level_services("compose.controller.yaml") == ["app", "caddy"]
    for name in ("app", "caddy"):
        block = _service_block("compose.controller.yaml", name)
        assert block.strip().splitlines()[1:] == [
            f"    extends: {{file: compose.yaml, service: {name}}}"
        ], name
    assert "worker" not in re.sub(r"^#.*$", "", text, flags=re.M)


def _compose():
    if not shutil.which("docker"):
        pytest.skip("Docker is not installed")
    probe = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
    if probe.returncode:
        pytest.skip("Docker Compose is not available")


def _config(files, project, env):
    cmd = ["docker", "compose", "-p", project]
    for name in files:
        cmd += ["-f", str(ROOT / name)]
    return subprocess.run(
        cmd + ["config", "--format", "json"],
        capture_output=True, text=True, cwd=ROOT,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", **env},
    )


HARDENING = ("cap_add", "cap_drop", "security_opt", "read_only", "tmpfs", "pids_limit",
             "mem_limit", "healthcheck", "environment", "volumes", "restart")


def test_rendered_roles_keep_compose_hardening():
    _compose()
    env = {"ADMIN_PASSWORD": "x", "MRPATCHY_CONTROLLER_DATA_VOLUME": "mrpatchy_app-data"}
    full = _config(["compose.yaml"], "mrpatchy", env)
    controller = _config(["compose.controller.yaml"], "mrpatchy", env)
    worker = _config(["compose.worker.yaml"], "mrpatchy-workers", env)
    for result in (full, controller, worker):
        assert result.returncode == 0, result.stderr
    full, controller, worker = (json.loads(r.stdout) for r in (full, controller, worker))

    assert set(controller["services"]) == {"app", "caddy"}
    for name in ("app", "caddy"):
        for key in HARDENING + ("networks", "ports", "depends_on"):
            assert controller["services"][name].get(key) == full["services"][name].get(key), (name, key)
    assert controller["volumes"] == full["volumes"]
    assert controller["networks"] == full["networks"]

    assert set(worker["services"]) == {"worker"}
    rendered = worker["services"]["worker"]
    assert "depends_on" not in rendered and "ports" not in rendered
    for key in HARDENING:
        if key == "environment":
            continue
        assert rendered.get(key) == full["services"]["worker"].get(key), key
    expected_env = dict(full["services"]["worker"]["environment"], MRPATCHY_WORKER_ID="")
    assert rendered["environment"] == expected_env
    assert worker["volumes"]["app-data"] == {"name": "mrpatchy_app-data", "external": True}


def test_worker_refuses_to_render_without_controller_volume():
    _compose()
    result = _config(["compose.worker.yaml"], "mrpatchy-workers", {})
    assert result.returncode != 0
    assert "MRPATCHY_CONTROLLER_DATA_VOLUME" in result.stderr


def test_worker_renders_without_controller_only_variables():
    _compose()
    result = _config(["compose.worker.yaml"], "mrpatchy-workers",
                     {"MRPATCHY_CONTROLLER_DATA_VOLUME": "mrpatchy_app-data"})
    assert result.returncode == 0, result.stderr
