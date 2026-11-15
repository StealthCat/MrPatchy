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


EXPECTED_ENV = {"MRPATCHY_EXPECTED_WORKER_IDS": "w1,w2", "MRPATCHY_EXPECTED_CONTROLLER_IDS": "c1"}


def _expected_env(service):
    env = service.get("environment", {})
    return {key: env.get(key) for key in EXPECTED_ENV}


def test_expected_inventory_reaches_the_coordinator_tick_in_workers():
    # The app sets DISABLE_SCHEDULER, so expected-worker and expected-controller notifications are
    # published only from a worker's coordinator tick; the variables must reach it (#773).
    _compose()
    env = {"ADMIN_PASSWORD": "x", "MRPATCHY_CONTROLLER_DATA_VOLUME": "mrpatchy_app-data", **EXPECTED_ENV}
    full = json.loads(_config(["compose.yaml"], "mrpatchy", env).stdout)
    controller = json.loads(_config(["compose.controller.yaml"], "mrpatchy", env).stdout)
    worker = json.loads(_config(["compose.worker.yaml"], "mrpatchy-workers", env).stdout)
    assert full["services"]["app"]["environment"]["DISABLE_SCHEDULER"] == "1"
    for service in (full["services"]["app"], full["services"]["worker"],
                    controller["services"]["app"], worker["services"]["worker"]):
        assert _expected_env(service) == EXPECTED_ENV
    unset = json.loads(_config(["compose.yaml"], "mrpatchy", {"ADMIN_PASSWORD": "x"}).stdout)
    for name in ("app", "worker"):
        assert _expected_env(unset["services"][name]) == dict.fromkeys(EXPECTED_ENV, "")


# GCP runtime overlays for the role files (#850). compose.gcp.yaml names both app and worker,
# so each role gets an overlay carrying only its own service block.
GCP_OVERLAYS = {"compose.controller.gcp.yaml": "app", "compose.worker.gcp.yaml": "worker"}
GCP_ENV = {"GCP_PROJECT": "ci-project", "GCP_ZONE": "us-central1-a"}


@pytest.mark.parametrize("path,service", sorted(GCP_OVERLAYS.items()))
def test_gcp_role_overlay_mirrors_only_its_compose_gcp_service(path, service):
    assert _top_level_services(path) == [service]
    assert _service_block(path, service) == _service_block("compose.gcp.yaml", service)


def test_compose_gcp_overlay_adds_stray_service_to_role_files():
    # Why the role overlays exist: the combined overlay injects the other role's partial service.
    _compose()
    env = {"ADMIN_PASSWORD": "x", "MRPATCHY_CONTROLLER_DATA_VOLUME": "mrpatchy_app-data", **GCP_ENV}
    controller = _config(["compose.controller.yaml", "compose.gcp.yaml"], "mrpatchy", env)
    worker = _config(["compose.worker.yaml", "compose.gcp.yaml"], "mrpatchy-workers", env)
    for result in (controller, worker):
        assert result.returncode == 0, result.stderr
    assert "worker" in json.loads(controller.stdout)["services"]
    assert "app" in json.loads(worker.stdout)["services"]


def test_rendered_gcp_roles_match_the_complete_gcp_installation():
    _compose()
    env = {"ADMIN_PASSWORD": "x", "MRPATCHY_CONTROLLER_DATA_VOLUME": "mrpatchy_app-data", **GCP_ENV}
    results = (
        _config(["compose.yaml", "compose.gcp.yaml"], "mrpatchy", env),
        _config(["compose.controller.yaml", "compose.controller.gcp.yaml"], "mrpatchy", env),
        _config(["compose.worker.yaml", "compose.worker.gcp.yaml"], "mrpatchy-workers", env),
    )
    for result in results:
        assert result.returncode == 0, result.stderr
    full, controller, worker = (json.loads(r.stdout) for r in results)

    assert set(controller["services"]) == {"app", "caddy"}
    for name in ("app", "caddy"):
        for key in HARDENING + ("networks", "ports", "depends_on", "image", "build"):
            assert controller["services"][name].get(key) == full["services"][name].get(key), (name, key)
    assert controller["volumes"] == full["volumes"]
    assert controller["networks"] == full["networks"]

    assert set(worker["services"]) == {"worker"}
    rendered = worker["services"]["worker"]
    assert "depends_on" not in rendered and "ports" not in rendered
    for key in HARDENING + ("image", "build", "command"):
        if key == "environment":
            continue
        assert rendered.get(key) == full["services"]["worker"].get(key), key
    assert rendered["environment"] == dict(full["services"]["worker"]["environment"], MRPATCHY_WORKER_ID="")
    assert worker["volumes"]["app-data"] == {"name": "mrpatchy_app-data", "external": True}

    for service in (controller["services"]["app"], rendered):
        assert service["image"] == "mrpatchy:gcp"
        assert service["build"]["dockerfile"] == "deploy/Dockerfile.gcp"
        assert {k: service["environment"][k] for k in ("CLOUDSDK_CONFIG", "CLOUDSDK_CORE_PROJECT",
                "CLOUDSDK_COMPUTE_ZONE")} == {"CLOUDSDK_CONFIG": "/data/gcloud",
                "CLOUDSDK_CORE_PROJECT": "ci-project", "CLOUDSDK_COMPUTE_ZONE": "us-central1-a"}
    assert controller["services"]["caddy"].get("image") != "mrpatchy:gcp"


@pytest.mark.parametrize("files,project", [
    (["compose.controller.yaml", "compose.controller.gcp.yaml"], "mrpatchy"),
    (["compose.worker.yaml", "compose.worker.gcp.yaml"], "mrpatchy-workers"),
])
@pytest.mark.parametrize("missing", sorted(GCP_ENV))
def test_gcp_role_overlays_fail_closed_without_project_or_zone(files, project, missing):
    _compose()
    env = {"ADMIN_PASSWORD": "x", "MRPATCHY_CONTROLLER_DATA_VOLUME": "mrpatchy_app-data", **GCP_ENV}
    del env[missing]
    result = _config(files, project, env)
    assert result.returncode != 0
    assert "Run install-gcp.sh first" in result.stderr
