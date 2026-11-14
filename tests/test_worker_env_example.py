""".env.worker.example: the worker-role environment template for compose.worker.yaml (#852)."""
import json
import re
import subprocess
from pathlib import Path

import pytest

from tests.test_compose_roles import _compose, _config

ROOT = Path(__file__).resolve().parents[1]


WORKER_ENV_EXAMPLE = ".env.worker.example"
WORKER_FILES = ("compose.worker.yaml", "compose.worker.gcp.yaml")
CONTROLLER_ONLY_KEYS = ("ADMIN_PASSWORD", "DOMAIN", "PUBLIC_URL", "BIND_IP", "HTTP_BIND_IP", "HTTPS_BIND_IP",
                        "HTTP_PORT", "HTTPS_PORT", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET",
                        "CONTROL_SUBNET", "CADDY_CONTROL_IP", "APP_CONTROL_IP", "MRPATCHY_WORKER_ID")


def _example_keys():
    """Keys the worker example sets (``KEY=``) and documents commented out (``# KEY=``)."""
    set_keys, documented = {}, set()
    for line in (ROOT / WORKER_ENV_EXAMPLE).read_text().splitlines():
        match = re.match(r"^(#\s*)?([A-Z][A-Z0-9_]*)=(.*)$", line)
        if match:
            documented.add(match.group(2))
            if not match.group(1):
                set_keys[match.group(2)] = match.group(3)
    return set_keys, documented


def _worker_file_variables():
    names = set()
    for path in WORKER_FILES:
        if (ROOT / path).exists():
            names |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", (ROOT / path).read_text()))
    return names


def test_worker_env_example_documents_every_worker_variable():
    _, documented = _example_keys()
    variables = _worker_file_variables()
    assert "MRPATCHY_CONTROLLER_DATA_VOLUME" in variables
    assert variables - documented == set()


def test_worker_env_example_sets_compose_defaults_and_the_required_volume():
    set_keys, _ = _example_keys()
    assert set_keys["MRPATCHY_CONTROLLER_DATA_VOLUME"] == "mrpatchy_app-data"
    defaults = dict(re.findall(r"\$\{([A-Z][A-Z0-9_]*):-([^}]*)\}", (ROOT / "compose.worker.yaml").read_text()))
    for key, value in set_keys.items():
        if key in defaults:
            assert value == defaults[key], key


def test_worker_env_example_has_no_controller_only_settings_or_credentials():
    _, documented = _example_keys()
    assert documented.isdisjoint(CONTROLLER_ONLY_KEYS), documented & set(CONTROLLER_ONLY_KEYS)
    text = (ROOT / WORKER_ENV_EXAMPLE).read_text()
    assert "BEGIN" not in text and "PRIVATE KEY" not in text
    for ignore in (".gitignore", ".dockerignore"):
        assert ".env.worker" in (ROOT / ignore).read_text().splitlines(), ignore


def _config_with_env_file(files, env):
    cmd = ["docker", "compose", "-p", "mrpatchy-workers", "--env-file", str(ROOT / WORKER_ENV_EXAMPLE)]
    for name in files:
        cmd += ["-f", str(ROOT / name)]
    return subprocess.run(cmd + ["config", "--format", "json"], capture_output=True, text=True, cwd=ROOT,
                          env={"PATH": "/usr/bin:/bin:/usr/local/bin", **env})


def test_worker_env_example_renders_the_worker_role_unchanged():
    _compose()
    with_example = _config_with_env_file(["compose.worker.yaml"], {})
    assert with_example.returncode == 0, with_example.stderr
    baseline = _config(["compose.worker.yaml"], "mrpatchy-workers",
                       {"MRPATCHY_CONTROLLER_DATA_VOLUME": "mrpatchy_app-data"})
    assert baseline.returncode == 0, baseline.stderr
    assert json.loads(with_example.stdout) == json.loads(baseline.stdout)


def test_worker_env_example_renders_with_the_gcp_worker_overlay():
    if not (ROOT / "compose.worker.gcp.yaml").exists():
        pytest.skip("compose.worker.gcp.yaml is not present")
    _compose()
    result = _config_with_env_file(["compose.worker.yaml", "compose.worker.gcp.yaml"],
                                   {"GCP_PROJECT": "ci-project", "GCP_ZONE": "us-central1-a"})
    assert result.returncode == 0, result.stderr
    assert set(json.loads(result.stdout)["services"]) == {"worker"}
