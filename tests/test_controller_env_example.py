""".env.controller.example: the controller-role environment template for compose.controller.yaml (#854)."""
import json
import re
import subprocess
from pathlib import Path

import pytest

from tests.test_compose_roles import _compose, _service_block

ROOT = Path(__file__).resolve().parents[1]

CONTROLLER_ENV_EXAMPLE = ".env.controller.example"
CONTROLLER_FILES = ("compose.controller.yaml", "compose.controller.gcp.yaml")
# Read only by compose.worker.yaml / the bundled worker, or by native worker processes.
WORKER_ONLY_KEYS = ("MRPATCHY_WORKER_ID", "MRPATCHY_WORKER_MEM_LIMIT", "MRPATCHY_WORKER_STOP_GRACE_PERIOD",
                    "MRPATCHY_JOB_CONCURRENCY", "MRPATCHY_POLL_CONCURRENCY", "MRPATCHY_AI_CONCURRENCY",
                    "MRPATCHY_CONTROLLER_DATA_VOLUME", "MRPATCHY_REQUIRE_CONTROLLER_STATE")
PLACEHOLDERS = ("ADMIN_PASSWORD", "DOMAIN", "PUBLIC_URL")
VARIABLE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)")


def _example_keys(name=CONTROLLER_ENV_EXAMPLE):
    """Keys an example sets (``KEY=``) and documents commented out (``# KEY=``)."""
    set_keys, documented = {}, set()
    for line in (ROOT / name).read_text().splitlines():
        match = re.match(r"^(#\s*)?([A-Z][A-Z0-9_]*)=(.*)$", line)
        if match:
            documented.add(match.group(2))
            if not match.group(1):
                set_keys[match.group(2)] = match.group(3)
    return set_keys, documented


def _controller_sources():
    """Text the controller role interpolates: the extended compose.yaml services and the role files."""
    texts = [_service_block("compose.yaml", name) for name in ("app", "caddy")]
    texts += [(ROOT / path).read_text() for path in CONTROLLER_FILES if (ROOT / path).exists()]
    return texts


def _controller_variables():
    return {name for text in _controller_sources() for name in VARIABLE.findall(text)}


def _controller_defaults():
    defaults = {}
    for text in _controller_sources():
        defaults.update(re.findall(r"\$\{([A-Z][A-Z0-9_]*):-([^}$]*)\}", text))
    return defaults


def test_controller_env_example_documents_every_controller_variable():
    _, documented = _example_keys()
    variables = _controller_variables()
    assert {"ADMIN_PASSWORD", "DATABASE_URL", "CONTROL_SUBNET", "MRPATCHY_EXPECTED_WORKER_IDS"} <= variables
    assert variables - documented == set()


def test_controller_env_example_values_match_env_example_or_compose_defaults():
    set_keys, _ = _example_keys()
    complete, _ = _example_keys(".env.example")
    defaults = _controller_defaults()
    for key in PLACEHOLDERS:
        assert set_keys[key] == complete[key], key
    for key, value in set_keys.items():
        if key in PLACEHOLDERS:
            continue
        expected = complete.get(key, defaults.get(key))
        assert expected is not None, f"{key} is not a controller setting"
        assert value == expected, key


def test_controller_env_example_has_no_worker_only_settings_or_credentials():
    set_keys, documented = _example_keys()
    assert documented.isdisjoint(WORKER_ONLY_KEYS), documented & set(WORKER_ONLY_KEYS)
    # Role files never assign fixed worker IDs; listing IDs here would report them as missing workers.
    assert set_keys.get("MRPATCHY_EXPECTED_WORKER_IDS") == ""
    text = (ROOT / CONTROLLER_ENV_EXAMPLE).read_text()
    assert "BEGIN" not in text and "PRIVATE KEY" not in text
    assert "replace-with" in set_keys["ADMIN_PASSWORD"]


def _render(env_file, files=("compose.controller.yaml",), env=None):
    cmd = ["docker", "compose", "-p", "mrpatchy", "--env-file", str(ROOT / env_file)]
    for name in files:
        cmd += ["-f", str(ROOT / name)]
    return subprocess.run(cmd + ["config", "--format", "json"], capture_output=True, text=True, cwd=ROOT,
                          env={"PATH": "/usr/bin:/bin:/usr/local/bin", **(env or {})})


def test_controller_env_example_renders_like_the_complete_env_example():
    _compose()
    with_example = _render(CONTROLLER_ENV_EXAMPLE)
    assert with_example.returncode == 0, with_example.stderr
    baseline = _render(".env.example")
    assert baseline.returncode == 0, baseline.stderr
    rendered = json.loads(with_example.stdout)
    assert rendered == json.loads(baseline.stdout)
    assert set(rendered["services"]) == {"app", "caddy"}


def test_compose_reports_exactly_the_variables_the_test_derives():
    _compose()
    cmd = ["docker", "compose", "-p", "mrpatchy", "--env-file", str(ROOT / CONTROLLER_ENV_EXAMPLE),
           "-f", str(ROOT / "compose.controller.yaml"), "config", "--variables", "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, env={"PATH": "/usr/bin:/bin:/usr/local/bin"})
    if result.returncode and "variables" in result.stderr:
        pytest.skip("this Docker Compose version has no config --variables")
    if result.returncode and "${" in result.stderr:
        # Some Compose releases cannot parse nested defaults such as ${HTTP_BIND_IP:-${BIND_IP:-0.0.0.0}}
        # in --variables mode, although they interpolate them correctly when rendering. Require the real
        # render to succeed; test_every_controller_interpolation_uses_the_derived_syntax still pins the set.
        rendered = _render(CONTROLLER_ENV_EXAMPLE)
        assert rendered.returncode == 0, rendered.stderr
        pytest.skip("this Docker Compose version's config --variables cannot parse nested defaults")
    assert result.returncode == 0, result.stderr
    derived = {name for text in _controller_sources()[:2] + [(ROOT / "compose.controller.yaml").read_text()]
               for name in VARIABLE.findall(text)}
    assert set(json.loads(result.stdout)) == derived


def test_every_controller_interpolation_uses_the_derived_syntax():
    """Compose-independent check: every ``$`` the controller role reads is ``$$`` or ``${NAME...}``.

    With no bare ``$NAME`` references, the ``${NAME`` names VARIABLE extracts are exactly the
    variables Compose interpolates, even where ``config --variables`` is unavailable.
    """
    texts = _controller_sources() + [(ROOT / "compose.controller.yaml").read_text()]
    for text in texts:
        stripped = text.replace("$$", "")
        assert re.findall(r"\$(?!\{[A-Z][A-Z0-9_]*)", stripped) == [], "unexpected interpolation syntax"
    assert {"HTTP_BIND_IP", "BIND_IP"} <= _controller_variables() | {
        name for text in texts for name in VARIABLE.findall(text)}


def test_controller_env_example_renders_with_the_gcp_controller_overlay():
    if not (ROOT / "compose.controller.gcp.yaml").exists():
        pytest.skip("compose.controller.gcp.yaml is not present")
    _compose()
    result = _render(CONTROLLER_ENV_EXAMPLE, ("compose.controller.yaml", "compose.controller.gcp.yaml"),
                     {"GCP_PROJECT": "ci-project", "GCP_ZONE": "us-central1-a"})
    assert result.returncode == 0, result.stderr
    assert set(json.loads(result.stdout)["services"]) == {"app", "caddy"}
