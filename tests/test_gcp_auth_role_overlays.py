"""Role-specific WIF credential overlays written by install-gcp.sh (#866)."""
import json
import subprocess

import pytest

from tests.test_compose_roles import ROOT, _compose
from tests.test_gcp_installer import installer  # noqa: F401  (pytest fixture)

ROLE_AUTH = {"compose.controller.gcp-auth.json": "app", "compose.worker.gcp-auth.json": "worker"}
WIF_CONFIG = {"type": "external_account", "credential_source": {"file": "/gcp/token"}}


def _credentials(root):
    directory = root.parent / (root.name + "-identity")
    directory.mkdir()
    (directory / "credentials.json").write_text(json.dumps(WIF_CONFIG))
    return directory


def test_installer_writes_one_service_overlay_per_role(installer):  # noqa: F811
    root, run = installer
    directory = _credentials(root)
    result = run("--public-url", "https://patchy.example.test", "--credential-dir", str(directory))
    assert result.returncode == 0, result.stderr
    combined = json.loads((root / "compose.gcp-auth.json").read_text())
    for name, service in ROLE_AUTH.items():
        path = root / name
        assert path.stat().st_mode & 0o777 == 0o600
        overlay = json.loads(path.read_text())
        assert overlay == {"services": {service: combined["services"][service]}}
        (mount,) = overlay["services"][service]["volumes"]
        assert mount == {"type": "bind", "source": str(directory.resolve()), "target": "/gcp", "read_only": True}
    # The complete installation path is unchanged: COMPOSE_FILE still names only the combined overlay.
    assert "COMPOSE_FILE=compose.yaml:compose.gcp.yaml:compose.gcp-auth.json\n" in (root / ".env").read_text()


def test_installer_writes_no_role_overlays_without_wif(installer):  # noqa: F811
    root, run = installer
    assert run("--public-url", "https://patchy.example.test").returncode == 0
    assert not any((root / name).exists() for name in ROLE_AUTH)


@pytest.mark.parametrize("name", sorted(ROLE_AUTH))
def test_installer_refuses_symlinked_role_overlay_before_writing(installer, name):  # noqa: F811
    root, run = installer
    directory = _credentials(root)
    target = root.parent / (root.name + "-elsewhere.json")
    target.write_text("{}")
    (root / name).symlink_to(target)
    result = run("--public-url", "https://patchy.example.test", "--credential-dir", str(directory))
    assert result.returncode != 0 and "Refusing symlink" in result.stderr
    assert target.read_text() == "{}"
    assert not (root / ".env").exists() and not (root / "compose.gcp-auth.json").exists()


def test_role_overlays_are_ignored_by_git_and_docker():
    for ignore in (".gitignore", ".dockerignore"):
        lines = (ROOT / ignore).read_text().splitlines()
        assert set(ROLE_AUTH) <= set(lines), ignore


ROLE_PAIRS = [
    (("compose.controller.yaml", "compose.controller.gcp.yaml"), "compose.controller.gcp-auth.json",
     "mrpatchy", {"app", "caddy"}),
    (("compose.worker.yaml", "compose.worker.gcp.yaml"), "compose.worker.gcp-auth.json",
     "mrpatchy-workers", {"worker"}),
]


@pytest.mark.parametrize("files,auth,project,services", ROLE_PAIRS)
def test_rendered_role_files_carry_only_their_wif_mount(installer, files, auth, project, services):  # noqa: F811
    _compose()
    root, run = installer
    directory = _credentials(root)
    assert run("--public-url", "https://patchy.example.test", "--credential-dir", str(directory)).returncode == 0
    cmd = ["docker", "compose", "-p", project]
    for name in files:
        cmd += ["-f", str(ROOT / name)]
    cmd += ["-f", str(root / auth), "config", "--format", "json"]
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "ADMIN_PASSWORD": "x", "GCP_PROJECT": "ci-project",
           "GCP_ZONE": "us-central1-a", "MRPATCHY_CONTROLLER_DATA_VOLUME": "mrpatchy_app-data"}
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, env=env)
    assert result.returncode == 0, result.stderr
    rendered = json.loads(result.stdout)["services"]
    assert set(rendered) == services
    for name, service in rendered.items():
        mounts = [item for item in service.get("volumes", []) if item.get("target") == "/gcp"]
        if name == ROLE_AUTH[auth]:
            (mount,) = mounts
            assert mount["type"] == "bind" and mount["read_only"] is True
            assert mount["source"] == str(directory.resolve())
        else:
            assert mounts == []
