"""Host-side tests also run with --noconftest; no application bootstrap needed."""
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("configure_compose", ROOT / "tools/configure_compose.py")
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


@pytest.mark.parametrize("apps,workers", [(1, 1), (3, 4), (1, 0), (3, 0), (0, 1), (0, 4), (16, 16)])
def test_layouts_preserve_role_security_and_state(apps, workers, tmp_path):
    config = tool.Config(apps=apps, workers=workers, external_data_volume="controller_app-data" if not apps else "")
    document = yaml.safe_load(tool.render(config, tmp_path / "custom.yaml"))
    base = yaml.safe_load((ROOT / "compose.yaml").read_text())
    services = document["services"]
    assert len(services) == apps + workers + bool(apps)
    for name, service in services.items():
        role = name.split("-")[0]
        for key in ("cap_drop", "cap_add", "security_opt", "read_only", "tmpfs", "pids_limit", "healthcheck"):
            assert service.get(key) == base["services"][role].get(key)
        assert set(service.get("depends_on", {})) <= services.keys()
        assert all(mount.split(":")[0] in document["volumes"] for mount in service["volumes"])
        if role == "app":
            assert service["environment"]["DISABLE_SCHEDULER"] == "1"
            assert "ipv4_address" not in service["networks"]["control"]
            assert "ports" not in service
        elif role == "worker":
            assert service["environment"]["MRPATCHY_RUNTIME_ROLE"] == "worker"
            assert service["environment"]["MRPATCHY_REQUIRE_CONTROLLER_STATE"] == "1"
            assert service["stop_grace_period"] == base["services"]["worker"]["stop_grace_period"]
            assert service["volumes"] == ["app-data:/data"]
            assert service["environment"]["MRPATCHY_WORKER_ID"] == ""
    for index in range(2, apps + 1):
        service = services[f"app-{index}"]
        assert service["depends_on"] == {tool.service_name("app", index - 1): {"condition": "service_healthy"}}
        assert service["networks"]["control"]["aliases"] == ["app"]
    if apps:
        assert services["caddy"]["depends_on"] == {tool.service_name("app", apps): {"condition": "service_healthy"}}
    else:
        assert document["volumes"] == {"app-data": {"external": True, "name": "controller_app-data"}}
        assert document["networks"] == {"management": {}}
        assert all("depends_on" not in s and "ports" not in s for s in services.values())
        assert "ADMIN_PASSWORD" not in tool.render(config, tmp_path / "custom.yaml")


def test_custom_network_ports_worker_ids_and_environment_are_consistent(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "must-not-leak")
    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://private:secret@host/db")
    config = tool.Config(apps=2, workers=3, database="mysql", worker_prefix="rack-a",
                         http_port=8080, https_port=8443, bind_ip="127.0.0.1", control_subnet="172.28.20.0/24",
                         jobs=6, polls=12, ai=8, app_memory="3g", worker_memory="6g")
    content = tool.render(config, tmp_path / "custom.yaml")
    assert "must-not-leak" not in content and "private:secret" not in content
    services = yaml.safe_load(content)["services"]
    for name in ("app", "app-2"):
        env = services[name]["environment"]
        assert env["FORWARDED_ALLOW_IPS"] == "172.28.20.2"
        assert env["HTTPS_PORT"] == "8443"
        assert env["PUBLIC_URL"] == "${PUBLIC_URL:-https://localhost:8443}"
        assert env["MRPATCHY_EXPECTED_WORKER_IDS"] == "rack-a-1,rack-a-2,rack-a-3"
    assert [services[tool.service_name("worker", i)]["environment"]["MRPATCHY_WORKER_ID"] for i in range(1, 4)] == ["rack-a-1", "rack-a-2", "rack-a-3"]
    # The coordinator tick (and its expected-worker notifications) runs in workers (#773).
    assert all(services[tool.service_name("worker", i)]["environment"]["MRPATCHY_EXPECTED_WORKER_IDS"]
               == "rack-a-1,rack-a-2,rack-a-3" for i in range(1, 4))
    assert services["worker"]["environment"]["MRPATCHY_JOB_CONCURRENCY"] == "6"
    assert services["worker"]["mem_limit"] == "6g"
    assert [port["published"] for port in services["caddy"]["ports"]] == ["8080", "8443", "8443"]
    assert all(port["host_ip"] == "127.0.0.1" for port in services["caddy"]["ports"])
    assert services["caddy"]["networks"]["control"]["ipv4_address"] == "172.28.20.2"


@pytest.mark.parametrize("runtime", ["build", "gcp", "image"])
def test_runtime_and_relocated_output(runtime, tmp_path):
    output = tmp_path / "outside.yaml"
    doc = tool.build_document(tool.Config(apps=2, workers=2, runtime=runtime, image="registry.example/patchy:tested"), output)
    for name, service in doc["services"].items():
        if name == "caddy":
            assert "@sha256:" in service["image"]
        elif runtime == "image":
            assert "build" not in service
            assert service["image"] == "registry.example/patchy:tested"
        else:
            assert (output.parent / service["build"]["context"]).resolve() == ROOT
            if runtime == "gcp":
                assert service["build"]["dockerfile"] == "deploy/Dockerfile.gcp"
                assert service["environment"]["CLOUDSDK_CONFIG"] == "/data/gcloud"
                assert "GCP_PROJECT:?" in service["environment"]["CLOUDSDK_CORE_PROJECT"]


@pytest.mark.parametrize("changes", [
    {"apps": 0, "workers": 0}, {"apps": -1}, {"workers": 17}, {"apps": True},
    {"apps": 0}, {"external_data_volume": "${bad}"}, {"project": "Bad Name"},
    {"runtime": "bad"}, {"runtime": "image"}, {"runtime": "image", "image": "${IMAGE}"},
    {"database": "postgres"}, {"http_port": 0}, {"https_port": 65536}, {"http_port": 443},
    {"bind_ip": "localhost"}, {"control_subnet": "172.30.254.0/28"},
    {"control_subnet": "::/64"}, {"jobs": 0}, {"polls": 65}, {"ai": -1},
    {"worker_prefix": "has spaces"}, {"app_memory": "-2g"}, {"worker_memory": "0m"},
])
def test_invalid_configuration_rejected(changes, tmp_path):
    with pytest.raises(ValueError):
        tool.build_document(replace(tool.Config(), **changes), tmp_path / "custom.yaml")


def test_save_requires_explicit_replacement_and_preserves_backup(tmp_path):
    output = tmp_path / "custom.yaml"
    tool.save("original", output)
    with pytest.raises(FileExistsError):
        tool.save("changed", output)
    assert output.read_text() == "original"
    tool.save("changed", output, overwrite=True)
    assert output.read_text() == "changed"
    assert (tmp_path / "custom.yaml.bak").read_text() == "original"
    with pytest.raises(FileExistsError):
        tool.save("again", output, overwrite=True)
    assert output.read_text() == "changed"


@pytest.mark.parametrize("name", ["compose.yaml", "compose.gcp.yaml", ".env"])
def test_cannot_replace_templates_or_env(name, tmp_path):
    output = tmp_path / name
    output.write_text("keep me")
    with pytest.raises(ValueError):
        tool.save("changed", output, overwrite=True, root=tmp_path)
    assert output.read_text() == "keep me"


def test_menu_invalid_choice_preview_and_worker_only_save(tmp_path, monkeypatch, capsys):
    output = tmp_path / "workers.yaml"
    answers = iter(["oops", "1", "3", "3", "existing_app-data", "6", "7", "", "y"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert tool.menu(tool.Config(), output) == 0
    doc = yaml.safe_load(output.read_text())
    assert list(doc["services"]) == ["worker", "worker-2", "worker-3"]
    transcript = capsys.readouterr().out
    assert "Choose an option" in transcript
    assert "docker compose --env-file" in transcript


def test_menu_cancel_and_declined_overwrite_leave_file_unchanged(tmp_path, monkeypatch):
    output = tmp_path / "custom.yaml"
    output.write_text("keep me")
    answers = iter(["7", "", "n", "7", "", "y", "no", "0"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert tool.menu(tool.Config(), output) == 0
    assert output.read_text() == "keep me"
    assert not output.with_name(output.name + ".bak").exists()


def test_cli_preview_and_invalid_input_do_not_write(tmp_path, capsys):
    output = tmp_path / "custom.yaml"
    assert tool.main(["--print", "--apps", "2", "--workers", "3", "--output", str(output)]) == 0
    assert len(yaml.safe_load(capsys.readouterr().out)["services"]) == 6
    assert not output.exists()
    assert tool.main(["--non-interactive", "--apps", "0", "--output", str(output)]) == 2
    assert not output.exists()


def test_eof_exits_cleanly(tmp_path, monkeypatch):
    def eof(_):
        raise EOFError
    monkeypatch.setattr("builtins.input", eof)
    assert tool.main(["--output", str(tmp_path / "custom.yaml")]) == 130


@pytest.mark.parametrize("apps,workers", [(2, 3), (2, 0), (0, 3)])
@pytest.mark.parametrize("runtime", ["build", "gcp", "image"])
def test_docker_compose_accepts_generated_layouts(apps, workers, runtime, tmp_path):
    docker = shutil.which("docker")
    standalone = shutil.which("docker-compose")
    if not docker and not standalone:
        pytest.skip("Docker CLI not installed; CI validates with Docker Compose")
    command = [docker, "compose"] if docker else [standalone]
    output = tmp_path / "custom.yaml"
    config = tool.Config(apps=apps, workers=workers, runtime=runtime, image="mrpatchy:test",
                         external_data_volume="existing_app-data", worker_prefix="ci")
    tool.save(tool.render(config, output), output)
    env = os.environ | {"ADMIN_PASSWORD": "disposable-config-test", "GCP_PROJECT": "ci-project", "GCP_ZONE": "us-central1-a"}
    result = subprocess.run(command + ["--env-file", str(ROOT / ".env.example"), "-f", str(output), "config", "--format", "json"],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout)
    assert len(parsed["services"]) == apps + workers + bool(apps)
