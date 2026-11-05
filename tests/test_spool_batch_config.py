import json
import time

import pytest

from app import main
from app.db import Audit, Session, Setting
from app.identity import User
from target import agent, bridge


MINIMUM = 16 * 1024
MAXIMUM = 1024 * 1024


def reset_agent(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "ROOT", tmp_path)
    monkeypatch.setattr(agent, "SPOOL_READY", set())
    monkeypatch.setattr(
        agent,
        "SPOOL_CONFIG_CACHE",
        {"identity": object(), "batch_limit_bytes": agent.DEFAULT_SPOOL_BATCH_BYTES},
    )


def write_config(tmp_path, value):
    path = tmp_path / "spool.json"
    path.write_text(json.dumps({"version": 1, "batch_limit_bytes": value}))
    path.chmod(0o600)
    return path


def test_agent_applies_persisted_cap_and_reports_effective_value(tmp_path, monkeypatch):
    reset_agent(tmp_path, monkeypatch)
    write_config(tmp_path, MINIMUM)
    processes = [{"pid": pid, "evidence": "x" * 6000} for pid in range(7)]

    agent.spool(processes, time.time())
    snapshot = agent.pending_events()

    assert snapshot["spool"]["batch_limit_bytes"] == MINIMUM
    assert all(len(json.dumps({"processes": event["processes"]}, separators=(",", ":")).encode()) <= MINIMUM for event in snapshot["events"])
    assert [item["pid"] for event in snapshot["events"] for item in event["processes"]] == list(range(7))
    agent.SPOOL_CONFIG_CACHE = {"identity": object(), "batch_limit_bytes": agent.DEFAULT_SPOOL_BATCH_BYTES}
    assert agent.spool_batch_limit() == MINIMUM


def test_oversize_observation_is_counted_without_losing_eligible_sibling(tmp_path, monkeypatch):
    reset_agent(tmp_path, monkeypatch)
    write_config(tmp_path, MINIMUM)

    agent.spool([{"pid": 1, "evidence": "x" * MINIMUM}, {"pid": 2}], time.time())
    snapshot = agent.pending_events()

    assert [item["pid"] for item in snapshot["events"][0]["processes"]] == [2]
    assert snapshot["spool"]["drop_reasons"]["oversize"] == {"batches": 1, "observations": 1}
    assert snapshot["spool"]["dropped_observations"] == 1


@pytest.mark.parametrize(
    "contents,mode",
    [
        ({"version": 1, "batch_limit_bytes": MINIMUM - 1}, 0o600),
        ({"version": 1, "batch_limit_bytes": True}, 0o600),
        ({"version": 2, "batch_limit_bytes": MINIMUM}, 0o600),
        ({"version": 1, "batch_limit_bytes": MINIMUM}, 0o644),
    ],
)
def test_agent_rejects_malformed_or_unsafe_configuration(tmp_path, monkeypatch, contents, mode):
    reset_agent(tmp_path, monkeypatch)
    path = tmp_path / "spool.json"
    path.write_text(json.dumps(contents))
    path.chmod(mode)
    with pytest.raises(ValueError, match="spool configuration|spool batch limit"):
        agent.spool_batch_limit()


def test_bridge_persists_validated_configuration_before_restart(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(bridge, "ROOT", tmp_path)
    monkeypatch.setattr(bridge, "spool_service_active", lambda: True, raising=False)
    monkeypatch.setattr(bridge, "run", lambda command, **kwargs: calls.append(command) or "")

    result = bridge.handle({"action": "spool-config", "batch_limit_bytes": 32 * 1024})

    assert result == {"configured": True, "version": 1, "batch_limit_bytes": 32 * 1024}
    assert json.loads((tmp_path / "spool.json").read_text()) == {"version": 1, "batch_limit_bytes": 32 * 1024}
    assert (tmp_path / "spool.json").stat().st_mode & 0o777 == 0o600
    assert calls == [["systemctl", "restart", "mrpatchy-agent"]]
    assert bridge.handle({"action": "spool-config-status"}) == {
        "version": 1, "batch_limit_bytes": 32 * 1024, "active": True,
    }
    assert len(calls) == 1


@pytest.mark.parametrize("previous_cap,was_active", [(None, False), (256 * 1024, True)])
def test_restart_failure_restores_previous_config_and_service(tmp_path, monkeypatch, previous_cap, was_active):
    path = tmp_path / "spool.json"
    if previous_cap is not None:
        write_config(tmp_path, previous_cap)
    previous = path.read_bytes() if path.exists() else None
    monkeypatch.setattr(bridge, "ROOT", tmp_path)
    monkeypatch.setattr(bridge, "spool_service_active", lambda: was_active, raising=False)
    calls = []

    def service(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            assert json.loads(path.read_bytes())["batch_limit_bytes"] == MAXIMUM
            raise RuntimeError("restart failed")
        assert (path.read_bytes() if path.exists() else None) == previous

    monkeypatch.setattr(bridge, "run", service)
    with pytest.raises(RuntimeError, match="previous configuration and service state restored"):
        bridge.handle({"action": "spool-config", "batch_limit_bytes": MAXIMUM})

    assert calls == [
        ["systemctl", "restart", "mrpatchy-agent"],
        ["systemctl", "restart" if was_active else "stop", "mrpatchy-agent"],
    ]
    assert (path.read_bytes() if path.exists() else None) == previous


def test_restart_failure_reports_unverified_service_recovery(tmp_path, monkeypatch):
    path = write_config(tmp_path, MINIMUM)
    monkeypatch.setattr(bridge, "ROOT", tmp_path)
    monkeypatch.setattr(bridge, "spool_service_active", lambda: True, raising=False)

    def service(command, **kwargs):
        raise TimeoutError("private service diagnostics")

    monkeypatch.setattr(bridge, "run", service)
    with pytest.raises(RuntimeError, match="recovery could not be verified"):
        bridge.handle({"action": "spool-config", "batch_limit_bytes": MAXIMUM})
    assert json.loads(path.read_bytes())["batch_limit_bytes"] == MINIMUM


@pytest.mark.parametrize("value", [True, "32768", MINIMUM - 1, MAXIMUM + 1])
def test_bridge_rejects_invalid_configuration_without_writing(tmp_path, monkeypatch, value):
    calls = []
    monkeypatch.setattr(bridge, "ROOT", tmp_path)
    monkeypatch.setattr(bridge, "run", lambda command, **kwargs: calls.append(command) or "")
    with pytest.raises(ValueError, match="Spool batch limit"):
        bridge.handle({"action": "spool-config", "batch_limit_bytes": value})
    assert not (tmp_path / "spool.json").exists()
    assert calls == []


def create_host(admin):
    response = admin.post("/api/hosts", json={"name": "Spool target", "address": "192.0.2.44"})
    assert response.status_code == 200
    return response.json()["id"]


def test_admin_api_confirms_persists_and_audits_target_setting(admin, monkeypatch):
    host_id = create_host(admin)
    calls = []

    def remote(host, payload, **kwargs):
        calls.append((host.id, payload, kwargs))
        return {"configured": True, "version": 1, "batch_limit_bytes": payload["batch_limit_bytes"]}

    monkeypatch.setattr(main.ssh, "call", remote)
    response = admin.put(f"/api/operations/{host_id}/spool", json={"batch_limit_bytes": 32 * 1024})
    assert response.status_code == 200
    assert response.json() == {"configured": True, "version": 1, "batch_limit_bytes": 32 * 1024}
    assert calls == [(host_id, {"action": "spool-config", "batch_limit_bytes": 32 * 1024}, {"lifecycle_blocking": False})]
    with Session() as session:
        assert session.get(Setting, "spool:" + host_id).value == {"version": 1, "batch_limit_bytes": 32 * 1024}
        record = session.query(Audit).filter_by(action="configure agent spool").one()
        assert record.detail == host_id + " batch_limit_bytes=32768"


def test_admin_api_rejects_invalid_values_roles_and_unconfirmed_receipts(admin, monkeypatch):
    host_id = create_host(admin)
    calls = []
    monkeypatch.setattr(main.ssh, "call", lambda *args, **kwargs: calls.append((args, kwargs)) or {"configured": False})

    for value in (True, "32768", MINIMUM - 1, MAXIMUM + 1):
        assert admin.put(f"/api/operations/{host_id}/spool", json={"batch_limit_bytes": value}).status_code == 422
    assert calls == []

    assert admin.put(f"/api/operations/{host_id}/spool", json={"batch_limit_bytes": MINIMUM}).status_code == 502
    with Session() as session:
        assert session.get(Setting, "spool:" + host_id) is None
        session.get(User, "admin").role = "operator"
        session.commit()
    assert admin.put(f"/api/operations/{host_id}/spool", json={"batch_limit_bytes": MINIMUM}).status_code == 403
    with Session() as session:
        session.get(User, "admin").role = "viewer"
        session.commit()
    assert admin.put(f"/api/operations/{host_id}/spool", json={"batch_limit_bytes": MINIMUM}).status_code == 403


@pytest.mark.parametrize("observed,active,expected_status", [
    (MINIMUM, True, 200),
    (MINIMUM, False, 502),
    (MAXIMUM, True, 502),
    (None, None, 502),
])
def test_lost_spool_receipt_uses_readback_without_replay(admin, monkeypatch, observed, active, expected_status):
    host_id = create_host(admin)
    calls = []

    def remote(host, payload, **kwargs):
        calls.append(payload)
        if len(calls) == 1 or observed is None:
            raise main.ssh.RemoteProtocolError("truncated SSH reply")
        return {"version": 1, "batch_limit_bytes": observed, "active": active}

    monkeypatch.setattr(main.ssh, "call", remote)
    response = admin.put(f"/api/operations/{host_id}/spool", json={"batch_limit_bytes": MINIMUM})
    assert response.status_code == expected_status
    assert calls == [{"action": "spool-config", "batch_limit_bytes": MINIMUM}, {"action": "spool-config-status"}]
    with Session() as session:
        setting = session.get(Setting, "spool:" + host_id)
        if expected_status == 200:
            assert setting.value == {"version": 1, "batch_limit_bytes": MINIMUM}
            assert "verified by readback" in session.query(Audit).filter_by(action="configure agent spool").one().detail
        else:
            assert setting is None
            assert session.query(Audit).filter_by(action="configure agent spool failed").one().detail.startswith(host_id)


def test_definite_target_rejection_preserves_controller_setting(admin, monkeypatch):
    host_id = create_host(admin)
    with Session() as session:
        session.add(Setting(key="spool:" + host_id, value={"version": 1, "batch_limit_bytes": MAXIMUM}))
        session.commit()

    def remote(host, payload, **kwargs):
        if payload["action"] == "spool-config":
            raise main.ssh.RemoteFailure("private service diagnostics")
        return {"version": 1, "batch_limit_bytes": MINIMUM, "active": True}

    monkeypatch.setattr(main.ssh, "call", remote)
    response = admin.put(f"/api/operations/{host_id}/spool", json={"batch_limit_bytes": MINIMUM})
    assert response.status_code == 502
    assert "private service diagnostics" not in response.text
    with Session() as session:
        assert session.get(Setting, "spool:" + host_id).value["batch_limit_bytes"] == MAXIMUM
        record = session.query(Audit).filter_by(action="configure agent spool failed").one()
        assert f"observed_batch_limit_bytes={MINIMUM}" in record.detail
        assert "private service diagnostics" not in record.detail
