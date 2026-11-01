"""Agent spool byte accounting, eBPF hash cache and capacity behaviour (#186)."""
import sqlite3
import time

from target import agent


def true_totals(path):
    db = sqlite3.connect(path)
    try:
        return db.execute("SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0),count(*) FROM events").fetchone()
    finally:
        db.close()


def test_running_totals_match_table_through_spool_ack_and_eviction(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "ROOT", tmp_path)
    monkeypatch.setattr(agent, "SPOOL_READY", set())
    monkeypatch.setattr(agent, "SPOOL_CAPACITY_BYTES", 2000)
    proc = {"executable": "/bin/x" * 20, "sha256": "a" * 64, "uid": "0", "connections": [], "capture": "ebpf"}
    for _ in range(30):
        agent.spool([proc], time.time())
        info = agent.pending_events()["spool"]
        size, count = true_totals(tmp_path / "events.db")
        assert (info["queued_bytes"], info["pending"]) == (size, count)
        assert size <= 2000
    assert agent.pending_events()["spool"]["dropped"] > 0
    ids = [e["id"] for e in agent.pending_events()["events"][:3]]
    agent.acknowledge(ids)
    agent.acknowledge(ids)  # repeated ack must not double-subtract
    info = agent.pending_events()["spool"]
    assert (info["queued_bytes"], info["pending"]) == true_totals(tmp_path / "events.db")


def test_existing_spool_without_totals_is_measured_once(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "ROOT", tmp_path)
    monkeypatch.setattr(agent, "SPOOL_READY", set())
    db = sqlite3.connect(tmp_path / "events.db")
    db.execute("CREATE TABLE events (id TEXT PRIMARY KEY, observed REAL, payload TEXT)")
    db.execute("CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER)")
    db.execute("INSERT INTO events VALUES ('a'||hex(randomblob(16)),1,'{\"processes\":[]}')")
    db.commit()
    db.close()
    info = agent.pending_events()["spool"]
    assert (info["queued_bytes"], info["pending"]) == true_totals(tmp_path / "events.db")
    assert info["pending"] == 1


def test_ebpf_process_reuses_hash_for_unchanged_binary(tmp_path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"payload")
    proc = tmp_path / "proc" / "42"
    proc.mkdir(parents=True)
    (proc / "exe").symlink_to(binary)
    cache = {}
    first = agent.ebpf_process(f"42\t0\t{binary}\n", tmp_path / "proc", cache)
    assert first["identity_verified"] and len(cache) == 1
    second = agent.ebpf_process(f"42\t0\t{binary}\n", tmp_path / "proc", cache)
    assert second["sha256"] == first["sha256"] and len(cache) == 1
    binary.write_bytes(b"changed payload")  # size/mtime change invalidates the entry
    third = agent.ebpf_process(f"42\t0\t{binary}\n", tmp_path / "proc", cache)
    assert third["sha256"] != first["sha256"]


def test_ebpf_hash_cache_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "EBPF_HASH_CACHE_LIMIT", 2)
    proc = tmp_path / "proc" / "7"
    proc.mkdir(parents=True)
    cache = {}
    for i in range(5):
        binary = tmp_path / f"b{i}"
        binary.write_bytes(bytes([i]) * (i + 1))
        link = proc / "exe"
        if link.is_symlink():
            link.unlink()
        link.symlink_to(binary)
        agent.ebpf_process(f"7\t0\t{binary}\n", tmp_path / "proc", cache)
        assert len(cache) <= 2
