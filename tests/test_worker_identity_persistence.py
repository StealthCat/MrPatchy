"""Worker identity persistence across restarts, container recreation and upgrades (#754)."""
import os
import subprocess
import sys
import textwrap
from pathlib import Path
import pytest
from sqlalchemy import select
from app import worker_registry as registry
from app.db import DATA,Session,Setting


@pytest.fixture(autouse=True)
def fresh_identity_state(client,monkeypatch):
    monkeypatch.delenv('MRPATCHY_WORKER_ID',raising=False)
    root=DATA/'worker-identities'
    for path in sorted(root.rglob('*'),reverse=True) if root.exists() else []:
        path.unlink() if path.is_file() else path.rmdir()
    yield


def registrations():
    with Session() as s:
        return [row.value for row in s.scalars(select(Setting).where(Setting.key.startswith(registry.PREFIX)))]


def test_generated_identity_survives_restart_and_reuses_registration():
    with registry.Registration('worker') as first:first_id,first_boot=first.id,first.boot
    # A restart, container recreation or `git pull` upgrade starts a new process with the
    # same persistent data volume but no in-memory state.
    with registry.Registration('worker') as second:
        assert second.id==first_id and second.boot!=first_boot
    rows=registrations()
    assert [row['id'] for row in rows]==[first_id]  # one registration, not a new one per restart
    assert rows[0]['boot_id']!=first_boot and rows[0]['state']=='stopped'


def test_concurrent_replicas_get_distinct_ids_that_persist_as_a_set():
    with registry.Registration('worker') as a,registry.Registration('worker') as b,registry.Registration('worker') as c:
        ids={a.id,b.id,c.id}
    assert len(ids)==3
    # Recreating all replicas reuses the same identities instead of adding three new registrations.
    with registry.Registration('worker') as a,registry.Registration('worker') as b,registry.Registration('worker') as c:
        assert {a.id,b.id,c.id}==ids
    assert {row['id'] for row in registrations()}==ids


def test_roles_have_separate_identity_pools():
    with registry.Registration('worker') as worker,registry.Registration('embedded') as embedded:
        assert worker.id!=embedded.id
    with registry.Registration('embedded') as embedded_again:assert embedded_again.id==embedded.id


def test_explicit_identity_takes_precedence_and_is_not_persisted(monkeypatch):
    with registry.Registration('worker') as generated:generated_id=generated.id
    monkeypatch.setenv('MRPATCHY_WORKER_ID','explicit-worker')
    with registry.Registration('worker') as explicit:assert explicit.id=='explicit-worker'
    monkeypatch.delenv('MRPATCHY_WORKER_ID')
    with registry.Registration('worker') as again:assert again.id==generated_id
    assert 'explicit-worker' not in {p.read_text().strip() for p in (DATA/'worker-identities'/'worker').iterdir()}


def test_corrupt_slot_is_kept_for_inspection_and_skipped(caplog):
    with registry.Registration('worker') as first:first_id=first.id
    slot=DATA/'worker-identities'/'worker'/'slot-01'
    slot.write_text('not a valid id!\n')
    with registry.Registration('worker') as second:
        assert second.id not in (first_id,'not a valid id!')
    assert slot.read_text()=='not a valid id!\n'
    assert 'invalid' in caplog.text


def test_exhausted_slots_fall_back_to_a_boot_identity(monkeypatch,caplog):
    monkeypatch.setattr(registry,'IDENTITY_SLOTS',1)
    with registry.Registration('worker') as held:
        with registry.Registration('worker') as extra:
            assert extra.id!=held.id
        assert 'boot-only identity' in caplog.text


def test_identity_persists_across_separate_processes_after_upgrade(tmp_path):
    """Run two real process lifetimes against one data directory, as `git pull` + restart does."""
    data=tmp_path/'data';data.mkdir()
    env={**os.environ,'DATA_DIR':str(data),'DATABASE_URL':'sqlite:///'+str(data/'mrpatchy.db')}
    env.pop('MRPATCHY_WORKER_ID',None)
    script=textwrap.dedent('''
        from app.db import Base,engine
        Base.metadata.create_all(engine)
        from app import worker_registry
        with worker_registry.Registration('worker') as node:print(node.id)
    ''')
    root=Path(__file__).resolve().parents[1]
    run=lambda:subprocess.run([sys.executable,'-c',script],cwd=root,env=env,capture_output=True,text=True,timeout=120)
    first=run();assert first.returncode==0,first.stderr
    second=run();assert second.returncode==0,second.stderr
    assert first.stdout.strip() and first.stdout.strip()==second.stdout.strip()
