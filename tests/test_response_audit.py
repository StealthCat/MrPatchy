import json
import uuid
from target import agent
from test_quarantine_target import response_files,approval


def test_audit_verifies_retained_bytes_and_detects_path_occupancy_without_mutation(response_files):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());agent.response_action(identifier,plan,approval())
    journals={p.name:p.read_bytes() for p in (vault/identifier).iterdir()}
    report=agent.response_audit(identifier,plan)
    assert report['state']=='verified' and report['facts']['held_verified'] and not report['facts']['source_present']
    assert {p.name:p.read_bytes() for p in (vault/identifier).iterdir()}==journals
    source.write_bytes(b'new deployment data must never enter audit receipts')
    report=agent.response_audit(identifier,plan)
    assert report['state']=='path_occupied' and report['facts']['source_present'] and not report['receipt']['restore_ready']
    assert 'new deployment data' not in json.dumps(report)
    assert source.read_bytes()==b'new deployment data must never enter audit receipts'


def test_missing_tampered_or_changed_parent_evidence_never_reports_verified(response_files):
    source,vault,plan=response_files;identifier=str(uuid.uuid4())
    assert agent.response_audit(identifier,plan)['state']=='missing' and not vault.exists()
    agent.response_action(identifier,plan,approval())
    source.parent.chmod(0o750)
    assert agent.response_audit(identifier,plan)['state']=='parent_changed'
    source.parent.chmod(0o700)
    (vault/identifier/'held').write_bytes(b'changed private evidence')
    report=agent.response_audit(identifier,plan)
    assert report['state']=='held_unverified' and not report['facts']['held_verified'] and report['receipt'] is None
    assert 'changed private evidence' not in json.dumps(report)


def test_audit_recognizes_explicit_original_restoration(response_files):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());agent.response_action(identifier,plan,approval())
    agent.response_action(identifier,plan,approval(True),restore=True)
    report=agent.response_audit(identifier,plan)
    assert report['state']=='restored' and report['receipt']['restore_attempted'] and source.exists()


def test_removed_original_parent_reports_parent_changed_not_missing(response_files,monkeypatch):
    import shutil
    source,vault,_=response_files
    nested=source.parent/'app'/'bin';nested.mkdir(parents=True);nested.parent.chmod(0o700);nested.chmod(0o700)
    target=nested/'evil';target.write_bytes(b'harmless response fixture');target.chmod(0o640)
    expected={'path':str(target),'sha256':agent.hashlib.sha256(target.read_bytes()).hexdigest(),'device':target.stat().st_dev,'inode':target.stat().st_ino}
    plan=agent.response_prepare(agent.evidence_prepare(expected));identifier=str(uuid.uuid4())
    agent.response_action(identifier,plan,approval())
    shutil.rmtree(source.parent/'app')
    report=agent.response_audit(identifier,plan)
    assert report['state']=='parent_changed' and report['facts']['held_verified'] and report['facts']['held_present']
    status=agent.response_status(identifier,plan)
    assert status['state']=='uncertain' and not status['restore_ready'] and (vault/identifier/'held').exists()


def test_parent_removed_between_status_parent_opens_is_never_missing(response_files,monkeypatch):
    # Interleaving from the #424 review: removing the parent after a first ancestor walk must not turn a retained vault entry into not_found/missing.
    import shutil
    source,vault,_=response_files
    nested=source.parent/'app'/'bin';nested.mkdir(parents=True);nested.parent.chmod(0o700);nested.chmod(0o700)
    target=nested/'evil';target.write_bytes(b'harmless response fixture');target.chmod(0o640)
    expected={'path':str(target),'sha256':agent.hashlib.sha256(target.read_bytes()).hexdigest(),'device':target.stat().st_dev,'inode':target.stat().st_ino}
    plan=agent.response_prepare(agent.evidence_prepare(expected));identifier=str(uuid.uuid4())
    agent.response_action(identifier,plan,approval())
    original=agent.response_parent;calls=[]
    def racing_parent(path):
        calls.append(path)
        if len(calls)>1:shutil.rmtree(source.parent/'app',ignore_errors=True)
        return original(path)
    monkeypatch.setattr(agent,'response_parent',racing_parent)
    report=agent.response_audit(identifier,plan)
    assert len(calls)==1 and report['state']=='verified' and report['facts']['held_verified']
    calls.clear()
    status=agent.response_status(identifier,plan)
    assert len(calls)==1 and status['state']=='quarantined' and (vault/identifier/'held').exists()
    def removed_at_open(path):
        calls.append(path);shutil.rmtree(source.parent/'app',ignore_errors=True)
        return original(path)
    monkeypatch.setattr(agent,'response_parent',removed_at_open);calls.clear()
    report=agent.response_audit(identifier,plan)
    assert len(calls)==1 and report['state']=='parent_changed' and report['facts']['held_verified']
    status=agent.response_status(identifier,plan)
    assert status['state']=='uncertain' and not status['restore_ready'] and (vault/identifier/'held').exists()
