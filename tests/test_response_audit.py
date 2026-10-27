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
