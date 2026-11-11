import copy

import pytest
from app import persistence, file_status, known_good, ai, startup_ai, incidents
from app.db import Session
from test_persistence_baseline import setup_host, payload, URL
from test_persistence_comparison import inventory
from test_file_status import report
from test_startup_ai import setup_incident, response

PATH = '/etc/cron.d/task'


def vendor_receipt(checksum='a'*64):
    value = report(checksum)
    value['vendor_manifest']['entries'][0]['path'] = PATH
    return value


def add_vendor(checksum='a'*64):
    with Session() as s:
        s.add(incidents.Inspection(id='signed', host_id='baseline-host',
            report=vendor_receipt(checksum)))
        s.commit()


def test_baseline_review_orders_evidence_without_ai_or_approval(admin, monkeypatch):
    setup_host(); add_vendor()
    events = []
    original_repository = file_status.repositories
    original_cache = known_good.lookup
    def repository(*args):
        events.append('repository')
        return original_repository(*args)
    def cache(*args, **kwargs):
        events.append('cache')
        return original_cache(*args, **kwargs)
    monkeypatch.setattr(file_status, 'repositories', repository)
    monkeypatch.setattr(known_good, 'lookup', cache)
    monkeypatch.setattr(ai, 'request', lambda *args: pytest.fail('Viewing must not call AI'))
    data = admin.get(URL).json()
    assert events == ['repository', 'cache']
    entry = data['file_review']['items'][0]
    assert entry['status'] == 'verified'
    assert entry['known_good']['status'] == 'miss'
    assert entry['behavior_status'] == 'unresolved'
    assert data['baseline'] is None
    with Session() as s:
        assert s.query(incidents.PersistenceBaseline).count() == 0


def test_review_hash_prevents_approval_after_provenance_changes(admin):
    setup_host(); add_vendor()
    body = {**payload(admin), 'review_digest': admin.get(URL).json()['review_digest']}
    with Session() as s:
        s.get(incidents.Inspection, 'signed').report = vendor_receipt('b'*64)
        s.commit()
    assert admin.post(URL, json=body).status_code == 409
    data = admin.get(URL).json()
    item = data['file_review']['items'][0]
    assert item['status'] == 'changed' and item['known_good']['status'] == 'bypassed'
    body['review_digest'] = data['review_digest']
    # A human may accept a legitimate local modification, with an explicit reason.
    assert admin.post(URL, json=body).status_code == 200


def test_untrusted_claims_gaps_and_symlinks_remain_unresolved(admin):
    setup_host()
    value = inventory()
    value.update(state='incomplete', gaps=['unreadable'], skipped=1)
    value['entries'][0].update(identity_verified=True, file_assessment={'status': 'verified'})
    value['entries'].append({'path': '/etc/cron.d/link', 'kind': 'symlink', 'target': PATH,
        'uid': 0, 'gid': 0, 'mode': 0o777, 'size': 4, 'mtime_ns': 1})
    before = copy.deepcopy(value)
    with Session() as s:
        result = persistence.assess_inventory(s, 'baseline-host', value)
    assert value == before
    assert result['coverage'] == 'incomplete' and result['gaps'] == ['unreadable']
    assert [r['status'] for r in result['items']] == ['unassessed', 'unavailable']
    assert all(r['known_good']['status'] == 'miss' for r in result['items'])


def test_startup_provider_receives_review_and_provenance_change_invalidates_plan(admin, monkeypatch):
    identifier = setup_incident(admin); add_vendor()
    def provider(payload, key):
        import json
        evidence = json.loads(payload['input'])
        assert evidence['baseline_file_review']['items'][0]['status'] == 'verified'
        assert evidence['baseline_file_review']['items'][0]['known_good']['status'] == 'miss'
        with Session() as other:
            other.get(incidents.Inspection, 'signed').report = vendor_receipt('b'*64)
            other.commit()
        return response(identifier)
    monkeypatch.setattr(ai, 'request', provider)
    with Session() as s:
        row = s.get(incidents.PersistenceIncident, identifier)
        with pytest.raises(ValueError, match='changed during'):
            startup_ai.generate(s, row, row.updated)
        assert s.query(incidents.Plan).count() == 0


def test_compaction_binds_omitted_file_evidence(admin):
    setup_host()
    inv = inventory()
    inv['entries'] = [{**inv['entries'][0], 'path': f'/etc/cron.d/task-{n}'} for n in range(30)]
    with Session() as s:
        first = startup_ai.file_review(s, 'baseline-host', inv)
        inv['entries'][-1]['sha256'] = 'c'*64
        second = startup_ai.file_review(s, 'baseline-host', inv)
    assert len(first['items']) == 20 and first['omitted'] == 10
    assert first['items'] == second['items'] and first['digest'] != second['digest']
