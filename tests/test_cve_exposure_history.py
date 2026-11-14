"""Durable per-server CVE exposure history from advisory scans (roadmap D slice, #858)."""
import shutil
from types import SimpleNamespace

import pytest

from app import advisories

ECO = 'Ubuntu:24.04:LTS'
HOST = 'exposure-host'


def _row(advisory_id, status, fixed=None, cves=('CVE-2026-0001',)):
    return {'advisory_id': advisory_id, 'cve_ids': list(cves), 'status': status, 'reason': '',
            'fixed_version': fixed, 'fix_available': fixed is not None}


def _result(*items):
    """items: (binary, source, version, [applicability rows])."""
    return {'checked': 0, 'ecosystem': ECO, 'results': [
        {'binary': binary, 'package': {'ecosystem': ECO, 'name': source}, 'version': version,
         'vulnerabilities': [], 'applicability': rows} for binary, source, version, rows in items]}


@pytest.fixture
def session(client):
    from app.db import Session
    with Session() as s:
        s.query(advisories.ExposureHistory).delete()
        s.commit()
        yield s


def _history(session, host=HOST):
    return {(i['advisory_id'], i['package']): i for i in advisories.history(session, host)['items']}


def test_affected_opens_and_fixed_rescan_resolves_without_losing_first_seen(session):
    advisories.record_history(session, HOST, _result(
        ('libfoo1:amd64', 'foo', '1.2-3', [_row('USN-1', 'affected', '1.2-4')])), now=100)
    session.commit()
    item = _history(session)[('USN-1', 'foo')]
    assert item['state'] == 'open' and item['first_affected_at'] == 100
    assert item['first_affected_version'] == '1.2-3' and item['fixed_version'] == '1.2-4'
    assert item['cve_ids'] == ['CVE-2026-0001']

    advisories.record_history(session, HOST, _result(
        ('libfoo1:amd64', 'foo', '1.2-3', [_row('USN-1', 'affected', '1.2-4')])), now=200)
    advisories.record_history(session, HOST, _result(
        ('libfoo1:amd64', 'foo', '1.2-4', [_row('USN-1', 'fixed', '1.2-4')])), now=300)
    session.commit()
    item = _history(session)[('USN-1', 'foo')]
    assert item['state'] == 'resolved'
    assert (item['first_affected_at'], item['last_affected_at'], item['resolved_at']) == (100, 200, 300)
    assert item['resolved_version'] == '1.2-4' and item['resolved_status'] == 'fixed'
    # A later fixed scan does not move the first resolution time.
    advisories.record_history(session, HOST, _result(
        ('libfoo1:amd64', 'foo', '1.2-4', [_row('USN-1', 'fixed', '1.2-4')])), now=400)
    session.commit()
    assert _history(session)[('USN-1', 'foo')]['resolved_at'] == 300


def test_uncertain_never_resolves_and_never_opens(session):
    advisories.record_history(session, HOST, _result(
        ('libfoo1:amd64', 'foo', '1.2-3', [_row('USN-1', 'affected'), _row('USN-2', 'uncertain')])), now=100)
    advisories.record_history(session, HOST, _result(
        ('libfoo1:amd64', 'foo', '1.2-3', [_row('USN-1', 'uncertain')])), now=200)
    session.commit()
    rows = _history(session)
    assert ('USN-2', 'foo') not in rows
    assert rows[('USN-1', 'foo')]['state'] == 'open'
    assert rows[('USN-1', 'foo')]['last_status'] == 'uncertain'
    assert rows[('USN-1', 'foo')]['last_affected_at'] == 100


def test_unscanned_packages_are_never_resolved(session):
    advisories.record_history(session, HOST, _result(
        ('libfoo1:amd64', 'foo', '1.2-3', [_row('USN-1', 'affected')]),
        ('libbar1:amd64', 'bar', '2.0-1', [_row('USN-9', 'affected')])), now=100)
    # A later scan of only bar, which no longer lists USN-9.
    advisories.record_history(session, HOST, _result(('libbar1:amd64', 'bar', '2.0-2', [])), now=200)
    session.commit()
    rows = _history(session)
    assert rows[('USN-1', 'foo')]['state'] == 'open'
    assert rows[('USN-9', 'bar')]['state'] == 'resolved'
    assert rows[('USN-9', 'bar')]['resolved_status'] == 'not-listed'
    assert rows[('USN-9', 'bar')]['resolved_version'] == '2.0-2'


def test_reaffected_exposure_reopens_and_keeps_original_first_seen(session):
    advisories.record_history(session, HOST, _result(('libfoo1:amd64', 'foo', '1.2-3', [_row('USN-1', 'affected')])), now=100)
    advisories.record_history(session, HOST, _result(('libfoo1:amd64', 'foo', '1.2-4', [_row('USN-1', 'unaffected')])), now=200)
    advisories.record_history(session, HOST, _result(('libfoo1:amd64', 'foo', '1.2-3', [_row('USN-1', 'affected')])), now=300)
    session.commit()
    item = _history(session)[('USN-1', 'foo')]
    assert item['state'] == 'open' and item['reopened'] == 1
    assert item['first_affected_at'] == 100 and item['last_affected_at'] == 300
    assert item['resolved_at'] is None


def test_affected_binary_of_a_shared_source_wins_and_conflicting_versions_do_not_resolve(session):
    advisories.record_history(session, HOST, _result(
        ('libfoo1:amd64', 'foo', '1.2-3', [_row('USN-1', 'fixed')]),
        ('foo-bin:amd64', 'foo', '1.2-3', [_row('USN-1', 'affected')])), now=100)
    session.commit()
    assert _history(session)[('USN-1', 'foo')]['state'] == 'open'
    # Two binaries of one source disagree on version; absence cannot resolve.
    advisories.record_history(session, HOST, _result(
        ('libfoo1:amd64', 'foo', '1.2-4', []), ('foo-bin:amd64', 'foo', '1.2-3', [])), now=200)
    session.commit()
    assert _history(session)[('USN-1', 'foo')]['state'] == 'open'


def test_history_is_per_server_and_ignores_invalid_rows(session):
    advisories.record_history(session, HOST, _result(('libfoo1:amd64', 'foo', '1.2-3', [
        _row('USN-1', 'affected'), _row(None, 'affected'), _row('bad id/../x', 'affected'),
        {'advisory_id': 'USN-3', 'status': 'bogus'}])), now=100)
    session.commit()
    assert list(_history(session)) == [('USN-1', 'foo')]
    assert advisories.history(session, 'other-host')['items'] == []


def test_history_coverage_discloses_gaps_and_restart_limits(session):
    text = advisories.history(session, HOST)['coverage']
    assert 'telemetry gaps' in text and 'restarts or reboots are not confirmed' in text
    assert '"uncertain" never resolves' in text and 'not evidence of exploitation' in text


@pytest.mark.skipif(not shutil.which('dpkg'), reason='native dpkg comparator required')
def test_route_history_survives_later_scans(admin, monkeypatch):
    from app.db import Host, Session
    inventory = {'os': 'ID=ubuntu\nVERSION_ID="24.04"',
                 'status': 'Package: libfoo1\nArchitecture: amd64\nVersion: 1.2-3ubuntu1\nSource: foo\n'
                           'Status: install ok installed\n'}
    with Session() as s:
        s.add(Host(id='history-host', name='History target', address='192.0.2.11',
                   fingerprint='SHA256:' + 'b' * 43, state='online', inventory=inventory))
        s.commit()
    record = {'id': 'UBUNTU-CVE-2026-0001', 'aliases': ['CVE-2026-0001'], 'affected': [{
        'package': {'ecosystem': ECO, 'name': 'foo'},
        'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '1.2-4'}]}]}]}
    listed = [True]

    def post(url, **kwargs):
        vulns = [{'id': record['id']}] if listed[0] else []
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {'results': [{'vulns': vulns}]})

    client = SimpleNamespace(get=lambda url, **kw: SimpleNamespace(raise_for_status=lambda: None, json=lambda: record),
                             close=lambda: None)
    monkeypatch.setattr(advisories.httpx, 'post', post)
    monkeypatch.setattr(advisories, '_detail_client', lambda: client)
    assert admin.post('/api/operations/history-host/advisories', json={'packages': ['libfoo1:amd64']}).status_code == 200
    body = admin.get('/api/operations/history-host/advisories').json()
    [item] = body['exposure_history']['items']
    assert item['advisory_id'] == 'UBUNTU-CVE-2026-0001' and item['state'] == 'open'
    assert body['exposure_history']['open'] == 1

    listed[0] = False  # the patched version is no longer listed by the advisory service
    with Session() as s:
        host = s.get(Host, 'history-host')
        host.inventory = {**inventory, 'status': inventory['status'].replace('1.2-3ubuntu1', '1.2-4')}
        s.commit()
    assert admin.post('/api/operations/history-host/advisories', json={'packages': ['libfoo1:amd64']}).status_code == 200
    body = admin.get('/api/operations/history-host/advisories').json()
    assert body['summary']['affected'] == 0  # the latest-scan setting no longer shows the exposure
    [item] = body['exposure_history']['items']
    assert item['state'] == 'resolved' and item['resolved_status'] == 'not-listed'
    assert item['first_affected_version'] == '1.2-3ubuntu1' and item['resolved_version'] == '1.2-4'
