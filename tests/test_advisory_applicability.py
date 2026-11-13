"""Per-server OSV advisory applicability (roadmap D slice, #783)."""
import shutil
from types import SimpleNamespace

import pytest

from app import advisories

pytestmark = pytest.mark.skipif(not shutil.which('dpkg'), reason='native dpkg comparator required')

ECO = 'Ubuntu:24.04:LTS'
INV = {'os': 'ID=ubuntu\nVERSION_ID="24.04"',
       'status': 'Package: libfoo1\nArchitecture: amd64\nVersion: 1.2-3ubuntu1\nSource: foo\nStatus: install ok installed\n'}


def _record(advisory_id, fixed, eco=ECO, package='foo', aliases=('CVE-2026-0001',)):
    return {'id': advisory_id, 'aliases': list(aliases), 'affected': [{
        'package': {'ecosystem': eco, 'name': package},
        'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': fixed}]}]}]}


def _stub(monkeypatch, ids, records, failures=()):
    gets = []

    def post(url, **kwargs):
        assert kwargs['follow_redirects'] is False
        return SimpleNamespace(raise_for_status=lambda: None,
                               json=lambda: {'results': [{'vulns': [{'id': i, 'modified': 'x'} for i in ids]}]})

    def get(url, **kwargs):
        assert kwargs['follow_redirects'] is False
        assert url.startswith(advisories.OSV_VULN_URL)
        advisory_id = url[len(advisories.OSV_VULN_URL):]
        gets.append(advisory_id)
        if advisory_id in failures:
            raise RuntimeError('network down')
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: records[advisory_id])

    monkeypatch.setattr(advisories.httpx, 'post', post)
    monkeypatch.setattr(advisories.httpx, 'get', get)
    return gets


def _by_id(result):
    return {row['advisory_id']: row for row in result['results'][0]['applicability']}


def test_matches_are_classified_against_this_release_and_source_version(monkeypatch):
    records = {
        'UBUNTU-CVE-2026-0001': _record('UBUNTU-CVE-2026-0001', '1.2-4'),
        'UBUNTU-CVE-2026-0002': _record('UBUNTU-CVE-2026-0002', '1.2-2', aliases=('CVE-2026-0002',)),
        # Only another release's ranges: never treated as applicable or safe.
        'UBUNTU-CVE-2026-0003': _record('UBUNTU-CVE-2026-0003', '9.9', eco='Ubuntu:22.04:LTS'),
    }
    gets = _stub(monkeypatch, list(records), records)
    result = advisories.scan(INV, ['libfoo1:amd64'])
    rows = _by_id(result)
    assert rows['UBUNTU-CVE-2026-0001']['status'] == 'affected'
    assert rows['UBUNTU-CVE-2026-0001']['fixed_version'] == '1.2-4'
    assert rows['UBUNTU-CVE-2026-0001']['cve_ids'] == ['CVE-2026-0001']
    assert rows['UBUNTU-CVE-2026-0002']['status'] == 'fixed'
    assert rows['UBUNTU-CVE-2026-0003']['status'] == 'uncertain'
    assert result['summary'] == {'affected': 1, 'fixed': 1, 'unaffected': 0, 'uncertain': 1}
    assert sorted(gets) == sorted(records)
    # Raw matches and coverage are kept for compatibility; coverage disclaims exploitation.
    assert len(result['results'][0]['vulnerabilities']) == 3
    assert 'not evidence of exploitation' in result['coverage']


def test_retrieval_failures_and_mismatched_records_are_uncertain_not_safe(monkeypatch):
    records = {'UBUNTU-CVE-2026-0005': {'id': 'SOMETHING-ELSE', 'affected': []},
               'UBUNTU-CVE-2026-0006': ['not', 'a', 'record']}
    _stub(monkeypatch, ['UBUNTU-CVE-2026-0004', *records, '../../etc/passwd'], records,
          failures={'UBUNTU-CVE-2026-0004'})
    result = advisories.scan(INV, ['libfoo1:amd64'])
    rows = result['results'][0]['applicability']
    assert [row['status'] for row in rows] == ['uncertain'] * 4
    assert rows[0]['reason'] == 'Advisory detail could not be retrieved'
    assert rows[1]['reason'] == rows[2]['reason'] == 'Advisory detail did not match the requested record'
    # An invalid ID is never requested and is not echoed back.
    assert rows[3]['advisory_id'] is None and rows[3]['reason'] == 'Advisory ID is missing or invalid'
    assert result['summary']['uncertain'] == 4


def test_detail_fetches_are_bounded(monkeypatch):
    monkeypatch.setattr(advisories, 'MAX_DETAIL_FETCHES', 2)
    ids = ['UBUNTU-CVE-2026-001' + str(i) for i in range(4)]
    records = {i: _record(i, '1.2-4') for i in ids}
    gets = _stub(monkeypatch, ids, records)
    result = advisories.scan(INV, ['libfoo1:amd64'])
    assert len(gets) == 2
    statuses = [row['status'] for row in result['results'][0]['applicability']]
    assert statuses.count('affected') == 2 and statuses.count('uncertain') == 2
    assert any('limit' in row['reason'] for row in result['results'][0]['applicability'])


def test_route_stores_applicability_for_the_server(admin, monkeypatch):
    from app.db import Host, Session
    with Session() as s:
        s.add(Host(id='advisory-host', name='Advisory target', address='192.0.2.10',
                   fingerprint='SHA256:' + 'a' * 43, state='online', inventory=INV))
        s.commit()
    records = {'UBUNTU-CVE-2026-0001': _record('UBUNTU-CVE-2026-0001', '1.2-4')}
    _stub(monkeypatch, list(records), records)
    response = admin.post('/api/operations/advisory-host/advisories', json={'packages': ['libfoo1:amd64']})
    assert response.status_code == 200, response.text
    stored = admin.get('/api/operations/advisory-host/advisories').json()
    assert stored['summary']['affected'] == 1
    assert stored['results'][0]['applicability'][0]['status'] == 'affected'


def test_detail_fetches_share_a_wall_clock_budget(monkeypatch):
    ids = ['UBUNTU-CVE-2026-002' + str(i) for i in range(3)]
    records = {i: _record(i, '1.2-4') for i in ids}
    clock = [1000.0]
    monkeypatch.setattr(advisories.time, 'monotonic', lambda: clock[0])
    gets = _stub(monkeypatch, ids, records)
    original_get = advisories.httpx.get
    timeouts = []

    def slow_get(url, **kwargs):
        timeouts.append(kwargs['timeout'])
        clock[0] += advisories.DETAIL_FETCH_DEADLINE - 5  # each fetch consumes most of the budget
        return original_get(url, **kwargs)

    monkeypatch.setattr(advisories.httpx, 'get', slow_get)
    result = advisories.scan(INV, ['libfoo1:amd64'])
    assert len(gets) == 2 and timeouts[0] == 30 and timeouts[1] == 5
    rows = result['results'][0]['applicability']
    assert [row['status'] for row in rows] == ['affected', 'affected', 'uncertain']
    assert 'time budget' in rows[2]['reason']
