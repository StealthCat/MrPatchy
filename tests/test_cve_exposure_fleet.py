"""Fleet-wide open CVE exposure summary from the durable ledger (roadmap D slice, #911)."""
import pytest

from app import advisories

ECO = 'Ubuntu:24.04:LTS'


def _row(advisory_id, status, fixed=None, cves=('CVE-2026-0001',)):
    return {'advisory_id': advisory_id, 'cve_ids': list(cves), 'status': status, 'reason': '',
            'fixed_version': fixed, 'fix_available': fixed is not None}


def _result(*items):
    return {'checked': 0, 'ecosystem': ECO, 'results': [
        {'binary': source, 'package': {'ecosystem': ECO, 'name': source}, 'version': version,
         'vulnerabilities': [], 'applicability': rows} for source, version, rows in items]}


@pytest.fixture
def fleet(client):
    from app.db import Host, Session
    with Session() as s:
        for host_id, name, enabled, deleted in (('h-a', 'Alpha', True, 0), ('h-b', 'Bravo', True, 0),
                                                ('h-c', 'Charlie', False, 0), ('h-d', 'Deleted', True, 123)):
            s.add(Host(id=host_id, name=name, address='192.0.2.1', fingerprint='SHA256:' + 'a' * 43,
                       state='online', enabled=enabled, deleted_at=deleted))
        s.commit()
        yield s


def _record(session, host, now, *items):
    advisories.record_history(session, host, _result(*items), now=now)
    session.commit()


def test_open_exposures_group_by_advisory_across_servers(fleet):
    _record(fleet, 'h-a', 100, ('foo', '1.0', [_row('USN-1', 'affected', '1.1', ('CVE-2026-0002', 'CVE-2026-0001'))]),
            ('bar', '2.0', [_row('USN-2', 'affected')]))
    _record(fleet, 'h-b', 50, ('foo', '1.0', [_row('USN-1', 'affected', '1.1', ('CVE-2026-0003',))]))
    _record(fleet, 'h-c', 300, ('foo', '1.0', [_row('USN-1', 'affected')]))
    data = advisories.fleet_open(fleet)
    assert data['totals'] == {'open_exposures': 4, 'servers': 3, 'advisories': 2}
    assert [i['advisory_id'] for i in data['items']] == ['USN-1', 'USN-2']  # most servers first
    usn1 = data['items'][0]
    assert usn1['servers'] == 3 and usn1['packages'] == 1 and usn1['first_affected_at'] == 50
    assert usn1['cve_ids'] == ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003']
    assert usn1['fixed_known'] == 2
    assert [(e['host_name'], e['enabled']) for e in usn1['exposures']] == [('Bravo', True), ('Alpha', True), ('Charlie', False)]
    assert usn1['exposures'][0]['fixed_version'] == '1.1' and usn1['exposures'][2]['fixed_version'] is None
    assert not data['truncated'] and not usn1['exposures_truncated'] and usn1['exposures_total'] == 3
    assert 'not evidence of exploitation' in data['coverage'] and 'not' in data['coverage']


def test_resolved_and_deleted_server_exposures_are_excluded(fleet):
    _record(fleet, 'h-a', 100, ('foo', '1.0', [_row('USN-1', 'affected', '1.1')]))
    _record(fleet, 'h-a', 200, ('foo', '1.1', [_row('USN-1', 'fixed', '1.1')]))
    _record(fleet, 'h-d', 100, ('foo', '1.0', [_row('USN-1', 'affected', '1.1')]))
    data = advisories.fleet_open(fleet)
    assert data['items'] == [] and data['totals'] == {'open_exposures': 0, 'servers': 0, 'advisories': 0}
    # A reopened exposure is open again and keeps the first-seen time.
    _record(fleet, 'h-a', 300, ('foo', '1.0', [_row('USN-1', 'affected', '1.1')]))
    item, = advisories.fleet_open(fleet)['items']
    assert item['exposures'][0]['reopened'] == 1 and item['first_affected_at'] == 100


def test_caps_flag_truncation_but_totals_cover_every_row(fleet):
    _record(fleet, 'h-a', 100, *[('p%d' % n, '1.0', [_row('USN-%d' % n, 'affected')]) for n in range(5)])
    _record(fleet, 'h-b', 100, ('p0', '1.0', [_row('USN-0', 'affected')]), ('q0', '1.0', [_row('USN-0', 'affected')]))
    data = advisories.fleet_open(fleet, advisory_limit=2, exposure_limit=2)
    assert data['truncated'] and len(data['items']) == 2
    assert data['totals'] == {'open_exposures': 7, 'servers': 2, 'advisories': 5}
    first = data['items'][0]
    assert first['advisory_id'] == 'USN-0' and first['servers'] == 2 and first['packages'] == 2
    assert len(first['exposures']) == 2 and first['exposures_truncated'] and first['exposures_total'] == 3


def test_one_server_with_many_packages_reports_exposures_not_servers(fleet):
    # One server, six affected packages under one advisory: the cap is on
    # exposures (server x package), so truncation must not claim more servers.
    _record(fleet, 'h-a', 100, *[('p%d' % n, '1.0', [_row('USN-1', 'affected', '1.1' if n % 2 else None,
                                                          ('CVE-2026-000%d' % n,))]) for n in range(6)])
    item, = advisories.fleet_open(fleet, exposure_limit=2)['items']
    assert item['servers'] == 1 and item['packages'] == 6
    assert item['exposures_total'] == 6 and len(item['exposures']) == 2 and item['exposures_truncated']
    assert [e['package'] for e in item['exposures']] == ['p0', 'p1']
    # Summary fields still cover every open row, not just the listed ones.
    assert item['fixed_known'] == 3 and item['cve_ids'] == ['CVE-2026-000%d' % n for n in range(6)]


def test_rows_query_loads_at_most_the_per_advisory_limit(fleet, monkeypatch):
    _record(fleet, 'h-a', 100, *[('p%d' % n, '1.0', [_row('USN-1', 'affected'), _row('USN-2', 'affected')])
                                 for n in range(6)])
    _record(fleet, 'h-b', 100, *[('q%d' % n, '1.0', [_row('USN-1', 'affected')]) for n in range(4)])
    loaded = []
    execute = fleet.execute

    def spy(statement, *args, **kwargs):
        frozen = execute(statement, *args, **kwargs).freeze()
        loaded.append(len(frozen().all()))
        return frozen()
    monkeypatch.setattr(fleet, 'execute', spy)
    data = advisories.fleet_open(fleet, exposure_limit=3)
    monkeypatch.undo()
    # Two advisories x at most three rows each; main loaded all 16 rows at once.
    assert max(loaded) <= 2 * 3
    assert [(i['advisory_id'], i['exposures_total'], len(i['exposures'])) for i in data['items']] == [
        ('USN-1', 10, 3), ('USN-2', 6, 3)]
    # Under the limit the summary is unchanged by the bound.
    assert advisories.fleet_open(fleet, exposure_limit=50) == advisories.fleet_open(fleet, exposure_limit=10)
    full = advisories.fleet_open(fleet)['items'][0]
    assert len(full['exposures']) == 10 and not full['exposures_truncated']


def test_fleet_route_is_admin_only_read_only(admin, monkeypatch):
    from app.db import Host, Session
    with Session() as s:
        s.add(Host(id='h-r', name='<b>Route</b>', address='192.0.2.9', fingerprint='SHA256:' + 'c' * 43, state='online'))
        s.commit()
        advisories.record_history(s, 'h-r', _result(('foo', '1.0', [_row('USN-9', 'affected')])), now=10)
        s.commit()

    def forbidden(*args, **kwargs):
        raise AssertionError('fleet view must not contact advisory services')
    monkeypatch.setattr(advisories, '_detail_client', forbidden)
    monkeypatch.setattr(advisories, 'scan', forbidden)
    response = admin.get('/api/cve-exposure/fleet')
    assert response.status_code == 200
    body = response.json()
    assert body['totals']['open_exposures'] == 1
    assert body['items'][0]['exposures'][0]['host_name'] == '<b>Route</b>'
    admin.post('/api/logout')
    assert admin.get('/api/cve-exposure/fleet').status_code in (401, 403)
