"""Advisory publication dates in a server's CVE exposure history (roadmap D slice, #938)."""
import math

import pytest

from app import advisories

ECO = 'Ubuntu:24.04:LTS'
HOST = 'publication-host'


def _row(advisory_id, status='affected', published=None):
    return {'advisory_id': advisory_id, 'cve_ids': ['CVE-2026-0001'], 'status': status, 'reason': '',
            'fixed_version': None, 'fix_available': False, 'published_at': published, 'modified_at': None}


def _result(*items):
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


def _items(session, latest):
    return {i['advisory_id']: i for i in advisories.history(session, HOST, latest=latest)['items']}


def test_history_reports_publication_and_first_affected_gap_from_latest_scan(session):
    scan = _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1', published=1000)]))
    advisories.record_history(session, HOST, scan, now=5000)
    session.commit()
    item = _items(session, scan)['USN-1']
    assert item['published_at'] == 1000
    assert item['publication_to_first_affected'] == 4000


def test_history_without_a_latest_scan_or_date_reports_null(session):
    scan = _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1')]))
    advisories.record_history(session, HOST, scan, now=5000)
    session.commit()
    for latest in (None, {}, {'results': 'bad'}, scan, _result()):
        item = _items(session, latest)['USN-1']
        assert item['published_at'] is None and item['publication_to_first_affected'] is None


@pytest.mark.parametrize('value', [0, -5, True, '1000', math.nan, math.inf, [1000]])
def test_malformed_stored_dates_are_never_reported(session, value):
    scan = _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1', published=value)]))
    advisories.record_history(session, HOST, _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1')])), now=5000)
    session.commit()
    item = _items(session, scan)['USN-1']
    assert item['published_at'] is None and item['publication_to_first_affected'] is None


def test_conflicting_dates_for_one_advisory_fail_closed(session):
    scan = _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1', published=1000)]),
                   ('libbar1:amd64', 'bar', '1.0', [_row('USN-1', published=1200)]))
    advisories.record_history(session, HOST, scan, now=5000)
    session.commit()
    items = advisories.history(session, HOST, latest=scan)['items']
    assert len(items) == 2
    assert all(i['published_at'] is None and i['publication_to_first_affected'] is None for i in items)
    # A later missing value after a valid one also fails closed.
    scan = _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1', published=1000)]),
                   ('libbar1:amd64', 'bar', '1.0', [_row('USN-1')]))
    assert advisories.publication_dates(scan) == {'USN-1': None}


def test_publication_after_first_affected_scan_gives_no_gap(session):
    # The ledger opened before the advisory's (later re-issued) publication date.
    advisories.record_history(session, HOST, _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1')])), now=1000)
    session.commit()
    scan = _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1', published=3000)]))
    item = _items(session, scan)['USN-1']
    assert item['published_at'] == 3000 and item['publication_to_first_affected'] is None


def test_resolved_exposure_keeps_publication_from_latest_fixed_scan(session):
    advisories.record_history(session, HOST, _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1')])), now=2000)
    fixed = _result(('libfoo1:amd64', 'foo', '1.1', [_row('USN-1', 'fixed', published=500)]))
    advisories.record_history(session, HOST, fixed, now=3000)
    session.commit()
    item = _items(session, fixed)['USN-1']
    assert item['state'] == 'resolved' and item['published_at'] == 500
    assert item['publication_to_first_affected'] == 1500


def test_invalid_advisory_ids_are_ignored():
    scan = _result(('libfoo1:amd64', 'foo', '1.0', [_row('bad id', published=1000), 'row', {'advisory_id': 7}]))
    assert advisories.publication_dates(scan) == {}


def test_coverage_explains_publication_source_and_gap(session):
    text = advisories.history(session, HOST)['coverage']
    assert 'publication date comes from the advisory record' in text
    assert 'not proof the server was exposed' in text
    assert 'advisory publication is not shown here' not in text
    # Earlier non-affected scans are not recorded, so the text never calls the period unmonitored.
    assert 'unmonitored' not in text.lower()
    assert 'may include scans that found the package fixed' in text


def test_earlier_fixed_scan_is_not_reported_as_an_unmonitored_period(session):
    # Review finding on 8252b21: a scan at 2000 covered the package and found it fixed, the package was
    # later downgraded and first classified affected at 9000. The ledger only tracks affected pairs, so
    # the interval is the time to the first affected observation, never an "unmonitored" gap.
    fixed = _result(('libfoo1:amd64', 'foo', '2.0', [_row('USN-1', 'fixed', published=1000)]))
    advisories.record_history(session, HOST, fixed, now=2000)
    affected = _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-1', published=1000)]))
    advisories.record_history(session, HOST, affected, now=9000)
    session.commit()
    item = _items(session, affected)['USN-1']
    assert item['first_affected_at'] == 9000
    assert item['publication_to_first_affected'] == 8000
    assert 'unmonitored_before_first_scan' not in item


def test_route_returns_publication_from_stored_scan(admin):
    from app.db import Host, Session, Setting
    with Session() as s:
        s.query(advisories.ExposureHistory).delete()
        s.add(Host(id='pub-host', name='Publication target', address='192.0.2.21',
                   fingerprint='SHA256:' + 'c' * 43, state='online', inventory={}))
        scan = _result(('libfoo1:amd64', 'foo', '1.0', [_row('USN-9', published=1000)]))
        advisories.record_history(s, 'pub-host', scan, now=86400 * 3 + 1000)
        s.merge(Setting(key='advisories:pub-host', value=scan))
        s.commit()
    body = admin.get('/api/operations/pub-host/advisories').json()
    [item] = body['exposure_history']['items']
    assert item['published_at'] == 1000 and item['publication_to_first_affected'] == 86400 * 3
