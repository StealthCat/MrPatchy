"""Advisory publication and modification dates in OSV applicability results (#862, roadmap D)."""
import json
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import advisories
from app import cve_exposure as ce

ECO = 'Ubuntu:24.04:LTS'
PKG = 'foo'
NOW = 1_800_000_000.0  # 2027-01-15 UTC
INV = {'os': 'ID=ubuntu\nVERSION_ID="24.04"',
       'status': 'Package: libfoo1\nArchitecture: amd64\nVersion: 1.2-3ubuntu1\nSource: foo\nStatus: install ok installed\n'}


def _record(advisory_id='UBUNTU-CVE-2026-0002', **dates):
    return {'id': advisory_id, 'aliases': ['CVE-2026-0002'], **dates, 'affected': [{
        'package': {'ecosystem': ECO, 'name': PKG},
        'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '1.2-4'}]}]}]}


@pytest.mark.parametrize('value,expected', [
    ('2026-03-04T05:06:07Z', 1772600767.0),
    ('2026-03-04T05:06:07.5Z', 1772600767.5),
    ('2026-03-04T05:06:07.123456789Z', 1772600767.123456),
    ('2026-03-04T07:06:07+02:00', 1772600767.0),
])
def test_record_date_parses_timezone_qualified_rfc3339(value, expected):
    assert advisories.record_date(value, NOW) == pytest.approx(expected)


@pytest.mark.parametrize('value', [
    None, 1772600767, True, '', '2026-03-04', '2026-03-04T05:06:07', '2026-13-04T05:06:07Z',
    '2026-02-30T05:06:07Z', 'yesterday', '1989-12-31T23:59:59Z', '2027-01-17T00:00:00Z',
    '2026-03-04T05:06:07Z' + ' ' * 40, '2026-03-04T05:06:07Z<script>',
])
def test_record_date_rejects_untrustworthy_values(value):
    assert advisories.record_date(value, NOW) is None


def test_dates_are_added_without_changing_classification():
    plain = ce.classify(_record(), ECO, PKG, '1.2-3')
    dated = advisories._applicability({'id': 'UBUNTU-CVE-2026-0002'}, {'UBUNTU-CVE-2026-0002': _record(
        published='2026-03-04T05:06:07Z', modified='2026-03-05T00:00:00Z')}, ECO, PKG, '1.2-3', now=NOW)
    assert dated['status'] == ce.AFFECTED == plain['status']
    assert {k: v for k, v in dated.items() if k not in ('published_at', 'modified_at')} == plain
    assert dated['published_at'] == 1772600767.0 and dated['modified_at'] == 1772668800.0


def test_bad_dates_are_null_and_never_change_status():
    for dates in ({}, {'published': 'not a date', 'modified': 42}, {'published': '2099-01-01T00:00:00Z'}):
        row = advisories._applicability({'id': 'UBUNTU-CVE-2026-0002'},
                                        {'UBUNTU-CVE-2026-0002': _record(**dates)}, ECO, PKG, '1.2-3', now=NOW)
        assert row['status'] == ce.AFFECTED
        assert row['published_at'] is None and row['modified_at'] is None


def test_unfetched_record_stays_uncertain_with_null_dates():
    row = advisories._applicability({'id': 'UBUNTU-CVE-2026-0002'},
                                    {'UBUNTU-CVE-2026-0002': 'Advisory detail could not be retrieved'}, ECO, PKG, '1.2-3')
    assert row['status'] == ce.UNCERTAIN
    assert row['published_at'] is None and row['modified_at'] is None


def test_coverage_discloses_what_the_dates_mean():
    assert 'not the vendor fix date or the time exposure began' in advisories.COVERAGE
    assert 'not evidence of exploitation' in advisories.COVERAGE


def _host():
    from app.db import Host, Session
    with Session() as s:
        if not s.get(Host, 'dated-host'):
            s.add(Host(id='dated-host', name='Dated target', address='192.0.2.12',
                       fingerprint='SHA256:' + 'c' * 43, state='online', inventory=INV))
            s.commit()


def test_route_returns_dates_and_reads_older_results(admin, monkeypatch):
    from app.db import Session, Setting
    _host()
    record = _record(published='2026-03-04T05:06:07Z')
    monkeypatch.setattr(advisories.httpx, 'post', lambda url, **kwargs: SimpleNamespace(
        raise_for_status=lambda: None, json=lambda: {'results': [{'vulns': [{'id': record['id']}]}]}))
    monkeypatch.setattr(advisories, '_fetch_records', lambda ids: {i: record for i in ids})
    fresh = admin.post('/api/operations/dated-host/advisories', json={'packages': ['libfoo1:amd64']})
    assert fresh.status_code == 200, fresh.text
    row = fresh.json()['results'][0]['applicability'][0]
    assert row['status'] == 'affected' and row['published_at'] == 1772600767.0 and row['modified_at'] is None

    # A result stored before #862 has no date keys and must still read unchanged.
    with Session() as s:
        stored = s.get(Setting, 'advisories:dated-host').value
        for key in ('published_at', 'modified_at'):
            stored['results'][0]['applicability'][0].pop(key)
        s.merge(Setting(key='advisories:dated-host', value=stored))
        s.commit()
    retained = admin.get('/api/operations/dated-host/advisories')
    assert retained.status_code == 200
    row = retained.json()['results'][0]['applicability'][0]
    assert row['status'] == 'affected' and 'published_at' not in row


APP_JS = (Path(__file__).resolve().parents[1] / 'app/static/app.js').read_text()


def _function(name):
    match = re.search(rf"function {name}\([^)]*\)\{{", APP_JS)
    assert match, f'{name} not found'
    depth = 0
    for index in range(match.end() - 1, len(APP_JS)):
        if APP_JS[index] == '{':
            depth += 1
        elif APP_JS[index] == '}':
            depth -= 1
            if depth == 0:
                return APP_JS[match.start():index + 1]
    raise AssertionError('incomplete')


@pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')
def test_panel_shows_publication_date_and_omits_unknown_dates():
    script = r"""
function esc(v){return String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
%s
%s
const row=(extra)=>({advisory_id:'UBUNTU-CVE-2026-0002',cve_ids:[],status:'affected',reason:'r',fixed_version:'1.2-4',...extra});
const render=a=>advisoryApplicability({summary:{},coverage:'c',results:[{binary:'libfoo1:amd64',package:{name:'foo'},version:'1.2-3',applicability:[a]}]});
console.log(JSON.stringify({
 dated:render(row({published_at:1772600767})),
 missing:render(row({})),
 bad:[render(row({published_at:'2026-03-04<script>'})),render(row({published_at:NaN})),render(row({published_at:-5}))],
}));
""" % (_function('advisoryDate'), _function('advisoryApplicability'))
    out = json.loads(subprocess.run(['node', '-e', script], check=True, capture_output=True, text=True).stdout)
    assert 'Fixed in 1.2-4 · Published 2026-03-04' in out['dated']
    assert 'Published' not in out['missing']
    for html in out['bad']:
        assert 'Published' not in html and '<script>' not in html
