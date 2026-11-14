"""Comparator exception text never reaches advisory results (#798, CodeQL alert #14)."""
from types import SimpleNamespace

import pytest

from app import advisories
from app import cve_exposure as ce

ECO = 'Ubuntu:24.04:LTS'
PKG = 'foo'
SECRET = "[Errno 2] No such file or directory: '/usr/bin/dpkg' at /srv/internal/path"
INV = {'os': 'ID=ubuntu\nVERSION_ID="24.04"',
       'status': 'Package: libfoo1\nArchitecture: amd64\nVersion: 1.2-3ubuntu1\nSource: foo\nStatus: install ok installed\n'}


def _record(advisory_id='UBUNTU-CVE-2026-0001', events=({'introduced': '0'}, {'fixed': '1.2-4'})):
    return {'id': advisory_id, 'aliases': ['CVE-2026-0001'], 'affected': [{
        'package': {'ecosystem': ECO, 'name': PKG},
        'ranges': [{'type': 'ECOSYSTEM', 'events': list(events)}]}]}


@pytest.mark.parametrize('error', [OSError(2, 'No such file or directory', '/srv/internal/path'),
                                   ValueError(SECRET), TypeError(SECRET), RuntimeError(SECRET)])
def test_comparator_exception_text_is_never_reported(error):
    def broken(_left, _right):
        raise error
    result = ce.classify(_record(), ECO, PKG, '1.2-3', compare=broken)
    assert result['status'] == ce.UNCERTAIN
    assert result['reason'] == 'Applicability could not be established: version comparison failed'
    assert '/srv/internal' not in result['reason'] and 'Errno' not in result['reason']


def test_fixed_validation_reasons_are_kept_and_actionable():
    malformed = ce.classify(_record(events=({'fixed': '1.0'},)), ECO, PKG, '1.2-3')
    assert malformed['status'] == ce.UNCERTAIN and malformed['reason'].endswith('range has no introduced event')
    syntax = ce.classify(_record(), ECO, PKG, 'v2.0')
    assert syntax['status'] == ce.UNCERTAIN and syntax['reason'].endswith('version does not have valid Debian version syntax')


def test_native_comparator_os_error_is_not_reported(monkeypatch):
    import app.debian_versions as dv

    def missing(*_args, **_kwargs):
        raise FileNotFoundError(2, 'No such file or directory', '/usr/bin/dpkg')
    monkeypatch.setattr(dv.subprocess, 'run', missing)
    result = ce.classify(_record(), ECO, PKG, '1.2-3')
    assert result['status'] == ce.UNCERTAIN
    assert result['reason'] == 'Applicability could not be established: version comparison failed'


def test_sanitize_reason_keeps_known_problems_and_replaces_unknown_text():
    prefix = 'Applicability could not be established: '
    assert ce.sanitize_reason(prefix + 'range has no introduced event; ' + SECRET) == (
        prefix + 'range has no introduced event; version comparison failed')
    assert ce.sanitize_reason(prefix + SECRET) == prefix + 'version comparison failed'
    for unchanged in ('Installed version is at or beyond the vendor fix', 'Advisory detail could not be retrieved', None):
        assert ce.sanitize_reason(unchanged) == unchanged


def _stub(monkeypatch, record):
    def post(url, **kwargs):
        return SimpleNamespace(raise_for_status=lambda: None,
                               json=lambda: {'results': [{'vulns': [{'id': record['id']}]}]})

    # Stub the detail fetch as a whole so this test is independent of its transport (#797).
    monkeypatch.setattr(advisories.httpx, 'post', post)
    monkeypatch.setattr(advisories, '_fetch_records', lambda ids: {i: record for i in ids})


def _host():
    from app.db import Host, Session
    with Session() as s:
        if not s.get(Host, 'exposure-host'):
            s.add(Host(id='exposure-host', name='Exposure target', address='192.0.2.11',
                       fingerprint='SHA256:' + 'b' * 43, state='online', inventory=INV))
            s.commit()


def test_fresh_and_retained_api_results_never_return_exception_text(admin, monkeypatch):
    import app.debian_versions as dv
    from app.db import Session, Setting
    _host()

    def missing(*_args, **_kwargs):
        raise FileNotFoundError(2, 'No such file or directory', SECRET)
    monkeypatch.setattr(dv.subprocess, 'run', missing)
    _stub(monkeypatch, _record())
    fresh = admin.post('/api/operations/exposure-host/advisories', json={'packages': ['libfoo1:amd64']})
    assert fresh.status_code == 200, fresh.text
    assert 'Errno' not in fresh.text and '/srv/internal' not in fresh.text
    row = fresh.json()['results'][0]['applicability'][0]
    assert row['status'] == 'uncertain' and row['reason'].endswith('version comparison failed')

    # A result stored before the fix still carries the raw text; reads must not return it.
    with Session() as s:
        stored = s.get(Setting, 'advisories:exposure-host').value
        stored['results'][0]['applicability'][0]['reason'] = (
            'Applicability could not be established: ' + SECRET)
        s.merge(Setting(key='advisories:exposure-host', value=stored))
        s.commit()
    retained = admin.get('/api/operations/exposure-host/advisories')
    assert retained.status_code == 200
    assert 'Errno' not in retained.text and '/srv/internal' not in retained.text
    row = retained.json()['results'][0]['applicability'][0]
    assert row['status'] == 'uncertain'
    assert row['reason'] == 'Applicability could not be established: version comparison failed'
