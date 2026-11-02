"""Public enrollment downloads retain retries without unlimited installer generation."""
import time
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select

from app import main
from app.db import Audit, Session, Setting
from app.security import token_hash


@pytest.fixture
def download(admin, monkeypatch):
    host = admin.post('/api/hosts', json={'name': 'Enrollment target', 'address': '192.0.2.20'}).json()['id']
    link = admin.post(f'/api/hosts/{host}/enrollment-link').json()
    calls = []
    monkeypatch.setattr(main.ssh, 'bootstrap', lambda h: calls.append(h.id) or '#!/bin/bash\n# installer\n')
    return host, urlsplit(link['url']).path, calls


def test_reusable_link_is_throttled_before_generation(admin, download):
    _, path, calls = download
    responses = [admin.get(path) for _ in range(11)]
    assert [r.status_code for r in responses] == [200] * 10 + [429]
    assert 1 <= int(responses[-1].headers['Retry-After']) <= 60
    assert len(calls) == 10


def test_valid_downloads_audit_first_and_retry_without_bearer(admin, download):
    host, path, _ = download
    assert admin.get(path).status_code == 200
    assert admin.get(path).status_code == 200
    with Session() as s:
        events = s.scalars(select(Audit).where(Audit.action == 'enrollment installer prepared').order_by(Audit.id)).all()
        assert len(events) == 2
        assert all(host in event.detail for event in events)
        assert 'first' in events[0].detail and 'retry' in events[1].detail
        assert all(path not in event.detail and path.rsplit('/', 1)[-1] not in event.detail for event in events)


def test_invalid_tokens_share_the_source_limit(admin, download):
    _, path, calls = download
    assert [admin.get('/enroll/invalid-' + str(n)).status_code for n in range(10)] == [404] * 10
    assert admin.get(path).status_code == 429
    assert not calls


def test_quota_shared_by_links_and_not_bypassed_by_forwarding_headers(admin, download):
    host, path, calls = download
    other = urlsplit(admin.post(f'/api/hosts/{host}/enrollment-link').json()['url']).path
    for n in range(10):
        assert admin.get(path if n % 2 else other).status_code == 200
    result = admin.get(other, headers={'X-Forwarded-For': '198.51.100.22', 'Forwarded': 'for=198.51.100.22'})
    assert result.status_code == 429
    assert len(calls) == 10
    assert result.headers['Cache-Control'] == 'no-store'


def test_anonymous_distinct_source_and_persisted_controller_state(admin, download):
    from fastapi.testclient import TestClient
    from app import enrollment_downloads as downloads
    _, path, _ = download
    for _ in range(10):
        assert admin.get(path).status_code == 200
    # A fresh module/controller object cannot reset the database-backed quota.
    import importlib
    importlib.reload(downloads)
    with TestClient(main.app) as same:
        assert not same.cookies
        assert same.get(path).status_code == 429
    with TestClient(main.app, client=('198.51.100.22', 50000)) as other:
        assert not other.cookies
        assert other.get(path).status_code == 200


def test_window_reopens_without_consuming_link_or_extending_expiry(admin, download, monkeypatch):
    from app import enrollment_downloads as downloads
    _, path, calls = download
    now = time.time()
    monkeypatch.setattr(downloads.time, 'time', lambda: now)
    for _ in range(10):
        assert admin.get(path).status_code == 200
    assert admin.get(path).status_code == 429
    with Session() as s:
        expiry = s.get(Setting, 'enroll:' + token_hash(path.rsplit('/', 1)[-1])).value['expires']
    now += 60
    assert admin.get(path).status_code == 200
    assert len(calls) == 11
    with Session() as s:
        row = s.get(Setting, 'enroll:' + token_hash(path.rsplit('/', 1)[-1]))
        assert row.value['expires'] == expiry
        assert row.value['downloads'] == 11


@pytest.mark.parametrize('kind,expected', [('expired', 404), ('disabled', 410), ('deleted', 410)])
def test_invalid_lifecycle_never_prepares_or_audits(admin, download, kind, expected):
    from app.db import Host
    host, path, calls = download
    with Session() as s:
        if kind == 'expired':
            row = s.get(Setting, 'enroll:' + token_hash(path.rsplit('/', 1)[-1]))
            row.value = {**row.value, 'expires': time.time() - 1}
        else:
            h = s.get(Host, host)
            if kind == 'disabled':
                h.enabled = False
            else:
                h.deleted_at = time.time()
        s.commit()
    assert admin.get(path).status_code == expected
    assert not calls
    with Session() as s:
        assert not s.scalars(select(Audit).where(Audit.action == 'enrollment installer prepared')).all()


def test_generation_failure_is_not_recorded_as_a_prepared_download(admin, download, monkeypatch):
    _, path, _ = download
    def fail(host):
        raise ValueError('installer unavailable')
    monkeypatch.setattr(main.ssh, 'bootstrap', fail)
    assert admin.get(path).status_code == 400
    with Session() as s:
        row = s.get(Setting, 'enroll:' + token_hash(path.rsplit('/', 1)[-1]))
        assert not row.value.get('downloads')
        assert not s.scalars(select(Audit).where(Audit.action == 'enrollment installer prepared')).all()


def test_revocation_between_initial_read_and_lifecycle_fence(admin, download, monkeypatch):
    from contextlib import contextmanager
    _, path, calls = download
    original = main.host_lifecycle.activity
    @contextmanager
    def revoke(*args, **kwargs):
        with original(*args, **kwargs) as revision:
            with Session() as s:
                s.delete(s.get(Setting, 'enroll:' + token_hash(path.rsplit('/', 1)[-1]))); s.commit()
            yield revision
    monkeypatch.setattr(main.host_lifecycle, 'activity', revoke)
    assert admin.get(path).status_code == 404
    assert not calls


def test_rotating_sources_cannot_evict_active_quota_and_storage_recovers(admin, monkeypatch):
    from fastapi import HTTPException
    from app import enrollment_downloads as downloads
    monkeypatch.setattr(downloads, 'SOURCE_LIMIT', 2)
    now = time.time()
    monkeypatch.setattr(downloads.time, 'time', lambda: now)
    for _ in range(10):
        downloads.admit('source-a')
    downloads.admit('source-b')
    for source in ('source-c', 'source-a'):
        with pytest.raises(HTTPException) as error:
            downloads.admit(source)
        assert error.value.status_code == 429
        assert error.value.headers == {'Retry-After': '60'}
    with Session() as s:
        state = s.get(Setting, downloads.STATE_KEY).value
        assert len(state) == 2 and len(state['source-a']) == 10
    now += 60
    downloads.admit('source-c')
    with Session() as s:
        assert s.get(Setting, downloads.STATE_KEY).value == {'source-c': [now]}


def test_lock_contention_is_bounded_and_never_generates_installer(admin, download):
    from app.coordination import Lock
    _, path, calls = download
    with Lock('enrollment-download-rate'):
        result = admin.get(path)
    assert result.status_code == 503
    assert result.headers['Retry-After'] == '1'
    assert not calls


def test_parallel_requests_preserve_allowance_and_usage_numbers(admin, download):
    from concurrent.futures import ThreadPoolExecutor
    _, path, calls = download
    with ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(pool.map(lambda _: admin.get(path), range(24)))
    assert all(r.status_code in (200, 429, 503) for r in responses)
    accepted = sum(r.status_code == 200 for r in responses)
    assert 1 <= accepted <= 10
    assert len(calls) == accepted
    # Complete the remaining allowance after contention, then it stays closed.
    for _ in range(10 - accepted):
        assert admin.get(path).status_code == 200
    assert admin.get(path).status_code == 429
    with Session() as s:
        events = s.scalars(select(Audit).where(Audit.action == 'enrollment installer prepared').order_by(Audit.id)).all()
        assert len(events) == 10
        assert ['use=' + str(n) + ' ' in event.detail for n, event in enumerate(events, 1)] == [True] * 10


def test_lifecycle_fence_and_audit_use_canonical_persisted_identity(admin, download, monkeypatch):
    from contextlib import contextmanager
    host, path, calls = download
    alias = host.upper()
    key = 'enroll:' + token_hash(path.rsplit('/', 1)[-1])
    with Session() as s:
        row = s.get(Setting, key)
        row.value = {**row.value, 'host_id': alias}; s.commit()
    # Model MySQL's case-insensitive PK lookup while retaining SQLite coverage.
    resolve = main.host_or_404
    monkeypatch.setattr(main, 'host_or_404', lambda s, identifier: resolve(s, host if identifier == alias else identifier))
    activity = main.host_lifecycle.activity
    fenced = []
    @contextmanager
    def capture(ids, *args, **kwargs):
        fenced.extend(ids)
        with activity(ids, *args, **kwargs) as revisions:
            yield revisions
    monkeypatch.setattr(main.host_lifecycle, 'activity', capture)
    assert admin.get(path).status_code == 200
    assert fenced == [host] and calls == [host]
    with Session() as s:
        assert s.get(Setting, key).value['host_id'] == host
        event = s.scalar(select(Audit).where(Audit.action == 'enrollment installer prepared'))
        assert event.detail.startswith(host + ' ')
