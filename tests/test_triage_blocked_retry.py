"""Administrator retry for process investigations blocked on AI configuration (#934)."""
import time

import pytest
from sqlalchemy import select

from app import ai, ai_claims, ai_retry, notifications, operations, triage_block_notifications, worker
from app.db import Audit, Behavior, Host, Session, Setting
from test_operations import login_as
from test_triage_block_notifications import block_all, rejected_key, seed

RETRY = '/api/investigations/blocked/retry'
ACTION = 'retry blocked AI investigations'


def states():
    with Session() as s:
        retries = {r.subject: r.state for r in s.scalars(select(ai_retry.TriageRetry))}
        return {b.host_id: (b.verdict, retries.get(b.id)) for b in s.scalars(select(Behavior))}


def triage_revisions():
    with Session() as s:
        return [r.lifecycle for r in s.scalars(
            select(notifications.NotificationRevision)
            .join(notifications.NotificationEvent,
                  notifications.NotificationEvent.id == notifications.NotificationRevision.event_id)
            .where(notifications.NotificationEvent.source == 'ai-triage',
                   notifications.NotificationEvent.kind == 'configuration-blocked')
            .order_by(notifications.NotificationRevision.revision))]


def blocked_now():
    with Session() as s:
        return triage_block_notifications.blocked_count(s, time.time())[0]


@pytest.fixture
def blocked(admin, monkeypatch):
    seed(('one', 'two'))
    block_all(monkeypatch, 2)
    assert blocked_now() == 2
    return admin


def test_retry_requeues_blocked_investigations_without_a_provider_call(blocked, monkeypatch):
    operations.collect_alerts(time.time())
    assert triage_revisions() == ['active']
    calls = []
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: calls.append(1) or rejected_key())
    reply = blocked.post(RETRY)
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert body['retried'] == 2 and body['remaining'] == 0 and '2 blocked investigations queued' in body['detail']
    assert calls == []
    assert states() == {'one': ('pending', None), 'two': ('pending', None)}
    with Session() as s:
        rows = list(s.scalars(select(Behavior)))
        assert all(r.attempted == 0 and r.analysis == triage_block_notifications.RETRY_ANALYSIS for r in rows)
        entries = list(s.scalars(select(Audit).where(Audit.action == ACTION)))
        assert len(entries) == 1 and 're-queued 2 blocked investigation' in entries[0].detail
    assert blocked.get('/api/investigation-status').json()['blocked'] == 0
    operations.collect_alerts(time.time() + 60)
    assert triage_revisions() == ['active', 'resolved']


def test_repeat_failure_blocks_again_and_resurfaces_the_notification(blocked, monkeypatch):
    operations.collect_alerts(time.time())
    assert blocked.post(RETRY).json()['retried'] == 2
    operations.collect_alerts(time.time() + 60)
    monkeypatch.setattr(ai.transport, 'post', rejected_key)
    worker.investigate_one()  # the provider still rejects the same model and key
    worker.investigate_one()
    assert blocked_now() == 2
    operations.collect_alerts(time.time() + 120)
    assert triage_revisions() == ['active', 'resolved', 'active']


@pytest.mark.parametrize('change', ['paused', 'server_disabled', 'server_deleted', 'approved', 'old_signature',
                                    'running', 'provider_wait'])
def test_retry_leaves_out_of_scope_blocked_rows_unchanged(blocked, change):
    with Session() as s:
        row = s.get(Behavior, 'subject-two')
        retry = s.get(ai_retry.TriageRetry, 'subject-two')
        if change == 'paused':
            s.merge(Setting(key='server-ai:two', value={'paused': True}))
        elif change == 'server_disabled':
            s.get(Host, 'two').enabled = False
        elif change == 'server_deleted':
            s.get(Host, 'two').deleted_at = time.time()
        elif change == 'approved':
            row.approved = True
        elif change == 'old_signature':
            retry.configuration = 'earlier-signature'
        elif change == 'running':
            s.add(ai_claims.Claim(subject=row.id, host_id='two', token='t', worker_id='w', boot_id='b',
                                  run_id='r', revision='x', configuration='c', created=time.time(),
                                  renewed=time.time(), expires=time.time() + 600))
        else:
            retry.provider_until = time.time() + 600
        before = (row.verdict, row.analysis, retry.state, retry.configuration)
        s.commit()
    body = blocked.post(RETRY).json()
    assert body['retried'] == 1
    assert body['remaining'] == (1 if change in ('running', 'provider_wait') else 0)
    with Session() as s:
        row = s.get(Behavior, 'subject-two')
        retry = s.get(ai_retry.TriageRetry, 'subject-two')
        assert (row.verdict, row.analysis, retry.state, retry.configuration) == before
        assert s.get(Behavior, 'subject-one').verdict == 'pending'
        assert s.get(ai_retry.TriageRetry, 'subject-one') is None


def test_nothing_blocked_or_ai_disabled_retries_nothing_and_writes_no_audit(blocked):
    with Session() as s:
        row = s.get(Setting, 'config')
        row.value = {**row.value, 'ai_enabled': False}
        s.commit()
    body = blocked.post(RETRY).json()
    assert body == {'retried': 0, 'remaining': 0,
                    'detail': 'No investigation can be retried now under the current AI configuration.'}
    assert {state for _, state in states().values()} == {'blocked'}
    with Session() as s:
        assert s.scalar(select(Audit).where(Audit.action == ACTION)) is None


def test_batches_are_bounded_and_report_the_remainder(blocked, monkeypatch):
    monkeypatch.setattr(triage_block_notifications.retry_candidates, '__defaults__', (1, None, None))
    first = blocked.post(RETRY).json()
    assert first['retried'] == 1 and first['remaining'] == 1 and '1 still blocked' in first['detail']
    second = blocked.post(RETRY).json()
    assert second['retried'] == 1 and second['remaining'] == 0


def test_retry_refuses_while_the_triage_lock_is_held(blocked):
    lock = worker.Lock('ai-triage')
    assert lock.acquire(False)
    try:
        assert blocked.post(RETRY).status_code == 409
    finally:
        lock.release()
    assert blocked_now() == 2


@pytest.mark.parametrize('role', ['viewer', 'operator'])
def test_retry_requires_an_administrator(blocked, role):
    blocked.post('/api/logout')
    login_as(blocked, 'reader-' + role, role)
    assert blocked.post(RETRY).status_code == 403
    assert blocked_now() == 2


# Per-server retry from a server's Investigations tab (#946).
HOST_RETRY = '/api/hosts/{}/investigations/blocked/retry'
HOST_COUNT = '/api/hosts/{}/investigations/blocked'


def test_host_count_is_scoped_to_one_server(blocked):
    assert blocked.get(HOST_COUNT.format('one')).json() == {'blocked': 1}
    assert blocked.get(HOST_COUNT.format('two')).json() == {'blocked': 1}
    assert blocked.get(HOST_COUNT.format('missing')).status_code == 404
    with Session() as s:
        row = s.get(Setting, 'config')
        row.value = {**row.value, 'ai_enabled': False}
        s.commit()
    assert blocked.get(HOST_COUNT.format('one')).json() == {'blocked': 0}


def test_host_retry_requeues_only_that_server_without_a_provider_call(blocked, monkeypatch):
    calls = []
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: calls.append(1) or rejected_key())
    reply = blocked.post(HOST_RETRY.format('one'))
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert body['retried'] == 1 and body['remaining'] == 0 and '1 blocked investigation queued' in body['detail']
    assert calls == []
    assert states() == {'one': ('pending', None), 'two': ('error', 'blocked')}
    assert blocked_now() == 1
    assert blocked.get(HOST_COUNT.format('one')).json() == {'blocked': 0}
    with Session() as s:
        entries = list(s.scalars(select(Audit).where(Audit.action == ACTION)))
        assert len(entries) == 1 and entries[0].detail.endswith('re-queued 1 blocked investigation(s) on one')


def test_host_retry_of_a_paused_server_retries_nothing(blocked):
    with Session() as s:
        s.merge(Setting(key='server-ai:one', value={'paused': True}))
        s.commit()
    body = blocked.post(HOST_RETRY.format('one')).json()
    assert body['retried'] == 0 and body['remaining'] == 0
    assert states() == {'one': ('error', 'blocked'), 'two': ('error', 'blocked')}
    with Session() as s:
        assert s.scalar(select(Audit).where(Audit.action == ACTION)) is None


def test_host_retry_rejects_unknown_servers_and_honours_the_triage_lock(blocked):
    assert blocked.post(HOST_RETRY.format('missing')).status_code == 404
    lock = worker.Lock('ai-triage')
    assert lock.acquire(False)
    try:
        assert blocked.post(HOST_RETRY.format('one')).status_code == 409
    finally:
        lock.release()
    assert blocked_now() == 2


@pytest.mark.parametrize('role', ['viewer', 'operator'])
def test_host_routes_require_an_administrator(blocked, role):
    blocked.post('/api/logout')
    login_as(blocked, 'reader-' + role, role)
    assert blocked.get(HOST_COUNT.format('one')).status_code == 403
    assert blocked.post(HOST_RETRY.format('one')).status_code == 403
    assert blocked_now() == 2
