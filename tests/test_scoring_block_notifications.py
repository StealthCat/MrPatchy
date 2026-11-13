"""Update scoring blocks on non-transient AI failures and notifies administrators (#790)."""
import json
import time

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_provider_backoff, notifications, operations, scoring_block_notifications, update_scores
from app.db import Host, Package, Session, Setting
from app.identity import User
from app.security import seal


def seed(hosts=('one',)):
    with Session() as s:
        for host in hosts:
            s.add(Host(id=host, name=host, address='192.0.2.1', fingerprint='', state='online',
                       inventory={'os': 'ID=debian\nVERSION_ID=12'}))
            s.add(Package(id=host + ':fixture', host_id=host, name='fixture', installed='1', candidate='2',
                          available_since=time.time() - 3600))
        s.add(User(username='viewer', password='x', role='viewer'))
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_updates_enabled': True,
                                              'ai_model': 'fixture-model', 'ai_control_mode': 'unthrottled'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def rejected_key(*args, **kwargs):
    rejected_key.calls += 1
    return httpx.Response(401, json={'error': {'code': 'invalid_api_key', 'message': 'sk-leaked-secret'}},
                          request=httpx.Request('POST', ai.URL))


def success(*args, **kwargs):
    items = json.loads(kwargs['json']['input'])
    result = {'assessments': [{'id': item['id'], 'score': 50, 'confidence': 'low',
                               'explanation': 'Bounded fixture assessment.', 'limitations': 'None.'}
                              for item in items]}
    return httpx.Response(200, json={'status': 'completed', 'output': [{'content': [
        {'type': 'output_text', 'text': json.dumps(result)}]}]}, request=httpx.Request('POST', ai.URL))


def later(monkeypatch, seconds):
    """Move the scoring clock past the hourly retry gate."""
    base = time.time()
    monkeypatch.setattr(update_scores.time, 'time', lambda: base + seconds)


def states():
    with Session() as s:
        return {row.host_id: row.state for row in s.scalars(select(update_scores.UpdateScore))}


def revisions():
    with Session() as s:
        return [(r.revision, r.lifecycle, r.severity, r.subject_revision)
                for r in s.scalars(select(notifications.NotificationRevision)
                                   .join(notifications.NotificationEvent,
                                         notifications.NotificationEvent.id == notifications.NotificationRevision.event_id)
                                   .where(notifications.NotificationEvent.source == 'ai-scoring')
                                   .order_by(notifications.NotificationRevision.revision))]


def set_config(**changes):
    with Session() as s:
        row = s.get(Setting, 'config')
        row.value = {**row.value, **changes}
        s.commit()


@pytest.fixture
def blocked(admin, monkeypatch):
    seed()
    rejected_key.calls = 0
    monkeypatch.setattr(ai.transport, 'post', rejected_key)
    update_scores.run_one()
    assert rejected_key.calls == 1 and states() == {'one': 'blocked'}


def test_non_transient_failure_blocks_without_hourly_paid_retry(blocked, monkeypatch):
    with Session() as s:
        row = s.scalar(select(update_scores.UpdateScore))
        assert row.configuration and row.next_at == 0 and row.score is None
        assert 'No automatic retry is scheduled until the saved AI model or API key changes' in row.explanation
        assert 'sk-leaked-secret' not in row.explanation
    # Main retried the same failing batch one hour later; blocked scores send nothing.
    later(monkeypatch, 7200)
    update_scores.run_one()
    later(monkeypatch, 3 * 86400)
    update_scores.run_one()
    assert rejected_key.calls == 1 and states() == {'one': 'blocked'}


def test_model_or_key_change_unblocks_immediately(blocked, monkeypatch):
    with Session() as s:
        s.merge(Setting(key='openai_key', value={'encrypted': seal('replacement-key')}))
        s.commit()
    monkeypatch.setattr(ai.transport, 'post', success)
    update_scores.run_one()  # no one-hour wait after the configuration changes
    with Session() as s:
        row = s.scalar(select(update_scores.UpdateScore))
        assert row.state == 'complete' and row.score == 50 and row.configuration == ''


def test_transient_failure_keeps_existing_error_retry(admin, monkeypatch):
    seed()
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: httpx.Response(
        500, json={'error': {'code': 'server_error'}}, request=httpx.Request('POST', ai.URL)))
    monkeypatch.setattr(ai_provider_backoff, 'failed', lambda error: 0)
    update_scores.run_one()
    assert states() == {'one': 'error'}
    operations.collect_alerts(time.time())
    assert revisions() == []


@pytest.mark.parametrize('body', [
    {'status': 'incomplete', 'incomplete_details': {'reason': 'max_output_tokens'}},
    {'status': 'completed', 'output': [{'content': [{'type': 'refusal', 'refusal': 'declined'}]}]},
    {'status': 'completed', 'output': [{'content': [{'type': 'output_text', 'text': 'not json'}]}]},
    {'status': 'completed', 'output': [{'content': [{'type': 'output_text', 'text': '{"assessments": []}'}]}]},
])
def test_non_transient_result_failures_also_block(admin, monkeypatch, body):
    """AC1: every non-transient, non-policy AIError blocks, as process triage does."""
    seed()
    calls = []

    def reply(*args, **kwargs):
        calls.append(1)
        return httpx.Response(200, json=body, request=httpx.Request('POST', ai.URL))

    monkeypatch.setattr(ai.transport, 'post', reply)
    update_scores.run_one()
    assert states() == {'one': 'blocked'}
    with Session() as s:
        row = s.scalar(select(update_scores.UpdateScore))
        assert row.configuration and update_scores.BLOCKED_SUFFIX.strip() in row.explanation
    later(monkeypatch, 7200)
    update_scores.run_one()
    assert len(calls) == 1 and states() == {'one': 'blocked'}


def test_non_ai_exceptions_keep_existing_error_retry(admin, monkeypatch):
    seed()

    def explode(*args, **kwargs):
        raise RuntimeError('unexpected fixture failure')

    monkeypatch.setattr(ai, 'request', explode)
    update_scores.run_one()
    assert states() == {'one': 'error'}
    with Session() as s:
        assert s.scalar(select(update_scores.UpdateScore)).configuration == ''


def test_blocked_scoring_publishes_one_safe_admin_event_without_flooding(blocked, admin, monkeypatch):
    now = time.time()
    operations.collect_alerts(now)
    with Session() as s:
        items = [i for i in notifications.list_for_user(s, 'admin') if i['source'] == 'ai-scoring']
        assert [i for i in notifications.list_for_user(s, 'viewer') if i['source'] == 'ai-scoring'] == []
    assert len(items) == 1
    item = items[0]
    assert item['kind'] == 'configuration-blocked' and item['lifecycle'] == 'active'
    assert item['deep_link'] == '#settings/ai' and item['host_id'] == ''
    with Session() as s:
        signature = s.scalar(select(update_scores.UpdateScore)).configuration
    for text in ('sk-leaked', 'private-key', signature):
        assert text not in item['reason'] and text not in revisions()[0][3]
    # A second server blocking under the same configuration adds no revision.
    with Session() as s:
        s.add(Host(id='two', name='two', address='192.0.2.2', fingerprint='', state='online',
                   inventory={'os': 'ID=debian\nVERSION_ID=12'}))
        s.add(Package(id='two:fixture', host_id='two', name='fixture', installed='1', candidate='2',
                      available_since=now - 3600))
        s.commit()
    update_scores.run_one()
    assert states() == {'one': 'blocked', 'two': 'blocked'}
    operations.collect_alerts(now + 60)
    operations.collect_alerts(now + 120)
    assert [r[1] for r in revisions()] == ['active']


def test_configuration_change_resolves_once_and_a_new_block_reopens(blocked, monkeypatch):
    now = time.time()
    operations.collect_alerts(now)
    first = revisions()[0][3]
    set_config(ai_model='replacement-model')
    operations.collect_alerts(now + 60)
    operations.collect_alerts(now + 120)
    assert [r[1] for r in revisions()] == ['active', 'resolved']
    update_scores.run_one()  # the replacement configuration is rejected too
    assert rejected_key.calls == 2
    operations.collect_alerts(now + 180)
    history = revisions()
    assert [r[1] for r in history] == ['active', 'resolved', 'active'] and history[2][3] != first


@pytest.mark.parametrize('change', ['ai_disabled', 'scoring_disabled', 'paused', 'server_disabled', 'superseded'])
def test_blocked_scores_that_no_longer_matter_resolve_the_event(blocked, change):
    now = time.time()
    operations.collect_alerts(now)
    with Session() as s:
        if change == 'ai_disabled':
            row = s.get(Setting, 'config')
            row.value = {**row.value, 'ai_enabled': False}
        elif change == 'scoring_disabled':
            row = s.get(Setting, 'config')
            row.value = {**row.value, 'ai_updates_enabled': False}
        elif change == 'paused':
            s.merge(Setting(key='server-ai:one', value={'paused': True}))
        elif change == 'server_disabled':
            s.get(Host, 'one').enabled = False
        else:
            s.get(Package, 'one:fixture').candidate = '3'  # new evidence gets a new score identity
        s.commit()
    operations.collect_alerts(now + 60)
    assert [r[1] for r in revisions()] == ['active', 'resolved']


def test_publish_without_blocked_scores_creates_nothing(admin):
    seed()
    with Session() as s:
        cfg = s.get(Setting, 'config').value
        assert scoring_block_notifications.publish(s, cfg, time.time()) is False
        s.commit()
    assert revisions() == []
