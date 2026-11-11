import json

import httpx
import pytest
from sqlalchemy import func, select

from app import ai, ai_assessments, notifications, triage_notifications, worker
from app.db import Behavior, Host, Session, Setting
from app.identity import User
from app.security import seal


def seed(verdict='pending'):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint=''))
        s.add(Behavior(id='subject', host_id='one', verdict=verdict, analysis='Awaiting',
                       evidence={'executable': '/srv/\x1bfixture<script>', 'sha256': 'a' * 64,
                                 'uid': '1000', 'identity_verified': True}))
        s.add(User(username='viewer', password='x', role='viewer'))
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture-model'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def provider(risk):
    result = {'risk': risk, 'explanation': 'Model text <img src=x> \x07', 'recommended_checks': 'Check',
              'requested_checks': []}
    return httpx.Response(200, json={'status': 'completed', 'output': [{'content': [
        {'type': 'output_text', 'text': json.dumps(result)}]}]}, request=httpx.Request('POST', ai.URL))


def retriage(admin):
    revision = admin.get('/api/investigations/subject/history').json()['current']['revision']
    response = admin.post('/api/investigations/subject/retriage',
                          json={'expected_revision': revision, 'reason': 'Review changed context'})
    assert response.status_code == 200


def history():
    with Session() as s:
        return [(r.revision, r.severity, r.lifecycle, r.subject_revision, r.reason, r.deep_link)
                for r in s.scalars(select(notifications.NotificationRevision)
                                   .order_by(notifications.NotificationRevision.revision))]


def viewer_items():
    with Session() as s:
        return notifications.list_for_user(s, 'viewer')


def test_significant_verdict_publishes_safe_viewer_event_and_unchanged_risk_does_not_flood(admin, monkeypatch):
    seed()
    risks = iter(['high', 'high', 'medium', 'high'])
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: provider(next(risks)))
    worker.investigate_one()
    items = viewer_items()
    assert len(items) == 1
    item = items[0]
    assert item['source'] == 'ai-triage' and item['kind'] == 'process-verdict'
    assert item['severity'] == 'high' and item['host_id'] == 'one' and item['lifecycle'] == 'active'
    assert item['deep_link'] == '#servers/one/investigations'
    assert 'advisory' in item['reason'] and 'authorize' in item['reason']
    # Neither the attacker-influenced path nor model output reaches the payload.
    assert 'fixture' not in item['reason'] and 'Model text' not in item['reason']
    with Session() as s:
        assert notifications.mark_read(s, 'viewer', item['id'], item['revision'])
        s.commit()

    retriage(admin)
    worker.investigate_one()  # unchanged high: no new revision, stays read
    assert len(history()) == 1
    assert viewer_items()[0]['read'] is True

    retriage(admin)
    worker.investigate_one()  # medium: changed risk resurfaces
    retriage(admin)
    worker.investigate_one()  # back to high: escalation resurfaces
    assert [(r[0], r[1], r[2]) for r in history()] == [
        (1, 'high', 'active'), (2, 'medium', 'active'), (3, 'high', 'active')]
    assert viewer_items()[0]['read'] is False
    with Session() as s:
        assert s.get(Behavior, 'subject').approved is False


def test_low_resolves_active_event_and_significant_verdict_reopens(admin, monkeypatch):
    seed()
    risks = iter(['medium', 'low', 'low', 'unknown', 'high'])
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: provider(next(risks)))
    worker.investigate_one()
    retriage(admin)
    worker.investigate_one()
    assert [(r[1], r[2]) for r in history()] == [('medium', 'active'), ('info', 'resolved')]
    retriage(admin)
    worker.investigate_one()  # already resolved: nothing new
    retriage(admin)
    worker.investigate_one()  # unknown: leaves state unchanged
    assert len(history()) == 2
    retriage(admin)
    worker.investigate_one()
    assert [(r[1], r[2]) for r in history()][-1] == ('high', 'active')


@pytest.mark.parametrize('risk', ['low', 'unknown'])
def test_insignificant_first_verdict_publishes_nothing(admin, monkeypatch, risk):
    seed()
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: provider(risk))
    worker.investigate_one()
    assert history() == []


def test_rolled_back_verdict_save_announces_nothing(admin, monkeypatch):
    seed()
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: provider('high'))

    def fail(*a, **k):
        raise RuntimeError('private transaction details')
    monkeypatch.setattr(ai_assessments, 'record', fail)
    worker.investigate_one()
    with Session() as s:
        assert s.get(Behavior, 'subject').verdict == 'error'
        assert s.scalar(select(func.count()).select_from(notifications.NotificationEvent)) == 0
        assert s.scalar(select(func.count()).select_from(notifications.NotificationArrival)) == 0


def test_known_good_style_low_reuse_resolves_only_existing_events(admin):
    seed(verdict='low')
    with Session() as s:
        row = s.get(Behavior, 'subject')
        assert triage_notifications.publish_verdict(s, row, now=1) is False
        row.verdict = 'high'
        assert triage_notifications.publish_verdict(s, row, now=2) is True
        row.verdict = 'low'
        assert triage_notifications.publish_verdict(s, row, now=3) is True
        assert triage_notifications.publish_verdict(s, row, now=4) is False
        s.commit()
    assert [(r[1], r[2]) for r in history()] == [('high', 'active'), ('info', 'resolved')]


def test_events_are_per_behavior_and_host(admin):
    seed()
    with Session() as s:
        s.add(Host(id='two', name='two', address='192.0.2.2', fingerprint=''))
        s.add(Behavior(id='other', host_id='two', verdict='high', evidence={}))
        s.flush()
        for row in s.scalars(select(Behavior)):
            row.verdict = 'high'
            triage_notifications.publish_verdict(s, row)
        s.commit()
    assert sorted(item['host_id'] for item in viewer_items()) == ['one', 'two']
