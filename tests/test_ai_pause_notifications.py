"""Issue #868: admin-only coverage notification while a server's AI is paused."""
import pytest
from sqlalchemy import func, select

from app import ai_pause_notifications, ai_policy, notifications
from app.db import Host, Session, Setting
from app.identity import User

BASE = '/api/hosts/one/security/ai-policy'
REASON = 'Pause provider processing for review'


@pytest.fixture
def managed(admin):
    with Session() as s:
        s.add_all([Host(id=x, name=x + ' secret-name', address='192.0.2.1', fingerprint='', state='online')
                   for x in ('one', 'two')])
        s.add(Setting(key='config', value={'ai_enabled': True}))
        s.commit()
    return admin


def save(client, paused, *, reason=REASON, host='one', **changes):
    url = BASE.replace('one', host)
    current = client.get(url).json()
    body = {'paused': paused, 'expected_revision': current['revision'], 'reason': reason, **changes}
    return client.put(url, json=body)


def items(client):
    response = client.get('/api/notifications', params={'source': 'ai-pause', 'include_dismissed': True})
    assert response.status_code == 200, response.text
    return response.json()['items']


def revisions():
    with Session() as s:
        return s.scalar(select(func.count()).select_from(notifications.NotificationRevision).join(
            notifications.NotificationEvent,
            notifications.NotificationEvent.id == notifications.NotificationRevision.event_id).where(
            notifications.NotificationEvent.source == 'ai-pause'))


def test_pausing_publishes_one_admin_only_host_scoped_event(managed):
    assert save(managed, True, reason='Secret free-text pause reason').status_code == 200
    [item] = items(managed)
    assert item['lifecycle'] == 'active' and item['severity'] == 'low' and item['revision'] == 1
    assert item['host_id'] == 'one' and item['deep_link'] == '#servers/one/security'
    assert 'paused' in item['reason'] and 'authorizes nothing' in item['reason']
    # Fixed text only: no administrator reason, server name or actor.
    assert 'Secret' not in item['reason'] and 'secret-name' not in item['reason']
    with Session() as s:
        s.add_all([User(username='pause-viewer', password='x', role='viewer'),
                   User(username='pause-operator', password='x', role='operator')])
        s.commit()
        assert notifications.unread_count(s, 'pause-viewer') == 0
        assert notifications.unread_count(s, 'pause-operator') == 0
        assert notifications.unread_count(s, 'admin') == 1


def test_reaffirming_or_changing_capacity_while_paused_adds_no_revision(managed):
    assert save(managed, True).status_code == 200
    assert save(managed, True, reason='Reaffirm the pause after review').status_code == 200
    assert save(managed, True, concurrency_limit=3).status_code == 200
    assert revisions() == 1
    # Capacity changes on a resumed server never publish.
    assert save(managed, False, host='two', concurrency_limit=3).status_code == 200
    assert [item['host_id'] for item in items(managed)] == ['one']


def test_resume_resolves_and_repause_reopens_the_same_event(managed):
    assert save(managed, True).status_code == 200
    [first] = items(managed)
    assert managed.post('/api/notifications/' + first['id'] + '/read',
                        json={'revision': first['revision']}).status_code == 200
    assert save(managed, False, reason='Resume provider processing after review').status_code == 200
    [resolved] = items(managed)
    assert resolved['id'] == first['id'] and resolved['revision'] == 2
    assert resolved['lifecycle'] == 'resolved' and resolved['severity'] == 'info'
    assert 'resumed' in resolved['reason']
    # Resuming an already resumed server adds nothing.
    assert save(managed, False, reason='Reaffirm resumed state after review').status_code == 200
    assert revisions() == 2
    assert save(managed, True).status_code == 200
    [reopened] = items(managed)
    assert reopened['id'] == first['id'] and reopened['revision'] == 3
    assert reopened['lifecycle'] == 'active' and not reopened['read']


def test_rejected_saves_publish_nothing(managed):
    assert save(managed, True, expected_revision='stale').status_code == 400
    assert save(managed, True, reason='too short').status_code == 422
    assert revisions() == 0
    with Session() as s:
        host = s.get(Host, 'one')
        with pytest.raises(ValueError):
            ai_policy.save(s, host, True, 'stale', REASON, 'admin')
        s.rollback()
    assert revisions() == 0


def test_server_deletion_resolves_an_active_pause_event(managed, monkeypatch):
    from app import host_lifecycle
    monkeypatch.setattr(host_lifecycle, 'remove_credentials', lambda host_id: None)
    assert save(managed, True).status_code == 200
    record = managed.get('/api/hosts/one/summary').json()['host']
    response = managed.request('DELETE', '/api/hosts/one', json={
        'confirmation': record['name'], 'expected_revision': record['lifecycle_revision'],
        'reason': 'Remove management after reviewing operations and retained records.'})
    assert response.status_code == 200, response.text
    [item] = items(managed)
    assert item['lifecycle'] == 'resolved' and item['revision'] == 2 and 'deleted' in item['reason']
    with Session() as s:
        assert ai_pause_notifications.resolve_host_notification(s, 'one') is False
        assert ai_pause_notifications.resolve_host_notification(s, 'two') is False
    assert revisions() == 2
