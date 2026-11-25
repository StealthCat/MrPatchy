"""Operational notification coverage for malformed per-server AI policies."""

import pytest
from sqlalchemy import select

from app import ai, ai_policy, notifications, operations
from app.db import Host, Session, Setting
from app.identity import User
from app.security import seal


NOW = 2_000_000_000.0
KIND = 'malformed-server-policy'
PRIVATE_VALUE = 'fixture-value-that-must-not-appear'


def seed():
    with Session() as session:
        session.add(User(username='viewer', password='x', role='viewer'))
        session.add(User(username='operator', password='x', role='operator'))
        session.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture-model'}))
        session.merge(Setting(key='openai_key', value={'encrypted': seal('fixture-key')}))
        for host in ('broken', 'paused', 'healthy', 'disabled', 'missing'):
            session.add(Host(id=host, name=host, address='192.0.2.1', fingerprint='',
                             enabled=host != 'disabled'))
        for host, value in (
            ('broken', {'paused': PRIVATE_VALUE}), ('paused', {'paused': True}),
            ('healthy', {}), ('disabled', [PRIVATE_VALUE]),
        ):
            session.add(Setting(key=ai_policy.PREFIX + host, value=value))
        session.commit()


def items(session, username='admin'):
    return [item for item in notifications.list_for_user(session, username) if item['kind'] == KIND]


def history(session):
    return list(session.scalars(select(notifications.NotificationRevision)
        .join(notifications.NotificationEvent,
              notifications.NotificationEvent.id == notifications.NotificationRevision.event_id)
        .where(notifications.NotificationEvent.kind == KIND)
        .order_by(notifications.NotificationRevision.revision)))


def test_collects_one_admin_repair_notice_and_reopens_after_recurrence(admin, monkeypatch):
    seed()
    monkeypatch.setattr(ai.transport, 'post', lambda *_args, **_kwargs: pytest.fail('Unexpected provider request'))
    operations.collect_alerts(NOW)
    operations.collect_alerts(NOW + 60)
    with Session() as session:
        [item] = items(session)
        assert item['host_id'] == 'broken' and item['deep_link'] == '#servers/broken/security'
        assert item['lifecycle'] == 'active' and item['severity'] == 'medium'
        assert 'repair' in item['reason'].lower()
        assert PRIVATE_VALUE not in str(item)
        assert items(session, 'viewer') == items(session, 'operator') == []
        assert len(history(session)) == 1
        assert session.scalar(select(operations.Alert.id).where(operations.Alert.kind == KIND)) is None
        notifications.mark_read(session, 'admin', item['id'], item['revision'], now=NOW + 61)
        session.commit()
    operations.collect_alerts(NOW + 120)
    with Session() as session:
        assert items(session)[0]['read'] is True

    fixed = admin.put('/api/hosts/broken/security/ai-policy', json={
        'paused': False, 'expected_revision': '', 'reason': 'Repair the malformed stored AI policy',
    })
    assert fixed.status_code == 200
    operations.collect_alerts(NOW + 180)
    operations.collect_alerts(NOW + 240)
    with Session() as session:
        assert [revision.lifecycle for revision in history(session)] == ['active', 'resolved']
        session.merge(Setting(key=ai_policy.PREFIX + 'broken', value=[PRIVATE_VALUE]))
        session.commit()
    operations.collect_alerts(NOW + 300)
    with Session() as session:
        [reopened] = items(session)
        assert reopened['id'] == item['id'] and reopened['read'] is False
        assert [revision.lifecycle for revision in history(session)] == ['active', 'resolved', 'active']
        assert PRIVATE_VALUE not in str(reopened)


@pytest.mark.parametrize('change', ['disable-ai', 'disable-server', 'delete-server'])
def test_resolves_when_ai_or_the_server_leaves_active_scope(admin, change):
    seed()
    operations.collect_alerts(NOW)
    with Session() as session:
        assert len(history(session)) == 1
        if change == 'disable-ai':
            cfg = session.get(Setting, 'config')
            cfg.value = {**cfg.value, 'ai_enabled': False}
        elif change == 'disable-server':
            session.get(Host, 'broken').enabled = False
        else:
            session.get(Host, 'broken').deleted_at = NOW + 1
        session.commit()
    operations.collect_alerts(NOW + 60)
    operations.collect_alerts(NOW + 120)
    with Session() as session:
        assert [revision.lifecycle for revision in history(session)] == ['active', 'resolved']


def test_repair_notice_revisions_are_independent_per_server(admin):
    seed()
    with Session() as session:
        session.merge(Setting(key=ai_policy.PREFIX + 'healthy', value={'paused': 0}))
        session.commit()
    operations.collect_alerts(NOW)
    with Session() as session:
        first = {item['host_id']: item for item in items(session)}
        assert first.keys() == {'broken', 'healthy'}
        assert first['broken']['id'] != first['healthy']['id']
        session.merge(Setting(key=ai_policy.PREFIX + 'broken', value={'paused': True}))
        session.commit()
    operations.collect_alerts(NOW + 60)
    with Session() as session:
        current = {item['host_id']: item for item in items(session)}
        assert current['broken']['lifecycle'] == 'resolved'
        assert current['healthy']['lifecycle'] == 'active'
        assert current['healthy']['revision'] == first['healthy']['revision']
