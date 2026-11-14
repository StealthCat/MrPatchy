import pytest
from sqlalchemy import select

from app import ai, ai_control_status, ai_credential_notifications, notifications, operations
from app.db import Session, Setting
from app.identity import User
from app.security import seal

NOW = 2_000_000_000.0
FOREIGN = 'gAAAAABforeign-ciphertext-from-another-controller-secret-key'


def seed(encrypted=None, *, enabled=True):
    with Session() as s:
        s.add(User(username='viewer', password='x', role='viewer'))
        s.merge(Setting(key='config', value={'ai_enabled': enabled, 'ai_model': 'fixture-model'}))
        if encrypted is not None:
            s.merge(Setting(key='openai_key', value=encrypted))
        s.commit()


def set_key(value):
    with Session() as s:
        if value is None:
            row = s.get(Setting, 'openai_key')
            if row is not None:
                s.delete(row)
        else:
            s.merge(Setting(key='openai_key', value=value))
        s.commit()


def revisions():
    with Session() as s:
        return [(r.revision, r.lifecycle, r.severity, r.subject_revision, r.reason)
                for r in s.scalars(select(notifications.NotificationRevision)
                                   .join(notifications.NotificationEvent,
                                         notifications.NotificationEvent.id == notifications.NotificationRevision.event_id)
                                   .where(notifications.NotificationEvent.kind == 'unreadable-key')
                                   .order_by(notifications.NotificationRevision.revision))]


def test_undecryptable_key_publishes_one_safe_admin_event_without_duplicates(admin):
    seed({'encrypted': FOREIGN})
    operations.collect_alerts(NOW)
    operations.collect_alerts(NOW + 60)
    history = revisions()
    assert [(r[1], r[2]) for r in history] == [('active', 'high')]
    assert history[0][3].startswith('unreadable:')
    with Session() as s:
        items = [item for item in notifications.list_for_user(s, 'admin') if item['kind'] == 'unreadable-key']
        assert [item['kind'] for item in notifications.list_for_user(s, 'viewer')] == []
    assert len(items) == 1
    item = items[0]
    assert item['source'] == 'ai-credential' and item['deep_link'] == '#settings/ai' and item['host_id'] == ''
    assert 'decrypted' in item['reason']
    # Fixed text only: no ciphertext, digest or exception text.
    rendered = str(items) + str(history)
    assert FOREIGN not in rendered and 'InvalidToken' not in rendered


@pytest.mark.parametrize('value,code', [(None, 'missing'), ({'encrypted': ''}, 'unreadable'),
                                        ({'other': 'x'}, 'unreadable'), ('not-a-dict', 'unreadable')])
def test_missing_or_malformed_key_rows_are_reported(admin, value, code):
    seed()
    set_key(value)
    operations.collect_alerts(NOW)
    history = revisions()
    assert [r[1] for r in history] == ['active']
    assert history[0][3].split(':')[0] == code
    assert ('no API key is saved' in history[0][4]) == (code == 'missing')


def test_readable_key_publishes_nothing(admin):
    seed({'encrypted': seal('private-key')})
    operations.collect_alerts(NOW)
    assert revisions() == []
    with Session() as s:
        assert ai_credential_notifications.state(s)[0] == 'ok'


@pytest.mark.parametrize('recovery', ['resaved', 'disabled'])
def test_recovery_resolves_once_and_a_new_failing_key_reopens(admin, recovery):
    seed({'encrypted': FOREIGN})
    operations.collect_alerts(NOW)
    first = revisions()[0][3]
    if recovery == 'resaved':
        set_key({'encrypted': seal('private-key')})
    else:
        with Session() as s:
            row = s.get(Setting, 'config')
            row.value = {**row.value, 'ai_enabled': False}
            s.commit()
    operations.collect_alerts(NOW + 60)
    operations.collect_alerts(NOW + 120)
    assert [r[1] for r in revisions()] == ['active', 'resolved']

    with Session() as s:
        row = s.get(Setting, 'config')
        row.value = {**row.value, 'ai_enabled': True}
        s.commit()
    set_key({'encrypted': FOREIGN + 'different'})
    operations.collect_alerts(NOW + 180)
    history = revisions()
    assert [r[1] for r in history] == ['active', 'resolved', 'active']
    assert history[2][3] != first


def test_new_failing_key_while_active_publishes_a_new_unread_revision(admin):
    seed({'encrypted': FOREIGN})
    operations.collect_alerts(NOW)
    with Session() as s:
        item = next(i for i in notifications.list_for_user(s, 'admin') if i['kind'] == 'unreadable-key')
        assert notifications.mark_read(s, 'admin', item['id'], item['revision'])
        s.commit()
    set_key({'encrypted': FOREIGN + 'replacement'})
    operations.collect_alerts(NOW + 60)
    assert [r[1] for r in revisions()] == ['active', 'active']
    with Session() as s:
        assert any(i['kind'] == 'unreadable-key' and not i['read'] for i in notifications.list_for_user(s, 'admin'))


def test_disabled_ai_with_unreadable_key_publishes_nothing(admin):
    seed({'encrypted': FOREIGN}, enabled=False)
    operations.collect_alerts(NOW)
    assert revisions() == []


def test_producer_never_calls_a_provider_or_reserves_spend(admin, monkeypatch):
    seed({'encrypted': FOREIGN})

    def forbidden(*args, **kwargs):
        raise AssertionError('provider call attempted')
    monkeypatch.setattr(ai.transport, 'post', forbidden)
    operations.collect_alerts(NOW)
    from app import ai_budget
    with Session() as s:
        assert s.scalar(select(ai_budget.BudgetEntry.id).limit(1)) is None


def test_control_status_reports_unreadable_key_without_ciphertext(admin):
    seed({'encrypted': FOREIGN})
    with Session() as s:
        result = ai_control_status.snapshot(s, NOW)
    assert not result['can_start_now']
    assert [b['code'] for b in result['blockers']] == ['credential']
    assert result['next_start_at'] is None
    assert FOREIGN not in str(result)

    set_key({'encrypted': seal('private-key')})
    with Session() as s:
        result = ai_control_status.snapshot(s, NOW)
    assert 'credential' not in [b['code'] for b in result['blockers']]

