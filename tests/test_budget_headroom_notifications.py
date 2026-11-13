"""Daily-cap headroom below the smallest possible paid call (#819)."""
from decimal import Decimal
import uuid

import pytest

from app import ai, ai_budget, ai_pricing, budget_headroom_notifications as headroom, notifications, operations
from app.db import Session, Setting, config

DAY = 1793404800.0  # 2026-10-31T00:00:00Z, inside the bundled catalog window
MODEL = 'gpt-6-astra'  # $50/M output: the 1600-token floor is just over $0.08


def configure(mode='daily_cap', cap='0.1', model=MODEL, enabled=True):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': enabled, 'ai_model': model, 'ai_control_mode': mode, 'ai_rate_per_hour': 20,
            'ai_daily_cap_usd': float(Decimal(cap)), 'ai_budget_timezone': 'UTC'}))
        session.commit()


def ledger(amount, *, created=DAY + 60, status='reserved', reset=DAY + 86400):
    with Session() as session:
        session.add(ai_budget.BudgetEntry(id=str(uuid.uuid4()), created=created, updated=created,
            reset_at=reset, timezone='UTC', model=MODEL, status=status,
            reservation_usd=Decimal(amount), pricing_version='fixture', pricing_source='fixture'))
        session.commit()


def event(session, kind='daily-cap-headroom'):
    return session.query(notifications.NotificationEvent).filter_by(source='ai-budget', kind=kind).one_or_none()


def revision(session, item):
    return session.get(notifications.NotificationRevision, (item.id, item.revision))


def test_floor_is_a_lower_bound_for_every_billable_path():
    floor = headroom.minimum_call_reservation(MODEL, DAY)
    assert floor['ok'] and Decimal('0.08') < floor['amount_usd'] < Decimal('0.081')
    # Real requests: an investigation and the larger scoring/plan/release output bounds.
    investigation = ai.investigation_payload({'pid': 1, 'exe': '/usr/bin/true'}, MODEL)
    for output in (ai.INVESTIGATION_TOKENS, 4000, 12000):
        quote = ai_pricing.reservation({**investigation, 'max_output_tokens': output}, DAY)
        assert quote['ok'] and quote['amount_usd'] >= floor['amount_usd']
    assert not headroom.minimum_call_reservation('private-model', DAY)['ok']


def test_headroom_below_smallest_call_notifies_admins_once_per_window(admin):
    from app.identity import User
    with Session() as session:
        session.add(User(username='viewer', password='x', role='viewer'));session.commit()
    configure(cap='0.1')
    ledger('0.05')
    ledger('3', status='released')
    operations.collect_alerts(DAY + 120)
    with Session() as session:
        item = event(session);current = revision(session, item)
        assert item.minimum_role == 'admin' and item.host_id == ''
        assert current.lifecycle == 'active' and current.severity == 'medium'
        assert current.deep_link == '#settings/ai'
        assert 'Only $0.05 of the shared daily AI spend cap of $0.1 (UTC day) remains' in current.reason
        assert 'smallest conservative reservation of $0.08' in current.reason
        assert '2026-11-01T00:00:00Z' in current.reason and 'not a provider invoice' in current.reason
        assert MODEL not in current.reason
        # At 50% of the cap neither the warning nor the exhausted notice applies.
        assert event(session, 'daily-cap-warning') is None and event(session, 'daily-cap') is None
        assert notifications.list_for_user(session, 'viewer') == []
        notifications.mark_read(session, 'admin', item.id, item.revision, now=DAY + 130);session.commit()
        first = current.reason
    # Further spend in the same window is not a new observation.
    ledger('0.01', status='uncertain')
    operations.collect_alerts(DAY + 180)
    with Session() as session:
        item = event(session)
        assert item.revision == 1 and revision(session, item).reason == first
        assert notifications.unread_count(session, 'admin') == 0
        assert not session.query(operations.Alert).filter(operations.Alert.kind.like('%cap%')).count()
    # A later window that is again too small resurfaces as unread.
    ledger('0.05', created=DAY + 86400 + 100, reset=DAY + 2 * 86400)
    operations.collect_alerts(DAY + 86400 + 130)
    with Session() as session:
        item = event(session);current = revision(session, item)
        assert item.revision == 2 and current.lifecycle == 'active'
        assert '2026-11-02T00:00:00Z' in current.reason
        assert notifications.unread_count(session, 'admin') >= 1


def test_headroom_that_fits_the_smallest_call_is_silent(admin):
    configure(cap='0.1')
    ledger('0.019')
    operations.collect_alerts(DAY + 120)
    with Session() as session:
        assert event(session) is None


@pytest.mark.parametrize('change', ['reset', 'raise_cap', 'rate_mode', 'unthrottled', 'disabled',
                                    'reached', 'unpriced'])
def test_headroom_notice_resolves(admin, change):
    configure(cap='0.1')
    ledger('0.05')
    operations.collect_alerts(DAY + 120)
    now = DAY + 180
    if change == 'reset':now = DAY + 86400 + 10
    elif change == 'raise_cap':configure(cap='1')
    elif change == 'rate_mode':configure(mode='rate')
    elif change == 'unthrottled':configure(mode='unthrottled')
    elif change == 'disabled':configure(enabled=False)
    elif change == 'reached':ledger('0.05')
    else:configure(model='private-model')
    operations.collect_alerts(now)
    operations.collect_alerts(now + 60)
    with Session() as session:
        item = event(session)
        assert item.revision == 2 and revision(session, item).lifecycle == 'resolved'
        if change == 'reached':
            assert revision(session, event(session, 'daily-cap')).lifecycle == 'active'
        if change == 'unpriced':
            assert revision(session, event(session, 'unpriced-model')).lifecycle == 'active'


def test_producer_never_reserves_or_changes_the_ledger(admin):
    configure(mode='rate_and_daily', cap='0.1')
    ledger('0.05')
    with Session() as session:
        before = sorted((row.id, row.status, row.reservation_usd) for row in session.query(ai_budget.BudgetEntry))
        assert headroom.publish(session, config(session), DAY + 120) is True
        session.commit()
        after = sorted((row.id, row.status, row.reservation_usd) for row in session.query(ai_budget.BudgetEntry))
        assert before == after
