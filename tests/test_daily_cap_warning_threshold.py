"""Configurable daily-cap advance-warning threshold (#810)."""
from decimal import Decimal
import uuid

import pytest

from app import ai_budget, notifications, operations
from app.db import Audit, Session, Setting


DAY=1793404800.0  # 2026-10-31T00:00:00Z
BASE={'repo_minutes':60,'deadlines':{'critical':24,'high':72,'normal':168,'low':720}}


def configure(cap=Decimal('1'), mode='daily_cap', **extra):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'gpt-6-luna', 'ai_control_mode': mode,
            'ai_rate_per_hour': 20, 'ai_daily_cap_usd': float(cap), 'ai_budget_timezone': 'UTC'} | extra))
        session.commit()


def set_percent(value):
    with Session() as session:
        row=session.get(Setting, 'config');row.value={**row.value, 'ai_daily_cap_warning_percent': value};session.commit()


def ledger(amount, status='reserved'):
    with Session() as session:
        session.add(ai_budget.BudgetEntry(id=str(uuid.uuid4()), created=DAY+60, updated=DAY+60,
            reset_at=DAY+86400, timezone='UTC', model='gpt-6-luna', status=status,
            reservation_usd=Decimal(amount), pricing_version='fixture', pricing_source='fixture'))
        session.commit()


def warning(session):
    event=session.query(notifications.NotificationEvent).filter_by(source='ai-budget', kind='daily-cap-warning').one_or_none()
    return event, (session.get(notifications.NotificationRevision, (event.id, event.revision)) if event else None)


def cap_event(session):
    return session.query(notifications.NotificationEvent).filter_by(source='ai-budget', kind='daily-cap').one_or_none()


def test_default_threshold_is_80_and_keeps_the_existing_fingerprint(admin):
    state=admin.get('/api/settings').json()
    assert state['ai_daily_cap_warning_percent']==80
    configure()
    ledger('0.8')
    operations.collect_alerts(DAY+120)
    with Session() as session:
        event,revision=warning(session)
        # Pre-#810 fingerprint: upgrading must not republish an active warning as unread.
        assert revision.subject_revision=='nearing:UTC:'+repr(DAY+86400)+':1'
        assert 'at least 80% of the cap' in revision.reason


def test_lower_threshold_warns_earlier_and_names_the_percent(admin):
    configure(ai_daily_cap_warning_percent=50)
    ledger('0.49')
    operations.collect_alerts(DAY+120)
    with Session() as session:
        assert warning(session)[0] is None
    ledger('0.01')
    operations.collect_alerts(DAY+180)
    with Session() as session:
        event,revision=warning(session)
        assert revision.lifecycle=='active' and event.minimum_role=='admin'
        assert 'reached $0.5 of the shared daily cap of $1 (UTC day), at least 50% of the cap' in revision.reason
        assert revision.subject_revision.endswith(':threshold:50')
        assert cap_event(session) is None


def test_zero_turns_the_warning_off_and_resolves_an_active_one(admin):
    configure()
    ledger('0.9')
    operations.collect_alerts(DAY+120)
    with Session() as session:
        assert warning(session)[1].lifecycle=='active'
    set_percent(0)
    operations.collect_alerts(DAY+180)
    operations.collect_alerts(DAY+240)
    with Session() as session:
        event,revision=warning(session)
        assert event.revision==2 and revision.lifecycle=='resolved'
        assert 'warning threshold' in revision.reason
    # The exhausted-cap notification does not depend on the advance warning.
    ledger('0.1')
    operations.collect_alerts(DAY+300)
    with Session() as session:
        assert warning(session)[0].revision==2
        assert cap_event(session) is not None


def test_changing_the_threshold_re_evaluates_on_next_collection(admin):
    configure()
    ledger('0.85')
    operations.collect_alerts(DAY+120)
    set_percent(90)
    operations.collect_alerts(DAY+180)
    with Session() as session:
        event,revision=warning(session)
        assert event.revision==2 and revision.lifecycle=='resolved'
    set_percent(60)
    operations.collect_alerts(DAY+240)
    operations.collect_alerts(DAY+300)
    with Session() as session:
        event,revision=warning(session)
        assert event.revision==3 and revision.lifecycle=='active'
        assert 'at least 60% of the cap' in revision.reason


@pytest.mark.parametrize('stored', [-1, 100, '70', True, 7.5, None])
def test_invalid_stored_threshold_falls_back_to_default(admin, stored):
    configure(ai_daily_cap_warning_percent=stored)
    assert ai_budget.warning_percent({'ai_daily_cap_warning_percent': stored})==80
    ledger('0.8')
    operations.collect_alerts(DAY+120)
    with Session() as session:
        assert 'at least 80% of the cap' in warning(session)[1].reason


@pytest.mark.parametrize('endpoint', ['/api/settings/ai', '/api/settings'])
def test_settings_endpoints_save_validate_and_audit_the_threshold(admin, endpoint):
    extra=BASE if endpoint=='/api/settings' else {}
    # A stored explicit mode, so the first save does not apply the legacy migration default.
    configure(mode='rate', ai_enabled=False)
    before=admin.get('/api/settings').json()['ai_controls_revision']
    r=admin.put(endpoint, json=extra|{'ai_daily_cap_warning_percent': 65})
    assert r.status_code==200, r.text
    state=admin.get('/api/settings').json()
    assert state['ai_daily_cap_warning_percent']==65
    # Notification-only: the admission/spend optimistic-concurrency token is unchanged.
    assert state['ai_controls_revision']==before
    with Session() as session:
        assert any('daily AI cap warning changed from 80% to 65%' in row.detail for row in session.query(Audit))
    assert admin.put(endpoint, json=extra|{'ai_daily_cap_warning_percent': 0}).status_code==200
    with Session() as session:
        assert any('from 65% to off' in row.detail for row in session.query(Audit))
    # Omitting the field keeps the stored value.
    assert admin.put(endpoint, json=extra|{'ai_rate_per_hour': 21}).status_code==200
    assert admin.get('/api/settings').json()['ai_daily_cap_warning_percent']==0
    for bad in (-1, 100, 50.5, '60', True, None):
        assert admin.put(endpoint, json=extra|{'ai_daily_cap_warning_percent': bad}).status_code==422, bad
    assert admin.get('/api/settings').json()['ai_daily_cap_warning_percent']==0


def test_threshold_requires_admin(client):
    from app.identity import User
    with Session() as session:
        session.add(User(username='viewer', password='x', role='viewer'));session.commit()
    assert client.put('/api/settings/ai', json={'ai_daily_cap_warning_percent': 50}).status_code in (401, 403)


def test_threshold_does_not_change_admission(admin):
    configure(ai_daily_cap_warning_percent=10)
    ledger('0.5')
    with Session() as session:
        before=ai_budget.status(session, DAY+120)
    operations.collect_alerts(DAY+120)
    with Session() as session:
        assert ai_budget.status(session, DAY+120)==before
        assert session.query(ai_budget.BudgetEntry).count()==1
        assert not session.query(operations.Alert).filter(operations.Alert.kind.like('%cap%')).count()
