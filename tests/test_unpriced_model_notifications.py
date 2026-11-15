"""Capped AI admission blocked by an unpriced saved model (#735)."""
import pytest

from app import ai_control_status, ai_pricing, notifications, operations
from app.db import Session, Setting, config
from app.identity import User
from app.security import seal

NOW = 1_794_441_600.0  # 2026-11-12T00:00:00Z, inside the bundled catalog's validity window.
EXPIRED = ai_pricing.EXPIRES_AT + 60
LINK = '#settings/ai'


def configure(*, model='gpt-5', mode='daily_cap', enabled=True):
    with Session() as session:
        session.merge(Setting(key='config', value={**config(session), 'ai_enabled': enabled, 'ai_model': model,
                                                    'ai_control_mode': mode, 'ai_daily_cap_usd': 5.0,
                                                    'ai_budget_timezone': 'UTC'}))
        session.merge(Setting(key='openai_key', value={'encrypted': seal('fixture')}))
        if not session.get(User, 'viewer'):
            session.add(User(username='viewer', password='x', role='viewer'))
        session.commit()


def current():
    with Session() as session:
        events = session.query(notifications.NotificationEvent).filter_by(
            source='ai-budget', kind='unpriced-model').all()
        if not events:
            return None, None
        assert len(events) == 1
        event = events[0]
        revision = session.get(notifications.NotificationRevision, (event.id, event.revision))
        session.expunge_all()
        return event, revision


# The clock is explicit and the bundled window is the subject under test, so opt out of the #742 fresh-catalog pin.
@pytest.mark.bundled_pricing_catalog
def test_model_status_is_alias_aware_and_fails_closed():
    assert ai_pricing.model_status('gpt-6-luna', NOW) == {'ok': True, 'code': '', 'model': 'gpt-6-luna', 'reason': ''}
    assert ai_pricing.model_status('gpt-5-mini-2025-08-07', NOW)['model'] == 'gpt-5-mini'
    unpriced = ai_pricing.model_status('gpt-5', NOW)
    assert not unpriced['ok'] and unpriced['code'] == 'model' and unpriced['model'] == 'gpt-5'
    assert unpriced['reason'] == ai_pricing.UNPRICED_MODEL_REASON
    invalid = ai_pricing.model_status('bad model <id>', NOW)
    assert not invalid['ok'] and invalid['code'] == 'model' and invalid['model'] == ''
    for when in (EXPIRED, ai_pricing.VERIFIED_AT - 1):
        stale = ai_pricing.model_status('gpt-6-luna', when)
        assert not stale['ok'] and stale['code'] == 'catalog'
    # The per-call reservation refuses the same model with the same fixed reason.
    refused = ai_pricing.reservation({'model': 'gpt-5', 'max_output_tokens': 10, 'input': 'x'}, NOW)
    assert not refused['ok'] and refused['reason'] == ai_pricing.UNPRICED_MODEL_REASON


@pytest.mark.parametrize('mode', ['daily_cap', 'rate_and_daily'])
def test_snapshot_reports_indefinite_pricing_gate_in_cap_modes(admin, mode):
    configure(mode=mode)
    with Session() as session:
        result = ai_control_status.snapshot(session, NOW)
    assert not result['can_start_now'] and result['next_start_at'] is None
    pricing = [item for item in result['blockers'] if item['code'] == 'pricing']
    assert len(pricing) == 1 and pricing[0]['next_at'] is None and pricing[0]['recheck_at'] is None
    assert pricing[0]['message'] == ai_control_status.PRICING_MESSAGES['model']
    assert 'gpt-5' not in str(result)


# The clock is explicit and the bundled window is the subject under test, so opt out of the #742 fresh-catalog pin.
@pytest.mark.bundled_pricing_catalog
def test_snapshot_reports_stale_catalog_and_omits_gate_when_priced_or_uncapped(admin):
    configure(model='gpt-6-luna')
    with Session() as session:
        assert ai_control_status.snapshot(session, NOW)['blockers'] == []
        stale = ai_control_status.snapshot(session, EXPIRED)
    assert [item['code'] for item in stale['blockers']] == ['pricing']
    assert stale['blockers'][0]['message'] == ai_control_status.PRICING_MESSAGES['catalog']
    for mode in ('rate', 'unthrottled', 'legacy'):
        configure(mode=mode)
        with Session() as session:
            assert not [item for item in ai_control_status.snapshot(session, NOW)['blockers'] if item['code'] == 'pricing']
    # Without a saved model the existing configuration gate already explains the hold.
    configure(model='')
    with Session() as session:
        codes = [item['code'] for item in ai_control_status.snapshot(session, NOW)['blockers']]
    assert 'configuration' in codes and 'pricing' not in codes


def test_snapshot_pricing_gate_requires_enabled_ai(admin):
    # #735 criterion 2: disabled AI reports only the `disabled` gate, and enabling
    # AI with the same unpriced model in a cap mode surfaces the pricing gate.
    configure(enabled=False)
    with Session() as session:
        disabled = ai_control_status.snapshot(session, NOW)
    assert [item['code'] for item in disabled['blockers']] == ['disabled']
    configure(enabled=True)
    with Session() as session:
        enabled = ai_control_status.snapshot(session, NOW)
    assert [item['code'] for item in enabled['blockers']] == ['pricing']
    assert not enabled['can_start_now'] and enabled['next_start_at'] is None


def test_unpriced_model_notifies_once_dedupes_and_is_admin_only(admin):
    configure()
    operations.collect_alerts(NOW)
    event, revision = current()
    assert event.revision == 1 and event.minimum_role == 'admin' and event.host_id == ''
    assert revision.lifecycle == 'active' and revision.severity == 'high' and revision.deep_link == LINK
    assert 'saved model gpt-5' in revision.reason and ai_pricing.VERSION in revision.reason
    assert 'No provider request is sent' in revision.reason
    assert 'gpt-5' not in revision.subject_revision and 'fixture' not in revision.reason
    operations.collect_alerts(NOW + 60)
    operations.collect_alerts(NOW + 120)
    assert current()[0].revision == 1
    with Session() as session:
        assert notifications.unread_count(session, 'admin') >= 1
        assert notifications.unread_count(session, 'viewer') == 0
        assert not any(item['source'] == 'ai-budget' for item in notifications.list_for_user(session, 'viewer'))
        # In-app only: no SMTP/webhook alert row.
        assert not session.query(operations.Alert).filter(operations.Alert.message.like('%unpriced%')).count()
        assert not session.query(operations.Alert).filter(operations.Alert.message.like('%saved model%')).count()


def test_changing_to_another_unpriced_model_resurfaces_as_unread(admin):
    configure()
    operations.collect_alerts(NOW)
    event, _ = current()
    with Session() as session:
        notifications.mark_read(session, 'admin', event.id, event.revision, now=NOW + 1)
        session.commit()
    configure(model='ft:gpt-6-luna:org:custom:abc')
    operations.collect_alerts(NOW + 60)
    event, revision = current()
    assert event.revision == 2 and revision.lifecycle == 'active'
    assert 'ft:gpt-6-luna:org:custom:abc' in revision.reason


def test_invalid_model_identifier_is_not_echoed(admin):
    configure(model='bad model <script>')
    operations.collect_alerts(NOW)
    _, revision = current()
    assert 'saved model ID:' in revision.reason and '<script>' not in revision.reason


@pytest.mark.parametrize('change', ['priced', 'rate', 'unthrottled', 'legacy', 'disabled', 'cleared'])
def test_resolves_once_when_no_longer_blocking_and_reopens(admin, change):
    configure()
    operations.collect_alerts(NOW)
    if change == 'priced':configure(model='gpt-6-luna')
    elif change == 'disabled':configure(enabled=False)
    elif change == 'cleared':configure(model='')
    else:configure(mode=change)
    operations.collect_alerts(NOW + 60)
    operations.collect_alerts(NOW + 120)
    event, revision = current()
    assert event.revision == 2 and revision.lifecycle == 'resolved' and revision.severity == 'info'
    configure()
    operations.collect_alerts(NOW + 180)
    event, revision = current()
    assert event.revision == 3 and revision.lifecycle == 'active'


def test_priced_or_uncapped_configurations_never_publish(admin):
    for model, mode, enabled in (('gpt-6-luna', 'daily_cap', True), ('gpt-5', 'rate', True),
                                 ('gpt-5', 'unthrottled', True), ('gpt-5', 'daily_cap', False), ('', 'daily_cap', True)):
        configure(model=model, mode=mode, enabled=enabled)
        operations.collect_alerts(NOW)
    assert current() == (None, None)


# The clock is explicit and the bundled window is the subject under test, so opt out of the #742 fresh-catalog pin.
@pytest.mark.bundled_pricing_catalog
def test_expired_catalog_is_left_to_the_catalog_notification(admin):
    configure()
    operations.collect_alerts(EXPIRED)
    assert current() == (None, None)
    with Session() as session:
        assert session.query(notifications.NotificationEvent).filter_by(source='ai-budget', kind='pricing-catalog').count() == 1
    # An existing active event is neither duplicated nor falsely resolved while the catalog is stale.
    operations.collect_alerts(NOW)
    operations.collect_alerts(EXPIRED + 60)
    event, revision = current()
    assert event.revision == 1 and revision.lifecycle == 'active'
