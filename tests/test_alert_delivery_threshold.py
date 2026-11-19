"""Administrator-configurable failed-attempt threshold for the alert-delivery notice (#1172)."""
import json

from sqlalchemy import select

from app import alert_delivery_notifications, notifications, operations
from app.db import Audit, Session, Setting

from tests.test_alert_delivery_notifications import attempt_delivery, configure, stale_host

ROUTE = '/api/operations/alert-delivery-threshold'


def failing_reasons():
    with Session() as s:
        return [(i['lifecycle'], i['reason']) for i in notifications.list_for_user(s, 'admin')
                if i['kind'] == 'delivery-failing']


def save(admin, value, expected):
    return admin.put(ROUTE, json={'failed_attempts': value, 'expected_failed_attempts': expected})


def test_default_threshold_and_invalid_stored_values_fall_back(admin):
    assert admin.get(ROUTE).json() == {'failed_attempts': 3, 'default': 3, 'minimum': 1, 'maximum': 20}
    for value in (0, 21, True, '5', 2.0, None):
        with Session() as s:
            s.merge(Setting(key=alert_delivery_notifications.THRESHOLD_KEY, value={'failed_attempts': value}))
            s.commit()
            assert alert_delivery_notifications.threshold(s) == 3
    with Session() as s:
        s.merge(Setting(key=alert_delivery_notifications.THRESHOLD_KEY, value=['not', 'a', 'dict']))
        s.commit()
        assert alert_delivery_notifications.threshold(s) == 3


def test_saved_threshold_controls_when_the_notice_fires(admin, monkeypatch):
    stale_host()
    configure()
    operations.collect_alerts()
    attempt_delivery(monkeypatch, 2)
    operations.collect_alerts()
    assert failing_reasons() == []  # two failures stay below the default of three

    assert save(admin, 2, 3).json()['failed_attempts'] == 2
    with Session() as s:  # changing the threshold itself publishes nothing
        assert s.scalar(select(notifications.NotificationEvent)
                        .where(notifications.NotificationEvent.kind == 'delivery-failing')) is None
        alert = s.scalars(select(operations.Alert)).one()
        assert (alert.state, alert.notified, alert.attempts) == ('open', 0, 2)  # nothing sent, retried or acknowledged
    operations.collect_alerts()
    [(lifecycle, reason)] = failing_reasons()
    assert lifecycle == 'active' and 'failed 2 or more delivery attempts' in reason

    assert save(admin, 5, 2).status_code == 200
    operations.collect_alerts()
    assert [item[0] for item in failing_reasons()] == ['resolved']  # raising the threshold clears the condition

    attempt_delivery(monkeypatch, 3)
    operations.collect_alerts()
    [(lifecycle, reason)] = failing_reasons()
    assert lifecycle == 'active' and 'failed 5 or more delivery attempts' in reason


def test_threshold_changes_are_validated_audited_and_guarded_against_concurrent_edits(admin):
    for value in (0, 21, True, '4', 3.5):
        response = save(admin, value, 3)
        assert response.status_code in (400, 422), value
    assert admin.get(ROUTE).json()['failed_attempts'] == 3

    assert save(admin, 4, 3).status_code == 200
    stale = save(admin, 6, 3)
    assert stale.status_code == 409 and 'reload' in stale.json()['detail']
    assert admin.get(ROUTE).json()['failed_attempts'] == 4
    assert save(admin, 4, 4).status_code == 200  # unchanged value: no new audit entry

    with Session() as s:
        entries = [json.loads(a.detail) for a in s.scalars(select(Audit).where(Audit.action == 'alert delivery threshold'))]
    assert entries == [{'actor': 'admin', 'before': 3, 'after': 4}]


def test_threshold_stays_readable_when_the_delivery_configuration_is_not(admin):
    with Session() as s:
        s.merge(Setting(key='notifications', value={'encrypted': 'not-a-sealed-value'}))
        s.commit()
    assert save(admin, 7, 3).status_code == 200
    assert admin.get(ROUTE).json()['failed_attempts'] == 7
    with Session() as s:
        assert alert_delivery_notifications.delivery_channel(s) == 'unknown'
        assert s.get(Setting, 'notifications').value == {'encrypted': 'not-a-sealed-value'}  # untouched
