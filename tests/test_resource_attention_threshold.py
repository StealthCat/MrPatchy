"""Administrator-configured low-resource notification threshold (#1297)."""
import pytest
from sqlalchemy import select

from app import operations
from app import resource_attention_notifications as producer
from app.db import Audit, Session, Setting, config
from test_operations import login_as
from test_resource_attention_notifications import add_host, set_telemetry, state, telemetry

DEADLINES = {'critical': 24, 'high': 72, 'normal': 168, 'low': 720}
# The exact pre-#1297 reason text for low disk space, pinned so the default never adds a revision on upgrade.
LEGACY_DISK = ('The agent reports low free disk space on the root file system (10% or less available). '
               'Patching, logging and evidence collection can fail or record wrong times. Review Agent health on '
               'this server and Activity → Workers. These are the agent\'s own advisory observations. This '
               'notification does not change agent health, free disk space or memory, adjust the clock or '
               'authorize any response.')


def set_percent(value):
    with Session() as s:
        item = s.get(Setting, 'config')
        s.merge(Setting(key='config', value={**(item.value if item else {}), producer.CONFIG_KEY: value}))
        s.commit()


def test_default_threshold_and_text_are_unchanged():
    assert producer.TRIGGER_AVAILABLE_PERCENT == 10 and producer.CLEAR_AVAILABLE_PERCENT == 15
    assert producer.trigger_percent({}) == 10
    assert producer.message({'disk-space-low'}) == LEGACY_DISK
    assert producer.message({'disk-space-low'}, 10) == LEGACY_DISK


@pytest.mark.parametrize('value', [0, 51, -5, '20', 20.0, True, None, [20]])
def test_invalid_stored_threshold_falls_back_to_default(value):
    assert producer.trigger_percent({producer.CONFIG_KEY: value}) == 10
    assert producer.trigger_percent(None) == 10


def test_configured_threshold_triggers_earlier_and_clears_five_points_above(admin):
    set_percent(20)
    add_host(data=telemetry(disk=20.0))
    operations.collect_alerts()
    revision, lifecycle, reason = state()
    assert (revision, lifecycle) == (1, 'active')
    assert '(20% or less available)' in reason and '10%' not in reason
    set_telemetry(telemetry(disk=25.0))  # inside the 20–25% clear band
    operations.collect_alerts()
    assert state()[:2] == (1, 'active')
    set_telemetry(telemetry(disk=25.1))
    operations.collect_alerts()
    assert state()[:2] == (2, 'resolved')
    set_telemetry(telemetry(disk=21.0))  # the band does not trigger a new event
    operations.collect_alerts()
    assert state()[:2] == (2, 'resolved')


def test_lower_threshold_ignores_values_the_default_would_flag(admin):
    set_percent(5)
    add_host(data=telemetry(memory=8.0))
    operations.collect_alerts()
    assert state() is None
    set_telemetry(telemetry(memory=5.0))
    operations.collect_alerts()
    assert state()[:2] == (1, 'active') and '(5% or less available)' in state()[2]


def test_threshold_change_keeps_active_categories_and_hysteresis(admin):
    add_host(data=telemetry(disk=9.0))
    operations.collect_alerts()
    assert state() == (1, 'active', LEGACY_DISK)
    # Raising the threshold rewrites the text once; the event stays active and keeps its category.
    set_percent(30)
    operations.collect_alerts()
    revision, lifecycle, reason = state()
    assert (revision, lifecycle) == (2, 'active') and '(30% or less available)' in reason
    operations.collect_alerts()
    assert state()[0] == 2
    # Lowering it below the value: the active category stays in the new clear band (5 + 5 = 10%).
    set_percent(5)
    set_telemetry(telemetry(disk=10.0))
    operations.collect_alerts()
    assert state()[:2] == (3, 'active') and '(5% or less available)' in state()[2]
    # Unknown telemetry under the new threshold is still not recovery.
    set_telemetry({'collected': telemetry()['collected']})
    operations.collect_alerts()
    assert state()[:2] == (3, 'active')
    set_telemetry(telemetry(disk=10.1))
    operations.collect_alerts()
    assert state()[:2] == (4, 'resolved')


def test_every_threshold_text_recovers_its_categories():
    for percent in range(producer.TRIGGER_MIN_PERCENT, producer.TRIGGER_MAX_PERCENT + 1):
        for codes in ({'disk-space-low'}, {'memory-low', 'clock-unsynchronized'}, {'clock-unsynchronized'},
                      set(producer.CODES)):
            text = producer.message(codes, percent)
            assert producer._BY_NORMALISED[producer._normalise(text)] == frozenset(codes)
    # A percentage outside the accepted range is not normalised, so it stays unrecognised.
    assert producer._normalise(producer.message({'disk-space-low'}, 60)) not in producer._BY_NORMALISED


def test_patch_settings_save_validates_audits_and_keeps_threshold_when_omitted(admin):
    assert admin.get('/api/settings').json()['resource_attention_percent'] == 10
    r = admin.put('/api/settings/patching', json={'repo_minutes': 60, 'deadlines': DEADLINES,
                                                  'resource_attention_percent': 25})
    assert r.status_code == 200, r.text
    assert admin.put('/api/settings/patching', json={'repo_minutes': 50, 'deadlines': DEADLINES}).status_code == 200
    assert admin.put('/api/settings/patching', json={'repo_minutes': 50, 'deadlines': DEADLINES,
                                                     'resource_attention_percent': 25}).status_code == 200
    assert admin.get('/api/settings').json()['resource_attention_percent'] == 25
    with Session() as s:
        cfg = config(s)
        assert cfg['resource_attention_percent'] == 25 and cfg['repo_minutes'] == 50
        details = [a.detail for a in s.scalars(select(Audit).where(Audit.action == 'update patching settings'))]
        assert sum('low-resource notification threshold changed from 10% to 25% available' in d
                   for d in details) == 1
        assert sum('low-resource' in d for d in details) == 1
    for bad in (0, 51, '20', 20.5, True, None):
        body = {'repo_minutes': 60, 'deadlines': DEADLINES, 'resource_attention_percent': bad}
        status = admin.put('/api/settings/patching', json=body).status_code
        assert status == (200 if bad is None else 422), bad
    assert admin.get('/api/settings').json()['resource_attention_percent'] == 25


def test_corrupt_stored_threshold_is_reported_and_applied_as_default(admin):
    set_percent('high')
    assert admin.get('/api/settings').json()['resource_attention_percent'] == 10
    add_host(data=telemetry(disk=10.0))
    operations.collect_alerts()
    assert state() == (1, 'active', LEGACY_DISK)


@pytest.mark.parametrize('role', ['viewer', 'operator'])
def test_non_administrators_cannot_change_the_threshold(client, role):
    login_as(client, 'reader', role)
    r = client.put('/api/settings/patching', json={'repo_minutes': 60, 'deadlines': DEADLINES,
                                                   'resource_attention_percent': 40})
    assert r.status_code == 403
    with Session() as s:
        assert producer.CONFIG_KEY not in config(s)
