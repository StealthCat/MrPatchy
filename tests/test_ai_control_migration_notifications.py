"""In-app notifications for the unattended legacy AI admission migration (#1178)."""
from sqlalchemy import select

from app import ai, ai_budget, ai_control_migration as migration, ai_control_preview as preview, notifications, operations
from app.db import Session, Setting
from app.identity import User

NOW = 2_000_000_000.0
IMPLICIT = {'ai_enabled': False, 'ai_model': '', 'ai_hourly_limit': 20, 'ai_update_hourly_limit': 20,
            'history_days': 45}


def store(value):
    with Session() as s:
        s.merge(Setting(key='config', value=value))
        if s.get(User, 'viewer') is None:
            s.add(User(username='viewer', password='x', role='viewer'))
        s.commit()


def revisions(kind):
    with Session() as s:
        return [(r.revision, r.lifecycle, r.severity, r.subject_revision, r.reason)
                for r in s.scalars(select(notifications.NotificationRevision)
                                   .join(notifications.NotificationEvent,
                                         notifications.NotificationEvent.id == notifications.NotificationRevision.event_id)
                                   .where(notifications.NotificationEvent.kind == kind)
                                   .order_by(notifications.NotificationRevision.revision))]


def visible(user):
    with Session() as s:
        return [item for item in notifications.list_for_user(s, user) if item['source'] == 'ai-admission']


def refuse(monkeypatch):
    real = preview.legacy_migration
    monkeypatch.setattr(preview, 'legacy_migration',
                        lambda values: real(values) | {'proposal_expands': True, 'proposal_expansions': ['x']})


def test_migration_publishes_one_admin_only_info_record(admin):
    store(IMPLICIT | {'ai_hourly_limit': 6})
    assert migration.migrate_implicit_legacy() == 'migrated'
    assert migration.migrate_implicit_legacy() is None  # a restart adds nothing
    operations.collect_alerts(NOW)
    [(revision, lifecycle, severity, subject, reason)] = revisions('legacy-migrated')
    assert (revision, lifecycle, severity, subject) == (1, 'active', 'info', 'rate:6')
    assert '6 AI starts per hour' in reason and 'no spend control was relaxed' in reason
    [item] = visible('admin')
    assert item['deep_link'] == '#settings/ai' and item['host_id'] == ''
    assert visible('viewer') == []
    assert revisions('legacy-migration-refused') == []


def test_refused_migration_publishes_once_and_resolves_after_an_explicit_save(admin, monkeypatch):
    store(IMPLICIT)
    refuse(monkeypatch)
    for _ in range(3):  # repeated startups stay one unread revision
        assert migration.migrate_implicit_legacy() == 'refused'
    operations.collect_alerts(NOW)
    operations.collect_alerts(NOW + 60)  # still implicit legacy: stays active
    [(_, lifecycle, severity, subject, reason)] = revisions('legacy-migration-refused')
    assert (lifecycle, severity, subject) == ('active', 'medium', 'refused')
    assert 'Nothing was changed' in reason and 'Settings → AI & models' in reason
    assert [item['kind'] for item in visible('viewer')] == []
    with Session() as s:
        assert s.get(Setting, 'config').value == IMPLICIT  # the notification wrote no settings

    store(IMPLICIT | {'ai_control_mode': 'legacy'})  # an administrator saved an explicit mode
    operations.collect_alerts(NOW + 120)
    operations.collect_alerts(NOW + 180)
    history = revisions('legacy-migration-refused')
    assert [(r[0], r[1], r[2]) for r in history] == [(1, 'active', 'medium'), (2, 'resolved', 'info')]
    assert revisions('legacy-migrated') == []


def test_a_later_successful_migration_resolves_an_earlier_refusal(admin, monkeypatch):
    store(IMPLICIT)
    refuse(monkeypatch)
    assert migration.migrate_implicit_legacy() == 'refused'
    monkeypatch.undo()
    assert migration.migrate_implicit_legacy() == 'migrated'
    operations.collect_alerts(NOW)
    assert [r[1] for r in revisions('legacy-migration-refused')] == ['active', 'resolved']
    assert [r[1] for r in revisions('legacy-migrated')] == ['active']


def test_notification_rejection_never_blocks_the_migration(admin, monkeypatch):
    store(IMPLICIT)

    def reject(*args, **kwargs):
        raise ValueError('rejected')
    monkeypatch.setattr(notifications, 'publish', reject)
    assert migration.migrate_implicit_legacy() == 'migrated'
    with Session() as s:
        assert s.get(Setting, 'config').value['ai_control_mode'] == 'rate'


def test_producer_never_calls_a_provider_or_reserves_spend(admin, monkeypatch):
    store(IMPLICIT)
    refuse(monkeypatch)
    calls = []
    monkeypatch.setattr(ai, 'request', lambda *a, **k: calls.append('provider'))
    monkeypatch.setattr(ai_budget, 'reserve', lambda *a, **k: calls.append('reserve'))
    assert migration.migrate_implicit_legacy() == 'refused'
    store(IMPLICIT | {'ai_control_mode': 'rate', 'ai_rate_per_hour': 10})
    operations.collect_alerts(NOW)
    assert calls == []
