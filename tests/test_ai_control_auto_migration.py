"""Unattended, non-expanding migration of never-reviewed legacy AI admission (#1039)."""
import threading

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import ai_control_migration as migration
from app import ai_control_preview as preview
from app.db import Audit, Session, Setting, config
from app.main import app

IMPLICIT = {'ai_enabled': False, 'ai_model': '', 'ai_hourly_limit': 20, 'ai_update_hourly_limit': 20,
            'history_days': 45}


def store(value):
    with Session() as s:
        s.merge(Setting(key='config', value=value));s.commit()


def stored():
    with Session() as s:
        return dict(s.get(Setting, 'config').value)


def audits():
    with Session() as s:
        return list(s.scalars(select(Audit).where(Audit.action == migration.ACTION)))


def test_implicit_legacy_moves_once_to_the_non_expanding_shared_rate(client):
    store(IMPLICIT | {'ai_hourly_limit': 6})
    with Session() as s:
        before = config(s)
    assert before['ai_control_mode'] == 'legacy'

    assert migration.migrate_implicit_legacy() == 'migrated'
    value = stored()
    assert value['ai_control_mode'] == 'rate' and value['ai_rate_per_hour'] == 6
    # Legacy limits and unrelated settings are preserved; nothing else is written.
    assert value == IMPLICIT | {'ai_hourly_limit': 6, 'ai_control_mode': 'rate', 'ai_rate_per_hour': 6}
    with Session() as s:
        after = config(s)
    compared = preview.compare(before, after)
    assert compared['changed'] and not compared['expands']
    for key, ceiling in compared['before']['hourly_starts'].items():
        assert compared['after']['hourly_starts'][key] <= ceiling, key
    [event] = audits()
    assert '6/hour' in event.detail and 'No admission or spend control was expanded' in event.detail
    assert 'automatic plans 10/hour' in event.detail

    # Idempotent: a restart (or a second controller/worker) changes nothing.
    assert migration.migrate_implicit_legacy() is None
    assert stored() == value and len(audits()) == 1


def test_defaults_include_the_hidden_automatic_plan_allowance(client):
    store(IMPLICIT)
    assert migration.migrate_implicit_legacy() == 'migrated'
    assert stored()['ai_rate_per_hour'] == 10  # not 20: never raises automatic plans (#878)


def test_explicit_modes_fresh_installs_and_explicit_legacy_are_untouched(client):
    with Session() as s:
        assert s.get(Setting, 'config') is None
    assert migration.migrate_implicit_legacy() is None
    with Session() as s:
        assert s.get(Setting, 'config') is None
    for mode in ('legacy', 'rate', 'daily_cap', 'rate_and_daily', 'unthrottled'):
        value = IMPLICIT | {'ai_control_mode': mode, 'ai_rate_per_hour': 300}
        store(value)
        assert migration.migrate_implicit_legacy() is None
        assert stored() == value
    assert audits() == []


def test_expanding_proposal_writes_nothing(client, monkeypatch):
    store(IMPLICIT)
    real = preview.legacy_migration
    monkeypatch.setattr(preview, 'legacy_migration',
                        lambda values: real(values) | {'proposal_expands': True, 'proposal_expansions': ['x']})
    assert migration.migrate_implicit_legacy() == 'refused'
    assert stored() == IMPLICIT and audits() == []


def test_concurrent_startups_apply_exactly_once(client):
    store(IMPLICIT)
    results, barrier = [], threading.Barrier(4)

    def run():
        barrier.wait();results.append(migration.migrate_implicit_legacy())
    threads = [threading.Thread(target=run) for _ in range(4)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert sorted(results, key=str) == [None, None, None, 'migrated']
    assert len(audits()) == 1 and stored()['ai_control_mode'] == 'rate'


def test_settings_form_loaded_before_migration_gets_a_stale_revision_refusal(admin):
    store(IMPLICIT)
    revision = admin.get('/api/settings').json()['ai_controls_revision']
    assert migration.migrate_implicit_legacy() == 'migrated'
    response = admin.put('/api/settings/ai', json={'ai_control_mode': 'legacy',
                                                  'expected_ai_controls_revision': revision})
    assert response.status_code == 409
    assert stored()['ai_control_mode'] == 'rate'


def test_application_startup_runs_the_migration(client):
    store(IMPLICIT)
    with TestClient(app):
        pass
    assert stored()['ai_control_mode'] == 'rate' and stored()['ai_rate_per_hour'] == 10
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(Audit).where(Audit.action == migration.ACTION)) == 1
