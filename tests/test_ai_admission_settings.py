"""Initial triage preflight shares settings without caching later budget checks."""
from contextlib import contextmanager
from sqlalchemy import event
from app import ai_claims, ai_retry, host_lifecycle
from app.db import Behavior, Host, Session, Setting, engine
from app.security import seal


def seed(mode):
    with Session() as s:
        s.add_all([
            Host(id='fixture-host', name='Fixture', address='192.0.2.1', fingerprint=''),
            Behavior(id='fixture-subject', host_id='fixture-host', evidence={'executable': '/fixture'}),
            Setting(key='config', value={'ai_enabled': True, 'ai_model': 'gpt-6-luna',
                'ai_control_mode': mode, 'ai_daily_cap_usd': 10}),
            Setting(key='openai_key', value={'encrypted': seal('fixture-key')}),
        ])
        s.commit()


def test_initial_claim_reads_settings_and_key_once(admin, monkeypatch):
    seed('rate')
    settings_reads = []
    in_queue = False
    original_activity = host_lifecycle.activity

    @contextmanager
    def activity(host_ids, kind):
        nonlocal in_queue
        in_queue = True
        with original_activity(host_ids, kind) as revisions:
            yield revisions

    monkeypatch.setattr(host_lifecycle, 'activity', activity)

    def capture(conn, cursor, statement, parameters, context, executemany):
        if not in_queue and statement.startswith('SELECT settings.'):
            values = parameters.values() if isinstance(parameters, dict) else parameters
            settings_reads.extend(value for value in values if value in ('config', 'openai_key'))

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        lease = ai_claims.acquire()
    finally:
        event.remove(engine, 'before_cursor_execute', capture)

    assert lease is not None
    assert settings_reads == ['config', 'openai_key']
    with Session() as s:
        assert s.get(ai_claims.Claim, lease.subject).configuration == ai_retry.configuration(s)


def test_capped_candidate_reloads_budget_settings_after_queue_lock(admin, monkeypatch):
    seed('daily_cap')
    original_activity = host_lifecycle.activity
    entered = []

    @contextmanager
    def activity(host_ids, kind):
        with original_activity(host_ids, kind) as revisions:
            entered.append(kind)
            with Session() as s:
                row = s.get(Setting, 'config')
                row.value = {**row.value, 'ai_daily_cap_usd': 0}
                s.commit()
            yield revisions

    monkeypatch.setattr(host_lifecycle, 'activity', activity)
    assert ai_claims.acquire() is None
    assert entered == ['queue']
    with Session() as s:
        assert s.get(ai_claims.Claim, 'fixture-subject') is None
        assert s.get(Behavior, 'fixture-subject').attempted == 0
