"""Current-window AI spend split by activity (issue #982)."""
from decimal import Decimal
import time

from sqlalchemy import event

from app import ai_budget, ai_runs
from app.db import Session, Setting, engine
from tests.test_ai_budget import configure


def _entry(identifier, run_id, status, reserve, actual=None, *, created, reset):
    return ai_budget.BudgetEntry(
        id=identifier, run_id=run_id, created=created, updated=created, reset_at=reset, timezone='UTC',
        model='private-model-name', status=status, reservation_usd=Decimal(reserve), actual_usd=actual,
        pricing_version='catalog-test', pricing_source='https://pricing.example.test/private')


def _seed(now):
    reset = ai_budget._window(now, 'UTC')[1]
    runs = [('run-triage', 'triage'), ('run-scoring', 'update_scoring'), ('run-plan', 'security_plan'),
            ('run-release', 'release_configuration'), ('run-test', 'connection_test'),
            ('run-legacy', 'retired_private_purpose')]
    current = dict(created=now - 1, reset=reset)
    with Session() as session:
        session.add_all(ai_runs.AIRun(id=identifier, purpose=purpose, model='private-model-name',
                                      host_id='private-host', subject='private-subject', state='complete')
                        for identifier, purpose in runs)
        session.add_all([
            _entry('e1', 'run-triage', 'settled', '9', Decimal('0.125'), **current),
            _entry('e2', 'run-triage', 'reserved', '0.2', **current),
            _entry('e3', 'run-triage', 'sent', '0.3', **current),
            _entry('e4', 'run-scoring', 'uncertain', '0.4', **current),
            _entry('e5', 'run-plan', 'settled', '1', Decimal('0.01'), **current),
            _entry('e6', 'run-release', 'reserved', '0.02', **current),
            _entry('e7', 'run-test', 'settled', '1', Decimal('0.001'), **current),
            _entry('e8', 'run-legacy', 'legacy_pending', '0.5', **current),
            _entry('e9', 'run-pruned-long-ago', 'settled', '1', Decimal('0.05'), **current),
            _entry('e10', '', 'reserved', '0.03', **current),
            # Never counted: released, or settled in a window that already reset.
            _entry('e11', 'run-triage', 'released', '99', **current),
            _entry('e12', 'run-triage', 'settled', '1', Decimal('0.75'), created=now - 3 * 86400,
                   reset=reset - 2 * 86400),
        ])
        session.commit()


def test_groups_match_counted_spend_without_loading_ledger_rows(admin):
    configure(cap=Decimal('100'))
    _seed(time.time())
    loaded = []
    ledger_queries = []

    def on_load(*args):
        loaded.append(1)

    def on_query(_connection, _cursor, statement, *_args):
        if 'ai_budget_entries' in statement:
            ledger_queries.append(statement)

    for model in (ai_budget.BudgetEntry, ai_runs.AIRun):
        event.listen(model, 'load', on_load)
    event.listen(engine, 'before_cursor_execute', on_query)
    try:
        response = admin.get('/api/settings/ai-spend-by-purpose')
    finally:
        event.remove(engine, 'before_cursor_execute', on_query)
        for model in (ai_budget.BudgetEntry, ai_runs.AIRun):
            event.remove(model, 'load', on_load)
    assert response.status_code == 200 and not loaded
    assert len(ledger_queries) == 1
    data = response.json()
    assert data['enabled'] and data['mode'] == 'daily_cap' and data['timezone'] == 'UTC'
    assert data['next_reset'] - data['window_start'] == 86400
    assert data['next_reset_authoritative'] is True
    assert data['groups'] == [
        {'purpose': 'triage', 'call_count': 3, 'settled_usd': '0.125', 'reserved_usd': '0.2',
         'uncertain_usd': '0.3', 'counted_usd': '0.625'},
        {'purpose': 'update_scoring', 'call_count': 1, 'settled_usd': '0', 'reserved_usd': '0',
         'uncertain_usd': '0.4', 'counted_usd': '0.4'},
        {'purpose': 'security_plan', 'call_count': 1, 'settled_usd': '0.01', 'reserved_usd': '0',
         'uncertain_usd': '0', 'counted_usd': '0.01'},
        {'purpose': 'release_configuration', 'call_count': 1, 'settled_usd': '0', 'reserved_usd': '0.02',
         'uncertain_usd': '0', 'counted_usd': '0.02'},
        {'purpose': 'connection_test', 'call_count': 1, 'settled_usd': '0.001', 'reserved_usd': '0',
         'uncertain_usd': '0', 'counted_usd': '0.001'},
        # An unrecognized stored purpose and an unrecognized status still count their ceiling.
        {'purpose': 'other', 'call_count': 1, 'settled_usd': '0', 'reserved_usd': '0',
         'uncertain_usd': '0', 'counted_usd': '0.5'},
        # A pruned run and a call without a run are kept, never dropped or guessed.
        {'purpose': 'unattributed', 'call_count': 2, 'settled_usd': '0.05', 'reserved_usd': '0.03',
         'uncertain_usd': '0', 'counted_usd': '0.08'},
    ]
    assert data['call_count'] == 10
    with Session() as session:
        status = ai_budget.status(session)
    assert data['counted_usd'] == status['counted_usd'] == '1.636'
    assert sum(Decimal(group['counted_usd']) for group in data['groups']) == Decimal(data['counted_usd'])
    for private in ('private-model-name', 'private-host', 'private-subject', 'retired_private_purpose',
                    'pricing.example.test', 'run-triage', 'run-pruned-long-ago'):
        assert private not in response.text


def test_window_kept_open_by_a_timezone_change_is_still_attributed(admin):
    configure(cap=Decimal('100'))
    now = time.time()
    reset = ai_budget._window(now, 'UTC')[1]
    with Session() as session:
        session.add(ai_runs.AIRun(id='run-old-window', purpose='update_scoring', model='m', state='complete'))
        # Admitted before today's window under a reset that has not happened yet.
        session.add(_entry('carried', 'run-old-window', 'settled', '1', Decimal('0.25'),
                           created=reset - 86400 - 60, reset=reset + 3600))
        session.commit()
        status = ai_budget.status(session, now)
        data = ai_budget.by_purpose(session, now)
        after = ai_budget.by_purpose(session, reset + 1)
    assert status['counted_usd'] == data['counted_usd'] == '0.25'
    assert status['next_reset_authoritative'] is data['next_reset_authoritative'] is False
    assert [(group['purpose'], group['counted_usd']) for group in data['groups']] == [('update_scoring', '0.25')]
    assert after['next_reset_authoritative'] is True
    assert after['counted_usd'] == '0.25'


def test_only_positive_observed_unreleased_spend_affects_reset_authority(admin):
    configure(cap=Decimal('100'))
    start, reset = ai_budget._window(time.time(), 'UTC')
    now = start + 3600
    with Session() as session:
        session.add_all([
            _entry('released', '', 'released', '2', created=now - 60, reset=reset + 3600),
            _entry('zero', '', 'settled', '3', Decimal('0'), created=now - 60, reset=reset + 3600),
            _entry('future', '', 'reserved', '4', created=now + 60, reset=reset + 3600),
        ])
        session.commit()
        assert ai_budget.status(session, now)['next_reset_authoritative'] is True
        assert ai_budget.by_purpose(session, now)['next_reset_authoritative'] is True


def test_uncapped_modes_report_no_cap_and_no_groups(admin):
    _seed(time.time())
    for mode in ('legacy', 'rate', 'unthrottled'):
        configure(mode=mode)
        data = admin.get('/api/settings/ai-spend-by-purpose').json()
        assert data['mode'] == mode and not data['enabled']
        assert data['groups'] == [] and data['counted_usd'] == '0' and data['call_count'] == 0
        assert data['timezone'] is None and data['window_start'] is None and data['next_reset'] is None
        assert data['next_reset_authoritative'] is False


def test_empty_capped_window_and_role_boundary(admin, client):
    from app.identity import User
    configure(mode='rate_and_daily')
    data = admin.get('/api/settings/ai-spend-by-purpose').json()
    assert data['enabled'] and data['groups'] == [] and data['counted_usd'] == '0'
    assert data['next_reset_authoritative'] is True
    assert len(data['limitations']) == 2
    with Session() as session:
        before = session.get(Setting, 'config').value
    assert admin.get('/api/settings/ai-spend-by-purpose').status_code == 200
    with Session() as session:
        assert session.get(Setting, 'config').value == before
        session.get(User, 'admin').role = 'operator'
        session.commit()
    assert admin.get('/api/settings/ai-spend-by-purpose').status_code == 403
    with Session() as session:
        session.get(User, 'admin').role = 'viewer'
        session.commit()
    assert admin.get('/api/settings/ai-spend-by-purpose').status_code == 403
