"""Durable known-good cache lookup outcome counters (roadmap B slice, #802)."""
import datetime

import pytest
from sqlalchemy import select

from app import ai, ai_assessments, ai_runs, known_good, known_good_lookups, worker
from app.db import Host, Session
from tests.test_known_good import complete, retained
from tests.test_known_good_miss import seed

DAY = 86400.0
NOW = datetime.datetime(2026, 11, 13, 12, tzinfo=datetime.timezone.utc).timestamp()


def rows():
    with Session() as s:
        return {(row.day, row.outcome): row.count
            for row in s.scalars(select(known_good_lookups.LookupCount))}


def fresh_result(*args, **kwargs):
    return {'risk': 'low', 'explanation': 'Fresh provider result',
        'recommended_checks': 'Continue deterministic monitoring', 'requested_checks': []}


def test_record_increments_one_daily_row_per_outcome(client):
    with Session() as s:
        for _ in range(3):
            known_good_lookups.record(s, 'hit', NOW)
        known_good_lookups.record(s, 'no_candidate', NOW)
        known_good_lookups.record(s, 'hit', NOW + DAY)
        s.commit()
    assert rows() == {('2026-11-13', 'hit'): 3, ('2026-11-13', 'no_candidate'): 1,
        ('2026-11-14', 'hit'): 1}


def test_unknown_outcomes_are_rejected_without_writing(client):
    with Session() as s:
        with pytest.raises(ValueError):
            known_good_lookups.record(s, '/usr/bin/fixture', NOW)
        s.commit()
    assert rows() == {}


def test_insert_race_loser_increments_the_winning_row(client, monkeypatch):
    with Session() as winner:
        known_good_lookups.record(winner, 'hit', NOW); winner.commit()
    calls = []
    original = known_good_lookups._increment

    def stale_first_update(s, day, outcome):
        calls.append(day)
        # Simulate a snapshot that missed the concurrent winner's insert.
        return 0 if len(calls) == 1 else original(s, day, outcome)
    monkeypatch.setattr(known_good_lookups, '_increment', stale_first_update)
    with Session() as loser:
        known_good_lookups.record(loser, 'hit', NOW)
        loser.commit()
    assert len(calls) == 2
    assert rows() == {('2026-11-13', 'hit'): 2}


def test_summary_bounds_window_and_retention_prunes_old_days(client):
    with Session() as s:
        known_good_lookups.record(s, 'hit', NOW - 500 * DAY)
        known_good_lookups.record(s, 'no_candidate', NOW - 45 * DAY)
        known_good_lookups.record(s, 'candidate_revoked', NOW - 29 * DAY)
        known_good_lookups.record(s, 'hit', NOW)
        known_good_lookups.record(s, 'hit', NOW)
        s.commit()
        result = known_good_lookups.summary(s, NOW)
    # Creating newer rows pruned the 500-day-old row; the 45-day row is retained
    # but outside the 30-day window.
    assert ('2026-11-13', 'hit') in rows() and len(rows()) == 3
    assert result['hits'] == 2 and result['total_misses'] == 1
    assert result['misses']['candidate_revoked'] == 1
    assert result['misses']['no_candidate'] == 0
    assert set(result['misses']) == set(known_good.MISS_TEXT) | {'miss_unclassified'}
    assert result['since_day'] == '2026-10-15' and result['window_days'] == 30
    assert result['counted_since_day'] == (datetime.date(2026, 11, 13) - datetime.timedelta(days=45)).isoformat()


def test_worker_counts_a_classified_miss_before_paid_investigation(client, monkeypatch):
    seed()
    monkeypatch.setattr(ai, 'investigate', fresh_result)
    worker.investigate_one()
    assert [key[1] for key in rows()] == ['no_candidate']
    assert list(rows().values()) == [1]


def test_worker_counts_a_hit_without_a_provider_call(client, monkeypatch):
    source = retained(snapshot=complete())
    source.policy_hash = ai_assessments.digest([ai.investigation_policy()])
    seed()
    with Session() as s:
        s.add(Host(id='host-one', name='Source', address='192.0.2.1', fingerprint=''))
        s.add(source); known_good.publish(s, source); s.commit()
    monkeypatch.setattr(ai, 'investigate', lambda *a, **k: pytest.fail('cache hit called provider'))
    worker.investigate_one()
    assert [key[1] for key in rows()] == ['hit']


def test_explainer_failure_is_counted_as_unclassified(client, monkeypatch):
    seed()
    monkeypatch.setattr(known_good, 'explain_miss',
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError('diagnostic broke')))
    monkeypatch.setattr(ai, 'investigate', fresh_result)
    worker.investigate_one()
    assert [key[1] for key in rows()] == ['miss_unclassified']


def test_counter_failure_never_changes_the_verdict(client, monkeypatch):
    seed()
    monkeypatch.setattr(known_good_lookups, 'record',
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError('counter broke')))
    monkeypatch.setattr(ai, 'investigate', fresh_result)
    worker.investigate_one()
    with Session() as s:
        from app.db import Behavior
        behavior = s.get(Behavior, 'behavior-two')
        assert behavior.verdict == 'low', behavior.analysis
        stages = {row.stage for row in s.scalars(select(ai_runs.AIEvent))}
    assert 'known_good_lookup' in stages
    assert rows() == {}


def test_lookup_summary_requires_admin(client):
    assert client.get('/api/ai/known-good/lookups').status_code in (401, 403)


def test_lookup_summary_endpoint_carries_only_fixed_counts(admin):
    with Session() as s:
        known_good_lookups.record(s, 'hit'); s.commit()
    response = admin.get('/api/ai/known-good/lookups')
    assert response.status_code == 200
    body = response.json()
    assert body['hits'] == 1 and body['total_misses'] == 0 and body['scope'] == 'process_triage'
    assert set(body) == {'window_days', 'since_day', 'timezone', 'counted_since_day',
        'hits', 'misses', 'total_misses', 'scope'}
