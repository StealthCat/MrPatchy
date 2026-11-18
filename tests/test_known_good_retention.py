"""Fleet known-good reuse across AI run-history pruning (roadmap B slice, issue #1027).

The worker's hourly cleanup prunes finished AI runs with their events, call
receipts and host links. The exact-match cache must keep working from its own
retained provenance afterwards, and must fail closed when that provenance is
missing rather than trusting a candidate it can no longer verify.
"""
import time

import pytest
from sqlalchemy import func, select

from app import ai, ai_assessments, ai_runs, known_good, worker
from app.db import Audit, Behavior, Host, Session, Setting
from app.security import seal
from tests.test_known_good import complete

SAFE = {'risk': 'low', 'explanation': 'Safe with complete evidence',
    'recommended_checks': 'Continue deterministic monitoring', 'requested_checks': []}


def second_host_snapshot():
    snapshot = complete()
    snapshot['host_id'] = 'host-two'
    snapshot['investigation']['details']['context']['process'] = {'pid': 99, 'start_ticks': 88}
    snapshot['investigation']['details']['known_good_context']['observation'] = {
        'host_id': 'host-two', 'pid': 99, 'start_ticks': 88, 'collected': 900}
    return snapshot


def seed_fleet():
    with Session() as s:
        s.add_all([Host(id='host-one', name='Source', address='192.0.2.1', fingerprint=''),
            Host(id='host-two', name='Current', address='192.0.2.2', fingerprint=''),
            Behavior(id='behavior-one', host_id='host-one', evidence=complete(),
                verdict='pending')])
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'gpt-fixture'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def provider_backed_source(monkeypatch):
    """Triage host one through the worker with one paid call; return its run and candidate."""
    calls = []
    monkeypatch.setattr(ai, 'investigate', lambda *a, **k: calls.append(a) or dict(SAFE))
    worker.investigate_one()
    assert len(calls) == 1
    with Session() as s:
        source = s.scalar(select(ai_assessments.Assessment).where(
            ai_assessments.Assessment.subject == 'behavior-one'))
        run = s.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject == 'behavior-one'))
        entry = s.scalar(select(known_good.Entry).where(
            known_good.Entry.assessment_id == source.id))
        assert source.source == 'ai' and source.run_id == run.id and run.state == 'complete'
        assert entry is not None and entry.active
        # A local receipt and event exist for the run, as a real provider call leaves.
        s.add(ai_runs.AICall(id='source-call', run_id=run.id, number=1,
            requested_model='gpt-fixture', status='estimated',
            pricing={'estimated_usd': '0.0100'}))
        s.add(ai_runs.AIEvent(run_id=run.id, stage='provider', message='fixture call'))
        s.commit()
        return run.id, source.id, entry.fingerprint


def age_and_prune(run_ids, now=None):
    now = now or time.time()
    with Session() as s:
        for run_id in run_ids:
            s.get(ai_runs.AIRun, run_id).started = now - 10 * 86400
        s.commit()
        worker.prune_history(s, now - 86400)
        s.commit()


def counts(s, model, column, value):
    return s.scalar(select(func.count()).select_from(model).where(column == value))


def test_reuse_survives_pruning_of_the_source_run_with_zero_provider_calls(client, monkeypatch):
    seed_fleet()
    run_id, source_id, fingerprint = provider_backed_source(monkeypatch)

    age_and_prune([run_id])

    with Session() as s:
        # Diagnostic history is gone.
        assert s.get(ai_runs.AIRun, run_id) is None
        assert counts(s, ai_runs.AICall, ai_runs.AICall.run_id, run_id) == 0
        assert counts(s, ai_runs.AIEvent, ai_runs.AIEvent.run_id, run_id) == 0
        assert counts(s, ai_runs.AIRunHost, ai_runs.AIRunHost.run_id, run_id) == 0
        # The retained provenance anchor and the cache entry are not.
        assert s.get(ai_assessments.Assessment, source_id) is not None
        assert s.get(known_good.Entry, fingerprint).active
        assert s.get(known_good.Observation, source_id).host_id == 'host-one'
        s.add(Behavior(id='behavior-two', host_id='host-two', evidence=second_host_snapshot(),
            verdict='pending'))
        s.commit()

    monkeypatch.setattr(ai, 'investigate',
        lambda *a, **k: pytest.fail('exact cache hit after pruning called the provider'))
    monkeypatch.setattr(ai.transport, 'post',
        lambda *a, **k: pytest.fail('exact cache hit after pruning sent a provider request'))
    worker.investigate_one()

    with Session() as s:
        behavior = s.get(Behavior, 'behavior-two')
        reused = s.scalar(select(ai_assessments.Assessment).where(
            ai_assessments.Assessment.subject == 'behavior-two'))
        run = s.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject == 'behavior-two'))
        status = known_good.assessment(reused, s)
        estimate = known_good.avoided_estimate(s)
        audit = s.scalar(select(Audit).where(Audit.action == 'reuse known-good candidate'))
    assert behavior.verdict == 'low' and reused.source == 'known_good'
    assert reused.result['known_good_reuse']['fingerprint'] == fingerprint
    assert reused.result['known_good_reuse']['source_assessment_id'] == source_id
    assert run.state == 'complete' and run.calls == 0
    assert status['reused'] and status['published']
    assert audit and fingerprint in audit.detail and 'host-two' in audit.detail
    # The pruned source run cannot be priced: the reuse is counted as
    # unattributable, never as free and never with an invented price.
    assert estimate['reuse_with_unavailable_source'] == 1
    assert estimate['reuse_with_priced_source'] == 0
    assert estimate['estimated_usd'] is None and estimate['estimated_calls'] == 0


def test_pruning_keeps_running_runs_and_every_cache_and_assessment_row(client, monkeypatch):
    seed_fleet()
    run_id, source_id, fingerprint = provider_backed_source(monkeypatch)
    now = time.time()
    with Session() as s:
        s.add(ai_runs.AIRun(id='still-running', purpose='triage', state='running',
            started=now - 10 * 86400))
        s.add(ai_runs.AICall(id='running-call', run_id='still-running', number=1,
            requested_model='gpt-fixture'))
        s.add(ai_runs.AIRun(id='recent', purpose='triage', state='complete', started=now))
        before = (s.scalar(select(func.count()).select_from(ai_assessments.Assessment)),
            s.scalar(select(func.count()).select_from(known_good.Entry)),
            s.scalar(select(func.count()).select_from(known_good.Observation)))
        s.commit()

    age_and_prune([run_id], now)

    with Session() as s:
        assert s.get(ai_runs.AIRun, run_id) is None
        assert s.get(ai_runs.AIRun, 'still-running').state == 'running'
        assert s.get(ai_runs.AICall, 'running-call') is not None
        assert s.get(ai_runs.AIRun, 'recent') is not None
        after = (s.scalar(select(func.count()).select_from(ai_assessments.Assessment)),
            s.scalar(select(func.count()).select_from(known_good.Entry)),
            s.scalar(select(func.count()).select_from(known_good.Observation)))
        assert after == before
        assert s.get(known_good.Entry, fingerprint).assessment_id == source_id


def test_missing_origin_assessment_fails_closed_and_pays_for_a_fresh_triage(client, monkeypatch):
    seed_fleet()
    run_id, source_id, fingerprint = provider_backed_source(monkeypatch)
    age_and_prune([run_id])
    policy_hash = ai_assessments.digest([ai.investigation_policy()])
    with Session() as s:
        # Simulate lost provenance: the candidate row outlives its origin.
        s.delete(s.get(known_good.Observation, source_id))
        s.delete(s.get(ai_assessments.Assessment, source_id))
        s.add(Behavior(id='behavior-two', host_id='host-two', evidence=second_host_snapshot(),
            verdict='pending'))
        s.commit()
        assert s.get(known_good.Entry, fingerprint).active
        assert known_good.lookup(s, second_host_snapshot(), 'gpt-fixture', [policy_hash]) is None
        assert known_good.explain_miss(s, second_host_snapshot(), 'gpt-fixture',
            [policy_hash])['code'] == 'candidate_unverified'

    calls = []
    monkeypatch.setattr(ai, 'investigate', lambda *a, **k: calls.append(a) or dict(SAFE))
    worker.investigate_one()

    with Session() as s:
        fresh = s.scalar(select(ai_assessments.Assessment).where(
            ai_assessments.Assessment.subject == 'behavior-two'))
        run = s.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject == 'behavior-two'))
        events = [(row.stage, row.message) for row in s.scalars(
            select(ai_runs.AIEvent).where(ai_runs.AIEvent.run_id == run.id))]
        reuse = s.scalar(select(Audit).where(Audit.action == 'reuse known-good candidate'))
    assert len(calls) == 1 and fresh.source == 'ai'
    assert reuse is None
    assert ('known_good_lookup', known_good.MISS_TEXT['candidate_unverified']) in events
