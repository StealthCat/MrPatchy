"""Free exact known-good hits during shared provider start holds (#1030, #1128).

An exact fleet known-good hit makes no provider call and reserves nothing. The
daily cap is a spend control, so it must not hold that verdict back until the
next reset. Every subject that would call the provider keeps today's deferral,
and pause, Refresh and revocation still apply. These tests drive the real
``worker.investigate_one()`` path; only the provider transport is a fixture.
"""
import json
import time
import uuid
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select

from app import (ai, ai_admission, ai_assessments, ai_budget, ai_claims,
                 ai_provider_backoff, ai_retry, ai_runs, known_good, worker)
from app.db import Audit, Behavior, Host, Session, Setting
from app.security import seal
from tests.test_known_good import complete, retained

MODEL = 'gpt-6-astra'


class Provider:
    def __init__(self):
        self.bodies = []

    def __call__(self, *args, **kwargs):
        self.bodies.append(kwargs['json'])
        raise AssertionError('No provider request may be sent in these tests')


@pytest.fixture
def provider(monkeypatch):
    sent = Provider()
    monkeypatch.setattr(ai.transport, 'post', sent)
    return sent


def configure(**changes):
    with Session() as s:
        s.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': MODEL, 'ai_control_mode': 'daily_cap',
            'ai_daily_cap_usd': 5.0, 'ai_budget_timezone': 'UTC', 'ai_updates_enabled': False,
            **changes}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def exhaust(amount='5'):
    """Record settled spend that uses the whole cap in the current window."""
    now = time.time()
    with Session() as s:
        s.add(ai_budget.BudgetEntry(id=str(uuid.uuid4()), run_id='', created=now, updated=now,
            reset_at=now + 86400, timezone='UTC', model=MODEL, status='settled',
            reservation_usd=Decimal(amount), actual_usd=Decimal(amount),
            pricing_version='fixture', pricing_source='fixture'))
        s.commit()


def seed(*, hit=True, refresh=False, first_seen=None, subject='behavior-two', host='host-two'):
    """An active exact candidate from host-one; ``host`` observes the same (or a different) artifact."""
    current = complete()
    current['host_id'] = host
    current['investigation']['details']['known_good_context']['observation']['host_id'] = host
    if not hit:
        current['sha256'] = 'f' * 64
        current['investigation']['details']['known_good_context']['artifact']['sha256'] = 'f' * 64
    with Session() as s:
        if s.get(Host, 'host-one') is None:
            source = retained(snapshot=complete())
            source.model = MODEL
            source.policy_hash = ai_assessments.digest([ai.investigation_policy()])
            s.add_all([Host(id='host-one', name='Source', address='192.0.2.1', fingerprint=''), source])
            s.flush()
            known_good.publish(s, source)
        if s.get(Host, host) is None:
            s.add(Host(id=host, name=host, address='203.0.113.' + str(len(host)), fingerprint=''))
        s.add(Behavior(id=subject, host_id=host, evidence=current, verdict='pending',
                       first_seen=first_seen if first_seen is not None else time.time()))
        if refresh:
            s.add(ai_assessments.Refresh(subject=subject, id='refresh-' + subject, actor='admin',
                reason='Explicitly request a fresh provider assessment', previous='assessment-one',
                withdrew_approval=False))
        s.commit()


def state(subject='behavior-two'):
    with Session() as s:
        behavior = s.get(Behavior, subject)
        return {
            'verdict': behavior.verdict,
            'assessments': [row.source for row in s.scalars(select(ai_assessments.Assessment).where(
                ai_assessments.Assessment.subject == subject))],
            'runs': [(row.state, row.calls) for row in s.scalars(
                select(ai_runs.AIRun).where(ai_runs.AIRun.subject == subject))],
            'claims': s.scalar(select(ai_claims.Claim).where(ai_claims.Claim.subject == subject)) is not None,
        }


def ledger():
    with Session() as s:
        return [(row.status, row.reservation_usd) for row in s.scalars(
            select(ai_budget.BudgetEntry).order_by(ai_budget.BudgetEntry.created))]


def reused(subject='behavior-two'):
    return {'verdict': 'low', 'assessments': ['known_good'], 'runs': [('complete', 0)], 'claims': False} == state(subject)


def held(subject='behavior-two'):
    return {'verdict': 'pending', 'assessments': [], 'runs': [], 'claims': False} == state(subject)


def _revoke_only_candidate():
    with Session() as s:
        entry = s.scalar(select(known_good.Entry))
        known_good.revoke(s, entry.fingerprint, entry.version, 'admin', 'Contradicted by new evidence')
        s.commit()


def test_exhausted_cap_still_reuses_an_exact_hit_with_zero_calls_and_no_new_reservation(client, provider):
    configure()
    exhaust()
    seed()
    # Close this probe session: on MySQL an open read transaction holds metadata
    # locks that block the next test's drop_all indefinitely.
    with Session() as s:
        assert ai_budget.waiting(s, time.time())  # the global cap gate is closed
    before = ledger()
    worker.investigate_one()
    assert provider.bodies == []
    assert reused()
    assert ledger() == before
    with Session() as s:
        assert s.scalar(select(Audit).where(Audit.action == 'reuse known-good candidate')) is not None


def test_cap_below_one_reservation_still_reuses_an_exact_hit(client, provider):
    """The issue's reproduction: the subject's own quote exceeds the remaining headroom."""
    configure(ai_daily_cap_usd=0.000001)
    seed()
    worker.investigate_one()
    assert provider.bodies == []
    assert reused()
    assert ledger() == []


def test_exhausted_cap_keeps_a_paid_subject_waiting_without_a_claim_run_or_reservation(client, provider):
    configure()
    exhaust()
    seed(hit=False)
    for _ in range(2):
        worker.investigate_one()
    assert provider.bodies == []
    assert held()
    assert [status for status, _ in ledger()] == ['settled']


def test_an_older_paid_subject_does_not_hold_a_newer_free_hit_behind_the_cap(client, provider):
    configure()
    exhaust()
    seed(hit=False, subject='behavior-old', host='host-three', first_seen=1)
    seed(subject='behavior-two', host='host-two', first_seen=2)
    worker.investigate_one()
    worker.investigate_one()
    assert provider.bodies == []
    assert reused('behavior-two')
    assert held('behavior-old')


def test_exhausted_cap_does_not_admit_an_administrator_retriage(client, provider):
    configure()
    exhaust()
    seed(refresh=True)
    worker.investigate_one()
    assert provider.bodies == []
    assert held()
    with Session() as s:
        assert s.get(ai_assessments.Refresh, 'behavior-two') is not None


def test_exhausted_cap_does_not_admit_a_hit_against_a_revoked_candidate(client, provider):
    configure()
    exhaust()
    seed()
    _revoke_only_candidate()
    worker.investigate_one()
    assert provider.bodies == []
    assert held()


def test_exhausted_cap_does_not_admit_a_hit_on_a_paused_server(client, provider):
    configure()
    exhaust()
    seed()
    with Session() as s:
        s.merge(Setting(key='server-ai:host-two', value={'paused': True}))
        s.commit()
    worker.investigate_one()
    assert held()
    with Session() as s:
        s.merge(Setting(key='server-ai:host-two', value={'paused': False}))
        s.commit()
    worker.investigate_one()
    assert provider.bodies == []
    assert reused()


def test_probe_is_read_only_and_agrees_with_the_worker_lookup(client, provider):
    configure()
    seed()
    with Session() as s:
        row = s.get(Behavior, 'behavior-two')
        evidence = dict(row.evidence)
        assert known_good.exact_hit_available(s, row, MODEL) is True
        assert not s.new and not s.dirty and not s.deleted
        assert row.evidence == evidence
        assert known_good.exact_hit_available(s, row, 'another-model') is False


@pytest.mark.parametrize('gates', [('rate',), ('backoff',), ('rate', 'backoff')])
def test_provider_start_holds_allow_only_exact_cache_reuse(client, provider, gates):
    configure(ai_control_mode='rate_and_daily')
    seed(hit=False, subject='older-miss', host='host-three', first_seen=1)
    seed(refresh=True, subject='older-refresh', host='host-four', first_seen=2)
    seed(subject='older-paused', host='host-five', first_seen=3)
    seed(first_seen=4)
    deadline = time.time() + 900
    with Session() as s:
        s.add(Setting(key='server-ai:host-five', value={'paused': True}))
        if 'rate' in gates:
            s.add(ai_admission.Admission(id='global', next_at=deadline, admitted=10))
        if 'backoff' in gates:
            s.add(ai_provider_backoff.ProviderBackoff(id='global', blocked_until=deadline, failures=1))
        s.commit()

    worker.investigate_one()
    worker.investigate_one()

    assert reused()
    assert all(held(subject) for subject in ('older-miss', 'older-refresh', 'older-paused'))
    assert provider.bodies == [] and ledger() == []
    with Session() as s:
        rate = s.get(ai_admission.Admission, 'global')
        rate_state = (rate.next_at, rate.admitted) if rate else None
        assert rate_state == ((deadline, 10) if 'rate' in gates else None)
        backoff = s.get(ai_provider_backoff.ProviderBackoff, 'global')
        assert (backoff.blocked_until if backoff else None) == (deadline if 'backoff' in gates else None)


def test_provider_hold_skips_evidence_probes_when_no_active_candidate(client, provider, monkeypatch):
    configure()
    seed()
    _revoke_only_candidate()
    ai_provider_backoff.failed(ai.AIError('fixture backoff', transient=True, retry_after=900))
    probes = []
    monkeypatch.setattr(known_good, 'exact_hit_available', lambda *args: probes.append(1) or False)
    worker.investigate_one()
    assert probes == [] and provider.bodies == []
    assert held()


def test_revocation_after_claim_cannot_send_during_provider_backoff(client, provider, monkeypatch):
    configure()
    seed()
    ai_provider_backoff.failed(ai.AIError('fixture backoff', transient=True, retry_after=900))
    assess = worker._assess_behavior

    def revoke_before_assessment(*args):
        _revoke_only_candidate()
        return assess(*args)

    monkeypatch.setattr(worker, '_assess_behavior', revoke_before_assessment)
    worker.investigate_one()

    assert provider.bodies == [] and ledger() == []
    assert state()['runs'] == [('deferred', 0)] and not state()['claims']
    with Session() as s:
        retry = s.get(ai_retry.TriageRetry, 'behavior-two')
        assert retry.state == 'deferred' and retry.attempts == 0
