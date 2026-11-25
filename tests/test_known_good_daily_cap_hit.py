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


# --- Rotating free-hit probe window (#1241) ---------------------------------

@pytest.fixture
def fresh_cursor(monkeypatch):
    monkeypatch.setattr(ai_claims, '_free_hit_cursor', None, raising=False)
    monkeypatch.setattr(ai_claims, '_free_hit_candidates', None, raising=False)
    monkeypatch.setattr(ai_claims, '_free_hit_sweep', None, raising=False)


@pytest.fixture
def probes(monkeypatch):
    seen = []
    probe = known_good.exact_hit_available

    def counted(s, row, model):
        seen.append(row.id)
        return probe(s, row, model)

    monkeypatch.setattr(known_good, 'exact_hit_available', counted)
    return seen


def test_a_hit_behind_a_full_window_of_older_paid_subjects_is_found(client, provider, fresh_cursor, probes):
    configure()
    exhaust()
    older = ['older-%02d' % index for index in range(ai_claims.FREE_HIT_SCAN)]
    for index, subject in enumerate(older):
        seed(hit=False, subject=subject, host='host-three', first_seen=1 + index)
    seed(first_seen=1000)

    worker.investigate_one()
    assert probes == older  # one bounded, oldest-first pass without a hit
    assert held()
    worker.investigate_one()

    assert reused()
    assert provider.bodies == [] and [status for status, _ in ledger()] == ['settled']
    assert all(held(subject) for subject in older)
    # The newest subject is probed first after the rotation, and every
    # closed-gate pass stays within the probe bound.
    assert probes[ai_claims.FREE_HIT_SCAN] == 'behavior-two'
    assert len(probes) <= 2 * ai_claims.FREE_HIT_SCAN
    assert ai_claims._free_hit_cursor is None


def test_the_rotation_wraps_to_reach_a_new_hit_older_than_the_cursor(client, provider, fresh_cursor, probes, monkeypatch):
    monkeypatch.setattr(ai_claims, 'FREE_HIT_SCAN', 2)
    configure()
    exhaust()
    for index in range(3):
        seed(hit=False, subject='miss-%d' % index, host='host-three', first_seen=10 + index)

    worker.investigate_one()
    worker.investigate_one()
    assert probes == ['miss-0', 'miss-1', 'miss-2', 'miss-0']  # the second pass wraps
    assert ai_claims._free_hit_cursor == (10, 'miss-0')

    seed(first_seen=5)  # a hit older than every subject and the cursor
    passes = 0
    while not reused() and passes < 3:
        worker.investigate_one()
        passes += 1
    assert reused()
    assert passes <= 2  # reached within ceil(subjects / FREE_HIT_SCAN) passes
    assert provider.bodies == []
    assert all(held('miss-%d' % index) for index in range(3))


def test_a_stale_cursor_still_probes_the_oldest_subjects(client, provider, fresh_cursor, monkeypatch):
    # A cursor beyond every eligible subject (cleared queue, or a cursor left
    # by an earlier database) wraps within the same pass instead of missing.
    monkeypatch.setattr(ai_claims, '_free_hit_cursor', (10 ** 12, 'gone'), raising=False)
    configure()
    exhaust()
    seed(hit=False, subject='older-miss', host='host-three', first_seen=1)
    seed(first_seen=2)
    worker.investigate_one()
    assert reused() and held('older-miss')
    assert provider.bodies == []


def _publish_candidate_for_misses(digest='f' * 64, assessment='assessment-late'):
    """Publish a new fleet candidate; the default matches every ``seed(hit=False)`` artifact."""
    snapshot = complete()
    snapshot['sha256'] = digest
    snapshot['investigation']['details']['known_good_context']['artifact']['sha256'] = digest
    with Session() as s:
        source = retained(id=assessment, subject='behavior-' + assessment, snapshot=snapshot)
        source.model = MODEL
        source.policy_hash = ai_assessments.digest([ai.investigation_policy()])
        s.add(source)
        s.flush()
        assert known_good.publish(s, source)['published']
        s.commit()


def test_a_new_candidate_restarts_the_rotation_so_the_oldest_new_hit_is_claimed_first(
        client, provider, fresh_cursor, probes, monkeypatch):
    # #1291: after a pass without a hit, a candidate published before the next
    # pass makes subjects behind the cursor exact hits. The oldest must win.
    monkeypatch.setattr(ai_claims, 'FREE_HIT_SCAN', 2)
    configure()
    exhaust()
    misses = ['miss-%d' % index for index in range(4)]
    for index, subject in enumerate(misses):
        seed(hit=False, subject=subject, host='host-three', first_seen=10 + index)

    worker.investigate_one()
    assert probes == ['miss-0', 'miss-1'] and ai_claims._free_hit_cursor is not None
    assert all(held(subject) for subject in misses)

    _publish_candidate_for_misses()
    worker.investigate_one()

    assert reused('miss-0')
    assert all(held(subject) for subject in misses[1:])
    # Restarted from the oldest: its own probe, then the re-check under the
    # host queue gate. No newer subject was probed.
    assert probes[2:] == ['miss-0', 'miss-0']
    assert provider.bodies == [] and [status for status, _ in ledger()] == ['settled']
    assert ai_claims._free_hit_cursor is None


def test_without_a_new_candidate_the_rotation_still_resumes_after_the_cursor(
        client, provider, fresh_cursor, probes, monkeypatch):
    # Control for #1291: an unchanged candidate set keeps the #1241 rotation,
    # and a revocation (which never creates a hit) does not restart it.
    monkeypatch.setattr(ai_claims, 'FREE_HIT_SCAN', 2)
    configure()
    exhaust()
    for index in range(4):
        seed(hit=False, subject='miss-%d' % index, host='host-three', first_seen=10 + index)

    worker.investigate_one()
    _revoke_only_candidate()
    worker.investigate_one()
    assert probes == ['miss-0', 'miss-1']  # no active candidate: no probe pass at all
    # Reopen the probe path without publishing a row. The product never
    # reactivates a candidate; this only shows the count, not activity, drives
    # the restart.
    with Session() as s:
        s.query(known_good.Entry).update({'active': True})
        s.commit()
    worker.investigate_one()
    assert probes == ['miss-0', 'miss-1', 'miss-2', 'miss-3']
    assert ai_claims._free_hit_cursor == (13, 'miss-3')
    assert provider.bodies == []


def test_a_restart_without_a_hit_does_not_rewind_the_rotation(client, provider, fresh_cursor, probes, monkeypatch):
    # #1291: an unrelated publication costs one bounded sweep from the oldest up
    # to the cursor, and the rotation then continues where it stopped instead of
    # starting over.
    monkeypatch.setattr(ai_claims, 'FREE_HIT_SCAN', 2)
    configure()
    exhaust()
    for index in range(6):
        seed(hit=False, subject='miss-%d' % index, host='host-three', first_seen=10 + index)

    worker.investigate_one()
    worker.investigate_one()
    assert ai_claims._free_hit_cursor == (13, 'miss-3')
    _publish_candidate_for_misses('e' * 64, 'assessment-unrelated')  # matches no subject
    worker.investigate_one()
    assert probes[4:] == ['miss-0', 'miss-1']  # the sweep starts from the oldest
    assert ai_claims._free_hit_cursor == (13, 'miss-3')  # not rewound
    worker.investigate_one()
    assert probes[6:] == ['miss-2', 'miss-3']  # and ends exactly at the cursor
    assert ai_claims._free_hit_cursor == (13, 'miss-3') and ai_claims._free_hit_sweep is None
    worker.investigate_one()
    assert probes[8:] == ['miss-4', 'miss-5']  # the rotation resumes after the cursor
    assert ai_claims._free_hit_cursor == (15, 'miss-5')
    assert all(held('miss-%d' % index) for index in range(6))
    assert provider.bodies == []


def _seed_ordered_misses(count, matching=(), digest='d' * 64):
    """Paid subjects ``miss-N``; those in ``matching`` share ``digest``, the others are unique."""
    for index in range(count):
        seed(hit=False, subject='miss-%d' % index, host='host-three', first_seen=10 + index)
        artifact = digest if index in matching else '%02d' % index * 32
        with Session() as s:
            behavior = s.get(Behavior, 'miss-%d' % index)
            evidence = json.loads(json.dumps(behavior.evidence))
            evidence['sha256'] = artifact
            evidence['investigation']['details']['known_good_context']['artifact']['sha256'] = artifact
            behavior.evidence = evidence
            s.commit()


def test_a_new_hit_beyond_the_first_window_but_behind_the_cursor_is_claimed_before_a_newer_one(
        client, provider, fresh_cursor, probes, monkeypatch):
    # #1291 review: seven subjects, three passes leave the cursor at miss-5, then
    # a candidate matching only miss-2 and miss-6 is published. miss-2 sits past
    # the first window after the oldest, so a single restart pass cannot see it;
    # the sweep must reach it before the rotation resumes at miss-6.
    monkeypatch.setattr(ai_claims, 'FREE_HIT_SCAN', 2)
    configure()
    exhaust()
    _seed_ordered_misses(7, matching=(2, 6))
    for _ in range(3):
        worker.investigate_one()
    assert probes == ['miss-%d' % index for index in range(6)]
    assert ai_claims._free_hit_cursor == (15, 'miss-5')

    _publish_candidate_for_misses('d' * 64)
    passes = 0
    while not reused('miss-2') and passes < 4:
        worker.investigate_one()
        assert held('miss-6')  # never overtaken by the newer hit
        passes += 1
    assert reused('miss-2')
    assert passes == 2  # ceil(subjects behind the cursor / FREE_HIT_SCAN) passes at most
    assert probes[6:] == ['miss-0', 'miss-1', 'miss-2', 'miss-2']  # probe, then host-gate re-check
    assert all(held('miss-%d' % index) for index in (0, 1, 3, 4, 5, 6))
    assert provider.bodies == [] and [status for status, _ in ledger()] == ['settled']
    assert ai_claims._free_hit_cursor is None and ai_claims._free_hit_sweep is None

    while not reused('miss-6') and passes < 10:
        worker.investigate_one()
        passes += 1
    assert reused('miss-6') and provider.bodies == []


def test_a_publication_during_a_sweep_restarts_it_from_the_oldest(
        client, provider, fresh_cursor, probes, monkeypatch):
    monkeypatch.setattr(ai_claims, 'FREE_HIT_SCAN', 2)
    configure()
    exhaust()
    _seed_ordered_misses(7, matching=(0,), digest='c' * 64)
    for _ in range(3):
        worker.investigate_one()
    _publish_candidate_for_misses('e' * 64, 'assessment-unrelated')
    worker.investigate_one()
    assert probes[6:] == ['miss-0', 'miss-1'] and ai_claims._free_hit_sweep is not None
    _publish_candidate_for_misses('c' * 64, 'assessment-oldest')  # now miss-0 is a hit
    worker.investigate_one()
    assert reused('miss-0')
    assert probes[8:] == ['miss-0', 'miss-0']
    assert all(held('miss-%d' % index) for index in range(1, 7)) and provider.bodies == []


# A positive balance smaller than the elected paid subject's own reservation
# leaves every shared start gate open. The paid subject must stay queued, and an
# exact hit elsewhere must still be reused with zero provider calls (#1490).

def test_paid_head_without_headroom_does_not_block_exact_reuse(client, provider):
    configure()
    exhaust('4.999999')  # The default $5 cap still has $0.000001 available.
    seed(hit=False, subject='behavior-old', host='host-three', first_seen=1)
    seed(subject='behavior-new', host='host-two', first_seen=2)
    with Session() as s:
        assert not ai_budget.waiting(s, time.time())  # the fleet-wide gate stays open
    before = ledger()
    worker.investigate_one()
    assert held('behavior-old')
    assert provider.bodies == []
    assert ledger() == before
    assert reused('behavior-new')


def test_paid_head_without_headroom_keeps_a_paused_hit_held(client, provider):
    configure()
    exhaust('4.999999')
    seed(hit=False, subject='behavior-old', host='host-three', first_seen=1)
    seed(subject='behavior-new', host='host-two', first_seen=2)
    with Session() as s:
        s.merge(Setting(key='server-ai:host-two', value={'paused': True}))
        s.commit()
    before = ledger()
    worker.investigate_one()
    assert provider.bodies == []
    assert ledger() == before
    assert held('behavior-old')
    assert held('behavior-new')


def test_paid_head_without_headroom_does_not_reuse_for_an_administrator_retriage(client, provider):
    configure()
    exhaust('4.999999')
    seed(hit=False, subject='behavior-old', host='host-three', first_seen=1)
    seed(subject='behavior-new', host='host-two', first_seen=2, refresh=True)
    worker.investigate_one()
    assert provider.bodies == []
    assert held('behavior-old')
    assert held('behavior-new')
    with Session() as s:
        assert s.get(ai_assessments.Refresh, 'behavior-new') is not None


def test_paid_head_that_fits_is_still_admitted_before_a_newer_hit(client, provider):
    configure()
    seed(hit=False, subject='behavior-old', host='host-three', first_seen=1)
    seed(subject='behavior-new', host='host-two', first_seen=2)
    lease = ai_claims.acquire()
    assert lease is not None and lease.subject == 'behavior-old'
    assert state('behavior-old')['claims']
    assert held('behavior-new')
    assert provider.bodies == []


def test_paid_head_over_the_whole_cap_is_still_blocked_with_a_reason(client, provider):
    configure(ai_daily_cap_usd=0.000001)
    seed(hit=False, subject='behavior-old', host='host-three', first_seen=1)
    seed(subject='behavior-new', host='host-two', first_seen=2)
    worker.investigate_one()
    with Session() as s:
        retry = s.get(ai_retry.TriageRetry, 'behavior-old')
        assert retry is not None and retry.state == 'blocked'
    worker.investigate_one()
    assert provider.bodies == []
    assert ledger() == []
    assert held('behavior-old')
    assert reused('behavior-new')
