"""Roadmap A milestone 4: triage claim contention and fairness under a daily spend cap (#1012).

Real threaded and multi-process triage runs against a shared daily cap that has room for
only some of the eligible work. Contention must never send a paid call beyond the cap or
investigate a subject twice. Work over the cap stays queued for the next window without
using a retry attempt, and a server with a large backlog cannot spend the remaining cap
while other servers with eligible work wait. Provider I/O is a disposable fixture.
"""
import json
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import pytest
from sqlalchemy import select

from app import ai, ai_budget, ai_claims, ai_pricing, ai_retry, ai_runs, worker
from app.db import Behavior, Host, Session, Setting
from app.security import seal
from tests.test_ai_claims import result

MODEL = 'gpt-6-astra'
# A fixed per-call reservation keeps "room for K calls" exact if the bundled rates change.
# Everything else about the quote (model, catalog validity, provenance) stays real.
CALL = Decimal('0.10')


def fixed_quote(real):
    def quote(payload):
        value = real(payload)
        return {**value, 'amount_usd': CALL} if value['ok'] else value
    return quote


@pytest.fixture
def priced(monkeypatch):
    monkeypatch.setattr(ai_pricing, 'reservation', fixed_quote(ai_pricing.reservation))


@pytest.fixture
def widened(monkeypatch):
    """Hold each authoritative reservation open between its spend read and its insert.

    Without this, the read-then-commit window inside ``ai_budget.reserve`` is too short for
    threads to interleave, so removing the shared budget lock would go unnoticed. Only the
    read made by ``reserve`` is delayed; preflight and status reads are unchanged.
    """
    real = ai_budget._state
    delayed = []

    def state(*args, **kwargs):
        value = real(*args, **kwargs)
        if sys._getframe(1).f_code is ai_budget.reserve.__code__:
            delayed.append(1)
            time.sleep(0.05)
        return value
    monkeypatch.setattr(ai_budget, '_state', state)
    yield
    # If reserve is wrapped or its spend read moves into a helper, the frame check above
    # stops matching and the lock test would silently fall back to relying on timing.
    assert delayed, 'widened never delayed a reserve() spend read; update the frame check'


def evidence(name):
    return {'executable': '/srv/' + name, 'sha256': 'a' * 64, 'uid': '1000', 'identity_verified': True}


def seed(backlog, calls, mode='daily_cap'):
    """backlog maps host id to its number of eligible subjects; the cap admits `calls`."""
    with Session() as s:
        s.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': MODEL, 'ai_hourly_limit': 1000,
            'ai_control_mode': mode, 'ai_rate_per_hour': 1000,
            # Half a call of headroom over K calls: K fit, K + 1 does not.
            'ai_daily_cap_usd': float(CALL * calls + CALL / 2), 'ai_budget_timezone': 'UTC'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        first_seen = 1
        for host_id, count in backlog.items():
            s.add(Host(id=host_id, name='Fixture ' + host_id, address='192.0.2.1', fingerprint=''))
            for n in range(count):
                name = host_id + '-' + str(n)
                # Earlier hosts in `backlog` hold the oldest work, so oldest-first alone
                # would serve them repeatedly.
                s.add(Behavior(id=name, host_id=host_id, first_seen=first_seen, evidence=evidence(name)))
                first_seen += 1
        s.commit()


def outcome():
    with Session() as s:
        runs = list(s.scalars(select(ai_runs.AIRun).where(ai_runs.AIRun.purpose == 'triage')))
        return {
            'runs': runs,
            'retries': {r.subject: r for r in s.scalars(select(ai_retry.TriageRetry))},
            'behaviors': {b.id: b for b in s.scalars(select(Behavior))},
            'ledger': list(s.scalars(select(ai_budget.BudgetEntry))),
            'claims': list(s.scalars(select(ai_claims.Claim))),
            'counted': Decimal(ai_budget.status(s)['counted_usd']),
            'cap': Decimal(str(s.get(Setting, 'config').value['ai_daily_cap_usd'])),
        }


def assert_cap_contention_outcome(state, sent_subjects, calls):
    """Criterion 1: exactly K paid calls, distinct subjects, the rest queued without cost."""
    assert len(sent_subjects) == calls
    assert len(set(sent_subjects)) == calls
    assert len(state['ledger']) == calls
    assert all(row.reservation_usd == CALL for row in state['ledger'])
    assert state['counted'] == CALL * calls <= state['cap']
    assert not state['claims']
    completed = {run.subject for run in state['runs'] if run.state == 'complete'}
    assert completed == set(sent_subjects)
    # No subject was ever admitted twice, sent or not.
    subjects = [run.subject for run in state['runs']]
    assert len(subjects) == len(set(subjects))
    reset = max(row.reset_at for row in state['ledger'])
    for subject, behavior in state['behaviors'].items():
        if subject in completed:
            assert behavior.verdict == 'low'
            continue
        retry = state['retries'].get(subject)
        if retry is None:
            # Refused by the read-only preflight before any run, attempt or claim.
            assert behavior.attempted == 0 and behavior.verdict == 'pending'
            assert subject not in subjects
        else:
            # Claimed, then refused by the authoritative reservation: queued, not failed.
            assert retry.state == 'deferred', (subject, retry.state, retry.reason)
            assert retry.attempts == 0
            assert retry.next_at >= reset
            run = next(run for run in state['runs'] if run.subject == subject)
            assert run.state == 'deferred'
    assert not [r for r in state['retries'].values() if r.state == 'blocked']


def overlapping_post(sent, guard, overlap):
    def post(*args, **kwargs):
        with guard:
            sent.append(ai_runs.active.get())
        overlap.wait(timeout=0.5)
        return result()
    return post


def subjects_for(run_ids):
    with Session() as s:
        return [s.get(ai_runs.AIRun, run_id).subject for run_id in run_ids]


@pytest.mark.usefixtures('priced', 'widened')
# In rate_and_daily the rate gate also spaces admissions, so only a cap with room for one
# call isolates cap contention there; daily_cap alone exercises several concurrent calls.
@pytest.mark.parametrize('mode,calls', [('daily_cap', 1), ('daily_cap', 3), ('rate_and_daily', 1)])
@pytest.mark.parametrize('preflight', ['enforced', 'bypassed'])
def test_concurrent_threads_never_send_beyond_the_cap_or_duplicate_a_subject(admin, monkeypatch, mode, calls, preflight):
    seed({'host-' + str(n): 2 for n in range(6)}, calls, mode)
    if preflight == 'bypassed':
        # The claim-time budget check is advisory. With it admitting everything, every
        # claim reaches the authoritative reservation, which alone must hold the cap.
        monkeypatch.setattr(ai_budget, 'waiting', lambda *args, **kwargs: 0)
    sent, guard, overlap = [], threading.Lock(), threading.Event()
    monkeypatch.setattr(ai.transport, 'post', overlapping_post(sent, guard, overlap))
    start = threading.Barrier(10)

    def run(_):
        start.wait(timeout=10)
        worker.investigate_one()

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(run, range(10)))
    state = outcome()
    assert_cap_contention_outcome(state, subjects_for(sent), calls)
    if preflight == 'bypassed':
        # All ten workers claimed work, so the reservation refused and deferred the rest.
        assert len(state['runs']) == 10
        assert len([r for r in state['retries'].values() if r.state == 'deferred']) == 10 - calls
    # Another round in the same window admits nothing more.
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: pytest.fail('The cap is already spent'))
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: worker.investigate_one(), range(4)))
    assert len(outcome()['ledger']) == calls


CHILD = """
import json, sys, threading, time
import pytest
from app import ai, ai_pricing, ai_runs, worker
from tests.pricing_catalog import pin_fresh_pricing_catalog
from tests.test_ai_claims import result
from tests.test_ai_claims_cap_contention_acceptance import fixed_quote

sent = []
def post(*args, **kwargs):
    sent.append(ai_runs.active.get())
    time.sleep(0.3)
    return result()

with pytest.MonkeyPatch.context() as patch:
    pin_fresh_pricing_catalog(patch)
    patch.setattr(ai_pricing, 'reservation', fixed_quote(ai_pricing.reservation))
    patch.setattr(ai.transport, 'post', post)
    print('ready', flush=True)
    sys.stdin.readline()
    threads = [threading.Thread(target=worker.investigate_one) for _ in range(2)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
print(json.dumps(sent), flush=True)
"""


@pytest.mark.usefixtures('priced')
def test_fresh_processes_share_the_cap_without_overspend_or_duplicates(admin):
    calls = 3
    seed({'host-' + str(n): 2 for n in range(5)}, calls)
    children = [subprocess.Popen([sys.executable, '-c', CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True) for _ in range(4)]
    try:
        for child in children:
            assert child.stdout.readline().strip() == 'ready'
        # Release all four processes (two threads each) as close together as possible.
        for child in children:
            child.stdin.write('\n')
            child.stdin.flush()
        sent = []
        for child in children:
            out, err = child.communicate(timeout=120)
            assert child.returncode == 0, err
            sent += json.loads(out.strip().splitlines()[-1])
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
    assert_cap_contention_outcome(outcome(), subjects_for(sent), calls)


@pytest.mark.usefixtures('priced')
def test_busy_server_cannot_spend_the_cap_ahead_of_waiting_servers_across_cycles(admin, monkeypatch):
    # host-busy holds the oldest and largest backlog; the cap has room for one call per server.
    seed({'host-busy': 5, 'host-a': 1, 'host-b': 1}, 3)
    served = []
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: served.append(ai_runs.active.get()) or result())
    # Serial scheduler cycles: each investigation releases its claim before the next.
    for _ in range(8):
        worker.investigate_one()
    with Session() as s:
        hosts = [s.get(ai_runs.AIRun, run_id).host_id for run_id in served]
    assert sorted(hosts) == ['host-a', 'host-b', 'host-busy']
    state = outcome()
    assert_cap_contention_outcome(state, subjects_for(served), 3)
    # The busy server's remaining work is still queued, not dropped or failed.
    waiting = [b for b in state['behaviors'].values() if b.host_id == 'host-busy' and b.verdict != 'low']
    assert len(waiting) == 4


@pytest.mark.usefixtures('priced', 'widened')
def test_busy_server_cannot_spend_the_cap_ahead_of_waiting_servers_in_a_burst(admin, monkeypatch):
    # The worker count does not exceed the servers with eligible work. Each claim records
    # its server's turn under the admission lock before the next claim is elected, so the
    # least-recent-turn order gives each concurrent claim a different server.
    seed({'host-busy': 5, 'host-a': 1, 'host-b': 1}, 3)
    sent, guard, overlap = [], threading.Lock(), threading.Event()
    monkeypatch.setattr(ai.transport, 'post', overlapping_post(sent, guard, overlap))
    start = threading.Barrier(3)

    def run(_):
        start.wait(timeout=10)
        worker.investigate_one()

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(run, range(3)))
    with Session() as s:
        hosts = sorted(s.get(ai_runs.AIRun, run_id).host_id for run_id in sent)
    assert hosts == ['host-a', 'host-b', 'host-busy']
    assert_cap_contention_outcome(outcome(), subjects_for(sent), 3)
    # The cap is spent: later cycles admit nothing and leave the backlog queued.
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: pytest.fail('The cap is already spent'))
    for _ in range(3):
        worker.investigate_one()
    state = outcome()
    assert len(state['ledger']) == 3
    assert len([b for b in state['behaviors'].values() if b.host_id == 'host-busy' and b.verdict != 'low']) == 4


def live_claim(host_id, subject):
    """A different worker's unexpired lease, as if it were mid-investigation."""
    now = time.time()
    with Session() as s:
        run = ai_runs.AIRun(id='run-' + subject, purpose='triage', model=MODEL, host_id=host_id, subject=subject)
        s.add(run)
        s.add(ai_claims.Claim(subject=subject, host_id=host_id, token='other-token', worker_id='process-other',
                              boot_id='other-boot', run_id=run.id, revision='', configuration='', created=now,
                              renewed=now, expires=now + ai_claims.LEASE_SECONDS))
        s.commit()


@pytest.mark.usefixtures('priced')
def test_a_server_already_under_investigation_yields_the_cap_to_an_idle_server(admin, monkeypatch):
    # No server has had a turn, so turns tie. host-busy holds the oldest work, so oldest-first
    # alone would elect it again; only live-occupancy balancing gives the last call to host-idle.
    seed({'host-busy': 3, 'host-idle': 1}, 1)
    live_claim('host-busy', 'host-busy-0')
    served = []
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: served.append(ai_runs.active.get()) or result())
    worker.investigate_one()
    with Session() as s:
        assert [s.get(ai_runs.AIRun, run_id).host_id for run_id in served] == ['host-idle']
        assert s.get(Behavior, 'host-idle-0').verdict == 'low'
        assert [row.reservation_usd for row in s.scalars(select(ai_budget.BudgetEntry))] == [CALL]
        # The other worker's live lease is untouched.
        assert s.get(ai_claims.Claim, 'host-busy-0').token == 'other-token'


@pytest.mark.usefixtures('priced')
def test_a_server_whose_only_work_is_claimed_does_not_win_the_election(admin, monkeypatch):
    # host-claimed holds the oldest work, but all of it is already under another worker's
    # live lease. Its other turn-free eligible peer must be elected rather than a host whose
    # election would find nothing to claim and leave the remaining cap unused.
    seed({'host-claimed': 1, 'host-open': 1}, 1)
    live_claim('host-claimed', 'host-claimed-0')
    # Same occupancy for both servers: the open one also has a live lease on unrelated work.
    live_claim('host-open', 'unrelated-subject')
    served = []
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: served.append(ai_runs.active.get()) or result())
    worker.investigate_one()
    with Session() as s:
        assert [s.get(ai_runs.AIRun, run_id).host_id for run_id in served] == ['host-open']
        assert s.get(Behavior, 'host-open-0').verdict == 'low'
