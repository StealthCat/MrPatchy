"""Roadmap A milestone 4: capped update scoring after scheduler coordinator loss."""
from concurrent.futures import Future
from contextlib import contextmanager
from decimal import Decimal
import json
import subprocess
import sys
import time

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_budget, ai_pricing, ai_runs, update_scores, worker, worker_registry
from app.db import Behavior, Host, Session
from tests.test_ai_daily_cap_billable_paths import (
    MODEL,
    NOW,
    RESET,
    clock as clock,
    configure,
    ledger_rows,
    respond,
    scoring_quote,
    scores,
    seed_scoring,
)

EVIDENCE = {'executable': '/srv/fixture', 'sha256': 'a' * 64, 'uid': '1000', 'identity_verified': True}
HOLD_SCHEDULER = """
from pathlib import Path
import sys

from app.coordination import Lock

with Lock('scheduler'):
    Path(sys.argv[1]).touch()
    sys.stdin.read(1)
"""


@contextmanager
def former_coordinator(ready):
    """Hold the real scheduler lock in a disposable process until it is killed."""
    with subprocess.Popen(
        [sys.executable, '-c', HOLD_SCHEDULER, str(ready)],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    ) as process:
        try:
            deadline = time.monotonic() + 20
            while not ready.exists() and time.monotonic() < deadline and process.poll() is None:
                time.sleep(0.025)
            if process.poll() is not None:
                pytest.fail(f'Scheduler fixture exited: {process.stderr.read().decode(errors="replace")}')
            assert ready.exists(), 'The former coordinator never acquired the scheduler lock'
            yield process
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=15)


class InlinePool:
    """Make dispatch deterministic while still running the real AI work."""

    def __init__(self, **_options):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def submit(self, fn, *args):
        future = Future()
        result = fn(*args) if fn in (worker.investigate_one, update_scores.run_one) else None
        future.set_result(result)
        return future


@pytest.mark.parametrize('has_headroom', [True, False], ids=['score-fits', 'score-deferred'])
def test_replacement_coordinator_keeps_shared_budget(admin, monkeypatch, clock, tmp_path, has_headroom):
    triage_quote = ai_pricing.reservation(ai.investigation_payload(EVIDENCE, MODEL))['amount_usd']
    score_floor = scoring_quote()
    cap = Decimal('10') if has_headroom else max(triage_quote, score_floor) + min(triage_quote, score_floor) / 2
    configure(cap)
    seed_scoring()
    with Session() as session:
        session.add(Host(id='triage-host', name='Triage fixture', address='192.0.2.1', fingerprint=''))
        session.add(Behavior(id='triage-subject', host_id='triage-host', evidence=EVIDENCE))
        session.commit()

    sent = []
    quotes = []
    leadership_ticks = []

    def post(*args, **kwargs):
        if isinstance(json.loads(kwargs['json']['input']), list):
            sent.append('update_scoring')
            return respond(scores)(*args, **kwargs)
        sent.append('triage')
        result = respond(lambda _: {'risk': 'low', 'explanation': 'Fixture result',
            'recommended_checks': 'Review the fixture', 'requested_checks': []})(*args, **kwargs)
        body = result.json()
        # Without a usage receipt, the triage charge keeps its conservative ceiling.
        del body['usage']
        return httpx.Response(200, json=body, request=result.request)

    reserve = ai_budget.reserve

    def record_quote(payload):
        quotes.append(ai_pricing.reservation(payload)['amount_usd'])
        return reserve(payload)

    monkeypatch.setattr(ai.transport, 'post', post)
    monkeypatch.setattr(ai_budget, 'reserve', record_quote)
    monkeypatch.setattr(update_scores, '_MEMO', {})
    monkeypatch.setattr(worker.concurrent.futures, 'ThreadPoolExecutor', InlinePool)
    monkeypatch.setattr(worker, 'periodic_ticks', lambda now, _: leadership_ticks.append(now))
    monkeypatch.setattr(worker, 'reconcile_interrupted_advisory_jobs', lambda: None)
    monkeypatch.setattr(worker.operations, 'collect_alerts', lambda **_: None)
    monkeypatch.setenv('MRPATCHY_AI_CONCURRENCY', '1')

    ticks = 0
    earlier_charge = None
    with former_coordinator(tmp_path / 'scheduler-ready') as former, worker_registry.Registration() as node:
        def wait(_):
            nonlocal ticks, earlier_charge
            ticks += 1
            clock.value = NOW + ticks * 6
            if ticks == 2:
                assert sent == ['triage'] and leadership_ticks == []
                with Session() as session:
                    assert session.scalar(select(update_scores.UpdateScore)) is None
                [earlier_charge] = ledger_rows()
                assert earlier_charge.status == 'uncertain' and earlier_charge.reset_at == RESET
                former.kill()
                assert former.wait(timeout=15) != 0
            return ticks >= 3

        monkeypatch.setattr(worker.stop, 'wait', wait)
        worker._loop(node)

    assert leadership_ticks == [NOW + 12]
    admitted_quote, successor_quote = quotes
    rows = ledger_rows()
    with Session() as session:
        assert session.get(Behavior, 'triage-subject').verdict == 'low'
        score = session.scalar(select(update_scores.UpdateScore))
        run = session.get(ai_runs.AIRun, score.run_id)
        assert run.purpose == 'update_scoring'
        triage_entries = [row for row in rows if session.get(ai_runs.AIRun, row.run_id).purpose == 'triage']
        [triage] = triage_entries
        assert triage.status == 'uncertain' and triage.reset_at == RESET and triage.call_id
        assert triage.id == earlier_charge.id and triage.call_id == earlier_charge.call_id
        assert triage.reservation_usd == earlier_charge.reservation_usd == admitted_quote
        counted = Decimal(ai_budget.status(session)['counted_usd'])

        if has_headroom:
            assert sent == ['triage', 'update_scoring'] and len(rows) == 2
            assert score.state == run.state == 'complete' and score.score == 40 and run.calls == 1
            [scoring] = [row for row in rows if row.run_id == run.id]
            assert scoring.status == 'settled' and scoring.reset_at == RESET and scoring.call_id
            assert counted == triage.reservation_usd + scoring.actual_usd
        else:
            # The score fits on its own. Only the retained charge makes it wait.
            assert successor_quote <= cap < admitted_quote + successor_quote
            assert sent == ['triage'] and len(rows) == 1
            assert score.state == run.state == 'deferred' and score.score is None and run.calls == 0
            assert score.next_at == pytest.approx(RESET, abs=1)
            assert counted == triage.reservation_usd
