"""Roadmap A milestone 4: non-triage billable paths share one daily spend cap.

Update scoring, AI security plans, release configuration review and the
administrator connection test all reach the provider through ``ai.request``.
These tests drive each of them through its real code path into a daily cap that
has no safe room left, and check four things: nothing is sent, nothing is
written to the ledger, deferrable work waits for the window reset instead of
failing, and every path draws from the same cap.  Only the provider transport is
a fixture.
"""
import json
import time
import uuid
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import func, select

from app import (
    ai,
    ai_budget,
    ai_pricing,
    ai_runs,
    incidents,
    releases,
    update_scores,
    worker,
)
from app.db import Host, Job, Package, Session, Setting
from app.security import seal

MODEL='gpt-6-luna'
NOW=1793404800.0+3600  # 2026-10-31T01:00:00Z, inside the bundled catalog's validity
RESET=1793491200.0     # 2026-11-01T00:00:00Z, the next UTC window


class Clock:
    def __init__(self, value):self.value=value
    def __call__(self):return self.value


@pytest.fixture
def clock(monkeypatch):
    # The modules share the time module, so one patch moves every reader together.
    value=Clock(NOW);monkeypatch.setattr(time, 'time', value)
    return value


def configure(cap):
    with Session() as session:
        session.merge(Setting(key='config', value={'ai_enabled':True,
            'ai_updates_enabled':True, 'ai_model':MODEL, 'ai_control_mode':'daily_cap',
            'ai_daily_cap_usd':float(cap), 'ai_budget_timezone':'UTC'}))
        session.merge(Setting(key='openai_key', value={'encrypted':seal('fixture-key')}))
        session.commit()


def spend(amount):
    """Record an earlier settled call in the current window."""
    with Session() as session:
        session.add(ai_budget.BudgetEntry(id=str(uuid.uuid4()), created=NOW-60, updated=NOW-60,
            reset_at=RESET, timezone='UTC', model=MODEL, status='settled',
            reservation_usd=Decimal(amount), actual_usd=Decimal(amount),
            pricing_version='fixture', pricing_source='fixture'))
        session.commit()


def ledger_rows():
    with Session() as session:
        return list(session.scalars(select(ai_budget.BudgetEntry).where(
            ai_budget.BudgetEntry.pricing_version!='fixture')))


def refuse_transport(monkeypatch):
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: pytest.fail('a capped call reached provider transport'))


def respond(body):
    def post(*args, **kwargs):
        return httpx.Response(200, json={'status':'completed', 'model':MODEL, 'service_tier':'default',
            'usage':{'input_tokens':10, 'output_tokens':10, 'total_tokens':20,
                'input_tokens_details':{'cached_tokens':0, 'cache_write_tokens':0},
                'output_tokens_details':{'reasoning_tokens':0}},
            'output':[{'content':[{'type':'output_text', 'text':json.dumps(body(kwargs['json']))}]}]},
            request=httpx.Request('POST', ai.URL))
    return post


def scores(payload):
    return {'assessments':[{'id':item['id'], 'score':40, 'confidence':'low',
        'explanation':'Bounded fixture assessment.', 'limitations':'No advisory evidence.'}
        for item in json.loads(payload['input'])]}


def seed_scoring():
    with Session() as session:
        session.add(Host(id='cap-score', name='Cap score', address='192.0.2.10',
            fingerprint='', state='online', inventory={'os':'ID=debian\nVERSION_ID=12'}))
        session.add(Package(id='cap-score:fixture', host_id='cap-score', name='fixture',
            installed='1', candidate='2', available_since=NOW-3600))
        session.commit()


def seed_security_plan():
    with Session() as session:
        session.add(Host(id='cap-plan', name='Cap plan', address='192.0.2.11',
            fingerprint='', state='online'))
        incidents.record(session, 'cap-plan', 'scan-cap', {'state':'completed_with_findings',
            'findings':[{'path':'/srv/fixture', 'sha256':'b'*64, 'evidence':'fixture rule'}]})
        incident=session.scalar(select(incidents.Incident))
        session.commit()
        return worker.enqueue(session, 'cap-plan', 'security-plan', {'incident_id':incident.id}), incident.id


def plan_body(incident_id):
    def body(payload):
        return {'summary':'Review the retained scanner evidence', 'severity':'unknown',
            'uncertainty':'The finding may be a false positive.',
            'steps':[{'action':'preserve_evidence', 'reason':'Retain the artifact receipt.',
                'impact':'Uses protected storage.', 'verification':'Compare the retained digest.',
                'evidence_ids':[incident_id, 'scan-cap']}]}
    return body


def scoring_quote():
    # The scoring request is bounded by max_output_tokens; any batch quote is
    # at least the bare output ceiling, so spending cap-minus-a-cent leaves no room.
    return ai_pricing.reservation({'model':MODEL, 'input':'x', 'max_output_tokens':4000})['amount_usd']


def test_update_scoring_defers_to_reset_without_send_or_ledger_and_resumes(admin, clock, monkeypatch):
    configure(Decimal(1));spend('0.999999');seed_scoring()
    refuse_transport(monkeypatch)
    update_scores.run_one()
    with Session() as session:
        row=session.scalar(select(update_scores.UpdateScore))
        assert row.state=='deferred' and row.next_at==pytest.approx(RESET, abs=1)
        assert row.score is None
        run=session.get(ai_runs.AIRun, row.run_id)
        assert run.state=='deferred' and run.calls==0 and run.purpose=='update_scoring'
    assert ledger_rows()==[]
    # Nothing is retried inside the spent window.
    clock.value=RESET-5;update_scores.run_one()
    assert ledger_rows()==[]
    clock.value=RESET+5
    monkeypatch.setattr(ai.transport, 'post', respond(scores))
    update_scores.run_one()
    with Session() as session:
        row=session.scalar(select(update_scores.UpdateScore))
        assert row.state=='complete' and row.score==40 and row.next_at==0
    rows=ledger_rows()
    assert len(rows)==1 and rows[0].status=='settled' and rows[0].reset_at==pytest.approx(RESET+86400)


def test_security_plan_job_stays_queued_until_reset_and_then_completes(admin, clock, monkeypatch):
    configure(Decimal(1));spend('0.999999')
    job_id,incident_id=seed_security_plan()
    refuse_transport(monkeypatch)
    worker.execute(job_id)
    with Session() as session:
        job=session.get(Job, job_id)
        assert job.state=='queued' and job.next_at==pytest.approx(RESET, abs=1)
        assert job.payload['_ai_deferred'] is True
        run=session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='security_plan'))
        assert run.state=='deferred' and run.calls==0
        assert session.scalar(select(func.count()).select_from(incidents.Plan))==0
    assert ledger_rows()==[]
    clock.value=RESET+5
    monkeypatch.setattr(ai.transport, 'post', respond(plan_body(incident_id)))
    worker.execute(job_id)
    with Session() as session:
        job=session.get(Job, job_id)
        assert job.state=='complete', job.output
        assert '_ai_deferred' not in job.payload
        assert session.scalar(select(incidents.Plan)).incident_id==incident_id
    assert [row.status for row in ledger_rows()]==['settled']


def test_release_configuration_review_is_a_controlled_wait_until_reset(admin, clock, monkeypatch):
    configure(Decimal(1));spend('0.999999')
    with Session() as session:
        session.add(Host(id='cap-release', name='Cap release', address='192.0.2.12',
            fingerprint='', state='online'))
        session.commit()
    refuse_transport(monkeypatch)
    with Session() as session, pytest.raises(ai.AIError) as raised:
        releases.ai_review(session, {'distribution':'debian', 'version':'13'}, '/etc/fixture.conf',
            'option = 1\n', 'option = 2\n', '', host_id='cap-release', plan_id='plan-cap')
    error=raised.value
    assert error.policy_wait and not error.transient
    assert ai.defer_until(error)==pytest.approx(RESET, abs=1)
    with Session() as session:
        run=session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='release_configuration'))
        assert run.calls==0
    assert ledger_rows()==[]


def test_connection_test_is_refused_before_transport_and_ledger(admin, clock, monkeypatch):
    configure(Decimal(1));spend('0.999999')
    refuse_transport(monkeypatch)
    response=admin.post('/api/settings/ai-test', json={})
    assert response.status_code==502
    assert 'daily AI spend cap' in response.json()['detail']
    assert 'No provider request was sent' in response.json()['detail']
    with Session() as session:
        run=session.get(ai_runs.AIRun, response.json()['run_id'])
        assert run.purpose=='connection_test' and run.calls==0
    assert ledger_rows()==[]


def test_paths_draw_from_one_cap_and_ledger_only_records_sent_calls(admin, clock, monkeypatch):
    """Room for one scoring call: once scoring sends it, a security plan waits for the reset."""
    quote=scoring_quote()
    # Leave room for one conservative scoring reservation but not for two calls.
    configure(Decimal(1));spend(str(Decimal(1)-quote-quote/2))
    seed_scoring();job_id,_incident_id=seed_security_plan()
    sent=[]
    def post(*args, **kwargs):
        sent.append(kwargs['json'].get('text', {}).get('format', {}).get('name'))
        return respond(scores)(*args, **kwargs)
    monkeypatch.setattr(ai.transport, 'post', post)
    update_scores.run_one()
    assert sent==['update_importance']
    with Session() as session:
        assert session.scalar(select(update_scores.UpdateScore)).state=='complete'
    rows=ledger_rows()
    assert len(rows)==1 and rows[0].status=='settled'
    # Settled cost is far below the reservation, so re-pin the spent amount to the
    # original ceiling: the plan must see the window as still too full.
    with Session() as session:
        entry=session.get(ai_budget.BudgetEntry, rows[0].id)
        entry.actual_usd=entry.reservation_usd;session.commit()
    worker.execute(job_id)
    assert sent==['update_importance']
    with Session() as session:
        job=session.get(Job, job_id)
        assert job.state=='queued' and job.next_at==pytest.approx(RESET, abs=1)
    assert len(ledger_rows())==1
