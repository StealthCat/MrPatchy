"""Retain advisory plan result-persistence timings through the real worker paths."""
import json
import re

import httpx
import pytest
from sqlalchemy import event, select

from app import ai, ai_runs, incidents, worker
from app.db import Job, Session
from tests.test_ai_plan_deferral import plan as incident_plan, seed_security_plan
from test_startup_ai import BASE, response as startup_plan, setup_incident


@pytest.fixture(params=['incident', 'startup'])
def advisory_job(admin, request):
    if request.param == 'incident':
        job_id, subject = seed_security_plan()
        return job_id, subject, incident_plan(subject)

    subject = setup_incident(admin)
    with Session() as session:
        updated = session.get(incidents.PersistenceIncident, subject).updated
    queued = admin.post(f'{BASE}/persistence-incidents/{subject}/plan',
                        json={'expected_updated': updated})
    assert queued.status_code == 200
    return queued.json()['job_id'], subject, startup_plan(subject)


@pytest.mark.parametrize(('case', 'timing_outcome'), [
    ('saved', 'complete'), ('save_failed', 'error'), ('invalid', None), ('refused', None),
])
def test_advisory_job_retains_persistence_timing(advisory_job, monkeypatch, case, timing_outcome):
    job_id, subject, content = advisory_job
    if case == 'invalid':
        content = {'summary': 'Incomplete fixture response'}
    message = {'type': 'output_text', 'text': json.dumps(content)}
    if case == 'refused':
        message = {'type': 'refusal', 'refusal': 'Refused fixture response'}
    response = {'status': 'completed', 'output': [{'content': [message]}]}
    monkeypatch.setattr(ai.transport, 'post', lambda *args, **kwargs:
        httpx.Response(200, json=response, request=httpx.Request('POST', ai.URL)))

    def reject_plan_flush(session, flush_context, instances):
        if any(isinstance(row, incidents.Plan) for row in session.new):
            raise RuntimeError('Fixture advisory plan write failed')

    if case == 'save_failed':
        event.listen(Session.class_, 'before_flush', reject_plan_flush)
    try:
        worker.execute(job_id)
    finally:
        if case == 'save_failed':
            event.remove(Session.class_, 'before_flush', reject_plan_flush)

    with Session() as session:
        job = session.get(Job, job_id)
        run = session.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject == subject))
        plan = session.scalar(select(incidents.Plan).where(incidents.Plan.incident_id == subject))
        timings = list(session.scalars(select(ai_runs.AIEvent.message).where(
            ai_runs.AIEvent.run_id == run.id, ai_runs.AIEvent.stage == 'timing_result_persistence')))
        assert run.calls == 1
        if case == 'saved':
            assert job.state == run.state == 'complete'
            assert plan is not None and plan.run_id == run.id
        else:
            assert job.state == 'failed' and run.state == 'error' and plan is None
        if timing_outcome is None:
            assert timings == []
        else:
            assert len(timings) == 1
            assert re.fullmatch(r'result persistence: [0-9]+\.[0-9]{3} ms; outcome=' + timing_outcome, timings[0])
