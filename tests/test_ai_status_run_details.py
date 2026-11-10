import time

import pytest
from sqlalchemy import event

from app import ai_runs
from app.db import Session, Setting, engine


@pytest.mark.parametrize('state,expected_error', [
    ('error', 'Latest diagnostic'), ('interrupted', 'Latest diagnostic'), ('complete', ''),
])
def test_status_reads_running_stage_and_latest_diagnostic_together(admin, state, expected_error):
    now = time.time()
    with Session() as session:
        session.add_all([
            Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture'}),
            Setting(key='openai_key', value={'encrypted': 'fixture'}),
            Setting(key='worker:heartbeat', value={'seen': now}),
            ai_runs.AIRun(id='running-old', purpose='triage', started=now - 40, stage='older stage'),
            ai_runs.AIRun(id='running-new', purpose='triage', started=now - 30, stage='evidence'),
            ai_runs.AIRun(id='worker-new', purpose='worker', started=now - 20,
                         state=state, message='Latest diagnostic'),
            ai_runs.AIRun(id='unrelated', purpose='update_scoring', started=now - 10,
                         stage='unrelated stage', message='Unrelated diagnostic'),
        ])
        session.commit()

    detail_reads = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        query = statement.lower()
        if 'from ai_runs' in query and 'order by ai_runs.started desc' in query:
            detail_reads.append(query)

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        with Session() as session:
            status = ai_runs.status(session)
    finally:
        event.remove(engine, 'before_cursor_execute', capture)

    assert status['reason'] == 'running'
    assert status['message'].endswith('Latest stage: evidence')
    assert status['last_run'] == 'worker-new'
    assert status['last_error'] == expected_error
    assert len(detail_reads) == 1
    assert 'union all' in detail_reads[0]
    assert 'ai_runs.subject' not in detail_reads[0]
    assert 'ai_runs.model' not in detail_reads[0]


def test_status_has_empty_run_details_when_no_matching_history(admin):
    with Session() as session:
        session.add(ai_runs.AIRun(id='unrelated', purpose='update_scoring', stage='unrelated'))
        session.commit()
        status = ai_runs.status(session)

    assert status['last_run'] is None
    assert status['last_error'] == ''
