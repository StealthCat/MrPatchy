import pytest
from sqlalchemy import event, select

from app import incidents
from app.db import Host, Job, Session, Setting, engine


@pytest.mark.parametrize('mode', ['legacy', 'rate', 'daily_cap', 'rate_and_daily', 'unthrottled'])
def test_auto_plan_only_counts_hourly_history_in_legacy_mode(admin, mode):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'fixture', 'ai_control_mode': mode,
        }))
        session.add(Setting(key='openai_key', value={'encrypted': 'fixture'}))
        for number in range(12):
            host_id = f'eligible-{number}'
            session.add(Host(id=host_id, name=host_id, address='192.0.2.1', fingerprint=''))
            session.add(Setting(key=f'security-policy:{host_id}', value={'auto_ai_plan': True}))
            session.add(incidents.Incident(id=host_id, host_id=host_id, scan_id='scan', evidence={}))
        session.add_all(Job(id=f'old-{number}', host_id='older-host', state='failed',
                            action='security-plan' if number % 2 else 'startup-plan') for number in range(10))
        session.commit()

    history_reads = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        sql = statement.lower()
        if 'count(' in sql and 'from jobs' in sql and 'jobs.created >' in sql:
            history_reads.append(sql)

    event.listen(engine, 'before_cursor_execute', observe)
    try:
        incidents.auto_plan_tick()
    finally:
        event.remove(engine, 'before_cursor_execute', observe)

    with Session() as session:
        queued = session.scalars(select(Job).where(Job.action == 'security-plan', Job.state == 'queued')).all()
        assert len(queued) == (0 if mode == 'legacy' else 10)
        assert all(job.payload['automatic'] is True for job in queued)
    assert len(history_reads) == (1 if mode == 'legacy' else 0)
