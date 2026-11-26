import pytest
from sqlalchemy import event, select

from app import incidents
from app.db import Host, Job, Session, Setting, engine


@pytest.mark.parametrize(('mode', 'recent', 'expected'), [
    ('legacy', 0, 10),
    ('legacy', 9, 1),
    ('legacy', 10, 0),
    ('legacy', 500, 0),
    ('rate', 10, 10),
    ('daily_cap', 10, 10),
    ('rate_and_daily', 10, 10),
    ('unthrottled', 10, 10),
])
def test_auto_plan_counts_only_a_bounded_recent_legacy_window(admin, mode, recent, expected):
    now = 1_750_000_000
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
                            action='security-plan' if number % 2 else 'startup-plan', created=now-3599)
                        for number in range(recent))
        session.add_all([
            Job(id='cutoff', host_id='older-host', state='failed', action='startup-plan', created=now-3600),
            Job(id='expired', host_id='older-host', state='failed', action='security-plan', created=now-3601),
            Job(id='unrelated', host_id='older-host', state='failed', action='release-plan', created=now-30),
        ])
        session.commit()

    history_reads = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        sql = ' '.join(statement.lower().split())
        if 'count(' in sql and 'from jobs' in sql and 'jobs.created >' in sql:
            history_reads.append(sql)

    event.listen(engine, 'before_cursor_execute', observe)
    try:
        incidents.auto_plan_tick(now)
    finally:
        event.remove(engine, 'before_cursor_execute', observe)

    with Session() as session:
        queued = session.scalars(select(Job).where(Job.action == 'security-plan', Job.state == 'queued')).all()
        assert len(queued) == expected
        assert all(job.payload['automatic'] is True for job in queued)
    assert len(history_reads) == (1 if mode == 'legacy' else 0)
    assert all(' limit ' in query for query in history_reads)
