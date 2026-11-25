from collections.abc import Mapping

import pytest
from sqlalchemy import event, select

from app import incidents
from app.db import Host, Job, Session, Setting, engine
from app.process_response import ProcessResponse
from app.quarantine import Quarantine
from app.repair_publication import Publication
from app.security import seal
from app.service_monitor import Watch


@pytest.mark.parametrize('mysql_aliases', [False, True], ids=['exact', 'mysql-aliases'])
def test_tick_batches_all_host_holds(admin, mysql_aliases):
    if mysql_aliases and engine.dialect.name != 'mysql':
        pytest.skip('requires native case-insensitive MySQL collation')

    def hold_host(host_id):
        return host_id.upper() if mysql_aliases else host_id

    hosts = ('running', 'recovery', 'watch', 'quarantine', 'publication', 'process',
             'clear-queued', 'clear')
    with Session() as session:
        session.add(Setting(key='openai_key', value={'encrypted': seal('fixture')}))
        session.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture'}))
        for host_id in hosts:
            session.add(Host(id=host_id, name=host_id, address='192.0.2.1', fingerprint='test'))
            session.add(Setting(key='security-policy:' + hold_host(host_id), value={'auto_ai_plan': True}))
            session.add(incidents.Incident(id=host_id, host_id=host_id, scan_id=host_id, evidence={}))
        session.add_all([
            Job(id='running-job', host_id=hold_host('running'), action='patch', state='running'),
            Job(id='recovery-job', host_id=hold_host('recovery'), action='patch', state='recovery_required'),
            Job(id='queued-job', host_id='clear-queued', action='patch', state='queued'),
            Watch(id='watch-hold', host_id=hold_host('watch'), actor='test', reason='test',
                  revision='test', hold=True),
            Quarantine(id='file-hold', host_id=hold_host('quarantine'), incident_id='quarantine',
                       archive_id='test', fingerprint='test', evidence_digest='test', plan={}, hold=True),
            Publication(id='publish-hold', host_id=hold_host('publication'), quarantine_id='test',
                        stage_id='test', expires=0, actor='test', reason='test', fingerprint='test',
                        stage_report_digest='test', plan={}, before_state='test', before_hold=False, hold=True),
            ProcessResponse(id='process-hold', host_id=hold_host('process'), quarantine_id='test',
                            observation_id='test', fingerprint='test', plan={}, hold=True),
        ])
        session.commit()

    reads = []
    hold_tables = (Watch, Quarantine, Publication, ProcessResponse)

    def observe(conn, cursor, statement, parameters, context, executemany):
        values = parameters.values() if isinstance(parameters, Mapping) else parameters
        sql = statement.lower()
        if sql.lstrip().startswith('select') and (
            'recovery_required' in values or any(model.__tablename__ in sql for model in hold_tables)
        ):
            reads.append(statement)

    event.listen(engine, 'before_cursor_execute', observe)
    try:
        incidents.auto_plan_tick()
    finally:
        event.remove(engine, 'before_cursor_execute', observe)

    with Session() as session:
        queued = set(session.scalars(select(Job.host_id).where(Job.action == 'security-plan')))
    assert queued == {'clear', 'clear-queued'}
    assert len(reads) == 1
