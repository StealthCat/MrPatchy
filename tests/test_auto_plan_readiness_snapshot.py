import pytest
from sqlalchemy import event
from test_auto_plan_status import seed

from app import ai_policy, auto_plan_status
from app.db import Host, Job, Session, Setting, config, engine
from app.process_response import ProcessResponse
from app.quarantine import Quarantine
from app.repair_publication import Publication
from app.service_monitor import Watch


@pytest.mark.parametrize('mysql_aliases', [False, True], ids=['exact', 'mysql-aliases'])
def test_plan_readiness_uses_one_server_snapshot(admin, mysql_aliases):
    if mysql_aliases and engine.dialect.name != 'mysql':
        pytest.skip('requires native case-insensitive MySQL collation')
    now = seed()

    def alias(host_id):
        return host_id.upper() if mysql_aliases else host_id

    expected = {
        'paused': 'paused', 'malformed': 'paused', 'job': 'held',
        'watch': 'held', 'file': 'held', 'publish': 'held', 'process': 'held',
        'inactive': 'inactive', 'web': 'ready',
    }
    with Session() as session:
        for host_id in expected.keys() - {'web'}:
            session.add(Host(id=host_id, name=host_id, address='192.0.2.1', fingerprint='test',
                             enabled=host_id not in {'inactive', 'paused', 'job'}))
            session.add(Setting(key='security-policy:' + host_id, value={'auto_ai_plan': True}))
        session.add_all([
            Setting(key=ai_policy.PREFIX + alias('paused'), value={'paused': True}),
            Setting(key=ai_policy.PREFIX + alias('malformed'), value=None),
            Job(id='overlapping-hold', host_id=alias('paused'), action='patch', state='running'),
            Job(id='job-hold', host_id=alias('job'), action='patch', state='recovery_required'),
            Watch(id='watch-hold', host_id=alias('watch'), actor='test', reason='test',
                  revision='test', hold=True),
            Quarantine(id='file-hold', host_id=alias('file'), incident_id='test', archive_id='test',
                       fingerprint='test', evidence_digest='test', plan={}, hold=True),
            Publication(id='publish-hold', host_id=alias('publish'), quarantine_id='test',
                        stage_id='test', expires=0, actor='test', reason='test', fingerprint='test',
                        stage_report_digest='test', plan={}, before_state='test', before_hold=False, hold=True),
            ProcessResponse(id='process-hold', host_id=alias('process'), quarantine_id='test',
                            observation_id='test', fingerprint='test', plan={}, hold=True),
        ])
        session.commit()

    reads = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().lower().startswith('select'):
            reads.append(statement)

    with Session() as session:
        configured = config(session)
        event.listen(engine, 'before_cursor_execute', observe)
        try:
            states = auto_plan_status._readiness(session, list(expected), configured)
        finally:
            event.remove(engine, 'before_cursor_execute', observe)
    assert states == expected

    response = admin.get('/api/security/auto-plan-status')
    assert response.status_code == 200
    assert {row['host_id']: row['state'] for row in response.json()['items']} == expected
    for host_id, state in expected.items():
        response = admin.get('/api/hosts/' + alias(host_id) + '/security/auto-plan-status')
        assert response.status_code == 200
        assert response.json()['state'] == state

    # One credential check and one statement for all listed servers.
    assert len(reads) == 2
