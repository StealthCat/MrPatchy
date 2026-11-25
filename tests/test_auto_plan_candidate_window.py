import pytest
from sqlalchemy import select

from app import incidents, worker
from app.db import Host, Job, Session, Setting
from app.security import seal


@pytest.mark.parametrize('mysql_aliases', [False, True], ids=['exact', 'mysql-aliases'])
def test_occupied_servers_leave_room_for_available_candidates(admin, monkeypatch, mysql_aliases):
    with Session() as session:
        if mysql_aliases and session.bind.dialect.name != 'mysql':
            pytest.skip('requires native case-insensitive MySQL collation')
        session.add(Setting(key='openai_key', value={'encrypted': seal('fixture')}))
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'fixture', 'ai_control_mode': 'rate',
        }))
        for host_id in ('startup-busy', 'incident-busy', 'second', 'first'):
            session.add(Host(id=host_id, name=host_id, address='192.0.2.1', fingerprint='test'))
            session.add(Setting(key='security-policy:' + host_id, value={'auto_ai_plan': True}))
        for host_id, action in (('startup-busy', 'startup-plan'), ('incident-busy', 'security-plan')):
            job_host = host_id.upper() if mysql_aliases else host_id
            session.add(Job(id=host_id, host_id=job_host, action=action, state='queued'))
            for number in range(55):
                identifier = f'{host_id}-{number:03d}'
                session.add(incidents.Incident(id=identifier, host_id=host_id, scan_id=identifier,
                                                evidence={}, updated=number))
        session.add_all([
            Job(id='finished-startup', host_id='first', action='startup-plan', state='failed'),
            incidents.Incident(id='second', host_id='second', scan_id='second', evidence={}, updated=101),
            incidents.Incident(id='first', host_id='first', scan_id='first', evidence={}, updated=100),
        ])
        session.commit()

    queued = []
    enqueue = worker.enqueue

    def record_enqueue(session, host_id, action, payload):
        job_id = enqueue(session, host_id, action, payload)
        queued.append(payload['incident_id'])
        return job_id

    monkeypatch.setattr(worker, 'enqueue', record_enqueue)
    incidents.auto_plan_tick()

    assert queued == ['first', 'second']
    with Session() as session:
        states = dict(session.execute(select(Job.id, Job.state)).all())
    assert states['startup-busy'] == states['incident-busy'] == 'queued'
