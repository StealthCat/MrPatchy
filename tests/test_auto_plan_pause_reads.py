from collections.abc import Mapping

import pytest
from sqlalchemy import event, select

from app import ai_policy, incidents
from app.db import Host, Job, Session, Setting, engine
from app.security import seal


def seed_policies(hosts):
    with Session() as session:
        session.add(Setting(key='openai_key', value={'encrypted': seal('fixture')}))
        session.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture'}))
        for host_id, policy_host_id, pause in hosts:
            session.add(Host(id=host_id, name=host_id, address='192.0.2.1', fingerprint='test'))
            session.add(Setting(key='security-policy:' + host_id, value={'auto_ai_plan': True}))
            session.add(incidents.Incident(id=host_id, host_id=host_id, scan_id=host_id, evidence={}))
            if policy_host_id is not None:
                session.add(Setting(key=ai_policy.PREFIX + policy_host_id, value=pause))
        session.commit()


def queued_hosts():
    with Session() as session:
        return set(session.scalars(select(Job.host_id).where(Job.action == 'security-plan')))


def test_tick_reads_pause_policies_without_per_host_queries(admin):
    seed_policies([
        ('first', None, None),
        ('second', 'second', {'paused': False}),
        ('third', 'third', {}),
        ('paused', 'paused', {'paused': True}),
        ('malformed', 'malformed', {'paused': 0}),
        ('non-object', 'non-object', None),
    ])
    policy_reads = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        values = parameters.values() if isinstance(parameters, Mapping) else parameters
        if statement.lstrip().lower().startswith('select') and any(
            isinstance(value, str) and value.startswith(('server-ai:', 'security-policy:'))
            for value in values
        ):
            policy_reads.append(statement)

    event.listen(engine, 'before_cursor_execute', observe)
    try:
        incidents.auto_plan_tick()
    finally:
        event.remove(engine, 'before_cursor_execute', observe)

    assert queued_hosts() == {'first', 'second', 'third'}
    assert len(policy_reads) == 1


def test_tick_pause_join_respects_mysql_collation(admin):
    if engine.dialect.name != 'mysql':
        pytest.skip('requires native case-insensitive MySQL collation')
    seed_policies([
        ('Paused-Host', 'paused-host', {'paused': True}),
        ('malformed-host', 'MALFORMED-HOST', ['invalid']),
        ('resumed-host', 'RESUMED-HOST', {'paused': False}),
    ])

    incidents.auto_plan_tick()

    assert queued_hosts() == {'resumed-host'}
