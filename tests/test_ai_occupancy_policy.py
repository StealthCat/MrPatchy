"""Admission fetches live counts and capacity policy in one read."""
from sqlalchemy import event
from app import ai_claims, ai_policy
from app.db import Behavior, Host, Session, Setting, engine
from app.security import seal


def test_occupied_host_capacity_is_read_with_claim_counts(admin):
    limits = {'guard-a': 1, 'guard-b': 3, 'guard-c': 'invalid'}
    hosts = ['guard-a', 'guard-b', 'guard-c', 'guard-d']
    with Session() as s:
        s.add_all([
            Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture'}),
            Setting(key='openai_key', value={'encrypted': seal('fixture-key')}),
        ])
        for index, host_id in enumerate(hosts):
            s.add(Host(id=host_id, name='Fixture', address='192.0.2.1', fingerprint=''))
            if host_id in limits:
                s.add(Setting(key=ai_policy.PREFIX + host_id, value={'concurrency_limit': limits[host_id]}))
            for slot in range(2):
                s.add(Behavior(id=f'{host_id}-{slot}', host_id=host_id, first_seen=slot * 10 + index,
                               evidence={'executable': '/fixture'}))
        s.commit()

    assert [ai_claims.acquire().host_id for _ in hosts] == hosts
    separate_reads = []
    joined_reads = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if 'LEFT OUTER JOIN settings' in statement and 'GROUP BY ai_triage_claims.host_id' in statement:
            joined_reads.append(statement)
        if statement.startswith('SELECT settings.'):
            values = parameters.values() if isinstance(parameters, dict) else parameters
            if any(isinstance(value, str) and value.startswith(ai_policy.PREFIX) for value in values):
                separate_reads.append(statement)

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        assert ai_claims.acquire().host_id == 'guard-b'
    finally:
        event.remove(engine, 'before_cursor_execute', capture)

    assert (len(joined_reads), len(separate_reads)) == (1, 0)
    assert ai_claims.acquire().host_id == 'guard-d'
    assert ai_claims.acquire() is None
