"""The investigation lease fence reads only the state needed to authorize work."""
import pytest
from sqlalchemy import event
from app import ai_claims
from app.db import Behavior, Host, Session, Setting, engine
from app.security import seal


@pytest.fixture
def lease(admin):
    with Session() as s:
        s.add_all([
            Host(id='lease-host', name='Fixture', address='192.0.2.1', fingerprint=''),
            Behavior(id='lease-subject', host_id='lease-host', evidence={'executable': '/srv/fixture'}),
            Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture'}),
            Setting(key='openai_key', value={'encrypted': seal('fixture-key')}),
        ])
        s.commit()
    claimed = ai_claims.acquire()
    assert claimed is not None
    return claimed


def validation_reads(lease, rejected=False):
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith(('SELECT hosts.', 'SELECT behaviors.')):
            statements.append(statement.partition('\n')[0].strip())

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        if rejected:
            with pytest.raises(ai_claims.Lost):
                lease.check()
        else:
            lease.check()
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    return statements


def test_live_lease_reads_only_host_lifecycle_fields(lease):
    statements = validation_reads(lease)
    assert [sql for sql in statements if sql.startswith('SELECT hosts.')] == [
        'SELECT hosts.enabled, hosts.deleted_at']
    assert any(sql.startswith('SELECT behaviors.') for sql in statements)


@pytest.mark.parametrize('state', ['expired', 'replaced', 'lost'])
def test_fenced_lease_does_not_read_host_or_behavior(lease, state):
    if state == 'lost':
        lease.lost.set()
    else:
        with Session() as s:
            claim = s.get(ai_claims.Claim, lease.subject)
            if state == 'expired':
                claim.expires = 0
            else:
                claim.token = 'replacement'
            s.commit()
    assert validation_reads(lease, rejected=True) == []
    assert lease.lost.is_set()


@pytest.mark.parametrize('change', ['disabled', 'deleted', 'evidence', 'missing'])
def test_live_lease_keeps_existing_lifecycle_and_evidence_rules(lease, change):
    with Session() as s:
        host = s.get(Host, lease.host_id)
        if change == 'disabled':
            host.enabled = False
        elif change == 'deleted':
            host.deleted_at = 1
        elif change == 'evidence':
            s.get(Behavior, lease.subject).evidence = {'executable': '/srv/replacement'}
        else:
            s.delete(host)
        s.commit()
    validation_reads(lease, rejected=change != 'missing')
