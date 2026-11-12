"""Database reads under the server activity guard."""
import pytest
from sqlalchemy import event, select
from app import host_lifecycle
from app.coordination import Lock
from app.db import Host, Session, engine


@pytest.mark.parametrize('batch_size, expected_reads', [(200, 1), (2, 3)])
def test_activity_reads_only_lifecycle_fields_in_batches(admin, monkeypatch, batch_size, expected_reads):
    expected = {f'guard-{i}': f'revision-{i}' for i in range(5)}
    with Session() as s:
        s.add_all(Host(id=host_id, name='Fixture', address='192.0.2.1', fingerprint='',
                       lifecycle_revision=revision) for host_id, revision in expected.items())
        s.commit()

    monkeypatch.setattr(host_lifecycle, 'ACTIVITY_READ_BATCH', batch_size, raising=False)
    reads = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith('SELECT hosts.'):
            reads.append(statement.partition('\n')[0].strip())

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        with host_lifecycle.activity([*reversed(expected), 'guard-0'], 'ai') as revisions:
            assert revisions == expected
    finally:
        event.remove(engine, 'before_cursor_execute', capture)

    projection = 'SELECT hosts.id, hosts.enabled, hosts.deleted_at, hosts.lifecycle_revision'
    assert reads == [projection] * expected_reads


def test_activity_omits_revision_for_unpersisted_bootstrap_host(admin):
    with host_lifecycle.activity(['unknown-bootstrap'], 'ai') as revisions:
        assert revisions == {}


def test_activity_preserves_requested_revision_key_under_mysql_collation(admin):
    if engine.dialect.name not in ('mysql', 'mariadb'):
        pytest.skip('Requires a case-insensitive MySQL host ID collation')
    with Session() as s:
        s.add(Host(id='guard-alias', name='Fixture', address='192.0.2.1', fingerprint='',
                   lifecycle_revision='revision-alias'))
        s.commit()
        if s.scalar(select(Host.id).where(Host.id=='GUARD-ALIAS')) is None:
            pytest.skip('The configured MySQL host ID collation is case-sensitive')

    with host_lifecycle.activity(['guard-alias', 'GUARD-ALIAS'], 'ai') as revisions:
        assert revisions == {'guard-alias': 'revision-alias', 'GUARD-ALIAS': 'revision-alias'}


@pytest.mark.parametrize('state', [{'enabled': False}, {'deleted_at': 1}])
def test_activity_releases_every_server_lock_when_one_server_is_inactive(admin, state):
    with Session() as s:
        s.add_all([
            Host(id='guard-active', name='Active', address='192.0.2.1', fingerprint=''),
            Host(id='guard-inactive', name='Inactive', address='192.0.2.2', fingerprint='', **state),
        ])
        s.commit()

    with pytest.raises(host_lifecycle.Inactive):
        with host_lifecycle.activity(['guard-inactive', 'guard-active'], 'ai'):
            pytest.fail('An inactive server must prevent activity')

    for host_id in ('guard-active', 'guard-inactive'):
        lock = Lock('server-ai:' + host_id)
        assert lock.acquire(False)
        lock.release()
