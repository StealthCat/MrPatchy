"""Per-server AI pause in the Servers directory listing (#864)."""
import pytest
from sqlalchemy import event

from app import ai_policy
from app.db import Session, Host, Setting, engine


def seed():
    with Session() as s:
        s.add_all([Host(id=x, name=x, address='192.0.2.1', fingerprint='') for x in
                   ('paused', 'resumed', 'missing', 'corrupt', 'truthy', 'nondict')])
        s.add_all([
            Setting(key=ai_policy.PREFIX + 'paused', value={'paused': True, 'revision': 'r1'}),
            Setting(key=ai_policy.PREFIX + 'resumed', value={'paused': False, 'revision': 'r2'}),
            # Corrupt stored policy must read as paused, exactly as the provider gate refuses it.
            Setting(key=ai_policy.PREFIX + 'corrupt', value={'paused': 'no'}),
            Setting(key=ai_policy.PREFIX + 'truthy', value={'revision': 'r3', 'paused': None}),
            Setting(key=ai_policy.PREFIX + 'nondict', value=['invalid policy']),
            # A policy row for a host that does not exist is ignored.
            Setting(key=ai_policy.PREFIX + 'ghost', value={'paused': True}),
            # A key sharing the prefix pattern only through a LIKE wildcard is not a policy row.
            Setting(key='server-aiXpaused', value={'paused': True}),
        ])
        s.commit()


def test_admin_listing_reports_gate_equivalent_pause_state(admin):
    seed()
    rows = {row['id']: row for row in admin.get('/api/hosts').json()}
    assert {key: row['ai_paused'] for key, row in rows.items()} == {
        'paused': True, 'resumed': False, 'missing': False,
        'corrupt': True, 'truthy': True, 'nondict': True,
    }
    # The listing agrees with the enforcement path for every host.
    from app.ai import AIError
    for key, row in rows.items():
        try:
            ai_policy.require([key])
            refused = False
        except AIError as error:
            refused = 'paused' in str(error)
        assert refused is row['ai_paused'], key


def capture_statements(client, path):
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, 'before_cursor_execute', record)
    try:
        response = client.get(path)
    finally:
        event.remove(engine, 'before_cursor_execute', record)
    assert response.status_code == 200
    return statements


def test_pause_state_adds_no_statement_to_the_listing(admin):
    """The policy read joins the bounded host query (#147 budget), never a separate scan."""
    seed()
    statements = capture_statements(admin, '/api/hosts')
    assert len(statements) <= 3
    host_queries = [q for q in statements if 'FROM hosts' in q]
    assert len(host_queries) == 1
    assert not any('LIKE' in q and 'settings' in q for q in statements)


def test_stored_paused_matches_gate_rule():
    assert ai_policy.stored_paused(None, present=False) is False
    assert ai_policy.stored_paused({'paused': False}) is False
    assert ai_policy.stored_paused({}) is False
    for value in ({'paused': True}, {'paused': 'no'}, {'paused': None}, ['x'], None, 'paused'):
        assert ai_policy.stored_paused(value) is True, value


def test_pause_and_resume_through_policy_route_update_listing(admin):
    seed()
    base = '/api/hosts/resumed/security/ai-policy'
    with Session() as s:
        s.add(Setting(key='config', value={'ai_enabled': True}))
        s.commit()
    current = admin.get(base).json()
    saved = admin.put(base, json={'paused': True, 'expected_revision': current['revision'],
                                  'reason': 'Pause provider processing for review'})
    assert saved.status_code == 200, saved.text
    assert {row['id']: row['ai_paused'] for row in admin.get('/api/hosts').json()}['resumed'] is True
    current = admin.get(base).json()
    assert admin.put(base, json={'paused': False, 'expected_revision': current['revision'],
                                 'reason': 'Resume provider processing after review'}).status_code == 200
    assert {row['id']: row['ai_paused'] for row in admin.get('/api/hosts').json()}['resumed'] is False


def test_deleted_listing_also_reports_pause_for_admin(admin):
    seed()
    with Session() as s:
        s.get(Host, 'paused').deleted_at = 1.0
        s.commit()
    rows = admin.get('/api/hosts?deleted=true').json()
    assert [(row['id'], row['ai_paused']) for row in rows] == [('paused', True)]


@pytest.mark.parametrize('role', ['viewer', 'operator'])
def test_other_roles_do_not_receive_pause_state(admin, role):
    seed()
    assert admin.put('/api/users', json={'username': 'directory-reader', 'role': role,
                                         'password': 'directory-test-password-long'}).status_code == 200
    admin.post('/api/logout')
    assert admin.post('/api/login', json={'username': 'directory-reader',
                                          'password': 'directory-test-password-long'}).status_code == 200
    rows = admin.get('/api/hosts').json()
    assert len(rows) == 6
    assert all('ai_paused' not in row for row in rows)
