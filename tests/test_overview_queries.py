"""/api/hosts and /api/dashboard must not load per-host blobs or every Package row (#147)."""
import time
from sqlalchemy import event
from app.db import Session, Host, Package, engine


def seed(count=3):
    with Session() as s:
        for i in range(count):
            s.add(Host(id=f'h{i}', name=f'h{i}', address='192.0.2.1', fingerprint='', state='online', last_seen=time.time(),
                       inventory={'architecture': 'amd64', 'os': 'Debian', 'package_manager': 'apt', 'dpkg_status': 'x' * 1000},
                       telemetry={'processes': ['p'] * 50}, baseline={'b': 1}, integrity=[1, 2] if i == 0 else []))
        s.add(Host(id='nomgr', name='nomgr', address='192.0.2.1', fingerprint='', inventory={}))
        s.add(Host(id='off', name='off', address='192.0.2.1', fingerprint='', enabled=False))
        long_ago = time.time() - 10 * 24 * 3600
        s.add_all([
            Package(id='a', host_id='h0', name='a', installed='1', candidate='2', priority='critical', available_since=long_ago),
            Package(id='b', host_id='h0', name='b', installed='1', candidate='2', priority='low', available_since=time.time()),
            Package(id='c', host_id='h1', name='c', installed='1', candidate=''),
            Package(id='d', host_id='off', name='d', installed='1', candidate='2', priority='critical', available_since=long_ago),
        ])
        s.commit()


def capture(client, path):
    statements = []
    def listener(conn, cursor, statement, *a): statements.append(statement)
    event.listen(engine, 'before_cursor_execute', listener)
    try: response = client.get(path)
    finally: event.remove(engine, 'before_cursor_execute', listener)
    assert response.status_code == 200
    return response.json(), statements


def test_hosts_does_not_select_blob_columns(admin):
    seed()
    body, statements = capture(admin, '/api/hosts')
    assert len(statements) <= 3
    assert not any('hosts.telemetry' in q or 'hosts.baseline' in q for q in statements)
    by = {h['id']: h for h in body}
    assert by['h0']['architecture'] == 'amd64' and by['h0']['os'] == 'Debian' and by['h0']['package_manager'] == 'apt'
    assert by['nomgr']['architecture'] == '' and by['nomgr']['package_manager'] == 'apt'
    assert 'inventory' not in by['h0'] and 'telemetry' not in by['h0']


def test_dashboard_counts_in_sql_without_loading_packages(admin):
    seed()
    body, statements = capture(admin, '/api/dashboard')
    assert not any('SELECT packages.id' in q or 'packages.name' in q for q in statements)
    assert body['servers'] == 4 and body['packages'] == 3 and body['updates'] == 2
    assert body['overdue'] == 1 and body['integrity_alerts'] == 2
