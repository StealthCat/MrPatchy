import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Event

import pytest
from sqlalchemy import Boolean, Double, Integer, JSON, Numeric, create_engine, select
from sqlalchemy.engine import make_url

from app import database_config as settings, database_migrate as migration, database_probe
from app.db import DATA, Base
from app.security import seal, unseal


def test_schema_object_diagnostics_are_bounded_and_terminal_safe():
    names={'table-'+str(index) for index in range(10)}|{'line\nbreak'}
    summary=migration.schema_object_summary('unexpected tables',names)
    assert 'line\\nbreak' in summary
    assert 'line\nbreak' not in summary
    assert '(+3 more)' in summary


@pytest.fixture
def isolated_profiles(monkeypatch, tmp_path):
    # Keep the running test app's DATA/key unchanged, isolate profile files only.
    (tmp_path / 'secret.key').write_bytes((DATA / 'secret.key').read_bytes())
    monkeypatch.setattr(settings, 'data_dir', lambda: tmp_path)
    return tmp_path


def mysql_body(**changes):
    return {'backend':'mysql','host':'db.example.test','database':'patchy','username':'patchy',
            'password':'p@ss:/?#&word', 'tls':True, **changes}


def test_settings_stage_encrypt_redact_and_leave_active_unchanged(admin, isolated_profiles):
    before = settings.runtime_url()
    response = admin.put('/api/settings/database', json=mysql_body())
    assert response.status_code == 200, response.text
    assert 'p@ss' not in response.text
    raw = (isolated_profiles / 'database-target.json').read_text()
    assert 'p@ss' not in raw and 'db.example.test' not in raw
    assert (isolated_profiles / 'database-target.json').stat().st_mode & 0o777 == 0o600
    assert settings.runtime_url() == before
    profile = settings.read_profile('target')
    url = make_url(settings.profile_url(profile))
    assert url.password == 'p@ss:/?#&word'
    assert url.query['ssl_check_hostname'] == 'true'
    import pymysql, ssl
    sql_engine=create_engine(url)
    args,kwargs=sql_engine.dialect.create_connect_args(url)
    connection=pymysql.connections.Connection(*args,**kwargs,defer_connect=True)
    assert connection.ctx.check_hostname and connection.ctx.verify_mode==ssl.CERT_REQUIRED
    assert connection._ssl_required
    sql_engine.dispose()
    assert admin.get('/api/settings/database').json()['target']['password_configured']
    assert admin.put('/api/settings/database', json=mysql_body(password='')).status_code == 200
    assert settings.read_profile('target')['password'] == 'p@ss:/?#&word'
    assert admin.put('/api/settings/database', json=mysql_body(password='',host='other.test')).status_code == 400
    assert admin.put('/api/settings/database', json=mysql_body(password='',tls=False)).status_code == 400
    assert admin.put('/api/settings/database', json=mysql_body(password='',clear_password=True)).status_code == 200
    assert not settings.read_profile('target')['password']


def test_paths_and_secret_validation(admin, isolated_profiles):
    assert admin.put('/api/settings/database', json={'backend':'sqlite','sqlite_file':'../old.db'}).status_code == 422
    assert admin.put('/api/settings/database', json=mysql_body(ca_file='relative.pem')).status_code == 400
    assert admin.put('/api/settings/database', json=mysql_body(clear_password=True)).status_code == 400
    assert admin.put('/api/settings/database', json=mysql_body(host='db/evil')).status_code == 422


def seed_all(engine):
    meta = migration.metadata()
    meta.create_all(engine)
    with engine.begin() as c:
        for table in meta.sorted_tables:
            rows=[]
            for i in range(2):
                row={}
                for col in table.columns:
                    if isinstance(col.type, Boolean): value=bool(i)
                    elif isinstance(col.type, Integer): value=41+i
                    elif isinstance(col.type, Double): value=1770000000.123456+i
                    elif isinstance(col.type, Numeric): value=Decimal('1.234567')+i
                    elif isinstance(col.type, JSON): value={'unicode':'raccoon 🦝 café','items':[None,True,False,1.25,{'id':'host-1'}]}
                    else: value='fixture-'+str(i)
                    row[col.name]=value
                if table.name=='users': row['password']=seal('fixture-credential-'+str(i))
                if table.name=='update_scores' and i==1: row['score']=None
                rows.append(row)
            c.execute(table.insert(),rows)
    return meta


@pytest.fixture
def source(tmp_path):
    path=tmp_path/'source.db';engine=create_engine('sqlite:///'+str(path))
    meta=seed_all(engine)
    yield str(engine.url),meta
    engine.dispose()


def test_copy_every_table_preserve_content_ids_nulls_secrets_and_next_id(source,tmp_path):
    url,meta=source;target='sqlite:///'+str(tmp_path/'copy.db')
    result=migration.migrate(url,target)
    assert set(result)==set(meta.tables)
    assert all(info['rows']==2 for info in result.values())
    engine=create_engine(target)
    with engine.begin() as c:
        assert unseal(c.scalar(select(meta.tables['users'].c.password).limit(1))).startswith('fixture-credential')
        audit=meta.tables['audit']
        result=c.execute(audit.insert().values(action='after-copy',detail='next generated id'))
        assert result.inserted_primary_key[0]>42
    engine.dispose()
    with pytest.raises(migration.MigrationError,match='not empty'):migration.migrate(url,target)


def test_dry_run_missing_source_same_target_and_unknown_schema(source,tmp_path):
    url,meta=source;path=tmp_path/'dry.db'
    result=migration.migrate(url,'sqlite:///'+str(path),dry_run=True)
    assert len(result)==len(meta.tables) and not path.exists()
    with pytest.raises(migration.MigrationError,match='does not exist'):
        migration.migrate('sqlite:///'+str(tmp_path/'missing.db'),'sqlite:///'+str(path))
    assert not (tmp_path/'missing.db').exists()
    with pytest.raises(migration.MigrationError,match='same SQLite'):migration.migrate(url,url)
    engine=create_engine(url)
    with engine.begin() as c:c.exec_driver_sql('CREATE TABLE unrelated (id INTEGER)')
    engine.dispose()
    with pytest.raises(migration.MigrationError,match='Source tables'):migration.migrate(url,'sqlite:///'+str(path))
    assert not path.exists()


def test_copy_rolls_back_on_mismatched_content(source,tmp_path,monkeypatch):
    url,meta=source;target='sqlite:///'+str(tmp_path/'failed.db')
    original=migration.fingerprint
    def mismatch(connection,table):
        result=original(connection,table)
        if str(connection.engine.url)==target:result['rows']+=1
        return result
    monkeypatch.setattr(migration,'fingerprint',mismatch)
    with pytest.raises(migration.MigrationError,match='verification failed'):migration.migrate(url,target)
    engine=create_engine(target)
    with engine.connect() as c:assert c.execute(select(meta.tables['users'])).first() is None
    engine.dispose()


def test_migration_refuses_running_jobs(source,tmp_path):
    url,meta=source;engine=create_engine(url)
    with engine.begin() as c:c.execute(meta.tables['jobs'].update().values(state='running'))
    engine.dispose()
    with pytest.raises(migration.MigrationError,match='Running jobs'):migration.migrate(url,'sqlite:///'+str(tmp_path/'dest.db'))


def test_offline_lock_and_activation(source,isolated_profiles,monkeypatch):
    url,meta=source
    monkeypatch.setenv('DATABASE_URL',url)
    settings.stage(settings.DatabaseInput(backend='sqlite',sqlite_file='activated.db'))
    with pytest.raises(migration.MigrationError,match='confirm-offline'):migration.run()
    with settings.maintenance_lock():
        with pytest.raises(ValueError,match='lock is busy'):migration.run(confirm_offline=True,activate=True)
    assert not (isolated_profiles/'database-active.json').exists()
    result=migration.run(confirm_offline=True,activate=True)
    assert result['activated']
    assert settings.runtime_url()=='sqlite:///'+str(isolated_profiles/'activated.db')
    assert make_url(url).database!=make_url(settings.runtime_url()).database
    # Both startup entrypoints resolve the same persisted profile, not stale .env.
    env={**os.environ,'DATA_DIR':str(isolated_profiles),'DATABASE_URL':url}
    out=subprocess.check_output([sys.executable,'-c','from app.db import URL; print(URL)'],env=env,text=True)
    assert out.strip()==settings.runtime_url()


def test_failed_migration_cannot_activate(source,isolated_profiles,monkeypatch):
    url,_=source;monkeypatch.setenv('DATABASE_URL',url)
    settings.stage(settings.DatabaseInput(backend='sqlite',sqlite_file='failed.db'))
    def fail(*a,**kw):raise migration.MigrationError('verification failed')
    monkeypatch.setattr(migration,'migrate',fail)
    with pytest.raises(migration.MigrationError):migration.run(confirm_offline=True,activate=True)
    assert settings.runtime_url()==url
    assert not (isolated_profiles/'database-active.json').exists()


@pytest.mark.skipif(not os.getenv('TEST_DATABASE_URL','').startswith('mysql'),reason='MySQL service required')
def test_sqlite_mysql_sqlite_full_roundtrip(client,source,tmp_path):
    from app.db import engine
    # Dedicated CI database, no production targets. Preserve all rows in all tables.
    Base.metadata.drop_all(engine)
    url,meta=source;mysql=os.environ['TEST_DATABASE_URL']
    first=migration.migrate(url,mysql)
    second=migration.migrate(mysql,'sqlite:///'+str(tmp_path/'roundtrip.db'))
    assert first==second
    with engine.begin() as c:
        result=c.execute(meta.tables['audit'].insert().values(action='new',detail='autoincrement'))
        assert result.inserted_primary_key[0]>42


def test_recovery_follows_active_profile_and_legacy_backup_refuses(isolated_profiles,monkeypatch):
    from scripts import recovery, backup
    monkeypatch.setenv('DATABASE_URL','sqlite:////old.db')
    settings.write_profile('active',{'url':'sqlite:////data/new.db'})
    assert recovery.active_database_url(isolated_profiles).database==str(isolated_profiles/'new.db')
    settings.write_profile('active',{'url':'sqlite:////data/sub/../../etc/x.db'})
    with pytest.raises(ValueError,match='container data directory'):recovery.active_database_url(isolated_profiles)
    settings.write_profile('active',{'url':'sqlite:////new.db'})
    with pytest.raises(ValueError,match='container data directory'):recovery.active_database_url(isolated_profiles)
    settings.write_profile('active',{'url':'sqlite:////data/new.db'})
    with pytest.raises(ValueError,match='offline migration profile'):
        backup.backup(isolated_profiles,isolated_profiles/'legacy.tar.gz')
    (isolated_profiles/'database-active.json').write_text('invalid')
    with pytest.raises(ValueError,match='active database profile'):
        recovery.active_database_url(isolated_profiles)


def test_sqlite_source_uri_escapes_special_filename_characters(tmp_path):
    from sqlalchemy.engine import URL
    source=create_engine(URL.create('sqlite',database=str(tmp_path/'source#%.db')))
    seed_all(source)
    source.dispose()
    result=migration.migrate(str(source.url),'sqlite:///'+str(tmp_path/'copy.db'))
    assert all(item['rows']==2 for item in result.values())


class FakeCursor:
    def __init__(self, log): self.log = log
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, sql): self.log.append(sql)
    def fetchone(self): return (1,)


class FakeConnection:
    def __init__(self, log): self.log = log; self.closed = False
    def cursor(self): return FakeCursor(self.log)
    def close(self): self.closed = True


def patch_connect(monkeypatch, outcome):
    import pymysql
    calls = []; log = []; connections = []
    def connect(**kwargs):
        calls.append(kwargs)
        if isinstance(outcome, Exception): raise outcome
        c = FakeConnection(log); connections.append(c); return c
    monkeypatch.setattr(pymysql, 'connect', connect)
    monkeypatch.setattr(settings, '_run_mysql_probe', database_probe.probe)
    return calls, log, connections


def test_connection_success_is_read_only_unsaved_and_closed(admin, isolated_profiles, monkeypatch):
    calls, log, connections = patch_connect(monkeypatch, None)
    response = admin.post('/api/settings/database/test', json=mysql_body())
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['ok'] and data['category'] == 'ok' and 'controller' in data['scope']
    assert 'p@ss' not in response.text
    assert log == ['SELECT 1'] and connections[0].closed
    assert calls[0]['connect_timeout'] <= 5 and calls[0]['ssl_verify_identity'] is True
    assert not (isolated_profiles / 'database-target.json').exists()


@pytest.mark.parametrize('error,category', [
    (__import__('pymysql').err.OperationalError(1045, "Access denied for 'patchy'@'h' (using password: YES)"), 'authentication'),
    (__import__('pymysql').err.OperationalError(1049, "Unknown database 'patchy'"), 'database'),
    (__import__('pymysql').err.OperationalError(1044, "Access denied for user to database"), 'access'),
    (__import__('pymysql').err.OperationalError(2003, "Can't connect to MySQL server on 'db.example.test'"), 'connectivity'),
    (__import__('pymysql').err.OperationalError(2003, "timed out"), 'timeout'),
    (__import__('ssl').SSLCertVerificationError('certificate verify failed: p@ss'), 'tls'),
])
def test_connection_failures_are_classified_and_redacted(admin, isolated_profiles, monkeypatch, error, category):
    patch_connect(monkeypatch, error)
    response = admin.post('/api/settings/database/test', json=mysql_body())
    assert response.status_code == 200
    data = response.json()
    assert not data['ok'] and data['category'] == category
    assert 'p@ss' not in response.text and 'patchy' not in data['detail'] and 'db.example.test' not in response.text


def test_connection_password_rules_and_sqlite_rejected(admin, isolated_profiles, monkeypatch):
    calls, _, _ = patch_connect(monkeypatch, None)
    assert admin.post('/api/settings/database/test', json=mysql_body(password='')).status_code == 400
    assert admin.put('/api/settings/database', json=mysql_body()).status_code == 200
    before = (isolated_profiles / 'database-target.json').read_text()
    assert admin.post('/api/settings/database/test', json=mysql_body(password='')).status_code == 200
    assert calls[-1]['password'] == 'p@ss:/?#&word'
    assert admin.post('/api/settings/database/test', json=mysql_body(password='', clear_password=True)).status_code == 200
    assert calls[-1]['password'] == ''
    assert admin.post('/api/settings/database/test', json=mysql_body(password='x', clear_password=True)).status_code == 400
    assert admin.post('/api/settings/database/test', json={'backend': 'sqlite'}).status_code == 400
    assert (isolated_profiles / 'database-target.json').read_text() == before


def test_connection_requires_administrator(client):
    assert client.post('/api/settings/database/test', json=mysql_body()).status_code in (401, 403)


def test_connection_probe_deadline_cancels_fragmented_handshake(monkeypatch, isolated_profiles):
    monkeypatch.setattr(settings, 'TEST_TIMEOUT', 2)
    delay = settings.TEST_TIMEOUT * 0.65

    def slow_server(listener):
        with listener.accept()[0] as peer:
            # Each read takes less than the driver timeout, but together they exceed the deadline.
            error_packet = b'\xff\x15\x04#28000Synthetic authentication refusal'
            time.sleep(delay)
            try:
                peer.sendall(len(error_packet).to_bytes(3, 'little') + b'\x00')
                peer.settimeout(delay)
                return peer.recv(1) == b''
            except ConnectionResetError:
                return True
            except TimeoutError:
                peer.sendall(error_packet)
                return False

    with socket.create_server(('127.0.0.1', 0)) as listener, ThreadPoolExecutor(1) as pool:
        listener.settimeout(5)
        server = pool.submit(slow_server, listener)
        result = settings.test_connection(settings.DatabaseInput(**mysql_body(
            host='127.0.0.1', port=listener.getsockname()[1], tls=False,
        )))
        assert result['category'] == 'timeout'
        assert server.result(timeout=5), 'Timed-out probe left the connection open'


def test_connection_probe_bounds_concurrency_and_releases_slots(monkeypatch, isolated_profiles):
    started, release = Event(), Event()

    def run_probe(kwargs):
        started.set()
        assert release.wait(timeout=5)
        return 'timeout'

    monkeypatch.setattr(settings, '_TEST_SLOTS', settings.BoundedSemaphore(1))
    monkeypatch.setattr(settings, '_run_mysql_probe', run_probe)
    body = settings.DatabaseInput(**mysql_body(tls=False))
    with ThreadPoolExecutor(1) as pool:
        first = pool.submit(settings.test_connection, body)
        try:
            assert started.wait(timeout=5)
            assert settings.test_connection(body)['category'] == 'busy'
        finally:
            release.set()
        assert first.result(timeout=5)['category'] == 'timeout'
    assert settings.test_connection(body)['category'] == 'timeout'


def test_probe_subprocess_never_puts_secrets_in_command_or_response(monkeypatch):
    def run(command, *, input, stdout, stderr, timeout, check):
        assert all('fixture-secret' not in arg for arg in command)
        assert json.loads(input)['password'] == 'fixture-secret'
        assert stderr == subprocess.DEVNULL
        return subprocess.CompletedProcess(command, 0, b'raw driver error: fixture-secret')

    monkeypatch.setattr(settings.subprocess, 'run', run)
    assert settings._run_mysql_probe({'password': 'fixture-secret'}) == 'error'


@pytest.mark.skipif(not os.getenv('TEST_DATABASE_URL', '').startswith('mysql'), reason='MySQL service required')
def test_connection_probe_with_live_mysql(admin, isolated_profiles):
    url = make_url(os.environ['TEST_DATABASE_URL'])
    body = mysql_body(host=url.host, port=url.port or 3306, database=url.database,
                      username=url.username, password=url.password, tls=False)
    before = settings.runtime_url()
    success = admin.post('/api/settings/database/test', json=body)
    assert success.status_code == 200 and success.json()['category'] == 'ok'
    failure = admin.post('/api/settings/database/test', json={**body, 'password': 'deliberately-wrong'})
    assert failure.status_code == 200 and failure.json()['category'] == 'authentication'
    assert settings.runtime_url() == before
    assert not (isolated_profiles / 'database-target.json').exists()
