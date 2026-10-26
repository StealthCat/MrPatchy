import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from sqlalchemy import Boolean, Double, Integer, JSON, create_engine, select
from sqlalchemy.engine import make_url

from app import database_config as settings, database_migrate as migration
from app.db import DATA, Base
from app.security import seal, unseal


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
    settings.write_profile('active',{'url':'sqlite:////new.db'})
    assert recovery.active_database_url(isolated_profiles).database=='/new.db'
    with pytest.raises(ValueError,match='offline migration profile'):
        backup.backup(isolated_profiles,isolated_profiles/'legacy.tar.gz')
    (isolated_profiles/'database-active.json').write_text('invalid')
    with pytest.raises(ValueError,match='active database profile'):
        recovery.active_database_url(isolated_profiles)
