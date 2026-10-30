import os
import subprocess
import sys
import pytest
from cryptography.fernet import Fernet
from app import worker_preflight as gate
from app.db import Session,Setting
from app.main import APP_VERSION

@pytest.fixture
def local(admin,tmp_path,monkeypatch):
    monkeypatch.setattr(gate,'DATA',tmp_path)
    key=tmp_path/'secret.key';key.write_bytes(Fernet.generate_key());key.chmod(0o600)
    with Session() as s:
        row=s.get(Setting,gate.KEY)
        if row:s.delete(row);s.commit()
    gate.publish(APP_VERSION)
    return key


def test_verified_read_only_and_version_upgrade(local):
    with Session() as s:before=dict(s.get(Setting,gate.KEY).value)
    assert gate.verify(APP_VERSION)=='verified'
    with Session() as s:assert s.get(Setting,gate.KEY).value==before
    gate.publish('999.0.0')
    with pytest.raises(ValueError,match='preflight failed'):gate.verify(APP_VERSION)
    gate.publish(APP_VERSION)
    with Session() as s:assert s.get(Setting,gate.KEY).value['encrypted']==before['encrypted']


@pytest.mark.parametrize('failure',['missing-key','wrong-key','public-key','symlink-key','missing-receipt','bad-receipt','wrong-format','wrong-version','boolean-format','bad-marker','invalid-key','long-key','fifo-key'])
def test_refuse_and_never_repair(local,failure):
    if failure=='missing-key':local.unlink()
    elif failure=='wrong-key':local.write_bytes(Fernet.generate_key())
    elif failure=='public-key':local.chmod(0o644)
    elif failure=='symlink-key':
        target=local.with_name('actual.key');local.rename(target);local.symlink_to(target)
    elif failure=='invalid-key':local.write_bytes(b'x'*44)
    elif failure=='long-key':local.write_bytes(local.read_bytes()+b'\n')
    elif failure=='fifo-key':local.unlink();os.mkfifo(local,0o600)
    else:
        with Session() as s:
            row=s.get(Setting,gate.KEY)
            if failure=='missing-receipt':s.delete(row)
            elif failure=='bad-receipt':row.value={'encrypted':'credential-secret'}
            elif failure=='wrong-format':row.value={**row.value,'format':2}
            elif failure=='boolean-format':row.value={**row.value,'format':True}
            elif failure=='bad-marker':row.value={**row.value,'encrypted':gate.local_cipher().encrypt(b'wrong marker').decode()}
            else:row.value={**row.value,'version':'0.0.1'}
            if failure=='boolean-format':
                from sqlalchemy.orm.attributes import flag_modified
                flag_modified(row,'value')
            s.commit()
    with Session() as s:
        row=s.get(Setting,gate.KEY);before=row.value if row else None
    with pytest.raises(ValueError,match='preflight failed') as error:gate.verify(APP_VERSION)
    assert 'credential-secret' not in str(error.value)
    assert local.exists()==(failure!='missing-key')
    with Session() as s:
        row=s.get(Setting,gate.KEY);assert (row.value if row else None)==before


def test_controller_refuses_foreign_key_without_replacing_receipt(local):
    with Session() as s:before=s.get(Setting,gate.KEY).value
    local.write_bytes(Fernet.generate_key())
    with pytest.raises(Exception):gate.publish(APP_VERSION)
    with Session() as s:assert s.get(Setting,gate.KEY).value==before


def test_opt_in_and_invalid_configuration(local,monkeypatch):
    monkeypatch.setenv('MRPATCHY_REQUIRE_CONTROLLER_STATE','1');assert gate.admission(APP_VERSION)=='verified'
    monkeypatch.setenv('MRPATCHY_REQUIRE_CONTROLLER_STATE','0');assert gate.admission(APP_VERSION)=='not_checked'
    monkeypatch.setenv('MRPATCHY_REQUIRE_CONTROLLER_STATE','yes')
    with pytest.raises(ValueError):gate.admission(APP_VERSION)
    assert gate.RESULT=='not_checked'


def test_native_worker_refuses_empty_state_before_bootstrap(tmp_path):
    directory=tmp_path/'empty';directory.mkdir()
    env={**os.environ,'DATA_DIR':str(directory),'DATABASE_URL':'sqlite:///'+str(directory/'empty.db'),'MRPATCHY_REQUIRE_CONTROLLER_STATE':'1'}
    result=subprocess.run([sys.executable,'-m','app.worker'],env=env,capture_output=True,text=True,timeout=20)
    assert result.returncode!=0 and 'controller-state preflight failed' in result.stderr
    assert not (directory/'secret.key').exists()
    import sqlite3
    connection=sqlite3.connect(directory/'empty.db')
    assert not connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    connection.close()


def test_database_failure_diagnostic_does_not_expose_secrets(local,monkeypatch):
    def unavailable():raise RuntimeError('mysql://secret-password@private-host')
    monkeypatch.setattr(gate,'Session',unavailable)
    with pytest.raises(ValueError) as error:gate.verify(APP_VERSION)
    assert 'secret-password' not in str(error.value) and 'private-host' not in str(error.value)


def test_controller_refuses_malformed_version(local):
    with Session() as s:
        row=s.get(Setting,gate.KEY);row.value={**row.value,'version':None};s.commit()
    with pytest.raises(ValueError):gate.publish(APP_VERSION)
    with Session() as s:assert s.get(Setting,gate.KEY).value['version'] is None


def test_legacy_receipt_upgrade_retains_canary(local):
    with Session() as s:
        row=s.get(Setting,gate.KEY);old=row.value['encrypted'];row.value={k:v for k,v in row.value.items() if k not in ('protocol','requirements')}|{'version':'0.13.0'};s.commit()
    with pytest.raises(ValueError):gate.verify(APP_VERSION)
    gate.publish(APP_VERSION)
    assert gate.verify(APP_VERSION)=='verified'
    with Session() as s:
        value=s.get(Setting,gate.KEY).value
        assert value['encrypted']==old and value['protocol']==1
        assert value['requirements']==gate.requirements_digest(gate.schema_requirements())


@pytest.mark.parametrize('change',[{'protocol':2},{'protocol':True},{'protocol':None},{'requirements':'bad'},{'requirements':'a'*64}])
def test_protocol_and_digest_refuse_without_repair(local,change):
    from sqlalchemy import update
    with Session() as s:
        before={**s.get(Setting,gate.KEY).value,**change}
        s.execute(update(Setting).where(Setting.key==gate.KEY).values(value=before));s.commit()
    with pytest.raises(ValueError):gate.verify(APP_VERSION)
    with pytest.raises(ValueError):gate.publish(APP_VERSION)
    with Session() as s:assert s.get(Setting,gate.KEY).value==before


@pytest.mark.parametrize('damage',['table','column','primary_key','view','additive'])
def test_read_only_schema_inspection_of_actual_database(local,monkeypatch,tmp_path,damage):
    from sqlalchemy import create_engine,inspect,Table,Column,MetaData,String,text,event
    from sqlalchemy.orm import sessionmaker
    from app.db import Base
    engine=create_engine('sqlite:///'+str(tmp_path/'isolated.db'))
    Base.metadata.create_all(engine)
    monkeypatch.setattr(gate,'Session',sessionmaker(engine))
    try:
        gate.publish(APP_VERSION)
        table=Base.metadata.tables['package_events']
        if damage=='additive':
            with engine.begin() as c:c.execute(text('ALTER TABLE package_events ADD COLUMN extension TEXT'))
        else:
            table.drop(engine)
            if damage in ('column','primary_key'):
                Table('package_events',MetaData(),*[Column(c.name,String,primary_key=(c.primary_key and damage!='primary_key')) for c in table.columns if not (damage=='column' and c.name=='host_id')]).create(engine)
            elif damage=='view':
                with engine.begin() as c:c.execute(text('CREATE VIEW package_events AS SELECT 1 AS id'))
        before=inspect(engine).get_table_names()
        with gate.Session() as s:receipt=dict(s.get(Setting,gate.KEY).value)
        statements=[]
        event.listen(engine,'before_cursor_execute',lambda conn,cursor,statement,parameters,context,executemany:statements.append(statement))
        if damage=='additive':assert gate.verify(APP_VERSION)=='verified'
        else:
            with pytest.raises(ValueError,match='required tables/columns/primary keys'):gate.verify(APP_VERSION)
        assert not any(statement.lstrip().upper().startswith(('CREATE','ALTER','DROP','INSERT','UPDATE','DELETE')) for statement in statements)
        assert inspect(engine).get_table_names()==before
        with gate.Session() as s:assert s.get(Setting,gate.KEY).value==receipt
    finally:engine.dispose()


def test_structure_inspection_denial_is_redacted(local,monkeypatch):
    def denied(*args):raise PermissionError('private database credentials')
    monkeypatch.setattr(gate,'inspect_structure',denied)
    with pytest.raises(ValueError) as error:gate.verify(APP_VERSION)
    assert 'private database credentials' not in str(error.value)


def test_model_registration_does_not_bootstrap_database(tmp_path):
    env={**os.environ,'DATA_DIR':str(tmp_path),'DATABASE_URL':'sqlite:///'+str(tmp_path/'empty.db')}
    result=subprocess.run([sys.executable,'-c',"import sys; from app.worker_preflight import schema_requirements; assert schema_requirements(); assert 'app.main' not in sys.modules"],env=env,capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr
    import sqlite3
    connection=sqlite3.connect(tmp_path/'empty.db')
    assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()==[]
    connection.close()


@pytest.mark.parametrize('damage',['table','column','primary_key'])
def test_native_strict_worker_refuses_drift_before_init(tmp_path,damage):
    import sqlite3
    from app.worker_registry import record_key
    directory=tmp_path/'native';directory.mkdir();database=directory/'state.db'
    env={**os.environ,'DATA_DIR':str(directory),'DATABASE_URL':'sqlite:///'+str(database),'MRPATCHY_REQUIRE_CONTROLLER_STATE':'1','MRPATCHY_WORKER_ID':'must-not-register'}
    setup=subprocess.run([sys.executable,'-c',"from fastapi.testclient import TestClient; from app.main import app; c=TestClient(app); c.__enter__(); c.__exit__(None,None,None)"],env=env,capture_output=True,text=True,timeout=30)
    assert setup.returncode==0,setup.stderr
    with sqlite3.connect(database) as c:
        if damage=='table':c.execute('DROP TABLE package_events')
        elif damage=='column':c.execute('ALTER TABLE package_events DROP COLUMN actor')
        else:
            columns=[row[1] for row in c.execute('PRAGMA table_info(package_events)')]
            c.execute('DROP TABLE package_events')
            c.execute('CREATE TABLE package_events ('+','.join('"'+column+'" TEXT' for column in columns)+')')
        before=list(c.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"))
    result=subprocess.run([sys.executable,'-m','app.worker'],env=env,capture_output=True,text=True,timeout=30)
    assert result.returncode!=0 and 'preflight failed' in result.stderr
    with sqlite3.connect(database) as c:
        assert list(c.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"))==before
        assert c.execute('SELECT value FROM settings WHERE key=?',(record_key('must-not-register'),)).fetchone() is None


def test_current_receipt_cannot_masquerade_as_legacy(local):
    with Session() as s:
        row=s.get(Setting,gate.KEY);row.value={k:v for k,v in row.value.items() if k not in ('protocol','requirements')};s.commit()
    with pytest.raises(ValueError):gate.publish(APP_VERSION)
