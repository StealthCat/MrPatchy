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
