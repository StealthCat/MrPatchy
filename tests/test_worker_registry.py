import json
import os
import subprocess
import sys
import pytest
from sqlalchemy import select
from app import worker_registry as registry
from app.db import Session,Setting
from app.main import APP_VERSION
from app.identity import User


def test_registration_exclusive_heartbeat_stop_and_version(admin,monkeypatch):
    monkeypatch.setenv('MRPATCHY_WORKER_ID','fixture-worker')
    with registry.Registration('worker') as first:
        assert first.version==APP_VERSION
        with pytest.raises(ValueError,match='already in use'):
            with registry.Registration():pass
        first.last-=16;first.heartbeat(True,['job-one'],3,True)
        data=admin.get('/api/operations/workers').json();row=data['items'][0]
        assert row['id']=='fixture-worker' and row['state']=='reporting'
        assert row['active_jobs']==['job-one'] and row['coordinator'] is True
        assert row['readiness']=='not_assessed' and data['fresh_seconds']==120
        assert row['job_capacity']==2 and row['poll_capacity']==8
    row=admin.get('/api/operations/workers').json()['items'][0]
    assert row['state']=='stopped' and row['active_jobs']==[]
    with registry.Registration() as second:assert second.boot!=first.boot


def test_stale_future_invalid_version_and_secret_projection(admin):
    version=APP_VERSION
    values=[('fresh',{'heartbeat':1000,'state':'reporting','version':version}),('stale',{'heartbeat':879,'state':'reporting','version':version}),('future',{'heartbeat':1006,'state':'reporting','version':version}),('mismatch',{'heartbeat':1000,'state':'reporting','version':'0.0.1'}),('missing-version',{'heartbeat':1000,'state':'reporting'}),('broken',{'heartbeat':'invalid','secret':'must-not-leak'})]
    with Session() as s:
        for key,value in values:s.add(Setting(key=registry.PREFIX+key,value={**value,'api_key':'must-not-leak'}))
        s.commit()
    data=registry.page(now=1000);rows={r['id']:r for r in data['items']}
    assert rows['fresh']['state']=='reporting' and rows['stale']['state']=='stale'
    assert rows['future']['state']=='unknown' and rows['mismatch']['state']=='version_mismatch'
    assert rows['broken']['state']=='unknown' and rows['missing-version']['state']=='unknown'
    assert 'must-not-leak' not in json.dumps(data,allow_nan=False)


def test_limits_roles_and_no_network(admin,monkeypatch):
    from app import ai,ssh
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('AI must not run'))
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('Target must not be contacted'))
    with Session() as s:
        for n in range(53):s.add(Setting(key=registry.PREFIX+str(n).zfill(3),value={}))
        s.commit()
    data=admin.get('/api/operations/workers').json();assert len(data['items'])==50 and data['more']
    assert len(admin.get('/api/operations/workers?offset=50').json()['items'])==3
    assert admin.get('/api/operations/workers?offset=-1').status_code==400
    for role in ('viewer','operator'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get('/api/operations/workers').status_code==403


def test_lost_identity_refuses_heartbeat(admin,monkeypatch):
    with registry.Registration() as node:
        monkeypatch.setattr(node.lock,'owned',lambda:False)
        with pytest.raises(registry.IdentityLost):node.heartbeat(False,[],0,False)


def test_invalid_configuration_and_static_version(admin,monkeypatch):
    monkeypatch.setenv('MRPATCHY_WORKER_ID','bad/id')
    with pytest.raises(ValueError):registry.Registration()
    monkeypatch.delenv('MRPATCHY_WORKER_ID')
    monkeypatch.setenv('MRPATCHY_DEPLOYMENT_TYPE','unsupported')
    with pytest.raises(ValueError):registry.Registration()
    assert registry.source_version()==APP_VERSION


@pytest.mark.parametrize('role,tls',[('worker',False),('controller',True)])
def test_role_startup_without_touching_real_paths(tmp_path,role,tls):
    log=tmp_path/'calls';bin=tmp_path/'bin';bin.mkdir()
    for command in ('mkdir','chown','gosu'):
        script=bin/command;script.write_text('#!/bin/sh\nprintf "%s\\n" "'+command+' $*" >> "$CALL_LOG"\n');script.chmod(0o755)
    result=subprocess.run(['/bin/sh','deploy/entrypoint.sh','python','-m','app.worker'],env={**os.environ,'PATH':str(bin),'CALL_LOG':str(log),'MRPATCHY_RUNTIME_ROLE':role},capture_output=True,text=True)
    assert result.returncode==0
    calls=log.read_text();assert ('/tls' in calls)==tls and ('app.tls' in calls)==tls
    assert 'gosu mrpatchy python -m app.worker' in calls


def test_scheduler_records_loop_without_claiming_work(admin,monkeypatch):
    from app import worker
    monkeypatch.setenv('MRPATCHY_WORKER_ID','loop-fixture')
    monkeypatch.setattr(worker.stop,'wait',lambda _:True)
    worker.loop()
    assert registry.page()['items'][0]['state']=='stopped'


def test_lost_identity_exits_before_scheduling_and_releases_leader(admin,monkeypatch):
    from app import worker
    monkeypatch.setattr(worker.stop,'wait',lambda _:False)
    monkeypatch.setattr(worker.scheduling,'tick',lambda *a:pytest.fail('must not schedule after identity loss'))
    class Lost:
        def heartbeat(self,*a):raise registry.IdentityLost('lost')
    with pytest.raises(registry.IdentityLost):worker._loop(Lost())
    lock=worker.Lock('scheduler')
    assert lock.acquire(False)
    lock.release()


def test_metadata_does_not_import_web_runtime(tmp_path):
    directory=tmp_path/'runtime';directory.mkdir()
    result=subprocess.run([sys.executable,'-c',"import sys; from app.worker_registry import source_version; assert 'app.main' not in sys.modules; print(source_version())"],env={**os.environ,'DATA_DIR':str(directory),'DATABASE_URL':'sqlite:///'+str(directory/'test.db')},capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()==APP_VERSION


def test_real_worker_process_registration_duplicate_identity_and_stop(tmp_path):
    import json
    import signal
    import sqlite3
    import time
    directory=tmp_path/'process';directory.mkdir();database=directory/'worker.db'
    env={**os.environ,'DATA_DIR':str(directory),'DATABASE_URL':'sqlite:///'+str(database),'MRPATCHY_WORKER_ID':'process-fixture','MRPATCHY_DEPLOYMENT_TYPE':'process'}
    output=tmp_path/'worker.log'
    with output.open('w') as stream:
        process=subprocess.Popen([sys.executable,'-m','app.worker'],env=env,stdout=stream,stderr=stream)
        try:
            report=None
            for _ in range(100):
                if process.poll() is not None:break
                try:
                    with sqlite3.connect(database,timeout=1) as db:
                        row=db.execute('SELECT value FROM settings WHERE key=?',(registry.record_key('process-fixture'),)).fetchone()
                        if row:report=json.loads(row[0]);break
                except sqlite3.OperationalError:pass
                time.sleep(.1)
            assert report and report['state']=='reporting',output.read_text()[-2000:]
            assert report['role']=='worker' and report['version']==APP_VERSION
            duplicate=subprocess.run([sys.executable,'-m','app.worker'],env=env,capture_output=True,text=True,timeout=15)
            assert duplicate.returncode!=0 and 'already in use' in duplicate.stderr
            assert process.poll() is None
            def command(action,revision):
                with sqlite3.connect(database,timeout=2) as db:
                    db.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',(registry.control_key('process-fixture'),json.dumps({'boot_id':report['boot_id'],'revision':revision,'action':action})))
                expected='drained' if action=='drain' else 'reporting'
                for _ in range(100):
                    with sqlite3.connect(database,timeout=2) as db:current=json.loads(db.execute('SELECT value FROM settings WHERE key=?',(registry.record_key('process-fixture'),)).fetchone()[0])
                    if current.get('control_revision')==revision and current['state']==expected:return
                    time.sleep(.1)
                pytest.fail('Real worker did not acknowledge '+action+': '+str(current))
            command('drain',1)
            assert process.poll() is None, 'Drain keeps the worker process alive'
            command('resume',2)
            process.send_signal(signal.SIGTERM);assert process.wait(timeout=15)==0
            with sqlite3.connect(database) as db:stopped=json.loads(db.execute('SELECT value FROM settings WHERE key=?',(registry.record_key('process-fixture'),)).fetchone()[0])
            assert stopped['state']=='stopped' and stopped['boot_id']==report['boot_id']
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)


def test_distinct_case_ids_survive_database_collation(admin,monkeypatch):
    monkeypatch.setenv('MRPATCHY_WORKER_ID','Worker-A')
    with registry.Registration():
        monkeypatch.setenv('MRPATCHY_WORKER_ID','worker-a')
        with registry.Registration():
            rows=registry.page()['items']
            assert {row['id'] for row in rows}=={'Worker-A','worker-a'}
            assert all(row['state']=='reporting' for row in rows)


def test_unverifiable_identity_is_fatal(admin,monkeypatch):
    with registry.Registration() as node:
        def unavailable():raise OSError('Connection lost')
        monkeypatch.setattr(node.lock,'owned',unavailable)
        with pytest.raises(registry.IdentityLost):node.heartbeat(False,[],0,False)


def test_expected_workers_independent_of_pagination_and_no_mutations(admin,monkeypatch):
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS','Worker-A,worker-a,missing')
    with Session() as s:
        for identity,state,heartbeat in [('Worker-A','reporting',1000),('worker-a','stopped',900)]:
            s.add(Setting(key=registry.record_key(identity),value={'id':identity,'heartbeat':heartbeat,'version':APP_VERSION,'state':state,'secret':'not-exposed'}))
        s.commit()
    before=None
    with Session() as s:before=list(s.scalars(select(Setting.key)))
    first=registry.page(now=1000);last=registry.page(offset=100,now=1000)
    assert first['expected']==last['expected'] and not last['items']
    expected={row['id']:row for row in first['expected']}
    assert expected['Worker-A']['state']=='reporting' and expected['worker-a']['state']=='stopped'
    assert expected['missing']['state']=='missing' and expected['missing']['registered'] is False
    assert all(row['readiness']=='not_assessed' for row in first['expected'])
    assert 'not-exposed' not in json.dumps(first)
    with Session() as s:assert list(s.scalars(select(Setting.key)))==before


@pytest.mark.parametrize('raw',['same,same','bad/id','one,','x'*49,','.join('w'+str(i) for i in range(101))])
def test_expected_worker_invalid_config_is_visible(admin,monkeypatch,raw):
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS',raw)
    data=admin.get('/api/operations/workers').json()
    assert data['expected']==[] and data['expectation_error']


@pytest.mark.parametrize('state,heartbeat,version,result',[('reporting',879,APP_VERSION,'stale'),('reporting',1006,APP_VERSION,'unknown'),('reporting',1000,'0.0.1','version_mismatch'),('drained',1000,APP_VERSION,'drained')])
def test_expected_worker_freshness_and_version(admin,monkeypatch,state,heartbeat,version,result):
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS','one')
    with Session() as s:s.add(Setting(key=registry.record_key('one'),value={'id':'one','heartbeat':heartbeat,'version':version,'state':state}));s.commit()
    assert registry.page(now=1000)['expected'][0]['state']==result


def test_expectations_absent_and_wrong_identity(admin,monkeypatch):
    monkeypatch.delenv('MRPATCHY_EXPECTED_WORKER_IDS',raising=False)
    assert registry.page()['expected']==[] and registry.page()['expectation_error'] is None
    monkeypatch.setenv('MRPATCHY_EXPECTED_WORKER_IDS','one')
    with Session() as s:s.add(Setting(key=registry.record_key('one'),value={'id':'different','heartbeat':1000}));s.commit()
    assert registry.page(now=1000)['expected'][0]['state']=='missing'
