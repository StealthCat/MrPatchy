"""Offline CLI regressions must run outside conftest's preloaded web process."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]


def child(code,env):
    return subprocess.run([sys.executable,'-c',code],cwd=ROOT,env=env,text=True,capture_output=True,timeout=30)


@pytest.fixture
def initialized_source(tmp_path):
    env={**os.environ,'DATA_DIR':str(tmp_path),'DATABASE_URL':'sqlite:///'+str(tmp_path/'source.db')}
    # Init is the schema path used by real startup, without the web-app import
    # that used to hide migration's stale model list in the ordinary test suite.
    seeded=child('''
import json,sys
from app.db import init,Session,Base
init()
from app.ai_retry import TriageRetry
from app.ai_assessments import Assessment,Refresh
from app.ai_claims import Claim
from app.known_good import Entry,Observation
with Session() as s:
    s.add(TriageRetry(subject='subject',configuration='a'*64,attempts=2,state='deferred',next_at=1770000000.125,provider_until=1770000001.5,reason='Keep provider delay'))
    s.add(Assessment(id='assessment',subject='subject',host_id='host',source='ai',model='fixture-model',run_id='run',policy_hash='b'*64,state_hash='c'*64,result={'risk':'low','explanation':'retained result'},snapshot={'sha256':'d'*64},inputs=[{'evidence':{'uid':'1000'}}],refresh={}))
    s.add(Refresh(subject='subject',id='refresh',actor='admin',reason='Retain explicit refresh request',previous='assessment',withdrew_approval=True))
    s.add(Claim(subject='subject',host_id='host',token='old-token',worker_id='old-worker',boot_id='e'*32,run_id='run',revision='f'*64,configuration='a'*64,created=1770000000.125,renewed=1770000001.5,expires=1770000121.5))
    s.add(Entry(fingerprint='1'*64,version=1,created=1770000002.25,classification_source='ai',model='fixture-model',policy_hash='b'*64,assessment_id='assessment',source_host_id='host',contract={'version':1,'artifact':{'sha256':'d'*64}},result={'risk':'low','explanation':'retained candidate'}))
    s.add(Observation(assessment_id='assessment',fingerprint='1'*64,host_id='host',subject='subject',created=1770000002.25,observation={'pid':42,'start_ticks':101}))
    s.commit()
assert 'app.main' not in sys.modules
print(json.dumps(sorted(Base.metadata.tables)))
''',env)
    assert seeded.returncode==0,seeded.stderr
    return env,set(json.loads(seeded.stdout)),tmp_path


def test_fresh_process_registry_dry_run_and_copy_preserve_current_ai_tables(initialized_source):
    env,tables,root=initialized_source
    code='''
import json,os,sys
from app.database_migrate import metadata,migrate
assert 'app.main' not in sys.modules
assert 'app.worker' not in sys.modules
result=migrate(os.environ['DATABASE_URL'],'sqlite:///DESTINATION',dry_run=DRY_RUN)
print(json.dumps(result,sort_keys=True))
'''.replace('DESTINATION',str(root/'destination.db'))
    dry=child(code.replace('DRY_RUN','True'),env)
    assert dry.returncode==0,dry.stderr
    result=json.loads(dry.stdout)
    assert set(result)==tables and not (root/'destination.db').exists()
    assert all(result[name]['rows']==1 for name in ('ai_triage_retries','ai_behavior_assessments','ai_behavior_refreshes','ai_triage_claims','ai_known_good_entries','ai_known_good_observations'))
    copied=child(code.replace('DRY_RUN','False'),env)
    assert copied.returncode==0,copied.stderr
    assert json.loads(copied.stdout)==result and (root/'source.db').exists()
    verified=child('''
import json,os
from sqlalchemy import create_engine,select
from app.database_migrate import metadata,fingerprint
meta=metadata();engine=create_engine('sqlite:///DESTINATION')
with engine.connect() as c:
    assert c.execute(select(meta.tables['ai_triage_retries'].c.attempts)).scalar_one()==2
    assert c.execute(select(meta.tables['ai_behavior_assessments'].c.inputs)).scalar_one()==[{'evidence':{'uid':'1000'}}]
    assert c.execute(select(meta.tables['ai_behavior_refreshes'].c.withdrew_approval)).scalar_one() is True
    assert c.execute(select(meta.tables['ai_triage_claims'].c.token)).scalar_one()=='old-token'
    assert c.execute(select(meta.tables['ai_triage_claims'].c.expires)).scalar_one()==1770000121.5
    assert c.execute(select(meta.tables['ai_known_good_entries'].c.contract)).scalar_one()=={'version':1,'artifact':{'sha256':'d'*64}}
    assert c.execute(select(meta.tables['ai_known_good_observations'].c.observation)).scalar_one()=={'pid':42,'start_ticks':101}
    print(json.dumps({t.name:fingerprint(c,t) for t in meta.sorted_tables},sort_keys=True))
'''.replace('DESTINATION',str(root/'destination.db')),env)
    assert verified.returncode==0,verified.stderr
    assert json.loads(verified.stdout)==result


@pytest.mark.parametrize('object_kind',['table','view'])
def test_fresh_process_still_refuses_unrecognized_source_objects(initialized_source,object_kind):
    env,_,root=initialized_source
    ddl='CREATE TABLE unrelated (id INTEGER)' if object_kind=='table' else 'CREATE VIEW unrelated AS SELECT 1 AS id'
    result=child('''
import os
from sqlalchemy import create_engine
from app.database_migrate import migrate,MigrationError
engine=create_engine(os.environ['DATABASE_URL'])
with engine.begin() as c:c.exec_driver_sql(DDL)
try:migrate(os.environ['DATABASE_URL'],'sqlite:///DESTINATION',dry_run=True)
except MigrationError as error:
    assert 'Source tables' in str(error)
    assert OBJECT_KIND in str(error)
    assert 'unrelated' in str(error)
else:raise AssertionError('Unrecognized source object was accepted')
'''.replace('DDL',repr(ddl)).replace('OBJECT_KIND',repr(object_kind)).replace('DESTINATION',str(root/'destination.db')),env)
    assert result.returncode==0,result.stderr
    assert not (root/'destination.db').exists()


def test_fresh_process_explains_missing_current_table_and_startup_repairs_it(initialized_source):
    env,_,root=initialized_source
    result=child('''
import os
from sqlalchemy import create_engine
from app.database_migrate import migrate,MigrationError
engine=create_engine(os.environ['DATABASE_URL'])
with engine.begin() as connection:
    connection.exec_driver_sql('DROP TABLE ai_triage_claims')
try:migrate(os.environ['DATABASE_URL'],'sqlite:///DESTINATION',dry_run=True)
except MigrationError as error:
    assert 'missing tables' in str(error)
    assert 'ai_triage_claims' in str(error)
else:raise AssertionError('Outdated source schema was accepted')
'''.replace('DESTINATION',str(root/'destination.db')),env)
    assert result.returncode==0,result.stderr
    repaired=child('''
import os
from app.db import init
from app.database_migrate import migrate
init()
result=migrate(os.environ['DATABASE_URL'],'sqlite:///DESTINATION',dry_run=True)
assert 'ai_triage_claims' in result
'''.replace('DESTINATION',str(root/'destination.db')),env)
    assert repaired.returncode==0,repaired.stderr
    assert not (root/'destination.db').exists()


SECRET='s3cret-Passw0rd-VALUE'


def stage_target(env,root,backend='sqlite'):
    values={'backend':backend,'host':'127.0.0.1','port':1,'database':'mrpatchy','username':'migrator','password':SECRET if backend=='mysql' else '','tls':False,'ca_file':'','sqlite_file':'destination.db'}
    done=child('from app import database_config as s;s.write_profile("target",%r)'%values,env)
    assert done.returncode==0,done.stderr


def cli(env,args,patch=''):
    code='import sys\nfrom app import database_migrate as m\n'+patch+'\nsys.exit(m.main(%r))'%(['--confirm-offline']+args,)
    return child(code,env)


def test_cli_dry_run_reports_stages_on_stderr_and_keeps_stdout_json(initialized_source):
    env,tables,root=initialized_source
    stage_target(env,root)
    done=cli(env,['--dry-run'])
    assert done.returncode==0,done.stderr
    assert set(json.loads(done.stdout)['tables'])==tables
    for marker in ('Taking the offline maintenance lock','Connecting to source','Validating source schema','Fingerprinting source table jobs','skipped (dry run)'):
        assert marker in done.stderr
    assert not (root/'destination.db').exists()
    copied=cli(env,[])
    assert copied.returncode==0,copied.stderr
    assert json.loads(copied.stdout)['dry_run'] is False
    assert 'Creating destination schema' in copied.stderr and 'Copying table jobs' in copied.stderr
    assert 'Verifying committed table jobs' in copied.stderr and 'Verified copy complete' in copied.stderr


def test_cli_unreachable_mysql_destination_names_stage_category_and_code_without_secrets(initialized_source):
    env,_,root=initialized_source
    stage_target(env,root,'mysql')
    done=cli(env,['--dry-run'])
    assert done.returncode==1 and done.stdout==''
    assert 'failed at stage destination-connect (destination)' in done.stderr
    assert 'Category: connection' in done.stderr and 'code: mysql 2003' in done.stderr and 'OperationalError' in done.stderr
    assert 'Destination: nothing has been written' in done.stderr and 'Active database unchanged' in done.stderr
    assert 'Check database access, TLS, schema and free space' not in done.stderr
    assert SECRET not in done.stderr and '127.0.0.1' not in done.stderr.split('Next check')[1]
    assert 'Stack:' not in done.stderr and '--verbose' in done.stderr
    verbose=cli(env,['--dry-run','--verbose'])
    assert 'Cause chain:' in verbose.stderr and 'Stack:' in verbose.stderr and 'database_migrate.py:' in verbose.stderr
    assert SECRET not in verbose.stderr


NESTED='''
import errno,ssl,sqlite3
import pymysql.err
from sqlalchemy import exc
LEAK="secret-row-value password=s3cret-Passw0rd-VALUE INSERT INTO t VALUES ('leak')\\nsecond line \\x1b[31m"
def wrap(orig):
    try:
        try:raise orig
        except Exception as inner:raise exc.OperationalError('INSERT INTO jobs VALUES (:p)',{'p':LEAK},inner) from inner
    except Exception as outer:return outer
'''
CASES={
 'auth':(NESTED+'''
def boom(*a,**k):raise wrap(pymysql.err.OperationalError(1045,LEAK))
m.validate_destination=boom''',[],'destination-validate','authentication','mysql 1045'),
 'tls':(NESTED+'''
def boom(*a,**k):raise wrap(ssl.SSLCertVerificationError(1,LEAK))
m.validate_destination=boom''',[],'destination-validate','tls','ssl'),
 'source-read':(NESTED+'''
def boom(*a,**k):
    error=sqlite3.OperationalError(LEAK);error.sqlite_errorname='SQLITE_CANTOPEN'
    raise wrap(error)
m.fingerprint=boom''',['--dry-run'],'source-fingerprint','permissions','SQLITE_CANTOPEN'),
 'copy-storage':(NESTED+'''
from sqlalchemy import Table
def boom(*a,**k):raise OSError(errno.ENOSPC,LEAK)
Table.insert=boom''',[],'copy','storage','ENOSPC'),
 'verify':(NESTED+'''
real=m.fingerprint;state={'n':0}
def boom(connection,table):
    state['n']+=1
    if state['n']>len(m.metadata().tables):raise wrap(pymysql.err.OperationalError(2013,LEAK))
    return real(connection,table)
m.fingerprint=boom''',[],'verify-transaction','connection','mysql 2013'),
}


@pytest.mark.parametrize('name',sorted(CASES))
@pytest.mark.parametrize('verbose',[False,True])
def test_cli_failures_report_stage_cause_and_redact_nested_driver_text(initialized_source,name,verbose):
    env,_,root=initialized_source
    stage_target(env,root)
    patch,args,stage,category,code=CASES[name]
    done=cli(env,args+(['--verbose'] if verbose else []),patch)
    assert done.returncode==1 and done.stdout==''
    assert 'failed at stage '+stage in done.stderr
    assert 'Category: '+category in done.stderr and 'code: '+code in done.stderr
    assert 'Active database unchanged' in done.stderr
    for leaked in (SECRET,'secret-row-value','INSERT INTO','second line','\x1b','leak'):
        assert leaked not in done.stderr
    assert ('Stack:' in done.stderr)==verbose
    if stage=='copy':assert 'rows may have been inserted' in done.stderr and 'table "' in done.stderr


def test_cli_controlled_refusals_keep_stage_and_message(initialized_source):
    env,_,root=initialized_source
    stage_target(env,root)
    from_dir=child('''
from sqlalchemy import create_engine
import os
with create_engine(os.environ['DATABASE_URL']).begin() as c:c.exec_driver_sql('CREATE TABLE unrelated (id INTEGER)')''',env)
    assert from_dir.returncode==0,from_dir.stderr
    done=cli(env,['--dry-run'])
    assert done.returncode==1 and done.stdout==''
    assert 'Migration refused at stage source-validate (source)' in done.stderr and 'unexpected tables' in done.stderr
    assert 'nothing has been written' in done.stderr
    missing=child('import sys\nfrom app import database_migrate as m\nsys.exit(m.main([]))',env)
    assert missing.returncode==1 and 'Pass --confirm-offline' in missing.stderr
