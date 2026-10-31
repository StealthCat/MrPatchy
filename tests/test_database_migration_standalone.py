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
with Session() as s:
    s.add(TriageRetry(subject='subject',configuration='a'*64,attempts=2,state='deferred',next_at=1770000000.125,provider_until=1770000001.5,reason='Keep provider delay'))
    s.add(Assessment(id='assessment',subject='subject',host_id='host',source='ai',model='fixture-model',run_id='run',policy_hash='b'*64,state_hash='c'*64,result={'risk':'low','explanation':'retained result'},snapshot={'sha256':'d'*64},inputs=[{'evidence':{'uid':'1000'}}],refresh={}))
    s.add(Refresh(subject='subject',id='refresh',actor='admin',reason='Retain explicit refresh request',previous='assessment',withdrew_approval=True))
    s.add(Claim(subject='subject',host_id='host',token='old-token',worker_id='old-worker',boot_id='e'*32,run_id='run',revision='f'*64,configuration='a'*64,created=1770000000.125,renewed=1770000001.5,expires=1770000121.5))
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
    assert all(result[name]['rows']==1 for name in ('ai_triage_retries','ai_behavior_assessments','ai_behavior_refreshes','ai_triage_claims'))
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
