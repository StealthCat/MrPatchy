"""Regression proofs for the original-requirements review."""
import base64
import copy
import importlib.util
import os
from pathlib import Path
import time
from types import SimpleNamespace
import pytest
from sqlalchemy import select
from sqlalchemy.dialects import mysql
from sqlalchemy.schema import CreateTable
from app import apt,worker
from app.db import Session,Host,Package,Behavior,Job

def inventory():
    return {'architecture':'arm64','foreign_architectures':[],'machine_id':'a'*32,'collected':time.time(),'status':'Package: example\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1\n\n','files':{'/etc/apt/sources.list':'deb [signed-by=/etc/apt/keyrings/vendor.gpg] https://example.org stable main\n'},'keys':{'/etc/apt/keyrings/vendor.gpg':base64.b64encode(b'fixture-key').decode()}}

def create_host(s):
    h=Host(id='review-host',name='Review target',address='192.0.2.1',fingerprint='SHA256:'+'a'*43,state='online',inventory=inventory(),baseline={'/managed':'abc'})
    s.add(h);s.commit();return h

def telemetry(**extra):
    return {'collected':time.time(),'hashed_at':time.time(),'managed':{'/managed':'abc'},'processes':[],'errors':[],**extra}

def test_removed_scoped_signing_keys_are_not_retained(tmp_path,monkeypatch):
    monkeypatch.setattr(apt,'DATA',tmp_path)
    inv=inventory();root,_=apt.prepare('host',inv)
    assert (root/'etc/apt/keyrings/vendor.gpg').exists()
    inv['keys']={};apt.prepare('host',inv)
    assert not (root/'etc/apt/keyrings/vendor.gpg').exists()

@pytest.mark.parametrize('source,deb822',[
    ('# deb [trusted=yes] https://example.org stable main\n',False),
    ('Types: deb\nURIs: https://example.org\nSuites: stable\nEnabled: no\nTrusted: yes\n',True),
])
def test_unsafe_source_can_be_disabled(source,deb822):
    assert apt.validate_source(source,deb822)==source

def test_duplicate_source_fields_rejected():
    with pytest.raises(ValueError):
        apt.validate_source('Types: deb\nURIs: file:/etc\nURIs: https://example.org\nSuites: ./\n',True)

def test_signed_by_cannot_reference_central_files(tmp_path,monkeypatch):
    monkeypatch.setattr(apt,'DATA',tmp_path)
    inv=inventory();inv['files']['/etc/apt/sources.list']='deb [signed-by=/tmp/central-key.gpg] https://example.org stable main'
    with pytest.raises(ValueError): apt.prepare('host',inv)

def test_target_atomic_honors_declared_mode_under_restrictive_umask(tmp_path):
    spec=importlib.util.spec_from_file_location('bridge_under_test',Path(__file__).parents[1]/'target/bridge.py')
    bridge=importlib.util.module_from_spec(spec);spec.loader.exec_module(bridge)
    old=os.umask(0o077)
    try: bridge.atomic(tmp_path/'key.asc',b'public key',0o644)
    finally: os.umask(old)
    assert (tmp_path/'key.asc').stat().st_mode & 0o777==0o644

def test_mysql_timestamps_are_double_precision():
    for model in [Host,Package,Behavior,Job]:
        sql=str(CreateTable(model.__table__).compile(dialect=mysql.dialect()))
        assert ' FLOAT ' not in sql

def test_collection_errors_cannot_produce_healthy_host(admin):
    with Session() as s:
        h=create_host(s)
        worker.ingest(s,h,{'telemetry':telemetry(errors=[{'pid':'123','error':'Permission denied'}])})
        assert h.state=='attention' and h.integrity

def test_future_hash_timestamp_is_not_healthy(admin):
    with Session() as s:
        h=create_host(s)
        worker.ingest(s,h,{'telemetry':telemetry(hashed_at=time.time()+99999)})
        assert h.state!='online'

def test_new_error_with_same_snapshot_is_not_ignored(admin):
    with Session() as s:
        h=create_host(s);t=telemetry()
        worker.ingest(s,h,{'telemetry':t})
        worker.ingest(s,h,{'telemetry':t,'collector-error':{'error':'inventory failed'}})
        assert h.state=='attention'

def test_failed_poll_rolls_back_partial_inventory(admin,monkeypatch):
    with Session() as s:
        h=create_host(s);s.refresh(h);old=copy.deepcopy(h.inventory)
    changed=inventory();changed['collected']+=10;changed['status']=changed['status'].replace('Version: 1','Version: 9')
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:{'inventory':changed,'telemetry':telemetry(processes=[{'invalid':'process'}])})
    worker.poll_host('review-host')
    with Session() as s:
        h=s.get(Host,'review-host');assert h.inventory==old

def test_telemetry_poll_continues_during_slow_job(admin,monkeypatch):
    with Session() as s: create_host(s)
    calls=[]
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:calls.append(1) or {'telemetry':telemetry()})
    with worker.host_lock('review-host'): worker.poll_host('review-host')
    assert calls

def test_inventory_change_invalidates_repository_freshness(admin):
    with Session() as s:
        h=create_host(s);h.last_repo=time.time();s.commit()
        inv=copy.deepcopy(h.inventory);inv['files']['/etc/apt/sources.list']='deb https://other.example.org stable main'
        worker.save_inventory(s,h,inv);s.commit()
        assert h.last_repo==0

def test_external_upgrade_clears_older_candidate(admin):
    with Session() as s:
        h=create_host(s)
        p=Package(id=h.id+':example:arm64',host_id=h.id,name='example:arm64',installed='1',candidate='2',available_since=time.time())
        s.add(p);s.commit()
        inv=copy.deepcopy(h.inventory);inv['status']=inv['status'].replace('Version: 1','Version: 3')
        worker.save_inventory(s,h,inv);s.commit()
        assert not p.candidate

def test_patch_rejected_when_last_refresh_failed(admin):
    with Session() as s:
        h=create_host(s);h.last_repo=time.time();h.repo_error='BADSIG'
        s.add(Package(id=h.id+':example:arm64',host_id=h.id,name='example:arm64',installed='1',candidate='2'));s.commit()
    assert admin.post('/api/hosts/review-host/patch',json={'packages':['example:arm64']}).status_code==409

def test_behavior_identity_includes_listener_bind_address():
    p={'executable':'/usr/bin/service','sha256':'a'*64,'uid':'1000','connections':[{'protocol':'tcp','local':'127.0.0.1','local_port':8080,'remote':'0.0.0.0','remote_port':0,'state':'0A'}]}
    changed=copy.deepcopy(p);changed['connections'][0]['local']='0.0.0.0'
    assert worker.behavior_evidence(p)!=worker.behavior_evidence(changed)

def test_reviewed_candidate_cannot_silently_change(admin):
    with Session() as s:
        h=create_host(s);h.last_repo=time.time()
        s.add(Package(id=h.id+':example:arm64',host_id=h.id,name='example:arm64',installed='1',candidate='3'));s.commit()
    r=admin.post('/api/hosts/review-host/patch',json={'packages':['example:arm64'],'expected_versions':{'example:arm64':'2'}})
    assert r.status_code==409

def test_stale_queued_patch_never_runs_installation(admin,monkeypatch):
    with Session() as s:
        h=create_host(s);h.last_repo=time.time()
        s.add(Package(id=h.id+':example:arm64',host_id=h.id,name='example:arm64',installed='1',candidate='2'))
        job_id=worker.enqueue(s,h.id,'patch',{'packages':['example:arm64=2']})
    calls=[]
    def remote(h,payload,**kwargs):
        calls.append(payload['action'])
        inv=inventory();inv['status']=inv['status'].replace('Version: 1','Version: 3')
        return inv
    monkeypatch.setattr(worker.ssh,'call',remote)
    worker.execute(job_id)
    assert calls==['inventory']
    with Session() as s: assert s.get(Job,job_id).state=='failed'

def test_mysql_existing_float_schema_migrates(admin):
    from app.db import engine,init
    from sqlalchemy import text,inspect
    if engine.dialect.name not in ('mysql','mariadb'): pytest.skip('Requires disposable MySQL integration database')
    with engine.begin() as connection:
        connection.execute(text('ALTER TABLE hosts MODIFY COLUMN last_seen FLOAT NOT NULL'))
    init()
    column=next(c for c in inspect(engine).get_columns('hosts') if c['name']=='last_seen')
    assert str(column['type'])=='DOUBLE'
    with Session() as s:
        h=create_host(s);h.last_seen=1792889701.75;s.commit();s.expire(h)
        assert h.last_seen==1792889701.75

def test_hash_alone_does_not_hide_world_writable_managed_code(admin):
    path='/usr/local/lib/mrpatchy/agent.py'
    with Session() as s:
        h=create_host(s);h.baseline={path:'unchanged-hash'}
        t=telemetry(managed={path:'unchanged-hash'},managed_metadata={path:{'uid':0,'gid':0,'mode':0o777}})
        worker.ingest(s,h,{'telemetry':t})
        assert h.state=='attention'
        assert any('permissions' in finding['issue'] for finding in h.integrity)

def test_legacy_bridge_upgrade_is_not_misreported_as_complete(monkeypatch):
    from app import ssh
    monkeypatch.setattr(ssh,'call',lambda *a,**kw:{'deployed':'anything','unit_sha256':'anything'})
    with pytest.raises(RuntimeError,match='legacy bootstrap'): ssh.deploy(SimpleNamespace())

def test_invalid_bridge_payload_does_not_partially_deploy(monkeypatch):
    from target import bridge
    written=[]
    monkeypatch.setattr(bridge,'atomic',lambda *a,**kw:written.append(a))
    code=b'pass\n'
    with pytest.raises(ValueError,match='bridge digest'):
        bridge.handle({'action':'deploy','agent':base64.b64encode(code).decode(),'sha256':bridge.hashlib.sha256(code).hexdigest(),'bridge':base64.b64encode(code).decode(),'bridge_sha256':'bad'})
    assert not written
