import base64
import copy
import hashlib
import json
import sys
import time
import uuid
from types import SimpleNamespace
import pytest
from sqlalchemy import select,func,text,inspect
from app import apt,worker
from app.db import Session,Host,Package,Setting,Behavior,InventoryRevision,Observation,engine,init
from app.security import seal
from app.repository_access import validate,rewrite
from app.process import bounded
from target import agent,bridge
from test_review_regressions import inventory,create_host,telemetry

def test_broken_package_states_are_visible():
    data=inventory()['status'].replace('install ok installed','install reinstreq half-configured')
    assert apt.installed(data)[0]['dpkg_state']=='install reinstreq half-configured'
    assert apt.installed(data.replace('half-configured','config-files'))==[]

def test_inventory_history_records_reversions(admin):
    with Session() as s:
        h=create_host(s);original=copy.deepcopy(h.inventory)
        worker.save_inventory(s,h,original);s.commit()
        changed=copy.deepcopy(original);changed['status']=changed['status'].replace('Version: 1','Version: 2')
        worker.save_inventory(s,h,changed);s.commit()
        worker.save_inventory(s,h,original);s.commit()
        worker.save_inventory(s,h,original);s.commit()
        assert s.scalar(select(func.count()).select_from(InventoryRevision))==3

def test_spool_survives_restart_and_ack_is_selective(tmp_path,monkeypatch):
    monkeypatch.setattr(agent,'ROOT',tmp_path)
    agent.spool([{'pid':1}],time.time());agent.spool([{'pid':2}],time.time())
    events=agent.pending_events()['events']
    assert len(events)==2
    agent.acknowledge([events[0]['id']])
    assert [e['id'] for e in agent.pending_events()['events']]==[events[1]['id']]
    agent.acknowledge([events[0]['id']])
    assert agent.pending_events()['spool']['pending']==1

def test_oversize_spool_is_reported(tmp_path,monkeypatch):
    monkeypatch.setattr(agent,'ROOT',tmp_path)
    agent.spool([{'oversize':'x'*2_000_001}],time.time())
    assert agent.pending_events()['spool']=={'pending':0,'dropped':1}

def test_replayed_events_are_idempotent(admin):
    event={'id':str(uuid.uuid4()),'observed':time.time()-300,'processes':[{'executable':'/usr/bin/test','sha256':'a'*64,'uid':'0','connections':[]}]}
    with Session() as s:
        h=create_host(s)
        for _ in range(2): worker.ingest(s,h,{'telemetry':telemetry(),'events':[event]})
        assert s.scalar(select(func.count()).select_from(Observation))==1
        assert s.scalar(select(func.count()).select_from(Behavior))==1

def test_failed_ingestion_never_acknowledges(admin,monkeypatch):
    from app import agent_maintenance
    monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'current'})
    with Session() as s: create_host(s)
    calls=[]
    event={'id':str(uuid.uuid4()),'observed':time.time(),'processes':[{'malformed':True}]}
    def call(h,payload):
        calls.append(payload['action'])
        return {'telemetry':telemetry(),'events':[event]}
    monkeypatch.setattr(worker.ssh,'call',call)
    worker.poll_host('review-host')
    assert calls==['snapshot']
    with Session() as s: assert s.scalar(select(func.count()).select_from(Observation))==0

def test_offline_repository_resolution_uses_saved_inventory(admin,monkeypatch):
    with Session() as s:
        h=create_host(s);h.state='offline';s.commit()
        monkeypatch.setattr(worker.ssh,'call',lambda *a:pytest.fail('Offline refresh attempted SSH'))
        monkeypatch.setattr(apt,'refresh',lambda host,inv,access:([],'checked centrally'))
        assert worker.update_repos(s,h)=='checked centrally'
        assert h.last_repo>0

def test_external_key_mapping_and_removed_key_fail_closed(tmp_path,monkeypatch):
    monkeypatch.setattr(apt,'DATA',tmp_path)
    inv=inventory();key=inv['keys'].pop('/etc/apt/keyrings/vendor.gpg')
    inv['keys']['/opt/vendor/public.gpg']=key
    inv['files']['/etc/apt/sources.list']=inv['files']['/etc/apt/sources.list'].replace('/etc/apt/keyrings/vendor.gpg','/opt/vendor/public.gpg')
    root,cfg=apt.prepare('example',inv)
    assert str(root/'etc/apt/keyrings/captured-') in (root/'etc/apt/sources.list').read_text()
    inv['keys']={}
    with pytest.raises(ValueError,match='not captured'): apt.prepare('example',inv)

def test_mirror_credentials_and_default_release(tmp_path,monkeypatch):
    monkeypatch.setattr(apt,'DATA',tmp_path)
    inv=inventory();inv['files']['/etc/apt/sources.list']=inv['files']['/etc/apt/sources.list'].replace('https://example.org','file:/srv/local')
    access={'mirrors':{'file:/srv/local':'https://mirror.example.test/local'},'credentials':[{'machine':'https://mirror.example.test/local','login':'user','password':'secret-token'}],'default_release':'stable'}
    root,cfg=apt.prepare('mirror',inv,access)
    assert 'file:/srv/local' not in (root/'etc/apt/sources.list').read_text()
    assert 'https://mirror.example.test/local' in (root/'etc/apt/sources.list').read_text()
    assert (root/'etc/apt/auth.conf').stat().st_mode & 0o777==0o600
    assert 'APT::Default-Release "stable"' in cfg.read_text()
    assert rewrite('deb file:/srv/local-other stable main',access)=='deb file:/srv/local-other stable main'

@pytest.mark.parametrize('access',[
    {'credentials':[{'machine':'http://example.test','login':'user','password':'secret'}]},
    {'credentials':[{'machine':'https://example.test','login':'user\npassword evil','password':'secret'}]},
    {'proxy':'http://proxy/"; DPkg::Pre-Invoke {"evil"};'},
    {'mirrors':{'file:/srv/repo':'file:/etc'}},
    {'default_release':'stable"; evil'},
])
def test_repository_access_rejects_injection(access):
    with pytest.raises(ValueError): validate(access)

def test_credentials_never_returned_and_installer_remains_available(admin):
    host=admin.post('/api/hosts',json={'name':'Offline target','address':'192.0.2.99'}).json()['id']
    before=admin.get('/api/hosts/'+host+'/installer')
    assert before.status_code==200 and 'useradd --system' in before.text
    access={'replace_credentials':True,'credentials':[{'machine':'https://repo.example.test','login':'user','password':'very-secret-token'}]}
    assert admin.put('/api/hosts/'+host+'/repository-access',json=access).status_code==200
    assert 'very-secret-token' not in admin.get('/api/hosts/'+host+'/repository-access').text
    with Session() as s:
        stored=s.get(Setting,'repository-access:'+host)
        assert 'very-secret-token' not in json.dumps(stored.value)
        h=s.get(Host,host);h.state='online';s.commit()
    assert admin.get('/api/hosts/'+host+'/installer').text==before.text

def test_bounded_subprocess_rejects_flood_and_timeout():
    with pytest.raises(RuntimeError,match='output exceeded'):
        bounded([sys.executable,'-c','print("x"*20000)'],limit=10000)
    with pytest.raises(TimeoutError):
        bounded([sys.executable,'-c','import time; time.sleep(5)'],timeout=.1)

def test_evidence_rejects_arbitrary_command():
    with pytest.raises(ValueError):
        bridge.process_evidence({'executable':'/usr/bin/python3','sha256':'a'*64,'checks':['shell']})

def test_evidence_for_exited_identity_is_explicit():
    assert bridge.process_evidence({'executable':'/does-not-exist','sha256':'a'*64,'checks':['executable']})['identity_verified'] is False

def test_two_stage_investigation_uses_only_allowlisted_checks(admin,monkeypatch):
    with Session() as s:
        h=create_host(s)
        worker.record_behavior(s,h,{'executable':'/bin/test','sha256':'a'*64,'uid':'0','connections':[]},time.time())
        s.add(Setting(key='config',value={'ai_enabled':True,'ai_model':'test-model','ai_hourly_limit':20}))
        s.add(Setting(key='openai_key',value={'encrypted':seal('test-not-a-real-key')}));s.commit()
    requests=[];ssh_calls=[]
    def post(*args,**kwargs):
        requests.append(kwargs['json'])
        checks=['executable'] if len(requests)==1 else []
        result={'risk':'unknown','explanation':'Evidence incomplete','recommended_checks':'Operator review','requested_checks':checks}
        return SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(result)}]}]})
    def call(host,payload,**kwargs):
        ssh_calls.append(payload);return {'identity_verified':False,'reason':'exited'}
    monkeypatch.setattr(worker.ai.transport,'post',post);monkeypatch.setattr(worker.ssh,'call',call)
    worker.investigate_one()
    assert len(requests)==2 and ssh_calls[0]['action']=='evidence'
    assert ssh_calls[0]['checks']==['executable'] and ssh_calls[0]['uid']=='0'
    assert all(r['store'] is False for r in requests)
    assert 'identity_verified' in requests[1]['input']

def test_package_state_schema_upgrade_is_idempotent(admin):
    with engine.begin() as connection: connection.execute(text('ALTER TABLE packages DROP COLUMN dpkg_state'))
    init();init()
    assert 'dpkg_state' in {c['name'] for c in inspect(engine).get_columns('packages')}

@pytest.mark.parametrize('verification',[{'active':False,'files':{}},{'active':True,'files':{}}])
def test_deploy_does_not_complete_without_verification(admin,monkeypatch,verification):
    from app.db import Job
    with Session() as s:
        h=create_host(s);job_id=worker.enqueue(s,h.id,'deploy')
    monkeypatch.setattr(worker.ssh,'deploy',lambda h:{'deployed':'test'})
    monkeypatch.setattr(worker.ssh,'public_key',lambda h:'ssh-ed25519 fixture')
    monkeypatch.setattr(worker.ssh,'call',lambda *args,**kwargs:verification)
    worker.execute(job_id)
    with Session() as s:
        assert s.get(Job,job_id).state=='failed'
        assert not s.get(Host,'review-host').baseline.get('/usr/local/lib/mrpatchy/agent.py')

def test_config_cannot_race_repository_resolution(admin):
    with Session() as s: create_host(s)
    with worker.host_lock('review-host'):
        result=admin.put('/api/hosts/review-host/repository-access',json={'default_release':'stable'})
    assert result.status_code==409

def test_history_detail_is_host_scoped(admin):
    with Session() as s:
        h=create_host(s);worker.save_inventory(s,h,h.inventory);s.commit()
        record=s.scalar(select(InventoryRevision)).id
    rows=admin.get('/api/hosts/review-host/history').json()
    assert len(rows)==1 and 'inventory' not in rows[0]
    assert admin.get('/api/hosts/review-host/history/'+record).status_code==200
    assert admin.get('/api/hosts/another-host/history/'+record).status_code==404

def test_broken_package_requires_repair_before_patch(admin):
    with Session() as s:
        h=create_host(s);worker.save_inventory(s,h,h.inventory)
        p=s.get(Package,h.id+':example:arm64');p.candidate='2';p.dpkg_state='install ok unpacked'
        h.last_repo=time.time();s.commit()
    result=admin.post('/api/hosts/review-host/patch',json={'packages':['example:arm64']})
    assert result.status_code==400 and 'broken' in result.json()['detail']


def test_failed_operation_log_fits_mysql_text_bytes(admin,monkeypatch):
    from app.db import Job
    with Session() as s:
        h=create_host(s);job_id=worker.enqueue(s,h.id,'deploy')
    def fail(host): raise RuntimeError('😀'*20000)
    monkeypatch.setattr(worker.ssh,'deploy',fail)
    worker.execute(job_id)
    with Session() as s:
        job=s.get(Job,job_id)
        assert job.state=='failed' and len(job.output.encode())<=48000

def test_older_replayed_behavior_keeps_earliest_observation(admin):
    process={'executable':'/bin/test','sha256':'b'*64,'uid':'0','connections':[]}
    with Session() as s:
        h=create_host(s);now=time.time()
        worker.record_behavior(s,h,process,now)
        worker.record_behavior(s,h,process,now-300)
        s.commit()
        row=s.scalar(select(Behavior))
        assert row.first_seen==now-300 and row.last_seen==now
