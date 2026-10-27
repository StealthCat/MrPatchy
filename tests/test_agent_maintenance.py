import time
from types import SimpleNamespace
import pytest
from app import agent_maintenance as maintenance,ssh,worker
from app.db import Session,Host,Setting,Job
from app.identity import User
from target import bridge

@pytest.fixture
def enrolled(monkeypatch):
    monkeypatch.setattr(ssh,'public_key',lambda _: 'ssh-ed25519 fixture')
    host=SimpleNamespace(id='agent-host',name='agent',baseline={})
    host.baseline=ssh.expected_files(host)
    return host

def receipt(host):
    return {'version':1,'files':{p:{'sha256':v,'uid':0,'gid':0,'mode':0o440 if 'sudoers.d' in p else 0o644} for p,v in host.baseline.items()},
            'directories_secure':True,'active':True,'enabled':True,'unit_path':'/etc/systemd/system/mrpatchy-agent.service','dropins':[]}

def test_current_outdated_and_unexpected_content_are_distinct(enrolled):
    host=enrolled;report=receipt(host)
    assert maintenance.assess(host,report)['state']=='current'
    path='/usr/local/lib/mrpatchy/agent.py'
    host.baseline={**host.baseline,path:'a'*64};report=receipt(host)
    status=maintenance.assess(host,report)
    assert status['state']=='outdated' and status['repairable']
    report['files'][path]['sha256']='b'*64
    status=maintenance.assess(host,report)
    assert status['state']=='drifted' and status['repairable']
    assert not maintenance.allowed({'auto_upgrade':True,'auto_repair':False},status)
    assert maintenance.allowed({'auto_upgrade':False,'auto_repair':True},status)

@pytest.mark.parametrize('path',maintenance.TRUST_PATHS)
def test_changed_trust_path_never_automatically_repaired(enrolled,path):
    report=receipt(enrolled);report['files'][path]['sha256']='b'*64
    status=maintenance.assess(enrolled,report)
    assert status['state']=='blocked' and not status['repairable']

@pytest.mark.parametrize('change',[{'directories_secure':False},{'dropins':['/etc/systemd/system/mrpatchy-agent.service.d/other.conf']},{'unit_path':'/tmp/fake.service'}])
def test_untrusted_configuration_blocks_repair(enrolled,change):
    assert maintenance.assess(enrolled,receipt(enrolled)|change)['state']=='blocked'

def test_disabled_service_is_repairable(enrolled):
    report=receipt(enrolled)|{'active':False,'enabled':False}
    assert maintenance.assess(enrolled,report)['state']=='drifted'

def test_check_queue_cooldown_policy_and_post_verification(admin,enrolled,monkeypatch):
    with Session() as s:
        host=Host(id=enrolled.id,name='agent',address='192.0.2.1',fingerprint='pinned',baseline=enrolled.baseline,state='online')
        s.add(host);s.add(Setting(key='agent-policy:'+host.id,value={'auto_upgrade':True,'auto_repair':True}));s.commit()
        broken=receipt(host)|{'active':False};healthy=receipt(host)
        monkeypatch.setattr(ssh,'call',lambda *a,**k:broken)
        maintenance.inspect(s,host)
        jobs=list(s.query(Job));assert len(jobs)==1 and jobs[0].action=='agent-update'
        maintenance.inspect(s,host);assert s.query(Job).count()==1
        job=jobs[0];job.state='running';s.commit()
        monkeypatch.setattr(ssh,'deploy',lambda h: {'deployed':True})
        with pytest.raises(ValueError,match='could not be verified'):maintenance.update(s,host,job)
        assert host.baseline==enrolled.baseline
        monkeypatch.setattr(ssh,'call',lambda *a,**k:healthy)
        assert maintenance.update(s,host,job)['changed'] is False
        job.state='failed';s.commit()
        maintenance.maybe_queue(s,host,maintenance.assess(host,broken));assert s.query(Job).count()==1
        job.created=time.time()-3601;s.commit()
        maintenance.maybe_queue(s,host,maintenance.assess(host,broken));assert s.query(Job).count()==2


def test_policy_disable_and_release_change_rechecked_before_mutation(admin,enrolled,monkeypatch):
    with Session() as s:
        host=Host(id=enrolled.id,name='agent',address='x',fingerprint='pinned',baseline=enrolled.baseline)
        s.add(host);s.commit()
        monkeypatch.setattr(ssh,'call',lambda *a,**k:receipt(host)|{'active':False})
        monkeypatch.setattr(ssh,'deploy',lambda h:pytest.fail('No mutation allowed'))
        job=SimpleNamespace(payload={'automatic':True,'release':maintenance.release_id(host)})
        with pytest.raises(ValueError,match='disabled'):maintenance.update(s,host,job)
        job.payload['release']='old'
        with pytest.raises(ValueError,match='release changed'):maintenance.update(s,host,job)


def test_policy_api_roles_stale_edits_and_job_queue(admin,enrolled):
    with Session() as s:s.add(Host(id=enrolled.id,name='agent',address='x',fingerprint='pinned',baseline=enrolled.baseline));s.commit()
    path='/api/hosts/'+enrolled.id+'/security/agent'
    state=admin.get(path).json();assert state['status']['state']=='unknown'
    data={'auto_upgrade':True,'auto_repair':True,'expected':state['policy']}
    assert admin.put(path,json=data).status_code==200
    assert admin.put(path,json=data).status_code==409
    assert admin.post(path+'/check',json={}).status_code==200
    assert admin.post(path+'/check',json={}).status_code==409
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(path).status_code==403
        assert admin.post(path+'/update',json={}).status_code==403


def test_file_status_rejects_symlinks_and_permissions(tmp_path):
    # /tmp is intentionally writable; the target must refuse this parent chain.
    target=tmp_path/'agent.py';target.write_text('fixture')
    assert bridge.agent_file_status(str(target))=={'unsafe':True}
    alias=tmp_path/'alias';alias.symlink_to(target)
    assert bridge.agent_file_status(str(alias))=={'unsafe':True}


def test_upgrade_commits_only_verified_new_baseline(admin,enrolled,monkeypatch):
    path='/usr/local/lib/mrpatchy/agent.py'
    old={**enrolled.baseline,path:'a'*64}
    with Session() as s:
        host=Host(id=enrolled.id,name='agent',address='x',fingerprint='pinned',baseline=old)
        s.add(host);s.commit()
        before=receipt(host);after=receipt(enrolled)
        responses=iter([before,after])
        monkeypatch.setattr(ssh,'call',lambda *a,**k:next(responses))
        monkeypatch.setattr(ssh,'deploy',lambda h:{'deployed':True})
        job=SimpleNamespace(payload={'release':maintenance.release_id(host),'automatic':False})
        assert maintenance.update(s,host,job)['changed']
        assert host.baseline==enrolled.baseline


def test_unavailable_check_never_queues_repairs(admin,enrolled,monkeypatch):
    with Session() as s:
        host=Host(id=enrolled.id,name='agent',address='x',fingerprint='pinned',baseline=enrolled.baseline)
        s.add(host);s.add(Setting(key='agent-policy:'+host.id,value={'auto_upgrade':True,'auto_repair':True}));s.commit()
        monkeypatch.setattr(ssh,'call',lambda *a,**k:(_ for _ in ()).throw(RuntimeError('secret output')))
        status=maintenance.inspect(s,host)
        assert status['state']=='unavailable' and 'secret output' not in str(status)
        assert s.query(Job).count()==0


def test_dormant_unenrolled_override_blocks_maintenance(enrolled):
    report=receipt(enrolled)
    report['files'][maintenance.OPTIONAL]={'sha256':'c'*64,'uid':0,'gid':0,'mode':0o644}
    assert maintenance.assess(enrolled,report)['state']=='blocked'


def test_poll_checks_before_importing_changed_collector(admin,enrolled,monkeypatch):
    with Session() as s:
        s.add(Host(id=enrolled.id,name='agent',address='x',fingerprint='pinned',baseline=enrolled.baseline,state='online'))
        s.add(Setting(key='agent-policy:'+enrolled.id,value={'auto_upgrade':False,'auto_repair':True}));s.commit()
    report=receipt(enrolled);report['files']['/usr/local/lib/mrpatchy/agent.py']['sha256']='b'*64
    calls=[]
    def call(host,payload,**kwargs):
        calls.append(payload['action'])
        assert payload['action']=='agent-status'
        return report
    monkeypatch.setattr(ssh,'call',call)
    worker.poll_host(enrolled.id)
    assert calls==['agent-status']
    with Session() as s:
        assert s.query(Job).one().action=='agent-update'
        assert s.get(Host,enrolled.id).state=='attention'
    # Even polling beside an active operation must honor the failed assessment.
    with worker.host_lock(enrolled.id):worker.poll_host(enrolled.id)
    assert calls==['agent-status']
    operations=maintenance.operations
    operations.collect_alerts()
    with Session() as s:assert s.query(operations.Alert).filter_by(kind='agent health').one().state=='open'


def test_known_drift_blocks_remote_jobs(admin,enrolled,monkeypatch):
    with Session() as s:
        s.add(Host(id=enrolled.id,name='agent',address='x',fingerprint='pinned',baseline=enrolled.baseline))
        s.add(Setting(key='agent-status:'+enrolled.id,value={'state':'drifted'}));s.commit()
        job=worker.enqueue(s,enrolled.id,'repair')
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('Known drift must block remote execution'))
    worker.execute(job)
    with Session() as s:assert s.get(Job,job).state=='failed'


@pytest.mark.parametrize('invalid',[False,True])
def test_manual_deploy_independently_verifies_and_clears_stale_health(admin,enrolled,monkeypatch,invalid):
    with Session() as s:
        s.add(Host(id=enrolled.id,name='agent',address='x',fingerprint='pinned',baseline=enrolled.baseline))
        s.add(Setting(key='agent-status:'+enrolled.id,value={'state':'blocked'}));s.commit()
        job_id=worker.enqueue(s,enrolled.id,'deploy')
    calls=[]
    monkeypatch.setattr(ssh,'deploy',lambda h:{'deployed':True})
    monkeypatch.setattr(worker,'save_inventory',lambda *a:None)
    def call(host,payload,**kwargs):
        calls.append(payload['action'])
        if payload['action']=='agent-status':return receipt(enrolled)|({'dropins':['/tmp/untrusted.conf']} if invalid else {})
        assert payload['action']=='inventory'
        return {}
    monkeypatch.setattr(ssh,'call',call)
    worker.execute(job_id)
    with Session() as s:
        assert s.get(Job,job_id).state==('failed' if invalid else 'complete')
        assert s.get(Setting,'agent-status:'+enrolled.id).value['state']==('blocked' if invalid else 'current')
    assert calls==(['agent-status'] if invalid else ['agent-status','inventory'])
