import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace
import uuid
import pytest
from app import releases,worker,ssh
from app.db import Session,Host,Job,Setting
from app.security import unseal
from target import release


def inventory(kind='debian',version='12',suite='bookworm'):
    return {'os':f'ID={kind}\nVERSION_ID="{version}"\n','architecture':'amd64','foreign_architectures':[],
            'machine_id':'a'*32,'status':'Package: nginx\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\nConffiles:\n /etc/nginx/nginx.conf '+hashlib.md5(b'old\n').hexdigest()+'\n\n',
            'keys':{},'files':{'/etc/apt/sources.list':f'deb https://deb.debian.org/debian {suite} main\n'}}

def ready_plan():
    inv=inventory()
    return {'format':1,'target':release.transition(inv),'runner_sha256':release.digest(Path(release.__file__).read_bytes()),
            'expires':time.time()+10000,'inventory_hash':release.fingerprint(inv),'blockers':[],
            'execution_files':{},'configs':[],'edits':[],'sources':{},'transaction':[],'custom_validation':False}

def saved(s,state='ready'):
    h=Host(id='release-host',name='Release fixture',address='192.0.2.10',fingerprint='fixture',baseline={'/usr/local/lib/mrpatchy/release.py':release.digest(Path(release.__file__).read_bytes())})
    row=releases.ReleasePlan(id=str(uuid.uuid4()),host_id=h.id,state=state)
    releases.store(row,ready_plan());s.add_all([h,row]);s.commit();return h,row

@pytest.mark.parametrize(('kind','version','expected'),[('debian','11','12'),('debian','12','13'),('ubuntu','22.04','24.04'),('ubuntu','24.04','26.04')])
def test_adjacent_stable_transitions(kind,version,expected):
    assert release.transition(inventory(kind,version))['version']==expected

@pytest.mark.parametrize('marker',['ID=raspbian','Package: raspberrypi-sys-mods\n','https://archive.raspberrypi.com/debian'])
def test_pi_derivatives_are_not_misidentified_as_debian(marker):
    inv=inventory()
    if marker.startswith('ID'):inv['os']=marker+'\nVERSION_ID=12'
    elif marker.startswith('Package'):inv['status']+=marker
    else:inv['files']['/etc/apt/sources.list']+='deb '+marker+' bookworm main\n'
    with pytest.raises(ValueError,match='new-image migration'):release.transition(inv)


def test_sources_transform_suites_disable_third_party_and_reject_pins():
    inv=inventory();inv['files']['/etc/apt/sources.list']+='deb https://vendor.example/repo bookworm main\n'
    inv['files']['/etc/apt/sources.list.d/security.sources']='Types: deb\nURIs: https://security.debian.org/debian-security\nSuites: bookworm-security\nComponents: main\n'
    files,disabled=releases.sources_for(inv,release.transition(inv))
    assert ' trixie main' in files['/etc/apt/sources.list']
    assert '# Mr Patchy release upgrade: deb https://vendor.example' in files['/etc/apt/sources.list']
    assert 'Suites: trixie-security' in files['/etc/apt/sources.list.d/security.sources']
    assert disabled==['https://vendor.example/repo']
    inv['files']['/etc/apt/preferences']='Package: *\nPin-Priority: 1001\n'
    with pytest.raises(ValueError,match='pinning'):releases.sources_for(inv,release.transition(inv))


def test_transaction_parser_normalizes_native_architecture():
    assert release.parse_transaction('Inst libfoo:arm64 [1] (2 Debian:13 [arm64])\nRemv obsolete [1]\n')==[
        {'action':'install','package':'libfoo','version':'2'},{'action':'remove','package':'obsolete','version':''}]


def test_plan_go_is_digest_bound_expiring_idempotent_and_admin_only(admin):
    with Session() as s:h,row=saved(s);url=f'/api/hosts/{h.id}/releases/{row.id}/decision';sha=row.digest;rid=row.id
    assert admin.post(url,json={'decision':'go','digest':'0'*64}).status_code==409
    result=admin.post(url,json={'decision':'go','digest':sha});assert result.status_code==200
    assert admin.post(url,json={'decision':'go','digest':sha}).json()==result.json()
    with Session() as s:
        row=s.get(releases.ReleasePlan,rid);assert row.state=='approved'
        assert s.get(Job,row.job_id).payload=={'plan_id':rid,'digest':sha,'_actor':'admin','_host_revision':h.lifecycle_revision}
        assert 'target' not in row.encrypted and json.loads(unseal(row.encrypted))['target']['version']=='13'
    # Role restrictions apply to both read-only plan contents and GO.
    from tests.test_operations import login_as
    login_as(admin,'release-reader','viewer')
    assert admin.get(f'/api/hosts/release-host/releases/{rid}').status_code==403
    assert admin.post(url,json={'decision':'go','digest':sha}).status_code==403

@pytest.mark.parametrize('reason',['expired','blocked','declined'])
def test_non_ready_plans_cannot_run(admin,reason):
    with Session() as s:
        h,row=saved(s,reason if reason!='expired' else 'ready')
        if reason=='expired':p=releases.body(row);p['expires']=0;releases.store(row,p);s.commit()
        rid=row.id;sha=row.digest
    assert admin.post(f'/api/hosts/release-host/releases/{rid}/decision',json={'decision':'go','digest':sha}).status_code==409


def test_no_go_never_creates_upgrade_job(admin):
    with Session() as s:h,row=saved(s);rid=row.id;sha=row.digest
    result=admin.post(f'/api/hosts/release-host/releases/{rid}/decision',json={'decision':'no-go','digest':sha})
    assert result.json()['state']=='declined'
    with Session() as s:assert not list(s.query(Job).all())


def test_start_checks_drift_before_detached_submission_and_never_replays(tmp_path,monkeypatch):
    monkeypatch.setattr(release,'execution_files',lambda:{})
    monkeypatch.setattr(release,'ROOT',tmp_path);calls=[]
    def atomic(path,data,*a):Path(path).write_bytes(data)
    monkeypatch.setattr(release,'bridge',lambda:SimpleNamespace(atomic=atomic,boot_id=lambda:'old',run=lambda cmd,**kw:calls.append(cmd)))
    monkeypatch.setattr(release,'check_drift',lambda plan:None)
    plan=ready_plan();req={'job_id':str(uuid.uuid4()),'plan':plan,'digest':release.digest(release.canonical(plan))}
    assert release.start(req)['state']=='accepted';assert release.start(req)['state']=='accepted'
    assert len(calls)==1 and calls[0][0]=='systemd-run'
    req['digest']='0'*64
    with pytest.raises(ValueError,match='digest mismatch'):release.start(req)


def test_target_rejects_stale_config_and_inventory(monkeypatch,tmp_path):
    inv=inventory();plan=ready_plan()
    monkeypatch.setattr(release,'bridge',lambda:SimpleNamespace(handle=lambda req:inv))
    release.check_drift(plan)
    inv['status']+='Package: newly-installed\n'
    with pytest.raises(ValueError,match='inventory'):release.check_drift(plan)


def test_rollback_intent_is_saved_before_hook_and_cannot_repeat(tmp_path,monkeypatch):
    monkeypatch.setattr(release,'ROOT',tmp_path);identifier=str(uuid.uuid4());folder=release.directory(identifier)
    monkeypatch.setattr(release,'execution_files',lambda:{})
    (folder/'plan.json').write_text(json.dumps(ready_plan()))
    state={'state':'upgrading','snapshot':'42','job':identifier};(folder/'state.json').write_text(json.dumps(state));calls=[]
    def hook(*args):
        calls.append(args);assert release.read_state(identifier)['rollback_attempted']
        raise RuntimeError('ambiguous snapshot response')
    monkeypatch.setattr(release,'bridge',lambda:SimpleNamespace(atomic=lambda p,d:Path(p).write_bytes(d),recovery_hook=hook))
    with pytest.raises(RuntimeError):release.rollback(identifier)
    with pytest.raises(ValueError,match='already attempted'):release.rollback(identifier)
    assert len(calls)==1


def test_central_resumes_reverted_rollback_receipt_without_restarting_upgrade(admin,monkeypatch):
    with Session() as s:
        h,row=saved(s,'running');job=Job(id=str(uuid.uuid4()),host_id=h.id,action='release-upgrade',state='running',payload={'plan_id':row.id,'digest':row.digest},output=json.dumps({'state':'rollback_reboot_pending','boot_before':'old','digest':row.digest}))
        s.add(job);s.commit();calls=[]
        def call(host,req,**kwargs):
            calls.append(req['action'])
            if req['action']=='recovery-status':return {'boot_id':'restored'}
            if req['action']=='release-restored':return {'state':'rolled_back'}
            raise AssertionError(req)
        monkeypatch.setattr(ssh,'call',call)
        assert releases.execute(s,h,job)['outcome']=='rolled_back'
        assert calls==['recovery-status','release-restored']
        assert job.payload['_release_receipt']['state']=='rolled_back'


def test_missing_previously_accepted_receipt_never_replays(admin,monkeypatch):
    with Session() as s:
        h,row=saved(s,'running');job=Job(id=str(uuid.uuid4()),host_id=h.id,action='release-upgrade',state='running',payload={'plan_id':row.id,'digest':row.digest},output='{"state":"accepted"}')
        s.add(job);s.commit();calls=[]
        monkeypatch.setattr(ssh,'call',lambda h,r,**kw:calls.append(r['action']) or {'state':'absent'})
        with pytest.raises(RuntimeError,match='refusing to replay'):releases.execute(s,h,job)
        assert calls==['release-status']


def test_ai_blocks_secrets_before_api_call(admin,monkeypatch):
    with Session() as s:
        from app.security import seal
        s.add(Setting(key='openai_key',value={'encrypted':seal('fixture')}))
        s.add(Setting(key='config',value={'ai_enabled':True,'ai_model':'configured-model'}));s.commit()
        monkeypatch.setattr(releases.httpx,'post',lambda *a,**k:pytest.fail('secret reached API'))
        with pytest.raises(ValueError,match='Potential secret'):releases.ai_review(s,{},'/etc/test.conf','password=secret','vendor','')


def test_old_bridge_is_upgraded_before_release_runner_deployment(monkeypatch):
    calls=[]
    def call(host,payload,**kwargs):
        calls.append(payload)
        result={key:payload[key] for key in ('bridge_sha256','unit_sha256')};result['deployed']=payload['sha256']
        if len(calls)>1:result.update(release_sha256=payload['release_sha256'],rpm_sha256=payload['rpm_sha256'])
        return result
    monkeypatch.setattr(ssh,'call',call)
    assert ssh.deploy(None)['release_sha256'] and len(calls)==2

@pytest.mark.parametrize('fail',[False,True])
def test_detached_runner_sequences_snapshot_upgrade_configuration_reboot_and_rollback(tmp_path,monkeypatch,fail):
    monkeypatch.setattr(release,'execution_files',lambda:{})
    monkeypatch.setattr(release,'ROOT',tmp_path)
    monkeypatch.setattr(release,'SERVICE_POLICY_PATH',tmp_path/'policy-rc.d')
    osfile=tmp_path/'os-release';osfile.write_text('ID=debian\nVERSION_ID="13"\n');monkeypatch.setattr(release,'OS_RELEASE',osfile)
    identifier=str(uuid.uuid4());folder=release.directory(identifier);plan=ready_plan()
    plan['transaction']=[{'action':'install','package':'nginx','version':'2'}]
    (folder/'plan.json').write_text(json.dumps(plan));(folder/'state.json').write_text(json.dumps({'state':'accepted','job':identifier,'digest':release.digest(release.canonical(plan))}))
    calls=[];phases=[]
    status=tmp_path/'status';status.write_text(inventory()['status']);monkeypatch.setattr(release,'STATUS_PATH',status)
    extended=tmp_path/'extended_states';extended.write_text('Package: nginx\nAuto-Installed: 1\n\n');monkeypatch.setattr(release,'EXTENDED_STATES_PATH',extended)
    def atomic(path,data,*args):
        Path(path).write_bytes(data)
        if Path(path).name=='state.json':phases.append(json.loads(data)['state'])
    def hook(action,value):
        if action=='rollback':assert not (tmp_path/'policy-rc.d').exists()
        calls.append(action)
        return {'snapshot':'42'} if action=='snapshot' else {'reboot_required':True}
    def run(cmd,**kw):
        if cmd[0]=='systemd-run':assert not (tmp_path/'policy-rc.d').exists()
        calls.append(cmd);return ''
    def bounded(*args,**kw):
        return (('Inst nginx [1] (2 Debian:13 [amd64])\n' if 'Version: 1\n' in status.read_text() else ''),'')
    stub=SimpleNamespace(atomic=atomic,run=run,bounded=bounded,boot_id=lambda:'old',recovery_hook=hook)
    monkeypatch.setattr(release,'bridge',lambda:stub)
    monkeypatch.setattr(release,'inspection',lambda:{'blockers':[]})
    monkeypatch.setattr(release,'check_drift',lambda p:None)
    def command(cmd,*args):
        assert (tmp_path/'policy-rc.d').read_bytes()==release.SERVICE_POLICY
        calls.append(cmd)
        if fail:raise RuntimeError('simulated package failure')
        if 'install' in cmd:status.write_text(inventory()['status'].replace('Version: 1','Version: 2'))
    monkeypatch.setattr(release,'command',command)
    release.run_upgrade(identifier)
    state=release.read_state(identifier)
    assert state['state']==('rollback_reboot_pending' if fail else 'reboot_pending')
    assert phases[:2]==['snapshotting','upgrading']
    assert not (tmp_path/'policy-rc.d').exists()
    assert calls[0]=='snapshot'
    if fail:assert calls.count('rollback')==1
    else:assert any(isinstance(c,list) and 'nginx=2' in c for c in calls)
    with pytest.raises(RuntimeError,match='replay'):release.run_upgrade(identifier)


def test_package_defaults_are_read_from_deb_without_extracting_paths(tmp_path,monkeypatch):
    import shutil,subprocess
    if not shutil.which('dpkg-deb'):pytest.skip('dpkg-deb required')
    package=tmp_path/'pkg';(package/'DEBIAN').mkdir(parents=True);(package/'etc/nginx').mkdir(parents=True)
    (package/'DEBIAN/control').write_text('Package: nginx\nVersion: 2\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: fixture\n')
    (package/'etc/nginx/nginx.conf').write_text('vendor defaults\n')
    deb=tmp_path/'fixture.deb';subprocess.run(['dpkg-deb','--build',str(package),str(deb)],check=True,capture_output=True)
    from app import process
    original=process.bounded
    def download(args,**kwargs):
        if args[0]=='apt-get':shutil.copy2(deb,Path(kwargs['cwd'])/'fixture.deb');return ('','')
        return original(args,**kwargs)
    monkeypatch.setattr(process,'bounded',download)
    monkeypatch.setattr(releases.apt,'run',lambda *a:'Package: nginx\nVersion: 2\nSize: '+str(deb.stat().st_size)+'\n')
    root=tmp_path/'apt';root.mkdir()
    result=releases.vendor_files(root,root/'apt.conf','nginx','2',['/etc/nginx/nginx.conf'])
    assert result['/etc/nginx/nginx.conf']=='vendor defaults\n'
    assert not list((root/'review-download').glob('*.deb'))


def test_planner_freezes_ai_diff_and_configuration_hashes(admin,monkeypatch,tmp_path):
    inv=inventory();content='old\n';sha=release.digest(content.encode());target=release.transition(inv)
    inspect={'inventory':inv,'fingerprint':release.fingerprint(inv),'target':target,'blockers':[],
             'custom_validator':True,'execution_files':{},'services':['nginx.service'],'runner_sha256':release.digest(Path(release.__file__).read_bytes())}
    with Session() as s:
        h,row=saved(s,'planning')
        monkeypatch.setattr(releases.apt,'DATA',tmp_path)
        monkeypatch.setattr(releases,'simulate',lambda *a:(tmp_path,tmp_path/'apt.conf',{'/etc/apt/sources.list':'deb https://deb.debian.org/debian trixie main\n'},[],[{'action':'install','package':'nginx','version':'2'}]))
        monkeypatch.setattr(releases,'vendor_files',lambda *a:{'/etc/nginx/nginx.conf':'vendor\n'})
        monkeypatch.setattr(releases,'ai_review',lambda *a,**kw:{'content':'merged\n','reason':'Preserve local intent with new syntax','blockers':[]})
        def call(host,req,**kw):
            if req['action']=='release-inspect':return inspect
            assert req['action']=='release-configs'
            return {'configs':{'/etc/nginx/nginx.conf':{'package':'nginx','content':content,'sha256':sha,'uid':0,'gid':0,'mode':0o644}}}
        monkeypatch.setattr(ssh,'call',call)
        assert releases.build(s,h,row.id)['state']=='ready'
        plan=releases.body(row)
        assert plan['edits'][0]['after']=='merged\n'
        assert '-old\n+merged\n' in plan['edits'][0]['diff']
        assert plan['configs'][0]['sha256']==sha
        assert plan['services']==['nginx.service']
        assert plan['custom_validation'] is True
        assert row.digest==release.digest(release.canonical(plan))


def test_service_recovery_ignores_transient_login_sessions():
    output='nginx.service loaded active running Web server\nuser@1000.service loaded active running User manager\nssh@old-connection.service loaded active running SSH session\nssh.service loaded active running SSH daemon\nmrpatchy-release-job.service loaded active running Release runner\n'
    assert release.service_inventory(output)==['nginx.service','ssh.service']

@pytest.mark.parametrize('secret',['db_password = secret','client_secret: secret','api_key="secret"','DATABASE_URL=https://user:secret@example.test/db','"access_token": "secret"'])
def test_ai_blocks_compound_credentials_and_url_passwords(admin,monkeypatch,secret):
    from app.security import seal
    with Session() as s:
        s.add(Setting(key='openai_key',value={'encrypted':seal('fixture')}))
        s.add(Setting(key='config',value={'ai_enabled':True,'ai_model':'configured-model'}));s.commit()
        monkeypatch.setattr(releases.httpx,'post',lambda *a,**k:pytest.fail('secret reached API'))
        with pytest.raises(ValueError,match='Potential secret'):releases.ai_review(s,{},'/etc/test.conf',secret,'vendor','')


def release_job(s):
    h,row=saved(s,'running')
    job=Job(id=str(uuid.uuid4()),host_id=h.id,action='release-upgrade',state='running',payload={'plan_id':row.id,'digest':row.digest})
    s.add(job);s.commit();return h,row,job


def test_release_retries_disconnect_and_ambiguous_start_without_replaying(admin,monkeypatch):
    with Session() as s:
        h,row,job=release_job(s);calls=[];statuses=iter([OSError('rebooting'),{'state':'absent'},{'state':'complete','digest':row.digest,'job':job.id}])
        def call(host,req,**kw):
            calls.append(req['action'])
            if req['action']=='release-start':raise OSError('reply lost after acceptance')
            assert req['action']=='release-status'
            result=next(statuses)
            if isinstance(result,Exception):raise result
            return result
        monkeypatch.setattr(ssh,'call',call);monkeypatch.setattr(releases.time,'sleep',lambda n:None)
        assert releases.execute(s,h,job)['outcome']=='complete'
        assert calls.count('release-start')==1
        assert job.payload['_release_submitted'] is True
        assert job.payload['_release_receipt']['state']=='complete'


def test_lost_submission_without_receipt_is_never_replayed(admin,monkeypatch):
    with Session() as s:
        h,row,job=release_job(s);job.payload={**job.payload,'_release_submitted':True};s.commit()
        calls=[];monkeypatch.setattr(ssh,'call',lambda h,r,**kw:calls.append(r['action']) or {'state':'absent'})
        with pytest.raises(RuntimeError,match='refusing to replay'):releases.execute(s,h,job)
        assert calls==['release-status']


@pytest.mark.parametrize('receipt',[{'state':'complete'},{'state':'complete','digest':'0'*64},{'state':'nonsense'}])
def test_release_does_not_accept_unbound_or_unknown_receipts(admin,monkeypatch,receipt):
    with Session() as s:
        h,row,job=release_job(s)
        monkeypatch.setattr(ssh,'call',lambda *a,**kw:receipt)
        with pytest.raises(ValueError,match='receipt mismatch'):releases.execute(s,h,job)
        assert row.state!='complete'


def test_restart_keeps_expired_recovery_deadline_and_rejects_wrong_restored_system(admin,monkeypatch):
    with Session() as s:
        h,row,job=release_job(s)
        job.output='display log is deliberately not JSON'
        job.payload={**job.payload,'_release_receipt':{'state':'rollback_reboot_pending','digest':row.digest,'boot_before':'old'},
                     '_release_health':{'key':'rollback_reboot_pending:old','deadline':time.time()-1}}
        s.commit();calls=[]
        def call(h,req,**kw):
            calls.append(req['action'])
            if req['action']=='recovery-status':return {'boot_id':'new'}
            assert req['action']=='release-restored'
            raise ValueError('Target still has upgraded packages')
        monkeypatch.setattr(ssh,'call',call)
        with pytest.raises(RuntimeError,match='original-system verification failed'):releases.execute(s,h,job)
        assert calls==['recovery-status','release-restored']
        assert job.payload['_release_health']['deadline']<time.time()


def test_rollback_intent_survives_lost_response(admin,monkeypatch):
    with Session() as s:
        h,row,job=release_job(s);calls=[]
        job.payload={**job.payload,'_release_health':{'key':'reboot_pending:old','deadline':time.time()-1}};s.commit()
        def call(h,req,**kw):
            action=req['action'];calls.append(action)
            if action=='release-status':return {'state':'reboot_pending','digest':row.digest,'boot_before':'old'}
            if action=='release-verify':raise ValueError('service unhealthy')
            if action=='recovery-status':return {'boot_id':'restored' if 'release-rollback' in calls else 'upgraded'}
            if action=='release-rollback':
                assert job.payload['_release_receipt']['state']=='rollback_reboot_pending'
                raise OSError('connection closed by reboot')
            assert action=='release-restored';return {'state':'rolled_back'}
        monkeypatch.setattr(ssh,'call',call)
        assert releases.execute(s,h,job)['outcome']=='rolled_back'
        assert calls.count('release-rollback')==1 and calls.count('release-status')==1


def test_restored_checks_original_inventory_and_services_without_journal(monkeypatch):
    inv=inventory();plan=ready_plan();plan['expires']=0;plan['services']=['nginx.service']
    monkeypatch.setattr(release,'execution_files',lambda:{})
    monkeypatch.setattr(release,'bridge',lambda:SimpleNamespace(
        handle=lambda req:inv if req['action']=='inventory' else {'collector_active':True,'failed_units':''},
        run=lambda cmd,**kw:'active' if cmd[0]=='systemctl' else '',boot_id=lambda:'restored'))
    assert release.restored(plan)['state']=='rolled_back'
    inv['os']='ID=debian\nVERSION_ID=13\n'
    with pytest.raises(ValueError,match='inventory'):release.restored(plan)


def test_service_guard_refuses_foreign_replacement(tmp_path,monkeypatch):
    policy=tmp_path/'policy';policy.write_bytes(b'#!/bin/sh\nexit 0\n');monkeypatch.setattr(release,'SERVICE_POLICY_PATH',policy)
    with pytest.raises(ValueError,match='guard changed'):release.remove_service_guard()
    assert policy.read_bytes()==b'#!/bin/sh\nexit 0\n'
    policy.write_bytes(release.SERVICE_POLICY);release.remove_service_guard();assert not policy.exists()


def test_reboot_timer_names_are_distinct(tmp_path,monkeypatch):
    calls=[]
    monkeypatch.setattr(release,'bridge',lambda:SimpleNamespace(atomic=lambda p,d:Path(p).write_bytes(d),boot_id=lambda:'old',run=lambda cmd,**kw:calls.append(cmd)))
    state={'job':str(uuid.uuid4())}
    release.schedule(tmp_path,state);release.schedule(tmp_path,state,True)
    assert calls[0][1]!=calls[1][1]


def test_changed_recovery_hook_invalidates_approval(monkeypatch):
    plan=ready_plan();monkeypatch.setattr(release,'execution_files',lambda:{'rollback':{'sha256':'new'}})
    with pytest.raises(ValueError,match='hook changed'):release.validate_plan(plan)


def test_debian_stages_preserve_dependency_flags_and_exact_versions(tmp_path,monkeypatch):
    status=tmp_path/'status';extended=tmp_path/'extended';status.write_text('Package: app\nStatus: install ok installed\nVersion: 1\n\nPackage: libold\nStatus: install ok installed\nVersion: 1\n\n')
    extended.write_text('Package: libold\nAuto-Installed: 1\n\n')
    monkeypatch.setattr(release,'STATUS_PATH',status);monkeypatch.setattr(release,'EXTENDED_STATES_PATH',extended)
    transaction=[{'action':'install','package':'app','version':'2'},{'action':'install','package':'libnew','version':'1'}]
    answers=iter(['Inst app [1] (2 Debian [amd64])\n','Inst app [1] (2 Debian [amd64])\n','Inst libnew (1 Debian [amd64])\n']);calls=[]
    monkeypatch.setattr(release,'bridge',lambda:SimpleNamespace(bounded=lambda *a,**kw:(next(answers),'')))
    def command(cmd,*args):
        calls.append(cmd)
        if '--no-remove' in cmd:status.write_text(status.read_text().replace('Version: 1','Version: 2',1))
        elif cmd[0]=='apt-get':status.write_text(status.read_text()+'Package: libnew\nStatus: install ok installed\nVersion: 1\n\n')
    monkeypatch.setattr(release,'command',command)
    release.debian_transaction(transaction,tmp_path)
    assert '--no-remove' in calls[0] and 'app=2' in calls[0]
    assert calls[-1]==['apt-mark','auto','--','libnew','libold']
    assert 'app' not in calls[-1]


def test_debian_minimal_stage_cannot_exceed_approval(tmp_path,monkeypatch):
    status=tmp_path/'status';status.write_text('');monkeypatch.setattr(release,'STATUS_PATH',status)
    monkeypatch.setattr(release,'EXTENDED_STATES_PATH',tmp_path/'absent')
    monkeypatch.setattr(release,'bridge',lambda:SimpleNamespace(bounded=lambda *a,**kw:('Inst unexpected (1 Debian [amd64])\n','')))
    monkeypatch.setattr(release,'command',lambda *a:pytest.fail('unapproved transaction executed'))
    with pytest.raises(ValueError,match='exceeds'):release.debian_transaction([],tmp_path)


def test_mysql_failed_lock_acquisition_closes_connection_and_releases_local_lock(monkeypatch):
    from app import coordination
    closed=[]
    def fail(*a,**kw):raise RuntimeError('database disconnected')
    connection=SimpleNamespace(execute=fail,close=lambda:closed.append(True))
    monkeypatch.setattr(coordination,'lock_engine',SimpleNamespace(url=SimpleNamespace(database='test'),dialect=SimpleNamespace(name='mysql'),connect=lambda:connection))
    lock=coordination.Lock('test')
    with pytest.raises(RuntimeError,match='disconnected'):lock.acquire()
    assert closed==[True] and lock.resource is None
    assert lock.local.acquire(False);lock.local.release()


def test_recovery_quarantine_creates_alert_and_reconciliation_resolves_it(admin):
    from app.operations import collect_alerts,Alert
    with Session() as s:
        h,row,job=release_job(s);job.state='recovery_required';s.commit();jid=job.id
    collect_alerts()
    with Session() as s:
        alert=s.query(Alert).filter_by(kind='recovery').one();assert alert.state=='open' and jid in alert.message
        s.get(Job,jid).state='interrupted';s.commit()
    collect_alerts()
    with Session() as s:assert s.query(Alert).filter_by(kind='recovery').one().state=='resolved'


@pytest.mark.parametrize('rebooted',[False,True])
def test_post_upgrade_rollback_handles_disappeared_normal_timer(tmp_path,monkeypatch,rebooted):
    monkeypatch.setattr(release,'ROOT',tmp_path);monkeypatch.setattr(release,'execution_files',lambda:{})
    identifier=str(uuid.uuid4());folder=release.directory(identifier);calls=[]
    (folder/'plan.json').write_text(json.dumps(ready_plan()))
    (folder/'state.json').write_text(json.dumps({'state':'reboot_pending','job':identifier,'boot_before':'old','snapshot':'42'}))
    def run(cmd,**kw):
        calls.append(cmd)
        if cmd[:2]==['systemctl','stop']:pytest.fail('cannot stop a nonexistent timer')
        return ''
    monkeypatch.setattr(release,'bridge',lambda:SimpleNamespace(atomic=lambda p,d:Path(p).write_bytes(d),run=run,
        boot_id=lambda:'new' if rebooted else 'old',recovery_hook=lambda *a:{'reboot_required':True}))
    assert release.rollback(identifier)['state']=='rollback_reboot_pending'
    assert any(cmd[0]=='systemd-run' and 'rollback-reboot' in cmd[1] for cmd in calls)
