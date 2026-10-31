import copy
import json
import time
import httpx
import pytest
from sqlalchemy import select,delete
from app import ai,ai_assessments,ai_provider_backoff,ai_retry,ai_runs,worker
from app.db import Session,Host,Behavior,Setting,Audit
from app.identity import User
from app.incidents import Inspection
from app.security import seal


def seed(verdict='low',approved=False):
    with Session() as s:
        for id in ('one','two'):s.add(Host(id=id,name=id,address='192.0.2.1',fingerprint=''))
        s.add(Behavior(id='subject',host_id='one',verdict=verdict,approved=approved,analysis='Original retained result',evidence={'executable':'/srv/fixture','sha256':'a'*64,'uid':'1000','identity_verified':True}))
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}));s.commit()


def current(admin,id='subject'):
    response=admin.get('/api/investigations/'+id+'/history');assert response.status_code==200
    return response.json()


def queue(admin,**values):
    return admin.post('/api/investigations/subject/retriage',json={'expected_revision':current(admin)['current']['revision'],'reason':'Review changed threat context',**values})


def provider(risk='high',checks=None):
    result={'risk':risk,'explanation':'Fresh assessment <untrusted>','recommended_checks':'Review collected evidence','requested_checks':checks or []}
    return httpx.Response(200,json={'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(result)}]}]},request=httpx.Request('POST',ai.URL))


def test_refresh_preserves_legacy_with_no_invented_model_and_keeps_prior_approval_explicit(admin,monkeypatch):
    seed(approved=True);calls=[]
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(k) or provider())
    assert queue(admin).status_code==409
    assert current(admin)['items']==[]
    result=queue(admin,withdraw_approval=True);assert result.status_code==200 and calls==[]
    data=current(admin);assert data['current']['verdict']=='pending' and not data['current']['approved']
    assert data['current']['refresh']['bypass_cache'] and data['current']['refresh']['withdrew_approval']
    legacy=admin.get('/api/investigations/subject/history/'+data['items'][0]['id']).json()
    assert legacy['source']=='legacy' and legacy['model']==legacy['run_id']==legacy['policy_hash']==''
    assert legacy['inputs']==[] and legacy['result']['saved_analysis']=='Original retained result'
    assert not legacy['known_good']['eligible'] and not legacy['known_good']['published']
    assert 'source_not_ai' in [reason['code'] for reason in legacy['known_good']['reasons']]
    assert queue(admin,withdraw_approval=True).status_code==409
    worker.investigate_one();assert len(calls)==1
    data=current(admin);assert data['current']['verdict']=='high' and not data['current']['approved']
    assert data['current']['refresh']=={} and len(data['items'])==2
    record=admin.get('/api/investigations/subject/history/'+data['items'][0]['id']).json()
    assert record['source']=='ai' and record['model']=='fixture-model' and record['run_id']
    assert record['refresh']['id']==result.json()['request_id'] and record['refresh']['previous']==legacy['id']
    assert record['refresh']['actor']=='admin' and len(record['policy_hash'])==64
    assert record['inputs'][0]['evidence']==json.loads(calls[0]['json']['input'])
    assert record['inputs'][0]['policy']['schema']==calls[0]['json']['text']['format']['schema']
    with Session() as s:assert s.scalar(select(Audit).where(Audit.action=='withdraw behavior approval for re-triage'))


@pytest.mark.parametrize('followup',[False,True])
def test_retained_complete_results_bound_to_exact_supplied_inputs_and_log_pruning(admin,monkeypatch,followup):
    seed(verdict='pending');sent=[]
    with Session() as s:
        row=s.get(Behavior,'subject');row.evidence={**row.evidence,'connections':[{'remote':'192.0.2.'+str(n)} for n in range(101)]};s.commit()
    def post(*a,**k):
        sent.append(k['json']);return provider('low',['executable'] if followup and len(sent)==1 else [])
    monkeypatch.setattr(ai.transport,'post',post)
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:{'identity_verified':True,'sha256':'a'*64,'service':'fixture context'})
    worker.investigate_one()
    data=current(admin);assert len(data['items'])==1
    id=data['items'][0]['id'];url='/api/investigations/subject/history/'+id
    record=admin.get(url).json();assert len(record['inputs'])==len(sent)==1+followup
    assert not record['known_good']['eligible'] and record['known_good']['fingerprint']==''
    assert 'known_good_context_missing' in [reason['code'] for reason in record['known_good']['reasons']]
    assert [i['evidence'] for i in record['inputs']]==[json.loads(x['input']) for x in sent]
    assert record['inputs'][0]['evidence']['omitted_connections']==1
    assert len(record['snapshot']['connections'])==101 and not data['current']['approved']
    with Session() as s:
        s.execute(delete(ai_runs.AIEvent));s.execute(delete(ai_runs.AICall));s.execute(delete(ai_runs.AIRunHost));s.execute(delete(ai_runs.AIRun))
        row=s.get(Behavior,'subject');row.evidence={'executable':'changed'};row.analysis='Changed later';s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:pytest.fail('History cannot call AI'))
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:pytest.fail('History cannot contact target'))
    assert admin.get(url).json()==record


def test_followup_binds_authenticated_vendor_provenance_without_sharing_host_observation(admin,monkeypatch):
    seed(verdict='pending');sent=[]
    manifest={'package':'fixture','version':'1.0-1','architecture':'amd64',
        'entries':[{'path':'/srv/fixture','sha256':'a'*64,'size':12}]}
    proof={'bundle_id':'fixture','release_sha256':'b'*64,'index_sha256':'c'*64,
        'artifact_sha256':'d'*64,'keyring_sha256':'e'*64,'signers':['A'*40],
        'authenticated_at':123,'scope':'fixture'}
    receipt={'trust_basis':'controller_authenticated_debian_artifact','package':'fixture',
        'version':'1.0-1','architecture':'amd64','scope_files':1,'examined':1,
        'state':'matches_artifact_bytes','gaps':[],'findings':[]}
    report={'version':1,'trust_basis':'controller_authenticated_debian_artifact','state':'collected',
        'packages':[],'persistence':None,'vendor_manifest':manifest,
        'vendor_authentication':proof,'vendor_verification':receipt}
    with Session() as s:s.add(Inspection(id='vendor-provenance',host_id='one',created=123,report=report));s.commit()
    def post(*args,**kwargs):
        sent.append(kwargs['json'])
        return provider('low',['executable'] if len(sent)==1 else [])
    coverage={'cache_eligible':False,'scope':'recorded_process_identity',
        'gaps':['configuration_not_collected','package_authentication_missing'],
        'consistency':'matching_before_after_samples','trust':'target_kernel_and_local_files'}
    context={'version':1,'process':{'pid':10,'start_ticks':20,'pid_namespace':30,
            'boot_id':'11111111-1111-1111-1111-111111111111','proc_device':40,'proc_inode':50},
        'credentials':{'Uid':['0','0','0','0'],'Gid':['0','0','0','0'],'Groups':['0'],
            'CapEff':['0000000000000000'],'NoNewPrivs':['1'],'Seccomp':['2']},
        'namespaces':{'pid':101,'net':102,'mnt':103,'user':104},
        'maps_sha256':'b'*64,'cgroup_sha256':'c'*64,
        'artifacts':[{'kind':'library','path':'/usr/lib/libfixture.so','identity_verified':True,
            'sha256':'d'*64,'source':'mapped-file','metadata':{'uid':0,'gid':0,'mode':493,'size':12}}],
        'executable':{'sha256':'a'*64,'uid':0,'gid':0,'mode':493,'size':12},
        'coverage':copy.deepcopy(coverage)}
    followup={'version':2,'identity_verified':True,'checks':['executable'],'context':context,
        'coverage':copy.deepcopy(coverage),'executable':{**context['executable'],
            'status':['Uid:\t0\t0\t0\t0','Gid:\t0\t0\t0\t0','CapEff:\t0000000000000000',
                'NoNewPrivs:\t1','Seccomp:\t2']}}
    monkeypatch.setattr(ai.transport,'post',post)
    monkeypatch.setattr(worker.ssh,'call',lambda *args,**kwargs:copy.deepcopy(followup))
    worker.investigate_one();assert len(sent)==2
    record=admin.get('/api/investigations/subject/history/'+current(admin)['items'][0]['id']).json()
    contract=record['snapshot']['investigation']['details']['known_good_context']
    assert contract['artifact']['sha256']=='a'*64 and contract['provenance']['verified']
    assert contract['followup']['complete'] and contract['followup']['policy_version']=='process-followup-v2'
    assert contract['observation']['host_id']=='one' and contract['observation']['vendor_inspection_id']=='vendor-provenance'
    assert 'package_authentication_missing' not in record['snapshot']['investigation']['details']['context']['coverage']['gaps']
    assert not record['known_good']['eligible'] and 'configuration_binding_invalid' in [row['code'] for row in record['known_good']['reasons']]
    assert 'known_good_context' in record['inputs'][1]['evidence']['investigation']['details']
    assert 'observation' not in record['inputs'][1]['evidence']['investigation']['details']['known_good_context']
    assert json.loads(sent[1]['input'])==record['inputs'][1]['evidence']


def test_current_saved_result_uses_existing_retained_revision_without_duplicate_legacy(admin,monkeypatch):
    seed(verdict='pending');monkeypatch.setattr(ai.transport,'post',lambda *a,**k:provider('low'))
    worker.investigate_one();before=current(admin)['items'];assert len(before)==1
    assert queue(admin).status_code==200
    assert len(current(admin)['items'])==1
    worker.investigate_one();assert len(current(admin)['items'])==2


def test_failure_and_pause_preserve_request_and_previous_result_until_success(admin,monkeypatch):
    seed();calls=[]
    assert queue(admin).status_code==200
    with Session() as s:s.add(Setting(key='server-ai:one',value={'paused':True}));s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or provider('unknown'))
    worker.investigate_one();assert calls==[]
    with Session() as s:s.get(Setting,'server-ai:one').value={'paused':False};s.commit()
    def timeout(*a,**k):calls.append(1);raise httpx.ReadTimeout('private-key')
    monkeypatch.setattr(ai.transport,'post',timeout);worker.investigate_one()
    data=current(admin);assert data['current']['verdict']=='error' and data['current']['refresh']['id']
    assert len(data['items'])==1 and 'private-key' not in data['current']['analysis']
    assert admin.post('/api/investigations/subject/retry').status_code==409
    with Session() as s:
        s.get(ai_retry.TriageRetry,'subject').provider_until=0
        s.get(ai_provider_backoff.ProviderBackoff,'global').blocked_until=0
        s.commit()
    assert admin.post('/api/investigations/subject/retry').status_code==200
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or provider('unknown'))
    worker.investigate_one();assert len(calls)==2
    assert current(admin)['current']['refresh']=={} and len(current(admin)['items'])==2


def test_stale_revision_and_observation_timestamps_and_duplicate_requests(admin):
    seed();revision=current(admin)['current']['revision']
    with Session() as s:s.get(Behavior,'subject').last_seen=time.time()+10;s.commit()
    assert current(admin)['current']['revision']==revision
    with Session() as s:s.get(Behavior,'subject').analysis='A later result';s.commit()
    assert queue(admin,expected_revision=revision).status_code==409
    assert current(admin)['items']==[]
    assert queue(admin).status_code==200
    assert queue(admin).status_code==409
    assert len(current(admin)['items'])==1


@pytest.mark.parametrize('state',['disabled','deleted','missing'])
def test_inactive_history_is_read_only(admin,state):
    seed()
    with Session() as s:
        h=s.get(Host,'one')
        if state=='disabled':h.enabled=False
        elif state=='deleted':h.deleted_at=time.time()
        else:s.delete(h)
        s.commit()
    assert current(admin)['current']['can_retriage'] is False
    assert queue(admin).status_code==409


@pytest.mark.parametrize('verdict',['pending','error'])
def test_retriage_not_retry_and_wrong_identity_links(admin,verdict):
    seed(verdict=verdict)
    assert queue(admin).status_code==409
    assert admin.get('/api/investigations/subject/history?host_id=two').status_code==404
    assert admin.get('/api/investigations/missing/history').status_code==404
    assert admin.get('/api/investigations/subject/history/missing').status_code==404
    assert admin.get('/api/investigations/subject/history?offset=-1').status_code==400
    assert admin.get('/api/investigations/subject/history?limit=51').status_code==400


@pytest.mark.parametrize('role',['viewer','operator'])
def test_history_and_refresh_are_admin_only(admin,role):
    seed();revision=current(admin)['current']['revision']
    with Session() as s:s.get(User,'admin').role=role;s.commit()
    assert admin.get('/api/investigations/subject/history').status_code==403
    assert admin.get('/api/investigations/subject/history/unknown').status_code==403
    assert admin.post('/api/investigations/subject/retriage',json={'expected_revision':revision,'reason':'review this result'}).status_code==403


def test_csrf_reason_validation_and_approval_race(admin):
    seed();revision=current(admin)['current']['revision']
    assert queue(admin,reason=' '*10).status_code==400
    with Session() as s:s.get(Behavior,'subject').approved=True;s.commit()
    assert queue(admin,expected_revision=revision,withdraw_approval=True).status_code==409
    admin.headers.pop('X-CSRF-Token')
    assert queue(admin).status_code==403


def test_global_execution_lock_keeps_refresh_and_active_result_separate(admin):
    seed()
    with worker.Lock('ai-triage'):
        assert queue(admin).status_code==409
    assert queue(admin).status_code==200


def test_pagination_record_identity_and_no_cross_host_reuse(admin,monkeypatch):
    seed(verdict='pending');calls=[]
    with Session() as s:
        original=s.get(Behavior,'subject')
        s.add(Behavior(id='other',host_id='two',evidence=copy.deepcopy(original.evidence)));s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or provider('low'))
    worker.investigate_one();worker.investigate_one();assert len(calls)==2
    data=current(admin);id=data['items'][0]['id']
    assert admin.get('/api/investigations/other/history/'+id).status_code==404
    assert admin.get('/api/investigations/subject/history/'+id+'?host_id=two').status_code==404
    assert queue(admin).status_code==200;worker.investigate_one()
    first=admin.get('/api/investigations/subject/history?limit=1').json()
    second=admin.get('/api/investigations/subject/history?limit=1&offset=1').json()
    assert first['more'] and not second['more'] and first['items'][0]['id']!=second['items'][0]['id']
    assert all('snapshot' not in x and 'inputs' not in x for x in first['items'])


def test_approval_changed_while_waiting_for_host_lock_is_not_silently_withdrawn(admin,monkeypatch):
    from contextlib import contextmanager
    from app import host_lifecycle
    seed();revision=current(admin)['current']['revision'];original=host_lifecycle.activity
    @contextmanager
    def changed(ids,kind):
        with original(ids,kind) as value:
            with Session() as other:other.get(Behavior,'subject').approved=True;other.commit()
            yield value
    monkeypatch.setattr(host_lifecycle,'activity',changed)
    assert queue(admin,expected_revision=revision).status_code==409
    with Session() as s:
        assert s.get(Behavior,'subject').approved
        assert s.get(ai_assessments.Refresh,'subject') is None
        assert not list(s.scalars(select(ai_assessments.Assessment)))


def test_global_pause_hourly_limit_and_follow_up_pause_do_not_bypass_admission(admin,monkeypatch):
    seed();calls=[]
    assert queue(admin).status_code==200
    with Session() as s:
        cfg=s.get(Setting,'config');cfg.value={**cfg.value,'ai_enabled':False};s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:calls.append(1) or provider('low',['executable']))
    worker.investigate_one();assert calls==[]
    with Session() as s:
        cfg=s.get(Setting,'config');cfg.value={**cfg.value,'ai_enabled':True,'ai_hourly_limit':1}
        s.add(ai_runs.AIRun(id='existing',purpose='triage',state='complete',host_id='one',finished=time.time()));s.commit()
    worker.investigate_one();assert calls==[]
    with Session() as s:s.delete(s.get(ai_runs.AIRun,'existing'));s.commit()
    def followup(*a,**k):
        with Session() as s:s.add(Setting(key='server-ai:one',value={'paused':True}));s.commit()
        return {'identity_verified':True,'sha256':'a'*64}
    monkeypatch.setattr(worker.ssh,'call',followup)
    worker.investigate_one();assert len(calls)==1
    data=current(admin);assert data['current']['verdict']=='error' and data['current']['refresh']['id']
    assert len(data['items'])==1


def test_retained_result_and_refresh_completion_share_the_result_transaction(admin,monkeypatch):
    seed();assert queue(admin).status_code==200
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:provider('low'))
    def fail(*a,**k):raise RuntimeError('private transaction details')
    monkeypatch.setattr(ai_assessments,'record',fail)
    worker.investigate_one()
    data=current(admin);assert data['current']['verdict']=='error' and data['current']['refresh']['id']
    assert len(data['items'])==1 and 'private transaction details' not in data['current']['analysis']
    with Session() as s:assert not list(s.scalars(select(ai_assessments.Assessment).where(ai_assessments.Assessment.source=='ai')))


def test_concurrent_refresh_requests_create_one_intent_and_preserve_one_prior_result(admin,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    seed();revision=current(admin)['current']['revision']
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:pytest.fail('Queueing must not call AI'))
    def send(_):
        return admin.post('/api/investigations/subject/retriage',json={'expected_revision':revision,'reason':'Concurrent reviewed refresh'}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:assert sorted(pool.map(send,range(2)))==[200,409]
    with Session() as s:
        assert len(list(s.scalars(select(ai_assessments.Refresh))))==1
        assert len(list(s.scalars(select(ai_assessments.Assessment))))==1
        assert s.get(Behavior,'subject').verdict=='pending' and not s.get(Behavior,'subject').approved
