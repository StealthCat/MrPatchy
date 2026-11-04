import hashlib
import json
import time
import datetime as dt
import pytest
import httpx
from sqlalchemy import select
from app import worker,ai,ai_runs,update_scores,package_history,install_times,scheduling
from app.db import Session,Host,Package,Behavior,Setting,Job
from app.security import seal,verify
from app.identity import User


def setup_ai(s,limit=20):
    s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'test-model','ai_hourly_limit':limit}))
    s.merge(Setting(key='openai_key',value={'encrypted':seal('secret-api-key')}))


def host(s,now=None):
    h=Host(id='host-a',name='Test host',address='192.0.2.1',fingerprint='SHA256:test',state='online',last_seen=now or time.time(),last_repo=now or time.time(),inventory={'os':'ID=debian\nVERSION_ID="12"','status':'','collected':time.time()},integrity=[])
    s.add(h);s.flush();return h


def pkg(s,h,name='openssl:amd64',version='1',candidate='2',priority='high'):
    p=Package(id=h.id+':'+name,host_id=h.id,name=name,installed=version,candidate=candidate,priority=priority,available_since=time.time()-7200)
    s.add(p);s.flush();return p


def response(data,status=200,**kwargs):
    return httpx.Response(status,json=data,request=httpx.Request('POST',ai.URL),**kwargs)


def completed(data):return response({'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]})


def test_triage_persists_stages_error_and_redacts_provider(admin,monkeypatch):
    with Session() as s:
        setup_ai(s);h=host(s);s.add(Behavior(id='b'*64,host_id=h.id,evidence={'executable':'/private/process','sha256':'a'*64,'connections':[]}));s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**kw:response({'error':{'code':'invalid_api_key','message':'secret-api-key /private/process'}},401,headers={'x-request-id':'req_test'}))
    worker.investigate_one();ai_runs.heartbeat()
    data=admin.get('/api/ai/runs').json()['items'];assert len(data)==1 and data[0]['state']=='error' and data[0]['calls']==1
    detail=admin.get('/api/ai/runs/'+data[0]['id']).json()
    assert [e['stage'] for e in detail['events'] if not e['stage'].startswith('timing_')]==['starting','api_request','api_response','failed']
    assert 'HTTP 401' in json.dumps(detail) and 'req_test' in json.dumps(detail)
    assert 'secret-api-key' not in json.dumps(detail) and '/private/process' not in json.dumps(detail)
    status=admin.get('/api/investigation-status').json();assert status['reason']=='blocked' and status['blocked']==1 and status['retry_at'] is None


def test_manual_retry_does_not_reset_hourly_quota(admin,monkeypatch):
    with Session() as s:
        setup_ai(s,1);h=host(s);s.add(Behavior(id='c'*64,host_id=h.id,evidence={}));s.commit()
    calls=[]
    def post(*a,**kw):calls.append(1);return response({'error':{'code':'insufficient_quota'}},429)
    monkeypatch.setattr(ai.transport,'post',post)
    worker.investigate_one();assert admin.post('/api/investigations/'+'c'*64+'/retry').status_code==200
    worker.investigate_one();assert len(calls)==1
    ai_runs.heartbeat();assert admin.get('/api/investigation-status').json()['reason']=='rate_limited'


def test_worker_failure_is_visible_without_leaking_detail(admin):
    ai_runs.task_failure(RuntimeError('secret password'))
    runs=admin.get('/api/ai/runs').json()['items'];assert runs[0]['purpose']=='worker' and 'RuntimeError' in runs[0]['message']
    assert 'secret password' not in json.dumps(runs)


def test_worker_status_explains_configuration_and_missing_worker(admin):
    assert admin.get('/api/investigation-status').json()['reason']=='disabled'
    with Session() as s:s.merge(Setting(key='config',value={'ai_enabled':True}));s.commit()
    assert admin.get('/api/investigation-status').json()['reason']=='configuration'
    with Session() as s:setup_ai(s);s.commit()
    assert admin.get('/api/investigation-status').json()['reason']=='worker_unavailable'
    ai_runs.heartbeat();assert admin.get('/api/investigation-status').json()['reason']=='idle'


def test_logs_admin_only_and_password_self_service(admin):
    assert admin.put('/api/users',json={'username':'reader','password':'initial-password-long','role':'viewer','enabled':True}).status_code==200
    login=admin.post('/api/login',json={'username':'reader','password':'initial-password-long'});admin.headers['X-CSRF-Token']=login.json()['csrf']
    assert admin.get('/api/ai/runs').status_code==403
    assert admin.get('/api/package-history').status_code==200
    assert admin.put('/api/users',json={'username':'admin','role':'admin','enabled':True,'password':'hijack-password-long'}).status_code==403
    assert admin.put('/api/identity/password',json={'password':'initial-password-long','new_password':'my-personal-password'}).status_code==200
    assert admin.get('/api/identity').status_code==401
    assert admin.post('/api/login',json={'username':'reader','password':'my-personal-password'}).status_code==200
    with Session() as s:assert verify('my-personal-password',s.get(User,'reader').password)


def score_reply(*args,**kwargs):
    inputs=json.loads(kwargs['json']['input'])
    return completed({'assessments':[{'id':x['id'],'score':75,'confidence':'high','explanation':'Repository classification suggests attention.','limitations':'No verified advisory.'} for x in inputs]})


def test_update_scores_are_exact_version_advisory_and_bounded(admin,monkeypatch):
    with Session() as s:
        setup_ai(s);h=host(s);h.inventory={**h.inventory,'os':'ID=debian\nVERSION_ID=12\nPRIVATE_TOKEN=secret'}
        for i in range(7):pkg(s,h,name=f'pkg{i}:amd64')
        s.commit()
    sent=[]
    def post(*a,**kw):sent.append(kw['json']);return score_reply(*a,**kw)
    monkeypatch.setattr(ai.transport,'post',post);update_scores.run_one()
    assert len(json.loads(sent[0]['input']))==5 and 'PRIVATE_TOKEN' not in sent[0]['input']
    data=admin.get('/api/hosts/host-a/packages').json();scored=[p for p in data if p['assessment']['state']=='complete']
    assert len(scored)==5 and all(p['assessment']['confidence']=='low' and p['priority']=='high' for p in scored)
    assert all(p['assessment']['score']==75 and p['installation']['state']=='unscheduled' for p in scored)
    with Session() as s:s.get(Package,'host-a:'+scored[0]['name']).candidate='3';s.commit()
    assert next(p for p in admin.get('/api/hosts/host-a/packages').json() if p['name']==scored[0]['name'])['assessment']['score'] is None
    assert admin.get('/api/jobs').json()==[]


@pytest.mark.parametrize('bad',['duplicate','bool','missing'])
def test_score_invalid_batch_not_accepted(admin,monkeypatch,bad):
    with Session() as s:setup_ai(s);h=host(s);pkg(s,h);pkg(s,h,name='other:amd64');s.commit()
    def post(*a,**kw):
        data=score_reply(*a,**kw).json();value=json.loads(data['output'][0]['content'][0]['text'])
        if bad=='duplicate':value['assessments'][1]['id']=value['assessments'][0]['id']
        elif bad=='bool':value['assessments'][0]['score']=True
        else:value['assessments'].pop()
        return completed(value)
    monkeypatch.setattr(ai.transport,'post',post);update_scores.run_one()
    with Session() as s:assert all(r.score is None and r.state=='error' for r in s.scalars(select(update_scores.UpdateScore)))


def test_score_inflight_candidate_change_is_discarded(admin,monkeypatch):
    with Session() as s:setup_ai(s);h=host(s);pkg(s,h);s.commit()
    def post(*a,**kw):
        with Session() as s:s.get(Package,'host-a:openssl:amd64').candidate='3';s.commit()
        return score_reply(*a,**kw)
    monkeypatch.setattr(ai.transport,'post',post);update_scores.run_one()
    with Session() as s:assert s.scalar(select(update_scores.UpdateScore)).state=='superseded'
    assert admin.get('/api/hosts/host-a/packages').json()[0]['assessment']['score'] is None


def inventory(version,extra=''):
    return {'status':f'Package: test\nArchitecture: amd64\nVersion: {version}\nStatus: install ok installed\n\n'+extra,'collected':time.time()}


def test_package_ledger_distinguishes_baseline_changes_and_job_observations(admin):
    with Session() as s:
        h=host(s);worker.save_inventory(s,h,inventory('1'));s.commit()
        assert s.scalar(select(package_history.PackageEvent)).action=='baseline'
        worker.save_inventory(s,h,inventory('1'));s.commit();assert len(list(s.scalars(select(package_history.PackageEvent))))==1
        token=package_history.operation.set({'job_id':'job-id','actor':'operator'})
        try:worker.save_inventory(s,h,inventory('2','Package: dependency\nArchitecture: amd64\nVersion: 1\nStatus: install ok installed\n'));s.commit()
        finally:package_history.operation.reset(token)
        worker.save_inventory(s,h,inventory('2'));s.commit()
    rows=admin.get('/api/package-history?host_id=host-a').json()['items']
    assert {r['action'] for r in rows}=={'baseline','version_changed','installed','removed'}
    changed=next(r for r in rows if r['action']=='version_changed');assert changed['before']==['1'] and changed['after']==['2'] and changed['actor']=='operator' and changed['job_id']=='job-id'
    assert admin.get('/api/package-history?q=dependency&limit=1').json()['more'] is True


def test_rpm_multiversion_removal_is_audited(admin):
    with Session() as s:
        h=host(s);p=pkg(s,h,name='kernel:x86_64',version='2',candidate='')
        h.inventory={'package_manager':'rpm','rpm_packages':[{'name':'kernel','arch':'x86_64','evr':'1'},{'name':'kernel','arch':'x86_64','evr':'2'}]}
        new={'package_manager':'rpm','rpm_packages':[{'name':'kernel','arch':'x86_64','evr':'2'}]}
        package_history.record(s,h,new,{p.name:p},[{'name':p.name,'installed':'2','dpkg_state':'install ok installed'}]);s.commit()
        changed=s.scalar(select(package_history.PackageEvent).where(package_history.PackageEvent.action=='version_changed'))
        assert changed.before==['1','2'] and changed.after==['2']


def test_confirmed_inventory_survives_later_health_failure(admin,monkeypatch):
    with Session() as s:
        h=host(s);worker.save_inventory(s,h,inventory('1'));s.commit()
        s.add(Job(id='patch-job',host_id=h.id,action='patch',payload={'packages':['test:amd64=2'],'_depends_on':[],'_actor':'operator'}));s.commit()
    monkeypatch.setattr(worker,'validate_patch',lambda *a:None)
    calls=[];health_calls=[]
    def call(h,body,**kw):
        if body['action']=='inventory':calls.append(1);return inventory('1' if len(calls)==1 else '2')
        if body['action']=='health':
            health_calls.append(1);return {'failed_units':[] if len(health_calls)==1 else ['service.service'],'collector_active':True}
        return {'ok':True}
    monkeypatch.setattr(worker.ssh,'call',call);worker.execute('patch-job')
    with Session() as s:
        assert s.get(Job,'patch-job').state=='failed'
        row=s.scalar(select(package_history.PackageEvent).where(package_history.PackageEvent.action=='version_changed'))
        assert row.after==['2'] and row.job_id=='patch-job'

NOW=dt.datetime(2026,10,26,12,tzinfo=dt.timezone.utc).timestamp() # Monday noon

def schedule(s,h,**overrides):
    policy=scheduling.ScheduleInput(name='Daily',enabled=True,approved=True,frequency='daily',minute=14*60,timezone='UTC').model_dump(exclude={'approved','revision'})
    policy.update(overrides)
    row=scheduling.PatchSchedule(id='schedule-a',policy=policy,updated=NOW-86400,revision=1);s.add(row);s.flush();return row


def test_install_time_is_schedule_start_not_priority_deadline(admin):
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h);p.available_since=NOW-3600;schedule(s,h)
        result=install_times.Planner(s,h,NOW).for_package(p)
        assert result['state']=='scheduled' and result['at']==NOW+7200
        p.held=True;assert install_times.Planner(s,h,NOW).for_package(p)['at'] is None


def test_install_time_intersects_maintenance_window_and_urgent_bypass(admin):
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h);p.available_since=NOW-3600
        s.add(Setting(key='window:'+h.id,value={'windows':[{'days':[0],'start':15*60,'end':16*60}]}))
        row=schedule(s,h);result=install_times.Planner(s,h,NOW).for_package(p);assert result['at']==NOW+3*3600
        row.policy={**row.policy,'high':{'enabled':True,'after_minutes':0,'bypass_window':True}}
        assert install_times.Planner(s,h,NOW).for_package(p)['at']==NOW


def test_install_time_queued_and_unknown_dependency(admin):
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h);job=Job(id='job-a',host_id=h.id,action='patch',payload={'packages':['openssl:amd64=2']});s.add(job);s.flush()
        assert install_times.Planner(s,h,NOW).for_package(p)['at']==NOW
        job.payload={**job.payload,'_depends_on':['missing']};assert install_times.Planner(s,h,NOW).for_package(p)['at'] is None
        job.state='running';assert install_times.Planner(s,h,NOW).for_package(p)['state']=='installing'


def test_failed_urgency_batch_is_not_promised_again(admin):
    with Session() as s:
        h=host(s,NOW);p=pkg(s,h);p.available_since=NOW-3600
        row=schedule(s,h,priorities=['low'],high={'enabled':True,'after_minutes':0,'bypass_window':True})
        key=json.dumps([(p.name,p.candidate,p.available_since)])
        scheduling.add_run(s,row,h,'high',NOW-60,key)
        run=s.scalar(select(scheduling.PatchRun));run.state='failed';s.flush()
        assert install_times.Planner(s,h,NOW).for_package(p)['at'] is None


def test_next_window_excludes_end_boundary_and_handles_next_week():
    windows=[{'days':[0],'start':11*60,'end':12*60}]
    assert install_times.next_window(windows,NOW,NOW+8*86400)==NOW+7*86400-3600
    assert install_times.next_window(windows,NOW,NOW+3600) is None


def test_retained_snapshots_backfill_without_duplicate_current_change(admin):
    from app.db import InventoryRevision
    with Session() as s:
        h=host(s);p=pkg(s,h,name='test:amd64',version='2',candidate='3');h.inventory=inventory('2')
        s.add(InventoryRevision(id='first',host_id=h.id,created=time.time()-100,inventory=inventory('1')))
        s.add(InventoryRevision(id='second',host_id=h.id,created=time.time()-50,inventory=inventory('2')));s.commit()
        worker.save_inventory(s,h,inventory('3'));s.commit()
        rows=list(s.scalars(select(package_history.PackageEvent).order_by(package_history.PackageEvent.id)))
        assert [(r.action,r.before,r.after) for r in rows]==[('baseline',[],['1']),('version_changed',['1'],['2']),('version_changed',['2'],['3'])]
        assert rows[0].source=='retained_inventory' and rows[1].actor==''
        worker.save_inventory(s,h,inventory('3'));s.commit();assert len(list(s.scalars(select(package_history.PackageEvent))))==3


def test_historical_scores_match_installed_version_and_transition(admin):
    now=time.time()
    with Session() as s:
        h=host(s);p=pkg(s,h,version='2',candidate='')
        s.add(update_scores.UpdateScore(id='old-assessment',host_id=h.id,name=p.name,installed='1',candidate='2',state='complete',score=78,completed=now-50,explanation='Saved rationale'))
        s.add(update_scores.UpdateScore(id='future-assessment',host_id=h.id,name=p.name,installed='2',candidate='3',state='complete',score=95,completed=now-10))
        s.add(package_history.PackageEvent(host_id=h.id,name=p.name,action='version_changed',before=['1'],after=['2'],observed=now-20,source='inventory'))
        s.commit()
    row=admin.get('/api/hosts/host-a/packages').json()[0]
    assert row['assessment']['score']==78 and row['assessment']['historical']
    event=admin.get('/api/package-history?host_id=host-a').json()['items'][0]
    assert event['assessment']['score']==78 and event['assessment']['to_version']=='2'
    with Session() as s:
        s.get(Package,'host-a:openssl:amd64').candidate='3';s.commit()
    row=admin.get('/api/hosts/host-a/packages').json()[0]
    assert row['installed_assessment']['score']==78
    assert row['assessment']['state']!='complete' # Different current evidence identity is not substituted.
    with Session() as s:
        s.get(update_scores.UpdateScore,'old-assessment').completed=now+1;s.commit()
    assert admin.get('/api/package-history?host_id=host-a').json()['items'][0]['assessment'] is None
