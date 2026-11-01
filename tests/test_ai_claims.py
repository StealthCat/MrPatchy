"""Real threaded runtime acceptance; all provider/SSH work is disposable I/O."""
import json
import math
import threading
import time
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
import httpx
import pytest
from sqlalchemy import select,event
from app import ai, ai_claims, ai_runs, ai_assessments, ai_retry, worker, worker_registry
from app.db import Session, Host, Behavior, Setting,engine
from app.security import seal


def seed(count=4,limit=20,same_host=False):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model','ai_hourly_limit':limit}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        for n in range(1 if same_host else count):s.add(Host(id='host-'+str(n),name='Fixture',address='192.0.2.1',fingerprint=''))
        for n in range(count):s.add(Behavior(id='subject-'+str(n),host_id='host-'+str(0 if same_host else n),
            evidence={'executable':'/srv/fixture-'+str(n),'sha256':'a'*64,'uid':'1000','identity_verified':True}))
        s.commit()


def result(checks=None):
    data={'risk':'low','explanation':'Advisory fixture','recommended_checks':'Review limitations','requested_checks':checks or []}
    return httpx.Response(200,json={'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(data)}]}]},request=httpx.Request('POST',ai.URL))


@pytest.mark.parametrize('followup',[False,True])
def test_four_investigations_overlap_and_keep_full_capability(admin,monkeypatch,followup):
    seed();barrier=threading.Barrier(4);guard=threading.Lock();sent=[];intervals=[];ssh_calls=[]
    def post(*a,**k):
        evidence=json.loads(k['json']['input']);first='investigation' not in evidence
        if first:barrier.wait(timeout=15)
        started=time.perf_counter();time.sleep(.2)
        with guard:
            sent.append((ai_policy_scope(),ai_runs.active.get(),k['json']))
            intervals.append((started,time.perf_counter()))
        return result(['executable','service'] if first and followup else [])
    def ssh(host,request,**kwargs):
        time.sleep(.05)
        with guard:ssh_calls.append((host.id,request))
        return {'identity_verified':True,'sha256':'a'*64,'context':host.id}
    monkeypatch.setattr(ai.transport,'post',post);monkeypatch.setattr(worker.ssh,'call',ssh)
    with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda _:worker.investigate_one(),range(4)))
    assert len(sent)==4*(1+followup) and len(ssh_calls)==4*followup
    # All four first calls really overlap; this is not four serial submissions.
    first_calls=sorted(intervals)[:4]
    assert max(i[0] for i in first_calls)<min(i[1] for i in first_calls)
    assert len({entry[1] for entry in sent})==4
    with Session() as s:
        assert not list(s.scalars(select(ai_claims.Claim)))
        saved=list(s.scalars(select(ai_assessments.Assessment)));assert len(saved)==4
        assert len(list(s.scalars(select(ai_runs.AICall))))==len(sent)
        for row in s.scalars(select(Behavior)):
            assert row.verdict=='low' and not row.approved
            record=next(r for r in saved if r.subject==row.id)
            assert len(record.inputs)==1+followup and record.host_id==row.host_id
            supplied=[payload for scope,run,payload in sent if run==record.run_id]
            assert all(scope==(row.host_id,) for scope,run,payload in sent if run==record.run_id)
            assert [i['evidence'] for i in record.inputs]==[json.loads(p['input']) for p in supplied]
            assert all(p['model']=='fixture-model' and p['max_output_tokens']==1600 and p['text']['format']['schema']==ai.SCHEMA for p in supplied)
        assert all(r.state=='complete' for r in s.scalars(select(ai_runs.AIRun)))


def ai_policy_scope():
    from app.ai_policy import scope
    return scope.get()


def test_atomic_hourly_admission_and_no_duplicate_subject(admin,monkeypatch):
    seed(count=4,limit=2);sent=[]
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:sent.append(ai_runs.active.get()) or result())
    with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(lambda _:worker.investigate_one(),range(8)))
    assert len(sent)==len(set(sent))==2
    with Session() as s:assert len(list(s.scalars(select(ai_runs.AIRun))))==2


def test_refused_admission_lock_does_not_mutate_work(admin,monkeypatch):
    seed(count=1)
    class Refused:
        def acquire(self):return False
        def release(self):pytest.fail('An unowned admission lock cannot be released')
    monkeypatch.setattr(ai_claims,'Lock',lambda name:Refused())
    assert ai_claims.acquire() is None
    with Session() as s:
        assert s.get(Behavior,'subject-0').attempted==0
        assert not list(s.scalars(select(ai_claims.Claim)))
        assert not list(s.scalars(select(ai_runs.AIRun)))


def test_one_subject_and_one_host_cannot_occupy_multiple_slots(admin,monkeypatch):
    seed(count=4,same_host=True);started=threading.Event();release=threading.Event();sent=[]
    def post(*a,**k):
        sent.append(1);started.set();assert release.wait(15);return result()
    monkeypatch.setattr(ai.transport,'post',post)
    with ThreadPoolExecutor(max_workers=4) as pool:
        first=pool.submit(worker.investigate_one);assert started.wait(15)
        others=[pool.submit(worker.investigate_one) for _ in range(3)]
        for future in others:future.result(15)
        assert sent==[1]
        assert admin.post('/api/investigations/subject-0/retry').status_code==409
        status=admin.get('/api/investigation-status').json();assert status['active']==1 and status['queued']==3
        release.set();first.result(15)


@pytest.mark.parametrize('change',['evidence','approval','configuration','expiry','token','worker_boot','worker_heartbeat','worker_identity'])
def test_changed_state_fences_late_provider_result(admin,monkeypatch,change):
    seed(count=1)
    with worker_registry.Registration() as node:
        def post(*a,**k):
            with Session() as s:
                if change=='evidence':s.get(Behavior,'subject-0').evidence={'executable':'changed'}
                elif change=='approval':s.get(Behavior,'subject-0').approved=True
                elif change=='configuration':s.get(Setting,'config').value={'ai_enabled':True,'ai_model':'changed-model'}
                elif change=='expiry':s.get(ai_claims.Claim,'subject-0').expires=0
                elif change=='token':s.get(ai_claims.Claim,'subject-0').token='replacement'
                elif change=='worker_boot':
                    row=s.get(Setting,worker_registry.record_key(node.id));row.value={**row.value,'boot_id':'f'*32}
                elif change=='worker_heartbeat':
                    row=s.get(Setting,worker_registry.record_key(node.id));row.value={**row.value,'heartbeat':0}
                elif change=='worker_identity':ai_claims.abandon_owner((node.id,node.boot))
                s.commit()
            return result()
        monkeypatch.setattr(ai.transport,'post',post)
        worker.investigate_one((node.id,node.boot))
        with Session() as s:
            assert s.get(Behavior,'subject-0').verdict=='pending'
            assert not list(s.scalars(select(ai_assessments.Assessment)))
            assert len(list(s.scalars(select(ai_runs.AICall))))==1 # Possible charges survive rejection.


def test_renewal_reconciliation_and_expired_owner_cannot_release_successor(admin):
    seed(count=2);one=ai_claims.acquire();assert one
    with one:
        before=time.time()
        with Session() as s:s.get(ai_claims.Claim,one.subject).expires=before+1;s.commit()
        one.renew()
        with Session() as s:assert s.get(ai_claims.Claim,one.subject).expires>=before+ai_claims.LEASE_SECONDS
        # A second worker admission must not interrupt this live run.
        two=ai_claims.acquire();assert two and two.subject!=one.subject
        with Session() as s:assert s.get(ai_runs.AIRun,one.run_id).state=='running'
        with two:pass
        with Session() as s:
            s.get(ai_claims.Claim,one.subject).expires=0
            s.get(ai_retry.TriageRetry,one.subject).next_at=0;s.commit()
        successor=ai_claims.acquire();assert successor and successor.subject==one.subject
        with pytest.raises(ai_claims.Lost):one.check()
    with Session() as s:
        assert s.get(ai_claims.Claim,successor.subject).token==successor.token
        assert s.get(ai_runs.AIRun,one.run_id).state=='interrupted'
    with successor:pass


def test_drain_blocks_new_claims_but_keeps_existing_owner_valid(admin):
    seed(count=2)
    with worker_registry.Registration() as node:
        owner=(node.id,node.boot);lease=ai_claims.acquire(owner);assert lease
        worker_registry.request_control(node.id,node.boot,0,'drain','Planned fixture maintenance','admin')
        assert ai_claims.acquire(owner) is None
        with lease:lease.renew();lease.check()


def test_live_background_renewal(admin,monkeypatch):
    seed(count=1);monkeypatch.setattr(ai_claims,'RENEW_SECONDS',.02)
    lease=ai_claims.acquire();renewed=threading.Event();original=lease.renew
    def renew():original();renewed.set()
    monkeypatch.setattr(lease,'renew',renew)
    with lease:assert renewed.wait(5)
    assert not lease.thread.is_alive()


@pytest.mark.parametrize('hosts',[1,4])
def test_claims_are_exclusive_across_fresh_processes(admin,hosts):
    seed(count=hosts)
    script="""
import json,sys
from app import ai_claims
lease=ai_claims.acquire()
print(json.dumps({'subject':lease.subject,'token':lease.token} if lease else None),flush=True)
sys.stdin.readline()
if lease:
    with lease:pass
"""
    children=[subprocess.Popen([sys.executable,'-c',script],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(4)]
    try:
        claims=[json.loads(child.stdout.readline()) for child in children]
        live=[value for value in claims if value]
        assert len(live)==hosts and len({value['subject'] for value in live})==hosts
        with Session() as s:assert len(list(s.scalars(select(ai_claims.Claim))))==hosts
    finally:
        for child in children:
            if child.poll() is None:child.stdin.write('\n');child.stdin.flush()
        for child in children:
            _,err=child.communicate(timeout=20);assert child.returncode==0,err


@pytest.mark.parametrize('capacity',[1,4])
@pytest.mark.parametrize('shutdown',[False,True])
def test_scheduler_bounds_slots_alternates_purposes_and_drains(admin,monkeypatch,capacity,shutdown):
    from concurrent.futures import Future
    from app import persistence,response_monitor,service_monitor,execution_scans
    monkeypatch.setenv('MRPATCHY_AI_CONCURRENCY',str(capacity))
    for module in (worker.scheduling,worker.incidents,persistence,response_monitor,service_monitor,execution_scans):
        monkeypatch.setattr(module,'tick' if module is worker.scheduling else 'schedule_tick',lambda *a:None)
    monkeypatch.setattr(worker.incidents,'auto_plan_tick',lambda *a:None)
    monkeypatch.setattr(worker.operations,'collect_alerts',lambda:None)
    pending=[];submitted=[];tick=[0];now=time.time()
    class Pool:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def submit(self,fn,*args):
            future=Future()
            if fn in (worker.investigate_one,worker.update_scores.run_one):
                future.set_running_or_notify_cancel();pending.append(future);submitted.append((tick[0],fn,args))
            else:future.set_result(None)
            return future
    monkeypatch.setattr(worker.concurrent.futures,'ThreadPoolExecutor',Pool)
    monkeypatch.setattr(worker.time,'time',lambda:now+tick[0]*6)
    with worker_registry.Registration() as node:
        def wait(_):
            tick[0]+=1
            if tick[0]==2:
                assert len(pending)==capacity
                for f in pending:f.set_result(None)
                pending.clear()
            if tick[0]==3:
                assert len(pending)==capacity
                if not shutdown:worker_registry.request_control(node.id,node.boot,0,'drain','Planned scheduler maintenance','admin')
            if tick[0]==4:
                assert node.draining
                other=worker.Lock('scheduler');assert other.acquire(False);other.release()
                for f in pending:f.set_result(None)
                pending.clear()
            return tick[0]>=5 or (shutdown and tick[0]>=3)
        monkeypatch.setattr(worker.stop,'wait',wait)
        worker._loop(node)
        assert node.last_state=='drained'
        assert len(submitted)==2*capacity and all(tick<3 for tick,_,_ in submitted)
        assert submitted[0][1] is worker.update_scores.run_one
        assert any(fn is worker.investigate_one for _,fn,_ in submitted)
        assert all(args==((node.id,node.boot),) for _,fn,args in submitted if fn is worker.investigate_one)


@pytest.mark.parametrize('value',[1,8])
def test_supported_serial_and_parallel_capacity_is_reported(admin,monkeypatch,value):
    monkeypatch.setenv('MRPATCHY_AI_CONCURRENCY',str(value))
    with worker_registry.Registration() as node:
        assert node.capacity['ai']==value
        node.last-=16;node.heartbeat(False,[],0,value)
        item=worker_registry.page()['items'][0]
        assert item['ai_capacity']==value and item['active_ai_tasks']==value
        assert admin.get('/api/investigation-status').json()['reported_capacity']==value


def test_database_json_normalization_is_bound_before_followup(admin,monkeypatch):
    if engine.dialect.name!='sqlite':pytest.skip('Deterministic DB-roundtrip simulation; native MySQL runs the complete pipeline separately')
    seed(count=1);sent=[];normalized=[]
    # Change only the bytes stored by the DB, leaving the ORM's in-memory value
    # untouched, as native JSON numeric representation can do on MySQL. One ULP
    # is enough to expose hashing an unrefreshed ORM value after a flush.
    def storage(connection,cursor,statement,parameters,context,many):
        if not statement.startswith('UPDATE behaviors SET') or 'evidence=' not in statement:return statement,parameters
        values=list(parameters)
        for n,value in enumerate(values):
            if not isinstance(value,str):continue
            try:data=json.loads(value)
            except ValueError:continue
            if not isinstance(data,dict) or not isinstance(data.get('investigation'),dict):continue
            data['investigation']['collected']=math.nextafter(data['investigation']['collected'],math.inf)
            normalized.append(data['investigation']['collected']);values[n]=json.dumps(data)
        return statement,tuple(values)
    def post(*a,**k):
        sent.append(json.loads(k['json']['input']));return result(['executable'] if len(sent)==1 else [])
    event.listen(engine,'before_cursor_execute',storage,retval=True)
    monkeypatch.setattr(ai.transport,'post',post)
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:{'identity_verified':False,'reason':'exited'})
    try:worker.investigate_one()
    finally:event.remove(engine,'before_cursor_execute',storage)
    with Session() as s:
        runs=list(s.scalars(select(ai_runs.AIRun)))
        assert len(sent)==2,[(r.state,r.message) for r in runs]
        assert len(normalized)==1 and sent[1]['investigation']['collected']==normalized[0]
        saved=s.scalar(select(ai_assessments.Assessment));assert saved and saved.inputs[1]['evidence']==sent[1]
        assert s.get(Behavior,'subject-0').verdict=='low'


def test_rate_throttled_triage_is_not_claimed_and_deferrals_are_spread(admin,monkeypatch):
    seed(count=4)
    with Session() as s:
        cfg=s.get(Setting,'config');cfg.value={**cfg.value,'ai_control_mode':'rate','ai_rate_per_hour':1};s.commit()
    sent=[]
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:sent.append(1) or result())
    for _ in range(4):worker.investigate_one()
    assert len(sent)==1
    with Session() as s:
        states=sorted(r.state for r in s.scalars(select(ai_runs.AIRun)))
        # The gate closed after the first admission: no runs/attempts for the rest.
        assert states==['complete']
        assert not list(s.scalars(select(ai_retry.TriageRetry)))
    # Force a refused item through the failure path: it must be deferred, not errored,
    # and later waiters must not share an identical wake time.
    from app.ai import AIError
    now=time.time();wakes=[]
    with Session() as s:
        rows=list(s.scalars(select(Behavior).order_by(Behavior.id)))[1:]
        for row in rows:
            ai_retry.begin(s,row,'sig',now)
            wakes.append(ai_retry.failed(s,row,AIError('wait',policy_wait=True,retry_after=600),now).next_at)
        s.commit()
    assert len(set(wakes))==3 and wakes==sorted(wakes)
