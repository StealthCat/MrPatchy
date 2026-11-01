import datetime as dt
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select
from app import scheduling as sched, operations, worker
from app.db import Session, Host, Package, Job, Setting
from app.identity import User


def stamp(text): return dt.datetime.fromisoformat(text).timestamp()


def policy(**changes):
    return sched.ScheduleInput(name='Weekly fleet', **changes).model_dump(exclude={'revision','approved'})


@pytest.mark.parametrize('timezone,start,end,minute,expected',[
    ('America/New_York','2026-03-08T00:00:00+00:00','2026-03-09T00:00:00+00:00',150,[]),
    ('America/New_York','2026-11-01T00:00:00+00:00','2026-11-02T00:00:00+00:00',90,['2026-11-01T05:30:00+00:00']),
    ('Asia/Kolkata','2026-06-01T00:00:00+00:00','2026-06-02T00:00:00+00:00',600,['2026-06-01T04:30:00+00:00']),
])
def test_timezone_and_dst(timezone,start,end,minute,expected):
    result=list(sched.occurrences(policy(frequency='daily',timezone=timezone,minute=minute),stamp(start),stamp(end)))
    assert result == [stamp(value) for value in expected]


def test_monthly_missing_day_and_weekday():
    start,end=stamp('2026-02-01T00:00:00+00:00'),stamp('2026-03-02T00:00:00+00:00')
    assert not list(sched.occurrences(policy(frequency='monthly',month_day=31),start,end))
    result=list(sched.occurrences(policy(frequency='weekly',days=[0],minute=60),start,end))
    assert len(result)==4
    assert all(dt.datetime.fromtimestamp(value,dt.timezone.utc).weekday()==0 for value in result)


@pytest.fixture
def fleet(admin):
    now=stamp('2026-06-01T02:00:00+00:00')
    with Session() as s:
        for id in ('alpha','beta'):
            s.add(Host(id=id,name=id,address='192.0.2.10',fingerprint='SHA256:'+'a'*43,state='online',
                       last_seen=now,last_repo=now,inventory={'status':'fixture'},baseline={'fixture':'hash'}))
            s.add(Package(id=id+':bash:amd64',host_id=id,name='bash:amd64',installed='1',candidate='2',priority='normal',available_since=now-7200))
        row=sched.PatchSchedule(id='schedule',policy=policy(enabled=True,approved=True,frequency='daily'),revision=1,updated=now-86400)
        s.add(row);s.commit()
    return now


def runs():
    with Session() as s: return list(s.scalars(select(sched.PatchRun).order_by(sched.PatchRun.host_id,sched.PatchRun.trigger)))


def complete_refreshes(now):
    with Session() as s:
        for job in s.scalars(select(Job).where(Job.action=='refresh')): job.state='complete'
        for h in s.scalars(select(Host)): h.last_repo=now
        s.commit()


def test_recurring_all_servers_refresh_then_exact_patch_once(fleet,monkeypatch):
    monkeypatch.setattr(worker.time,'time',lambda:fleet)
    sched.tick(fleet);sched.tick(fleet)
    assert len(runs())==2 and all(r.state=='refreshing' for r in runs())
    complete_refreshes(fleet);sched.tick(fleet)
    with Session() as s:
        patches=list(s.scalars(select(Job).where(Job.action=='patch')))
        assert len(patches)==2
        assert all(j.payload['packages']==['bash:amd64=2'] and j.payload['_recovery_policy']=={'reboot':False,'rollback':False} for j in patches)
        assert all(operations.eligible(s,j) for j in patches)
    sched.tick(fleet)
    with Session() as s: assert len(list(s.scalars(select(Job).where(Job.action=='patch'))))==2


def test_distributed_ticks_do_not_duplicate(fleet):
    with ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(sched.tick,[fleet]*4))
    assert len(runs())==2
    with Session() as s: assert len(list(s.scalars(select(Job))))==2


def test_new_servers_are_included_and_selected_scope_is_respected(fleet):
    with Session() as s:
        row=s.get(sched.PatchSchedule,'schedule');row.policy={**row.policy,'all_hosts':False,'host_ids':['alpha']};s.commit()
    sched.tick(fleet)
    assert [r.host_id for r in runs()]==['alpha']
    with Session() as s:
        row=s.get(sched.PatchSchedule,'schedule');row.policy={**row.policy,'all_hosts':True};s.commit()
    sched.tick(fleet)
    assert {r.host_id for r in runs()}=={'alpha','beta'}


def test_no_missed_window_catchup_or_retroactive_save(fleet):
    sched.tick(fleet+7201)
    assert not runs()
    with Session() as s:
        row=s.get(sched.PatchSchedule,'schedule');row.updated=fleet+1;s.commit()
    sched.tick(fleet+2)
    assert not runs()


def test_urgency_delay_priority_filter_and_window_override(fleet,monkeypatch):
    monkeypatch.setattr(worker.time,'time',lambda:fleet)
    with Session() as s:
        row=s.get(sched.PatchSchedule,'schedule');row.policy=policy(enabled=True,approved=True,frequency='daily',minute=180,
            critical={'enabled':True,'after_minutes':0,'bypass_window':True},high={'enabled':True,'after_minutes':180})
        for h in s.scalars(select(Host)):
            s.add(Setting(key='window:'+h.id,value={'windows':[{'days':[0],'start':600,'end':660}]}))
            s.add(Package(id=h.id+':urgent:amd64',host_id=h.id,name='urgent:amd64',installed='1',candidate='2',priority='critical',available_since=fleet-60))
            s.add(Package(id=h.id+':high:amd64',host_id=h.id,name='high:amd64',installed='1',candidate='2',priority='high',available_since=fleet-60))
        s.commit()
    sched.tick(fleet)
    assert len(runs())==2 and all(r.trigger=='critical' and r.state=='refreshing' for r in runs())
    complete_refreshes(fleet);sched.tick(fleet)
    with Session() as s:
        patches=list(s.scalars(select(Job).where(Job.action=='patch')))
        assert all(j.payload['packages']==['urgent:amd64=2'] and operations.eligible(s,j) for j in patches)
        # Relabeling the candidate removes its urgent authorization before installation.
        p=s.get(Package,'alpha:urgent:amd64');p.priority='normal';s.commit()
        job=next(j for j in patches if j.host_id=='alpha')
        with pytest.raises(ValueError,match='priority'): sched.validate_selection(s,s.get(Host,'alpha'),job)


def test_regular_and_urgent_default_respect_windows(fleet):
    with Session() as s:
        row=s.get(sched.PatchSchedule,'schedule');row.policy={**row.policy,'high':{'enabled':True,'after_minutes':0,'bypass_window':False}}
        for host in ('alpha','beta'):
            s.get(Package,host+':bash:amd64').priority='high'
            s.add(Setting(key='window:'+host,value={'windows':[{'days':[0],'start':600,'end':660}]}))
        s.commit()
    sched.tick(fleet)
    assert len(runs())==4 and all('maintenance' in r.detail for r in runs())
    sched.tick(fleet+7201)
    assert all(r.state=='skipped' for r in runs())


@pytest.mark.parametrize('condition',['held','broken','offline','integrity','policy','quarantine','stale'])
def test_safety_gates(fleet,monkeypatch,condition):
    monkeypatch.setattr(worker.time,'time',lambda:fleet)
    with Session() as s:
        h=s.get(Host,'alpha');p=s.get(Package,'alpha:bash:amd64')
        if condition=='held':p.held=True
        if condition=='broken':p.dpkg_state='install ok unpacked'
        if condition=='offline':h.state='offline'
        if condition=='integrity':h.integrity=[{'issue':'hash mismatch'}]
        if condition=='stale':h.last_seen=fleet-121
        if condition=='policy':s.add(Setting(key='recovery:alpha',value={'reboot':True,'rollback':False}))
        if condition=='quarantine':s.add(Job(id='uncertain',host_id='alpha',action='patch',state='recovery_required'))
        s.commit()
    sched.tick(fleet);complete_refreshes(fleet);sched.tick(fleet)
    with Session() as s:
        assert not s.scalar(select(Job.id).where(Job.host_id=='alpha',Job.action=='patch',Job.id!='uncertain'))


def test_pause_cancels_queued_not_running_and_fences_stale_editor(fleet,admin):
    sched.tick(fleet)
    with Session() as s:
        jobs=list(s.scalars(select(Job)));jobs[0].state='running';s.commit();running=jobs[0].id
    existing=admin.get('/api/schedules').json()['schedules'][0]
    changed=admin.put('/api/schedules/schedule',json={**existing,'enabled':False})
    assert changed.status_code==200
    assert admin.put('/api/schedules/schedule',json={**existing,'enabled':False}).status_code==400
    with Session() as s:
        assert s.get(Job,running).state=='running'
        assert sum(j.state=='cancelled' for j in s.scalars(select(Job)))==1
    sched.tick(fleet)
    assert len(runs())==2


def test_expired_patch_is_cancelled_and_failures_not_retried(fleet,monkeypatch):
    monkeypatch.setattr(worker.time,'time',lambda:fleet)
    sched.tick(fleet);complete_refreshes(fleet);sched.tick(fleet)
    sched.tick(fleet+7201)
    assert all(r.state=='skipped' for r in runs())
    with Session() as s: assert all(j.state=='cancelled' for j in s.scalars(select(Job).where(Job.action=='patch')))


def test_dispatcher_first_expiry_is_skipped_not_cancelled(fleet,monkeypatch):
    monkeypatch.setattr(worker.time,'time',lambda:fleet)
    sched.tick(fleet);complete_refreshes(fleet);sched.tick(fleet)
    late=fleet+7201
    with Session() as s:
        for job in s.scalars(select(Job).where(Job.action=='patch')):
            assert sched.job_guard(s,job,late) is False
            assert job.state=='cancelled' and 'expired' in job.output and 'authorization' not in job.output
    assert all(r.state=='skipped' and 'expired' in r.detail for r in runs())
    sched.tick(late)
    assert all(r.state=='skipped' for r in runs())
    operations.collect_alerts()
    with Session() as s:
        Alert=operations.Alert
        kinds={a.kind for a in s.scalars(select(Alert))}
        assert 'scheduled patching' in kinds


def test_failed_refresh_never_patches(fleet):
    sched.tick(fleet)
    with Session() as s:
        for j in s.scalars(select(Job)): j.state='failed'
        s.commit()
    sched.tick(fleet);sched.tick(fleet)
    assert all(r.state=='failed' for r in runs())
    with Session() as s: assert not s.scalar(select(Job.id).where(Job.action=='patch'))


def test_api_approval_validation_roles_and_calendar(admin,fleet):
    assert admin.post('/api/schedules',json={'name':'unsafe','enabled':True}).status_code==422
    for extra in ({'timezone':'invalid/Zone'},{'all_hosts':False},{'host_ids':['missing'],'all_hosts':False},{'minute':1440},{'days':[7]}):
        assert admin.post('/api/schedules',json={'name':'bad',**extra}).status_code in (400,422)
    assert admin.get('/api/schedules/calendar',params={'start':fleet,'end':fleet+86400*63}).status_code==400
    assert admin.get('/api/schedules/calendar',params={'start':'nan','end':fleet}).status_code==400
    result=admin.get('/api/schedules/calendar',params={'start':fleet,'end':fleet+86400*2})
    assert result.status_code==200
    assert len(result.json()['events'])==2
    assert result.json()['events'][0]['servers']==2
    saved=admin.headers.pop('X-CSRF-Token')
    assert admin.post('/api/schedules',json={'name':'safe'}).status_code==403
    admin.headers['X-CSRF-Token']=saved
    with Session() as s:
        s.get(User,'admin').role='operator';s.commit()
    assert admin.get('/api/schedules').status_code==403
    assert admin.post('/api/schedules',json={'name':'safe'}).status_code==403


def test_executor_installs_only_reviewed_exact_versions(fleet,monkeypatch):
    monkeypatch.setattr(worker.time,'time',lambda:fleet)
    sched.tick(fleet);complete_refreshes(fleet);sched.tick(fleet)
    calls=[]
    def call(host,request,**kwargs):
        calls.append(request)
        if request['action']=='health':return {'collector_active':True,'failed_units':[]}
        return {}
    monkeypatch.setattr(worker.ssh,'call',call)
    monkeypatch.setattr(worker,'save_inventory',lambda *args:None)
    job_id=next(r.job_id for r in runs() if r.host_id=='alpha')
    worker.execute(job_id)
    with Session() as s: assert s.get(Job,job_id).state=='complete'
    assert next(r for r in calls if r['action']=='patch')=={'action':'patch','packages':['bash:amd64=2']}
    assert any(r['action']=='health' for r in calls)


def test_urgent_run_skipped_outside_window_is_reissued_when_window_opens(fleet):
    with Session() as s:
        row=s.get(sched.PatchSchedule,'schedule');row.policy={**row.policy,'high':{'enabled':True,'after_minutes':0,'bypass_window':False}}
        for host in ('alpha','beta'):
            s.get(Package,host+':bash:amd64').priority='high'
            s.add(Setting(key='window:'+host,value={'windows':[{'days':[0],'start':600,'end':660}]}))
        s.commit()
    sched.tick(fleet)
    sched.tick(fleet+7201)
    assert all(r.state=='skipped' for r in runs()) and not any(r.job_id for r in runs())
    opened=fleet+8*3600
    with Session() as s:
        for h in s.scalars(select(Host)):h.last_seen=opened
        s.commit()
    before=len(runs())
    sched.tick(opened)
    fresh=[r for r in runs() if r.state!='skipped']
    assert len(runs())>before and fresh and all(r.trigger=='high' for r in fresh)
    sched.tick(opened+1)
    assert len(runs())==before+len(fresh)


def test_urgent_failed_batch_is_not_reissued(fleet,monkeypatch):
    monkeypatch.setattr(worker.time,'time',lambda:fleet)
    with Session() as s:
        row=s.get(sched.PatchSchedule,'schedule');row.policy=policy(enabled=True,approved=True,frequency='daily',minute=180,high={'enabled':True,'after_minutes':0})
        for p in s.scalars(select(Package)):p.priority='high'
        s.commit()
    sched.tick(fleet);complete_refreshes(fleet);sched.tick(fleet)
    with Session() as s:
        for j in s.scalars(select(Job).where(Job.action=='patch')):j.state='failed'
        s.commit()
    for _ in range(3):sched.tick(fleet)
    assert len(runs())==2 and all(r.state=='failed' for r in runs())
    operations.collect_alerts()
    with Session() as s:assert len(list(s.scalars(select(operations.Alert).where(operations.Alert.kind=='scheduled patching'))))==2


def test_hourly_calendar_includes_window_crossing_midnight(fleet):
    with Session() as s:
        row=s.get(sched.PatchSchedule,'schedule');row.policy={**row.policy,'minute':23*60,'window_minutes':180}
        s.commit()
        start=stamp('2026-06-02T00:00:00+00:00')
        events=sched.calendar(s,start,start+86400)
        assert any(e['start']<start<e['end'] for e in events)


def test_claim_rechecks_authorization_and_window(fleet,monkeypatch):
    monkeypatch.setattr(worker.time,'time',lambda:fleet)
    sched.tick(fleet);complete_refreshes(fleet);sched.tick(fleet)
    with Session() as s:
        job=s.get(Job,next(r.job_id for r in runs() if r.host_id=='alpha'))
        s.add(Setting(key='window:alpha',value={'windows':[{'days':[0],'start':600,'end':660}]}));s.commit()
        assert operations.eligible(s,job) is False
        with pytest.raises(ValueError,match='maintenance window closed'):sched.validate_selection(s,s.get(Host,'alpha'),job)
        row=s.get(sched.PatchSchedule,'schedule');row.revision+=1;s.commit()
        assert operations.eligible(s,job) is False
        assert job.state=='cancelled'


def test_deleted_schedule_cannot_spawn_after_refresh(fleet,admin):
    sched.tick(fleet)
    assert admin.request('DELETE','/api/schedules/schedule',json={'revision':1}).status_code==200
    complete_refreshes(fleet);sched.tick(fleet)
    with Session() as s:
        assert not s.scalar(select(Job.id).where(Job.action=='patch'))
        assert all(r.state=='cancelled' for r in s.scalars(select(sched.PatchRun)))
