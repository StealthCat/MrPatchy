import json
import time
import pytest
from sqlalchemy import select
from app import ai_runs, scheduling, update_scores
from app.db import Session, Host, Package, Behavior, Job, Setting
from app.identity import User


@pytest.fixture
def servers(admin):
    now=time.time()
    with Session() as s:
        for identifier in ('alpha','beta'):
            s.add(Host(id=identifier,name=identifier,address='192.0.2.1',fingerprint='SHA256:test',state='online',last_seen=now,
                last_repo=now,inventory={'os':'ID=debian','architecture':'amd64','files':{'private':'sensitive repository config'},
                'machine_id':identifier+'-machine','collected':now},telemetry={'collected':now,'hashed_at':now,'processes':[{'secret':'process arguments'}]},baseline={'private':'hash'}))
            s.add(Package(id=identifier+':bash',host_id=identifier,name='bash',installed='1',candidate='2',priority='critical',available_since=now-86400*2))
            s.add(Behavior(id=identifier,host_id=identifier,evidence={'executable':'/'+identifier},verdict='pending'))
            s.add(Job(id=identifier,host_id=identifier,action='patch',state='complete',output=identifier+' output',payload={'secret':'private job payload'},created=now))
        s.commit()
    return now


def test_summary_is_scoped_and_uses_explicit_safe_fields(admin,servers):
    with Session() as s:
        s.add(Package(id='beta:other',host_id='beta',name='other',installed='1'))
        s.add(Behavior(id='beta-other',host_id='beta',evidence={},approved=True));s.commit()
    response=admin.get('/api/hosts/alpha/summary');assert response.status_code==200
    data=response.json()
    assert data['host']['id']=='alpha' and data['system']['machine_id']=='alpha-machine'
    assert data['counts']=={'packages':1,'updates':1,'held':0,'overdue':1,'investigations':1,'unapproved':1,'pending_ai':1}
    assert data['last_patch']['id']=='alpha' and data['collector']['processes']==1
    assert not any(value in response.text for value in ('sensitive repository','process arguments','private job payload','beta-machine'))
    assert not {'inventory','telemetry','baseline'} & data['host'].keys()


def test_host_filters_apply_before_pagination(admin,servers):
    with Session() as s:
        for n in range(110):
            s.add(Job(id='beta-'+str(n),host_id='beta',action='patch',created=servers+100+n))
            s.add(Behavior(id='beta-'+str(n),host_id='beta',evidence={},last_seen=servers+100+n))
        s.add(Job(id='alpha-old',host_id='alpha',action='refresh',created=servers-100));s.commit()
    assert [r['id'] for r in admin.get('/api/jobs?host_id=alpha&limit=1').json()]==['alpha']
    assert [r['id'] for r in admin.get('/api/jobs?host_id=alpha&limit=1&offset=1').json()]==['alpha-old']
    assert [r['id'] for r in admin.get('/api/investigations?host_id=alpha&limit=1').json()]==['alpha']
    assert admin.get('/api/investigations?host_id=alpha&limit=1&offset=1').json()==[]
    assert 'payload' not in admin.get('/api/jobs?host_id=alpha').json()[0]


def test_ai_filter_recovers_legacy_batch_links_and_keeps_new_membership(admin,servers):
    with ai_runs.track('triage','fixture',host_id='alpha') as triage: pass
    with ai_runs.track('update_scoring','fixture',host_ids=['alpha','beta']) as shared: pass
    with ai_runs.track('update_scoring','fixture',host_ids=['alpha']) as single: pass
    with Session() as s:
        s.add(ai_runs.AIRun(id='legacy-batch',purpose='update_scoring',state='complete'))
        s.add(update_scores.UpdateScore(id='old-score',host_id='alpha',name='bash',installed='1',candidate='2',run_id='legacy-batch'))
        # Lots of newer unrelated activity must not crowd out this server's older runs.
        for n in range(110):s.add(ai_runs.AIRun(id='unrelated-'+str(n),purpose='triage',host_id='beta',started=servers+100+n))
        s.commit()
    result=admin.get('/api/ai/runs?host_id=alpha').json()['items']
    assert {r['id'] for r in result}=={triage,shared,single,'legacy-batch'}
    assert next(r for r in result if r['id']==shared)['shared_batch']
    assert not next(r for r in result if r['id']==single)['shared_batch']
    with Session() as s:s.delete(s.get(update_scores.UpdateScore,'old-score'));s.commit()
    # Durable memberships stay visible independently of current score rows.
    result=admin.get('/api/ai/runs?host_id=alpha&purpose=update_scoring').json()['items']
    assert {r['id'] for r in result}=={shared,single}
    page=admin.get('/api/ai/runs?host_id=alpha&limit=1').json()
    assert len(page['items'])==1 and page['more']


def test_calendar_contains_only_assigned_windows_and_this_hosts_run_states(admin,servers):
    # Fixed date makes recurrence assertions independent of the execution clock.
    start=1780272000;end=start+86400
    def policy(name,host_ids,all_hosts=False):
        return scheduling.ScheduleInput(name=name,enabled=True,approved=True,frequency='daily',timezone='UTC',minute=120,
            all_hosts=all_hosts,host_ids=host_ids).model_dump(exclude={'revision','approved'})
    with Session() as s:
        for name,ids,all_hosts in [('alpha-only',['alpha'],False),('beta-only',['beta'],False),('fleet',[],True)]:
            s.add(scheduling.PatchSchedule(id=name,policy=policy(name,ids,all_hosts),updated=start-86400))
        for host,state in [('alpha','complete'),('beta','failed')]:
            s.add(scheduling.PatchRun(id=host,schedule_id='fleet',revision=1,host_id=host,trigger='regular',due=start+7200,expires=start+10800,state=state))
        s.add(Setting(key='window:alpha',value={'windows':[{'days':[0],'start':60,'end':180}]}));s.commit()
    data=admin.get(f'/api/hosts/alpha/patching?start={start}&end={end}').json()
    assert {p['name'] for p in data['schedules']}=={'alpha-only','fleet'}
    assert all('host_ids' not in p for p in data['schedules'])
    assert {e['title'] for e in data['events']}=={'alpha-only','fleet'}
    fleet=next(e for e in data['events'] if e['title']=='fleet')
    assert fleet['states']=={'complete':1} and fleet['servers']==1
    assert data['windows']==[{'days':[0],'start':60,'end':180}]
    with Session() as s:
        fleet=next(e for e in scheduling.calendar(s,start,end) if e['title']=='fleet')
        assert fleet['states']=={'complete':1,'failed':1} and fleet['servers']==2


@pytest.mark.parametrize('path', ['/summary','/snapshot','/patching?start=1&end=2'])
def test_missing_server_is_404(admin,path):
    assert admin.get('/api/hosts/missing'+path).status_code==404


@pytest.mark.parametrize('path', ['/api/jobs?host_id=missing','/api/investigations?host_id=missing','/api/ai/runs?host_id=missing',
    '/api/package-history?host_id=missing'])
def test_missing_server_filter_is_404(admin,path):
    assert admin.get(path).status_code==404


@pytest.mark.parametrize('path', ['/api/jobs?offset=-1','/api/jobs?limit=101','/api/investigations?limit=501',
    '/api/investigations?offset=-1','/api/hosts/alpha/patching?start=1&end=999999999',
    '/api/hosts/alpha/patching?start=nan&end=10'])
def test_invalid_filters_are_rejected(admin,servers,path):
    assert admin.get(path).status_code==400


@pytest.mark.parametrize('role',['viewer','operator'])
def test_monitoring_tabs_remain_readable_but_sensitive_data_stays_admin_only(admin,servers,role):
    with Session() as s:s.get(User,'admin').role=role;s.commit()
    for path in ['/api/hosts/alpha/summary','/api/hosts/alpha/patching?start=1&end=2','/api/jobs?host_id=alpha',
                 '/api/investigations?host_id=alpha','/api/package-history?host_id=alpha','/api/hosts/alpha/packages']:
        assert admin.get(path).status_code==200,path
    for path in ['/api/hosts/alpha/snapshot','/api/hosts/alpha/history','/api/ai/runs?host_id=alpha','/api/hosts/alpha/repositories']:
        assert admin.get(path).status_code==403,path
    assert admin.put('/api/operations/alpha/window',json={'windows':[]}).status_code==403
    assert admin.put('/api/investigations/alpha',json={'approved':True}).status_code==403


def test_admin_snapshot_is_current_and_scoped(admin,servers):
    data=admin.get('/api/hosts/alpha/snapshot').json()
    assert data['inventory']['machine_id']=='alpha-machine'
    assert data['telemetry']['processes']==[{'secret':'process arguments'}]
    assert data['baseline']=={'private':'hash'}
