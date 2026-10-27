import copy
import time
import uuid
import pytest
from app import response_monitor as monitor,worker,quarantine,incidents,operations,agent_maintenance
from app.db import Session,Job,Setting
from app.identity import User
from test_quarantine import scenario,row,approve,BASE


def report(record,state='verified'):
    facts={'journal_verified':True,'parents_match':True,'held_present':True,'source_present':False,'held_verified':True}
    receipt={'id':record['id'],'plan':copy.deepcopy(record['plan']),'state':'quarantined','restore_ready':True,'restore_attempted':False}
    if state=='path_occupied':facts['source_present']=True;receipt.update(state='uncertain',restore_ready=False)
    if state=='held_unverified':facts['held_verified']=False;receipt=None
    if state in ('missing','unavailable'):
        facts={'journal_verified':False,'parents_match':None,'held_present':None,'source_present':None,'held_verified':False};receipt=None
    if state=='restored':facts.update(held_present=False,source_present=True,held_verified=False);receipt.update(state='restored',restore_ready=False,restore_attempted=True)
    return {'version':1,'id':record['id'],'plan_digest':record['plan_digest'],'state':state,'facts':facts,'receipt':receipt}


@pytest.fixture
def retained(admin,scenario,monkeypatch):
    action=approve(admin,row(admin));worker.execute(action.json()['job_id']);record=row(admin)
    released=admin.post(BASE+'/quarantines/'+record['id']+'/release',json={'plan_digest':record['plan_digest'],'receipt_digest':record['receipt_digest'],'reason':'Reviewed the application and accepted quarantine impact.','confirmation':'KEEP QUARANTINED'})
    assert released.status_code==200
    original=worker.ssh.call;control={'state':'verified','fail':False,'calls':[]}
    def remote(host,request,**kwargs):
        if request['action']!='quarantine-audit':return original(host,request,**kwargs)
        control['calls'].append(copy.deepcopy(request))
        if control['fail']:raise TimeoutError('secret fixture content must never appear in check history')
        return report(record,control['state'])
    monkeypatch.setattr(worker.ssh,'call',remote)
    return control


def configure(admin,**changes):
    current=admin.get(BASE+'/response-monitor').json()['policy']
    return admin.put(BASE+'/response-monitor',json={**current,'enabled':True,'interval_minutes':5,'expected_revision':current['revision'],**changes})


def queue(admin,advance=601):
    monitor.schedule_tick(time.time()+advance)
    with Session() as s:return s.query(Job).filter_by(action='quarantine-audit',state='queued').one().id


def checks(admin,record):return admin.get(BASE+'/quarantines/'+record['id']+'/checks').json()['items']


def test_default_off_interval_deduplication_and_readonly_receipt(admin,retained):
    monitor.schedule_tick(time.time()+10000)
    with Session() as s:assert not s.query(Job).filter_by(action='quarantine-audit').count()
    assert configure(admin).status_code==200
    identifier=queue(admin);monitor.schedule_tick(time.time()+10000)
    with Session() as s:assert s.query(Job).filter_by(action='quarantine-audit').count()==1
    worker.execute(identifier);record=row(admin)
    assert record['state']=='quarantined' and not record['hold'] and len(retained['calls'])==1
    proof=checks(admin,record)[0];assert proof['state']=='verified' and proof['report']['plan_digest']==record['plan_digest']
    assert 'plan' not in proof['report'] and 'content' not in str(proof['report'])
    assert admin.get(BASE+'/response-monitor').json()['problem_count']==0
    monitor.schedule_tick(time.time()+10)
    with Session() as s:assert s.query(Job).filter_by(action='quarantine-audit').count()==1


@pytest.mark.parametrize('state',['path_occupied','held_unverified','missing'])
def test_alerts_and_optional_pause_preserve_history_and_incident(admin,retained,state):
    configure(admin);retained['state']=state;identifier=queue(admin);worker.execute(identifier);record=row(admin)
    assert record['state']=='uncertain' and not record['hold'] and not record['receipt']
    with Session() as s:
        assert s.get(Job,identifier).state=='failed'
        assert s.query(incidents.Incident).one().state=='open'
    operations.collect_alerts()
    with Session() as s:assert s.query(operations.Alert).filter_by(kind='response integrity').one().state=='open'
    configure(admin,pause_on_problem=True);identifier=queue(admin);worker.execute(identifier)
    assert row(admin)['hold'] and len(checks(admin,record))==2
    # Turning off the policy does not erase the latest problem or release its hold.
    configure(admin,enabled=False);operations.collect_alerts()
    assert row(admin)['hold']
    with Session() as s:assert s.query(operations.Alert).filter_by(kind='response integrity').one().state=='open'


def test_unavailable_helper_records_no_target_claim_or_old_readiness(admin,retained,monkeypatch):
    configure(admin,pause_on_problem=True)
    monkeypatch.setattr(agent_maintenance,'inspect',lambda *a,**k:{'state':'unavailable'})
    identifier=queue(admin);worker.execute(identifier);record=row(admin)
    assert not retained['calls'] and record['hold'] and not record['receipt']
    proof=checks(admin,record)[0]
    assert proof['state']=='unavailable' and proof['report']['failure']=={'stage':'helper','type':'ValueError'}


@pytest.mark.parametrize('change',['policy','watch','during_health'])
def test_changed_queued_authorization_prevents_remote_audit(admin,retained,monkeypatch,change):
    configure(admin);identifier=queue(admin);record=row(admin)
    if change=='policy':configure(admin,enabled=False)
    elif change=='watch':
        assert admin.put(BASE+'/quarantines/'+record['id']+'/watch',json={'enabled':False,'expected_revision':'','plan_digest':record['plan_digest'],'reason':'Retire this response after reviewing the retained evidence.'}).status_code==200
    else:
        def changed(s,host,**kwargs):
            with Session() as other:
                setting=other.get(Setting,'response-monitor:'+host.id);setting.value={**setting.value,'enabled':False,'revision':'new'};other.commit()
            return {'state':'current'}
        monkeypatch.setattr(agent_maintenance,'inspect',changed)
    worker.execute(identifier)
    assert not retained['calls'] and checks(admin,record)[0]['state']=='skipped'
    assert row(admin)['state']=='quarantined' and not row(admin)['hold']


def test_outage_and_later_manual_verification_retain_failed_receipt(admin,retained):
    configure(admin);retained['fail']=True;worker.execute(queue(admin));record=row(admin)
    proof=checks(admin,record)[0];assert proof['state']=='unavailable'
    assert 'secret fixture' not in str(proof)
    retained['fail']=False
    queued=admin.post(BASE+'/quarantines/'+record['id']+'/status',json={});worker.execute(queued.json()['job_id'])
    assert admin.get(BASE+'/response-monitor').json()['problem_count']==0
    assert checks(admin,record)[0]['state']=='unavailable'


def test_policy_disabled_during_remote_read_does_not_create_pause(admin,retained,monkeypatch):
    configure(admin,pause_on_problem=True);identifier=queue(admin);record=row(admin)
    def disabled(*args,**kwargs):
        with Session() as other:
            setting=other.get(Setting,'response-monitor:response-host');setting.value={**setting.value,'enabled':False,'revision':'changed-during-read'};other.commit()
        return report(record,'path_occupied')
    monkeypatch.setattr(worker.ssh,'call',disabled)
    worker.execute(identifier)
    assert row(admin)['state']=='uncertain' and not row(admin)['hold']
    assert checks(admin,record)[0]['state']=='path_occupied'
    assert checks(admin,record)[0]['report']['pause_on_problem'] is False


@pytest.mark.parametrize('change',['identity','positive_facts','version'])
def test_unbound_or_false_positive_reports_never_become_verified(admin,retained,monkeypatch,change):
    configure(admin);identifier=queue(admin);record=row(admin);bad=report(record)
    if change=='identity':bad['id']='different-response'
    if change=='positive_facts':bad['facts']['source_present']=True
    if change=='version':bad['version']=True
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:bad)
    worker.execute(identifier)
    assert row(admin)['state']=='uncertain' and not row(admin)['receipt']
    assert checks(admin,record)[0]['state']=='unavailable'


def test_retiring_watch_requires_review_and_never_clears_hold(admin,retained):
    configure(admin,pause_on_problem=True);retained['state']='path_occupied';worker.execute(queue(admin));record=row(admin)
    url=BASE+'/quarantines/'+record['id']+'/watch'
    body={'enabled':False,'expected_revision':'','plan_digest':record['plan_digest'],'reason':'Reviewed and explicitly retired this response watch.'}
    assert admin.put(url,json=body).status_code==200
    assert admin.put(url,json=body).status_code==409
    assert row(admin)['hold'] and checks(admin,record)
    assert admin.get(BASE+'/response-monitor').json()['watched']==0
    with Session() as s:assert s.query(quarantine.Event).filter_by(kind='watch_reviewed').one().details['reason']==body['reason']


def test_round_robin_defers_for_busy_jobs_but_checks_own_hold(admin,retained):
    configure(admin);record=row(admin)
    with Session() as s:
        other=quarantine.Quarantine(id=str(uuid.uuid4()),host_id='response-host',incident_id='old',archive_id='archive',state='quarantined',hold=False,fingerprint='pin',evidence_digest='b'*64,plan=record['plan'],created=1,observed=1)
        s.add(other);s.commit();second=other.id
        busy=worker.enqueue(s,'response-host','refresh')
    monitor.schedule_tick(time.time()+601)
    with Session() as s:
        assert not s.query(Job).filter_by(action='quarantine-audit').count()
        s.get(Job,busy).state='cancelled';s.commit()
    identifier=queue(admin)
    with Session() as s:assert s.get(Job,identifier).payload['quarantine_id']==second
    # Own-response holds allow verification even with deferred ordinary work.
    with Session() as s:
        s.get(Job,identifier).state='cancelled';s.get(quarantine.Quarantine,record['id']).hold=True
        worker.enqueue(s,'response-host','refresh')
    identifier=queue(admin)
    with Session() as s:assert s.get(Job,identifier).payload['quarantine_id']==record['id']


def test_stale_coverage_policy_conflicts_pagination_and_role_boundaries(admin,retained):
    configure(admin);record=row(admin)
    with Session() as s:s.get(quarantine.Quarantine,record['id']).observed=time.time()-4000;s.commit()
    assert admin.get(BASE+'/response-monitor').json()['overdue_count']==1
    operations.collect_alerts()
    with Session() as s:assert s.query(operations.Alert).filter_by(kind='response verification').one().state=='open'
    assert admin.put(BASE+'/response-monitor',json={'enabled':True,'expected_revision':''}).status_code==409
    assert admin.get(BASE+'/quarantines/'+record['id']+'/checks?offset=-1').status_code==400
    assert admin.get(BASE.replace('response-host','other')+'/quarantines/'+record['id']+'/checks').status_code==404
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(BASE+'/response-monitor').status_code==403
        assert admin.put(BASE+'/response-monitor',json={}).status_code==403
        assert admin.get(BASE+'/quarantines/'+record['id']+'/checks').status_code==403
        assert admin.put(BASE+'/quarantines/'+record['id']+'/watch',json={'enabled':False,'expected_revision':'','plan_digest':record['plan_digest'],'reason':'Reviewed this retained response watch.'}).status_code==403


def test_retired_records_do_not_consume_active_monitoring_scope(admin,retained,monkeypatch):
    configure(admin);record=row(admin);monkeypatch.setattr(monitor,'LIMIT',1)
    with Session() as s:
        old=quarantine.Quarantine(id=str(uuid.uuid4()),host_id='response-host',incident_id='old',archive_id='archive',state='quarantined',hold=False,fingerprint='pin',evidence_digest='b'*64,plan=record['plan'],created=1,observed=1)
        s.add(old);s.add(Setting(key='response-watch:'+old.id,value={'enabled':False,'revision':'retired'}));s.commit()
    result=admin.get(BASE+'/response-monitor').json()
    assert result['watched']==1 and not result['scope_limited']
    identifier=queue(admin)
    with Session() as s:assert s.get(Job,identifier).payload['quarantine_id']==record['id']


def test_pinned_host_change_cannot_retarget_an_existing_check(admin,retained):
    from app.db import Host
    configure(admin);identifier=queue(admin);record=row(admin)
    with Session() as s:s.get(Host,'response-host').fingerprint='different-pin';s.commit()
    worker.execute(identifier)
    assert not retained['calls'] and checks(admin,record)[0]['state']=='skipped'
    assert admin.get(BASE+'/response-monitor').json()['problems'][0]['state']=='identity_changed'
