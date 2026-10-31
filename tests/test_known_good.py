import copy
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy import select

from app import ai, ai_assessments, ai_runs, known_good, worker
from app.db import Audit, Behavior, Host, Session, Setting
from app.incidents import Inspection
from app.security import seal


def sha(letter):
    return letter * 64


def complete():
    snapshot = {
        'executable': '/usr/bin/fixture', 'sha256': sha('a'), 'identity_verified': True,
        'host_id': 'host-one', 'observed': 100,
        'investigation': {'details': {
            'version': 2, 'identity_verified': True,
            'context': {'version': 1, 'process': {'pid': 10, 'start_ticks': 20},
                'coverage': {'scope': 'recorded_process_identity', 'gaps': []}},
            'known_good_context': {
                'version': 1,
                'artifact': {'version': 1, 'verified': True, 'path': '/usr/bin/fixture',
                    'sha256': sha('a'), 'manifest_sha256': sha('b'), 'kind': 'elf'},
                'provenance': {'version': 1, 'verified': True, 'scheme': 'vendor-signature',
                    'subject': 'fixture-package', 'release': '1.0-1',
                    'manifest_sha256': sha('c'), 'proof_sha256': sha('d')},
                'configuration': {'version': 1, 'complete': True, 'manifest_sha256': sha('e')},
                'behavior': {'version': 1, 'complete': True, 'manifest_sha256': sha('f'),
                    'privileges_sha256': sha('1'), 'startup_sha256': sha('2'),
                    'network_sha256': sha('3'), 'execution_sha256': sha('4'),
                    'memory_sha256': sha('5')},
                'followup': {'version': 1, 'complete': True, 'requirements_sha256': sha('6'),
                    'evidence_sha256': sha('7'), 'policy_version': 'process-followup-v1'},
                'coverage': {'version': 1, 'complete': True, 'manifest_sha256': sha('8'), 'gaps': []},
                'observation': {'host_id': 'host-one', 'pid': 10, 'start_ticks': 20,
                    'collected': 100, 'ephemeral_source_ports': [49152]},
            },
        }},
    }
    return snapshot


def evaluate(snapshot=None, **overrides):
    values = {'snapshot': snapshot or complete(), 'model': 'gpt-fixture',
        'policy_hash': sha('9'), 'result': {'risk': 'low', 'explanation': 'Safe with complete evidence',
            'recommended_checks':'Continue deterministic monitoring','requested_checks':[]},
        'source': 'ai'}
    values.update(overrides)
    return known_good.evaluate(**values)


def codes(result):
    return [reason['code'] for reason in result['reasons']]


def retained(id='assessment-one',host='host-one',subject='behavior-one',snapshot=None,
        result=None,source='ai'):
    return ai_assessments.Assessment(id=id,subject=subject,host_id=host,source=source,
        model='gpt-fixture',policy_hash=sha('9'),state_hash=sha('0'),
        result=result or {'risk':'low','explanation':'Safe with complete evidence',
            'recommended_checks':'Continue deterministic monitoring','requested_checks':[]},
        snapshot=snapshot or complete(),inputs=[])


def test_complete_contract_creates_non_published_candidate():
    result = evaluate()
    assert result == {'version': 1, 'eligible': True, 'published': False,
        'fingerprint': result['fingerprint'], 'reasons': []}
    assert len(result['fingerprint']) == 64


def test_host_process_time_and_ephemeral_port_observations_do_not_change_fingerprint():
    first = complete(); second = copy.deepcopy(first)
    second['host_id'] = 'host-two'; second['observed'] = 999
    second['investigation']['details']['context']['process'] = {'pid': 999, 'start_ticks': 888}
    second['investigation']['details']['known_good_context']['observation'] = {
        'host_id': 'host-two', 'pid': 999, 'start_ticks': 888, 'boot_id': 'other',
        'collected': 999, 'ephemeral_source_ports': [60000],
    }
    assert evaluate(first)['fingerprint'] == evaluate(second)['fingerprint']


@pytest.mark.parametrize('component,field',[('artifact','manifest_sha256'),('provenance','proof_sha256'),
    ('configuration','manifest_sha256'),('behavior','network_sha256'),
    ('followup','evidence_sha256'),('coverage','manifest_sha256')])
def test_every_security_manifest_changes_the_fingerprint(component,field):
    changed = complete()
    changed['investigation']['details']['known_good_context'][component][field] = sha('0')
    assert evaluate(changed)['fingerprint'] != evaluate()['fingerprint']


@pytest.mark.parametrize('component,marker',[('artifact','verified'),('provenance','verified'),
    ('configuration','complete'),('behavior','complete'),('followup','complete'),('coverage','complete')])
def test_unverified_or_incomplete_components_are_explicit_misses(component,marker):
    snapshot = complete();snapshot['investigation']['details']['known_good_context'][component][marker] = False
    result = evaluate(snapshot)
    assert not result['eligible'] and not result['fingerprint']
    assert any(code.startswith(component+'_binding') for code in codes(result))


def test_host_fields_inside_canonical_components_are_rejected_not_silently_ignored():
    snapshot = complete();snapshot['investigation']['details']['known_good_context']['behavior']['host_id'] = 'leak'
    result = evaluate(snapshot)
    assert not result['eligible'] and 'observation_fields_invalid' in codes(result)


@pytest.mark.parametrize('changes,reason',[
    ({'source': 'legacy'}, 'source_not_ai'),
    ({'result': {'risk': 'medium', 'explanation': 'Not safe'}}, 'result_not_safe'),
    ({'model': ''}, 'model_missing'),
    ({'policy_hash': ''}, 'policy_binding_missing'),
])
def test_assessment_provenance_and_policy_fail_closed(changes,reason):
    result = evaluate(**changes)
    assert not result['eligible'] and reason in codes(result)


def test_safe_candidate_requires_a_complete_final_provider_result():
    result=evaluate(result={'risk':'low','explanation':'More evidence is required',
        'recommended_checks':'Collect executable details','requested_checks':['executable']})
    assert not result['eligible'] and codes(result)==['result_not_safe']


def test_current_partial_receipt_is_a_miss_without_guessing_missing_context():
    snapshot = {'executable': '/usr/bin/fixture', 'sha256': sha('a'), 'identity_verified': True,
        'investigation': {'details': {'version': 2, 'identity_verified': True,
            'context': {'coverage': {'scope': 'recorded_process_identity',
                'gaps': ['package_authentication_missing']}}}}}
    result = evaluate(snapshot)
    assert not result['eligible'] and result['fingerprint'] == ''
    assert codes(result) == ['coverage_incomplete', 'known_good_context_missing']


def test_malformed_saved_coverage_fails_closed_without_breaking_history():
    snapshot = complete();snapshot['investigation']['details']['context']['coverage'] = ['untrusted']
    result = evaluate(snapshot)
    assert not result['eligible']
    assert {'coverage_incomplete', 'recorded_process_not_bound'} <= set(codes(result))


def test_model_and_policy_are_part_of_the_exact_match_contract():
    baseline = evaluate()['fingerprint']
    assert evaluate(model='other-model')['fingerprint'] != baseline
    assert evaluate(policy_hash=sha('0'))['fingerprint'] != baseline


def test_eligible_assessment_is_published_with_minimal_isolated_provenance(client):
    with Session() as s:
        row=retained();s.add(row)
        status=known_good.publish(s,row);s.commit()
        entry=s.get(known_good.Entry,status['fingerprint'])
        observation=s.get(known_good.Observation,row.id)
        actions=list(s.scalars(select(Audit.action).where(
            Audit.action.in_(['publish known-good candidate','link known-good observation']))))
    assert status['eligible'] and status['published']
    assert entry.assessment_id==row.id and entry.source_host_id=='host-one'
    assert set(entry.contract)=={'version',*known_good.COMPONENTS}
    assert 'observation' not in entry.contract and 'host_id' not in str(entry.contract)
    assert observation.observation==complete()['investigation']['details']['known_good_context']['observation']
    assert sorted(actions)==['link known-good observation','publish known-good candidate']


def test_assessment_api_reports_only_an_active_durable_publication(admin):
    with Session() as s:
        s.add(Host(id='host-one',name='Fixture',address='192.0.2.10',fingerprint=''))
        s.add(Behavior(id='behavior-one',host_id='host-one',evidence=complete(),verdict='low'))
        row=retained();s.add(row);status=known_good.publish(s,row);s.commit()
    response=admin.get('/api/investigations/behavior-one/history/'+row.id)
    assert response.status_code==200
    reported=response.json()['known_good']
    assert all(reported[key]==value for key,value in status.items())
    assert reported['active'] and not reported['review_required']
    assert reported['linked_assessments']==1


def test_lookup_revalidates_exact_context_policy_and_active_state(client):
    row=retained()
    with Session() as s:
        s.add(row);published=known_good.publish(s,row);s.commit()
        hit=known_good.lookup(s,complete(),'gpt-fixture',[sha('0'),sha('9')])
        assert hit['fingerprint']==published['fingerprint']
        assert hit['assessment_id']==row.id and hit['source_host_id']=='host-one'
        assert known_good.lookup(s,complete(),'other-model',[sha('9')]) is None
        assert known_good.lookup(s,complete(),'gpt-fixture',[sha('9')],bypass=True) is None
        changed=complete()
        changed['investigation']['details']['known_good_context']['behavior']['network_sha256']=sha('0')
        assert known_good.lookup(s,changed,'gpt-fixture',[sha('9')]) is None
        s.get(known_good.Entry,published['fingerprint']).active=False;s.commit()
        assert known_good.lookup(s,complete(),'gpt-fixture',[sha('9')]) is None


def test_worker_exact_match_reuses_without_provider_call_and_retains_host_provenance(client,monkeypatch):
    current=complete();current['host_id']='host-two'
    current['investigation']['details']['context']['process']={'pid':99,'start_ticks':88}
    current['investigation']['details']['known_good_context']['observation']={
        'host_id':'host-two','pid':99,'start_ticks':88,'collected':900}
    policy_hash=ai_assessments.digest([ai.investigation_policy()])
    source=retained(snapshot=complete());source.policy_hash=policy_hash
    with Session() as s:
        s.add_all([Host(id='host-one',name='Source',address='192.0.2.1',fingerprint=''),
            Host(id='host-two',name='Current',address='192.0.2.2',fingerprint=''),source,
            Behavior(id='behavior-two',host_id='host-two',evidence=current,verdict='pending')])
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'gpt-fixture'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        published=known_good.publish(s,source);s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:pytest.fail('exact cache hit called provider'))
    worker.investigate_one()
    with Session() as s:
        behavior=s.get(Behavior,'behavior-two')
        saved=s.scalar(select(ai_assessments.Assessment).where(
            ai_assessments.Assessment.subject=='behavior-two'))
        run=s.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject=='behavior-two'))
        observation=s.get(known_good.Observation,saved.id)
        status=known_good.assessment(saved,s)
        event=s.scalar(select(Audit).where(Audit.action=='reuse known-good candidate'))
    assert behavior.verdict=='low' and saved.source=='known_good' and saved.inputs==[]
    assert saved.result['known_good_reuse']['fingerprint']==published['fingerprint']
    assert run.state=='complete' and run.calls==0
    assert observation.host_id=='host-two' and status['reused'] and status['published']
    assert event and published['fingerprint'] in event.detail


def test_admin_revocation_blocks_reuse_and_marks_every_linked_assessment_for_review(admin):
    current=complete();current['host_id']='host-two'
    current['investigation']['details']['known_good_context']['observation']={
        'host_id':'host-two','pid':99,'start_ticks':88,'collected':900}
    source=retained()
    behavior_one=Behavior(id='behavior-one',host_id='host-one',evidence=complete(),verdict='low')
    behavior_two=Behavior(id='behavior-two',host_id='host-two',evidence=current,verdict='low')
    with Session() as s:
        s.add_all([Host(id='host-one',name='Source',address='192.0.2.1',fingerprint=''),
            Host(id='host-two',name='Current',address='192.0.2.2',fingerprint=''),
            behavior_one,behavior_two,source])
        published=known_good.publish(s,source);s.flush()
        hit=known_good.lookup(s,current,'gpt-fixture',[sha('9')])
        reused=ai_assessments.record_reuse(s,behavior_two,hit);s.flush()
        known_good.link_reuse(s,reused,hit);s.commit()

    reason='A new deterministic detector requires fleet review'
    response=admin.post('/api/ai/known-good/'+published['fingerprint']+'/revoke',json={
        'expected_version':1,'reason':reason})
    assert response.status_code==200
    assert response.json()['linked_assessments']==2 and response.json()['review_required']
    with Session() as s:
        entry=s.get(known_good.Entry,published['fingerprint'])
        event=s.scalar(select(Audit).where(Audit.action=='revoke known-good candidate'))
        assert not entry.active and entry.revoked_by=='admin' and entry.revoked_reason==reason
        assert event and reason in event.detail and 'linked=2' in event.detail
        assert known_good.lookup(s,current,'gpt-fixture',[sha('9')]) is None

    original=admin.get('/api/investigations/behavior-one/history/'+source.id).json()['known_good']
    linked=admin.get('/api/investigations/behavior-two/history/'+reused.id).json()['known_good']
    for status in (original,linked):
        assert status['eligible'] and not status['published'] and not status['active']
        assert status['review_required'] and status['linked_assessments']==2
        assert status['revoked_by']=='admin' and status['revoked_reason']==reason
    assert linked['reused'] and linked['source_assessment_id']==source.id


def test_revocation_enforces_role_csrf_lock_version_reason_and_current_state(admin):
    from app.identity import User
    row=retained()
    with Session() as s:
        s.add(row);published=known_good.publish(s,row);s.commit()
    path='/api/ai/known-good/'+published['fingerprint']+'/revoke'
    body={'expected_version':1,'reason':'Review this candidate across the fleet'}

    assert admin.post(path,json=body,headers={'X-CSRF-Token':'wrong'}).status_code==403
    with Session() as s:s.get(User,'admin').role='viewer';s.commit()
    assert admin.post(path,json=body).status_code==403
    with Session() as s:s.get(User,'admin').role='admin';s.commit()
    assert admin.post(path,json={**body,'expected_version':2}).status_code==409
    assert admin.post(path,json={**body,'reason':' short '}).status_code==422
    lock=worker.Lock('ai-triage');assert lock.acquire(False)
    try:assert admin.post(path,json=body).status_code==409
    finally:lock.release()
    assert admin.post('/api/ai/known-good/not-a-fingerprint/revoke',json=body).status_code==400
    assert admin.post(path,json=body).status_code==200
    assert admin.post(path,json=body).status_code==409


def test_explicit_retriage_bypasses_exact_match_and_calls_provider(client,monkeypatch):
    current=complete();current['host_id']='host-two'
    current['investigation']['details']['known_good_context']['observation']['host_id']='host-two'
    policy_hash=ai_assessments.digest([ai.investigation_policy()])
    source=retained(snapshot=complete());source.policy_hash=policy_hash
    behavior=Behavior(id='behavior-two',host_id='host-two',evidence=current,verdict='pending')
    refresh=ai_assessments.Refresh(subject=behavior.id,id='refresh-two',actor='admin',
        reason='Explicitly request a fresh provider assessment',previous=source.id,
        withdrew_approval=False)
    with Session() as s:
        s.add_all([Host(id='host-one',name='Source',address='192.0.2.1',fingerprint=''),
            Host(id='host-two',name='Current',address='192.0.2.2',fingerprint=''),
            source,behavior,refresh])
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'gpt-fixture'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        known_good.publish(s,source);s.commit()
    calls=[]
    monkeypatch.setattr(ai,'investigate',lambda *args,**kwargs: calls.append(args) or {
        'risk':'low','explanation':'Fresh provider result',
        'recommended_checks':'Continue deterministic monitoring','requested_checks':[]})
    worker.investigate_one()
    with Session() as s:
        saved=s.scalar(select(ai_assessments.Assessment).where(
            ai_assessments.Assessment.subject=='behavior-two'))
        assert s.get(ai_assessments.Refresh,'behavior-two') is None
        assert s.scalar(select(Audit).where(Audit.action=='reuse known-good candidate')) is None
    assert len(calls)==1 and saved.source=='ai' and saved.refresh['id']=='refresh-two'


def test_ineligible_assessment_does_not_publish_any_durable_candidate(client):
    snapshot=complete();snapshot['investigation']['details']['known_good_context']['coverage']['complete']=False
    with Session() as s:
        row=retained(snapshot=snapshot);s.add(row)
        status=known_good.publish(s,row);s.commit()
        assert s.scalar(select(known_good.Entry)) is None
        assert s.scalar(select(known_good.Observation)) is None
    assert not status['eligible'] and not status['published']


def test_exact_cross_host_matches_deduplicate_entry_but_retain_each_observation(client):
    second=complete();second['host_id']='host-two'
    second['investigation']['details']['context']['process']={'pid':99,'start_ticks':88}
    second['investigation']['details']['known_good_context']['observation']={
        'host_id':'host-two','pid':99,'start_ticks':88,'collected':900}
    with Session() as s:
        first=retained();other=retained('assessment-two','host-two','behavior-two',second)
        s.add_all([first,other]);left=known_good.publish(s,first);right=known_good.publish(s,other)
        # Publishing the same assessment again is idempotent as well.
        repeated=known_good.publish(s,other);s.commit()
        entries=list(s.scalars(select(known_good.Entry)))
        observations=list(s.scalars(select(known_good.Observation)))
    assert left['fingerprint']==right['fingerprint']==repeated['fingerprint']
    assert left['published'] and right['published'] and repeated['published']
    assert len(entries)==1 and len(observations)==2
    assert {row.host_id for row in observations}=={'host-one','host-two'}


def test_concurrent_exact_matches_atomically_deduplicate_the_candidate(client):
    barrier=threading.Barrier(2)
    snapshots=[]
    for number in (1,2):
        value=complete();value['host_id']=f'host-{number}'
        value['investigation']['details']['known_good_context']['observation']={
            'host_id':f'host-{number}','pid':number,'start_ticks':number+10,'collected':100+number}
        snapshots.append(value)
    def run(number):
        with Session() as s:
            row=retained(f'assessment-{number}',f'host-{number}',f'behavior-{number}',snapshots[number-1])
            s.add(row);barrier.wait(timeout=5)
            result=known_good.publish(s,row);s.commit();return result
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(run,(1,2)))
    with Session() as s:
        assert len(list(s.scalars(select(known_good.Entry))))==1
        assert len(list(s.scalars(select(known_good.Observation))))==2
    assert all(result['published'] for result in results)


def test_changed_canonical_context_publishes_a_distinct_entry(client):
    changed=complete();changed['host_id']='host-two'
    changed['investigation']['details']['known_good_context']['observation']['host_id']='host-two'
    changed['investigation']['details']['known_good_context']['behavior']['network_sha256']=sha('0')
    with Session() as s:
        first=retained();other=retained('assessment-two','host-two','behavior-two',changed)
        s.add_all([first,other]);left=known_good.publish(s,first);right=known_good.publish(s,other);s.commit()
        assert len(list(s.scalars(select(known_good.Entry))))==2
    assert left['fingerprint']!=right['fingerprint']


def test_inactive_candidate_is_never_reactivated_by_a_later_assessment(client):
    with Session() as s:
        first=retained();s.add(first);published=known_good.publish(s,first)
        entry=s.get(known_good.Entry,published['fingerprint']);entry.active=False
        second=complete();second['host_id']='host-two'
        second['investigation']['details']['known_good_context']['observation']['host_id']='host-two'
        other=retained('assessment-two','host-two','behavior-two',second);s.add(other)
        status=known_good.publish(s,other);s.commit()
        assert not s.get(known_good.Entry,published['fingerprint']).active
        assert not known_good.assessment(other,s)['published']
    assert status['eligible'] and not status['published']


def test_conflicting_stored_fingerprint_identity_fails_closed(client):
    row=retained();fingerprint=known_good.assessment(row)['fingerprint']
    with Session() as s:
        s.add(known_good.Entry(fingerprint=fingerprint,version=1,
            classification_source='ai',model='different-model',policy_hash=sha('9'),
            assessment_id='other',source_host_id='host-two',contract={'version':1},
            result={'risk':'low'}))
        s.add(row);s.commit()
        with pytest.raises(RuntimeError,match='collision'):
            known_good.publish(s,row)
        s.rollback()
        assert s.get(known_good.Observation,row.id) is None
        assert not known_good.assessment(row,s)['published']


def vendor_report(path='/usr/bin/fixture',checksum=None,state='matches_artifact_bytes'):
    checksum=checksum or sha('a')
    manifest={'package':'fixture','version':'1.0-1','architecture':'amd64',
        'entries':[{'path':path,'sha256':checksum,'size':123}]}
    proof={'bundle_id':'fixture','release_sha256':sha('b'),'index_sha256':sha('c'),
        'artifact_sha256':sha('d'),'keyring_sha256':sha('e'),'signers':['A'*40],
        'authenticated_at':123,'scope':'fixture'}
    receipt={'trust_basis':'controller_authenticated_debian_artifact','package':'fixture','version':'1.0-1',
        'architecture':'amd64','scope_files':1,'examined':1,'state':state,'gaps':[],'findings':[]}
    return {'version':1,'trust_basis':'controller_authenticated_debian_artifact','state':'collected','packages':[],
        'persistence':None,'vendor_manifest':manifest,'vendor_authentication':proof,'vendor_verification':receipt}


def partial(host='one',pid=10,collected=100):
    gaps=['configuration_not_collected','package_authentication_missing']
    coverage={'cache_eligible':False,'scope':'recorded_process_identity','gaps':gaps,
        'consistency':'matching_before_after_samples','trust':'target_kernel_and_local_files'}
    context={'version':1,'process':{'pid':pid,'start_ticks':20,'pid_namespace':1000+pid,
            'boot_id':'a'*8+'-'+'a'*4+'-'+'a'*4+'-'+'a'*4+'-'+'a'*12,
            'proc_device':30+pid,'proc_inode':40+pid},
        'credentials':{'Uid':['0','0','0','0'],'Gid':['0','0','0','0'],'Groups':['0'],
            'CapEff':['0000000000000000'],'NoNewPrivs':['1'],'Seccomp':['2']},
        'namespaces':{'pid':2000+pid,'net':3000+pid,'mnt':4000+pid,'user':5000+pid},
        'maps_sha256':sha('b'),'cgroup_sha256':sha('c'),
        'artifacts':[{'kind':'library','path':'/usr/lib/libfixture.so','identity_verified':True,
            'sha256':sha('d'),'source':'mapped-file','metadata':{'uid':0,'gid':0,'mode':493,'size':12}}],
        'executable':{'sha256':sha('a'),'uid':0,'gid':0,'mode':493,'size':123},
        'coverage':copy.deepcopy(coverage)}
    return {'executable':'/usr/bin/fixture','sha256':sha('a'),'identity_verified':True,
        'investigation':{'collected':collected,'details':{'version':2,'identity_verified':True,
            'checks':['package'],'context':context,'coverage':copy.deepcopy(coverage),
            'package':'fixture: /usr/bin/fixture'}}}


def test_controller_authenticated_vendor_receipt_binds_exact_artifact_but_stays_ineligible(client):
    with Session() as s:
        s.add(Inspection(id='vendor-one',host_id='one',created=123,report=vendor_report()));s.commit()
        bound=known_good.bind_vendor_provenance(s,'one',partial(),100)
    details=bound['investigation']['details'];contract=details['known_good_context']
    assert 'package_authentication_missing' not in details['context']['coverage']['gaps']
    assert contract['artifact']['sha256']==sha('a') and contract['provenance']['verified']
    result=evaluate(bound)
    assert not result['eligible'] and result['fingerprint']==''
    assert 'provenance_binding_invalid' not in codes(result)
    assert contract['followup']['complete'] and contract['followup']['policy_version']=='process-followup-v2'
    assert 'followup_binding_invalid' not in codes(result)
    assert {'configuration_binding_invalid','behavior_binding_invalid','coverage_binding_invalid'}<=set(codes(result))


def test_vendor_binding_is_cross_host_stable_but_observations_remain_local(client):
    report=vendor_report()
    with Session() as s:
        s.add_all([Inspection(id='vendor-cross-one',host_id='cross-one',created=123,report=report),
            Inspection(id='vendor-cross-two',host_id='cross-two',created=456,report=copy.deepcopy(report))]);s.commit()
        first=known_good.bind_vendor_provenance(s,'cross-one',partial('cross-one',10,100),100)
        second=known_good.bind_vendor_provenance(s,'cross-two',partial('cross-two',99,900),900)
    left=first['investigation']['details']['known_good_context'];right=second['investigation']['details']['known_good_context']
    assert {name:left[name] for name in known_good.COMPONENTS}=={name:right[name] for name in known_good.COMPONENTS}
    assert left['observation']!=right['observation']


@pytest.mark.parametrize('mutation',["credentials","maps","cgroup","artifact","result"])
def test_security_relevant_followup_changes_alter_the_evidence_manifest(client,mutation):
    with Session() as s:
        s.add(Inspection(id='vendor-followup-'+mutation,host_id=mutation,created=123,report=vendor_report()));s.commit()
        baseline=partial(mutation)
        changed=copy.deepcopy(baseline)
        details=changed['investigation']['details'];context=details['context']
        if mutation=='credentials':context['credentials']['Uid'][1]='1000'
        elif mutation=='maps':context['maps_sha256']=sha('e')
        elif mutation=='cgroup':context['cgroup_sha256']=sha('f')
        elif mutation=='artifact':context['artifacts'][0]['sha256']=sha('e')
        else:details['package']='other: /usr/bin/fixture'
        first=known_good.bind_vendor_provenance(s,mutation,baseline,100)
        second=known_good.bind_vendor_provenance(s,mutation,changed,100)
    left=first['investigation']['details']['known_good_context']['followup']
    right=second['investigation']['details']['known_good_context']['followup']
    assert left['requirements_sha256']==right['requirements_sha256']
    assert left['evidence_sha256']!=right['evidence_sha256']


def test_changed_followup_requirements_change_the_requirements_manifest(client):
    with Session() as s:
        s.add(Inspection(id='vendor-requirements',host_id='requirements',created=123,report=vendor_report()));s.commit()
        baseline=partial('requirements')
        changed=copy.deepcopy(baseline);details=changed['investigation']['details']
        details['checks']=['package','executable']
        details['executable']={**details['context']['executable'],
            'status':['Uid:\t0\t0\t0\t0','Gid:\t0\t0\t0\t0','CapEff:\t0000000000000000','NoNewPrivs:\t1','Seccomp:\t2']}
        first=known_good.bind_vendor_provenance(s,'requirements',baseline,100)
        second=known_good.bind_vendor_provenance(s,'requirements',changed,100)
    left=first['investigation']['details']['known_good_context']['followup']
    right=second['investigation']['details']['known_good_context']['followup']
    assert left['requirements_sha256']!=right['requirements_sha256']
    assert left['evidence_sha256']!=right['evidence_sha256']


def test_check_order_is_not_a_cross_host_difference(client):
    with Session() as s:
        s.add(Inspection(id='vendor-order',host_id='order',created=123,report=vendor_report()));s.commit()
        first=partial('order');second=copy.deepcopy(first)
        for value in (first,second):
            details=value['investigation']['details'];details['checks']=['package','executable']
            details['executable']={**details['context']['executable'],'status':['Uid:\t0\t0\t0\t0']}
        second['investigation']['details']['checks'].reverse()
        left=known_good.bind_vendor_provenance(s,'order',first,100)
        right=known_good.bind_vendor_provenance(s,'order',second,100)
    assert (left['investigation']['details']['known_good_context']['followup']==
        right['investigation']['details']['known_good_context']['followup'])


def test_invalid_complete_receipt_does_not_remove_any_declared_gap(client):
    evidence=partial('invalid');del evidence['investigation']['details']['context']['cgroup_sha256']
    with Session() as s:
        s.add(Inspection(id='vendor-invalid',host_id='invalid',created=123,report=vendor_report()));s.commit()
        bound=known_good.bind_vendor_provenance(s,'invalid',evidence,100)
    assert bound==evidence
    assert 'package_authentication_missing' in bound['investigation']['details']['context']['coverage']['gaps']
    assert 'known_good_context' not in bound['investigation']['details']


@pytest.mark.parametrize('field,value',[('checks',[{}]),('gaps',[{}])])
def test_unhashable_receipt_values_fail_closed_without_removing_gaps(client,field,value):
    evidence=partial('unhashable-'+field);details=evidence['investigation']['details']
    if field=='checks':details['checks']=value
    else:
        details['context']['coverage']['gaps']=value
        details['coverage']['gaps']=copy.deepcopy(value)
    with Session() as s:
        s.add(Inspection(id='vendor-unhashable-'+field,host_id='unhashable-'+field,
            created=123,report=vendor_report()));s.commit()
        bound=known_good.bind_vendor_provenance(s,'unhashable-'+field,evidence,100)
    assert bound==evidence and 'known_good_context' not in bound['investigation']['details']


@pytest.mark.parametrize('inspection_id,host,report',[
    ('vendor-miss-hash','miss-hash',vendor_report(checksum=sha('f'))),
    ('vendor-miss-state','miss-state',vendor_report(state='differences')),
])
def test_changed_or_incomplete_vendor_receipt_is_a_contextual_miss(client,inspection_id,host,report):
    with Session() as s:
        s.add(Inspection(id=inspection_id,host_id=host,created=123,report=report));s.commit()
        bound=known_good.bind_vendor_provenance(s,host,partial(host),100)
    assert 'known_good_context' not in bound['investigation']['details']
    assert 'package_authentication_missing' in bound['investigation']['details']['context']['coverage']['gaps']


@pytest.mark.parametrize('details',[None,{},{'version':2,'identity_verified':True,'context':None},
    {'version':2,'identity_verified':True,'context':{'coverage':{'scope':'recorded_process_identity','gaps':[None]}}}])
def test_malformed_followup_never_crashes_vendor_binding(client,details):
    evidence={'executable':'/usr/bin/fixture','sha256':sha('a'),'investigation':{'details':details}}
    with Session() as s:assert known_good.bind_vendor_provenance(s,'one',evidence,100)==evidence
