import pytest
from app import automation_conflicts as ac

H='a'*64


def entry(i='cron:/etc/cron.d/x#1',behaviors=('runs_package_manager',),**k):
    return dict(entry_id=i,mechanism='cron_entry',digest=H,behaviors=list(behaviors),enabled=True,next_run=None,**k)


def ev(entry_id='cron:/etc/cron.d/x#1',kind='lock_contention',op='patch'):
    return dict(kind=kind,operation=op,observed_at=10,job_id='j1',entry_id=entry_id)


def one(entries,evidence,upcoming=()):
    return ac.classify(entries,evidence,upcoming)['findings'][0]


def test_observed_requires_linked_evidence_and_matching_rule():
    f=one([entry()],[ev()])
    assert f['state']=='observed' and f['rule']['id']=='R1' and f['evidence'][0]['job_id']=='j1' and f['affected_operations']==['patch']
    assert one([entry()],[ev(kind='state_drift')])['state']=='insufficient_evidence'  # tag cannot explain this evidence
    assert one([entry()],[ev(entry_id=None)])['state']=='insufficient_evidence'  # lock alone proves nothing
    assert one([entry(behaviors=())],[ev()])['state']=='insufficient_evidence'  # unfamiliar script alone proves nothing


def test_likely_needs_enabled_entry_inside_window_and_is_not_observed():
    e=entry(behaviors=('reboots_host',));e['next_run']=50
    win=[dict(operation='patch',window_start=40,window_end=60)]
    f=one([e],[],win);assert f['state']=='likely' and f['evidence']==[] and 'no interference has been observed' in f['reason']
    assert one([e],[],[dict(operation='patch',window_start=60,window_end=70)])['state']=='insufficient_evidence'
    e['enabled']=False;assert one([e],[],win)['state']=='insufficient_evidence'


def test_findings_are_deterministic_and_inputs_validated():
    a=[entry('b'),entry('a')];out=ac.classify(a,[ev('a')])
    assert [f['entry_id'] for f in out['findings']]==['a','b'] and out==ac.classify(list(reversed(a)),[ev('a')])
    assert ac.classify(a,[ev('zzz')])['unlinked_evidence']==1
    for bad in ([entry(behaviors=('nope',))],[entry('a'),entry('a')],[dict(entry_id='a',digest='x')]):
        with pytest.raises(ValueError):ac.classify(bad,[])
    with pytest.raises(ValueError):ac.classify([entry()],[dict(ev(),kind='bogus')])
    with pytest.raises(ValueError):ac.classify([entry(str(i)) for i in range(501)],[])
    assert not any('malicious' in str(f).lower() for f in out['findings'])


def test_plan_is_proposal_bound_to_entry_state_and_reapproval():
    f=one([entry()],[ev()])
    p=ac.plan(f,'prevent_future_starts','Collides with patch window')
    assert p['requires_approval'] and p['scope']=='single_entry' and p['execution']=='typed_operation' and not p['needs_response_authorization']
    assert 'disable_service_wide' in p['never'] and len(p['binding'])==64
    assert ac.approval_current(p,f)
    changed=dict(f,entry_digest='b'*64);assert not ac.approval_current(p,changed)
    assert not ac.approval_current(p,dict(f,state='likely'))
    assert not ac.approval_current(p,dict(f,entry_id='other'))
    assert ac.plan(f,'prevent_future_starts','r',mode='temporary',restore_at=99)['binding']!=p['binding']


def test_plan_refusals():
    f=one([entry()],[ev()]);weak=one([entry(behaviors=())],[])
    with pytest.raises(ValueError):ac.plan(weak,'prevent_future_starts','r')
    with pytest.raises(ValueError):ac.plan(f,'prevent_future_starts','  ')
    with pytest.raises(ValueError):ac.plan(f,'prevent_future_starts','r',mode='temporary')
    with pytest.raises(ValueError):ac.plan(f,'prevent_future_starts','r',restore_at=5)
    with pytest.raises(ValueError):ac.plan(f,'delete','r')
    for a in ('stop_active','terminate_process'):
        with pytest.raises(ValueError):ac.plan(f,a,'r')
        p=ac.plan(f,a,'r',separate_scope=True);assert p['needs_response_authorization'] and p['execution']=='manual_step'
    assert ac.plan(f,'prevent_future_starts','r',mechanism='rc_local')['execution']=='manual_step'
