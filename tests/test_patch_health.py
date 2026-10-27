import json
import pytest
from app import operations, worker
from app.db import Session,Host,Job
from target import bridge

OLD='logrotate.service loaded failed failed Rotate log files\nsystemd-networkd-wait-online.service loaded failed failed Wait for Network to be Online'
def health(units='',active=True):return {'failed_units':units,'collector_active':active,'reboot_required':False}

def test_comparison_ignores_order_and_description_but_not_new_failures():
    before=health(OLD)
    same=health('systemd-networkd-wait-online.service loaded failed failed Different description\nlogrotate.service loaded failed failed Rotation')
    result=operations.patch_health_comparison(before,same)
    assert result['passed'] and not result['new_failed_units']
    result=operations.patch_health_comparison(before,health(['logrotate.service','new.service']))
    assert not result['passed'] and result['new_failed_units']==['new.service']
    assert result['recovered_units']==['systemd-networkd-wait-online.service']
    assert not operations.patch_health_comparison(before,health(OLD,False))['passed']

@pytest.mark.parametrize('bad',[{},health(None),health('some invalid output'),health([None]),{'failed_units':'','collector_active':'true'}])
def test_uncertain_health_is_not_clean(bad):
    with pytest.raises(ValueError):operations.patch_health_comparison(health(),bad)

@pytest.mark.parametrize('after,expected',[(health(OLD),'complete'),(health('new.service loaded failed failed New'),'failed'),(health(OLD,False),'failed')])
def test_rollout_persists_baseline_and_compares_immediately(admin,monkeypatch,after,expected):
    with Session() as s:
        s.add(Host(id='health-host',name='health',address='192.0.2.1',fingerprint='test'))
        s.add(Job(id='health-job',host_id='health-host',action='patch',payload={'packages':['demo=2'],'_depends_on':[]}));s.commit()
    calls=[];samples=iter([health(OLD),after])
    def call(host,request,**kwargs):
        calls.append(request['action'])
        if request['action']=='health':return next(samples)
        if request['action']=='patch':
            with Session() as s:assert s.get(Job,'health-job').payload['_health_before']==health(OLD)
            assert request=={'action':'patch','packages':['demo=2']}
        return {}
    monkeypatch.setattr(worker.ssh,'call',call)
    monkeypatch.setattr(worker,'save_inventory',lambda *args:None)
    monkeypatch.setattr(worker,'validate_patch',lambda *args:None)
    worker.execute('health-job')
    assert calls==['inventory','health','patch','inventory','health']
    with Session() as s:
        row=s.get(Job,'health-job');assert row.state==expected
        assert 'new_failed_units' in row.output and 'logrotate.service' in row.output

@pytest.mark.parametrize('sample,policy',[(health('',False),{}),(health(OLD),{'reboot':True,'rollback':False}),({}, {})])
def test_bad_preflight_never_attempts_patch(admin,monkeypatch,sample,policy):
    with Session() as s:
        s.add(Host(id='preflight',name='preflight',address='192.0.2.1',fingerprint='test'))
        s.add(Job(id='preflight-job',host_id='preflight',action='patch',payload={'packages':['demo=2'],'_depends_on':[],'_recovery_policy':policy}));s.commit()
    calls=[]
    monkeypatch.setattr(worker.ssh,'call',lambda host,req,**kw:calls.append(req['action']) or (sample if req['action']=='health' else {}))
    monkeypatch.setattr(worker,'save_inventory',lambda *args:None)
    monkeypatch.setattr(worker,'validate_patch',lambda *args:None)
    monkeypatch.setattr(operations,'recovery_policy',lambda *args:policy)
    worker.execute('preflight-job')
    assert 'patch' not in calls and 'protected-patch' not in calls
    with Session() as s:assert s.get(Job,'preflight-job').state=='failed'

def test_target_recovery_preflight_creates_no_transaction(tmp_path,monkeypatch):
    monkeypatch.setattr(bridge,'ROOT',tmp_path)
    calls=[]
    monkeypatch.setattr(bridge,'handle',lambda request:calls.append(request['action']) or health(OLD))
    with pytest.raises(ValueError,match='no package changes'):
        bridge.protected_patch({'job_id':'a'*36,'packages':['demo=2'],'policy':{'reboot':True}})
    assert calls==['health']
    assert not (tmp_path/'transactions'/('a'*36+'.json')).exists()

def test_target_health_list_is_not_truncated(monkeypatch):
    units=''.join(f'unit-{n}.service loaded failed failed Example\n' for n in range(1000))
    assert len(units)>20000
    monkeypatch.setattr(bridge,'bounded',lambda *args,**kwargs:(units,''))
    monkeypatch.setattr(bridge,'run',lambda *args,**kwargs:'active')
    monkeypatch.setattr(bridge,'rpm_backend',lambda:False)
    result=bridge.handle({'action':'health'})
    assert len(operations.failed_unit_names(result))==1000
    assert result['failed_units'].startswith('unit-0.service')
    monkeypatch.setattr(bridge,'bounded',lambda *args,**kwargs:('', 'Failed to connect to bus'))
    with pytest.raises(RuntimeError,match='unambiguous'):bridge.handle({'action':'health'})
