"""Read-only per-server agent spool health (issue #108 increment)."""
import time
import pytest
from app import agent_spool_health as health
from app.db import Session, Host
from app.identity import User

CAPACITY=48_000_000


def spool(queued=0,pending=0,**extra):
    value={'pending':pending,'queued_bytes':queued,'capacity_bytes':CAPACITY,'batch_limit_bytes':262_144,
           'dropped':5,'dropped_observations':7,
           'drop_reasons':{'oversize':{'batches':1,'observations':2},'capacity':{'batches':3,'observations':5},'unclassified_batches':1}}
    value.update(extra);return value


def add_host(name='h',telemetry=None,**fields):
    with Session() as s:
        s.add(Host(id=name,name=name,address='192.0.2.1',fingerprint='',telemetry=telemetry if telemetry is not None else {},**fields));s.commit()


def set_role(name):
    with Session() as s:
        s.get(User,'admin').role=name;s.commit()


def test_fresh_report_has_queue_pressure_and_loss_by_reason(admin):
    add_host(telemetry={'collected':time.time(),'spool':spool(queued=int(CAPACITY*.5),pending=4)})
    body=admin.get('/api/hosts/h/spool-health').json()
    assert body['status']=='fresh' and body['pressure']=='ok' and body['lifecycle']=='enabled'
    assert body['queue']=={'pending_batches':4,'queued_bytes':CAPACITY//2,'capacity_bytes':CAPACITY,'utilization_percent':50.0,'batch_limit_bytes':262_144}
    assert body['loss']['by_reason']['capacity']=={'batches':3,'observations':5}
    assert body['loss']['dropped_batches']==5 and body['loss']['unclassified_batches']==1
    assert 'oldest_observation_age' in body['unavailable_metrics']
    assert 'oldest_observation_age' not in body.get('queue',{})


@pytest.mark.parametrize('fraction,expected',[(.69,'ok'),(.70,'warning'),(.89,'warning'),(.90,'critical'),(1.5,'critical')])
def test_pressure_thresholds(fraction,expected):
    host=Host(id='x',telemetry={'collected':time.time(),'spool':spool(queued=int(CAPACITY*fraction))})
    result=health.health(host)
    assert result['pressure']==expected and result['queue']['utilization_percent']<=100


def test_stale_and_missing_and_malformed_are_explicit_not_zero(admin):
    add_host('old',{'collected':time.time()-3600,'spool':spool()})
    add_host('none',{'collected':time.time()})
    add_host('bad',{'collected':time.time(),'spool':spool(queued=-1)})
    add_host('nan',{'collected':time.time(),'spool':spool(pending='Infinity')})
    add_host('zero',{'collected':time.time(),'spool':spool(capacity_bytes=0)})
    assert admin.get('/api/hosts/old/spool-health').json()['status']=='stale'
    for name in ('none','bad','nan','zero'):
        body=admin.get(f'/api/hosts/{name}/spool-health').json()
        assert body['status']=='unavailable' and body['pressure']=='unavailable' and 'queue' not in body,name


def test_non_finite_pending_is_unavailable_without_persisting_it():
    host=Host(id='x',telemetry={'collected':time.time(),'spool':spool(pending=float('inf'))})
    result=health.health(host)
    assert result['status']=='unavailable' and 'queue' not in result


@pytest.mark.parametrize('field',['pending','queued_bytes'])
def test_fractional_queue_counters_are_unavailable(field):
    host=Host(id='x',telemetry={'collected':time.time(),'spool':spool(**{field:1.9})})
    result=health.health(host)
    assert result['status']=='unavailable' and 'queue' not in result


@pytest.mark.parametrize('field',['dropped','dropped_observations','batch_limit_bytes'])
def test_fractional_optional_counters_are_null_not_truncated(field):
    host=Host(id='x',telemetry={'collected':time.time(),'spool':spool(**{field:2.5})})
    result=health.health(host)
    assert health.count(2.5) is None and health.count(3.0)==3
    flat=[result['loss']['dropped_batches'],result['loss']['lost_observations'],result['queue']['batch_limit_bytes']]
    assert 2 not in flat


def test_fractional_loss_reason_counters_are_null():
    reasons={'oversize':{'batches':1.5,'observations':2.5},'capacity':{'batches':3,'observations':5}}
    host=Host(id='x',telemetry={'collected':time.time(),'spool':spool(drop_reasons=reasons)})
    loss=health.health(host)['loss']['by_reason']
    assert loss['oversize']=={'batches':None,'observations':None} and loss['capacity']['batches']==3


def test_payloads_and_unknown_keys_never_returned(admin):
    secret='/private/executable-secret'
    value=spool(extra_key=secret,events=[{'executable':secret}])
    value['drop_reasons']['custom']={'batches':1,'path':secret}
    add_host(telemetry={'collected':time.time(),'spool':value,'processes':[{'executable':secret}]})
    assert secret not in admin.get('/api/hosts/h/spool-health').text


def test_lifecycle_and_roles(admin):
    add_host('off',{'collected':time.time(),'spool':spool()},enabled=False)
    add_host('gone',{'collected':time.time(),'spool':spool()},deleted_at=1)
    assert admin.get('/api/hosts/off/spool-health').json()['lifecycle']=='disabled'
    assert admin.get('/api/hosts/gone/spool-health').json()['lifecycle']=='deleted'
    assert admin.get('/api/hosts/missing/spool-health').status_code==404
    set_role('viewer')
    assert admin.get('/api/hosts/off/spool-health').status_code==200
    assert admin.get('/api/hosts/gone/spool-health').status_code==403
    assert admin.post('/api/hosts/off/spool-health').status_code in (404,405)
