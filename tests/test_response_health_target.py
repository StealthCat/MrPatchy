import copy
import sys
import uuid
import pytest
from target import agent,bridge

ID=str(uuid.uuid4());DIGEST='a'*64;BOOT='12345678-1234-1234-1234-123456789abc'


def properties(unit='example.service',**changes):
    return {'Id':unit,'LoadState':'loaded','ActiveState':'active','SubState':'running','Result':'success',
            'ExecMainCode':0,'ExecMainStatus':0,'MainPID':41,'NRestarts':0,'InvocationID':'a'*32,'FragmentPath':'/etc/systemd/system/'+unit,'UnitFileState':'enabled',**changes}


@pytest.fixture
def source(monkeypatch):
    calls=[];values={'before':properties(),'after':properties()}
    monkeypatch.setattr(agent,'response_service_boot',lambda:BOOT)
    def query(unit,timeout):
        assert 0<timeout<=3;calls.append(unit)
        return copy.deepcopy(values['before' if len(calls)%2 else 'after'])
    monkeypatch.setattr(agent,'response_service_query',query)
    return values,calls


def test_service_health_is_read_only_stable_properties_with_boot_recheck(source):
    values,calls=source
    report=agent.response_service_health(ID,DIGEST,['example.service'])
    assert calls==['example.service']*2 and report['state']=='healthy' and not report['gaps']
    assert report['boot_rechecked'] and report['services'][0]['before']==report['services'][0]['after']==properties()


@pytest.mark.parametrize('change',[{'ActiveState':'failed','Result':'exit-code'},{'ActiveState':'inactive','SubState':'dead'},
    {'LoadState':'not-found'},{'Result':'signal'},{'ExecMainStatus':1},{'ExecMainCode':2},{'MainPID':0}])
def test_unhealthy_selected_unit_is_a_problem(source,change):
    values,_=source;values['before'].update(change);values['after'].update(change)
    assert agent.response_service_health(ID,DIGEST,['example.service'])['state']=='problem'


def test_successful_active_oneshot_is_supported(source):
    values,_=source
    for sample in values.values():sample.update(SubState='exited',MainPID=0,ExecMainCode=1)
    assert agent.response_service_health(ID,DIGEST,['example.service'])['state']=='healthy'


def test_changing_pid_or_restart_count_is_incomplete_instead_of_healthy(source):
    values,_=source;values['after']['NRestarts']=1
    report=agent.response_service_health(ID,DIGEST,['example.service'])
    assert report['state']=='unavailable' and report['gaps']==['unit_changing']
    assert report['services'][0]['state']=='changing'


@pytest.mark.parametrize('failure',[ValueError('PRIVATE_ERROR'),TimeoutError('PRIVATE_ERROR'),OSError('PRIVATE_ERROR')])
def test_query_failures_are_sanitized_coverage_gaps(source,monkeypatch,failure):
    def failed(*a):raise failure
    monkeypatch.setattr(agent,'response_service_query',failed)
    report=agent.response_service_health(ID,DIGEST,['example.service'])
    assert report['state']=='unavailable' and report['gaps']==['unit_unavailable'] and 'PRIVATE_ERROR' not in str(report)


@pytest.mark.parametrize('boot',['changed','missing'])
def test_boot_change_or_unavailable_prevents_positive_health(source,monkeypatch,boot):
    calls=[]
    def read():
        calls.append(1)
        if boot=='missing':raise OSError('private')
        return BOOT if len(calls)==1 else str(uuid.uuid4())
    monkeypatch.setattr(agent,'response_service_boot',read)
    report=agent.response_service_health(ID,DIGEST,['example.service'])
    assert report['state']=='unavailable' and not report['boot_rechecked']
    assert ('boot_changed' if boot=='changed' else 'boot_unavailable') in report['gaps']


@pytest.mark.parametrize('units',[[],['*.service'],['--all.service'],['/etc/example.service'],['a.service','a.service'],['a.timer'],['a.service\nrestart'],['a'*129+'.service'],['a.service']*17,True,[1]])
def test_untrusted_unit_selection_cannot_invoke_systemctl(source,units):
    _,calls=source
    with pytest.raises(ValueError):agent.response_service_health(ID,DIGEST,units)
    assert not calls


def test_query_uses_only_bounded_fixed_systemctl_show_arguments(monkeypatch):
    def bounded(args,**kwargs):
        assert args==['/usr/bin/systemctl','show','--no-pager','--no-ask-password','--property='+','.join(agent.SERVICE_PROPERTIES),'--','example.service']
        assert kwargs['timeout']==2 and kwargs['limit']==8192 and kwargs['env']['LC_ALL']=='C'
        return '\n'.join(key+'='+str(value) for key,value in properties().items())+'\n','',0
    monkeypatch.setattr(bridge,'bounded',bounded)
    assert agent.response_service_query('example.service',2)==properties()


@pytest.mark.parametrize('change',['duplicate','missing','unexpected','counter','control','failed_exit','huge_counter','stderr'])
def test_untrusted_systemctl_output_is_rejected(monkeypatch,change):
    value=properties();status=0
    if change=='missing':del value['Result']
    if change=='unexpected':value['ExecStart']='SECRET_COMMAND'
    if change=='counter':value['MainPID']='-1'
    if change=='control':value['FragmentPath']='bad\x00path'
    if change=='failed_exit':status=1
    if change=='huge_counter':value['NRestarts']=2**64
    output='\n'.join(key+'='+str(item) for key,item in value.items())
    if change=='duplicate':output+='\nId=example.service'
    monkeypatch.setattr(bridge,'bounded',lambda *a,**k:(output,'SECRET_ERROR' if change=='stderr' else '',status))
    with pytest.raises((ValueError,RuntimeError)):agent.response_service_query('example.service',2)


def test_total_deadline_produces_explicit_gaps_without_more_queries(source,monkeypatch):
    _,calls=source;clock=iter([0,91,92])
    monkeypatch.setattr(agent.time,'monotonic',lambda:next(clock))
    report=agent.response_service_health(ID,DIGEST,['example.service','other.service'])
    assert not calls and report['state']=='unavailable' and report['gaps']==['time_limit','unit_unavailable']


def test_bridge_dispatches_only_read_only_service_action(source,monkeypatch):
    monkeypatch.setitem(sys.modules,'agent',agent)
    result=bridge.handle({'action':'response-service-health','id':ID,'plan_digest':DIGEST,'units':['example.service']})
    assert result['state']=='healthy'
