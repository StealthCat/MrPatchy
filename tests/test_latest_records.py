"""Shared newest-record selection preserves response-specific filters."""
from types import SimpleNamespace
import pytest
from app import latest_records,response_health,response_processes,repair_publication
from app.db import Session


MODULES=(response_processes,response_health)


def observation(module,identifier,host,response,created):
    fields={'id':identifier,'host_id':host,'quarantine_id':response,'created':created,
            'actor':'admin','state':'observed','report':{}}
    if module is response_health:fields['reason']='Reviewed service state.'
    return module.Observation(**fields)


def publication(identifier,host,response,created,state='complete'):
    return repair_publication.Publication(id=identifier,host_id=host,quarantine_id=response,
        stage_id='stage-'+identifier,created=created,expires=created+300,actor='admin',reason='Reviewed publication.',
        fingerprint='pin',stage_report_digest='a'*64,plan={},state=state,hold=True,
        before_state='quarantined',before_hold=True)


@pytest.mark.parametrize('module',MODULES)
def test_latest_observation_preserves_host_scope_and_created_id_order(admin,module):
    with Session() as s:
        s.add_all([observation(module,'old','host-a','response-a',1),
                   observation(module,'tie-z','host-a','response-a',2),
                   observation(module,'tie-a','host-a','response-a',2),
                   observation(module,'other','host-a','response-b',3),
                   observation(module,'foreign-new','host-b','response-a',4)])
        s.commit()
        rows=[SimpleNamespace(id='response-a',host_id='host-a'),SimpleNamespace(id='response-b',host_id='host-a')]
        assert {key:value.id for key,value in module.latest(s,rows).items()}=={
            'response-a':'tie-a','response-b':'other'}


def test_latest_publication_preserves_host_and_terminal_state_filters(admin):
    with Session() as s:
        s.add_all([publication('active-old','host-a','response-a',1),
                   publication('active-new','host-a','response-a',2),
                   publication('rejected-newer','host-a','response-a',3,'rejected'),
                   publication('recovered-newest','host-a','response-a',4,'console_recovered'),
                   publication('foreign','host-b','response-a',5),
                   publication('second','host-a','response-b',2)])
        s.commit()
        rows=[SimpleNamespace(id='response-a',host_id='host-a'),SimpleNamespace(id='response-b',host_id='host-a')]
        assert {key:value.id for key,value in repair_publication.latest(s,rows).items()}=={
            'response-a':'active-new','response-b':'second'}


@pytest.mark.parametrize('module,model,condition_count',[
    (response_processes,response_processes.Observation,1),
    (response_health,response_health.Observation,1),
    (repair_publication,repair_publication.Publication,2),
])
def test_latest_wrappers_delegate_to_shared_query(monkeypatch,module,model,condition_count):
    calls=[]
    monkeypatch.setattr(latest_records,'latest_by',lambda *args:calls.append(args) or {'shared':True})
    session=object();rows=[SimpleNamespace(id='response',host_id='host')]
    assert module.latest(session,rows)=={'shared':True}
    args=calls[0]
    assert args[:4]==(session,model,'quarantine_id',['response']) and len(args)==4+condition_count


@pytest.mark.parametrize('module',(*MODULES,repair_publication))
def test_latest_empty_scope_avoids_query(module):
    assert module.latest(object(),[])=={}
