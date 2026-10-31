import json
import httpx
import pytest
from app import ai, worker
from app.db import Session, Setting, Behavior, Host
from app.identity import User
from app.security import seal


def setup_ai():
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model','ai_hourly_limit':20}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('secret-test-key')}));s.commit()


def success():
    result={'risk':'unknown','explanation':'Connection test only','recommended_checks':'None','requested_checks':[]}
    return httpx.Response(200,json={'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(result)}]}]},request=httpx.Request('POST',ai.URL))


@pytest.mark.parametrize('status,code,param,hint',[
    (401,'invalid_api_key',None,'saved key'),(403,None,None,'permissions'),
    (404,'model_not_found','model','model ID'),(429,'insufficient_quota',None,'billing'),
    (429,'project_spend_limit_exceeded',None,'spend limit'),(429,'credit_balance_exhausted',None,'prepaid'),
    (429,'rate_limit_exceeded',None,'rate limit'),(400,'unsupported_parameter','text.format','structured-output'),
    (503,'server_is_overloaded',None,'overloaded')])
def test_investigation_records_safe_actionable_provider_error(admin,monkeypatch,status,code,param,hint):
    setup_ai()
    with Session() as s:
        s.add(Behavior(id='api-error',host_id='fixture',evidence={'executable':'/sensitive/host/path'}));s.commit()
    def post(*args,**kwargs):
        return httpx.Response(status,json={'error':{'code':code,'param':param,'message':'secret-test-key /sensitive/host/path private-provider-response'}},
                              headers={'x-request-id':'req_fixture_123'},request=httpx.Request('POST',ai.URL))
    monkeypatch.setattr(ai.transport,'post',post)
    worker.investigate_one()
    with Session() as s:
        row=s.get(Behavior,'api-error')
        assert row.verdict=='error' and not row.approved
        assert f'HTTP {status}' in row.analysis and hint in row.analysis and 'req_fixture_123' in row.analysis
        assert all(v not in row.analysis for v in ('secret-test-key','/sensitive/host/path','private-provider-response'))
        if code:assert code in row.analysis
        if param:assert param in row.analysis


def test_unknown_codes_headers_and_non_json_provider_bodies_are_not_echoed():
    response=httpx.Response(400,json={'error':{'code':'secret-test-key','param':'private-data','message':'private-message'}},headers={'x-request-id':'private-header'})
    message=str(ai.http_error(response))
    assert '400' in message and all(v not in message for v in ('secret-test-key','private-data','private-message','private-header'))
    assert '502' in str(ai.http_error(httpx.Response(502,text='<html>private gateway details</html>')))
    assert 'private gateway' not in str(ai.http_error(httpx.Response(502,text='<html>private gateway details</html>')))


@pytest.mark.parametrize('exception',[httpx.ConnectError('secret DNS/proxy credentials'),httpx.ReadTimeout('secret timeout details')])
def test_transport_errors_are_safe_and_useful(client,monkeypatch,exception):
    def fail(*a,**kw):raise exception
    monkeypatch.setattr(ai.transport,'post',fail)
    with pytest.raises(ai.AIError) as error:ai.investigate({},'fixture','secret-test-key')
    assert 'secret' not in str(error.value) and ('HTTPS' in str(error.value) or 'DNS' in str(error.value))


@pytest.mark.parametrize('body',[
    {'status':'incomplete','incomplete_details':{'reason':'max_output_tokens'}},
    {'status':'completed','output':[{'content':[{'type':'refusal','refusal':'private reflected content'}]}]},
    {'status':'completed','output':[{'content':[{'type':'output_text','text':'{"truncated":"private'}]}]},
    {'status':'completed','output':None}])
def test_incomplete_refused_and_malformed_responses_are_not_accepted(client,monkeypatch,body):
    monkeypatch.setattr(ai.transport,'post',lambda *a,**k:httpx.Response(200,json=body,request=httpx.Request('POST',ai.URL)))
    with pytest.raises(ai.AIError) as error:ai.investigate({},'fixture','secret-test-key')
    assert 'private' not in str(error.value)


def test_ai_probe_uses_saved_settings_no_host_evidence_and_is_rate_limited(admin,monkeypatch):
    setup_ai();calls=[]
    with Session() as s:s.add(Host(id='private-host',name='private-host',address='192.0.2.4',fingerprint='',inventory={'secret':'host-evidence'}));s.commit()
    def post(*a,**kw):calls.append(kw);return success()
    monkeypatch.setattr(ai.transport,'post',post)
    result=admin.post('/api/settings/ai-test')
    assert result.status_code==200 and result.json()['ok']
    payload=calls[0]['json'];assert payload['model']=='fixture-model' and payload['store'] is False
    assert payload['text']['format']['schema']==ai.SCHEMA and payload['max_output_tokens']==1600
    assert 'private-host' not in json.dumps(payload) and 'host-evidence' not in json.dumps(payload)
    assert admin.post('/api/settings/ai-test').status_code==429 and len(calls)==1


def test_ai_probe_checks_configuration_permissions_and_csrf(admin,monkeypatch):
    monkeypatch.setattr(ai.transport,'post',lambda *a,**kw:pytest.fail('must not call provider'))
    assert admin.post('/api/settings/ai-test').status_code==400
    setup_ai()
    with Session() as s:s.get(User,'admin').role='viewer';s.commit()
    assert admin.post('/api/settings/ai-test').status_code==403
    with Session() as s:s.get(User,'admin').role='admin';s.commit()
    admin.headers.pop('X-CSRF-Token')
    assert admin.post('/api/settings/ai-test').status_code==403


def test_failed_probe_releases_lock_and_returns_diagnostic(admin,monkeypatch):
    setup_ai()
    def fail(*a,**kw):return httpx.Response(401,json={'error':{'code':'invalid_api_key','message':'secret-test-key'}},request=httpx.Request('POST',ai.URL))
    monkeypatch.setattr(ai.transport,'post',fail)
    r=admin.post('/api/settings/ai-test');assert r.status_code==502 and 'HTTP 401' in r.json()['detail'] and 'secret-test-key' not in r.text
    with Session() as s:s.get(Setting,'ai-test:last').value={'attempted':0};s.commit()
    monkeypatch.setattr(ai.transport,'post',lambda *a,**kw:success())
    assert admin.post('/api/settings/ai-test').status_code==200


def test_settings_strip_pasted_whitespace_without_losing_saved_key(admin):
    body={'repo_minutes':60,'deadlines':{'critical':24,'high':72,'normal':168,'low':720},'ai_enabled':True,'ai_model':'  fixture-model  ','api_key':' secret-test-key\n'}
    assert admin.put('/api/settings',json=body).status_code==200
    assert admin.get('/api/settings').json()['ai_model']=='fixture-model'
    body['ai_model']='ChatGPT display label'
    assert admin.put('/api/settings',json=body).status_code==400
