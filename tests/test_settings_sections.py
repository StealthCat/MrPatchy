import httpx
import pytest
from app import ai
from app.db import Session, Setting, config
from app.security import unseal


def no_provider(monkeypatch):
    def unexpected(*a,**kw):pytest.fail('Saving must not contact the provider')
    monkeypatch.setattr(ai.httpx,'get',unexpected)
    monkeypatch.setattr(ai.httpx,'post',unexpected)


def test_key_can_be_saved_with_no_model_even_if_ai_configuration_is_broken(admin,monkeypatch):
    no_provider(monkeypatch)
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':''}));s.commit()
    r=admin.put('/api/settings/ai-key',json={'api_key':' new-secret-key\n'})
    assert r.status_code==200 and r.json()['api_key_configured']
    assert 'new-secret-key' not in r.text
    state=admin.get('/api/settings').json()
    assert state['ai_model']=='' and state['ai_enabled']
    assert state['api_key_revision']==r.json()['api_key_revision']
    with Session() as s:assert unseal(s.get(Setting,'openai_key').value['encrypted'])=='new-secret-key'


def test_model_save_independent_of_discovery_and_provider_404(admin,monkeypatch):
    no_provider(monkeypatch)
    admin.put('/api/settings/ai-key',json={'api_key':'fixture-key'})
    assert admin.put('/api/settings/ai',json={'ai_model':'missing-model','ai_enabled':True}).status_code==200
    r=admin.put('/api/settings/ai',json={'ai_model':'  selected-model  ','ai_enabled':True})
    assert r.status_code==200 and r.json()['ai_model']=='selected-model'
    calls=[]
    def reject(url,**kw):
        calls.append(kw)
        return httpx.Response(404,json={'error':{'code':'model_not_found','message':'fixture-key private body'}},headers={'x-request-id':'req_current_test'},request=httpx.Request('POST',url))
    monkeypatch.setattr(ai.httpx,'post',reject)
    test=admin.post('/api/settings/ai-test',json={'expected_model':'selected-model','expected_key_revision':r.json()['api_key_revision']})
    assert test.status_code==502 and test.json()['model']=='selected-model' and test.json()['run_id']
    assert 'req_current_test' in test.text and 'fixture-key' not in test.text and 'private body' not in test.text
    assert calls[0]['json']['model']=='selected-model'
    assert admin.get('/api/settings').json()['ai_model']=='selected-model'
    # Provider failure never prevents saving the next choice.
    assert admin.put('/api/settings/ai',json={'ai_model':'replacement-model','ai_enabled':True}).status_code==200
    assert len(calls)==1


def test_test_refuses_changed_model_or_key_without_sending_provider_request(admin,monkeypatch):
    no_provider(monkeypatch)
    first=admin.put('/api/settings/ai-key',json={'api_key':'fixture-key'}).json()
    admin.put('/api/settings/ai',json={'ai_model':'model-a'})
    assert admin.post('/api/settings/ai-test',json={'expected_model':'old-model'}).status_code==409
    admin.put('/api/settings/ai-key',json={'api_key':'changed-key'})
    assert admin.post('/api/settings/ai-test',json={'expected_model':'model-a','expected_key_revision':first['api_key_revision']}).status_code==409


def test_section_saves_preserve_unrelated_configuration_and_do_not_validate_broken_ai(admin,monkeypatch):
    no_provider(monkeypatch)
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'','history_days':120}));s.commit()
    policy={'repo_minutes':15,'deadlines':{'critical':12,'high':48,'normal':168,'low':300}}
    assert admin.put('/api/settings/patching',json=policy).status_code==200
    assert admin.put('/api/settings/history',json={'history_days':90}).status_code==200
    admin.put('/api/settings/ai-key',json={'api_key':'fixture-key'})
    assert admin.put('/api/settings/ai',json={'ai_model':'test-model','ai_hourly_limit':7}).status_code==200
    state=admin.get('/api/settings').json()
    assert state['repo_minutes']==15 and state['deadlines']==policy['deadlines'] and state['history_days']==90
    assert state['ai_model']=='test-model' and state['ai_hourly_limit']==7
    assert admin.put('/api/settings/history',json={'history_days':42,'ai_model':'overwrite'}).status_code==422
    assert admin.put('/api/settings/ai',json={'ai_model':'test-model','history_days':1}).status_code==422


@pytest.mark.parametrize('path,body',[
 ('ai-key',{'api_key':'fixture-key'}),('ai',{'ai_model':'model'}),
 ('patching',{'repo_minutes':60,'deadlines':{'critical':24,'high':72,'normal':168,'low':720}}),('history',{'history_days':60})])
def test_section_writes_require_admin_and_csrf(admin,path,body):
    csrf=admin.headers.pop('X-CSRF-Token')
    assert admin.put('/api/settings/'+path,json=body).status_code==403
    admin.headers['X-CSRF-Token']=csrf
    from app.identity import User
    with Session() as s:s.get(User,'admin').role='viewer';s.commit()
    assert admin.put('/api/settings/'+path,json=body).status_code==403
