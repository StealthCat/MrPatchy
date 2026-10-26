import httpx
import pytest
from app import ai
from app.db import Session, Setting
from app.security import seal


def test_discovery_uses_saved_key_returns_dynamic_sorted_unique_models(admin, monkeypatch):
    with Session() as s:
        s.merge(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
        s.merge(Setting(key='config',value={'ai_model':'gone-model'}));s.commit()
    def get(url,**kwargs):
        assert url==ai.MODELS_URL and kwargs['headers']=={'Authorization':'Bearer fixture-key'}
        return httpx.Response(200,json={'data':[{'id':x} for x in ['new-model','ft:private:model','new-model','embedding-model']]},request=httpx.Request('GET',url))
    monkeypatch.setattr(ai.httpx,'get',get)
    result=admin.get('/api/settings/ai-models')
    assert result.status_code==200
    assert result.json()=={'models':['embedding-model','ft:private:model','new-model'],'selected':'gone-model','selected_available':False}
    assert 'fixture-key' not in result.text


def test_discovery_requires_key_and_keeps_errors_redacted(admin,monkeypatch):
    assert admin.get('/api/settings/ai-models').status_code==400
    with Session() as s:s.add(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}));s.commit()
    monkeypatch.setattr(ai.httpx,'get',lambda *a,**k:httpx.Response(403,json={'error':{'message':'fixture-key sensitive data'}},headers={'x-request-id':'req_models'},request=httpx.Request('GET',ai.MODELS_URL)))
    response=admin.get('/api/settings/ai-models')
    assert response.status_code==502 and 'req_models' in response.text and 'fixture-key' not in response.text


@pytest.mark.parametrize('data',[{}, {'data':{}},{'data':[{}]},{'data':[{'id':'bad <script>'}]},{'data':[None]}])
def test_invalid_model_lists_do_not_reach_ui(data,monkeypatch):
    monkeypatch.setattr(ai.httpx,'get',lambda *a,**k:httpx.Response(200,json=data,request=httpx.Request('GET',ai.MODELS_URL)))
    with pytest.raises(ai.AIError,match='invalid model list'):ai.list_models('fixture-key')


@pytest.mark.parametrize('path',['/api/settings/database','/api/settings/ai-models'])
def test_new_endpoints_require_admin(client,path):
    assert client.get(path).status_code==401
    from app.identity import User
    from app.security import password_hash
    with Session() as s:s.add(User(username='viewer',password=password_hash('viewer-password'),role='viewer'));s.commit()
    login=client.post('/api/login',json={'username':'viewer','password':'viewer-password'})
    client.headers['X-CSRF-Token']=login.json()['csrf']
    assert client.get(path).status_code==403
    if path.endswith('database'):
        assert client.put(path,json={'backend':'sqlite'}).status_code==403
