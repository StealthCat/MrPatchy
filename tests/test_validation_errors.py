def test_login_validation_does_not_echo_input(client):
    for body in ({'username':'admin@example.com','password':'x'},{'password':'p'*1100}):
        r=client.post('/api/login',json=body)
        assert r.status_code==422
        assert r.json()=={'detail':'Invalid credentials'}
        assert 'input' not in r.text and 'p'*50 not in r.text

def test_other_validation_errors_are_short_and_do_not_echo_input(admin):
    r=admin.post('/api/hosts',json={'name':'bad','address':'host;touch /tmp/x'})
    assert r.status_code==422
    detail=r.json()['detail']
    assert isinstance(detail,str) and detail.startswith('address:')
    assert 'touch' not in detail and 'input' not in detail

def test_validation_errors_do_not_reflect_dynamic_or_extra_keys(admin):
    canary='CANARY'+'k'*5015
    r=admin.put('/api/settings/patching',json={'deadlines':{canary:'not-an-int'}})
    assert r.status_code==422
    detail=r.json()['detail']
    assert isinstance(detail,str) and len(detail)<=1000
    assert 'CANARY' not in r.text and 'k'*64 not in r.text
    r=admin.post('/api/settings/ai-test',json={'CANARY_extra_field_'+'x'*500:1})
    assert r.status_code==422
    assert 'CANARY' not in r.text and 'x'*64 not in r.text
    assert 'Unexpected field' in r.json()['detail']
