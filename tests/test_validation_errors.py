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
