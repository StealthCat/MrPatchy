import pytest
from app.db import Audit,Job,Session


def test_audit_pages_stable_order_and_detail(admin):
    with Session() as s:
        s.add_all([Audit(created=100000000000,action='page fixture',detail=str(i)) for i in range(6)]);s.commit()
    first=admin.get('/api/audit?limit=3').json()
    second=admin.get('/api/audit?offset=3&limit=3').json()
    assert len(first)==len(second)==3
    assert [x['id'] for x in first+second]==sorted([x['id'] for x in first+second],reverse=True)
    detail=admin.get('/api/audit/entries/'+str(first[0]['id'])).json()
    assert detail==first[0]
    assert admin.get('/api/audit/entries/99999999').status_code==404


@pytest.mark.parametrize('query',['offset=-1','limit=0','limit=201'])
def test_invalid_audit_pages(admin,query):
    assert admin.get('/api/audit?'+query).status_code==400


def test_job_detail_scope_and_payload_projection(admin):
    with Session() as s:
        s.add(Job(id='detail-fixture',host_id='host-one',action='refresh',state='complete',payload={'private':'not returned'},output='stored'));s.commit()
    assert admin.get('/api/jobs/detail-fixture?host_id=host-two').status_code==404
    for query in ('','?host_id=host-one'):
        row=admin.get('/api/jobs/detail-fixture'+query).json()
        assert row['host_id']=='host-one' and row['output']=='stored' and 'payload' not in row


@pytest.mark.parametrize('role',['viewer','operator'])
def test_audit_pages_require_administrator(admin,role):
    assert admin.put('/api/users',json={'username':'activity-viewer','role':role,'password':'activity-test-password-long'}).status_code==200
    admin.post('/api/logout')
    response=admin.post('/api/login',json={'username':'activity-viewer','password':'activity-test-password-long'})
    assert response.status_code==200
    assert admin.get('/api/audit?limit=1').status_code==403
    assert admin.get('/api/audit/entries/1').status_code==403
