"""Retained deleted-host evidence is administrator-only on indirect/global reads."""
import time
import pytest
from app.db import Session, Host, Job, Behavior
from app.identity import User
from app.package_history import PackageEvent


@pytest.fixture
def retained(admin):
    with Session() as s:
        for name in ('active', 'disabled', 'deleted'):
            s.add(Host(id=name, name=name, address='192.0.2.1', fingerprint='',
                       enabled=name=='active', deleted_at=1 if name=='deleted' else 0))
            s.add(Job(id='job-'+name, host_id=name, action='refresh', state='complete',
                      output='retained-'+name, created=100 if name=='deleted' else 1))
            s.add(Behavior(id='behavior-'+name, host_id=name, evidence={'private':name}))
            s.add(PackageEvent(host_id=name, name='package-'+name, action='installed',
                               observed=time.time(), recorded=100 if name=='deleted' else 1,
                               source='inventory'))
        s.add(Job(id='global-job', host_id='', action='maintenance', state='complete'))
        s.commit()
    return admin


def role(name):
    with Session() as s:
        s.get(User,'admin').role=name
        s.commit()


@pytest.mark.parametrize('access',['viewer','operator'])
@pytest.mark.parametrize('path',[
    '/api/hosts/deleted/summary',
    '/api/jobs?host_id=deleted',
    '/api/jobs/job-deleted',
    '/api/jobs/job-deleted?host_id=deleted',
    '/api/investigations?host_id=deleted',
    '/api/package-history?host_id=deleted',
])
def test_deleted_direct_query_and_indirect_reads_denied(retained,access,path):
    role(access)
    assert retained.get(path).status_code==403


@pytest.mark.parametrize('access',['viewer','operator'])
@pytest.mark.parametrize('endpoint,key',[
    ('/api/jobs','id'),('/api/package-history','host_id'),('/api/investigations','host_id'),
])
def test_global_lists_filter_deleted_before_pagination(retained,access,endpoint,key):
    role(access)
    response=retained.get(endpoint+'?limit=1')
    assert response.status_code==200,response.text
    rows=response.json()
    if isinstance(rows,dict):rows=rows['items']
    assert len(rows)==1
    assert 'deleted' not in rows[0][key]
    response=retained.get(endpoint)
    rows=response.json()
    if isinstance(rows,dict):rows=rows['items']
    assert all('deleted' not in row[key] for row in rows)


@pytest.mark.parametrize('access',['viewer','operator','admin'])
@pytest.mark.parametrize('host',['active','disabled'])
def test_existing_active_and_disabled_read_policy_preserved(retained,access,host):
    role(access)
    for path in ('/api/jobs?host_id='+host,'/api/jobs/job-'+host,
                 '/api/investigations?host_id='+host,'/api/package-history?host_id='+host):
        assert retained.get(path).status_code==200,path
    assert retained.get('/api/jobs/global-job').status_code==200


def test_administrator_retains_deleted_records(retained):
    for path in ('/api/jobs?host_id=deleted','/api/jobs/job-deleted',
                 '/api/investigations?host_id=deleted','/api/package-history?host_id=deleted'):
        response=retained.get(path)
        assert response.status_code==200,response.text
        assert 'deleted' in response.text
    assert any(row['host_id']=='deleted' for row in retained.get('/api/jobs').json())
    assert any(row['host_id']=='deleted' for row in retained.get('/api/package-history').json()['items'])


def test_missing_or_mismatched_job_scope_remains_not_found(retained):
    role('viewer')
    assert retained.get('/api/jobs/job-deleted?host_id=active').status_code==404
    assert retained.get('/api/jobs/missing').status_code==404
    assert retained.get('/api/jobs?host_id=missing').status_code==404
