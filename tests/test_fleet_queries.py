import time
from app.db import Session,Host,Package
from app.fleet_queries import PAGE_MAX


def add_host(name,os_name='Ubuntu 24.04',seen=None,deleted=0):
    with Session() as s:
        h=Host(id='h-'+name,name=name,address='192.0.2.9',fingerprint='',state='online',last_seen=time.time() if seen is None else seen,deleted_at=deleted,inventory={'os':os_name})
        s.add(h);s.commit();return h.id


def add_package(host_id,name,candidate='2',since=None,priority='critical'):
    with Session() as s:
        s.add(Package(id=host_id+':'+name,host_id=host_id,name=name,installed='1',candidate=candidate,priority=priority,available_since=time.time() if since is None else since));s.commit()


def save(admin,name='Overdue openssl',**filter):
    r=admin.post('/api/fleet/queries',json={'name':name,'filter':filter});assert r.status_code==200,r.text;return r.json()


def test_overdue_package_query_drills_down_to_exact_hosts_and_flags_stale(admin):
    old=time.time()-30*86400
    a=add_host('alpha');b=add_host('bravo',seen=1.0);c=add_host('charlie');d=add_host('deleted',deleted=5)
    add_package(a,'openssl',since=old);add_package(b,'openssl',since=old);add_package(c,'openssl',since=time.time());add_package(d,'openssl',since=old)
    q=save(admin,package='openssl',overdue_only=True)
    r=admin.get('/api/fleet/queries/'+q['id']+'/results');assert r.status_code==200,r.text;body=r.json()
    assert [h['name'] for h in body['hosts']]==['alpha','bravo']
    assert body['matched_hosts']==2 and body['stale_hosts']==1
    assert {h['name']:h['fresh'] for h in body['hosts']}=={'alpha':True,'bravo':False}
    pkg=body['hosts'][0]['matching_packages'][0]
    assert pkg['name']=='openssl' and pkg['overdue'] is True and body['query']['version']==1 and body['as_of']>0


def test_pagination_is_bounded_and_filters_combine(admin):
    for i in range(3):add_host('web%d'%i)
    add_host('db',os_name='Debian 12')
    q=save(admin,'Ubuntu',os='Ubuntu')
    page=admin.get('/api/fleet/queries/'+q['id']+'/results?limit=2&offset=2').json()
    assert page['matched_hosts']==3 and [h['name'] for h in page['hosts']]==['web2']
    assert admin.get('/api/fleet/queries/'+q['id']+'/results?limit=%d'%(PAGE_MAX+1)).status_code==400
    assert admin.get('/api/fleet/queries/'+q['id']+'/results?offset=-1').status_code==400


def test_update_requires_current_version_and_names_are_unique(admin):
    q=save(admin);assert admin.post('/api/fleet/queries',json={'name':q['name'],'filter':{}}).status_code==409
    stale=admin.put('/api/fleet/queries/'+q['id'],json={'name':'Renamed','filter':{'os':'x'},'expected_version':9});assert stale.status_code==409
    ok=admin.put('/api/fleet/queries/'+q['id'],json={'name':'Renamed','filter':{'os':'x'},'expected_version':1});assert ok.json()['version']==2
    assert admin.delete('/api/fleet/queries/'+q['id']).status_code==200
    assert admin.get('/api/fleet/queries/'+q['id']+'/results').status_code==404
