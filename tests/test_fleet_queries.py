import time
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import event
from app.db import Session,Host,Package
from app.fleet_queries import PAGE_MAX,PACKAGES_PER_HOST


def add_host(name,os_name='Ubuntu 24.04',seen=None,deleted=0):
    with Session() as s:
        observed=time.time() if seen is None else seen
        h=Host(id='h-'+name,name=name,address='192.0.2.9',fingerprint='',state='online',last_seen=observed,deleted_at=deleted,inventory={'os':os_name,'collected':observed})
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


def test_package_evidence_materialization_is_bounded_in_sql(admin):
    host=add_host('many')
    with Session() as s:
        s.bulk_insert_mappings(Package,[{'id':host+':pkg-'+str(i),'host_id':host,'name':f'pkg-{i:05d}',
            'installed':'1','candidate':'2','priority':'normal','available_since':time.time()} for i in range(2000)])
        s.commit()
    q=save(admin,'Bounded',package='pkg-');loaded=[]
    def load(package,context):loaded.append(package.id)
    event.listen(Package,'load',load)
    try:response=admin.get('/api/fleet/queries/'+q['id']+'/results')
    finally:event.remove(Package,'load',load)
    assert response.status_code==200
    row=response.json()['hosts'][0]
    assert row['matching_package_count']==2000 and len(row['matching_packages'])==PACKAGES_PER_HOST
    assert len(loaded)<=PACKAGES_PER_HOST


def test_future_or_missing_observation_never_counts_as_fresh(admin):
    now=time.time();ids=[add_host(name) for name in ('future-contact','future-observation','missing','fresh')]
    with Session() as s:
        s.get(Host,ids[0]).last_seen=now+86400
        s.get(Host,ids[1]).inventory={'os':'Ubuntu','collected':now+86400}
        s.get(Host,ids[2]).inventory={'os':'Ubuntu'}
        s.commit()
    q=save(admin,'Freshness')
    body=admin.get('/api/fleet/queries/'+q['id']+'/results').json()
    assert body['stale_hosts']==3
    assert {row['name'] for row in body['hosts'] if row['fresh']}=={'fresh'}


def test_concurrent_updates_cannot_both_accept_one_saved_version(admin,monkeypatch):
    from app import main
    original=main.saved_query_or_404
    def slow_read(*args,**kwargs):
        row=original(*args,**kwargs);time.sleep(.03);return row
    monkeypatch.setattr(main,'saved_query_or_404',slow_read)
    q=save(admin,'Concurrent')
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses=list(pool.map(lambda i:admin.put('/api/fleet/queries/'+q['id'],
            json={'name':'Change '+str(i),'filter':{},'expected_version':1}),range(4)))
    assert sorted(response.status_code for response in responses)==[200,409,409,409]
