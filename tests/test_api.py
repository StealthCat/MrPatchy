import ast
import base64
import re
import subprocess
from app.db import Session,Host,Package,Job,Behavior,Setting
from app import worker
FINGERPRINT='SHA256:'+'a'*43

def host(admin):
    r=admin.post('/api/hosts',json={'name':'Test Pi','address':'192.0.2.10'})
    assert r.status_code==200,r.text
    return r.json()['id']

def test_auth_and_csrf(client):
    assert client.get('/api/hosts').status_code==401
    r=client.post('/api/login',json={'password':'test-password-long-enough'})
    assert r.status_code==200
    assert 'HttpOnly' in r.headers['set-cookie']
    assert client.post('/api/hosts',json={'name':'n','address':'127.0.0.1'}).status_code==403

def test_offline_installer_is_self_contained(admin,tmp_path):
    id=host(admin)
    result=admin.get(f'/api/hosts/{id}/installer')
    script=result.text
    assert result.status_code==200
    assert 'apt-get' not in script and 'curl ' not in script
    assert 'restrict,command=' in script and '/opt/drpatch' in script
    path=tmp_path/'installer.sh';path.write_text(script)
    subprocess.run(['bash','-n',str(path)],check=True)
    for block in re.findall(r"python3 - <<'PY'\n(.*?)\nPY",script,re.S): ast.parse(block)
    assert admin.post(f'/api/hosts/{id}/actions/deploy').status_code==400
    assert admin.put(f'/api/hosts/{id}/fingerprint',json={'fingerprint':FINGERPRINT}).status_code==200
    assert admin.post(f'/api/hosts/{id}/actions/deploy').status_code==200

def test_enrollment_link_expiry(admin):
    id=host(admin)
    link=admin.post(f'/api/hosts/{id}/enrollment-link').json()['url']
    assert admin.get(link).status_code==200
    with Session() as s:
        from sqlalchemy import select
        row=s.scalar(select(Setting).where(Setting.key.like('enroll:%')))
        row.value={**row.value,'expires':0};s.commit()
    assert admin.get(link).status_code==404

def test_no_shell_or_source_path_injection(admin):
    assert admin.post('/api/hosts',json={'name':'bad','address':'host;touch /tmp/x'}).status_code==422
    id=host(admin)
    assert admin.put(f'/api/hosts/{id}/repositories',json={'path':'/etc/sudoers','content':'bad'}).status_code==400
    assert admin.put(f'/api/hosts/{id}/repositories',json={'path':'/etc/apt/sources.list','content':'deb [trusted=yes] https://example.com stable main'}).status_code==400
    assert admin.put(f'/api/hosts/{id}/repositories',json={'path':'/etc/apt/sources.list','content':'deb file:/tmp/repo stable main'}).status_code==400

def test_repository_write_becomes_reviewable_job(admin):
    id=host(admin)
    r=admin.put(f'/api/hosts/{id}/repositories',json={'path':'/etc/apt/sources.list.d/vendor.sources','content':'Types: deb\nURIs: https://example.org/debian\nSuites: stable\nComponents: main\n'})
    assert r.status_code==200
    with Session() as s:
        job=s.get(Job,r.json()['job_id'])
        assert job.action=='repository' and job.state=='queued'

def test_settings_validation_and_secret_redaction(admin):
    cfg=admin.get('/api/settings').json()
    body={k:cfg[k] for k in ['repo_minutes','deadlines','ai_enabled','ai_model','ai_hourly_limit']}
    body['api_key']='secret-not-for-ui'
    assert admin.put('/api/settings',json=body).status_code==200
    result=admin.get('/api/settings')
    assert result.json()['api_key_configured']
    assert 'secret-not-for-ui' not in result.text
    body['repo_minutes']=0
    assert admin.put('/api/settings',json=body).status_code==422

def test_patch_requires_fresh_inventory_and_honors_holds(admin):
    import time
    id=host(admin)
    with Session() as s:
        h=s.get(Host,id);h.last_repo=time.time()
        s.add(Package(id=id+':bash:arm64',host_id=id,name='bash:arm64',installed='1',candidate='2',held=True));s.commit()
    assert admin.post(f'/api/hosts/{id}/patch',json={'packages':['bash:arm64']}).status_code==400
    with Session() as s:
        p=s.get(Package,id+':bash:arm64');p.held=False;s.commit()
    r=admin.post(f'/api/hosts/{id}/patch',json={'packages':['bash:arm64']})
    assert r.status_code==200
    with Session() as s: assert s.get(Job,r.json()['job_id']).payload['packages']==['bash:arm64=2']

def test_patch_route_shares_worker_patch_validation(admin):
    import time
    id=host(admin)
    with Session() as s:
        h=s.get(Host,id);h.last_repo=0
        s.add(Package(id=id+':bash',host_id=id,name='bash',installed='1',candidate='2',dpkg_state='install ok installed'));s.commit()
    assert admin.post(f'/api/hosts/{id}/patch',json={'packages':['bash']}).status_code==409
    with Session() as s: s.get(Host,id).last_repo=time.time();s.commit()
    r=admin.post(f'/api/hosts/{id}/patch',json={'packages':['bash'],'expected_versions':{'bash':'1'}})
    assert r.status_code==409 and 'bash' in r.text
    with Session() as s: s.get(Package,id+':bash').dpkg_state='install ok half-configured';s.commit()
    r=admin.post(f'/api/hosts/{id}/patch',json={'packages':['bash']})
    assert r.status_code==400 and 'bash' in r.text
    with Session() as s: s.get(Package,id+':bash').dpkg_state='install ok installed';s.commit()
    assert admin.post(f'/api/hosts/{id}/patch',json={'packages':['bash'],'expected_versions':{'bash':'2'}}).status_code==200

def test_ai_never_automatically_approves(admin,monkeypatch):
    import time
    id=host(admin)
    with Session() as s:
        h=s.get(Host,id);h.baseline={'/managed':'aaa'};s.commit()
        snapshot={'telemetry':{'collected':time.time(),'hashed_at':time.time(),'managed':{'/managed':'BAD'},'processes':[{'pid':12,'executable':'/usr/bin/test','uid':'0','sha256':'b'*64,'connections':[]}]}}
        worker.ingest(s,h,snapshot)
        from sqlalchemy import select
        row=s.scalar(select(Behavior))
        assert row.approved is False and row.verdict=='pending'
        assert h.integrity[0]['path']=='/managed'
        row.verdict='low';s.commit();assert row.approved is False
        rid=row.id
    assert admin.put('/api/investigations/'+rid,json={'approved':True}).status_code==200
    assert admin.get('/api/investigations').json()[0]['approved'] is True

def test_changed_connection_has_new_identity():
    a={'pid':1,'executable':'/bin/a','sha256':'f'*64,'uid':'1000','connections':[{'protocol':'tcp','local':'10.0.0.2','local_port':50000,'remote':'10.0.0.1','remote_port':443,'state':'01'}]}
    b={**a,'pid':2,'connections':[{**a['connections'][0],'local_port':50001}]}
    assert worker.behavior_evidence(a)==worker.behavior_evidence(b)
    b['connections'][0]['remote_port']=22
    assert worker.behavior_evidence(a)!=worker.behavior_evidence(b)


def test_metrics_host_count_excludes_deleted_servers(admin):
    keep=host(admin)
    gone=admin.post('/api/hosts',json={'name':'Gone Pi','address':'192.0.2.11'}).json()['id']
    assert 'mrpatchy_hosts 2\n' in admin.get('/api/metrics').text
    with Session() as s:
        s.get(Host,gone).deleted_at=1;s.commit()
    assert 'mrpatchy_hosts 1\n' in admin.get('/api/metrics').text
    assert keep

def test_patch_route_reads_config_once_per_batch(admin):
    import time
    from sqlalchemy import event
    from app.db import engine
    id=host(admin)
    names=['p%d'%i for i in range(12)]
    with Session() as s:
        s.get(Host,id).last_repo=time.time()
        for n in names: s.add(Package(id=id+':'+n,host_id=id,name=n,installed='1',candidate='2',dpkg_state='install ok installed'))
        s.commit()
    seen=[]
    def spy(conn,cur,stmt,*a): seen.append(stmt)
    event.listen(engine,'before_cursor_execute',spy)
    try: r=admin.post(f'/api/hosts/{id}/patch',json={'packages':names})
    finally: event.remove(engine,'before_cursor_execute',spy)
    assert r.status_code==200
    assert sum('FROM settings' in x for x in seen)<=4  # constant, not one per package
