import time
from types import SimpleNamespace
from sqlalchemy import select
from app.main import app
from app.db import Session,Host,Job,Setting
from app.identity import User,code,consume_otp
from app.security import seal
from app import operations
from test_review_regressions import create_host

def login_as(client,name,role):
    with Session() as s:
        from app.security import password_hash
        s.add(User(username=name,password=password_hash('long-test-password'),role=role));s.commit()
    r=client.post('/api/login',json={'username':name,'password':'long-test-password'})
    assert r.status_code==200
    client.headers['X-CSRF-Token']=r.json()['csrf']

def test_viewer_cannot_mutate_or_read_installer(client):
    login_as(client,'reader','viewer')
    assert client.post('/api/hosts',json={'name':'bad','address':'192.0.2.1'}).status_code==403
    assert client.get('/api/hosts/x/installer').status_code==403
    assert client.get('/api/hosts').status_code==200
    assert client.get('/api/settings').status_code==403

def test_operator_cannot_deploy_or_change_trust(client):
    login_as(client,'operator','operator')
    assert client.post('/api/hosts/x/actions/deploy').status_code==403
    assert client.put('/api/users',json={'username':'operator','role':'admin'}).status_code==403
    assert client.post('/api/hosts/x/actions/refresh').status_code==404

def test_role_change_revokes_existing_session(admin):
    login_as(admin,'reader','viewer')
    with Session() as s:
        u=s.get(User,'reader');u.enabled=False;s.commit()
    assert admin.get('/api/hosts').status_code==401

def test_totp_vector_and_replay():
    # RFC 6238 SHA-1 test vector reduced to six digits.
    secret='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    assert code(secret,1)=='287082'
    user=SimpleNamespace(otp_secret=seal(secret),otp_counter=-1)
    assert consume_otp(user,'287082',now=59)
    assert not consume_otp(user,'287082',now=59)

def test_mfa_enable_invalidates_sessions(admin):
    from app.security import unseal
    r=admin.post('/api/identity/mfa',json={'password':'test-password-long-enough'})
    assert r.status_code==200
    otp=code(r.json()['secret'],int(time.time()//30))
    assert admin.post('/api/identity/mfa/confirm',json={'otp':otp}).status_code==200
    assert admin.get('/api/hosts').status_code==401
    assert admin.post('/api/login',json={'password':'test-password-long-enough'}).status_code==401

def test_window_boundaries():
    # 2024-01-01 Monday at midnight UTC
    now=1704067200
    w=[{'days':[0],'start':60,'end':120}]
    assert not operations.in_window(w,now)
    assert operations.in_window(w,now+3600)
    assert not operations.in_window(w,now+7200)

def test_failed_canary_blocks_next(admin):
    with Session() as s:
        create_host(s)
        first=Job(id='first',host_id='review-host',action='patch',state='failed')
        second=Job(id='second',host_id='review-host',action='patch',payload={'_depends_on':['first']})
        s.add_all([first,second]);s.commit()
        assert not operations.eligible(s,second)
        assert second.state=='blocked'

def test_alert_ack_suppresses_delivery(admin,monkeypatch):
    with Session() as s:
        create_host(s)
    operations.collect_alerts()
    with Session() as s:
        a=s.scalar(select(operations.Alert));assert a.kind=='stale'
        a.state='acknowledged'
        s.add(Setting(key='notifications',value={'encrypted':seal('{"enabled":true,"url":"https://example.test","token":""}')}));s.commit()
    monkeypatch.setattr(operations.httpx,'post',lambda *a,**k: (_ for _ in ()).throw(AssertionError('Unexpected delivery')))
    operations.deliver_one()

def test_webhook_retry_and_success(admin,monkeypatch):
    with Session() as s:
        s.add(operations.Alert(id='alert',host_id='host',kind='stale',message='test'))
        s.add(Setting(key='notifications',value={'encrypted':seal('{"enabled":true,"url":"https://example.test","token":""}')}));s.commit()
    calls=[]
    monkeypatch.setattr(operations.httpx,'post',lambda *a,**k:calls.append(k) or SimpleNamespace(raise_for_status=lambda:None))
    operations.deliver_one();operations.deliver_one()
    assert len(calls)==1 and calls[0]['follow_redirects'] is False

def test_window_invalid_values_rejected(admin):
    assert admin.put('/api/operations/h/window',json={'windows':[{'days':[8],'start':0,'end':60}]}).status_code==400

def test_bootstrap_admin_cannot_be_disabled(admin):
    assert admin.put('/api/users',json={'username':'admin','role':'viewer','enabled':False}).status_code==400

def test_advisories_use_source_versions_and_paginate(monkeypatch):
    from app import advisories
    inv={'os':'ID=ubuntu\nVERSION_ID="24.04"','status':'Package: binary\nArchitecture: amd64\nVersion: 2+b1\nSource: source (2)\nStatus: install ok installed\n'}
    calls=[]
    def post(url,**kwargs):
        calls.append(kwargs['json'])
        return SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'results':[{'vulns':[{'id':'CVE-test'}]}]})
    monkeypatch.setattr(advisories.httpx,'post',post)
    result=advisories.scan(inv,['binary:amd64'])
    assert calls[0]['queries'][0]=={'package':{'ecosystem':'Ubuntu:24.04:LTS','name':'source'},'version':'2'}
    assert result['results'][0]['vulnerabilities'][0]['id']=='CVE-test'

def test_derivative_advisory_coverage_is_not_assumed():
    import pytest
    from app.advisories import ecosystem
    with pytest.raises(ValueError):ecosystem('ID=raspbian\nVERSION_ID="12"')

def test_backup_restore_round_trip(tmp_path):
    import sqlite3
    import importlib.util
    from pathlib import Path
    spec=importlib.util.spec_from_file_location('backup',Path(__file__).parents[1]/'scripts/backup.py')
    backup=importlib.util.module_from_spec(spec);spec.loader.exec_module(backup)
    source=tmp_path/'source';source.mkdir()
    with sqlite3.connect(source/'mrpatchy.db') as db:db.execute('CREATE TABLE example (value TEXT)');db.execute("INSERT INTO example VALUES ('kept')")
    (source/'secret.key').write_bytes(b'test-key')
    backup.backup(source,tmp_path/'backup.tar.gz')
    backup.restore(tmp_path/'backup.tar.gz',tmp_path/'restored')
    with sqlite3.connect(tmp_path/'restored/mrpatchy.db') as db:assert db.execute('SELECT value FROM example').fetchone()[0]=='kept'
    assert (tmp_path/'backup.tar.gz').stat().st_mode&0o777==0o600
