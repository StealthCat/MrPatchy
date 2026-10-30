import base64
import json
from pathlib import Path
import paramiko
import pytest
from app import ssh,tls,worker
from app.db import Session,Setting,Behavior
from app.security import seal

def test_host_key_is_pinned_before_authentication():
    key=paramiko.RSAKey.generate(2048)
    policy=ssh.Pinned(ssh.fingerprint(key))
    policy.missing_host_key(None,'test',key)
    with pytest.raises(paramiko.SSHException): ssh.Pinned('SHA256:wrong').missing_host_key(None,'test',key)

def test_tls_rejects_config_injection(tmp_path,monkeypatch):
    monkeypatch.setenv('TLS_DIR',str(tmp_path))
    with pytest.raises(ValueError): tls.apply({'domain':'example.org {\n evil','mode':'internal'})
    with pytest.raises(ValueError): tls.apply({'domain':'example.org','mode':'acme','acme_url':'https://example.org/\nadmin off'})

def test_tls_certificate_and_private_key_validated(tmp_path,monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from datetime import datetime,timedelta,timezone
    monkeypatch.setenv('TLS_DIR',str(tmp_path))
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'patchy.example.org')])
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('patchy.example.org')]),False).sign(key,hashes.SHA256())
    payload={'domain':'wrong.example.org','mode':'uploaded','certificate':cert.public_bytes(serialization.Encoding.PEM).decode(),'private_key':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()}
    with pytest.raises(ValueError,match='SAN'): tls.apply(payload)
    captured=[]
    class Result:
        def raise_for_status(self): pass
    monkeypatch.setattr(tls.httpx,'post',lambda *a,**kw: captured.append(kw) or Result())
    payload['domain']='patchy.example.org';tls.apply(payload)
    assert 'reverse_proxy app:8000' in captured[0]['content']
    assert (tmp_path/'Caddyfile').exists()

def test_ai_request_minimization_and_no_auto_trust(admin,monkeypatch):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'test-model','ai_hourly_limit':10}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('test-key')}))
        s.add(Behavior(id='b'*64,host_id='test-host',evidence={'executable':'/usr/bin/bash','sha256':'a'*64,'uid':'0','connections':[]}));s.commit()
    calls=[]
    class Result:
        def raise_for_status(self): pass
        def json(self): return {'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps({'risk':'low','explanation':'Needs verification','recommended_checks':'Review package provenance'})}]}]}
    monkeypatch.setattr(worker.ai.transport,'post',lambda *a,**kw:calls.append(kw) or Result())
    worker.investigate_one()
    assert calls[0]['json']['store'] is False
    assert 'tools' not in calls[0]['json']
    assert calls[0]['json']['text']['format']['strict'] is True
    with Session() as s:
        b=s.get(Behavior,'b'*64);assert b.verdict=='low' and not b.approved

def test_unknown_behavior_retries_use_backoff(admin,monkeypatch):
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'test-model','ai_hourly_limit':10}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('test-key')}))
        s.add(Behavior(id='c'*64,host_id='test-host',evidence={'executable':'test'}));s.commit()
    calls=[]
    def fail(*a,**kw): calls.append(1);raise TimeoutError('secret must not leak')
    monkeypatch.setattr(worker.ai.transport,'post',fail)
    worker.investigate_one();worker.investigate_one()
    assert len(calls)==1
    with Session() as s:
        b=s.get(Behavior,'c'*64);assert b.verdict=='error' and 'secret must not leak' not in b.analysis
