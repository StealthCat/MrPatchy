from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading
import time
import httpx
import pytest
from app import tls

class OK:
    def raise_for_status(self): pass

def test_rejected_tls_configuration_does_not_leave_uploaded_secrets(tmp_path,monkeypatch):
    monkeypatch.setenv('TLS_DIR',str(tmp_path))
    with pytest.raises(Exception):
        tls.apply({'domain':'patchy.example.org','mode':'uploaded','certificate':'bad-cert','private_key':'sensitive-invalid-key'})
    assert not list(tmp_path.iterdir())

def test_acme_credentials_are_rejected_even_with_empty_username(tmp_path,monkeypatch):
    monkeypatch.setenv('TLS_DIR',str(tmp_path))
    with pytest.raises(ValueError):
        tls.apply({'domain':'patchy.example.org','mode':'acme','acme_url':'https://:secret@ca.example.org/directory'})

def test_failed_tls_persistence_restores_previous_live_config(tmp_path,monkeypatch):
    monkeypatch.setenv('TLS_DIR',str(tmp_path))
    previous='previous validated configuration'
    (tmp_path/'Caddyfile').write_text(previous)
    calls=[]
    monkeypatch.setattr(tls.httpx,'post',lambda *a,**kw:calls.append(kw['content']) or OK())
    original=Path.replace
    def fail_save(self,target):
        if self.name=='Caddyfile.pending': raise OSError('simulated persistence failure')
        return original(self,target)
    monkeypatch.setattr(Path,'replace',fail_save)
    with pytest.raises(OSError): tls.apply({'domain':'patchy.example.org','mode':'internal'})
    assert calls[-1]==previous and len(calls)==2
    assert (tmp_path/'Caddyfile').read_text()==previous
    assert [p.name for p in tmp_path.iterdir()]==['Caddyfile']

def test_uncertain_caddy_state_preserves_recovery_material(tmp_path,monkeypatch):
    monkeypatch.setenv('TLS_DIR',str(tmp_path));(tmp_path/'Caddyfile').write_text('previous')
    def timeout(*a,**kw): raise httpx.TimeoutException('Timeout after possible apply')
    monkeypatch.setattr(tls.httpx,'post',timeout)
    with pytest.raises(RuntimeError,match='rollback'):
        tls.apply({'domain':'patchy.example.org','mode':'internal'})
    assert list(tmp_path.glob('*/recovery-required'))

def test_concurrent_tls_changes_are_serialized(tmp_path,monkeypatch):
    monkeypatch.setenv('TLS_DIR',str(tmp_path))
    counts={'active':0,'maximum':0};lock=threading.Lock();calls=[]
    def apply(*a,**kw):
        with lock:
            counts['active']+=1;counts['maximum']=max(counts.values())
        time.sleep(.02)
        calls.append(kw['content'])
        with lock: counts['active']-=1
        return OK()
    monkeypatch.setattr(tls.httpx,'post',apply)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda n:tls.apply({'domain':n+'.example.org','mode':'internal'}),['one','two']))
    assert counts['maximum']==1
    assert (tmp_path/'Caddyfile').read_text()==calls[-1]
