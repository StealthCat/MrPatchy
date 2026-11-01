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
    previous='previous.example.org {\n tls internal\n reverse_proxy app:8000\n}\n'
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
    monkeypatch.setenv('TLS_DIR',str(tmp_path));(tmp_path/'Caddyfile').write_text('previous.example.org {\n tls internal\n reverse_proxy app:8000\n}\n')
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

def _state_folders(tmp_path):
    return [p for p in tmp_path.iterdir() if p.is_dir()]

def test_successful_apply_prunes_stale_state_folders_with_old_secrets(tmp_path,monkeypatch):
    monkeypatch.setenv('TLS_DIR',str(tmp_path))
    monkeypatch.setattr(tls.httpx,'post',lambda *a,**kw:OK())
    for key in ('eab-secret-one','eab-secret-two','eab-secret-three'):
        tls.apply({'domain':'patchy.example.org','mode':'acme','acme_url':'https://ca.example.org/directory','eab_id':'id','eab_key':key})
    tls.apply({'domain':'patchy.example.org','mode':'acme','acme_url':'https://ca.example.org/directory','clear_eab':True})
    folders=_state_folders(tmp_path)
    assert len(folders)==2
    assert 'eab-secret-one' not in ''.join(p.joinpath('profiles.json').read_text() for p in folders)
    assert tls.directory().joinpath('Caddyfile').read_text().count(folders[0].name)+tls.directory().joinpath('Caddyfile').read_text().count(folders[1].name)==1

def test_pruning_keeps_recovery_required_folders(tmp_path,monkeypatch):
    monkeypatch.setenv('TLS_DIR',str(tmp_path))
    monkeypatch.setattr(tls.httpx,'post',lambda *a,**kw:OK())
    stale=tmp_path/'11111111-1111-1111-1111-111111111111';stale.mkdir()
    (stale/'recovery-required').write_text('x');(stale/'profiles.json').write_text('{}')
    tls.apply({'domain':'a.example.org','mode':'internal'})
    tls.apply({'domain':'b.example.org','mode':'internal'})
    tls.apply({'domain':'c.example.org','mode':'internal'})
    assert (stale/'profiles.json').exists()
    assert len(_state_folders(tmp_path))==3

def test_failed_apply_does_not_prune_previous_state(tmp_path,monkeypatch):
    monkeypatch.setenv('TLS_DIR',str(tmp_path))
    monkeypatch.setattr(tls.httpx,'post',lambda *a,**kw:OK())
    tls.apply({'domain':'a.example.org','mode':'internal'})
    tls.apply({'domain':'b.example.org','mode':'internal'})
    before={p.name for p in _state_folders(tmp_path)}
    calls=[]
    def boom(*a,**kw):
        calls.append(1)
        if len(calls)==1: raise httpx.ConnectError('down')
        return OK()
    monkeypatch.setattr(tls.httpx,'post',boom)
    with pytest.raises(httpx.ConnectError): tls.apply({'domain':'c.example.org','mode':'internal'})
    assert {p.name for p in _state_folders(tmp_path)}==before
