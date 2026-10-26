import os
from types import SimpleNamespace
from pathlib import Path
import pytest
from target import agent
from app.db import Session,Host,Setting,Job
from app.identity import User

def test_missing_engine_is_not_clean(tmp_path,monkeypatch):
    monkeypatch.setattr('shutil.which',lambda name:None)
    result=agent.security_scan([str(tmp_path)])
    assert result['state']=='incomplete' and result['scanned']==0 and result['gaps']

def test_scan_detects_and_reports_symlink_gaps(tmp_path,monkeypatch):
    file=tmp_path/'sample';file.write_text('harmless fixture')
    (tmp_path/'link').symlink_to(file)
    monkeypatch.setattr('shutil.which',lambda name:'/test/clamscan')
    def scan(args,**kw):
        if '--version' in args:return SimpleNamespace(stdout='Fixture engine',returncode=0)
        assert os.read(kw['pass_fds'][0],100)==b'harmless fixture'
        return SimpleNamespace(stdout='Fixture.Signature FOUND',returncode=1)
    monkeypatch.setattr(agent.subprocess,'run',scan)
    result=agent.security_scan([str(tmp_path)])
    assert result['scanned']==1 and result['skipped']==1 and result['state']=='incomplete'
    assert result['findings'][0]['path']==str(file)
    assert len(result['findings'][0]['sha256'])==64

def test_changed_file_is_not_accepted(tmp_path,monkeypatch):
    file=tmp_path/'sample';file.write_text('before')
    monkeypatch.setattr('shutil.which',lambda name:'/test/clamscan')
    def scan(args,**kw):
        if '--version' not in args:file.write_text('after modification')
        return SimpleNamespace(stdout='',returncode=0)
    monkeypatch.setattr(agent.subprocess,'run',scan)
    result=agent.security_scan([str(tmp_path)])
    assert result['state']=='incomplete' and result['scanned']==0

@pytest.mark.parametrize('paths',[[],['relative'],['/tmp/../etc']])
def test_invalid_scan_paths(paths):
    with pytest.raises(ValueError):agent.security_scan(paths)

def test_security_api_permissions_and_duplicate_jobs(admin):
    with Session() as s:
        s.add(Host(id='scan-host',name='scan',address='192.0.2.1',fingerprint='test'));s.commit()
    assert admin.get('/api/hosts/scan-host/security').json()['state']=='not_scanned'
    assert admin.post('/api/hosts/scan-host/security',json={'paths':['/tmp']}).status_code==200
    assert admin.post('/api/hosts/scan-host/security',json={'paths':['/tmp']}).status_code==409
    with Session() as s:s.get(User,'admin').role='operator';s.commit()
    assert admin.get('/api/hosts/scan-host/security').status_code==403
    assert admin.post('/api/hosts/scan-host/security',json={'paths':['/tmp']}).status_code==403
