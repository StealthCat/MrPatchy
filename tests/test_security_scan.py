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

@pytest.fixture
def healthy_engine(monkeypatch):
    import time
    monkeypatch.setattr('shutil.which',lambda name:'/test/clamscan')
    version='ClamAV 1.4.0/12345/'+time.strftime('%a %b %d %H:%M:%S %Y',time.gmtime())+'\n'
    def scan(args,**kw):
        return SimpleNamespace(stdout=version if '--version' in args else '',returncode=0)
    monkeypatch.setattr(agent.subprocess,'run',scan)
    return version

@pytest.mark.parametrize('age,state',[(0,'recent'),(7*86400,'recent'),(7*86400+1,'stale'),(-301,'future')])
def test_signature_build_age_boundary(age,state):
    from datetime import datetime,timezone
    built=datetime(2026,10,20,12,tzinfo=timezone.utc).timestamp()
    result=agent.signature_status('ClamAV 1.4.0/12345/Tue Oct 20 12:00:00 2026',built+age)
    assert result['state']==state and result['built_at']==built

@pytest.mark.parametrize('version',['ClamAV 1.4.0','Fixture engine','ClamAV 1/12/Tue Bad 20 12:00:00 2026','ClamAV 1/12/Tue Oct 99 12:00:00 2026'])
def test_unknown_signature_metadata_is_explicit(version):
    assert agent.signature_status(version,0)['state']=='unknown'

@pytest.mark.parametrize('path',['/proc','/proc/1','/sys','/dev','/run','/var/lib/mrpatchy-quarantine/files','//proc'])
def test_excluded_roots_are_rejected(path):
    with pytest.raises(ValueError):agent.security_scan([path])

def test_parent_symlink_is_rejected(tmp_path,healthy_engine):
    real=tmp_path/'real';real.mkdir();(real/'nested').mkdir()
    (tmp_path/'alias').symlink_to(real,target_is_directory=True)
    with pytest.raises(ValueError,match='ancestors'):
        agent.security_scan([str(tmp_path/'alias'/'nested')])

def test_recent_scan_and_unknown_signature_coverage(tmp_path,healthy_engine,monkeypatch):
    (tmp_path/'file').write_text('sample')
    good=agent.security_scan([str(tmp_path)])
    assert good['state']=='no_detections' and good['signatures']['state']=='recent'
    monkeypatch.setattr(agent.subprocess,'run',lambda args,**kw:SimpleNamespace(stdout='ClamAV 1.4.0' if '--version' in args else '',returncode=0))
    bad=agent.security_scan([str(tmp_path)])
    assert bad['state']=='incomplete' and bad['scanned']==1 and bad['skipped']==0 and bad['finished']

def test_directory_swap_cannot_follow_outside_symlink(tmp_path,healthy_engine,monkeypatch):
    root=tmp_path/'root';root.mkdir();inside=root/'child';inside.mkdir();(inside/'file').write_text('inside')
    outside=tmp_path/'outside';outside.mkdir();(outside/'secret').write_text('outside')
    opened=agent.os.open;scanned=[]
    def race(path,flags,*args,**kwargs):
        if path=='child':
            inside.rename(root/'old');inside.symlink_to(outside,target_is_directory=True)
        return opened(path,flags,*args,**kwargs)
    monkeypatch.setattr(agent.os,'open',race)
    def scan(args,**kwargs):
        if '--version' in args:return SimpleNamespace(stdout=healthy_engine,returncode=0)
        scanned.append(os.read(kwargs['pass_fds'][0],100));return SimpleNamespace(stdout='',returncode=0)
    monkeypatch.setattr(agent.subprocess,'run',scan)
    report=agent.security_scan([str(root)])
    assert b'outside' not in scanned and report['state']=='incomplete'

def test_replaced_file_path_is_not_accepted(tmp_path,healthy_engine,monkeypatch):
    file=tmp_path/'file';file.write_text('original')
    def scan(args,**kw):
        if '--version' in args:return SimpleNamespace(stdout=healthy_engine,returncode=0)
        file.unlink();file.write_text('replacement')
        return SimpleNamespace(stdout='Fixture FOUND',returncode=1)
    monkeypatch.setattr(agent.subprocess,'run',scan)
    result=agent.security_scan([str(tmp_path)])
    assert result['state']=='incomplete' and result['scanned']==0 and not result['findings']

def test_empty_directory_traversal_budget_is_bounded(tmp_path,healthy_engine,monkeypatch):
    for n in range(20):(tmp_path/str(n)).mkdir()
    monkeypatch.setattr(agent,'SCAN_MAX_ENTRIES',3)
    result=agent.security_scan([str(tmp_path)])
    assert result['state']=='incomplete' and result['entries_examined']==4
    assert any('budget' in gap for gap in result['gaps'])

def test_depth_limit_and_fds_closed(tmp_path,healthy_engine,monkeypatch):
    path=tmp_path
    for n in range(8):path=path/'child';path.mkdir()
    (path/'file').write_text('deep')
    monkeypatch.setattr(agent,'SCAN_MAX_DEPTH',2)
    before=len(os.listdir('/proc/self/fd'))
    result=agent.security_scan([str(tmp_path)])
    assert result['scanned']==0 and any('depth limit' in gap for gap in result['gaps'])
    assert len(os.listdir('/proc/self/fd'))==before

def test_database_change_during_scan_is_incomplete(tmp_path,healthy_engine,monkeypatch):
    (tmp_path/'file').write_text('sample');versions=iter([healthy_engine,healthy_engine.replace('/12345/','/12346/')])
    monkeypatch.setattr(agent.subprocess,'run',lambda args,**kw:SimpleNamespace(stdout=next(versions) if '--version' in args else '',returncode=0))
    result=agent.security_scan([str(tmp_path)])
    assert result['signatures']['state']=='changed' and result['state']=='incomplete' and result['scanned']==1

def test_stale_signatures_retain_detections(tmp_path,healthy_engine,monkeypatch):
    (tmp_path/'file').write_text('sample')
    monkeypatch.setattr(agent.subprocess,'run',lambda args,**kw:SimpleNamespace(stdout='ClamAV 1.4.0/12345/Tue Oct 20 12:00:00 2020' if '--version' in args else 'Fixture FOUND',returncode=0 if '--version' in args else 1))
    result=agent.security_scan([str(tmp_path)])
    assert result['state']=='incomplete' and result['signatures']['state']=='stale' and len(result['findings'])==1

def test_final_health_failure_keeps_scan_incomplete(tmp_path,healthy_engine,monkeypatch):
    (tmp_path/'file').write_text('sample');calls=[]
    def scan(args,**kw):
        if '--version' in args:
            calls.append(True)
            if len(calls)>1:raise OSError('gone')
            return SimpleNamespace(stdout=healthy_engine,returncode=0)
        return SimpleNamespace(stdout='',returncode=0)
    monkeypatch.setattr(agent.subprocess,'run',scan)
    result=agent.security_scan([str(tmp_path)])
    assert result['state']=='incomplete' and result['signatures']['state']=='unknown' and result['scanned']==1
