import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
import pytest
from target import agent
from test_quarantine_target import response_files,approval


@pytest.fixture
def procfs(tmp_path,monkeypatch):
    root=tmp_path/'proc';root.mkdir();source=tmp_path/'retained';source.write_bytes(b'harmless process metadata fixture')
    boot=root/'sys/kernel/random';boot.mkdir(parents=True);(boot/'boot_id').write_text('12345678-1234-1234-1234-123456789abc\n')
    (root/'99999/ns').mkdir(parents=True);(root/'99999/ns/pid').write_bytes(b'');(root/'self').symlink_to('99999')
    def add(pid=123,ticks=17):
        process=root/str(pid);process.mkdir();(process/'ns').mkdir();(process/'ns/pid').write_bytes(b'')
        (process/'stat').write_text(str(pid)+' (name ) with spaces) S '+'0 '*18+str(ticks)+' 0\n')
        (process/'fd').mkdir();(process/'map_files').mkdir()
        return process
    monkeypatch.setattr(agent,'response_proc_root',lambda:os.open(root,os.O_RDONLY|os.O_DIRECTORY))
    return root,source,add


def inspect(source):return agent.response_proc_scan({'dev':source.stat().st_dev,'ino':source.stat().st_ino})


def test_process_reference_metadata_finds_exact_inode_without_reading_contents(procfs,monkeypatch):
    root,source,add=procfs;process=add()
    (process/'exe').symlink_to(source);(process/'fd/7').symlink_to(source);(process/'map_files/aaa-bbb').symlink_to(source)
    other=source.parent/'same-bytes';shutil.copyfile(source,other);(process/'fd/8').symlink_to(other)
    original=agent.response_proc_read
    def metadata_only(directory,name,limit=4096):
        assert name in ('stat','sys/kernel/random/boot_id')
        return original(directory,name,limit)
    monkeypatch.setattr(agent,'response_proc_read',metadata_only)
    result=inspect(source)
    assert result['scope']=='helper_visible_process_leaders' and not result['gaps']
    assert result['matches']==[{'pid':123,'start_ticks':17,'pid_namespace':(process/'ns/pid').stat().st_ino,'references':{'executable':1,'descriptor':1,'memory_map':1}}]
    assert 'harmless' not in str(result) and str(source) not in str(result)


def test_disappearing_references_and_permission_failures_are_gaps(procfs,monkeypatch):
    _,source,add=procfs;process=add();(process/'fd/1').symlink_to('/does-not-exist')
    real=agent.os.stat
    def denied(path,*a,**k):
        if path=='exe':raise PermissionError('sensitive OS text')
        return real(path,*a,**k)
    monkeypatch.setattr(agent.os,'stat',denied)
    result=inspect(source)
    assert not result['matches'] and result['gaps']=={'executable_unavailable':1,'reference_disappeared':1}
    assert 'sensitive' not in str(result)


def test_pid_reuse_or_unreadable_identity_cannot_create_a_reference(procfs,monkeypatch):
    _,source,add=procfs;process=add();(process/'fd/1').symlink_to(source)
    real=agent.response_proc_identity;calls=0
    def changed(directory,pid):
        nonlocal calls
        calls+=1
        return real(directory,pid)|({'start_ticks':99} if calls==2 else {})
    monkeypatch.setattr(agent,'response_proc_identity',changed)
    result=inspect(source)
    assert not result['matches'] and result['gaps']=={'process_changed':1}
    (process/'stat').write_bytes(b'bad identity')
    assert inspect(source)['gaps']=={'process_unavailable':1}


@pytest.mark.parametrize('kind',['entries','processes','matches','seconds'])
def test_work_and_result_limits_are_explicit(procfs,monkeypatch,kind):
    _,source,add=procfs
    for pid in range(1,4):process=add(pid);(process/'fd/1').symlink_to(source)
    monkeypatch.setattr(agent,'RESPONSE_PROC_LIMITS',{**agent.RESPONSE_PROC_LIMITS,kind:0 if kind=='seconds' else 1})
    result=inspect(source)
    code={'entries':'entry_limit','processes':'process_limit','matches':'match_limit','seconds':'time_limit'}[kind]
    assert result['gaps'][code]==1 and len(result['matches'])<=1


def test_procfs_failure_and_symlinked_pid_directories_fail_closed(procfs,monkeypatch):
    root,source,add=procfs;process=add();(root/'999').symlink_to(process)
    result=inspect(source)
    assert result['gaps']['process_unavailable']==1
    def refused():raise ValueError('not procfs')
    monkeypatch.setattr(agent,'response_proc_root',refused)
    result=inspect(source)
    assert not result['matches'] and result['gaps']=={'procfs_unavailable':1} and result['boot_id'] is None


def test_real_procfs_open_descriptor_survives_quarantine_and_audit_is_read_only(response_files):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());ready=source.parent/'ready'
    code="import os,sys,time; f=open(sys.argv[1],'rb'); open(sys.argv[2],'w').write(os.readlink('/proc/self')); time.sleep(120)"
    process=subprocess.Popen([sys.executable,'-c',code,str(source),str(ready)])
    try:
        deadline=time.monotonic()+5
        while not ready.exists():
            assert process.poll() is None and time.monotonic()<deadline
            time.sleep(.01)
        agent.response_action(identifier,plan,approval())
        before={p.name:p.stat().st_mtime_ns for p in (vault/identifier).iterdir()}
        report=agent.response_processes(identifier,plan)
        assert report['state']=='references_found' and report['held_verified'],report
        match=next(m for m in report['observation']['matches'] if m['pid']==int(ready.read_text()))
        assert match['references']['descriptor']>=1
        assert process.poll() is None and not source.exists()
        assert before=={p.name:p.stat().st_mtime_ns for p in (vault/identifier).iterdir()}
        process.terminate();process.wait(timeout=5)
        # The helper pins held bytes during inspection; its own descriptor must
        # not create a permanent false positive after external references close.
        closed=agent.response_processes(identifier,plan)
        assert closed['state']=='none_observed' and not closed['observation']['matches'],closed
        (vault/identifier/'held').write_bytes(b'changed')
        assert agent.response_processes(identifier,plan)['state']=='unavailable'
    finally:process.terminate();process.wait(timeout=5)


def test_partial_process_findings_survive_entry_limit_and_observer_is_excluded(procfs,monkeypatch):
    root,source,add=procfs;process=add();(process/'exe').symlink_to(source)
    for n in range(10):(process/'fd'/str(n)).symlink_to(source)
    # Three root entries (sys, observer, self), one PID and one descriptor fit.
    monkeypatch.setattr(agent,'RESPONSE_PROC_LIMITS',{**agent.RESPONSE_PROC_LIMITS,'entries':5})
    result=inspect(source)
    assert result['gaps']=={'entry_limit':1} and result['matches'][0]['references']['executable']==1
    observer=root/'99999';(observer/'fd').mkdir();(observer/'fd/1').symlink_to(source)
    (process/'exe').unlink()
    for path in (process/'fd').iterdir():path.unlink()
    monkeypatch.setattr(agent,'RESPONSE_PROC_LIMITS',{**agent.RESPONSE_PROC_LIMITS,'entries':50000})
    assert not inspect(source)['matches']


def test_missing_or_restored_evidence_is_never_process_clearance(response_files):
    source,vault,plan=response_files;identifier=str(uuid.uuid4())
    assert agent.response_processes(identifier,plan)['state']=='unavailable' and not vault.exists()
    agent.response_action(identifier,plan,approval());agent.response_action(identifier,plan,approval(True),restore=True)
    assert agent.response_processes(identifier,plan)['state']=='unavailable' and source.exists()


def test_unreadable_procfs_is_unavailable_even_when_boot_metadata_is_readable(response_files,monkeypatch):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());agent.response_action(identifier,plan,approval())
    monkeypatch.setattr(agent,'response_proc_scan',lambda identity:{'scope':'helper_visible_process_leaders',
        'boot_id':'12345678-1234-1234-1234-123456789abc','pid_namespace':123,'observer_pid':99,
        'processes_examined':0,'entries_examined':0,'matches':[],'gaps':{'procfs_unavailable':1}})
    report=agent.response_processes(identifier,plan)
    assert report['held_verified'] and report['state']=='unavailable' and report['observation']['gaps']
