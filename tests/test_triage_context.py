"""Read-only triage context on real procfs, plus controlled collection races."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import time
from contextlib import contextmanager
import pytest
from target import agent,bridge


@pytest.fixture
def live_script(tmp_path):
    script=tmp_path/'fixture.py';script.write_text('import time\nprint("ready",flush=True)\ntime.sleep(120)\n')
    process=subprocess.Popen([sys.executable,str(script),'DO-NOT-EXPORT-ARGUMENT'],env={**os.environ,'TRIAGE_SECRET':'DO-NOT-EXPORT-ENVIRONMENT'},stdout=subprocess.PIPE)
    try:
        assert process.stdout.readline()==b'ready\n'
        try:os.readlink('/proc/'+str(process.pid)+'/exe')
        except (PermissionError,FileNotFoundError):pytest.skip('Execution environment does not expose child procfs; native Linux CI validates the live target')
        yield process,script
    finally:
        process.terminate();process.wait(timeout=5);process.stdout.close()


@pytest.fixture
def context_files(tmp_path,monkeypatch):
    proc=tmp_path/'314';proc.mkdir();(proc/'ns').mkdir()
    for name in ('pid','net','mnt','user'):(proc/'ns'/name).touch()
    script=tmp_path/'fixture.py';script.write_text('import time\ntime.sleep(120)\n')
    executable=tmp_path/'python3';executable.write_bytes(b'verified interpreter fixture')
    (proc/'exe').symlink_to(executable);(proc/'root').symlink_to('/')
    (proc/'stat').write_text('314 (fixture) S '+'0 '*18+'12345 0\n')
    (proc/'status').write_text('Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n')
    (proc/'maps').write_text('');(proc/'cgroup').write_text('0::/fixture.service\n')
    (proc/'cmdline').write_bytes(b'python3\0'+os.fsencode(script)+b'\0DO-NOT-EXPORT-ARGUMENT\0')
    monkeypatch.setattr(agent,'response_service_boot',lambda:'11111111-1111-1111-1111-111111111111')
    monkeypatch.setattr(agent,'response_proc_root',lambda:os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
    process=SimpleNamespace(pid=314,proc=proc)
    yield process,script


@contextmanager
def opened(process):
    fd=os.open(str(getattr(process,'proc','/proc/'+str(process.pid))),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:yield fd
    finally:os.close(fd)


def inspect_context(process):
    with opened(process) as fd:
        path=os.readlink('exe',dir_fd=fd)
        checksum=agent.hash_artifact(Path('/proc/self/fd')/str(fd)/'exe',{})
        return agent.triage_process_context(fd,process.pid,path,checksum,time.monotonic()+10)


def test_real_interpreter_script_and_credentials_are_bound_without_secrets(live_script):
    process,script=live_script
    facts,data=inspect_context(process)
    assert facts['process']==data['process'] and data['process']['pid']==process.pid
    assert data['process']['start_ticks']>0 and data['process']['boot_id']
    assert data['credentials']['Uid'][1]==str(os.geteuid())
    assert set(data['namespaces'])=={'pid','net','mnt','user'}
    entry=next(x for x in data['artifacts'] if x.get('kind')=='script')
    assert entry['sha256']==hashlib.sha256(script.read_bytes()).hexdigest()
    assert entry['metadata']['size']==script.stat().st_size and entry['identity_verified']
    assert data['executable']['sha256']==hashlib.sha256(Path('/proc',str(process.pid),'exe').read_bytes()).hexdigest()
    assert data['coverage']['cache_eligible'] is False
    assert 'package_authentication_missing' in data['coverage']['gaps']
    assert 'original_observation_process_not_identified' in data['coverage']['gaps']
    text=json.dumps(data)
    assert 'DO-NOT-EXPORT' not in text and 'import time' not in text and 'maps' not in data


@pytest.mark.parametrize('change',['process','credentials','namespaces','maps','executable_identity','cgroup'])
def test_before_after_context_races_reject_the_entire_result(context_files,monkeypatch,change):
    process,_=context_files;original=agent.triage_process_facts;count=0
    def changed(*args):
        nonlocal count
        value=original(*args);count+=1
        if count==2:
            value=copy.deepcopy(value)
            if change=='cgroup':value[change]+=b'changed'
            elif change=='maps':value[change]+='changed'
            elif change=='executable_identity':value[change][0]+=1
            elif change=='process':value[change]['start_ticks']+=1
            elif change=='credentials':value[change]['Uid'][1]='12345'
            else:value[change]['net']+=1
        return value
    monkeypatch.setattr(agent,'triage_process_facts',changed)
    with pytest.raises(ValueError,match='changed'):inspect_context(process)


def test_missing_artifacts_and_time_limits_are_explicit(context_files,monkeypatch):
    process,_=context_files
    monkeypatch.setattr(agent,'provenance',lambda *a,**k:[{'kind':'library','identity_verified':False,'error':'PermissionError'}])
    _,data=inspect_context(process)
    assert 'artifact_coverage_incomplete' in data['coverage']['gaps'] and not data['coverage']['cache_eligible']
    with opened(process) as fd:
        with pytest.raises(ValueError,match='budget'):agent.triage_process_context(fd,process.pid,os.readlink('exe',dir_fd=fd),'a'*64,time.monotonic()-1)


def test_bridge_rechecks_files_after_optional_commands_and_never_returns_mixed_context(context_files,monkeypatch):
    process,script=context_files
    # Restrict the real-procfs search to this fixture, not unrelated Python jobs.
    original=bridge.os.listdir
    monkeypatch.setattr(bridge.os,'listdir',lambda directory:[str(process.pid)] if isinstance(directory,int) else original(directory))
    request={'executable':os.readlink(process.proc/'exe'),
        'sha256':agent.hash_artifact(process.proc/'exe',{}),'checks':['package','executable']}
    monkeypatch.setattr(bridge,'run',lambda *a,**k:'fixture: owner only, not authenticated')
    result=bridge.process_evidence(request)
    assert result['identity_verified'] and result['version']==2
    assert result['context']['process']['pid']==process.pid
    assert 'Uid:\t0\t0\t0\t0' in result['executable']['status']
    assert 'package_authentication_missing' in result['coverage']['gaps']
    def mutate(*a,**k):script.write_text('changed after first hash\n');return 'fixture'
    monkeypatch.setattr(bridge,'run',mutate)
    failed=bridge.process_evidence(request)
    assert not failed['identity_verified'] and 'context' not in failed and 'package' not in failed


def test_bridge_exit_wrong_hash_and_nonmatching_paths_fail_closed(context_files,monkeypatch):
    process,_=context_files;original=bridge.os.listdir
    monkeypatch.setattr(bridge.os,'listdir',lambda directory:[str(process.pid)] if isinstance(directory,int) else original(directory))
    request={'executable':os.readlink(process.proc/'exe'),'sha256':'a'*64,'checks':['executable']}
    assert bridge.process_evidence(request)['identity_verified'] is False
    request['executable']='/not/the/observed/executable'
    assert bridge.process_evidence(request)['identity_verified'] is False
    (process.proc/'exe').unlink()
    assert bridge.process_evidence(request)['identity_verified'] is False


def test_bounded_metadata_and_no_caller_selected_paths(context_files,monkeypatch):
    process,_=context_files;original=agent.response_proc_read
    def oversized(directory,name,limit=4096):
        if name=='maps':raise ValueError('Process metadata exceeds budget')
        return original(directory,name,limit)
    monkeypatch.setattr(agent,'response_proc_read',oversized)
    with pytest.raises(ValueError,match='budget'):inspect_context(process)
    with pytest.raises(ValueError):bridge.process_evidence({'executable':'/etc/shadow','sha256':'a'*64,'checks':['shell']})


def test_fixture_context_retains_script_metadata_and_rejects_malformed_credentials(context_files):
    process,script=context_files
    _,data=inspect_context(process)
    entry=next(x for x in data['artifacts'] if x['kind']=='script')
    assert entry['identity_verified'] and entry['sha256']==hashlib.sha256(script.read_bytes()).hexdigest()
    assert entry['metadata']=={'uid':script.stat().st_uid,'gid':script.stat().st_gid,'mode':script.stat().st_mode&0o7777,'size':script.stat().st_size}
    assert 'DO-NOT-EXPORT' not in json.dumps(data)
    (process.proc/'status').write_text('Uid: 0 0 0 0\nGid: 0 0 0 0\nCapEff: NOT-HEX\nNoNewPrivs: 1\nSeccomp: 2\n')
    with pytest.raises(ValueError,match='capabilities'):inspect_context(process)


def test_observed_uid_must_match_and_invalid_uid_is_rejected(context_files,monkeypatch):
    process,_=context_files;original=bridge.os.listdir
    monkeypatch.setattr(bridge.os,'listdir',lambda directory:[str(process.pid)] if isinstance(directory,int) else original(directory))
    request={'executable':os.readlink(process.proc/'exe'),'sha256':agent.hash_artifact(process.proc/'exe',{}),'checks':['executable'],'uid':'12345'}
    assert bridge.process_evidence(request)['identity_verified'] is False
    request['uid']='0';assert bridge.process_evidence(request)['identity_verified']
    request['uid']='untrusted-account'
    with pytest.raises(ValueError,match='account'):bridge.process_evidence(request)


def test_isolated_installed_bridge_can_load_the_trusted_collector(tmp_path):
    installed=tmp_path/'installed';installed.mkdir()
    target=Path(__file__).resolve().parents[1]/'target'
    for name in ('agent.py','bridge.py'):
        source=(target/name).read_text().replace('/usr/local/lib/mrpatchy',str(installed))
        (installed/name).write_text(source)
    result=subprocess.run([sys.executable,'-I',str(installed/'bridge.py')],input=json.dumps({'action':'evidence','executable':'/not-a-running-triage-fixture','sha256':'a'*64,'checks':['executable']}),text=True,capture_output=True,timeout=15)
    assert result.returncode==0,result.stdout+result.stderr
    assert json.loads(result.stdout)['identity_verified'] is False
