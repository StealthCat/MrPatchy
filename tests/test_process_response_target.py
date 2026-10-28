import copy
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import uuid
import pytest
from target import agent


@pytest.fixture
def process_files(monkeypatch):
    if os.geteuid()!=0:pytest.skip('Real protected root-owned process fixture runs in native SSH containers')
    root=Path('/srv')/('patchy-process-test-'+uuid.uuid4().hex);root.mkdir(mode=0o700)
    source=root/'sleep-fixture';shutil.copyfile(shutil.which('sleep'),source);source.chmod(0o755)
    monkeypatch.setattr(agent,'RESPONSE_ROOT',root/'quarantine');monkeypatch.setattr(agent,'PROCESS_RESPONSE_ROOT',root/'processes')
    try:process=subprocess.Popen([str(source),'120'])
    except PermissionError:
        shutil.rmtree(root);pytest.skip('Local /srv does not permit executable fixtures; native containers cover signals')
    try:
        snapshot=agent.evidence_prepare({'path':str(source),'sha256':agent.hashlib.sha256(source.read_bytes()).hexdigest(),'device':source.stat().st_dev,'inode':source.stat().st_ino})
        quarantine_plan=agent.response_prepare(snapshot);quarantine_id=str(uuid.uuid4())
        agent.response_action(quarantine_id,quarantine_plan,approval('quarantine'))
        deadline=time.monotonic()+5
        while True:
            observed=agent.response_processes(quarantine_id,quarantine_plan)['observation']
            matches=[m for m in (observed or {}).get('matches',[]) if m['references'].get('executable')==1]
            if matches:break
            assert process.poll() is None and time.monotonic()<deadline
            time.sleep(.01)
        expected={k:matches[0][k] for k in ('pid','start_ticks','pid_namespace')}
        plan=agent.process_prepare(quarantine_id,quarantine_plan,expected,observed['boot_id'],observed['pid_namespace'])
        yield {'process':process,'root':root,'plan':plan,'id':str(uuid.uuid4()),'q_id':quarantine_id,'q_plan':quarantine_plan,'observed':observed,'expected':expected}
    finally:
        if process.poll() is None:process.send_signal(signal.SIGCONT);process.terminate()
        process.wait(timeout=5);shutil.rmtree(root)


def approval(action='suspend'):
    return {'id':str(uuid.uuid4()),'action':action,'expires':time.time()+240,'actor':'test','reason':'Reviewed harmless process fixture and service impact.'}


def perform(fixture,resume=False):return agent.process_response(fixture['id'],fixture['plan'],approval('resume' if resume else 'suspend'),resume=resume)
def verify(fixture):return agent.process_response(fixture['id'],fixture['plan'],status_only=True)


def test_real_pidfd_stop_status_resume_and_non_replay(process_files,monkeypatch):
    f=process_files;real=signal.pidfd_send_signal;signals=[]
    def recorded(fd,sig,*args):
        if sig:signals.append(sig)
        return real(fd,sig,*args)
    monkeypatch.setattr(signal,'pidfd_send_signal',recorded)
    assert verify(f)['state']=='not_started' and not (f['root']/'processes').exists()
    stopped=perform(f);assert stopped['state']=='suspended' and stopped['resume_ready'] and stopped['threads']==1
    assert f['process'].poll() is None and verify(f)==stopped
    assert perform(f)==stopped and signals==[signal.SIGSTOP]
    resumed=perform(f,True);assert resumed['state']=='resumed' and resumed['resume_attempted'] and not resumed['resume_ready']
    assert perform(f,True)==resumed and perform(f)==resumed and signals==[signal.SIGSTOP,signal.SIGCONT]
    directory=f['root']/'processes'/f['id']
    assert {p.name for p in directory.iterdir()}=={'intent.json','suspended.json','resume-intent.json','resumed.json'}
    assert directory.stat().st_mode&0o777==0o700
    assert all(p.stat().st_mode&0o777==0o600 for p in directory.iterdir())


@pytest.mark.parametrize('change',['pid','ticks','namespace','proc_inode','boot','held','expiry','already_stopped'])
def test_changed_scope_refuses_without_delivering_a_signal(process_files,monkeypatch,change):
    f=process_files;plan=copy.deepcopy(f['plan']);review=approval();signals=[];real=signal.pidfd_send_signal
    if change=='pid':plan['process']['pid']=1
    if change=='ticks':plan['process']['start_ticks']+=1
    if change=='namespace':plan['process']['pid_namespace']+=1
    if change=='proc_inode':plan['process']['proc_inode']+=1
    if change=='boot':plan['boot_id']='00000000-0000-0000-0000-000000000000'
    if change=='held':(f['root']/'quarantine'/f['q_id']/'held').chmod(0o755)
    if change=='expiry':review['expires']=time.time()-1
    if change=='already_stopped':f['process'].send_signal(signal.SIGSTOP);time.sleep(.02)
    def recorded(fd,sig,*args):
        if sig:signals.append(sig)
        return real(fd,sig,*args)
    monkeypatch.setattr(signal,'pidfd_send_signal',recorded)
    with pytest.raises((ValueError,OSError)):agent.process_response(f['id'],plan,review)
    assert not signals and not (f['root']/'processes'/f['id']/'intent.json').exists()


def test_helper_and_ancestors_are_never_prepared(process_files):
    f=process_files;root=agent.response_proc_root()
    try:
        pid=int(os.readlink('self',dir_fd=root));directory=os.open(str(pid),os.O_RDONLY|os.O_DIRECTORY,dir_fd=root)
        try:expected=agent.response_proc_identity(directory,pid)
        finally:os.close(directory)
    finally:os.close(root)
    with pytest.raises(ValueError,match='ancestor|helper'):agent.process_prepare(f['q_id'],f['q_plan'],expected,f['observed']['boot_id'],f['observed']['pid_namespace'])


@pytest.mark.parametrize('resume',[False,True])
def test_lost_completion_is_reconciled_without_repeating_signal(process_files,monkeypatch,resume):
    f=process_files
    if resume:perform(f)
    real=agent.response_json
    def interrupted(directory,name,value=None):
        if value is not None and name==('resumed.json' if resume else 'suspended.json'):raise OSError('Lost completion')
        return real(directory,name,value)
    monkeypatch.setattr(agent,'response_json',interrupted)
    with pytest.raises(OSError):perform(f,resume)
    observed=verify(f)
    assert observed['state']==('resumed' if resume else 'suspended')
    assert perform(f,resume)==observed


def test_interrupted_resume_intent_is_never_replayed(process_files,monkeypatch):
    f=process_files;perform(f);real=signal.pidfd_send_signal
    def interrupted(fd,sig,*args):
        if sig==signal.SIGCONT:raise OSError('Before resume syscall')
        return real(fd,sig,*args)
    monkeypatch.setattr(signal,'pidfd_send_signal',interrupted)
    with pytest.raises(OSError):perform(f,True)
    observed=verify(f)
    assert observed['state']=='uncertain' and observed['resume_attempted'] and not observed['resume_ready']
    assert perform(f,True)==observed


def test_expiry_after_durable_intent_prevents_signal_and_never_replays(process_files,monkeypatch):
    f=process_files;real=agent.response_json;now=time.time();signals=[];send=signal.pidfd_send_signal
    def delayed(directory,name,value=None):
        result=real(directory,name,value)
        if name=='intent.json' and value is not None:monkeypatch.setattr(agent.time,'time',lambda:now+600)
        return result
    monkeypatch.setattr(agent,'response_json',delayed)
    def recorded(fd,sig,*args):
        if sig:signals.append(sig)
        return send(fd,sig,*args)
    monkeypatch.setattr(signal,'pidfd_send_signal',recorded)
    with pytest.raises(ValueError,match='expired'):perform(f)
    assert not signals and verify(f)['state']=='uncertain'
    monkeypatch.setattr(agent.time,'time',lambda:now)
    assert perform(f)['state']=='uncertain' and not signals


def test_observed_exit_is_not_replaced_by_a_new_pid_action(process_files):
    f=process_files;perform(f)
    f['process'].send_signal(signal.SIGCONT);f['process'].terminate();f['process'].wait(timeout=5)
    assert verify(f)['state']=='exited' and not verify(f)['resume_ready']
    assert perform(f,True)['state']=='exited'


@pytest.mark.parametrize('change',['credentials','threads','executable'])
def test_unsupported_live_scope_refuses_before_intent(process_files,monkeypatch,change):
    f=process_files
    if change=='credentials':
        read=agent.response_proc_read
        def unprivileged(directory,name,limit=4096):
            value=read(directory,name,limit)
            if name=='status':return b'Uid:\t1000\t1000\t1000\t1000\nTgid:\t'+str(f['plan']['process']['pid']).encode()+b'\n'
            return value
        monkeypatch.setattr(agent,'response_proc_read',unprivileged)
    if change=='threads':monkeypatch.setattr(agent,'process_threads',lambda directory:(_ for _ in ()).throw(ValueError('Thread limit')))
    if change=='executable':monkeypatch.setattr(agent,'process_executable',lambda *args:False)
    with pytest.raises(ValueError):perform(f)
    assert not (f['root']/'processes'/f['id']/'intent.json').exists()


def test_missing_journal_is_not_reported_as_an_unstarted_response(process_files):
    f=process_files;perform(f)
    (f['root']/'processes'/f['id']/'intent.json').unlink()
    with pytest.raises(FileNotFoundError):verify(f)
