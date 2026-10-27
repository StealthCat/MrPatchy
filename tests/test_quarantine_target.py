import os
from pathlib import Path
import shutil
import stat
import time
import uuid
import pytest
from target import agent


@pytest.fixture
def response_files(monkeypatch):
    if os.geteuid()!=0:pytest.skip('Requires a real protected root-owned namespace; native SSH containers exercise production guards')
    root=Path('/srv')/('patchy-response-test-'+uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    source=root/'suspect';source.write_bytes(b'harmless response fixture');source.chmod(0o640)
    vault=root/'vault';monkeypatch.setattr(agent,'RESPONSE_ROOT',vault)
    expected={'path':str(source),'sha256':agent.hashlib.sha256(source.read_bytes()).hexdigest(),'device':source.stat().st_dev,'inode':source.stat().st_ino}
    plan=agent.response_prepare(agent.evidence_prepare(expected))
    try:yield source,vault,plan
    finally:shutil.rmtree(root)


def approval(restore=False):return {'id':str(uuid.uuid4()),'action':'restore' if restore else 'quarantine','expires':time.time()+240,'actor':'test','reason':'Approved harmless fixture response.'}


def test_quarantine_and_no_overwrite_restore_are_idempotent(response_files):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());review=approval()
    receipt=agent.response_action(identifier,plan,review)
    assert receipt['state']=='quarantined' and receipt['restore_ready'] and not source.exists()
    held=vault/identifier/'held';assert held.read_bytes()==b'harmless response fixture' and stat.S_IMODE(held.stat().st_mode)==0o600
    assert agent.response_action(identifier,plan,review)==receipt
    assert agent.response_status(identifier,plan)==receipt
    source.write_bytes(b'new deployment must survive')
    conflict=agent.response_action(identifier,plan,approval(True),restore=True)
    assert conflict['state']=='uncertain' and not conflict['restore_ready'] and source.read_bytes()==b'new deployment must survive'
    assert held.exists() and not (vault/identifier/'restore-intent.json').exists()
    source.unlink();restored=agent.response_action(identifier,plan,approval(True),restore=True)
    assert restored['state']=='restored' and source.read_bytes()==b'harmless response fixture'
    assert stat.S_IMODE(source.stat().st_mode)==0o640 and source.stat().st_ino==plan['file']['identity']['ino']
    assert agent.response_action(identifier,plan,approval(True),restore=True)==restored
    assert agent.response_action(identifier,plan,review)==restored


@pytest.mark.parametrize('change',['mode','hardlink','symlink','owner','special_bits','parent_write','bytes','xattrs'])
def test_preparation_or_execution_rejects_changed_unsafe_sources(response_files,change):
    source,vault,plan=response_files
    if change=='mode':source.chmod(0o666)
    if change=='hardlink':os.link(source,source.parent/'alias')
    if change=='symlink':source.rename(source.parent/'other');source.symlink_to(source.parent/'other')
    if change=='owner':
        try:os.chown(source,65534,65534)
        except OSError as error:
            if error.errno not in (1,22):raise
            pytest.skip('Fixture needs a mapped non-root UID and CAP_CHOWN; native SSH containers cover root ownership')
    if change=='special_bits':source.chmod(0o4644)
    if change=='parent_write':source.parent.chmod(0o777)
    if change=='bytes':source.write_bytes(b'changed')
    if change=='xattrs':os.setxattr(source,'user.patchy',b'changed')
    with pytest.raises((ValueError,OSError)):agent.response_action(str(uuid.uuid4()),plan,approval())
    assert not vault.exists()


def test_scope_expiry_and_wrong_plan_refuse_before_mutation(response_files,tmp_path):
    source,vault,plan=response_files
    with pytest.raises(ValueError):agent.response_action(str(uuid.uuid4()),plan,{**approval(),'expires':time.time()-1})
    with pytest.raises(ValueError):agent.response_action(str(uuid.uuid4()),{**plan,'vault_device':plan['vault_device']+1},approval())
    other=tmp_path/'outside';other.write_bytes(b'outside')
    with pytest.raises(ValueError,match='scope|supports'):agent.response_prepare({**plan['file'],'path':str(other)})
    assert source.exists() and not vault.exists()
    identifier=str(uuid.uuid4());assert agent.response_status(identifier,plan)['state']=='not_found'
    assert not vault.exists()


def test_interruption_after_move_before_permission_change_requires_review_but_can_restore(response_files,monkeypatch):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());rename=agent.response_rename
    def interrupted(*args):rename(*args);raise OSError('Lost process after atomic rename')
    monkeypatch.setattr(agent,'response_rename',interrupted)
    with pytest.raises(OSError):agent.response_action(identifier,plan,approval())
    assert not source.exists() and (vault/identifier/'held').is_file()
    receipt=agent.response_status(identifier,plan)
    assert receipt['state']=='uncertain' and receipt['restore_ready']
    assert agent.response_action(identifier,plan,approval())==receipt
    monkeypatch.setattr(agent,'response_rename',rename)
    assert agent.response_action(identifier,plan,approval(True),restore=True)['state']=='restored'


@pytest.mark.parametrize('restore',[False,True])
def test_lost_completion_receipt_is_reconciled_from_journal_and_inode(response_files,monkeypatch,restore):
    source,vault,plan=response_files;identifier=str(uuid.uuid4())
    if restore:agent.response_action(identifier,plan,approval())
    write=agent.response_json
    def interrupted(directory,name,value=None):
        if value is not None and name==('restored.json' if restore else 'quarantined.json'):raise OSError('Interrupted final journal write')
        return write(directory,name,value)
    monkeypatch.setattr(agent,'response_json',interrupted)
    with pytest.raises(OSError):agent.response_action(identifier,plan,approval(restore),restore=restore)
    receipt=agent.response_status(identifier,plan)
    assert receipt['state']==('restored' if restore else 'quarantined')
    assert source.exists()==restore


def test_restore_rename_race_never_overwrites_and_is_never_automatically_retried(response_files,monkeypatch):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());agent.response_action(identifier,plan,approval())
    rename=agent.response_rename
    def collide(*args):source.write_bytes(b'concurrent deployment');return rename(*args)
    monkeypatch.setattr(agent,'response_rename',collide)
    with pytest.raises(OSError):agent.response_action(identifier,plan,approval(True),restore=True)
    assert source.read_bytes()==b'concurrent deployment' and (vault/identifier/'held').exists()
    receipt=agent.response_status(identifier,plan)
    assert receipt['state']=='uncertain' and receipt['restore_attempted'] and not receipt['restore_ready']
    source.unlink();assert agent.response_action(identifier,plan,approval(True),restore=True)['restore_attempted']
    assert not source.exists() # Recovery requires console review after interrupted restore.


def test_replaced_held_inode_or_changed_security_metadata_cannot_restore(response_files):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());agent.response_action(identifier,plan,approval())
    held=vault/identifier/'held';held.rename(vault/identifier/'old');held.write_bytes(b'harmless response fixture');held.chmod(0o600)
    with pytest.raises(ValueError):agent.response_action(identifier,plan,approval(True),restore=True)
    assert not source.exists()


def test_expiry_during_final_source_verification_never_moves_file(response_files,monkeypatch):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());check=agent.response_prepare;calls=0;now=time.time()
    def delayed(snapshot):
        nonlocal calls
        calls+=1;result=check(snapshot)
        if calls==2:monkeypatch.setattr(agent.time,'time',lambda:now+600)
        return result
    monkeypatch.setattr(agent,'response_prepare',delayed)
    with pytest.raises(ValueError,match='expired'):agent.response_action(identifier,plan,approval())
    assert source.exists() and not (vault/identifier/'held').exists()
    assert agent.response_status(identifier,plan)['state']=='not_moved'
