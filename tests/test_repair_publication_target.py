import copy
import os
import stat
import time
import uuid
import pytest
from target import agent
from test_repair_staging_target import staging,upload,finish
from test_quarantine_target import response_files


@pytest.fixture
def publication(staging):
    f=staging;upload(f);staged=finish(f);identifier=str(uuid.uuid4())
    plan={'stage_id':f['id'],'stage_plan':copy.deepcopy(f['plan']),'payload':staged['payload']}
    review={'id':identifier,'action':'publish','expires':time.time()+240,'actor':'admin','reason':'Reviewed live publication and service activation risk.','plan_digest':agent.repair_digest(plan)}
    return {**f,'publication_id':identifier,'publication_plan':plan,'publication_approval':review}


def publish(f):return agent.repair_publication(f['publication_id'],f['publication_plan'],f['publication_approval'])
def observe(f):return agent.repair_publication(f['publication_id'],f['publication_plan'],status_only=True)


def test_atomic_publication_retains_original_and_expires_into_readonly_replays(publication):
    f=publication;identity=f['publication_plan']['payload']['identity'];assert observe(f)['state']=='not_started'
    result=publish(f)
    assert result['state']=='published' and result['facts']['completion_recorded'] and not result['facts']['private_present']
    assert f['source'].read_bytes()==f['data'] and f['source'].stat().st_ino==identity['ino']
    assert stat.S_IMODE(f['source'].stat().st_mode)==0o640
    assert (f['vault']/f['qid']/'held').read_bytes()==b'harmless response fixture'
    assert not (f['root']/f['id']/'payload').exists()
    before=f['source'].stat();f['publication_approval']['expires']=time.time()-1
    assert publish(f)['state']=='published' and observe(f)['state']=='published'
    assert f['source'].stat().st_ctime_ns==before.st_ctime_ns and f['source'].stat().st_mtime_ns==before.st_mtime_ns
    # A different operation ID cannot reuse this staging publication intent.
    f['publication_id']=str(uuid.uuid4())
    with pytest.raises(ValueError):publish(f)


def test_publication_verification_never_writes_or_replays(publication,monkeypatch):
    f=publication;publish(f);real=agent.os.open
    def readonly(path,flags,*args,**kwargs):
        assert flags&os.O_ACCMODE==os.O_RDONLY and not flags&(os.O_CREAT|os.O_TRUNC)
        return real(path,flags,*args,**kwargs)
    monkeypatch.setattr(agent.os,'open',readonly)
    assert observe(f)['state']=='published' and publish(f)['state']=='published'


def test_lost_completion_is_positive_only_after_current_inode_hash_and_original_checks(publication,monkeypatch):
    f=publication;write=agent.response_json
    def interrupted(directory,name,value=None):
        if name=='published.json' and value is not None:raise OSError('Lost completion journal')
        return write(directory,name,value)
    monkeypatch.setattr(agent,'response_json',interrupted)
    with pytest.raises(OSError):publish(f)
    assert observe(f)['state']=='published' and not observe(f)['facts']['completion_recorded']
    assert publish(f)['state']=='published' and not (f['root']/f['id']/'published.json').exists()


def test_concurrent_deployment_is_never_overwritten_or_retried(publication,monkeypatch):
    f=publication;rename=agent.response_rename
    def conflict(*args):f['source'].write_bytes(b'legitimate concurrent deployment');return rename(*args)
    monkeypatch.setattr(agent,'response_rename',conflict)
    with pytest.raises(OSError):publish(f)
    assert f['source'].read_bytes()==b'legitimate concurrent deployment'
    result=observe(f);assert result['state']=='uncertain' and result['facts']['private_present']
    assert publish(f)['state']=='uncertain'
    f['source'].unlink();assert publish(f)['state']=='uncertain' and not f['source'].exists()


@pytest.mark.parametrize('phase',['intent','chmod'])
def test_interruption_after_intent_never_retries_a_live_mutation(publication,monkeypatch,phase):
    f=publication
    if phase=='intent':
        write=agent.response_json
        def interrupted(directory,name,value=None):
            result=write(directory,name,value)
            if name=='publish-intent.json' and value is not None:raise OSError('Lost process after intent')
            return result
        monkeypatch.setattr(agent,'response_json',interrupted)
    else:
        chmod=agent.os.fchmod
        def interrupted(fd,mode):chmod(fd,mode);raise OSError('Lost process after permissions')
        monkeypatch.setattr(agent.os,'fchmod',interrupted)
    with pytest.raises(OSError):publish(f)
    assert not f['source'].exists() and observe(f)['state']=='uncertain' and publish(f)['state']=='uncertain'
    assert (f['root']/f['id']/'payload').exists()


@pytest.mark.parametrize('phase',['intent','chmod'])
def test_expiry_is_checked_before_permission_change_and_rename(publication,monkeypatch,phase):
    f=publication;now=time.time()
    if phase=='intent':
        write=agent.response_json
        def expired(directory,name,value=None):
            result=write(directory,name,value)
            if name=='publish-intent.json' and value is not None:monkeypatch.setattr(agent.time,'time',lambda:now+1000)
            return result
        monkeypatch.setattr(agent,'response_json',expired)
    else:
        chmod=agent.os.fchmod
        def expired(fd,mode):chmod(fd,mode);monkeypatch.setattr(agent.time,'time',lambda:now+1000)
        monkeypatch.setattr(agent.os,'fchmod',expired)
    with pytest.raises(ValueError,match='expired'):publish(f)
    assert not f['source'].exists() and observe(f)['state']=='uncertain'


@pytest.mark.parametrize('change',['bytes','mode','inode','hardlink','xattrs','symlink'])
def test_changed_staged_payload_refuses_before_publication_intent(publication,change):
    f=publication;payload=f['root']/f['id']/'payload'
    if change=='bytes':payload.write_bytes(b'changed')
    if change=='mode':payload.chmod(0o755)
    if change=='inode':payload.rename(payload.with_name('old'));payload.write_bytes(f['data']);payload.chmod(0o600)
    if change=='hardlink':os.link(payload,payload.with_name('alias'))
    if change=='xattrs':os.setxattr(payload,'user.test',b'changed')
    if change=='symlink':payload.unlink();payload.symlink_to('/etc/passwd')
    with pytest.raises((ValueError,OSError)):publish(f)
    assert not f['source'].exists() and not (f['root']/f['id']/'publish-intent.json').exists()


@pytest.mark.parametrize('change',['bytes','mode','inode','missing','hardlink','xattrs','journal','original','parents'])
def test_post_publication_tampering_never_reports_verified(publication,change):
    f=publication;publish(f)
    if change=='bytes':f['source'].write_bytes(b'changed')
    if change=='mode':f['source'].chmod(0o755)
    if change=='inode':f['source'].rename(f['source'].with_name('old-live'));f['source'].write_bytes(f['data']);f['source'].chmod(0o640)
    if change=='missing':f['source'].unlink()
    if change=='hardlink':os.link(f['source'],f['source'].with_name('alias-live'))
    if change=='xattrs':os.setxattr(f['source'],'user.test',b'changed')
    if change=='journal':(f['root']/f['id']/'published.json').write_text('{}')
    if change=='original':(f['vault']/f['qid']/'held').write_bytes(b'changed original')
    if change=='parents':f['source'].parent.chmod(0o777)
    try:result=observe(f)
    except (ValueError,OSError):return
    assert result['state']=='uncertain'


@pytest.mark.parametrize('change',['expired','future','action','digest','reason'])
def test_separate_valid_publish_approval_is_mandatory(publication,change):
    f=publication
    if change=='expired':f['publication_approval']['expires']=time.time()-1
    if change=='future':f['publication_approval']['expires']=time.time()+1000
    if change=='action':f['publication_approval']['action']='stage'
    if change=='digest':f['publication_approval']['plan_digest']='b'*64
    if change=='reason':f['publication_approval']['reason']=' '*20
    with pytest.raises(ValueError):publish(f)
    assert not (f['root']/f['id']/'publish-intent.json').exists() and not f['source'].exists()


def test_occupied_destination_blocks_before_intent(publication):
    f=publication;f['source'].write_bytes(b'new deployment')
    result=publish(f);assert result['state']=='blocked' and result['readiness']['state']=='blocked'
    assert f['source'].read_bytes()==b'new deployment' and not (f['root']/f['id']/'publish-intent.json').exists()


def test_package_database_change_after_move_retains_uncertainty(publication,monkeypatch):
    f=publication;calls=0
    def identity(manifest):
        nonlocal calls
        calls+=1
        if calls>2:raise ValueError('Package changed during publication')
        return 'expected'
    monkeypatch.setattr(agent,'vendor_identity',identity)
    result=publish(f)
    assert result['state']=='uncertain' and f['source'].read_bytes()==f['data'] and not (f['root']/f['id']/'published.json').exists()


@pytest.mark.parametrize('staging',[0o600,0o755],indirect=True)
def test_selected_permission_policy_is_explicit_and_retained_original_stays_private(publication):
    f=publication;result=publish(f)
    assert result['state']=='published'
    assert stat.S_IMODE(f['source'].stat().st_mode)==f['plan']['replacement_mode']
    assert stat.S_IMODE((f['vault']/f['qid']/'held').stat().st_mode)==0o600
