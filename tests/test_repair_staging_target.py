import base64
import copy
import os
import stat
import time
import uuid
import pytest
from target import agent
from test_quarantine_target import response_files,approval as quarantine_approval


@pytest.fixture
def staging(response_files,monkeypatch,request):
    source,vault,original=response_files;qid=str(uuid.uuid4())
    if getattr(request,'param',None) is not None:
        source.chmod(request.param)
        original=agent.response_prepare(agent.evidence_prepare({'path':str(source),'sha256':original['file']['sha256'],'device':source.stat().st_dev,'inode':source.stat().st_ino}))
    agent.response_action(qid,original,quarantine_approval())
    root=source.parent/'staging';monkeypatch.setattr(agent,'REPAIR_STAGE_ROOT',root)
    monkeypatch.setattr(agent,'vendor_identity',lambda manifest:'expected')
    monkeypatch.setattr(agent,'vendor_owner',lambda *args:None)
    data=b'trusted replacement\n'+b'x'*agent.REPAIR_CHUNK_SIZE
    manifest={'package':'fixture','version':'1.0-1','architecture':'all','entries':[{'path':str(source),'sha256':agent.hashlib.sha256(data).hexdigest(),'size':len(data)}]}
    plan={'quarantine_id':qid,'quarantine_plan':original,'manifest':manifest,'authentication_digest':'a'*64,'replacement_mode':stat.S_IMODE(original['file']['identity']['mode'])}
    identifier=str(uuid.uuid4())
    review={'id':identifier,'action':'stage','expires':time.time()+240,'actor':'admin','reason':'Reviewed authenticated private staging only.','plan_digest':agent.repair_digest(plan)}
    return {'source':source,'vault':vault,'qid':qid,'root':root,'id':identifier,'plan':plan,'approval':review,'data':data}


def begin(f):return agent.repair_stage_begin(f['id'],f['plan'],f['approval'])
def status(f):return agent.repair_stage_status(f['id'],f['plan'])
def chunk(f,offset=0,data=None):
    data=f['data'][offset:offset+agent.REPAIR_CHUNK_SIZE] if data is None else data
    return agent.repair_stage_chunk(f['id'],f['plan'],offset,base64.b64encode(data).decode())
def upload(f):
    begin(f)
    for offset in range(0,len(f['data']),agent.REPAIR_CHUNK_SIZE):chunk(f,offset)
def finish(f):return agent.repair_stage_finish(f['id'],f['plan'])


def test_chunked_staging_and_expired_replays_never_publish_or_modify_original(staging):
    f=staging;upload(f);result=finish(f)
    assert result['state']=='staged' and result['facts']=={'intent_verified':True,'payload_verified':True,'completion_recorded':True}
    directory=f['root']/f['id'];payload=directory/'payload'
    assert payload.read_bytes()==f['data'] and stat.S_IMODE(payload.stat().st_mode)==0o600 and not f['source'].exists()
    assert (f['vault']/f['qid']/'held').read_bytes()==b'harmless response fixture'
    assert all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in directory.iterdir())
    before={p.name:(p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in directory.iterdir()}
    f['approval']['expires']=time.time()-1
    assert begin(f)['state']=='staged' and chunk(f)['state']=='staged' and finish(f)['state']=='staged'
    assert before=={p.name:(p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in directory.iterdir()}


def test_status_is_read_only_and_missing_operations_create_nothing(staging,monkeypatch):
    f=staging;assert status(f)['state']=='not_found' and not f['root'].exists()
    upload(f);finish(f);real=agent.os.open
    def readonly(path,flags,*args,**kwargs):
        assert flags&os.O_ACCMODE==os.O_RDONLY and not flags&(os.O_CREAT|os.O_TRUNC)
        return real(path,flags,*args,**kwargs)
    monkeypatch.setattr(agent.os,'open',readonly)
    assert status(f)['state']=='staged'


@pytest.mark.parametrize('change',['bytes','mode','symlink','hardlink','inode','xattrs','journal','parent'])
def test_changed_payload_or_journals_never_verify(staging,change):
    f=staging;upload(f);finish(f);directory=f['root']/f['id'];payload=directory/'payload'
    if change=='bytes':payload.write_bytes(b'changed')
    if change=='mode':payload.chmod(0o644)
    if change=='symlink':payload.unlink();payload.symlink_to('/etc/passwd')
    if change=='hardlink':os.link(payload,directory/'alias')
    if change=='inode':payload.rename(directory/'old');payload.write_bytes(f['data']);payload.chmod(0o600)
    if change=='xattrs':os.setxattr(payload,'user.test',b'changed')
    if change=='journal':(directory/'finish-intent.json').write_text('{}')
    if change=='parent':f['root'].chmod(0o777)
    with pytest.raises((ValueError,OSError)):status(f)
    assert not f['source'].exists()


def test_interrupted_chunk_intent_cannot_be_retried(staging,monkeypatch):
    f=staging;begin(f);write=agent.response_json
    def interrupted(directory,name,value=None):
        result=write(directory,name,value)
        if name=='chunk-0.json' and value is not None:raise OSError('Interrupted before chunk append')
        return result
    monkeypatch.setattr(agent,'response_json',interrupted)
    with pytest.raises(OSError):chunk(f)
    assert status(f)['state']=='incomplete' and status(f)['received']==0
    assert chunk(f)['state']=='incomplete' and (f['root']/f['id']/'payload.partial').stat().st_size==0


def test_completed_chunk_with_lost_reply_is_observed_without_another_append(staging,monkeypatch):
    f=staging;begin(f);observe=agent.repair_stage_status_open;failed=False
    def interrupted(*args):
        nonlocal failed
        result=observe(*args)
        if result['received'] and not failed:failed=True;raise OSError('Lost chunk reply')
        return result
    monkeypatch.setattr(agent,'repair_stage_status_open',interrupted)
    with pytest.raises(OSError):chunk(f)
    partial=f['root']/f['id']/'payload.partial';before=partial.stat()
    assert status(f)['received']==agent.REPAIR_CHUNK_SIZE and chunk(f)['state']=='receiving'
    assert partial.stat().st_mtime_ns==before.st_mtime_ns and partial.stat().st_size==agent.REPAIR_CHUNK_SIZE


def test_lost_completion_is_reconciled_but_finish_intent_is_never_replayed(staging,monkeypatch):
    f=staging;upload(f);write=agent.response_json
    def interrupted(directory,name,value=None):
        if name=='staged.json' and value is not None:raise OSError('Lost completion journal')
        return write(directory,name,value)
    monkeypatch.setattr(agent,'response_json',interrupted)
    with pytest.raises(OSError):finish(f)
    assert status(f)['state']=='staged' and not status(f)['facts']['completion_recorded']
    assert finish(f)['state']=='staged' and not (f['root']/f['id']/'staged.json').exists()


def test_interrupted_finish_before_rename_never_retries(staging,monkeypatch):
    f=staging;upload(f)
    monkeypatch.setattr(agent,'response_rename',lambda *args:(_ for _ in ()).throw(OSError('Interrupted rename')))
    with pytest.raises(OSError):finish(f)
    assert status(f)['state']=='incomplete' and finish(f)['state']=='incomplete'
    assert not (f['root']/f['id']/'payload').exists() and not f['source'].exists()


@pytest.mark.parametrize('change',['expired','future','action','id','digest','reason'])
def test_invalid_approval_refused_before_private_storage(staging,change):
    f=staging
    if change=='expired':f['approval']['expires']=time.time()-1
    if change=='future':f['approval']['expires']=time.time()+3600
    if change=='action':f['approval']['action']='publish'
    if change=='id':f['approval']['id']=str(uuid.uuid4())
    if change=='digest':f['approval']['plan_digest']='b'*64
    if change=='reason':f['approval']['reason']=' '*20
    with pytest.raises(ValueError):begin(f)
    assert not f['root'].exists()


def test_expiry_after_chunk_intent_does_not_append(staging,monkeypatch):
    f=staging;begin(f);write=agent.response_json;now=time.time()
    def expired(directory,name,value=None):
        result=write(directory,name,value)
        if name.startswith('chunk-') and value is not None:monkeypatch.setattr(agent.time,'time',lambda:now+1000)
        return result
    monkeypatch.setattr(agent,'response_json',expired)
    with pytest.raises(ValueError,match='expired'):chunk(f)
    assert status(f)['state']=='incomplete' and status(f)['received']==0


@pytest.mark.parametrize('phase',['begin','finish'])
def test_occupied_live_path_is_never_overwritten(staging,phase):
    f=staging
    if phase=='finish':upload(f)
    f['source'].write_bytes(b'legitimate deployment')
    result=begin(f) if phase=='begin' else finish(f)
    assert result['state']=='blocked' and 'destination_occupied' in result['readiness']['gaps']
    assert f['source'].read_bytes()==b'legitimate deployment'
    if phase=='begin':assert not f['root'].exists()
    else:assert not (f['root']/f['id']/'payload').exists()


def test_invalid_chunk_boundaries_and_changed_chunk_ids_refuse(staging):
    f=staging;begin(f)
    for offset,encoded in [(True,'eA=='),(1,'eA=='),(0,'eA=='),(0,'!'*10),(0,'A'*(4*((agent.REPAIR_CHUNK_SIZE+2)//3)+4))]:
        with pytest.raises((ValueError,TypeError)):agent.repair_stage_chunk(f['id'],f['plan'],offset,encoded)
    assert status(f)['received']==0
    chunk(f)
    with pytest.raises(ValueError,match='different bytes'):chunk(f,data=b'z'*agent.REPAIR_CHUNK_SIZE)
    assert status(f)['received']==agent.REPAIR_CHUNK_SIZE


def test_wrong_full_payload_hash_never_seals(staging):
    f=staging;begin(f)
    chunk(f,data=b'z'*agent.REPAIR_CHUNK_SIZE);chunk(f,agent.REPAIR_CHUNK_SIZE)
    with pytest.raises(ValueError,match='approved artifact'):finish(f)
    assert not (f['root']/f['id']/'finish-intent.json').exists() and not f['source'].exists()


def test_eight_operation_quota_bounds_abandoned_storage(staging):
    f=staging
    for _ in range(8):
        f['id']=str(uuid.uuid4());f['approval']['id']=f['id'];assert begin(f)['state']=='receiving'
    f['id']=str(uuid.uuid4());f['approval']['id']=f['id']
    assert begin(f)['state']=='capacity_reached'
    assert len(list(f['root'].iterdir()))==8


def test_empty_authenticated_payload_requires_no_chunks(staging):
    f=staging;f['data']=b'';f['plan']['manifest']['entries'][0].update(size=0,sha256=agent.hashlib.sha256(b'').hexdigest())
    f['approval']['plan_digest']=agent.repair_digest(f['plan'])
    begin(f);assert finish(f)['state']=='staged' and (f['root']/f['id']/'payload').read_bytes()==b''


def test_changed_plan_and_missing_intent_cannot_create_a_positive_receipt(staging):
    f=staging;begin(f);other=copy.deepcopy(f['plan']);other['authentication_digest']='c'*64
    with pytest.raises(ValueError):agent.repair_stage_status(f['id'],other)
    (f['root']/f['id']/'intent.json').unlink()
    assert status(f)['state']=='incomplete' and begin(f)['state']=='incomplete'
