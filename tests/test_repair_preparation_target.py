import copy
import os
from pathlib import Path
import uuid
import pytest
from target import agent,bridge
from test_quarantine_target import response_files,approval


@pytest.fixture
def retained(response_files,monkeypatch):
    source,vault,plan=response_files;identifier=str(uuid.uuid4());agent.response_action(identifier,plan,approval())
    state={'identity':False,'owner':False,'change':False,'during':lambda:None};calls=[]
    manifest={'package':'fixture','version':'1.0-1','architecture':'all','entries':[{'path':str(source),'sha256':'a'*64,'size':5}]}
    def command(args,**kwargs):
        calls.append(args)
        assert '--' in args and kwargs['timeout']==10
        if '-S' in args:
            state['during']()
            return ('other: '+str(source)+'\n' if state['owner'] else 'fixture: '+str(source)+'\n'),'',0
        assert args[:2]==['dpkg-query','-W']
        return ('installed 2.0-1 all\n' if state['identity'] or (state['change'] and len(calls)>2) else 'installed 1.0-1 all\n'),'',0
    monkeypatch.setattr(bridge,'bounded',command)
    return {'source':source,'vault':vault,'plan':plan,'id':identifier,'manifest':manifest,'state':state,'calls':calls}


def prepare(fixture):return agent.repair_readiness(fixture['id'],fixture['plan'],fixture['manifest'])


def test_positive_readiness_uses_only_reads_and_does_not_create_or_publish(retained,monkeypatch):
    f=retained;directory=f['vault']/f['id'];before={p.name:(p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in directory.iterdir()}
    real=agent.os.open
    def read_only(path,flags,*args,**kwargs):
        assert flags&os.O_ACCMODE==os.O_RDONLY and not flags&(os.O_CREAT|os.O_TRUNC)
        return real(path,flags,*args,**kwargs)
    monkeypatch.setattr(agent.os,'open',read_only)
    result=prepare(f)
    assert result['state']=='ready' and all(v is True for v in result['facts'].values()) and result['replacement_mode']==0o640
    assert len(f['calls'])==4 and not f['source'].exists()
    assert before=={p.name:(p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in directory.iterdir()}
    assert (directory/'held').read_bytes()==b'harmless response fixture'


@pytest.mark.parametrize('change',['occupied','symlink','identity','owner','db_change','held','missing','parent','namespace_race'])
def test_incomplete_or_changed_readiness_never_reports_ready(retained,change):
    f=retained
    if change=='occupied':f['source'].write_bytes(b'legitimate deployment')
    if change=='symlink':f['source'].symlink_to('/does-not-exist')
    if change=='identity':f['state']['identity']=True
    if change=='owner':f['state']['owner']=True
    if change=='db_change':f['state']['change']=True
    if change=='held':(f['vault']/f['id']/'held').write_bytes(b'changed')
    if change=='missing':(f['vault']/f['id']/'held').unlink()
    if change=='parent':f['source'].parent.chmod(0o777)
    if change=='namespace_race':f['state']['during']=lambda:f['source'].write_bytes(b'concurrent deployment')
    result=prepare(f)
    assert result['state']=='blocked' and result['gaps']
    if change in ('occupied','namespace_race'):assert f['source'].read_bytes() in (b'legitimate deployment',b'concurrent deployment')
    if change in ('occupied','symlink','namespace_race'):assert result['facts']['destination_empty'] is False


def test_extended_attributes_are_not_reconstructed_from_untrusted_original_metadata(response_files,monkeypatch):
    source,vault,old=response_files;os.setxattr(source,'user.fixture',b'attribute bytes')
    snapshot=agent.evidence_prepare({'path':str(source),'sha256':old['file']['sha256'],'device':source.stat().st_dev,'inode':source.stat().st_ino})
    plan=agent.response_prepare(snapshot);identifier=str(uuid.uuid4());agent.response_action(identifier,plan,approval())
    monkeypatch.setattr(agent,'vendor_identity',lambda manifest:'expected');monkeypatch.setattr(agent,'vendor_owner',lambda *args:None)
    result=agent.repair_readiness(identifier,plan,{'package':'fixture','version':'1','architecture':'all','entries':[{'path':str(source),'sha256':'a'*64,'size':5}]})
    assert result['state']=='blocked' and 'unsupported_metadata' in result['gaps'] and result['replacement_mode'] is None


def test_rpm_queries_bind_exact_owner_without_plugins_or_scripts(retained,monkeypatch):
    f=retained;f['manifest'].update(package_manager='rpm',version='1:1.0-1',architecture='noarch');calls=[]
    def command(args,**kwargs):
        calls.append(args);assert args[:3]==['rpm','--noplugins','-q']
        assert '--verify' not in args and '--eval' not in args
        return 'fixture 1:1.0-1 noarch\n','',0
    monkeypatch.setattr(bridge,'bounded',command)
    assert prepare(f)['state']=='ready' and len(calls)==4
    assert sum('--whatprovides' in args for args in calls)==2


@pytest.mark.parametrize('change',['path','hash','size','entries'])
def test_invalid_manifest_refused_before_queries(retained,change):
    f=retained;manifest=copy.deepcopy(f['manifest'])
    if change=='path':manifest['entries'][0]['path']='/etc/passwd'
    if change=='hash':manifest['entries'][0]['sha256']='invalid'
    if change=='size':manifest['entries'][0]['size']=True
    if change=='entries':manifest['entries']*=2
    with pytest.raises(ValueError):agent.repair_readiness(f['id'],f['plan'],manifest)
    assert not f['calls']
