import json,os,stat
import pytest
from pathlib import Path
from target import agent


def test_atomic_writes_private_file_and_syncs_directory(tmp_path,monkeypatch):
    synced=[]
    real=os.fsync
    monkeypatch.setattr(os,'fsync',lambda fd:(synced.append(stat.S_ISDIR(os.fstat(fd).st_mode)),real(fd))[1])
    target=tmp_path/'status.json'
    agent.atomic(target,{'ok':True})
    assert json.loads(target.read_text())=={'ok':True}
    assert stat.S_IMODE(target.stat().st_mode)==0o600
    assert synced==[False,True]
    assert [p.name for p in tmp_path.iterdir()]==['status.json']


def test_atomic_refuses_symlink_destination(tmp_path):
    victim=tmp_path/'victim';victim.write_text('keep')
    link=tmp_path/'telemetry.json';link.symlink_to(victim)
    with pytest.raises(ValueError,match='symlink'):agent.atomic(link,{'x':1})
    assert victim.read_text()=='keep' and link.is_symlink()
    assert sorted(p.name for p in tmp_path.iterdir())==['telemetry.json','victim']


def test_managed_hash_and_metadata_come_from_one_descriptor(tmp_path):
    path=tmp_path/'managed';path.write_bytes(b'abc');path.chmod(0o640)
    found={}
    digest=agent.hash_artifact(str(path),{},metadata=found)
    assert digest==agent.digest(str(path))
    assert (found['uid'],found['gid'],found['mode'])==(path.stat().st_uid,path.stat().st_gid,0o640)
