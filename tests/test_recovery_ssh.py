"""Recovery of the SSH identity directory for empty and populated fleets (#131)."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat

import pytest
from sqlalchemy import create_engine

from app.db import Base


def recovery_module():
    spec=importlib.util.spec_from_file_location('recovery',Path(__file__).parents[1]/'scripts/recovery.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def deployment(tmp_path,hosts=(),keys=(),ssh_dir=True):
    """A valid initialized deployment with the real application schema."""
    data=tmp_path/'data';data.mkdir()
    database=data/'mrpatchy.db'
    engine=create_engine('sqlite:///'+str(database));Base.metadata.create_all(engine);engine.dispose()
    with sqlite3.connect(database) as db:
        for host,deleted in hosts:
            db.execute("INSERT INTO hosts (id,name,address,port,fingerprint,state,enabled,deleted_at,lifecycle_revision,error,repo_error,last_seen,last_repo,inventory,telemetry,baseline,integrity) VALUES (?,?,'192.0.2.1',22,'SHA256:fixture','online',1,?,'','','',0,0,'{}','{}','{}','[]')",(host,host,deleted))
    (data/'secret.key').write_text('encryption fixture')
    if ssh_dir:
        (data/'ssh').mkdir(mode=0o700)
        for host in keys:(data/'ssh'/(host+'.key')).write_text('private fixture '+host)
    others=[]
    for name in ('tls','caddy-data','caddy-config'):
        path=tmp_path/name;path.mkdir();(path/'fixture').write_text(name);others.append(path)
    return data,others


@pytest.fixture
def recovery(tmp_path,monkeypatch):
    module=recovery_module();module.calls=[];module.bundles=[]
    def run(args,**kwargs):
        module.calls.append(args)
        if args[:2]==['restic','backup']:
            saved=tmp_path/('captured-'+str(len(module.bundles)));shutil.copytree(Path(kwargs['cwd'])/'bundle',saved);module.bundles.append(saved)
    monkeypatch.setattr(module,'remote',lambda:None);monkeypatch.setattr(module,'run',run)
    monkeypatch.delenv('DATABASE_URL',raising=False)
    return module


def activate(recovery,bundle,tmp_path):
    target=tmp_path/'restored';target.mkdir()
    recovery.activate(bundle,target/'data',target/'tls',target/'caddy-data',target/'caddy-config',uid=os.getuid())
    return target


def test_zero_server_backup_without_ssh_directory_round_trips(recovery,tmp_path):
    data,others=deployment(tmp_path,ssh_dir=False)
    recovery.backup(data,*others)
    assert [call[:2] for call in recovery.calls]==[['restic','backup'],['restic','check']]
    bundle,=recovery.bundles
    assert (bundle/'ssh').is_dir() and not any((bundle/'ssh').iterdir())
    assert json.loads((bundle/'manifest.json').read_text())['ssh_hosts']==[]
    assert not (data/'ssh').exists()  # Backup never mutates the source deployment.
    restored=activate(recovery,bundle,tmp_path)/'data'
    assert (restored/'ssh').is_dir() and not any((restored/'ssh').iterdir())
    assert stat.S_IMODE((restored/'ssh').stat().st_mode)==0o700
    assert (restored/'mrpatchy.db').is_file() and (restored/'secret.key').read_text()=='encryption fixture'


def test_populated_fleet_backup_and_activation_retain_keys(recovery,tmp_path):
    data,others=deployment(tmp_path,hosts=[('host-a',0),('host-b',0)],keys=['host-a','host-b'])
    (data/'ssh'/'host-a.rotation.json').write_text('{}')
    recovery.backup(data,*others)
    bundle,=recovery.bundles
    assert json.loads((bundle/'manifest.json').read_text())['ssh_hosts']==['host-a','host-b']
    restored=activate(recovery,bundle,tmp_path)/'data'
    assert (restored/'ssh'/'host-b.key').read_text()=='private fixture host-b'
    assert (restored/'ssh'/'host-a.rotation.json').is_file()


def test_deleted_servers_do_not_require_keys(recovery,tmp_path):
    data,others=deployment(tmp_path,hosts=[('gone',1793404800.0)],ssh_dir=False)
    recovery.backup(data,*others)
    bundle,=recovery.bundles
    assert json.loads((bundle/'manifest.json').read_text())['ssh_hosts']==[]


@pytest.mark.parametrize('ssh_dir',[False,True])
def test_backup_refuses_missing_keys_for_enrolled_servers(recovery,tmp_path,ssh_dir):
    data,others=deployment(tmp_path,hosts=[('host-a',0),('host-b',0)],keys=['host-a'],ssh_dir=ssh_dir)
    with pytest.raises(ValueError,match='Missing SSH private key for enrolled server.*host-b'):recovery.backup(data,*others)
    assert not recovery.calls and not recovery.bundles


def test_backup_refuses_empty_or_linked_key_and_linked_directory(recovery,tmp_path):
    data,others=deployment(tmp_path,hosts=[('host-a',0)],keys=[])
    (data/'ssh'/'host-a.key').write_text('')
    with pytest.raises(ValueError,match='host-a'):recovery.backup(data,*others)
    (data/'ssh'/'host-a.key').unlink();(data/'ssh'/'host-a.key').symlink_to(tmp_path/'tls'/'fixture')
    with pytest.raises(ValueError):recovery.backup(data,*others)
    shutil.rmtree(data/'ssh');(data/'ssh').symlink_to(tmp_path/'tls')
    with pytest.raises(ValueError,match='symlink'):recovery.backup(data,*others)
    assert not recovery.calls


def test_activation_refuses_bundle_missing_enrolled_key_before_mutation(recovery,tmp_path):
    data,others=deployment(tmp_path,hosts=[('host-a',0)],keys=['host-a'])
    recovery.backup(data,*others)
    bundle,=recovery.bundles
    (bundle/'ssh'/'host-a.key').unlink()
    with pytest.raises(ValueError,match='host-a'):activate(recovery,bundle,tmp_path)
    assert not any((tmp_path/'restored').iterdir())
    # The database is checked too, so an edited manifest cannot hide the server.
    (bundle/'manifest.json').write_text(json.dumps({'format':1,'database':'sqlite','ssh_hosts':[]}))
    with pytest.raises(ValueError,match='host-a'):recovery.activate(bundle,tmp_path/'r2'/'data',tmp_path/'r2'/'tls',tmp_path/'r2'/'cd',tmp_path/'r2'/'cc',uid=os.getuid())
    assert not (tmp_path/'r2').exists()


def test_activation_rejects_malformed_server_identifiers(recovery,tmp_path):
    data,others=deployment(tmp_path,ssh_dir=False)
    recovery.backup(data,*others)
    bundle,=recovery.bundles
    for value in (['../secret'],'host-a'):
        (bundle/'manifest.json').write_text(json.dumps({'format':1,'database':'sqlite','ssh_hosts':value}))
        with pytest.raises(ValueError):activate(recovery,bundle,tmp_path)
        shutil.rmtree(tmp_path/'restored')


def test_legacy_bundle_without_server_list_still_activates(recovery,tmp_path):
    data,others=deployment(tmp_path,hosts=[('host-a',0)],keys=['host-a'])
    recovery.backup(data,*others)
    bundle,=recovery.bundles
    (bundle/'manifest.json').write_text(json.dumps({'format':1,'database':'sqlite'}))
    restored=activate(recovery,bundle,tmp_path)/'data'
    assert (restored/'ssh'/'host-a.key').is_file()
