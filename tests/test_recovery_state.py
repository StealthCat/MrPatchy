"""Durable filesystem coverage in complete recovery (#120)."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db import Base
from app import evidence_archive
from app.evidence_vault import EvidenceArchive
from test_recovery_ssh import recovery, deployment, activate


def durable_state(data):
    for name in ('evidence-archive','vendor-packages','yara-rules','gcloud'):
        directory=data/name/'sample';directory.mkdir(parents=True,mode=0o700)
        (directory/'content').write_bytes(name.encode())
        (directory/'content').chmod(0o600)
    (data/'yara-rules'/'trustedkeys.gpg').write_bytes(b'keyring fixture')
    (data/'vendor-packages'/'trustedkeys.gpg').write_bytes(b'vendor keyring fixture')


def test_durable_evidence_trust_and_gcp_state_round_trip(recovery,tmp_path):
    data,others=deployment(tmp_path,ssh_dir=False)
    durable_state(data)
    recovery.backup(data,*others)
    bundle,=recovery.bundles
    for name in ('evidence-archive','vendor-packages','yara-rules','gcloud'):
        assert (bundle/name/'sample/content').read_bytes()==name.encode()
    restored=activate(recovery,bundle,tmp_path)/'data'
    for name in ('evidence-archive','vendor-packages','yara-rules','gcloud'):
        assert (restored/name/'sample/content').read_bytes()==name.encode()
        assert stat.S_IMODE((restored/name).stat().st_mode)==0o700
        assert stat.S_IMODE((restored/name/'sample/content').stat().st_mode)==0o600
    assert (restored/'yara-rules/trustedkeys.gpg').read_bytes()==b'keyring fixture'


@pytest.mark.parametrize('change',['modified','missing','extra','symlink','hardlink','fifo','manifest'])
def test_tampered_state_refused_before_activation_mutates_destinations(recovery,tmp_path,change):
    data,others=deployment(tmp_path,ssh_dir=False);durable_state(data)
    recovery.backup(data,*others);bundle,=recovery.bundles
    path=bundle/'evidence-archive/sample/content'
    if change=='modified':path.write_bytes(b'changed')
    elif change=='missing':path.unlink()
    elif change=='extra':(path.parent/'extra').write_text('extra')
    elif change=='symlink':path.unlink();path.symlink_to(data/'evidence-archive/sample/content')
    elif change=='hardlink':os.link(path,path.parent/'alias')
    elif change=='fifo':path.unlink();os.mkfifo(path)
    else:
        manifest=json.loads((bundle/'manifest.json').read_text());del manifest['durable_state']['yara-rules']
        (bundle/'manifest.json').write_text(json.dumps(manifest))
    target=tmp_path/'untouched'
    with pytest.raises((ValueError,FileNotFoundError)):
        recovery.activate(bundle,target/'data',target/'tls',target/'caddy-data',target/'caddy-config')
    assert not target.exists()


@pytest.mark.parametrize('change',['root_symlink','nested_symlink','hardlink','fifo'])
def test_unsafe_source_refused_without_restic_publication(recovery,tmp_path,change):
    data,others=deployment(tmp_path,ssh_dir=False);durable_state(data)
    path=data/'yara-rules/sample/content'
    if change=='root_symlink':
        shutil.rmtree(data/'yara-rules');(data/'yara-rules').symlink_to(data/'vendor-packages')
    elif change=='nested_symlink':path.unlink();path.symlink_to(data/'vendor-packages/sample/content')
    elif change=='hardlink':os.link(path,path.parent/'alias')
    else:path.unlink();os.mkfifo(path)
    with pytest.raises(ValueError):recovery.backup(data,*others)
    assert not recovery.calls


def test_legacy_bundle_warns_and_absence_is_explicit(recovery,tmp_path,capsys):
    data,others=deployment(tmp_path,ssh_dir=False);recovery.backup(data,*others)
    bundle,=recovery.bundles;manifest=json.loads((bundle/'manifest.json').read_text())
    assert manifest['format']==2 and set(manifest['durable_state'].values())=={None}
    assert 'absent at backup' in capsys.readouterr().err
    manifest={'format':1,'database':'sqlite'};(bundle/'manifest.json').write_text(json.dumps(manifest))
    activate(recovery,bundle,tmp_path)
    assert 'Legacy format-1 bundle has no evidence/trust/GCP filesystem coverage' in capsys.readouterr().err


def seed_archive(data,engine):
    """An actual EvidenceArchive with receipt and bytes accepted by verify()."""
    identifier=str(uuid.uuid4());content=b'preserved evidence; never execute\x00'
    row=EvidenceArchive(id=identifier,host_id='host',copy_id='copy',state='verified',
        snapshot={'sha256':hashlib.sha256(content).hexdigest(),'identity':{'size':len(content)}},
        fingerprint='SHA256:fixture',actor='admin',reason='recovery drill',created=1,expires=2)
    with Session(engine) as session:session.add(row);session.commit();session.refresh(row);session.expunge(row)
    root=data/'evidence-archive';root.mkdir(mode=0o700)
    folder=root/identifier;folder.mkdir(mode=0o700)
    (folder/'content').write_bytes(content)
    (folder/'receipt.json').write_text(json.dumps(evidence_archive.manifest(row)))
    for path in folder.iterdir():path.chmod(0o600)
    return row


def test_actual_archive_still_verifies_after_sqlite_database_and_files_recovery(recovery,tmp_path,monkeypatch):
    data,others=deployment(tmp_path,ssh_dir=False)
    engine=create_engine('sqlite:///'+str(data/'mrpatchy.db'))
    row=seed_archive(data,engine);engine.dispose()
    monkeypatch.setattr(evidence_archive,'DATA',data)
    assert evidence_archive.verify(row)=='verified'
    recovery.backup(data,*others);bundle,=recovery.bundles
    target=activate(recovery,bundle,tmp_path)/'data'
    restored=create_engine('sqlite:///'+str(target/'mrpatchy.db'))
    monkeypatch.setattr(evidence_archive,'DATA',target)
    with Session(restored) as session:assert evidence_archive.verify(session.get(EvidenceArchive,row.id))=='verified'
    restored.dispose()


def test_missing_verified_archive_blocks_successful_backup(recovery,tmp_path):
    data,others=deployment(tmp_path,ssh_dir=False)
    engine=create_engine('sqlite:///'+str(data/'mrpatchy.db'));row=seed_archive(data,engine);engine.dispose()
    (data/'evidence-archive'/row.id/'content').unlink()
    with pytest.raises(ValueError,match='Missing verified evidence'):recovery.backup(data,*others)
    assert not recovery.calls


from test_vendor import signing, bundle as vendor_bundle
from test_yara import bundle as yara_bundle


def test_signed_vendor_and_yara_bundles_authenticate_after_recovery(recovery,tmp_path,monkeypatch,vendor_bundle,yara_bundle):
    from app import vendor,yara_rules
    location=tmp_path/'deployment';location.mkdir()
    data,others=deployment(location,ssh_dir=False)
    shutil.copytree(vendor_bundle[0].parent,data/'vendor-packages')
    shutil.copytree(yara_bundle.parent,data/'yara-rules')
    monkeypatch.setenv('DATA_DIR',str(data))
    expected_vendor=vendor.authenticate('fixture');expected_yara=yara_rules.authenticate('fixture')
    recovery.backup(data,*others);bundle,=recovery.bundles
    target=activate(recovery,bundle,tmp_path)/'data';monkeypatch.setenv('DATA_DIR',str(target))
    actual_vendor=vendor.authenticate('fixture');actual_yara=yara_rules.authenticate('fixture')
    assert actual_vendor[0]==expected_vendor[0] and actual_yara[0]==expected_yara[0]
    for actual,expected in ((actual_vendor[1],expected_vendor[1]),(actual_yara[1],expected_yara[1])):
        assert actual['keyring_sha256']==expected['keyring_sha256'] and actual['signers']==expected['signers']


@pytest.mark.parametrize('backend',['sqlite','mysql'])
def test_native_encrypted_evidence_recovery_drill(client,tmp_path,monkeypatch,backend):
    """Real restic and (in MySQL CI) native dump/import, not mocked database copies."""
    from app.db import engine as application_engine
    from test_recovery_ssh import recovery_module
    mysql_url=os.getenv('TEST_DATABASE_URL','')
    if backend=='mysql' and not mysql_url.startswith('mysql'):pytest.skip('MySQL recovery runs in the MySQL CI shard')
    if not shutil.which('restic'):pytest.skip('Native restic is installed in SQLite/MySQL CI')
    module=recovery_module();monkeypatch.setattr(module,'remote',lambda:None)
    data,others=deployment(tmp_path,ssh_dir=False)
    if backend=='sqlite':
        source=create_engine('sqlite:///'+str(data/'mrpatchy.db'))
        monkeypatch.setenv('DATABASE_URL','sqlite:///'+str(data/'mrpatchy.db'))
    else:
        assert shutil.which('mysql') and shutil.which('mysqldump'),'MySQL CI requires native recovery clients'
        source=application_engine;monkeypatch.setenv('DATABASE_URL',mysql_url)
    row=seed_archive(data,source)
    password=tmp_path/'password';password.write_text('disposable-restic-drill-password')
    monkeypatch.setenv('RESTIC_PASSWORD_FILE',str(password));monkeypatch.setenv('RESTIC_REPOSITORY',str(tmp_path/'repository'))
    module.run(['restic','init']);module.backup(data,*others)
    bundle=module.restore('latest',tmp_path/'staging')
    assert json.loads((bundle/'manifest.json').read_text())['database']==backend
    if backend=='mysql':Base.metadata.drop_all(source)
    source.dispose()
    target=activate(module,bundle,tmp_path)/'data'
    restored=create_engine('sqlite:///'+str(target/'mrpatchy.db')) if backend=='sqlite' else application_engine
    monkeypatch.setattr(evidence_archive,'DATA',target)
    with Session(restored) as session:
        record=session.get(EvidenceArchive,row.id)
        assert record and evidence_archive.verify(record)=='verified'
    restored.dispose()
