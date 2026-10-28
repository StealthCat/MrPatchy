import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time
import pytest
from app import vendor,worker,incidents
from app.db import Session,Host,Job
from app.identity import User
from target import agent,bridge


def tar(items):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz') as archive:
        for name,data in items:
            info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
    return out.getvalue()


def ar(items):
    out=b'!<arch>\n'
    for name,data in items:
        out+=(name+'/').ljust(16).encode()+b'0           0     0     100644  '+str(len(data)).ljust(10).encode()+b'`\n'+data+(b'\n' if len(data)%2 else b'')
    return out


@pytest.fixture(scope='module')
def signing():
    if not shutil.which('gpgv'):pytest.skip('gpgv unavailable')
    import pgpy
    from pgpy.constants import PubKeyAlgorithm,KeyFlags,HashAlgorithm,SymmetricKeyAlgorithm,CompressionAlgorithm
    key=pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign,2048)
    key.add_uid(pgpy.PGPUID.new('Vendor test',email='fixture@example.invalid'),usage={KeyFlags.Sign},hashes=[HashAlgorithm.SHA256],ciphers=[SymmetricKeyAlgorithm.AES256],compression=[CompressionAlgorithm.ZLIB])
    def gpg(*args):
        if args==('--export',):return subprocess.CompletedProcess([],0,bytes(key.pubkey),b'')
        Path(args[args.index('--output')+1]).write_bytes(bytes(key.sign(Path(args[-1]).read_bytes(),detached=True,hash=HashAlgorithm.SHA256)))
    return gpg


@pytest.fixture
def bundle(tmp_path,monkeypatch,signing):
    monkeypatch.setenv('DATA_DIR',str(tmp_path))
    root=tmp_path/'vendor-packages';directory=root/'fixture';directory.mkdir(parents=True)
    (root/'trustedkeys.gpg').write_bytes(signing('--export').stdout)
    control=b'Package: patchy-test\nVersion: 1.0-1\nArchitecture: amd64\n'
    artifact=ar([('debian-binary',b'2.0\n'),('control.tar.gz',tar([('./control',control)])),('data.tar.gz',tar([('./usr/share/patchy-test',b'known bytes')]))])
    (directory/'package.deb').write_bytes(artifact)
    index=b'Package: patchy-test\nVersion: 1.0-1\nArchitecture: amd64\nSize: '+str(len(artifact)).encode()+b'\nSHA256: '+vendor.sha(artifact).encode()+b'\n\n'
    (directory/'Packages').write_bytes(index);(directory/'index-path').write_text('main/binary-amd64/Packages\n')
    def sign(date=None,expires=None):
        from email.utils import formatdate
        release='Origin: Test vendor\nSuite: stable\nDate: '+formatdate(time.time() if date is None else date,usegmt=True)+'\n'
        if expires is not None:release+='Valid-Until: '+formatdate(expires,usegmt=True)+'\n'
        release+='SHA256:\n '+vendor.sha(index)+' '+str(len(index))+' main/binary-amd64/Packages\n'
        (directory/'Release').write_text(release)
        signing('--yes','--detach-sign','--output',str(directory/'Release.gpg'),str(directory/'Release'))
    sign();return directory,sign


def test_authenticated_manifest_does_not_use_target_metadata(bundle):
    manifest,proof=vendor.authenticate('fixture')
    assert manifest=={'package':'patchy-test','version':'1.0-1','architecture':'amd64','entries':[{'path':'/usr/share/patchy-test','sha256':vendor.sha(b'known bytes'),'size':11}]}
    assert len(proof['signers'])==1 and proof['artifact_sha256'] and proof['keyring_sha256']
    assert 'known bytes' not in json.dumps(manifest)


@pytest.mark.parametrize('file',['Release','Release.gpg','Packages','package.deb','index-path'])
def test_tampered_chain_rejected(bundle,file):
    directory,_=bundle
    with (directory/file).open('ab') as stream:stream.write(b'tampered')
    with pytest.raises((ValueError,KeyError,UnicodeError)):vendor.authenticate('fixture')


@pytest.mark.parametrize('age,expires',[(8*86400,None),(-600,None),(0,-1)])
def test_signed_stale_future_expired_release_rejected(bundle,age,expires):
    _,sign=bundle;sign(time.time()-age,time.time()+expires if expires else None)
    with pytest.raises(ValueError):vendor.authenticate('fixture')


def test_wrong_key_and_symlink_files_rejected(bundle,tmp_path):
    directory,_=bundle
    key=directory.parent/'trustedkeys.gpg';key.write_bytes(b'not a key')
    with pytest.raises(ValueError):vendor.authenticate('fixture')
    path=directory/'Packages';path.unlink();path.symlink_to(tmp_path/'elsewhere')
    with pytest.raises(OSError):vendor.read_file(path,100)
    with pytest.raises(ValueError):vendor.authenticate('../fixture')


def test_tar_traversal_duplicate_and_budget():
    with pytest.raises(ValueError):list(vendor.tar_members(tar([('../escape',b'x')])))
    with pytest.raises(ValueError):list(vendor.tar_members(tar([('/absolute',b'x')])))
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w') as archive:
        info=tarfile.TarInfo('huge');info.size=33*1024*1024;archive.addfile(info)
    with pytest.raises(ValueError):list(vendor.tar_members(out.getvalue()))


@pytest.mark.parametrize('content_size',[True,False])
def test_zstd_tar_bounded_and_strict(monkeypatch,content_size):
    import gzip
    import zstandard
    raw=gzip.decompress(tar([('./srv/test',b'known bytes')]))
    compressor=zstandard.ZstdCompressor(write_content_size=content_size,write_checksum=True)
    if content_size:compressed=compressor.compress(raw)
    else:
        stream=compressor.compressobj();compressed=stream.compress(raw)+stream.flush()
        assert zstandard.get_frame_parameters(compressed).window_size>128*1024
    members=[]
    for archive,member,path in vendor.tar_members(compressed):
        members.append((path,archive.extractfile(member).read()))
    assert members==[('/srv/test',b'known bytes')]
    for invalid in (compressed[:-1],compressed+b'extra',compressed+compressed):
        with pytest.raises(ValueError):list(vendor.tar_members(invalid))
    monkeypatch.setattr(vendor,'TAR_STREAM_LIMIT',len(raw)-1)
    with pytest.raises(ValueError):list(vendor.tar_members(compressed))


def test_zstd_tar_window_limit():
    import zstandard
    compressor=zstandard.ZstdCompressor(compression_params=zstandard.ZstdCompressionParameters.from_level(1,window_log=28,force_max_window=True,write_content_size=False)).compressobj()
    # A streaming frame advertises its configured window even for a small input.
    with pytest.raises(ValueError,match='work limit'):list(vendor.tar_members(compressor.compress(b'x'*1024)+compressor.flush()))


def manifest(path):return {'package':'patchy-test','version':'1.0-1','architecture':'amd64','entries':[{'path':str(path),'sha256':vendor.sha(b'known bytes'),'size':11}]}


def installed(monkeypatch,change=False):
    calls=[]
    def query(args,**kwargs):
        assert args==['dpkg-query','-W','-f=${db:Status-Status} ${Version} ${Architecture}\n','--','patchy-test:amd64']
        calls.append(args)
        return ('installed 2 amd64\n' if change and len(calls)>1 else 'installed 1.0-1 amd64\n'),'',0
    monkeypatch.setattr(bridge,'bounded',query)
    return calls


def test_target_match_modified_missing_and_identity_drift(tmp_path,monkeypatch):
    path=tmp_path/'file';path.write_bytes(b'known bytes');calls=installed(monkeypatch)
    assert agent.vendor_inspect(manifest(path))['state']=='matches_artifact_bytes'
    assert len(calls)==2
    path.write_bytes(b'modified');assert agent.vendor_inspect(manifest(path))['findings'][0]['status']=='content_differs'
    path.unlink();assert agent.vendor_inspect(manifest(path))['findings'][0]['status']=='missing'
    path.write_bytes(b'known bytes');installed(monkeypatch,True)
    assert agent.vendor_inspect(manifest(path))['state']=='incomplete'


def test_target_symlink_special_and_parent_alias_are_gaps(tmp_path,monkeypatch):
    installed(monkeypatch)
    target=tmp_path/'target';target.write_bytes(b'known bytes')
    link=tmp_path/'link';link.symlink_to(target)
    assert agent.vendor_inspect(manifest(link))['state']=='incomplete'
    alias=tmp_path/'alias';alias.symlink_to(tmp_path,target_is_directory=True)
    assert agent.vendor_inspect(manifest(alias/'target'))['state']=='incomplete'
    fifo=tmp_path/'fifo';os.mkfifo(fifo)
    assert agent.vendor_inspect(manifest(fifo))['state']=='incomplete'


def test_target_replacement_during_hash_is_gap(tmp_path,monkeypatch):
    installed(monkeypatch);path=tmp_path/'file';path.write_bytes(b'known bytes')
    original=os.read;changed=False
    def read(fd,count):
        nonlocal changed
        data=original(fd,count)
        if data and not changed:
            changed=True;path.unlink();path.write_bytes(b'known bytes')
        return data
    monkeypatch.setattr(os,'read',read)
    assert agent.vendor_inspect(manifest(path))['state']=='incomplete'


def test_vendor_api_and_worker_retains_controller_provenance(admin,monkeypatch,bundle):
    with Session() as s:s.add(Host(id='vendor-host',name='vendor-host',address='192.0.2.1',fingerprint='test'));s.commit()
    path='/api/hosts/vendor-host/security/vendor-inspections'
    assert admin.post(path,json={'bundle_id':'../escape'}).status_code==422
    queued=admin.post(path,json={'bundle_id':'fixture'});assert queued.status_code==200
    assert admin.post('/api/hosts/vendor-host/security/inspections',json={'packages':[]}).status_code==409
    def call(host,request,**kwargs):
        assert request['action']=='vendor-inspect' and request['manifest']['version']=='1.0-1'
        return {'trust_basis':'controller_authenticated_debian_artifact','package':'patchy-test','version':'1.0-1','architecture':'amd64','state':'matches_artifact_bytes','scope_files':1,'examined':1,'findings':[],'gaps':[]}
    monkeypatch.setattr(worker.ssh,'call',call)
    worker.execute(queued.json()['job_id'])
    with Session() as s:
        job=s.get(Job,queued.json()['job_id']);assert job.state=='complete',job.output
        receipt=s.get(incidents.Inspection,job.id).report
        assert receipt['vendor_authentication']['signers'] and receipt['vendor_verification']['state']=='matches_artifact_bytes'
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.post(path,json={'bundle_id':'fixture'}).status_code==403


def test_authentication_failure_prevents_ssh(admin,monkeypatch):
    with Session() as s:s.add(Host(id='no-vendor',name='x',address='192.0.2.1',fingerprint='x'));s.commit()
    def forbidden(*args,**kwargs):pytest.fail('SSH must not run without authenticated evidence')
    monkeypatch.setattr(worker.ssh,'call',forbidden)
    response=admin.post('/api/hosts/no-vendor/security/vendor-inspections',json={'bundle_id':'missing'})
    worker.execute(response.json()['job_id'])
    with Session() as s:
        assert s.get(Job,response.json()['job_id']).state=='failed'
        assert s.get(incidents.Inspection,response.json()['job_id']) is None


@pytest.mark.parametrize('patch',[{'examined':0},{'scope_files':2},{'gaps':['unreadable']},{'findings':[{'path':'/outside','status':'missing'}]}])
def test_controller_rejects_contradictory_or_unscoped_receipts(patch):
    item=manifest(Path('/fixture'))
    receipt={'trust_basis':'controller_authenticated_debian_artifact','package':'patchy-test','version':'1.0-1','architecture':'amd64','state':'matches_artifact_bytes','scope_files':1,'examined':1,'findings':[],'gaps':[]}
    with pytest.raises(ValueError):vendor.validate_receipt(item,{**receipt,**patch})


def test_target_cannot_label_local_receipt_as_controller_authenticated():
    with Session() as s:
        for basis in ('target_local_package_database','controller_authenticated_debian_artifact'):
            report={'version':1,'trust_basis':basis,'state':'collected','packages':[],'vendor_authentication':{'signers':['forged']}}
            with pytest.raises(ValueError):incidents.record_inspection(s,'host','forged-job',report)
