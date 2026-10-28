import copy
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest
from app import vendor,vendor_rpm,worker,incidents
from app.db import Session,Host,Job
from target import agent,bridge

SIGNATURE='''package.rpm:
    Header V4 RSA/SHA256 Signature, key ID 0123456789abcdef: OK
    Header SHA256 digest: OK (hash)
    Header SHA1 digest: OK (hash)
    Payload SHA256 digest: OK (hash)
    MD5 digest: OK (hash)
'''


def metadata(**changes):
    data={'package':['Patchy_test'],'epoch':['2'],'version':['1.0'],'release':['1'],'architecture':['x86_64'],'algorithm':['8'],
          'paths':['/usr/share/patchy-fixture'],'digests':['a'*64],'sizes':['11'],'longsizes':['11'],'modes':[str(0o100644)],'flags':['0']}
    data.update(changes)
    root=ET.Element('metadata')
    for key,values in data.items():
        node=ET.SubElement(root,key)
        for value in values:ET.SubElement(node,'string').text=value
    return ET.tostring(root,encoding='unicode')


def test_rpm_requires_explicit_verified_strong_signature_and_digests():
    assert vendor_rpm.signature_ids(SIGNATURE)==['0123456789abcdef']
    for value in [SIGNATURE.replace('SHA256 Signature','SHA1 Signature'),SIGNATURE.replace('Payload SHA256 digest: OK','Payload SHA256 digest: BAD'),SIGNATURE.replace('Header V4 RSA/SHA256 Signature, key ID 0123456789abcdef: OK',''),SIGNATURE.replace(': OK',': NOKEY'),SIGNATURE.replace('Header SHA256 digest: OK','Header SHA256 digest: NOT OK'),'digests OK']:
        with pytest.raises(ValueError):vendor_rpm.signature_ids(value)


def test_rpm_manifest_epoch_architecture_and_explicit_exclusions():
    manifest,excluded=vendor_rpm.metadata_manifest(metadata())
    assert manifest['version']=='2:1.0-1' and manifest['package_manager']=='rpm' and manifest['architecture']=='x86_64'
    assert manifest['entries']==[{'path':'/usr/share/patchy-fixture','sha256':'a'*64,'size':11}] and excluded==0
    output=metadata(paths=['/regular','/link','/ghost','/directory'],digests=['a'*64,'','',''],sizes=['1','0','0','0'],longsizes=['1','0','0','0'],modes=[str(0o100644),str(0o120777),str(0o100644),str(0o40755)],flags=['0','0','64','0'])
    manifest,excluded=vendor_rpm.metadata_manifest(output)
    assert len(manifest['entries'])==1 and excluded==2


@pytest.mark.parametrize('changes',[
    {'algorithm':['1']},{'epoch':['-1']},{'version':['1\nscript']},{'package':['--all']},{'architecture':['../bad']},
    {'paths':['/../escape']},{'paths':['/a','/a']},{'sizes':['-1']},{'longsizes':[str(33*1024*1024)]},{'digests':['']},{'modes':[]},{'flags':[]},
    {'longsizes':['1','2']},{'paths':['/a\n/b']},{'paths':['//a']},
])
def test_rpm_metadata_fails_closed(changes):
    with pytest.raises(ValueError):vendor_rpm.metadata_manifest(metadata(**changes))


def test_rpm_metadata_limits_and_unknown_xml():
    count=201
    with pytest.raises(ValueError):vendor_rpm.metadata_manifest(metadata(paths=['/file'+str(i) for i in range(count)],digests=['a'*64]*count,sizes=['1']*count,longsizes=['1']*count,modes=[str(0o100644)]*count,flags=['0']*count))
    with pytest.raises(ValueError):vendor_rpm.metadata_manifest('<!DOCTYPE metadata [<!ENTITY x "x">]>'+metadata())
    with pytest.raises(ValueError):vendor_rpm.metadata_manifest(metadata().replace('</metadata>','<unexpected/></metadata>'))


def test_rpm_authentication_isolates_trust_and_bounds_native_processes(tmp_path,monkeypatch):
    root=tmp_path/'vendor-packages';directory=root/'fixture';directory.mkdir(parents=True)
    (directory/'package.rpm').write_bytes(b'fixture rpm');(root/'rpm-trustedkeys.asc').write_bytes(b'fixture key')
    monkeypatch.setenv('DATA_DIR',str(tmp_path));calls=[]
    def bounded(args,**kwargs):
        calls.append(args)
        assert kwargs['timeout']==30 and kwargs['limit']==1024*1024 and kwargs['env']['LC_ALL']=='C'
        assert args[:2] in (['/usr/bin/rpmkeys','--noplugins'],['/usr/bin/rpm','--noplugins'])
        assert '--dbpath' in args and args[args.index('--dbpath')+1].startswith(kwargs['env']['HOME'])
        assert '--define' in args and '_keyring rpmdb' in args
        if '--import' in args:
            assert Path(args[-1]).read_bytes()==b'fixture key';return '',''
        assert Path(args[-1]).read_bytes()==b'fixture rpm'
        return (SIGNATURE if '--checksig' in args else metadata()),''
    monkeypatch.setattr(vendor_rpm,'bounded',bounded)
    manifest,proof=vendor.authenticate('fixture',now=123)
    assert len(calls)==3 and manifest['version']=='2:1.0-1'
    assert proof['artifact_sha256']==vendor.sha(b'fixture rpm') and proof['keyring_sha256']==vendor.sha(b'fixture key')
    assert proof['signature_key_ids']==['0123456789abcdef'] and proof['authenticated_at']==123
    assert not Path(calls[0][calls[0].index('--dbpath')+1]).exists()
    (directory/'package.deb').write_bytes(b'also deb')
    with pytest.raises(ValueError,match='Ambiguous'):vendor.authenticate('fixture')


def test_signature_failure_prevents_header_query(tmp_path,monkeypatch):
    root=tmp_path/'vendor-packages';directory=root/'fixture';directory.mkdir(parents=True)
    (directory/'package.rpm').write_bytes(b'rpm');(root/'rpm-trustedkeys.asc').write_bytes(b'key')
    calls=[]
    def bounded(args,**kwargs):
        calls.append(args)
        if '--import' in args:return '',''
        if '--checksig' in args:return 'digests OK',''
        pytest.fail('Unauthenticated header must not be queried')
    monkeypatch.setattr(vendor_rpm,'bounded',bounded)
    with pytest.raises(ValueError):vendor_rpm.authenticate(directory,root,'fixture')
    assert len(calls)==2


def test_rpm_target_checks_exact_epoch_and_architecture_before_and_after_hashing(tmp_path,monkeypatch):
    path=tmp_path/'file';path.write_bytes(b'vendor bytes')
    manifest={'package_manager':'rpm','package':'Patchy_test','version':'2:1.0-1','architecture':'x86_64','entries':[{'path':str(path),'sha256':vendor.sha(path.read_bytes()),'size':path.stat().st_size}]}
    calls=[];identity='Patchy_test 2:1.0-1 x86_64\n'
    def bounded(args,**kwargs):
        calls.append(args)
        assert args==['rpm','--noplugins','-q','--qf','%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\n','--','Patchy_test.x86_64']
        return identity,'',0
    monkeypatch.setattr(bridge,'bounded',bounded)
    receipt=agent.vendor_inspect(manifest)
    assert receipt['state']=='matches_artifact_bytes' and len(calls)==2
    vendor.validate_receipt(manifest,receipt)
    identity='Patchy_test 1:1.0-1 x86_64\n'
    receipt=agent.vendor_inspect(manifest)
    assert receipt['state']=='incomplete' and receipt['examined']==0
    identity='Patchy_test 2:1.0-1 x86_64\nPatchy_test 3:1.0-1 x86_64\n'
    assert agent.vendor_inspect(manifest)['state']=='incomplete'
    identity='Patchy_test 2:1.0-1 aarch64\n'
    assert agent.vendor_inspect(manifest)['state']=='incomplete'


def test_rpm_worker_retains_provenance_and_rejects_target_trust_forgery(admin,monkeypatch):
    manifest,_=vendor_rpm.metadata_manifest(metadata())
    proof={'signature_key_ids':['0123456789abcdef'],'artifact_sha256':'b'*64}
    monkeypatch.setattr(vendor,'authenticate',lambda *args:(manifest,proof))
    with Session() as s:s.add(Host(id='rpm-vendor',name='rpm',address='192.0.2.1',fingerprint='test'));s.commit()
    receipt={'trust_basis':'controller_authenticated_rpm_artifact','package':manifest['package'],'version':manifest['version'],'architecture':manifest['architecture'],'scope_files':1,'examined':1,'state':'matches_artifact_bytes','gaps':[],'findings':[]}
    monkeypatch.setattr(worker.ssh,'call',lambda *args,**kwargs:copy.deepcopy(receipt))
    response=admin.post('/api/hosts/rpm-vendor/security/vendor-inspections',json={'bundle_id':'fixture'})
    worker.execute(response.json()['job_id'])
    with Session() as s:
        job=s.get(Job,response.json()['job_id']);assert job.state=='complete',job.output
        report=s.get(incidents.Inspection,job.id).report
        assert report['trust_basis']=='controller_authenticated_rpm_artifact' and report['vendor_authentication']==proof
        with pytest.raises(ValueError):incidents.record_inspection(s,'rpm-vendor','forged',{**report,'trust_basis':'controller_authenticated_rpm_artifact'})
    with pytest.raises(ValueError):vendor.validate_receipt(manifest,{**receipt,'trust_basis':'controller_authenticated_debian_artifact'})


def test_native_xml_array_wrappers_and_wrong_tag_names():
    root=ET.fromstring(metadata())
    for node in root:
        if node.tag in vendor_rpm.ARRAYS:
            wrapper=ET.Element('rpmTag',{'name':vendor_rpm.ARRAYS[node.tag].capitalize()})
            wrapper.extend(list(node));node[:]=[wrapper]
    manifest,_=vendor_rpm.metadata_manifest(ET.tostring(root,encoding='unicode'))
    assert manifest['version']=='2:1.0-1' and len(manifest['entries'])==1
    root.find('paths/rpmTag').set('name','Unexpected')
    with pytest.raises(ValueError,match='wrapper'):vendor_rpm.metadata_manifest(ET.tostring(root,encoding='unicode'))
