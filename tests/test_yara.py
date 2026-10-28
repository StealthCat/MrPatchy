import copy
import json
import os
import sys
import time
import pytest
from target import agent
from app import yara_rules,incidents,worker
from app.db import Session,Host,Job
from test_vendor import signing

SOURCE='rule Fixture { strings: $a = "PATCHY_TEST" condition: $a }'
def packet():
    import hashlib
    return {'source':SOURCE,'sha256':hashlib.sha256(SOURCE.encode()).hexdigest(),'issued':time.time()-60,'expires':time.time()+3600}

@pytest.fixture
def bundle(tmp_path,monkeypatch,signing):
    monkeypatch.setenv('DATA_DIR',str(tmp_path));root=tmp_path/'yara-rules';directory=root/'fixture';directory.mkdir(parents=True)
    (root/'trustedkeys.gpg').write_bytes(signing('--export').stdout)
    rules=packet();meta={k:v for k,v in rules.items() if k!='source'};meta['version']=1
    (directory/'rules.yar').write_text(SOURCE);(directory/'manifest.json').write_text(json.dumps(meta))
    signing('--yes','--detach-sign','--output',str(directory/'manifest.json.sig'),str(directory/'manifest.json'))
    return directory

def test_authentication_binds_source_manifest_and_operator_key(bundle):
    rules,proof=yara_rules.authenticate('fixture');assert rules['source']==SOURCE
    assert proof['rules_sha256']==rules['sha256'] and proof['signers'] and proof['manifest_sha256']

@pytest.mark.parametrize('name',['rules.yar','manifest.json','manifest.json.sig'])
def test_tampered_bundle_rejected(bundle,name):
    with (bundle/name).open('ab') as f:f.write(b'tampered')
    with pytest.raises((ValueError,RuntimeError)):yara_rules.authenticate('fixture')

@pytest.mark.parametrize('patch',[{'expires':0},{'issued_offset':600},{'sha256':'0'*64},{'expires_offset':40*86400},{'source':'include "private"'},{'source':'import "console"'},{'source':'abc\x00'},{'source':'x'*(128*1024+1)}])
def test_invalid_or_unsafe_rule_packets_rejected(patch):
    # Collection can precede this test by several minutes in the MySQL suite.
    # Construct relative timestamps now so the intended invalidity cannot age out.
    patch=dict(patch)
    for field in ('issued','expires'):
        if field+'_offset' in patch:patch[field]=time.time()+patch.pop(field+'_offset')
    with pytest.raises(ValueError):agent.validate_yara_rules({**packet(),**patch})

def fake_engine(tmp_path,monkeypatch,diagnostics=False):
    import shutil
    script=tmp_path/'yara';script.write_text('#!'+sys.executable+'\nimport sys,os\nif "--version" in sys.argv:print("4.2.0");sys.exit(0)\nassert "-C" not in sys.argv\nsource=open(sys.argv[-2]).read()\ndata=open(sys.argv[-1],"rb").read()\n'+('print("warning",file=sys.stderr)\n' if diagnostics else '')+'\nif b"PATCHY_TEST" in data:print("Fixture "+sys.argv[-1])\n');script.chmod(0o755)
    monkeypatch.setattr(shutil,'which',lambda value:str(script) if value=='yara' else None)

def test_descriptor_scan_retains_matches_provenance_and_excludes_links(tmp_path,monkeypatch):
    fake_engine(tmp_path,monkeypatch);root=tmp_path/'scan';root.mkdir();(root/'bad').write_text('PATCHY_TEST');(root/'good').write_text('benign')
    rules=packet();report=agent.security_scan([str(root)],rules)
    assert report['state']=='completed_with_findings' and report['scanned']==2 and len(report['findings'])==1
    assert report['findings'][0]['evidence']=='YARA rules: Fixture' and report['signatures']['database_version']==rules['sha256']
    (root/'link').symlink_to(root/'bad')
    assert agent.security_scan([str(root)],rules)['state']=='incomplete'

def test_missing_engine_and_diagnostics_are_incomplete(tmp_path,monkeypatch):
    import shutil
    monkeypatch.setattr(shutil,'which',lambda value:None)
    report=agent.security_scan([str(tmp_path)],packet())
    assert report['state']=='incomplete' and report['signatures']['database_version']==packet()['sha256']
    fake_engine(tmp_path,monkeypatch,True);root=tmp_path/'scan';root.mkdir();(root/'bad').write_text('PATCHY_TEST')
    report=agent.security_scan([str(root)],packet());assert report['state']=='incomplete' and not report['findings']

def test_api_worker_history_and_manual_only_plan_policy(admin,monkeypatch,bundle):
    with Session() as s:s.add(Host(id='yara-host',name='yara',address='192.0.2.1',fingerprint='pin'));s.commit()
    url='/api/hosts/yara-host/security/yara'
    queued=admin.post(url,json={'bundle_id':'fixture','paths':['/tmp']});assert queued.status_code==200
    assert admin.post('/api/hosts/yara-host/security',json={'paths':['/tmp']}).status_code==409
    def call(host,request,**kwargs):
        assert request['action']=='yara-scan' and request['rules']['source']==SOURCE
        return {'version':2,'engine':'YARA','state':'completed_with_findings','signatures':{'state':'recent','database_version':request['rules']['sha256']},'findings':[{'path':'/tmp/fixture','sha256':'a'*64,'evidence':'YARA rules: Fixture'}],'gaps':[]}
    monkeypatch.setattr(worker.ssh,'call',call);worker.execute(queued.json()['job_id'])
    with Session() as s:
        job=s.get(Job,queued.json()['job_id']);assert job.state=='complete',job.output
        report=s.get(incidents.Scan,job.id).report;assert report['rule_bundle']['signers']
        incident=s.query(incidents.Incident).one();assert incident.evidence['scan_context']['rule_bundle']['rules_sha256']==packet()['sha256']
        with pytest.raises(ValueError):incidents.record(s,'yara-host','forged',report)

def test_bad_authentication_prevents_remote_access(admin,monkeypatch):
    with Session() as s:s.add(Host(id='yara-host',name='yara',address='192.0.2.1',fingerprint='pin'));s.commit()
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:pytest.fail('No SSH without authentication'))
    queued=admin.post('/api/hosts/yara-host/security/yara',json={'bundle_id':'missing','paths':['/tmp']})
    worker.execute(queued.json()['job_id'])
    with Session() as s:assert s.get(Job,queued.json()['job_id']).state=='failed'


def test_yara_does_not_inherit_automatic_clamav_ai_upload(admin):
    from app.db import Setting
    from app.security import seal
    with Session() as s:
        s.add(Host(id='yara-host',name='yara',address='192.0.2.1',fingerprint='pin'))
        s.add(Setting(key='openai_key',value={'encrypted':seal('fixture')}))
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture'}))
        s.add(Setting(key='security-policy:yara-host',value={'auto_ai_plan':True}))
        incidents.record(s,'yara-host','yara-scan',{'engine':'YARA','findings':[{'path':'/tmp/test','sha256':'a'*64}]})
        s.commit()
    incidents.auto_plan_tick()
    with Session() as s:assert s.query(Job).filter(Job.action=='security-plan').count()==0


def test_rule_compilation_diagnostics_fail_even_with_empty_scope(tmp_path,monkeypatch):
    fake_engine(tmp_path,monkeypatch,True);root=tmp_path/'empty';root.mkdir()
    report=agent.security_scan([str(root)],packet())
    assert report['state']=='incomplete' and report['scanned']==0 and report['gaps']
