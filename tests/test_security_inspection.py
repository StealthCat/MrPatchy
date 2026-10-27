import json
import os
import sys
import time
from pathlib import Path
import pytest
from target import agent,bridge
from app import incidents,worker
from app.db import Session,Host,Job
from app.identity import User

@pytest.mark.parametrize('packages,persistence',[([],False),(['--all'],True),(['bash*'],True),(['x;id'],True),(['x','x'],True),(['x']*17,True),(['x'],'true')])
def test_inspection_scope_rejects_unbounded_selection(packages,persistence):
    with pytest.raises(ValueError):agent.validate_inspection(packages,persistence)

def test_verification_parser_preserves_spaces_configuration_and_gaps():
    rows,gaps=agent.parse_package_verification('??5?????? c /etc/my config\nmissing     /usr/bin/example\nS.5....T.   /usr/lib/example\nunexpected warning')
    assert len(rows)==3 and rows[0]['path']=='/etc/my config' and rows[0]['configuration_file']
    assert rows[1]['status']=='missing' and gaps
    rows,gaps=agent.parse_package_verification('\n'.join('??5??????   /file'+str(i) for i in range(201)))
    assert len(rows)==200 and gaps

@pytest.mark.parametrize('rpm',[False,True])
def test_package_verification_uses_safe_commands_and_detects_identity_change(monkeypatch,rpm):
    exists=Path.exists
    monkeypatch.setattr(Path,'exists',lambda p: not rpm if str(p)=='/var/lib/dpkg/status' else exists(p))
    calls=[];queries=[]
    def bounded(args,**kwargs):
        calls.append(args)
        assert kwargs['timeout']<=30 and kwargs['limit']==512000
        if args[0]=='dpkg-query' or '-q' in args:
            queries.append(True)
            return ('pkg 1-1 x86_64\n' if rpm else 'installed 1\n') if len(queries)==1 else 'changed\n','',0
        if rpm:assert '--noscripts' in args and '--nodeps' in args
        else:assert '--verify-format=rpm' in args
        assert args[-2]=='--'
        return '??5?????? c /etc/example\n','',1
    monkeypatch.setattr(bridge,'bounded',bounded)
    result=agent.security_inspect(['pkg:amd64' if not rpm else 'pkg:x86_64'],False)
    assert result['state']=='incomplete' and result['trust_basis']=='target_local_package_database'
    assert result['packages'][0]['findings'][0]['configuration_file']
    assert result['packages'][0]['gaps']==['Package identity changed during verification']
    assert len(calls)==3


def test_package_failure_is_not_no_differences(monkeypatch):
    monkeypatch.setattr(bridge,'bounded',lambda *a,**k:(_ for _ in ()).throw(RuntimeError('private diagnostic')))
    result=agent.security_inspect(['missing'],False)
    assert result['state']=='incomplete' and result['packages'][0]['state']=='incomplete'
    assert 'private diagnostic' not in json.dumps(result)


def test_runner_can_return_expected_difference_status_but_default_still_raises():
    args=[sys.executable,'-c','import sys;print("difference");sys.exit(1)']
    out,err,status=bridge.bounded(args,timeout=5,allowed_codes=(0,1),return_status=True)
    assert out.strip()=='difference' and status==1
    with pytest.raises(RuntimeError):bridge.bounded(args,timeout=5)
    with pytest.raises(RuntimeError):bridge.bounded([sys.executable,'-c','print("x"*10000)'],limit=100,timeout=5)


def test_persistence_is_metadata_only_and_never_follows_links(tmp_path,monkeypatch):
    root=tmp_path/'startup';root.mkdir();(root/'task').write_text('SECRET CONTENT')
    outside=tmp_path/'outside';outside.mkdir();(outside/'hidden').write_text('outside')
    (root/'enabled').symlink_to(outside,target_is_directory=True)
    os.mkfifo(root/'pipe')
    monkeypatch.setattr(agent,'PERSISTENCE_ROOTS',(str(root),str(tmp_path/'absent')))
    monkeypatch.setattr(agent,'PERSISTENCE_FILES',())
    result=agent.persistence_inventory(time.monotonic()+5)
    assert len(result['entries'])==2 and result['state']=='incomplete'
    assert 'SECRET CONTENT' not in json.dumps(result) and 'hidden' not in json.dumps(result)
    assert next(r for r in result['entries'] if r['kind']=='regular')['sha256']
    assert result['missing_roots']==[str(tmp_path/'absent')]


def test_persistence_parent_symlink_and_expired_budget(tmp_path,monkeypatch):
    real=tmp_path/'real';real.mkdir();(real/'nested').mkdir()
    (tmp_path/'alias').symlink_to(real,target_is_directory=True)
    monkeypatch.setattr(agent,'PERSISTENCE_ROOTS',(str(tmp_path/'alias'/'nested'),))
    monkeypatch.setattr(agent,'PERSISTENCE_FILES',())
    assert agent.persistence_inventory(time.monotonic()+5)['state']=='incomplete'
    monkeypatch.setattr(agent,'PERSISTENCE_ROOTS',(str(real),))
    result=agent.persistence_inventory(time.monotonic()-1)
    assert result['state']=='incomplete' and not result['entries']


def test_inspection_api_worker_history_scope_permissions(admin,monkeypatch):
    with Session() as s:
        for identifier in ('one','two'):s.add(Host(id=identifier,name=identifier,address='192.0.2.1',fingerprint='test'))
        s.commit()
    path='/api/hosts/one/security/inspections'
    assert admin.post(path,json={'packages':['--all']}).status_code==400
    assert admin.get('/api/hosts/missing/security/inspections').status_code==404
    queued=admin.post(path,json={'packages':['base-files'],'persistence':False});assert queued.status_code==200
    assert admin.post(path,json={'packages':[]}).status_code==409
    receipt={'version':1,'trust_basis':'target_local_package_database','state':'collected','packages':[],'persistence':None}
    def call(host,request,**kwargs):
        assert request=={'action':'security-inspect','packages':['base-files'],'persistence':False}
        return receipt
    monkeypatch.setattr(worker.ssh,'call',call)
    job_id=queued.json()['job_id'];worker.execute(job_id)
    with Session() as s:
        assert s.get(Job,job_id).state=='complete'
        assert s.get(incidents.Inspection,job_id).report==receipt
    assert admin.get(path).json()['items'][0]['id']==job_id
    assert admin.get('/api/hosts/two/security/inspections').json()['items']==[]
    for role in ('viewer','operator'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(path).status_code==403
        assert admin.post(path,json={'packages':[]}).status_code==403


def test_native_dpkg_read_only_inspection(tmp_path,monkeypatch):
    """Use an isolated database, not the runner's mutable/protected system files."""
    import hashlib
    import shutil
    if not shutil.which('dpkg-query') or not shutil.which('dpkg'):pytest.skip('dpkg unavailable')
    root=tmp_path/'root';db=root/'var/lib/dpkg';(db/'info').mkdir(parents=True)
    payload=root/'usr/share/patchy-fixture/value';payload.parent.mkdir(parents=True)
    payload.write_text('original\n')
    (db/'status').write_text('Package: patchy-fixture\nStatus: install ok installed\nArchitecture: all\nVersion: 1\nDescription: disposable verification fixture\nMaintainer: Test <test@example.invalid>\n\n')
    (db/'info/patchy-fixture.list').write_text('/usr/share/patchy-fixture/value\n')
    (db/'info/patchy-fixture.md5sums').write_text(hashlib.md5(payload.read_bytes()).hexdigest()+'  usr/share/patchy-fixture/value\n')
    original=bridge.bounded
    exists=Path.exists
    monkeypatch.setattr(Path,'exists',lambda p: True if str(p)=='/var/lib/dpkg/status' else exists(p))
    def isolated(args,**kwargs):
        option='--root='+str(root) if args[0]=='dpkg' else '--admindir='+str(db)
        return original([args[0],option,*args[1:]],**kwargs)
    monkeypatch.setattr(bridge,'bounded',isolated)
    result=agent.security_inspect(['patchy-fixture'],False)
    assert result['packages'][0]['state']=='no_reported_differences',result
    payload.write_text('changed\n')
    result=agent.security_inspect(['patchy-fixture'],False)
    assert result['packages'][0]['state']=='differences',result
    assert result['packages'][0]['findings'][0]['path']=='/usr/share/patchy-fixture/value'
    payload.unlink()
    result=agent.security_inspect(['patchy-fixture'],False)
    assert result['packages'][0]['findings'][0]['status']=='missing',result


def test_receipts_are_immutable_and_malformed_reports_rejected(admin):
    receipt={'version':1,'trust_basis':'target_local_package_database','state':'collected','packages':[],'persistence':None}
    with Session() as s:
        incidents.record_inspection(s,'one','receipt',receipt);s.commit()
        incidents.record_inspection(s,'one','receipt',{'invalid':'replacement'});s.commit()
        assert s.get(incidents.Inspection,'receipt').report==receipt
        with pytest.raises(ValueError):incidents.record_inspection(s,'one','bad',{**receipt,'packages':'invalid'})
        with pytest.raises(ValueError):incidents.record_inspection(s,'one','bad',{**receipt,'persistence':{'state':'collected','entries':[{}]*257}})
