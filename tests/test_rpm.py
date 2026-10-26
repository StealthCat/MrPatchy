import base64
import json
import sys
from types import SimpleNamespace

import pytest
from app import packages, worker
from app.db import Host, Job, Package, Session
from target import rpm_support as rpm, bridge


def inventory():
    return {'package_manager':'rpm','architecture':'x86_64','rpm_vars':{'releasever':'44','basearch':'x86_64'},
            'rpm_packages':[{'name':'Example_pkg','arch':'x86_64','evr':'1:2.0-3.fc44','held':False}],
            'os':'ID=fedora\nVERSION_ID=44\n','status':'fixture','files':{},'keys':{}}


def source(extra=''):
    return '[vendor]\nname=Vendor\nbaseurl=https://example.test/$releasever/$basearch\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/vendor.asc\n'+extra


def test_rpm_source_vars_disabled_and_unsigned_metadata_policy():
    rows=rpm.repositories({'/etc/yum.repos.d/vendor.repo':source()},inventory()['rpm_vars'])
    assert rows[0]['baseurl']==['https://example.test/44/x86_64']
    assert not rows[0]['repo_gpgcheck']
    assert rpm.repositories({'/etc/yum.repos.d/vendor.repo':source('enabled=0\nsslverify=0')},{})==[]
    for old,new in [('gpgcheck=1','gpgcheck=0'),('https://','http://'),('file:///etc/pki/rpm-gpg/vendor.asc','https://example.test/key.asc')]:
        with pytest.raises(ValueError):rpm.repositories({'/etc/yum.repos.d/vendor.repo':source().replace(old,new)},inventory()['rpm_vars'])
    with pytest.raises(ValueError):rpm.repositories({'/etc/yum.repos.d/vendor.repo':source('sslverify=0')},inventory()['rpm_vars'])
    with pytest.raises(ValueError):rpm.repositories({'/etc/yum.repos.d/vendor.repo':source('sslclientkey=/etc/secret.key')},inventory()['rpm_vars'])
    with pytest.raises(ValueError):rpm.repositories({'/etc/yum.repos.d/vendor.repo':source().replace('$releasever','$unknown')},inventory()['rpm_vars'])
    with pytest.raises(ValueError):rpm.repositories({'/etc/yum.repos.d/a.repo':source(),'/etc/yum.repos.d/b.repo':source()},inventory()['rpm_vars'])
    assert not rpm.source_path('/etc/yum.repos.d/../../sudoers')
    assert not rpm.key_path('/etc/pki/rpm-gpg/../private.key')


def test_rpm_api_repository_dispatch_and_release_guard(admin):
    host_id=admin.post('/api/hosts',json={'name':'Fedora','address':'192.0.2.11'}).json()['id']
    with Session() as s:
        s.get(Host,host_id).inventory=inventory();s.commit()
    assert admin.put(f'/api/hosts/{host_id}/repositories',json={'path':'/etc/apt/sources.list','content':''}).status_code==400
    r=admin.put(f'/api/hosts/{host_id}/repositories',json={'path':'/etc/yum.repos.d/vendor.repo','content':source()})
    assert r.status_code==200
    with Session() as s: assert s.get(Job,r.json()['job_id']).payload['path'].endswith('vendor.repo')
    assert admin.post(f'/api/hosts/{host_id}/releases').status_code==409
    assert admin.get('/api/hosts').json()[0]['package_manager']=='rpm'


def test_bridge_dispatch_avoids_apt_and_blocks_invalid_rpm_paths(monkeypatch):
    monkeypatch.setattr(bridge,'rpm_backend',lambda:True)
    calls=[]
    monkeypatch.setattr(bridge,'rpm_module',lambda:SimpleNamespace(patch=lambda specs:calls.append(specs) or {'output':'rpm'},source_path=rpm.source_path))
    assert bridge.handle({'action':'patch','packages':['Example_pkg:x86_64=1:2.0-3.fc44']})['output']=='rpm'
    assert calls==[['Example_pkg:x86_64=1:2.0-3.fc44']]
    with pytest.raises(ValueError):bridge.repo_path('/etc/apt/sources.list')
    assert str(bridge.repo_path('/etc/yum.repos.d/vendor.repo')).endswith('vendor.repo')


def test_rpm_worker_uses_native_epoch_comparison(admin,monkeypatch):
    inv=inventory();host_id=admin.post('/api/hosts',json={'name':'Fedora','address':'192.0.2.11'}).json()['id']
    inv['rpm_packages'][0]['evr']='2:1.0-1'
    monkeypatch.setattr(packages,'installed',lambda inv:[{'name':'Example_pkg:x86_64','installed':'2:1.0-1','held':False,'dpkg_state':'install ok installed'}])
    pairs=[]
    monkeypatch.setattr(packages,'newer_flags',lambda inv,value:pairs.extend(value) or [False])
    with Session() as s:
        h=s.get(Host,host_id);s.add(Package(id=host_id+':Example_pkg:x86_64',host_id=host_id,name='Example_pkg:x86_64',installed='1:9.0-1',candidate='1:10.0-1'));s.commit()
        worker.save_inventory(s,h,inv);s.commit()
        assert not s.get(Package,host_id+':Example_pkg:x86_64').candidate
    assert pairs==[('1:10.0-1','2:1.0-1')]


def test_rpm_transaction_rejects_unsafe_changes_and_untrusted_signatures(monkeypatch):
    # Exercise the actual adapter around a deterministic DNF transaction model.
    pkg=lambda name,version,arch='x86_64':SimpleNamespace(name=name,arch=arch,evr=version,repo=SimpleNamespace(priority=99,cost=1000),reponame='vendor')
    wanted=pkg('Example_pkg','2.0-2');old=pkg('Example_pkg','2.0-1');unrelated=pkg('other','1.0-1')
    class Query:
        def available(self):return self
        def filter(self,**kw):return [wanted]
    class Base:
        signature=0;remove=[old];installs=[wanted];completed=False
        def __init__(self):
            self.conf=SimpleNamespace(read=lambda:None);self.repos=SimpleNamespace(iter_enabled=lambda:[])
            self.sack=SimpleNamespace(query=Query);self.transaction=SimpleNamespace(install_set=self.installs,remove_set=self.remove)
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read_all_repos(self):pass
        def fill_sack(self):pass
        def package_upgrade(self,p):pass
        def resolve(self,allow_erasing):assert not allow_erasing
        def download_packages(self,p):pass
        def package_signature_check(self,p):return self.signature,'untrusted'
        def do_transaction(self):Base.completed=True
    monkeypatch.setitem(sys.modules,'dnf',SimpleNamespace(Base=Base))
    monkeypatch.setattr(rpm,'local_inventory',inventory)
    monkeypatch.setattr(rpm,'installed',lambda inv:[{'name':'Example_pkg:x86_64','installed':'2.0-1','held':False}])
    monkeypatch.setattr(rpm,'compare',lambda a,b:(a>b)-(a<b))
    assert rpm.patch(['Example_pkg:x86_64=2.0-2'])['output'].startswith('DNF completed')
    assert Base.completed
    for removes,signature in [([old,unrelated],0),([old],1),([old],2)]:
        Base.completed=False;Base.remove=removes;Base.signature=signature
        with pytest.raises(ValueError):rpm.patch(['Example_pkg:x86_64=2.0-2'])
        assert not Base.completed
    with pytest.raises(ValueError):rpm.patch(['Example_pkg:x86_64=2.0-2;id'])


def test_rpm_inherits_trust_and_rejects_global_transaction_overrides():
    files={'/etc/yum.repos.d/vendor.repo':source().replace('https://','http://'),
           '/etc/dnf/dnf.conf':'[main]\nrepo_gpgcheck=1\n'}
    assert rpm.repositories(files,inventory()['rpm_vars'])[0]['repo_gpgcheck']
    files['/etc/dnf/dnf.conf']='[main]\nrepo_gpgcheck=1\ntsflags=nodocs\n'
    assert rpm.repositories(files,inventory()['rpm_vars'])
    for option in ('reposdir=/tmp/repos','tsflags=nosignature'):
        files['/etc/dnf/dnf.conf']='[main]\n'+option+'\n'
        with pytest.raises(ValueError):rpm.repositories(files,inventory()['rpm_vars'])


def test_rpm_inventory_redacts_repository_credentials():
    text='[vendor]\npassword=secret-value\nproxy_password = proxy-secret\nbaseurl=https://user:secret@example.test/rpm\ngpgcheck=1\n'
    cleaned=rpm.redact_config(text)
    assert 'secret' not in cleaned and 'gpgcheck=1' in cleaned and cleaned.count('[redacted]')==3
    with pytest.raises(ValueError):rpm.repositories({'/etc/yum.repos.d/vendor.repo':cleaned},{})
    with pytest.raises(ValueError):rpm.validate_main({'files':{'/etc/dnf/dnf.conf':'[main]\nproxy_password=[redacted]'}})
