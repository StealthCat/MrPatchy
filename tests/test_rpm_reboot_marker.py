import pytest
from target import rpm_support

GOOD='0123abcd-0123-abcd-0123-0123456789ab'


def test_marker_records_validated_boot_id(tmp_path):
    boot=tmp_path/'boot_id';boot.write_text(GOOD+'\n');marker=tmp_path/'marker'
    rpm_support.write_reboot_marker(marker,boot)
    assert marker.read_text()==GOOD


@pytest.mark.parametrize('bad',['','not-a-boot-id\n','0123ABCD-0123-abcd-0123-0123456789ab','x'*500])
def test_marker_rejects_malformed_boot_id(tmp_path,bad):
    boot=tmp_path/'boot_id';boot.write_text(bad);marker=tmp_path/'marker'
    with pytest.raises(ValueError,match='Boot identity'):rpm_support.write_reboot_marker(marker,boot)
    assert not marker.exists()


def _transaction(monkeypatch,tmp_path,package,boot_text):
    """Drive the real patch() entry point around a deterministic DNF transaction model."""
    import sys
    from types import SimpleNamespace
    pkg=SimpleNamespace(name=package,arch='x86_64',evr='2.0-2',repo=SimpleNamespace(priority=99,cost=1000),reponame='vendor')
    events=[]
    class Query:
        def available(self):return self
        def filter(self,**kw):return [pkg]
    class Base:
        def __init__(self):
            self.conf=SimpleNamespace(read=lambda:None);self.repos=SimpleNamespace(iter_enabled=lambda:[])
            self.sack=SimpleNamespace(query=Query);self.transaction=SimpleNamespace(install_set=[pkg],remove_set=[])
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read_all_repos(self):pass
        def fill_sack(self):pass
        def package_upgrade(self,p):pass
        def resolve(self,allow_erasing):pass
        def download_packages(self,p):pass
        def package_signature_check(self,p):return 0,''
        def do_transaction(self):events.append('committed')
    monkeypatch.setitem(sys.modules,'dnf',SimpleNamespace(Base=Base))
    monkeypatch.setattr(rpm_support,'local_inventory',lambda:{'files':{},'rpm_vars':{}})
    monkeypatch.setattr(rpm_support,'repositories',lambda files,variables:[])
    monkeypatch.setattr(rpm_support,'validate_main',lambda inv:None)
    monkeypatch.setattr(rpm_support,'installed',lambda inv:[{'name':package+':x86_64','installed':'2.0-1','held':False}])
    monkeypatch.setattr(rpm_support,'compare',lambda a,b:(a>b)-(a<b))
    boot=tmp_path/'boot_id';boot.write_text(boot_text);marker=tmp_path/'marker'
    real_boot,real_write=rpm_support.validated_boot_id,rpm_support.write_reboot_marker
    monkeypatch.setattr(rpm_support,'validated_boot_id',lambda boot_path=None:events.append('boot') or real_boot(boot))
    monkeypatch.setattr(rpm_support,'write_reboot_marker',lambda value=None:real_write(marker,boot,value))
    return events,marker


def test_malformed_boot_id_refuses_reboot_patch_before_transaction(monkeypatch,tmp_path):
    events,marker=_transaction(monkeypatch,tmp_path,'kernel-core','not-a-boot-id\n')
    with pytest.raises(ValueError,match='Boot identity'):rpm_support.patch(['kernel-core:x86_64=2.0-2'])
    assert events==['boot'] and not marker.exists()


def test_reboot_patch_records_validated_marker_after_commit(monkeypatch,tmp_path):
    events,marker=_transaction(monkeypatch,tmp_path,'kernel-core',GOOD+'\n')
    result=rpm_support.patch(['kernel-core:x86_64=2.0-2'])
    assert result['reboot_required'] and events==['boot','committed'] and marker.read_text()==GOOD


def test_non_reboot_patch_does_not_depend_on_boot_identity(monkeypatch,tmp_path):
    events,marker=_transaction(monkeypatch,tmp_path,'Example_pkg','not-a-boot-id\n')
    result=rpm_support.patch(['Example_pkg:x86_64=2.0-2'])
    assert not result['reboot_required'] and events==['committed'] and not marker.exists()
