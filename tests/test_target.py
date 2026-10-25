import importlib.util
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'target'/(name+'.py')); mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

def test_bridge_rejects_shell_in_package():
    bridge=module('bridge')
    with pytest.raises(ValueError): bridge.handle({'action':'patch','packages':['bash=1;id']})
    with pytest.raises(ValueError): bridge.handle({'action':'shell','command':'id'})
    with pytest.raises(ValueError): bridge.repo_path('/etc/apt/sources.list.d/../../sudoers.sources')

def test_deploy_digest_checked_before_write():
    bridge=module('bridge')
    with pytest.raises(ValueError): bridge.handle({'action':'deploy','agent':'cHJpbnQoMSk=','sha256':'bad'})

def test_proc_network_address_parsing():
    agent=module('agent')
    assert agent.address('0100007F:0016',False)==('127.0.0.1',22)
    assert agent.address('00000000000000000000000001000000:01BB',True)==('::1',443)

def test_symlink_destination_rejected(tmp_path):
    bridge=module('bridge');target=tmp_path/'target';target.write_text('original');link=tmp_path/'link';link.symlink_to(target)
    with pytest.raises(ValueError): bridge.atomic(link,b'bad')
    assert target.read_text()=='original'
