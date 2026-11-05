import base64
import os
import stat
from target import bridge


def upload(monkeypatch,tmp_path,existing_mode=None):
    keyrings=tmp_path/'etc'/'apt'/'keyrings'
    keyrings.parent.mkdir(parents=True)
    if existing_mode is not None:
        keyrings.mkdir(mode=existing_mode);keyrings.chmod(existing_mode)
    monkeypatch.setattr(bridge,'APT_KEYRINGS',keyrings)
    monkeypatch.setattr(bridge,'rpm_backend',lambda:False)
    old=os.umask(0o077)
    try:
        result=bridge.handle({'action':'key','name':'vendor.gpg','data':base64.b64encode(b'key').decode()})
    finally:os.umask(old)
    return keyrings,result


def test_missing_keyring_directory_is_traversable_under_bridge_umask(monkeypatch,tmp_path):
    keyrings,result=upload(monkeypatch,tmp_path)
    assert result=={'saved':str(keyrings/'vendor.gpg')}
    assert stat.S_IMODE(keyrings.stat().st_mode)==0o755
    assert stat.S_IMODE((keyrings/'vendor.gpg').stat().st_mode)==0o644


def test_existing_0700_keyring_directory_from_older_bridge_is_repaired(monkeypatch,tmp_path):
    keyrings,_=upload(monkeypatch,tmp_path,0o700)
    assert stat.S_IMODE(keyrings.stat().st_mode)==0o755
