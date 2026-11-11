import os
import stat
import time
import pytest
from sqlalchemy.engine import make_url
from app import apt
from test_recovery_ssh import recovery_module

SOURCE='deb [signed-by=/usr/share/keyrings/test.gpg] https://example.org/debian stable main\n'


@pytest.fixture
def permissive_umask():
    previous=os.umask(0)
    try:yield
    finally:os.umask(previous)


def inventory():
    return {'architecture':'amd64','foreign_architectures':[],'machine_id':'a'*32,'collected':time.time(),'status':'',
            'files':{'/etc/apt/sources.list':SOURCE},'keys':{'/usr/share/keyrings/test.gpg':''}}


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_apt_auth_file_is_private_from_creation_and_replaces_symlinks(tmp_path,monkeypatch,permissive_umask):
    monkeypatch.setattr(apt,'DATA',tmp_path)
    created=[]
    real_open=os.open
    def observed_open(path,flags,*args,**kwargs):
        if str(path).endswith('auth.conf'):created.append((flags,args[0] if args else kwargs.get('mode')))
        return real_open(path,flags,*args,**kwargs)
    monkeypatch.setattr(apt.os,'open',observed_open)
    access={'credentials':[{'machine':'https://example.org/debian','login':'user','password':'secret-one'}]}
    root,_=apt.prepare('host',inventory(),access)
    auth=root/'etc/apt/auth.conf'
    assert created and all(flags&os.O_EXCL and flags&os.O_NOFOLLOW and created_mode==0o600 for flags,created_mode in created)
    assert mode(auth)==0o600 and 'password secret-one' in auth.read_text()
    outside=tmp_path/'outside';outside.write_text('untouched');outside.chmod(0o644)
    auth.unlink();auth.symlink_to(outside)
    access['credentials'][0]['password']='secret-two'
    apt.prepare('host',inventory(),access)
    assert not auth.is_symlink() and mode(auth)==0o600 and 'password secret-two' in auth.read_text()
    assert outside.read_text()=='untouched'


def test_mysql_option_file_is_private_from_creation(tmp_path,permissive_umask):
    recovery=recovery_module()
    path=recovery.mysql_options(make_url('mysql+pymysql://app:p%40ss@localhost/mrpatchy'),tmp_path)
    assert mode(path)==0o600 and 'password="p@ss"' in path.read_text()
    outside=tmp_path/'outside';outside.write_text('untouched')
    path.unlink();path.symlink_to(outside)
    recovery.mysql_options(make_url('mysql+pymysql://app:other@localhost/mrpatchy'),tmp_path)
    assert not path.is_symlink() and mode(path)==0o600 and 'password="other"' in path.read_text()
    assert outside.read_text()=='untouched'


def test_remote_mysql_without_ca_leaves_no_credential_file(tmp_path,monkeypatch):
    monkeypatch.delenv('MYSQL_SSL_CA',raising=False)
    recovery=recovery_module()
    with pytest.raises(ValueError,match='MYSQL_SSL_CA'):
        recovery.mysql_options(make_url('mysql+pymysql://app:secret@db.example.org/mrpatchy'),tmp_path)
    assert not (tmp_path/'mysql.cnf').exists()
    monkeypatch.setenv('MYSQL_SSL_CA','/etc/ssl/db-ca.pem')
    text=recovery.mysql_options(make_url('mysql+pymysql://app:secret@db.example.org/mrpatchy'),tmp_path).read_text()
    assert text.endswith('ssl-ca="/etc/ssl/db-ca.pem"\nssl-verify-server-cert=1\n') and 'password="secret"' in text
