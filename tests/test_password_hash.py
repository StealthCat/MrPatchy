import hashlib

from app import security
from app.db import DATA, Session
from app.identity import User
from app.main import app, login_attempts
from app.security import derive_key, needs_rehash, password_hash, verify


def legacy_hash(password, salt='ab' * 16):
    return salt + ':' + hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def test_new_hashes_are_versioned_and_verify():
    value = password_hash('correct horse')
    assert value.startswith('scrypt$131072$8$1$')
    assert verify('correct horse', value) and not verify('wrong', value)
    assert not needs_rehash(value)


def test_legacy_hashes_verify_and_need_rehash():
    value = legacy_hash('old password')
    assert verify('old password', value) and not verify('nope', value)
    assert needs_rehash(value)


def test_tampered_or_malformed_hashes_fail_closed():
    value = password_hash('pw')
    assert not verify('pw', value[:-1] + ('0' if value[-1] != '0' else '1'))
    for bad in ('', 'garbage', 'scrypt$x$8$1$aa$bb', 'scrypt$131072$8$1$zz$bb'):
        assert not verify('pw', bad)
        assert not needs_rehash(bad)


def test_login_upgrades_legacy_hash(client):
    login_attempts.clear()
    with Session() as s:
        s.add(User(username='legacy', password=legacy_hash('legacy-pass'), role='admin')); s.commit()
    response = client.post('/api/login', json={'username': 'legacy', 'password': 'legacy-pass'})
    assert response.status_code == 200
    with Session() as s:
        stored = s.get(User, 'legacy').password
    assert stored.startswith('scrypt$131072$') and verify('legacy-pass', stored)
    login_attempts.clear()
    assert client.post('/api/login', json={'username': 'legacy', 'password': 'legacy-pass'}).status_code == 200


def test_failed_login_does_not_rehash(client):
    login_attempts.clear()
    old = legacy_hash('another-pass')
    with Session() as s:
        s.add(User(username='legacy2', password=old, role='admin')); s.commit()
    assert client.post('/api/login', json={'username': 'legacy2', 'password': 'bad'}).status_code == 401
    with Session() as s:
        assert s.get(User, 'legacy2').password == old


def test_fernet_is_cached_until_key_file_changes():
    first = security.cipher()
    assert security.cipher() is first
    path = DATA / 'secret.key'
    original = path.read_bytes()
    try:
        path.write_bytes(security.Fernet.generate_key())
        assert security.cipher() is not first
    finally:
        path.write_bytes(original)


def test_cookie_secret_is_derived_not_the_fernet_key():
    key = (DATA / 'secret.key').read_bytes()
    derived = derive_key('oidc-flow-cookie')
    assert len(derived) == 32 and derived != key
    assert derived != derive_key('other-purpose')
    assert hashlib.sha256(security.cipher()._signing_key).digest() != derived
    middleware = [m for m in app.user_middleware if m.cls.__name__ == 'SessionMiddleware'][0]
    assert middleware.kwargs['secret_key'] == derived.hex()
