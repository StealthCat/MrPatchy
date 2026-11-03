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


def test_kdf_concurrency_is_bounded(monkeypatch):
    import threading, time
    active = peak = 0
    lock = threading.Lock()
    real = hashlib.scrypt

    def slow(*a, **k):
        nonlocal active, peak
        with lock:
            active += 1; peak = max(peak, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return real(*a, **k)

    monkeypatch.setattr(security.hashlib, 'scrypt', slow)
    monkeypatch.setattr(security, '_KDF_SLOTS', threading.BoundedSemaphore(2))
    threads = [threading.Thread(target=password_hash, args=('pw',)) for _ in range(8)]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert peak <= 2


def test_concurrent_legacy_logins_both_succeed(client):
    import threading
    from app import main
    with Session() as s:
        s.add(User(username='racer', password=legacy_hash('pw-race'), role='admin', enabled=True)); s.commit()
    main.login_attempts.clear()
    barrier = threading.Barrier(2)
    real_verify = main.verify
    def sync_verify(*a):
        r = real_verify(*a)
        try: barrier.wait(2)
        except threading.BrokenBarrierError: pass
        return r
    main.verify = sync_verify
    codes = []
    def go():
        c = type(client)(app)
        codes.append(c.post('/api/login', json={'username': 'racer', 'password': 'pw-race', 'otp': ''}).status_code)
    try:
        ts = [threading.Thread(target=go) for _ in range(2)]
        [t.start() for t in ts]; [t.join() for t in ts]
    finally:
        main.verify = real_verify
    assert codes == [200, 200], codes
