import os

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import Audit, Session
from app.identity import User, new_secret
from app.main import app, login_attempts, login_throttle_logged
from app.security import seal

PASSWORD = os.environ['ADMIN_PASSWORD']


def entries(action):
    with Session() as s:
        return [row.detail for row in s.scalars(select(Audit).where(Audit.action == action).order_by(Audit.id))]


def test_wrong_password_is_audited_without_the_password(client):
    response = client.post('/api/login', json={'username': 'admin', 'password': 'definitely-wrong-guess'})
    assert response.status_code == 401
    [detail] = entries('login failed')
    assert detail.startswith('admin ') and 'bad password' in detail
    assert 'definitely-wrong-guess' not in detail
    assert entries('login') == []


def test_unknown_and_disabled_accounts_are_audited_with_an_identical_response(client):
    wrong = client.post('/api/login', json={'username': 'admin', 'password': 'bad'})
    unknown = client.post('/api/login', json={'username': 'nobody', 'password': 'bad'})
    with Session() as s:
        s.get(User, 'admin').enabled = False
        s.commit()
    disabled = client.post('/api/login', json={'username': 'admin', 'password': PASSWORD})
    assert (wrong.status_code, wrong.json()) == (unknown.status_code, unknown.json())  # no enumeration
    assert disabled.status_code == 401
    details = entries('login failed')
    assert len(details) == 3
    assert 'bad password' in details[0]
    assert details[1].startswith('nobody ') and 'unknown or disabled account' in details[1]
    assert details[2].startswith('admin ') and 'unknown or disabled account' in details[2]


def test_bad_mfa_code_is_audited_after_a_correct_password(client):
    with Session() as s:
        s.get(User, 'admin').otp_secret = seal(new_secret())
        s.commit()
    response = client.post('/api/login', json={'username': 'admin', 'password': PASSWORD, 'otp': '000000'})
    assert response.status_code == 401
    [detail] = entries('login failed')
    assert 'bad MFA code' in detail and PASSWORD not in detail


def test_successful_login_is_not_recorded_as_a_failure(client):
    assert client.post('/api/login', json={'password': PASSWORD}).status_code == 200
    assert entries('login failed') == [] and entries('login throttled') == []
    assert len(entries('login')) == 1


def test_lockout_is_audited_once_per_window_not_once_per_rejected_request(client):
    login_attempts.clear()
    for _ in range(10):
        assert client.post('/api/login', json={'username': 'admin', 'password': 'bad'}).status_code == 401
    for _ in range(5):
        assert client.post('/api/login', json={'username': 'admin', 'password': 'bad'}).status_code == 429
    assert len(entries('login failed')) == 10
    [detail] = entries('login throttled')
    assert detail.startswith('admin ') and 'account limit' in detail
    assert 'bad' not in detail  # no credential material


def test_address_limit_is_audited_once_even_across_many_usernames(client):
    login_attempts.clear()
    for n in range(50):
        assert client.post('/api/login', json={'username': 'user' + str(n), 'password': 'bad'}).status_code == 401
    for n in range(5):
        assert client.post('/api/login', json={'username': 'other' + str(n), 'password': 'bad'}).status_code == 429
    assert len(entries('login failed')) == 50
    [detail] = entries('login throttled')
    assert 'address limit' in detail


def test_address_limit_ignores_other_ipv6_addresses_that_share_a_text_prefix(client):
    import time
    login_attempts.clear()
    login_throttle_logged.clear()
    now = time.time()
    # '2001:db8::1:2:user0' starts with the text '2001:db8::1:' but belongs to another address.
    for n in range(50):
        login_attempts['2001:db8::1:2:user' + str(n)] = [now]
    neighbour = TestClient(app, client=('2001:db8::1', 50000))
    assert neighbour.post('/api/login', json={'password': PASSWORD}).status_code == 200
    assert entries('login throttled') == []


def test_ipv6_address_limit_still_applies_to_the_same_address(client):
    import time
    login_attempts.clear()
    login_throttle_logged.clear()
    now = time.time()
    for n in range(50):
        login_attempts['2001:db8::1:user' + str(n)] = [now]
    same = TestClient(app, client=('2001:db8::1', 50000))
    assert same.post('/api/login', json={'password': PASSWORD}).status_code == 429
    [detail] = entries('login throttled')
    assert 'address limit' in detail


def test_full_bucket_table_evicts_oldest_instead_of_locking_everyone_out(client):
    import time
    from app import main
    login_attempts.clear()
    now = time.time()
    for n in range(main.LOGIN_BUCKET_LIMIT):
        login_attempts['198.51.100.1:u' + str(n)] = [now - 200 + n * 0.001]
    assert client.post('/api/login', json={'username': 'admin', 'password': PASSWORD}).status_code == 200
    assert len(login_attempts) <= main.LOGIN_BUCKET_LIMIT
    assert '198.51.100.1:u0' not in login_attempts and '198.51.100.1:u1' in login_attempts


def test_missing_and_disabled_accounts_still_run_the_password_hash(client, monkeypatch):
    from app import main
    calls = []
    real = main.verify
    monkeypatch.setattr(main, 'verify', lambda password, value: calls.append(value) or real(password, value))
    login_attempts.clear()
    assert client.post('/api/login', json={'username': 'nobody', 'password': 'bad'}).status_code == 401
    assert calls == [main.DUMMY_PASSWORD_HASH]
    with Session() as s:
        s.get(User, 'admin').enabled = False
        s.commit()
    assert client.post('/api/login', json={'username': 'admin', 'password': PASSWORD}).status_code == 401
    assert calls == [main.DUMMY_PASSWORD_HASH] * 2


def test_password_hashing_does_not_hold_the_login_lock(client, monkeypatch):
    from app import main
    held = []
    real = main.verify
    monkeypatch.setattr(main, 'verify', lambda password, value: held.append(main.login_lock.locked()) or real(password, value))
    login_attempts.clear()
    assert client.post('/api/login', json={'username': 'admin', 'password': PASSWORD}).status_code == 200
    assert held == [False]


def test_failures_from_many_addresses_are_flagged_once_without_blocking(client):
    from fastapi.testclient import TestClient
    from app import main
    login_attempts.clear()
    main.login_account_failures.clear()
    main.login_throttle_logged.clear()
    for n in range(8):
        with TestClient(main.app, client=('203.0.113.' + str(n + 1), 5000)) as other:
            assert other.post('/api/login', json={'username': 'admin', 'password': 'bad'}).status_code == 401
    [detail] = entries('login suspicious')  # once per window, however many further addresses fail
    assert detail.startswith('admin ') and 'bad' not in detail
    # A legitimate sign-in from an address that did not fail is still accepted.
    with TestClient(main.app, client=('198.51.100.9', 5000)) as good:
        assert good.post('/api/login', json={'password': PASSWORD}).status_code == 200
    assert len(entries('login')) == 1


def test_failures_from_one_address_are_not_flagged_as_suspicious(client):
    from app import main
    login_attempts.clear()
    main.login_account_failures.clear()
    for _ in range(6):
        client.post('/api/login', json={'username': 'admin', 'password': 'bad'})
    assert entries('login suspicious') == []
