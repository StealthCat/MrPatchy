from types import SimpleNamespace

from app.identity import code, consume_otp, new_secret
from app.security import seal


def _user(secret):
    return SimpleNamespace(otp_secret=seal(secret), otp_pending='', otp_counter=-1)


def test_grouped_authenticator_code_is_accepted():
    secret = new_secret()
    counter = 1000
    value = code(secret, counter)
    assert consume_otp(_user(secret), value[:3] + ' ' + value[3:], now=counter * 30)
    assert consume_otp(_user(secret), ' ' + value + '\t', now=counter * 30)


def test_otp_still_rejects_wrong_length_and_non_digits():
    secret = new_secret()
    counter = 1000
    value = code(secret, counter)
    for bad in (value[:5], value + '1', value[:5] + 'x', '', '१२३४५६'):
        assert not consume_otp(_user(secret), bad, now=counter * 30)


def test_login_accepts_grouped_otp_length(client):
    r = client.post('/api/login', json={'username': 'admin', 'password': 'wrong', 'otp': '123 456'})
    assert r.status_code != 422
    r = client.post('/api/login', json={'username': 'admin', 'password': 'x', 'otp': '1' * 17})
    assert r.status_code == 422
