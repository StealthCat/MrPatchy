import pytest

from app import gpgv, vendor, yara_rules


def status(digest='8', fingerprint='A' * 40):
    return (f'[GNUPG:] VALIDSIG {fingerprint} 2026-11-01 0 0 4 0 1 '
            f'{digest} 00 {fingerprint}\n')


def test_valid_signers_requires_complete_strong_status_rows():
    first = 'A' * 40
    second = 'B' * 40
    assert gpgv.valid_signers(status('8', first) + status('11', second)) == [first, second]
    for invalid in ('', '\ufffd', '[GNUPG:] VALIDSIG incomplete\n', status('2'),
                    status('8') + status('3', second)):
        with pytest.raises(gpgv.GPGVError):
            gpgv.valid_signers(invalid)


def test_vendor_and_yara_use_the_same_verifier():
    assert vendor.verify_gpgv is gpgv.verify
    assert yara_rules.verify_gpgv is gpgv.verify


@pytest.mark.parametrize('error', [RuntimeError('diagnostic body'),
                                   TimeoutError('slow'), OSError('missing')])
def test_verify_normalizes_command_failures(monkeypatch, error):
    monkeypatch.setattr(gpgv, 'bounded', lambda *args, **kwargs: (_ for _ in ()).throw(error))
    with pytest.raises(gpgv.GPGVError, match='verification failed') as raised:
        gpgv.verify(['gpgv'])
    assert type(raised.value) is gpgv.GPGVError
    assert 'diagnostic body' not in str(raised.value)
    assert raised.value.__cause__ is None


def test_verify_returns_only_fingerprints_and_keeps_bounds(monkeypatch):
    captured = {}
    def run(args, **kwargs):
        captured.update(args=args, **kwargs)
        return status(), 'ignored diagnostics'
    monkeypatch.setattr(gpgv, 'bounded', run)
    assert gpgv.verify(['gpgv'], timeout=7, limit=1234) == ['A' * 40]
    assert captured == {'args': ['gpgv'], 'timeout': 7, 'limit': 1234}
