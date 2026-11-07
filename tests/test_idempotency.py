import pytest

from app import idempotency as idem


def test_keys_are_bounded_and_never_echoed():
    assert idem.valid_key('retry-0001.a:b') == 'retry-0001.a:b'
    for bad in ('short', 'x' * 129, 'has space 123', '-leading-dash', '', None, 12345678):
        with pytest.raises(ValueError) as raised:
            idem.valid_key(bad)
        assert str(bad) not in str(raised.value) or str(bad) == ''


def test_fingerprint_ignores_order_and_duplicates_but_binds_everything_else():
    base = idem.fingerprint('svc-1', ['b', 'a'], {'x': 1, 'y': [1, 2]}, 'patch')
    assert base == idem.fingerprint('svc-1', ['a', 'b', 'a'], {'y': [1, 2], 'x': 1}, 'patch')
    assert base != idem.fingerprint('svc-2', ['a', 'b'], {'x': 1, 'y': [1, 2]}, 'patch')
    assert base != idem.fingerprint('svc-1', ['a', 'b', 'c'], {'x': 1, 'y': [1, 2]}, 'patch')
    assert base != idem.fingerprint('svc-1', ['a', 'b'], {'x': 2, 'y': [1, 2]}, 'patch')
    assert base != idem.fingerprint('svc-1', ['a', 'b'], {'x': 1, 'y': [1, 2]}, 'reboot')


def test_invalid_inputs_are_rejected():
    for args in (('', [], {}), ('svc', 'abc', {}), ('svc', [], {'x': float('nan')}), ('svc', [], {'x': object()})):
        with pytest.raises(ValueError):
            idem.fingerprint(*args)


def test_decisions():
    fp = idem.fingerprint('svc', ['h1'], {'a': 1})
    assert idem.decide(None, fp) == (idem.NEW, None)
    assert idem.decide({'fingerprint': fp, 'complete': True, 'result': {'job': 7}}, fp) == (idem.REPLAY, {'job': 7})
    assert idem.decide({'fingerprint': fp}, fp) == (idem.IN_PROGRESS, None)
    other = idem.fingerprint('svc', ['h2'], {'a': 1})
    assert idem.decide({'fingerprint': fp, 'complete': True, 'result': {'job': 7}}, other) == (idem.CONFLICT, None)
