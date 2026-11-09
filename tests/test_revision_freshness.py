import pytest

from app import revision_freshness as rf

NOW = 1_800_000_000.0


def check(cached=5, auth=5, confirmed=NOW - 5, now=NOW, **kw):
    return rf.check_freshness(cached, auth, confirmed, now, **kw)


def test_matching_recent_revision_is_fresh():
    r = check()
    assert r['verdict'] == rf.FRESH and r['usable'] is True
    assert r['age_seconds'] == 5


def test_behind_revision_is_stale():
    r = check(cached=4)
    assert r['verdict'] == rf.STALE_REVISION and not r['usable']


def test_old_confirmation_is_stale_even_when_revisions_match():
    r = check(confirmed=NOW - 31)
    assert r['verdict'] == rf.STALE_AGE and not r['usable']
    assert check(confirmed=NOW - 30)['verdict'] == rf.FRESH


def test_cached_ahead_of_authoritative_is_unknown():
    assert check(cached=6)['verdict'] == rf.UNKNOWN


@pytest.mark.parametrize('kw', [
    {'cached': None}, {'auth': None}, {'confirmed': None}, {'now': None},
    {'cached': -1}, {'cached': True}, {'cached': '5'}, {'auth': 5.0},
    {'confirmed': float('nan')}, {'confirmed': float('inf')},
    {'confirmed': NOW + 1}, {'max_age': 0}, {'max_age': -3},
    {'max_age': None}, {'max_age': True},
])
def test_unestablishable_freshness_never_fails_open(kw):
    r = check(**kw)
    assert r['verdict'] == rf.UNKNOWN and r['usable'] is False


def test_require_fresh_raises_unless_fresh():
    assert rf.require_fresh(1, 1, NOW, NOW)['usable'] is True
    for args in ((1, 2, NOW, NOW), (1, 1, NOW - 99, NOW), (None, 1, NOW, NOW)):
        with pytest.raises(ValueError):
            rf.require_fresh(*args)


def test_only_fresh_is_usable():
    assert {v for v in rf.VERDICTS if v == rf.FRESH} == {rf.FRESH}
    assert len(rf.VERDICTS) == 4
