import copy
import hashlib

from app import firmware_artifact_trust as ft

D = hashlib.sha256(b'fw').hexdigest()
NOW = 1_000_000.0


def case():
    return (
        {'id': 'dev1'},
        {'id': 'r1', 'version': '1.2', 'compatible_device_ids': ['dev1']},
        {'id': 's1', 'kind': 'lvfs', 'trusted': True, 'trust_revision': 't1',
         'metadata_verified_at': NOW - 100},
        {'sha256': D, 'observed_sha256': D, 'complete': True, 'signature_verified': True},
    )


def test_good_artifact_is_installable_with_binding():
    r = ft.evaluate(*case(), None, NOW)
    assert r['state'] == 'installable'
    assert r['binding']['trust_revision'] == 't1' and len(r['binding']['binding_sha256']) == 64


def test_each_failure_is_not_installable():
    cases = {
        'artifact_incomplete': lambda c: c[3].update(complete=False),
        'signature_not_verified': lambda c: c[3].update(signature_verified=False),
        'digest_mismatch': lambda c: c[3].update(observed_sha256=hashlib.sha256(b'x').hexdigest()),
        'digest_not_computed': lambda c: c[3].pop('observed_sha256'),
        'device_incompatible': lambda c: c[1].update(compatible_device_ids=['other']),
        'source_not_trusted': lambda c: c[2].update(trusted=False),
        'testing_source_not_enabled': lambda c: c[2].update(testing=True),
        'metadata_stale': lambda c: c[2].update(metadata_verified_at=NOW - 30 * 86400),
        'metadata_unverified': lambda c: c[2].pop('metadata_verified_at'),
    }
    for reason, mutate in cases.items():
        c = case()
        mutate(c)
        r = ft.evaluate(*c, None, NOW)
        assert r['state'] == 'not_installable' and reason in r['reasons'], reason
        assert 'binding' not in r


def test_policy_blocks_and_allowlists():
    c = case()
    assert 'release_blocked' in ft.evaluate(*c, {'blocked_releases': ['r1']}, NOW)['reasons']
    assert 'checksum_not_approved' in ft.evaluate(*c, {'approved_checksums': ['0' * 64]}, NOW)['reasons']
    assert 'source_not_allowed' in ft.evaluate(*c, {'allowed_sources': ['other']}, NOW)['reasons']
    assert ft.evaluate(*c, {'approved_checksums': [D.upper()], 'allowed_sources': ['s1']}, NOW)['state'] == 'installable'


def test_future_dated_metadata_is_stale():
    c = case()
    c[2]['metadata_verified_at'] = NOW + 5
    assert 'metadata_stale' in ft.evaluate(*c, None, NOW)['reasons']


def test_recheck_detects_drift_and_never_mutates():
    c = case()
    bound = ft.evaluate(*c, None, NOW)['binding']
    before = copy.deepcopy(c)
    assert ft.recheck(bound, *c, None, NOW)['state'] == 'installable'
    assert c == before
    c[2]['trust_revision'] = 't2'
    r = ft.recheck(bound, *c, None, NOW)
    assert r == {'state': 'replan', 'reasons': ['trust_revision_changed']}
    c = case()
    assert ft.recheck(bound, *c, None, NOW + 30 * 86400)['state'] == 'replan'
