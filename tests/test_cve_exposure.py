"""CVE applicability and exposure-window contract (roadmap D, issue #672)."""
import shutil

import pytest

from app import cve_exposure as ce

ECO = 'Debian:12'
PKG = 'openssl'


def fake_compare(left, right):
    """Deterministic dotted-integer ordering standing in for dpkg."""
    def key(value):
        if not all(part.isdigit() for part in value.split('.')):
            raise ValueError('uncomparable test version')
        return [int(part) for part in value.split('.')]
    a, b = key(left), key(right)
    return (a > b) - (a < b)


def vuln(*entries, vid='DEBIAN-CVE-2026-0001', aliases=('CVE-2026-0001',)):
    return {'id': vid, 'aliases': list(aliases), 'affected': list(entries)}


def entry(*ranges, versions=None, ecosystem=ECO, name=PKG):
    item = {'package': {'ecosystem': ecosystem, 'name': name}}
    if ranges:
        item['ranges'] = list(ranges)
    if versions is not None:
        item['versions'] = versions
    return item


def eco(*events):
    return {'type': 'ECOSYSTEM', 'events': list(events)}


def classify(record, version):
    return ce.classify(record, ECO, PKG, version, compare=fake_compare)


def test_installed_version_inside_range_is_affected_with_next_fix():
    record = vuln(entry(eco({'introduced': '0'}, {'fixed': '3.2'})))
    result = classify(record, '3.1')
    assert result['status'] == ce.AFFECTED
    assert result['fixed_version'] == '3.2' and result['fix_available'] is True
    assert result['cve_ids'] == ['CVE-2026-0001'] and result['advisory_id'] == 'DEBIAN-CVE-2026-0001'


def test_installed_fix_and_later_versions_are_fixed():
    record = vuln(entry(eco({'introduced': '0'}, {'fixed': '3.2'})))
    for version in ('3.2', '3.10'):
        result = classify(record, version)
        assert result['status'] == ce.FIXED and result['fixed_version'] == '3.2'


def test_version_before_introduction_is_unaffected():
    record = vuln(entry(eco({'introduced': '2.0'}, {'fixed': '2.5'})))
    result = classify(record, '1.9')
    assert result['status'] == ce.UNAFFECTED and result['fixed_version'] is None


def test_unsorted_multi_interval_events_follow_version_order():
    record = vuln(entry(eco({'fixed': '4.3'}, {'introduced': '4.0'}, {'fixed': '2.5'}, {'introduced': '0'})))
    assert classify(record, '2.1')['status'] == ce.AFFECTED
    assert classify(record, '2.1')['fixed_version'] == '2.5'
    assert classify(record, '3.0')['status'] == ce.FIXED
    assert classify(record, '4.1')['fixed_version'] == '4.3'
    assert classify(record, '4.3')['status'] == ce.FIXED


def test_no_published_fix_is_affected_without_fix_available():
    record = vuln(entry(eco({'introduced': '0'})))
    result = classify(record, '9.9')
    assert result['status'] == ce.AFFECTED and result['fix_available'] is False
    assert 'no fixed version' in result['reason']


def test_last_affected_bound():
    record = vuln(entry(eco({'introduced': '1.0'}, {'last_affected': '1.4'})))
    assert classify(record, '1.4')['status'] == ce.AFFECTED
    assert classify(record, '1.5')['status'] == ce.UNAFFECTED


def test_explicit_versions_list_marks_affected():
    record = vuln(entry(versions=['3.0', '3.1']))
    assert classify(record, '3.1')['status'] == ce.AFFECTED
    assert classify(record, '3.2')['status'] == ce.UNAFFECTED


def test_other_distribution_or_package_entries_never_establish_applicability():
    record = vuln(
        entry(eco({'introduced': '0'}, {'fixed': '9.9'}), ecosystem='Debian:11'),
        entry(eco({'introduced': '0'}, {'fixed': '9.9'}), name='libssl3'),
        entry(eco({'introduced': '0'}, {'fixed': '9.9'}), ecosystem='PyPI'),
    )
    result = classify(record, '1.0')
    assert result['status'] == ce.UNCERTAIN
    assert 'no vendor data' in result['reason']


@pytest.mark.parametrize('ranges', [
    [{'type': 'GIT', 'events': [{'introduced': 'abc'}]}],
    [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '9.0'}]}],
    [eco({'introduced': '0'}, {'limit': '9.0'})],
    [eco({'fixed': '2.0'})],
    [eco({'introduced': '0', 'fixed': '2.0'})],
    [eco({'introduced': 3})],
    [eco()],
    [{'type': 'ECOSYSTEM', 'events': 'introduced 0'}],
    [eco({'introduced': '0'}, {'fixed': '0'})],
])
def test_unsupported_or_malformed_ranges_are_uncertain_not_unaffected(ranges):
    record = vuln(entry(*ranges))
    assert classify(record, '5.0')['status'] == ce.UNCERTAIN


def test_affected_range_wins_over_a_malformed_sibling_range():
    record = vuln(entry({'type': 'GIT', 'events': [{'introduced': 'abc'}]}, eco({'introduced': '0'}, {'fixed': '6.0'})))
    assert classify(record, '5.0')['status'] == ce.AFFECTED


def test_fixed_with_an_unevaluable_sibling_range_is_uncertain():
    record = vuln(entry({'type': 'GIT', 'events': [{'introduced': 'abc'}]}, eco({'introduced': '0'}, {'fixed': '4.0'})))
    assert classify(record, '5.0')['status'] == ce.UNCERTAIN


def test_comparator_failure_is_uncertain():
    record = vuln(entry(eco({'introduced': '0'}, {'fixed': '1.0'})))
    assert classify(record, '1.0~rc1')['status'] == ce.UNCERTAIN

    def broken(_left, _right):
        raise RuntimeError('dpkg missing')
    result = ce.classify(record, ECO, PKG, '0.5', compare=broken)
    assert result['status'] == ce.UNCERTAIN and 'comparison failed' in result['reason']


@pytest.mark.parametrize('installed', [None, '', 7])
def test_unknown_installed_version_is_uncertain(installed):
    record = vuln(entry(eco({'introduced': '0'}, {'fixed': '1.0'})))
    assert classify(record, installed)['status'] == ce.UNCERTAIN


@pytest.mark.parametrize('record', [None, [], {'id': 'X'}, {'id': 'X', 'affected': 'all'},
                                    {'id': 'X', 'affected': [entry()]}])
def test_malformed_advisories_are_uncertain(record):
    assert classify(record, '1.0')['status'] == ce.UNCERTAIN


def test_oversized_affected_list_is_uncertain():
    record = vuln(*[entry(eco({'introduced': '0'})) for _ in range(ce.MAX_AFFECTED_ENTRIES + 1)])
    assert classify(record, '1.0')['status'] == ce.UNCERTAIN


@pytest.mark.parametrize('value', ['0', '1.0', '2.5-1', '1:2.0', '3.0.11-1~deb12u2', '1.0~rc1', '2:1.2+dfsg-3.1',
                                   '1.0-2-3', '1:2:3', '9.9+git20240101'])
def test_valid_debian_version_syntax_is_accepted(value):
    assert ce.valid_debian_version(value)


@pytest.mark.parametrize('value', ['v2.0', 'abc', '', ' 1.0', '1.0 beta', '-1.0', '1.0-', ':1.0', 'a:1.0', '1:',
                                   '1.0-r_1', '1.0_1', None, 7, '1.0-1:2'])
def test_malformed_debian_version_syntax_is_rejected(value):
    assert not ce.valid_debian_version(value)


@pytest.mark.parametrize('events,installed', [
    ([{'introduced': 'v2.0'}, {'fixed': '3.0'}], '2.5-1'),   # dpkg would sort v2.0 above 2.5-1 -> unaffected
    ([{'introduced': '0'}, {'fixed': 'abc'}], '2.5-1'),      # dpkg would always call this affected
    ([{'introduced': '0'}, {'fixed': '3.0'}], 'v2.5'),       # malformed installed version
])
def test_native_comparator_reports_malformed_versions_as_uncertain(events, installed):
    record = vuln(entry(eco(*events)))
    result = ce.classify(record, ECO, PKG, installed)
    assert result['status'] == ce.UNCERTAIN and result['fixed_version'] is None


def test_native_compare_rejects_malformed_syntax_before_invoking_dpkg(monkeypatch):
    monkeypatch.setattr(ce, 'newer_flags', lambda pairs: pytest.fail('dpkg must not be consulted'))
    with pytest.raises(ValueError):
        ce.native_compare('v2.0', '2.5-1')


@pytest.mark.skipif(not shutil.which('dpkg'), reason='native dpkg ordering unavailable')
def test_native_debian_ordering_handles_epochs_tildes_and_backports():
    record = vuln(entry(eco({'introduced': '0'}, {'fixed': '3.0.11-1~deb12u2'})))
    assert ce.classify(record, ECO, PKG, '3.0.11-1~deb12u1')['status'] == ce.AFFECTED
    assert ce.classify(record, ECO, PKG, '3.0.11-1~deb12u2')['status'] == ce.FIXED
    assert ce.classify(record, ECO, PKG, '3.0.11-1')['status'] == ce.FIXED
    epoch = vuln(entry(eco({'introduced': '0'}, {'fixed': '1:1.0'})))
    assert ce.classify(epoch, ECO, PKG, '9.9')['status'] == ce.AFFECTED


# --- exposure window ---------------------------------------------------------

def test_without_applicability_the_window_is_not_applicable():
    result = ce.exposure_window(100, [{'kind': 'fix_installed', 'at': 150, 'verified': True}], now=200)
    assert result['state'] == ce.NOT_APPLICABLE and result['duration_seconds'] is None


def test_window_stays_open_with_no_fix_and_reports_duration():
    result = ce.exposure_window(100, [{'kind': 'applicable', 'at': 120}], now=500, monitoring_started_at=50)
    assert result['state'] == ce.OPEN and result['duration_seconds'] == 380
    assert result['start_basis'] == 'first_observed'
    assert result['intervals'] == [{'start': 120, 'end': None, 'state': ce.OPEN,
                                    'fix_installed_at': None, 'effective_at': None, 'closed_at': None}]
    assert result['gaps'] == [] and result['monitoring_complete'] is True


def test_verified_install_without_required_activation_closes():
    events = [{'kind': 'applicable', 'at': 120}, {'kind': 'fix_available', 'at': 200},
              {'kind': 'fix_installed', 'at': 300, 'verified': True}]
    result = ce.exposure_window(100, events, now=900, monitoring_started_at=0)
    assert result['state'] == ce.CLOSED
    assert (result['fix_available_at'], result['fix_installed_at'], result['closed_at']) == (200, 300, 300)
    assert result['duration_seconds'] == 180


def test_required_restart_keeps_window_pending_until_activation():
    events = [{'kind': 'applicable', 'at': 120},
              {'kind': 'fix_installed', 'at': 300, 'verified': True, 'activation_required': True}]
    pending = ce.exposure_window(100, events, now=900, monitoring_started_at=0)
    assert pending['state'] == ce.PENDING_ACTIVATION and pending['closed_at'] is None
    assert pending['duration_seconds'] == 780
    closed = ce.exposure_window(100, events + [{'kind': 'activated', 'at': 400}], now=900, monitoring_started_at=0)
    assert closed['state'] == ce.CLOSED and closed['effective_at'] == 400 and closed['fix_installed_at'] == 300


@pytest.mark.parametrize('install', [
    {'kind': 'fix_installed', 'at': 300},
    {'kind': 'fix_installed', 'at': 300, 'verified': 'yes'},
    {'kind': 'install_failed', 'at': 300},
])
def test_failed_partial_or_unverified_installs_do_not_close(install):
    result = ce.exposure_window(100, [{'kind': 'applicable', 'at': 120}, install], now=900, monitoring_started_at=0)
    assert result['state'] == ce.OPEN and result['closed_at'] is None and result['notes']


def test_activation_before_install_does_not_close():
    events = [{'kind': 'applicable', 'at': 120}, {'kind': 'activated', 'at': 200}]
    assert ce.exposure_window(100, events, now=900)['state'] == ce.OPEN


def test_rollback_reopens_a_closed_window():
    events = [{'kind': 'applicable', 'at': 120}, {'kind': 'fix_installed', 'at': 300, 'verified': True},
              {'kind': 'reintroduced', 'at': 600}]
    result = ce.exposure_window(100, events, now=900, monitoring_started_at=0)
    assert result['state'] == ce.OPEN and result['reopened'] == 1
    # The verified-fixed period 300-600 is not exposure; the first closure is retained.
    assert result['closed_at'] is None and result['duration_seconds'] == 180 + 300
    assert [(w['start'], w['end'], w['closed_at']) for w in result['intervals']] == [(120, 300, 300), (600, None, None)]
    again = ce.exposure_window(100, events + [{'kind': 'fix_installed', 'at': 700, 'verified': True}],
                               now=900, monitoring_started_at=0)
    assert again['state'] == ce.CLOSED and again['closed_at'] == 700 and again['reopened'] == 1
    assert again['duration_seconds'] == 180 + 100


def test_events_are_applied_in_time_order():
    events = [{'kind': 'fix_installed', 'at': 300, 'verified': True}, {'kind': 'applicable', 'at': 120}]
    assert ce.exposure_window(100, events, now=900)['state'] == ce.CLOSED


def test_late_enrollment_missing_monitoring_and_offline_gaps_are_disclosed():
    events = [{'kind': 'applicable', 'at': 400}]
    late = ce.exposure_window(100, events, now=1000, monitoring_started_at=350,
                              offline_periods=[(50, 120), (500, 600), (2000, 3000)])
    assert late['gaps'] == [
        {'kind': 'offline', 'start': 100, 'end': 120},
        {'kind': 'late_enrollment', 'start': 100, 'end': 350},
        {'kind': 'offline', 'start': 500, 'end': 600},
    ]
    assert late['monitoring_complete'] is False
    none = ce.exposure_window(100, events, now=1000)
    assert none['gaps'] == [{'kind': 'no_monitoring', 'start': 100, 'end': 1000}]


def test_applicability_recorded_before_publication_is_noted():
    result = ce.exposure_window(100, [{'kind': 'applicable', 'at': 50}], now=200, monitoring_started_at=0)
    assert result['state'] == ce.OPEN and result['duration_seconds'] == 100 and result['notes']


@pytest.mark.parametrize('kwargs', [
    {'published_at': 300, 'events': [], 'now': 200},
    {'published_at': 100, 'events': [{'kind': 'applicable', 'at': 300}], 'now': 200},
    {'published_at': 100, 'events': [{'kind': 'exploited', 'at': 150}], 'now': 200},
    {'published_at': float('nan'), 'events': [], 'now': 200},
    {'published_at': True, 'events': [], 'now': 200},
    {'published_at': 100, 'events': 'applicable', 'now': 200},
    {'published_at': 100, 'events': [{'kind': 'applicable', 'at': 150}], 'now': 200, 'offline_periods': [(190, 180)]},
    {'published_at': 100, 'events': [{'kind': 'applicable', 'at': 150}], 'now': 200, 'monitoring_started_at': -1},
])
def test_clock_order_and_malformed_inputs_are_rejected(kwargs):
    with pytest.raises(ValueError):
        ce.exposure_window(**kwargs)


# --- review regressions on 874813e (PR #673) ----------------------------------

def test_overlapping_ranges_report_only_a_fix_that_clears_every_range():
    record = vuln(entry(eco({'introduced': '1'}, {'fixed': '3'}), eco({'introduced': '2'}, {'fixed': '5'})))
    result = classify(record, '2')
    assert result['status'] == ce.AFFECTED
    assert result['fixed_version'] == '5' and result['fix_available'] is True
    assert classify(record, '3')['status'] == ce.AFFECTED
    assert classify(record, '5')['status'] == ce.FIXED


def test_overlapping_ranges_across_entries_and_explicit_versions():
    record = vuln(entry(eco({'introduced': '1'}, {'fixed': '3'})), entry(versions=['3']))
    result = classify(record, '2')
    assert result['status'] == ce.AFFECTED and result['fixed_version'] is None
    assert result['fix_available'] is False and 'clears every' in result['reason']


def test_fix_inside_an_otherwise_unaffected_sibling_range_is_not_reported():
    record = vuln(entry(eco({'introduced': '1'}, {'fixed': '3'}), eco({'introduced': '3'}, {'fixed': '4'})))
    result = classify(record, '2')
    assert result['status'] == ce.AFFECTED and result['fixed_version'] == '4'


def test_malformed_aliases_do_not_raise():
    result = classify({'id': 'X', 'aliases': 42, 'affected': []}, '1')
    assert result['status'] == ce.UNCERTAIN and result['cve_ids'] == []
    ok = classify({'id': 'CVE-2026-1', 'aliases': 'CVE-2026-2', 'affected': [entry(eco({'introduced': '0'}))]}, '1')
    assert ok['status'] == ce.AFFECTED and ok['cve_ids'] == ['CVE-2026-1']


@pytest.mark.parametrize('versions', [[42], ['1.5', None], [''], [['1']]])
def test_non_string_explicit_versions_are_uncertain(versions):
    assert classify(vuln(entry(versions=versions)), '1')['status'] == ce.UNCERTAIN


def test_non_string_explicit_versions_do_not_hide_a_matching_range():
    record = vuln(entry(eco({'introduced': '0'}, {'fixed': '2'}), versions=[42]))
    assert classify(record, '1')['status'] == ce.AFFECTED


def test_fully_monitored_late_applicability_starts_at_first_observation():
    result = ce.exposure_window(100, [{'kind': 'applicable', 'at': 800}], now=900, monitoring_started_at=0)
    assert result['state'] == ce.OPEN and result['start_basis'] == 'first_observed'
    assert result['duration_seconds'] == 100 and result['monitoring_complete'] is True and result['notes'] == []


@pytest.mark.parametrize('kwargs,gaps', [
    ({}, [{'kind': 'no_monitoring', 'start': 100, 'end': 900}]),
    ({'monitoring_started_at': 300}, [{'kind': 'late_enrollment', 'start': 100, 'end': 300}]),
    ({'monitoring_started_at': 0, 'offline_periods': [(400, 500)]}, [{'kind': 'offline', 'start': 400, 'end': 500}]),
])
def test_unmonitored_interval_before_observation_starts_at_publication(kwargs, gaps):
    result = ce.exposure_window(100, [{'kind': 'applicable', 'at': 800}], now=900, **kwargs)
    assert result['start_basis'] == 'publication' and result['duration_seconds'] == 800
    assert result['gaps'] == gaps and result['monitoring_complete'] is False and result['notes']


def test_gaps_inside_a_verified_fixed_interval_are_not_exposure_gaps():
    events = [{'kind': 'applicable', 'at': 120}, {'kind': 'fix_installed', 'at': 300, 'verified': True},
              {'kind': 'reintroduced', 'at': 600}, {'kind': 'fix_installed', 'at': 700, 'verified': True}]
    result = ce.exposure_window(100, events, now=900, monitoring_started_at=0, offline_periods=[(400, 500)])
    assert result['state'] == ce.CLOSED and result['duration_seconds'] == 280
    assert result['gaps'] == [] and result['monitoring_complete'] is True
    assert [w['closed_at'] for w in result['intervals']] == [300, 700]
    overlapping = ce.exposure_window(100, events, now=900, monitoring_started_at=0, offline_periods=[(550, 650)])
    assert overlapping['gaps'] == [{'kind': 'offline', 'start': 600, 'end': 650}]


def test_applicable_after_closure_reopens_conservatively():
    events = [{'kind': 'applicable', 'at': 120}, {'kind': 'fix_installed', 'at': 300, 'verified': True},
              {'kind': 'applicable', 'at': 600}]
    result = ce.exposure_window(100, events, now=900, monitoring_started_at=0)
    assert result['state'] == ce.OPEN and result['reopened'] == 1
    assert result['duration_seconds'] == 180 + 300 and result['applicable_at'] == 120


def test_reintroduced_while_pending_activation_keeps_one_interval_open():
    events = [{'kind': 'applicable', 'at': 120},
              {'kind': 'fix_installed', 'at': 300, 'verified': True, 'activation_required': True},
              {'kind': 'reintroduced', 'at': 400}, {'kind': 'activated', 'at': 500}]
    result = ce.exposure_window(100, events, now=900, monitoring_started_at=0)
    assert result['state'] == ce.OPEN and result['reopened'] == 0
    assert len(result['intervals']) == 1 and result['duration_seconds'] == 780
