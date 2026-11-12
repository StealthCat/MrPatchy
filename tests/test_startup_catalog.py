import pytest

from app import startup_catalog as sc

# The roots and files the current target agent inventories (target/agent.py).
AGENT_SCOPE = ['/etc/systemd/system', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly',
               '/etc/cron.monthly', '/var/spool/cron', '/etc/init.d', '/etc/profile.d', '/etc/crontab',
               '/etc/rc.local', '/etc/ld.so.preload']


def by_id(result):
    return {m['id']: m for m in result['mechanisms']}


def test_catalog_is_well_formed_and_documents_required_mechanisms():
    ids = [m['id'] for m in sc._MECHANISMS]
    assert len(ids) == len(set(ids))
    for required in ('cron_system', 'cron_runparts', 'cron_user', 'anacron', 'at_queue', 'systemd_system',
                     'systemd_generated', 'systemd_transient', 'systemd_user', 'sysv', 'rc_local', 'shell_system',
                     'shell_user', 'xdg_autostart', 'ssh_rc', 'udev_rules', 'loader_preload', 'modules_load',
                     'modprobe', 'systemd_generators', 'systemd_hooks', 'ssh_forced_command', 'login_hooks',
                     'event_hooks', 'package_manager_hooks'):
        assert required in ids
    for m in sc._MECHANISMS:
        assert m['trigger'] in sc.TRIGGERS and m['scope'] in sc.SCOPES and m['parse'] in sc.PARSE_LEVELS
        for loc in m['locations']:
            assert sc._absolute_ok(loc['path']) or sc._home_ok(loc['path'])
            assert loc['families'] and set(loc['families']) <= set(sc.FAMILIES)
        if any(loc['path'].startswith('~/') for loc in m['locations']):
            assert m['scope'] == 'per_user'


def test_only_implemented_parsers_claim_entries():
    assert {m['id'] for m in sc._MECHANISMS if m['parse'] == 'entries'} == {'cron_system', 'cron_user'}


def test_family_specific_locations():
    debian, rpm = by_id(sc.catalog('debian')), by_id(sc.catalog('rpm'))
    assert debian['cron_user']['locations'] == ['/var/spool/cron/crontabs']
    assert rpm['cron_user']['locations'] == ['/var/spool/cron']
    assert '/etc/bash.bashrc' in debian['shell_system']['locations']
    assert '/etc/bashrc' in rpm['shell_system']['locations'] and '/etc/bash.bashrc' not in rpm['shell_system']['locations']
    assert '/etc/rc.d/init.d' in rpm['sysv']['locations'] and '/etc/rc2.d' in debian['sysv']['locations']
    assert '/etc/modules' in debian['modules_load']['locations'] and '/etc/modules' not in rpm['modules_load']['locations']


@pytest.mark.parametrize('family', [None, 'arch', 'Debian', ['debian']])
def test_unknown_family_fails_closed(family):
    listing = sc.catalog(family)
    assert listing['mechanisms'] == [] and listing['gaps'][0]['code'] == 'unknown_family'
    result = sc.coverage(family, AGENT_SCOPE)
    assert result['mechanisms'] == [] and result['family'] is None and result['gaps'][0]['code'] == 'unknown_family'


def test_current_agent_scope_coverage_is_explicit():
    result = sc.coverage('debian', AGENT_SCOPE, ['/etc/rc.local'], complete=True, entries_reported=True)
    mechanisms = by_id(result)
    assert mechanisms['cron_system']['state'] == 'covered' and mechanisms['cron_system']['entries_parsed'] is True
    assert mechanisms['cron_runparts']['state'] == 'covered' and mechanisms['cron_runparts']['entries_parsed'] is False
    assert any(g['code'] == 'metadata_only' for g in mechanisms['cron_runparts']['gaps'])
    assert mechanisms['cron_user']['state'] == 'covered'
    # The spool root covers Debian's atjobs directory as metadata, never as parsed jobs.
    assert mechanisms['at_queue']['state'] == 'covered' and mechanisms['at_queue']['entries_parsed'] is False
    assert mechanisms['loader_preload']['state'] == 'covered'
    # Only one of rc.local's locations exists on Debian and it was reported missing.
    assert mechanisms['rc_local']['state'] == 'absent_reported'
    assert any(g['code'] == 'absence_is_not_safety' for g in mechanisms['rc_local']['gaps'])
    systemd = mechanisms['systemd_system']
    assert systemd['state'] == 'partial'
    uncollected = next(g for g in systemd['gaps'] if g['code'] == 'locations_not_collected')['paths']
    assert '/usr/lib/systemd/system' in uncollected and '/etc/systemd/system' not in uncollected
    for missing in ('anacron', 'udev_rules', 'modprobe', 'modules_load', 'xdg_autostart', 'systemd_transient'):
        assert mechanisms[missing]['state'] == 'not_collected' and mechanisms[missing]['entries_parsed'] is False
    assert result['additional'] == [] and [g['code'] for g in result['gaps']] == ['catalog_not_exhaustive']


def test_rpm_family_maps_spool_to_both_cron_and_at():
    mechanisms = by_id(sc.coverage('rpm', AGENT_SCOPE, complete=True))
    assert mechanisms['cron_user']['state'] == 'covered' and mechanisms['at_queue']['state'] == 'not_collected'
    assert mechanisms['sysv']['state'] == 'partial'


def test_missing_root_is_never_reported_as_covered():
    result = by_id(sc.coverage('debian', ['/etc/udev/rules.d', '/run/udev/rules.d', '/usr/lib/udev/rules.d',
                                          '/lib/udev/rules.d'], ['/etc/udev/rules.d'], complete=True))
    udev = result['udev_rules']
    assert udev['state'] == 'covered'
    assert {loc['path']: loc['state'] for loc in udev['locations']}['/etc/udev/rules.d'] == 'absent_reported'
    assert any(g['code'] == 'absence_is_not_safety' for g in udev['gaps'])
    all_missing = sc.coverage('debian', ['/etc/ld.so.preload'], ['/etc/ld.so.preload'], complete=True)
    assert by_id(all_missing)['loader_preload']['state'] == 'absent_reported'


def test_narrower_collected_root_is_partial_not_covered():
    result = by_id(sc.coverage('debian', ['/etc/systemd/system/ssh.service.d']))
    location = {loc['path']: loc['state'] for loc in result['systemd_system']['locations']}
    assert location['/etc/systemd/system'] == 'partial_subpath' and result['systemd_system']['state'] == 'partial'
    assert any(g['code'] == 'locations_partly_collected' for g in result['systemd_system']['gaps'])


def test_home_relative_locations_need_complete_home_enumeration():
    roots = ['/etc/xdg/autostart', '~/.config/autostart']
    partial = by_id(sc.coverage('debian', roots))['xdg_autostart']
    assert partial['state'] == 'partial'
    assert any(g['code'] == 'user_homes_incomplete' for g in partial['gaps'])
    complete = by_id(sc.coverage('debian', roots, complete=True, homes_complete=True))['xdg_autostart']
    assert complete['state'] == 'covered'
    assert by_id(sc.coverage('debian', roots, homes_complete=True))['ssh_rc']['state'] == 'not_collected'


def test_additional_collected_roots_are_labeled_additional_only():
    result = sc.coverage('debian', ['/opt/app/hooks', '/etc/crontab', '/srv/gone'], ['/srv/gone'])
    assert result['additional'] == [
        {'path': '/opt/app/hooks', 'mechanism': 'additional', 'missing': False, 'failed': False},
        {'path': '/srv/gone', 'mechanism': 'additional', 'missing': True, 'failed': False}]
    assert by_id(result)['cron_system']['state'] == 'partial'


@pytest.mark.parametrize('collected,missing', [
    ('x', []), (['relative'], []), (['/etc/../root'], []), (['/a\x00b'], []), (['/a', '/a'], []),
    (['/a'], ['/b']), (['/a'] * (sc.MAX_ROOTS + 1), []), (['~/../x'], []),
    (['/etc/cron.d', '/etc/cron.d/x'], ['/etc/cron.d']),
])
def test_malformed_collection_fails_closed(collected, missing):
    result = sc.coverage('debian', collected, missing)
    assert result['mechanisms'] == [] and result['gaps'][-1]['code'] == 'malformed_collection'


@pytest.mark.parametrize('flags', [{'homes_complete': 'yes'}, {'complete': 1}, {'entries_reported': None},
                                   {'failed_roots': ['/x']}, {'additional_roots': ['/x']}])
def test_flags_and_subsets_are_strict(flags):
    result = sc.coverage('debian', ['/etc/crontab'], **flags)
    assert result['mechanisms'] == [] and result['gaps'][-1]['code'] == 'malformed_collection'


def test_failed_root_is_never_collected():
    # RHEL /etc/init.d is a symlink the agent refuses to follow: in scope, but with a gap.
    result = sc.coverage('rpm', ['/etc/init.d', '/etc/rc.local'], failed_roots=['/etc/init.d'], complete=True)
    sysv = by_id(result)['sysv']
    assert {loc['path']: loc['state'] for loc in sysv['locations']}['/etc/init.d'] == 'collection_failed'
    assert sysv['state'] == 'partial' and any(g['code'] == 'collection_failed' for g in sysv['gaps'])
    budget = by_id(sc.coverage('debian', ['/etc/crontab', '/etc/cron.d'], failed_roots=['/etc/cron.d'],
                               complete=True, entries_reported=True))['cron_system']
    assert budget['state'] == 'partial' and budget['entries_parsed'] is True


def test_incomplete_collection_never_reports_covered():
    result = sc.coverage('debian', AGENT_SCOPE, entries_reported=True)
    assert all(m['state'] != 'covered' for m in result['mechanisms'])
    assert any(g['code'] == 'collection_incomplete' for g in result['gaps'])


@pytest.mark.parametrize('collected,missing,reported', [
    (['/etc/cron.d'], ['/etc/cron.d'], True),
    (['/etc/crontab'], ['/etc/crontab'], True),
    (['/etc/cron.d/one'], [], True),
    (['/etc/crontab', '/etc/cron.d'], [], False),
])
def test_entries_parsed_requires_a_fully_collected_reported_location(collected, missing, reported):
    cron = by_id(sc.coverage('debian', collected, missing, complete=True, entries_reported=reported))['cron_system']
    assert cron['entries_parsed'] is False and any(g['code'] == 'entries_not_parsed' for g in cron['gaps'])


def test_additional_roots_are_never_credited_to_a_mechanism():
    roots = ['/etc/systemd/system', '/etc/systemd/system.control', '/run/systemd/system',
             '/run/systemd/system.control', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system',
             '/lib/systemd/system']
    assert by_id(sc.coverage('debian', roots, complete=True))['systemd_system']['state'] == 'covered'
    admin = roots[1:]
    result = sc.coverage('debian', roots, additional_roots=admin, complete=True)
    assert by_id(result)['systemd_system']['state'] == 'partial'
    assert [a['path'] for a in result['additional']] == admin


def test_coverage_never_raises_on_odd_input():
    odd = [None, True, 1.5, float('nan'), {}, {'a': 1}, [[1]], [{1}], b'/etc', ['\ud800'], 'x' * 5000, [None]]
    for value in odd:
        for result in (sc.coverage(value, AGENT_SCOPE), sc.coverage('debian', value), sc.coverage('debian', [], value),
                       sc.coverage('debian', [], failed_roots=value), sc.coverage('debian', [], complete=value),
                       sc.validate_additional_scope(value), sc.validate_additional_scope(['/opt/x'], value)):
            assert isinstance(result, dict)


def test_additional_scope_validation_reasons():
    result = sc.validate_additional_scope(['/opt/app/hooks', 'relative', '/opt/app/hooks', '/opt/app/hooks/sub',
                                           '/proc/1', '/', '/etc/cron.d', '/etc/cron.d/x', '/etc', '/a\nb',
                                           '/usr/lib/systemd/system', '/srv/jobs'])
    assert len(result['rejected']) == 10
    assert result['accepted'] == [{'path': '/opt/app/hooks', 'mechanism': 'additional'},
                                  {'path': '/srv/jobs', 'mechanism': 'additional'}]
    assert [r['reason'] for r in result['rejected']] == [
        'invalid_path', 'duplicate', 'overlaps_additional', 'pseudo_or_root_filesystem', 'invalid_path',
        'overlaps_catalog_location', 'overlaps_catalog_location', 'overlaps_catalog_location', 'invalid_path',
        'overlaps_catalog_location']
    assert all('path' not in r for r in result['rejected'])  # rejected input is not echoed back


def test_additional_scope_respects_family_and_limits():
    assert sc.validate_additional_scope(['/etc/bashrc'], 'debian')['accepted'] == [
        {'path': '/etc/bashrc', 'mechanism': 'additional'}]
    assert sc.validate_additional_scope(['/etc/bashrc'], 'rpm')['rejected'][0]['reason'] == 'overlaps_catalog_location'
    unknown = sc.validate_additional_scope(['/x', '/etc/cron.d', '/etc/bashrc', '/etc/bash.bashrc'], 'arch')
    assert unknown['gaps'][0]['code'] == 'unknown_family' and unknown['accepted'] == [{'path': '/x', 'mechanism': 'additional'}]
    assert {r['reason'] for r in unknown['rejected']} == {'overlaps_catalog_location'}
    assert sc.validate_additional_scope('x')['gaps'][0]['code'] == 'malformed_scope'
    over = sc.validate_additional_scope([f'/opt/{i}' for i in range(sc.MAX_ADDITIONAL + 1)])
    assert over['accepted'] == [] and over['gaps'][0]['code'] == 'over_limit'


def test_additional_scope_mirrors_agent_exclusions_and_homes():
    result = sc.validate_additional_scope(['/run/user/1000', '/var/lib/mrpatchy-quarantine/x', '/var/lib', '/home',
                                           '/root', '/home/alice', '/home/alice/.ssh', '/root/.bashrc',
                                           '/home/alice/.config', '/home/alice/bin', '/root/tools'])
    assert [r['reason'] for r in result['rejected']] == [
        'pseudo_or_root_filesystem', 'excluded_state_directory', 'excluded_state_directory',
        'overlaps_catalog_location', 'overlaps_catalog_location', 'overlaps_catalog_location',
        'overlaps_catalog_location', 'overlaps_catalog_location', 'overlaps_catalog_location']
    assert [a['path'] for a in result['accepted']] == ['/home/alice/bin', '/root/tools']
    assert sc.MAX_ADDITIONAL == 16


def test_catalog_declares_it_is_not_exhaustive():
    assert sc.catalog('debian')['gaps'][0]['code'] == 'catalog_not_exhaustive'
    assert sc.coverage('rpm', ['/etc/crontab'])['gaps'][0]['code'] == 'catalog_not_exhaustive'


# Regressions for the #724 peer review (2026-11-12).
def _locs(mechanism):
    return {loc['path']: loc for loc in mechanism['locations']}


def test_usrmerge_alias_takes_the_canonical_state_only_for_the_exact_target():
    roots = ['/etc/systemd/system', '/etc/systemd/system.control', '/run/systemd/system',
             '/run/systemd/system.control', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system',
             '/lib/systemd/system']
    merged = by_id(sc.coverage('debian', roots, failed_roots=['/lib/systemd/system'], complete=True,
                               symlink_targets={'/lib/systemd/system': '/usr/lib/systemd/system'}))['systemd_system']
    assert merged['state'] == 'covered'
    assert _locs(merged)['/lib/systemd/system'] == {'path': '/lib/systemd/system', 'state': 'collected',
                                                    'alias_of': '/usr/lib/systemd/system'}
    # Without the reported link, or with any other target, the failure stands.
    for links in (None, {'/lib/systemd/system': '/tmp/evil'}, {'/lib/systemd/system': '/usr/lib/systemd'}):
        result = by_id(sc.coverage('debian', roots, failed_roots=['/lib/systemd/system'], complete=True,
                                   symlink_targets=links))['systemd_system']
        assert result['state'] == 'partial'
        assert _locs(result)['/lib/systemd/system']['state'] == 'collection_failed'
        assert 'alias_of' not in _locs(result)['/lib/systemd/system']


def test_alias_inherits_a_failed_or_missing_canonical_location():
    roots = ['/usr/lib/udev/rules.d', '/lib/udev/rules.d']
    links = {'/lib/udev/rules.d': '/usr/lib/udev/rules.d'}
    failed = by_id(sc.coverage('debian', roots, failed_roots=roots, complete=True, symlink_targets=links))
    assert _locs(failed['udev_rules'])['/lib/udev/rules.d']['state'] == 'collection_failed'
    missing = by_id(sc.coverage('debian', roots, missing_roots=['/usr/lib/udev/rules.d'],
                                failed_roots=['/lib/udev/rules.d'], complete=True, symlink_targets=links))
    assert _locs(missing['udev_rules'])['/lib/udev/rules.d']['state'] == 'absent_reported'


def test_rpm_init_d_and_rc_local_aliases():
    scope = ['/etc/init.d', '/etc/rc.d', '/etc/rc.local']
    links = {'/etc/init.d': '/etc/rc.d/init.d', '/etc/rc.local': '/etc/rc.d/rc.local'}
    result = by_id(sc.coverage('rpm', scope, failed_roots=['/etc/init.d', '/etc/rc.local'], complete=True,
                               symlink_targets=links))
    assert result['sysv']['state'] == 'covered' and result['rc_local']['state'] == 'covered'
    # A symlink at a non-alias location is never satisfied by its target.
    debian = by_id(sc.coverage('debian', ['/etc/init.d'], failed_roots=['/etc/init.d'], complete=True,
                               symlink_targets={'/etc/init.d': '/etc/rc.d/init.d'}))
    assert _locs(debian['sysv'])['/etc/init.d']['state'] == 'collection_failed'
    assert sc.catalog('rpm')['mechanisms'][[m['id'] for m in sc.catalog('rpm')['mechanisms']].index('sysv')][
        'aliases'] == {'/etc/init.d': '/etc/rc.d/init.d'}


@pytest.mark.parametrize('links', ['x', {'/etc/crontab': 'relative'}, {'/not-collected': '/etc'},
                                   {'/etc/crontab': None}])
def test_malformed_symlink_targets_fail_closed(links):
    result = sc.coverage('debian', ['/etc/crontab'], symlink_targets=links)
    assert result['mechanisms'] == [] and result['gaps'][-1]['code'] == 'malformed_collection'


def test_incomplete_collection_never_claims_parsed_entries():
    cron = by_id(sc.coverage('debian', ['/etc/crontab', '/etc/cron.d'], entries_reported=True))['cron_system']
    assert cron['entries_parsed'] is False and any(g['code'] == 'entries_not_parsed' for g in cron['gaps'])


def test_builtin_home_root_is_credited_consistently_with_scope_validation():
    assert sc.validate_additional_scope(['/home'])['rejected'][0]['reason'] == 'overlaps_catalog_location'
    result = sc.coverage('debian', ['/home', '/srv/app'], complete=True, homes_complete=True)
    assert [a['path'] for a in result['additional']] == ['/srv/app']
