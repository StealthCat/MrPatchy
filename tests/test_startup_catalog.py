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
                     'modprobe'):
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
    result = sc.coverage('debian', AGENT_SCOPE, ['/etc/rc.local'])
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
    assert result['additional'] == [] and result['gaps'] == []


def test_rpm_family_maps_spool_to_both_cron_and_at():
    mechanisms = by_id(sc.coverage('rpm', AGENT_SCOPE))
    assert mechanisms['cron_user']['state'] == 'covered' and mechanisms['at_queue']['state'] == 'not_collected'
    assert mechanisms['sysv']['state'] == 'partial'


def test_missing_root_is_never_reported_as_covered():
    result = by_id(sc.coverage('debian', ['/etc/udev/rules.d', '/run/udev/rules.d', '/usr/lib/udev/rules.d',
                                          '/lib/udev/rules.d'], ['/etc/udev/rules.d']))
    udev = result['udev_rules']
    assert udev['state'] == 'covered'
    assert {loc['path']: loc['state'] for loc in udev['locations']}['/etc/udev/rules.d'] == 'absent_reported'
    all_missing = sc.coverage('debian', ['/etc/ld.so.preload'], ['/etc/ld.so.preload'])
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
    complete = by_id(sc.coverage('debian', roots, homes_complete=True))['xdg_autostart']
    assert complete['state'] == 'covered'
    assert by_id(sc.coverage('debian', roots, homes_complete=True))['ssh_rc']['state'] == 'not_collected'


def test_additional_collected_roots_are_labeled_additional_only():
    result = sc.coverage('debian', ['/opt/app/hooks', '/etc/crontab', '/srv/gone'], ['/srv/gone'])
    assert result['additional'] == [{'path': '/opt/app/hooks', 'mechanism': 'additional', 'missing': False},
                                    {'path': '/srv/gone', 'mechanism': 'additional', 'missing': True}]
    assert by_id(result)['cron_system']['state'] == 'partial'


@pytest.mark.parametrize('collected,missing', [
    ('x', []), (['relative'], []), (['/etc/../root'], []), (['/a\x00b'], []), (['/a', '/a'], []),
    (['/a'], ['/b']), (['/a'] * (sc.MAX_ROOTS + 1), []), (['~/../x'], []),
])
def test_malformed_collection_fails_closed(collected, missing):
    result = sc.coverage('debian', collected, missing)
    assert result['mechanisms'] == [] and result['gaps'][0]['code'] == 'malformed_collection'


def test_homes_complete_must_be_boolean():
    assert sc.coverage('debian', ['/etc/crontab'], homes_complete='yes')['gaps'][0]['code'] == 'malformed_collection'


def test_additional_scope_validation_reasons():
    result = sc.validate_additional_scope(['/opt/app/hooks', 'relative', '/opt/app/hooks', '/opt/app/hooks/sub',
                                           '/proc/1', '/', '/etc/cron.d', '/etc/cron.d/x', '/etc', '/a\nb',
                                           '/usr/lib/systemd/system', '/srv/jobs'])
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
    assert sc.validate_additional_scope(['/x'], 'arch')['gaps'][0]['code'] == 'unknown_family'
    assert sc.validate_additional_scope('x')['gaps'][0]['code'] == 'malformed_scope'
    over = sc.validate_additional_scope([f'/opt/{i}' for i in range(sc.MAX_ADDITIONAL + 1)])
    assert over['accepted'] == [] and over['gaps'][0]['code'] == 'over_limit'
