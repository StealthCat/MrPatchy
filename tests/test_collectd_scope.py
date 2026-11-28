"""collectd configuration joins built-in startup scope without invalidating baselines (#1551)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

DEBIAN = '/etc/collectd'
RPM_CONF = '/etc/collectd.conf'
RPM_D = '/etc/collectd.d'
NEW = (DEBIAN, RPM_CONF, RPM_D)
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/hosts.allow', '/etc/hosts.deny',
           '/etc/rsnapshot.conf', '/etc/gitconfig', '/etc/kdump.conf', '/etc/auto.master',
           '/etc/request-key.d', '/etc/request-key.conf', '/etc/clamav', '/etc/clamd.d', '/etc/freshclam.conf',
           '/etc/dovecot', '/etc/postgresql')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    after = copy.deepcopy(before)
    after['scope'] += list(NEW)
    if present:
        after['entries'] += [entry(DEBIAN + '/collectd.conf', 'c'), entry(DEBIAN + '/collectd.conf.d/exec.conf', 'e')]
        after['missing_roots'] += [RPM_CONF, RPM_D]
    else:
        after['missing_roots'] += list(NEW)
    return after


def test_agent_built_in_scope_includes_both_layouts():
    assert DEBIAN in agent.PERSISTENCE_ROOTS and RPM_D in agent.PERSISTENCE_ROOTS and RPM_CONF in agent.PERSISTENCE_FILES
    assert RPM_CONF in agent.PROMOTED_PERSISTENCE_FILES
    assert DEBIAN in agent.PROMOTED_PERSISTENCE_ROOTS and RPM_D in agent.PROMOTED_PERSISTENCE_ROOTS
    assert set(NEW) <= set(agent.validate_custom_paths([]))
    assert set(NEW) <= set(persistence.ADDITIVE_BUILTIN_SCOPE)


def test_agent_hashes_collectd_files_without_running_their_programs(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    debian = tmp_path / 'collectd'
    (debian / 'collectd.conf.d').mkdir(parents=True)
    (debian / 'collectd.conf').write_text(
        'LoadPlugin exec\n<Include "/etc/collectd/collectd.conf.d">\n  Filter "*.conf"\n</Include>\n'
        '<Plugin network>\n  <Server "192.0.2.9">\n    Password "c2VjcmV0"\n  </Server>\n</Plugin>\n')
    (debian / 'collectd.conf.d' / 'exec.conf').write_text(
        f'<Plugin exec>\n  Exec "nobody" "/usr/bin/touch" "{marker}"\n'
        f'  NotificationExec "nobody" "/usr/bin/touch" "{marker}"\n</Plugin>\n')
    (debian / 'thresholds.conf').write_text('<Threshold>\n</Threshold>\n')
    rpm_d = tmp_path / 'collectd.d'
    rpm_d.mkdir()
    (rpm_d / 'exec.conf').write_text(f'<Plugin exec>\n  Exec "collectd" "/usr/bin/touch" "{marker}"\n</Plugin>\n')
    (rpm_d / 'alias.conf').symlink_to(rpm_d / 'exec.conf')
    rpm_conf = tmp_path / 'collectd.conf'
    rpm_conf.write_text('LoadPlugin exec\nInclude "/etc/collectd.d"\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(debian), str(rpm_d), str(tmp_path / 'absent.d')))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(rpm_conf), str(tmp_path / 'absent.conf')))
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected'
    assert set(rows) == {str(debian / 'collectd.conf'), str(debian / 'collectd.conf.d' / 'exec.conf'),
                         str(debian / 'thresholds.conf'), str(rpm_d / 'exec.conf'), str(rpm_d / 'alias.conf'),
                         str(rpm_conf)}
    assert rows[str(rpm_d / 'alias.conf')]['kind'] == 'symlink'
    assert all(rows[p]['sha256'] for p in rows if rows[p]['kind'] == 'regular')
    assert result['missing_roots'] == [str(tmp_path / 'absent.d'), str(tmp_path / 'absent.conf')]
    assert not marker.exists()
    # Hashing only: no parsed detail or file content (such as the network plugin password) is attached.
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    assert 'c2VjcmV0' not in repr(result)
    persistence.validate(result)


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == sorted(NEW) and 'previously_custom' not in result


def test_collectd_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-1]['sha256'] = 'd' * 64
    after['entries'].append(entry(DEBIAN + '/collectd.conf.d/zz-new.conf'))
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind']) for c in result['changes']] == [
        (DEBIAN + '/collectd.conf.d/exec.conf', 'changed'), (DEBIAN + '/collectd.conf.d/zz-new.conf', 'added')]


@pytest.mark.parametrize('stored', [[DEBIAN], [DEBIAN + '/collectd.conf'], [RPM_D + '/exec.conf'], [RPM_CONF, RPM_D]])
def test_earlier_custom_collectd_path_is_still_compared_after_promotion(stored):
    customs = [entry(DEBIAN + '/collectd.conf', 'c')] if stored[0].startswith(DEBIAN + '/') or stored[0] == DEBIAN \
        else [entry(RPM_D + '/exec.conf', 'c')]
    before = inventory(scope=(*EARLIER, *stored), entries=[entry('/etc/crontab'), *customs])
    after = inventory(scope=(*EARLIER, *NEW), entries=[entry('/etc/crontab'), *copy.deepcopy(customs)])
    after['entries'][-1]['sha256'] = 'f' * 64
    result = persistence.compare(before, after)
    assert result['state'] == 'compared' and result.get('previously_custom', []) == sorted(set(stored) - set(NEW))
    assert result['newly_in_scope'] == sorted(set(NEW) - set(stored))
    assert [(c['path'], c['kind']) for c in result['changes']] == [(customs[0]['path'], 'changed')]


@pytest.mark.parametrize('extra', ['/etc/collectd-web.conf', '/etc/collectd.conf.rpmnew', '/etc/collectd.d.bak',
                                   '/etc/collectdmon.conf', '/usr/share/collectd', '/var/lib/collectd'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


@pytest.mark.parametrize('stored', [[DEBIAN], [DEBIAN + '/collectd.conf', DEBIAN + '/collectd.conf.d'],
                                    [RPM_D], [RPM_D + '/exec.conf'], [RPM_CONF], [RPM_CONF, DEBIAN]])
def test_stored_custom_paths_stay_valid_and_are_covered_once(stored):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(stored) == builtin
    assert agent.validate_custom_paths([*stored, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    agent.validate_inspection([], True, stored)


@pytest.mark.parametrize('stored', [[DEBIAN, DEBIAN], [RPM_CONF, RPM_CONF]])
def test_duplicate_promoted_paths_are_rejected(stored):
    with pytest.raises(ValueError):
        agent.validate_custom_paths(stored)


@pytest.mark.parametrize('value', ['/etc/collectd-web.conf', '/etc/collectd.d.bak/x', '/etc/collectd.conf.rpmnew',
                                   '/etc/collectdmon.conf'])
def test_sibling_paths_are_not_promoted_and_stay_additional_scope(value):
    assert not agent.promoted_custom_path(value)
    assert agent.validate_custom_paths([value])[-1] == value
    assert startup_inventory.mechanism(value) == ('additional', 'Additional inventory scope')


@pytest.mark.parametrize('value', [DEBIAN + '/../shadow', DEBIAN + '/', RPM_D + '//x', RPM_D + '/a\nb'])
def test_non_canonical_paths_inside_the_directories_are_not_promoted(value):
    assert not agent.promoted_custom_path(value)
    with pytest.raises(ValueError):
        agent.validate_custom_paths([value])


def test_catalogs_label_paths_and_state_the_gap():
    assert startup_inventory.mechanism(DEBIAN + '/collectd.conf') == ('collectd', 'collectd configuration')
    assert startup_inventory.mechanism(RPM_CONF) == ('collectd_rpm', 'collectd main configuration')
    assert startup_inventory.mechanism(RPM_D + '/exec.conf') == ('collectd_d', 'collectd configuration drop-ins')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['collectd']['observed_files'] == 2
    assert rows['collectd_rpm']['observed_files'] == 0 and rows['collectd_d']['observed_files'] == 0
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'collectd')
    assert mechanism['parse'] == 'metadata' and mechanism['scope'] == 'system'
    assert [(loc['path'], loc['families']) for loc in mechanism['locations']] == [
        (DEBIAN, ('debian',)), (RPM_CONF, ('rpm',)), (RPM_D, ('rpm',))]
    assert DEBIAN in startup_catalog._all_locations('debian') and RPM_D in startup_catalog._all_locations('rpm')
    assert any(DEBIAN in gap and RPM_CONF in gap and RPM_D in gap and 'NotificationExec' in gap
               and 'let this view evaluate' in gap and 'not captured' in gap for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [DEBIAN, RPM_D + '/exec.conf', RPM_CONF], 'enabled': True,
                                 'interval_hours': 12, 'expected_revision': current['revision']})
    assert saved.status_code == 200, saved.text


def store(before, after):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Inspection(id='old', host_id='one', created=time.time() - 2, report={'persistence': before}))
        s.add(PersistenceBaseline(id='baseline', host_id='one', inspection_id='old', evidence_digest=digest(before),
                                  actor='admin', reason='Reviewed fixture metadata'))
        s.add(Setting(key='persistence-baseline:one', value={'id': 'baseline'}))
        s.add(Inspection(id='new', host_id='one', created=time.time() - 1, report={'persistence': after}))
        s.commit()
        return persistence.status(s, 'one')


def test_baseline_status_and_startup_view_mark_newly_covered_paths(admin):
    before = inventory()
    status = store(before, upgraded(before))
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == sorted(NEW)
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    conf = rows[DEBIAN + '/collectd.conf']
    assert conf['change'] == 'not_in_baseline' and conf['mechanism'] == 'collectd'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged'


def test_startup_view_keeps_earlier_custom_collectd_directory_compared(admin):
    before = inventory(scope=(*EARLIER, DEBIAN), entries=[entry('/etc/crontab'), entry(DEBIAN + '/collectd.conf', 'c')])
    after = inventory(scope=(*EARLIER, *NEW), entries=[entry('/etc/crontab'), entry(DEBIAN + '/collectd.conf', 'c'),
                                                       entry(RPM_CONF, 'e')])
    status = store(before, after)
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == [RPM_CONF, RPM_D]
    rows = {r['path']: r for r in admin.get('/api/hosts/one/security/startup-inventory').json()['items']}
    assert rows[DEBIAN + '/collectd.conf']['change'] == 'unchanged' and rows[RPM_CONF]['change'] == 'not_in_baseline'
