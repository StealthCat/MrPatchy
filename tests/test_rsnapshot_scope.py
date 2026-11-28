"""/etc/rsnapshot.conf joins built-in startup scope without invalidating baselines (#1530)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

CONF = '/etc/rsnapshot.conf'
WRAPPERS = ('/etc/hosts.allow', '/etc/hosts.deny')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', *WRAPPERS), entries=None):
    rows = [entry('/etc/cron.d/rsnapshot'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    after = copy.deepcopy(before)
    after['scope'].append(CONF)
    if present:
        after['entries'].append(entry(CONF, 'c'))
    else:
        after['missing_roots'].append(CONF)
    return after


def test_agent_built_in_scope_includes_rsnapshot_conf():
    assert CONF in agent.PERSISTENCE_FILES and CONF in agent.validate_custom_paths([])


def test_agent_hashes_conf_without_parsing_or_running_include_commands(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    conf = tmp_path / 'rsnapshot.conf'
    conf.write_text(f'config_version\t1.2\ncmd_preexec\t/usr/local/bin/pre\ninclude_conf\t`/usr/bin/touch {marker}`\n')
    linked = tmp_path / 'linked.conf'
    linked.symlink_to(conf)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(conf), str(linked), str(tmp_path / 'absent')))
    result = agent.persistence_inventory(time.monotonic() + 5)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected' and set(rows) == {str(conf), str(linked)}
    assert rows[str(conf)]['sha256'] and rows[str(linked)]['kind'] == 'symlink' and rows[str(linked)]['target'] == str(conf)
    assert result['missing_roots'] == [str(tmp_path / 'absent')]
    assert not marker.exists()
    assert not any(key in row for row in result['entries'] for key in ('cron', 'anacron', 'at'))
    persistence.validate(result)


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == [CONF]


def test_pre_anacrontab_baseline_accepts_all_promoted_files_together():
    before = inventory(scope=('/etc/cron.d', '/etc/crontab'))
    after = upgraded(before)
    after['scope'] += ['/etc/anacrontab', *WRAPPERS]
    result = persistence.compare(before, after)
    assert result['state'] == 'compared' and result['newly_in_scope'] == sorted(['/etc/anacrontab', *WRAPPERS, CONF])


def test_conf_changes_are_reported_once_both_inventories_cover_it():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-1]['sha256'] = 'd' * 64
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind'], c['fields']) for c in result['changes']] == [(CONF, 'changed', ['sha256'])]


def test_conf_removal_is_reported_once_both_inventories_cover_it():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'].pop()
    after['missing_roots'].append(CONF)
    assert [(c['path'], c['kind']) for c in persistence.compare(before, after)['changes']] == [(CONF, 'removed')]


@pytest.mark.parametrize('extra', ['/etc/rsnapshot.conf.default', '/etc/rsnapshot.d'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


def test_stored_custom_conf_path_stays_valid_and_is_covered_once():
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths([CONF]) == builtin
    assert agent.validate_custom_paths([CONF, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    with pytest.raises(ValueError):
        agent.validate_custom_paths([CONF, CONF])
    agent.validate_inspection([], True, [CONF])


def test_catalogs_label_conf_and_state_the_gap():
    assert startup_inventory.mechanism(CONF) == ('rsnapshot', 'rsnapshot configuration')
    assert startup_inventory.mechanism('/etc/rsnapshot.conf.default') == ('additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['rsnapshot']['observed_files'] == 1
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'rsnapshot')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'schedule'
    assert [loc['path'] for loc in mechanism['locations']] == [CONF]
    assert any(CONF in gap and 'include_conf' in gap and 'not collected' in gap for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_conf_path_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [CONF], 'enabled': True, 'interval_hours': 12,
                                 'expected_revision': current['revision']})
    assert saved.status_code == 200, saved.text


def test_baseline_status_and_startup_view_mark_newly_covered_conf(admin):
    before = inventory()
    after = upgraded(before)
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Inspection(id='old', host_id='one', created=time.time() - 2, report={'persistence': before}))
        s.add(PersistenceBaseline(id='baseline', host_id='one', inspection_id='old', evidence_digest=digest(before),
                                  actor='admin', reason='Reviewed fixture metadata'))
        s.add(Setting(key='persistence-baseline:one', value={'id': 'baseline'}))
        s.add(Inspection(id='new', host_id='one', created=time.time() - 1, report={'persistence': after}))
        s.commit()
        status = persistence.status(s, 'one')
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == [CONF]
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows[CONF]['change'] == 'not_in_baseline' and rows[CONF]['mechanism'] == 'rsnapshot'
    assert rows['/etc/cron.d/rsnapshot']['change'] == 'unchanged' and view['newly_in_scope'] == [CONF]
