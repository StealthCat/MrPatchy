"""/etc/auto.master joins built-in startup scope without invalidating baselines (#1375)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

MASTER = '/etc/auto.master'
KDUMP = '/etc/kdump.conf'
GITCONFIG = '/etc/gitconfig'
WRAPPERS = ('/etc/hosts.allow', '/etc/hosts.deny')
RSNAPSHOT = '/etc/rsnapshot.conf'
EARLIER = ('/etc/anacrontab', *WRAPPERS, RSNAPSHOT, GITCONFIG, KDUMP)


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=('/etc/cron.d', '/etc/crontab', *EARLIER), entries=None):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    after = copy.deepcopy(before)
    after['scope'].append(MASTER)
    if present:
        after['entries'].append(entry(MASTER, 'c'))
    else:
        after['missing_roots'].append(MASTER)
    return after


def test_agent_built_in_scope_includes_auto_master():
    assert MASTER in agent.PERSISTENCE_FILES and MASTER in agent.validate_custom_paths([])
    assert MASTER in agent.PROMOTED_PERSISTENCE_FILES and MASTER in persistence.ADDITIVE_BUILTIN_SCOPE


def test_agent_hashes_auto_master_without_running_its_program_maps(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    program = tmp_path / 'auto.prog'
    program.write_text(f'#!/bin/sh\ntouch {marker}\n')
    program.chmod(0o755)
    master = tmp_path / 'auto.master'
    master.write_text(f'/net -hosts\n/prog program:{program}\n/direct {program}\n+auto.master\n')
    linked = tmp_path / 'linked'
    linked.symlink_to(master)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(master), str(linked), str(tmp_path / 'absent')))
    result = agent.persistence_inventory(time.monotonic() + 5)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected' and set(rows) == {str(master), str(linked)}
    assert rows[str(master)]['sha256'] and rows[str(linked)]['kind'] == 'symlink' and rows[str(linked)]['target'] == str(master)
    assert result['missing_roots'] == [str(tmp_path / 'absent')]
    assert not marker.exists()
    assert not any(key in row for row in result['entries'] for key in ('cron', 'anacron', 'at', 'tcp_wrappers'))
    persistence.validate(result)


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == [MASTER]


def test_pre_anacrontab_baseline_accepts_all_promoted_files_together():
    before = inventory(scope=('/etc/cron.d', '/etc/crontab'))
    after = upgraded(before)
    after['scope'] += list(EARLIER)
    result = persistence.compare(before, after)
    assert result['state'] == 'compared'
    assert result['newly_in_scope'] == sorted([*EARLIER, MASTER])


def test_master_changes_are_reported_once_both_inventories_cover_it():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-1]['sha256'] = 'd' * 64
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind'], c['fields']) for c in result['changes']] == [(MASTER, 'changed', ['sha256'])]


def test_master_removal_is_reported_once_both_inventories_cover_it():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'].pop()
    after['missing_roots'].append(MASTER)
    assert [(c['path'], c['kind']) for c in persistence.compare(before, after)['changes']] == [(MASTER, 'removed')]


@pytest.mark.parametrize('extra', ['/etc/auto.master.d', '/etc/auto_master', '/etc/auto.misc', '/etc/autofs.conf',
                                   '/etc/default/autofs', '/etc/sysconfig/autofs', '/etc/auto.master.rpmnew'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


def test_stored_custom_master_path_stays_valid_and_is_covered_once():
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths([MASTER]) == builtin
    assert agent.validate_custom_paths([MASTER, '/etc/auto.master.d']) == builtin + ['/etc/auto.master.d']
    with pytest.raises(ValueError):
        agent.validate_custom_paths([MASTER, MASTER])
    agent.validate_inspection([], True, [MASTER])


def test_catalogs_label_master_and_state_the_gap():
    assert startup_inventory.mechanism(MASTER) == ('autofs', 'autofs master map')
    assert startup_inventory.mechanism('/etc/auto.master.d/extra.autofs') == ('additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['autofs']['observed_files'] == 1
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'autofs')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'event' and mechanism['scope'] == 'system'
    assert [(loc['path'], loc['families']) for loc in mechanism['locations']] == [(MASTER, ('debian', 'rpm'))]
    assert all(MASTER in startup_catalog._all_locations(family) for family in ('debian', 'rpm'))
    assert any(MASTER in gap and 'resolves the program maps' in gap and 'auto.master.d' in gap and 'incomplete' in gap
               for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_master_path_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [MASTER], 'enabled': True, 'interval_hours': 12,
                                 'expected_revision': current['revision']})
    assert saved.status_code == 200, saved.text


def test_baseline_status_and_startup_view_mark_newly_covered_master(admin):
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
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == [MASTER]
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows[MASTER]['change'] == 'not_in_baseline' and rows[MASTER]['mechanism'] == 'autofs'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged' and view['newly_in_scope'] == [MASTER]
