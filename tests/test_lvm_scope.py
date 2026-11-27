"""The LVM configuration cascade joins built-in startup scope without invalidating baselines (#1599)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

LVM_DIR = '/etc/lvm'
LVM_CONF = '/etc/lvm/lvm.conf'
LVM_LOCAL = '/etc/lvm/lvmlocal.conf'
NEW = (LVM_CONF, LVM_LOCAL)
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/kdump.conf', '/etc/auto.master')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None, missing=()):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0,
            'missing_roots': list(missing)}


def test_agent_built_in_scope_holds_only_the_cascade_files():
    assert set(NEW) <= set(agent.PERSISTENCE_FILES) and set(NEW) == set(agent.NESTED_PERSISTENCE_FILES)
    assert LVM_DIR not in agent.PERSISTENCE_ROOTS and LVM_DIR not in agent.PERSISTENCE_FILES
    assert set(NEW) <= set(agent.validate_custom_paths([]))
    assert set(NEW) <= set(persistence.ADDITIVE_BUILTIN_SCOPE) and LVM_DIR not in persistence.ADDITIVE_BUILTIN_SCOPE


def test_agent_hashes_cascade_files_without_walking_backups_or_running_commands(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    lvm = tmp_path / 'lvm'
    (lvm / 'archive').mkdir(parents=True)
    (lvm / 'backup').mkdir()
    (lvm / 'lvm.conf').write_text(f'global {{\n  thin_check_executable = "/usr/bin/touch {marker}"\n}}\n')
    (lvm / 'lvmlocal.conf').write_text(f'dmeventd {{\n  thin_command = "/usr/bin/touch {marker}"\n}}\n')
    (lvm / 'archive' / 'vg0_00001.vg').write_text('contents = "Text Format Volume Group"\n')
    (lvm / 'backup' / 'vg0').write_text('contents = "Text Format Volume Group"\n')
    files = (str(lvm / 'lvm.conf'), str(lvm / 'lvmlocal.conf'))
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(tmp_path / 'absent.d'),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected' and set(rows) == set(files)
    assert all(row['sha256'] for row in rows.values())
    assert not marker.exists()
    # Hashing only: no parsed detail is attached, even with job parsing enabled.
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    persistence.validate(result)


def test_absent_cascade_files_are_missing_not_gaps(tmp_path, monkeypatch):
    files = (str(tmp_path / 'lvm' / 'lvm.conf'), str(tmp_path / 'lvm' / 'lvmlocal.conf'))
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    result = agent.persistence_inventory(time.monotonic() + 5)
    assert result['state'] == 'collected' and result['missing_roots'] == list(files) and not result['entries']


@pytest.mark.parametrize('stored', [[LVM_DIR], [LVM_DIR + '/profile'], [LVM_CONF], [LVM_LOCAL, '/etc/lvm/archive'],
                                    [LVM_DIR + '/lvm_web.conf']])
def test_stored_custom_lvm_paths_stay_valid(stored):
    scope = agent.validate_custom_paths(list(stored))
    assert set(NEW) <= set(scope) and len(set(scope)) == len(scope)


@pytest.mark.parametrize('stored', [['/etc'], ['/'], [LVM_DIR, LVM_DIR + '/profile'], ['/etc/lvm/'], ['/etc/lvm/../cron.d']])
def test_overlapping_custom_paths_are_still_rejected(stored):
    with pytest.raises(ValueError):
        agent.validate_custom_paths(list(stored))


def test_custom_lvm_directory_leaves_cascade_files_to_built_in_scope(tmp_path, monkeypatch):
    lvm = tmp_path / 'lvm'
    (lvm / 'profile').mkdir(parents=True)
    (lvm / 'lvm.conf').write_text('global {}\n')
    (lvm / 'lvmlocal.conf').write_text('local {}\n')
    (lvm / 'profile' / 'thin.profile').write_text('allocation {}\n')
    files = (str(lvm / 'lvm.conf'), str(lvm / 'lvmlocal.conf'))
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    monkeypatch.setattr(agent, 'NESTED_PERSISTENCE_FILES', files)
    assert agent.validate_custom_paths([str(lvm)]) == [*files, str(lvm)]
    result = agent.persistence_inventory(time.monotonic() + 5, custom_paths=[str(lvm)])
    paths = [r['path'] for r in result['entries']]
    assert result['state'] == 'collected'
    assert sorted(paths) == sorted([*files, str(lvm / 'profile' / 'thin.profile')]) and len(paths) == len(set(paths))
    persistence.validate({**result, 'scope': [*files, str(lvm)]})


def test_earlier_baseline_compares_within_its_scope_and_lists_new_files():
    before = inventory()
    after = copy.deepcopy(before)
    after['scope'] += list(NEW)
    after['entries'] += [entry(LVM_CONF, 'c')]
    after['missing_roots'] += [LVM_LOCAL]
    comparison = persistence.compare(before, after)
    assert comparison['state'] == 'compared' and comparison['changes'] == []
    assert comparison['newly_in_scope'] == sorted(NEW)


def test_earlier_custom_lvm_directory_keeps_comparing_its_files():
    before = inventory(scope=(*EARLIER, LVM_DIR), entries=[entry('/etc/crontab'), entry(LVM_CONF, 'c'),
                                                           entry(LVM_DIR + '/profile/thin.profile', 'f')])
    after = inventory(scope=(*EARLIER, LVM_DIR, *NEW), entries=[entry('/etc/crontab'), entry(LVM_CONF, 'd'),
                                                                entry(LVM_DIR + '/profile/thin.profile', 'f')],
                      missing=[LVM_LOCAL])
    comparison = persistence.compare(before, after)
    assert comparison['state'] == 'compared' and 'newly_in_scope' not in comparison
    assert [(c['path'], c['kind']) for c in comparison['changes']] == [(LVM_CONF, 'changed')]


def test_earlier_custom_lvm_file_is_promoted_and_keeps_comparing():
    before = inventory(scope=(*EARLIER, LVM_CONF), entries=[entry('/etc/crontab'), entry(LVM_CONF, 'c')])
    after = inventory(scope=(*EARLIER, *NEW), entries=[entry('/etc/crontab'), entry(LVM_CONF, 'c'), entry(LVM_LOCAL, 'e')])
    comparison = persistence.compare(before, after)
    assert comparison['state'] == 'compared' and comparison['changes'] == []
    assert comparison['newly_in_scope'] == [LVM_LOCAL]


@pytest.mark.parametrize('extra', [LVM_DIR, '/etc/lvm/archive', '/etc/lvm/lvm_web.conf'])
def test_other_lvm_paths_are_not_additive_built_in_scope(extra):
    before = inventory()
    after = inventory(scope=(*EARLIER, extra))
    assert persistence.compare(before, after)['note'].startswith('Inventory scope changed')


def test_catalogs_label_files_and_state_the_gap():
    assert startup_inventory.mechanism(LVM_CONF) == ('lvm', 'LVM configuration')
    assert startup_inventory.mechanism(LVM_LOCAL) == ('lvm_local', 'LVM local configuration')
    assert startup_inventory.mechanism(LVM_DIR + '/profile/thin.profile')[0] == 'additional'
    gap = next(g for g in startup_inventory.GAPS if g.startswith('LVM2:'))
    assert 'not yet evaluated' in gap and 'lvm_<tag>.conf' in gap and 'archive' in gap
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'lvm')
    assert [loc['path'] for loc in mechanism['locations']] == list(NEW)


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


def test_saved_monitor_policy_with_custom_lvm_directory_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [LVM_DIR], 'enabled': True, 'interval_hours': 12,
                                 'expected_revision': current['revision']})
    assert saved.status_code == 200, saved.text


def test_startup_view_marks_new_files_and_keeps_custom_directory_compared(admin):
    before = inventory(scope=(*EARLIER, LVM_DIR), entries=[entry('/etc/crontab'), entry(LVM_CONF, 'c')])
    after = inventory(scope=(*EARLIER, LVM_DIR, *NEW), entries=[entry('/etc/crontab'), entry(LVM_CONF, 'c'),
                                                                entry(LVM_LOCAL, 'e')])
    status = store(before, after)
    assert status['state'] == 'drifted' and 'newly_in_scope' not in status['comparison']
    rows = {r['path']: r for r in admin.get('/api/hosts/one/security/startup-inventory').json()['items']}
    assert rows[LVM_CONF]['change'] == 'unchanged' and rows[LVM_CONF]['mechanism'] == 'lvm'
    assert rows[LVM_LOCAL]['change'] == 'added' and rows[LVM_LOCAL]['mechanism'] == 'lvm_local'
