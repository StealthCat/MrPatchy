"""Samba configuration joins built-in startup scope without invalidating baselines (#1580)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

SAMBA = '/etc/samba'
SMB_CONF = '/etc/samba/smb.conf'
SYSCONFIG_DIR = '/etc/sysconfig'
SYSCONFIG = '/etc/sysconfig/samba'
NEW = (SAMBA, SYSCONFIG)
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/kdump.conf', '/etc/auto.master')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None, missing=()):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0,
            'missing_roots': list(missing)}


def test_agent_built_in_scope_holds_samba_directory_and_options_file():
    assert SAMBA in agent.PERSISTENCE_ROOTS and SAMBA in agent.PROMOTED_PERSISTENCE_ROOTS
    assert SYSCONFIG in agent.PERSISTENCE_FILES and SYSCONFIG in agent.NESTED_PERSISTENCE_FILES
    assert SYSCONFIG in agent.PROMOTED_PERSISTENCE_FILES
    assert SYSCONFIG_DIR not in agent.PERSISTENCE_ROOTS and SYSCONFIG_DIR not in agent.PERSISTENCE_FILES
    assert SYSCONFIG_DIR not in persistence.ADDITIVE_BUILTIN_SCOPE
    assert set(NEW) <= set(agent.validate_custom_paths([]))
    assert set(NEW) <= set(persistence.ADDITIVE_BUILTIN_SCOPE)


def test_agent_hashes_samba_files_without_running_commands_or_storing_content(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    samba = tmp_path / 'samba'
    sysconfig = tmp_path / 'sysconfig'
    samba.mkdir()
    sysconfig.mkdir()
    (samba / 'smb.conf').write_text(
        f'[global]\n  panic action = /usr/bin/touch {marker}\n  include = {samba / "shares.conf"}\n'
        f'[data]\n  path = /srv\n  root preexec = /usr/bin/touch {marker}\n')
    (samba / 'shares.conf').write_text(f'[more]\n  postexec = /usr/bin/touch {marker}\n')
    (samba / 'smbpasswd').write_text('alice:1000:XXXXSECRETHASHXXXX:\n')
    (sysconfig / 'samba').write_text('SMBDOPTIONS="-D"\nNMBDOPTIONS="-D"\n')
    (sysconfig / 'network').write_text('NETWORKING=yes\n')
    files = (str(sysconfig / 'samba'),)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(samba),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected'
    assert set(rows) == {str(samba / 'smb.conf'), str(samba / 'shares.conf'), str(samba / 'smbpasswd'), *files}
    assert all(row['sha256'] for row in rows.values())
    assert not marker.exists()
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    assert 'SECRETHASH' not in repr(result) and 'root preexec' not in repr(result)
    persistence.validate(result)


def test_symlinked_smb_conf_is_recorded_not_followed(tmp_path, monkeypatch):
    samba = tmp_path / 'samba'
    samba.mkdir()
    outside = tmp_path / 'outside.conf'
    outside.write_text('[global]\n')
    (samba / 'smb.conf').symlink_to(outside)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(samba),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    result = agent.persistence_inventory(time.monotonic() + 5)
    rows = {r['path']: r for r in result['entries']}
    assert rows[str(samba / 'smb.conf')]['kind'] == 'symlink'
    assert rows[str(samba / 'smb.conf')]['target'] == str(outside)
    assert str(outside) not in rows


def test_absent_samba_paths_are_missing_not_gaps(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(tmp_path / 'samba'),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(tmp_path / 'sysconfig' / 'samba'),))
    result = agent.persistence_inventory(time.monotonic() + 5)
    assert result['state'] == 'collected' and not result['entries'] and not result['gaps']
    assert sorted(result['missing_roots']) == sorted([str(tmp_path / 'samba'), str(tmp_path / 'sysconfig' / 'samba')])


@pytest.mark.parametrize('stored', [[SAMBA], [SMB_CONF], ['/etc/samba/includes'], [SYSCONFIG_DIR], [SYSCONFIG],
                                    [SAMBA, SYSCONFIG_DIR], ['/etc/sysconfig/network', SAMBA]])
def test_stored_custom_samba_paths_stay_valid(stored):
    scope = agent.validate_custom_paths(list(stored))
    assert set(NEW) <= set(scope) and len(set(scope)) == len(scope)


@pytest.mark.parametrize('stored', [['/etc'], ['/'], ['/etc/samba/'], ['/etc/samba/../cron.d'],
                                    [SYSCONFIG_DIR, SYSCONFIG + '/x']])
def test_overlapping_or_noncanonical_custom_paths_are_still_rejected(stored):
    with pytest.raises(ValueError):
        agent.validate_custom_paths(list(stored))


def test_custom_sysconfig_directory_leaves_samba_options_to_built_in_scope(tmp_path, monkeypatch):
    sysconfig = tmp_path / 'sysconfig'
    sysconfig.mkdir()
    (sysconfig / 'samba').write_text('SMBDOPTIONS="-D"\n')
    (sysconfig / 'network').write_text('NETWORKING=yes\n')
    files = (str(sysconfig / 'samba'),)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    monkeypatch.setattr(agent, 'NESTED_PERSISTENCE_FILES', files)
    assert agent.validate_custom_paths([str(sysconfig)]) == [*files, str(sysconfig)]
    result = agent.persistence_inventory(time.monotonic() + 5, custom_paths=[str(sysconfig)])
    paths = [r['path'] for r in result['entries']]
    assert sorted(paths) == sorted([*files, str(sysconfig / 'network')]) and len(paths) == len(set(paths))
    persistence.validate({**result, 'scope': [*files, str(sysconfig)]})


def test_earlier_baseline_compares_within_its_scope_and_lists_new_paths():
    before = inventory()
    after = copy.deepcopy(before)
    after['scope'] += list(NEW)
    after['entries'] += [entry(SMB_CONF, 'c')]
    after['missing_roots'] += [SYSCONFIG]
    comparison = persistence.compare(before, after)
    assert comparison['state'] == 'compared' and comparison['changes'] == []
    assert comparison['newly_in_scope'] == sorted(NEW)


def test_earlier_custom_samba_directory_is_promoted_and_keeps_comparing():
    before = inventory(scope=(*EARLIER, SAMBA), entries=[entry('/etc/crontab'), entry(SMB_CONF, 'c')])
    after = inventory(scope=(*EARLIER, *NEW), entries=[entry('/etc/crontab'), entry(SMB_CONF, 'd')],
                      missing=[SYSCONFIG])
    comparison = persistence.compare(before, after)
    assert comparison['state'] == 'compared' and comparison['newly_in_scope'] == [SYSCONFIG]
    assert [(c['path'], c['kind']) for c in comparison['changes']] == [(SMB_CONF, 'changed')]


def test_earlier_custom_sysconfig_directory_keeps_comparing_the_options_file():
    before = inventory(scope=(*EARLIER, SYSCONFIG_DIR), entries=[entry('/etc/crontab'), entry(SYSCONFIG, 'c')])
    after = inventory(scope=(*EARLIER, SYSCONFIG_DIR, *NEW), entries=[entry('/etc/crontab'), entry(SYSCONFIG, 'c')],
                      missing=[SAMBA])
    comparison = persistence.compare(before, after)
    assert comparison['state'] == 'compared' and comparison['changes'] == []
    assert comparison['newly_in_scope'] == [SAMBA]


@pytest.mark.parametrize('extra', [SYSCONFIG_DIR, '/etc/samba.bak', '/var/lib/samba', '/etc/default/samba',
                                   '/usr/share/samba'])
def test_neighbouring_paths_are_not_additive_built_in_scope(extra):
    assert persistence.compare(inventory(), inventory(scope=(*EARLIER, extra)))['note'].startswith('Inventory scope changed')


def test_catalogs_label_paths_and_state_the_gap():
    assert startup_inventory.mechanism(SMB_CONF) == ('samba', 'Samba configuration')
    assert startup_inventory.mechanism(SYSCONFIG) == ('samba_sysconfig', 'Samba daemon options')
    assert startup_inventory.mechanism('/etc/samba.bak')[0] == 'additional'
    assert startup_inventory.mechanism('/etc/sysconfig/network')[0] == 'additional'
    gap = next(g for g in startup_inventory.GAPS if g.startswith('Samba:'))
    assert 'not yet evaluated' in gap and 'root preexec' in gap and 'registry' in gap and '/var/lib/samba' in gap
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'samba')
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


def test_saved_monitor_policy_with_custom_samba_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [SAMBA, SYSCONFIG_DIR], 'enabled': True, 'interval_hours': 12,
                                 'expected_revision': current['revision']})
    assert saved.status_code == 200, saved.text


def test_startup_view_marks_new_files_and_keeps_custom_directory_compared(admin):
    before = inventory(scope=(*EARLIER, SAMBA), entries=[entry('/etc/crontab'), entry(SMB_CONF, 'c')])
    after = inventory(scope=(*EARLIER, *NEW), entries=[entry('/etc/crontab'), entry(SMB_CONF, 'c'),
                                                       entry('/etc/samba/lmhosts', 'e'), entry(SYSCONFIG, 'f')])
    status = store(before, after)
    assert status['comparison']['newly_in_scope'] == [SYSCONFIG]
    rows = {r['path']: r for r in admin.get('/api/hosts/one/security/startup-inventory').json()['items']}
    assert rows[SMB_CONF]['change'] == 'unchanged' and rows[SMB_CONF]['mechanism'] == 'samba'
    # The earlier custom /etc/samba observed the directory, so a new file in it was added on the host.
    assert rows['/etc/samba/lmhosts']['change'] == 'added'
    # The options file was outside the earlier scope, so it is newly covered, not added on the host.
    assert rows[SYSCONFIG]['change'] == 'not_in_baseline' and rows[SYSCONFIG]['mechanism'] == 'samba_sysconfig'
