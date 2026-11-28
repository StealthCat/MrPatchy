"""ISC dhcpd configuration files join built-in startup scope without invalidating baselines (#1593)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

DHCP_DIR = '/etc/dhcp'
DEFAULT_DIR = '/etc/default'
DHCPD = '/etc/dhcp/dhcpd.conf'
DHCPD6 = '/etc/dhcp/dhcpd6.conf'
DEFAULTS = '/etc/default/isc-dhcp-server'
NEW = (DHCPD, DHCPD6, DEFAULTS)
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/kdump.conf', '/etc/auto.master')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None, missing=()):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0,
            'missing_roots': list(missing)}


def test_agent_built_in_scope_holds_only_the_dhcpd_files():
    assert set(NEW) <= set(agent.PERSISTENCE_FILES) and set(NEW) <= set(agent.NESTED_PERSISTENCE_FILES)
    assert set(NEW) <= set(agent.PROMOTED_PERSISTENCE_FILES)
    for directory in (DHCP_DIR, DEFAULT_DIR):
        assert directory not in agent.PERSISTENCE_ROOTS and directory not in agent.PERSISTENCE_FILES
        assert directory not in persistence.ADDITIVE_BUILTIN_SCOPE
    assert set(NEW) <= set(agent.validate_custom_paths([]))
    assert set(NEW) <= set(persistence.ADDITIVE_BUILTIN_SCOPE)


def test_agent_hashes_dhcpd_files_without_walking_leases_or_running_programs(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    dhcp = tmp_path / 'dhcp'
    default = tmp_path / 'default'
    (dhcp / 'dhclient-exit-hooks.d').mkdir(parents=True)
    default.mkdir()
    (dhcp / 'dhcpd.conf').write_text(
        f'key omapi {{ algorithm hmac-sha256; secret "c2VjcmV0"; }}\n'
        f'execute("/usr/bin/touch", "{marker}");\n'
        f'subnet 192.0.2.0 netmask 255.255.255.0 {{ on commit {{ execute("/usr/bin/touch", "{marker}"); }} }}\n')
    (dhcp / 'dhcpd6.conf').write_text(f'on release {{ execute("/usr/bin/touch", "{marker}"); }}\n')
    (dhcp / 'dhclient-exit-hooks.d' / 'hook').write_text(f'touch {marker}\n')
    (default / 'isc-dhcp-server').write_text('INTERFACESv4="eth0"\nOPTIONS="-user root"\n')
    (default / 'grub').write_text('GRUB_TIMEOUT=5\n')
    files = (str(dhcp / 'dhcpd.conf'), str(dhcp / 'dhcpd6.conf'), str(default / 'isc-dhcp-server'))
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(tmp_path / 'absent.d'),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected' and set(rows) == set(files)
    assert all(row['sha256'] for row in rows.values())
    assert not marker.exists()
    # Hashing only: no parsed detail or file content (such as the OMAPI secret) is attached.
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    assert 'c2VjcmV0' not in repr(result)
    persistence.validate(result)


def test_absent_dhcpd_files_are_missing_not_gaps(tmp_path, monkeypatch):
    files = (str(tmp_path / 'dhcp' / 'dhcpd.conf'), str(tmp_path / 'dhcp' / 'dhcpd6.conf'),
             str(tmp_path / 'default' / 'isc-dhcp-server'))
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    result = agent.persistence_inventory(time.monotonic() + 5)
    assert result['state'] == 'collected' and result['missing_roots'] == list(files) and not result['entries']


@pytest.mark.parametrize('stored', [[DHCP_DIR], [DEFAULT_DIR], [DHCP_DIR, DEFAULT_DIR], [DHCPD], [DEFAULTS],
                                    [DHCPD6, '/etc/dhcp/dhclient-exit-hooks.d'], ['/etc/dhcp/dhclient.conf'],
                                    ['/etc/default/grub', DHCP_DIR]])
def test_stored_custom_dhcp_paths_stay_valid(stored):
    scope = agent.validate_custom_paths(list(stored))
    assert set(NEW) <= set(scope) and len(set(scope)) == len(scope)


@pytest.mark.parametrize('stored', [['/etc'], ['/'], [DHCP_DIR, DHCP_DIR + '/dhclient-exit-hooks.d'],
                                    ['/etc/dhcp/'], ['/etc/dhcp/../cron.d'], [DEFAULT_DIR, DEFAULTS + '/x']])
def test_overlapping_custom_paths_are_still_rejected(stored):
    with pytest.raises(ValueError):
        agent.validate_custom_paths(list(stored))


def test_custom_dhcp_directory_leaves_dhcpd_files_to_built_in_scope(tmp_path, monkeypatch):
    dhcp = tmp_path / 'dhcp'
    (dhcp / 'dhclient-exit-hooks.d').mkdir(parents=True)
    (dhcp / 'dhcpd.conf').write_text('authoritative;\n')
    (dhcp / 'dhcpd6.conf').write_text('authoritative;\n')
    (dhcp / 'dhclient-exit-hooks.d' / 'hook').write_text('true\n')
    files = (str(dhcp / 'dhcpd.conf'), str(dhcp / 'dhcpd6.conf'))
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    monkeypatch.setattr(agent, 'NESTED_PERSISTENCE_FILES', files)
    assert agent.validate_custom_paths([str(dhcp)]) == [*files, str(dhcp)]
    result = agent.persistence_inventory(time.monotonic() + 5, custom_paths=[str(dhcp)])
    paths = [r['path'] for r in result['entries']]
    assert result['state'] == 'collected'
    assert sorted(paths) == sorted([*files, str(dhcp / 'dhclient-exit-hooks.d' / 'hook')]) and len(paths) == len(set(paths))
    persistence.validate({**result, 'scope': [*files, str(dhcp)]})


def test_earlier_baseline_compares_within_its_scope_and_lists_new_files():
    before = inventory()
    after = copy.deepcopy(before)
    after['scope'] += list(NEW)
    after['entries'] += [entry(DHCPD, 'c')]
    after['missing_roots'] += [DHCPD6, DEFAULTS]
    comparison = persistence.compare(before, after)
    assert comparison['state'] == 'compared' and comparison['changes'] == []
    assert comparison['newly_in_scope'] == sorted(NEW)


def test_earlier_custom_dhcp_directory_keeps_comparing_its_files():
    before = inventory(scope=(*EARLIER, DHCP_DIR), entries=[entry('/etc/crontab'), entry(DHCPD, 'c'),
                                                            entry(DHCP_DIR + '/dhclient.conf', 'f')])
    after = inventory(scope=(*EARLIER, DHCP_DIR, *NEW), entries=[entry('/etc/crontab'), entry(DHCPD, 'd'),
                                                                 entry(DHCP_DIR + '/dhclient.conf', 'f'),
                                                                 entry(DEFAULTS, 'e')],
                      missing=[DHCPD6])
    comparison = persistence.compare(before, after)
    assert comparison['state'] == 'compared' and comparison['newly_in_scope'] == [DEFAULTS]
    assert [(c['path'], c['kind']) for c in comparison['changes']] == [(DHCPD, 'changed')]


def test_earlier_custom_dhcpd_file_is_promoted_and_keeps_comparing():
    before = inventory(scope=(*EARLIER, DHCPD), entries=[entry('/etc/crontab'), entry(DHCPD, 'c')])
    after = inventory(scope=(*EARLIER, *NEW), entries=[entry('/etc/crontab'), entry(DHCPD, 'c'), entry(DEFAULTS, 'e')],
                      missing=[DHCPD6])
    comparison = persistence.compare(before, after)
    assert comparison['state'] == 'compared' and comparison['changes'] == []
    assert comparison['newly_in_scope'] == sorted([DHCPD6, DEFAULTS])


@pytest.mark.parametrize('extra', [DHCP_DIR, DEFAULT_DIR, '/etc/dhcp/dhclient.conf', '/etc/ltsp/dhcpd.conf'])
def test_other_dhcp_paths_are_not_additive_built_in_scope(extra):
    before = inventory()
    after = inventory(scope=(*EARLIER, extra))
    assert persistence.compare(before, after)['note'].startswith('Inventory scope changed')


def test_catalogs_label_files_and_state_the_gap():
    assert startup_inventory.mechanism(DHCPD) == ('dhcpd', 'ISC dhcpd configuration')
    assert startup_inventory.mechanism(DHCPD6) == ('dhcpd6', 'ISC dhcpd DHCPv6 configuration')
    assert startup_inventory.mechanism(DEFAULTS) == ('dhcpd_defaults', 'ISC DHCP server defaults')
    assert startup_inventory.mechanism(DHCP_DIR + '/dhclient.conf')[0] == 'additional'
    gap = next(g for g in startup_inventory.GAPS if g.startswith('ISC dhcpd:'))
    assert 'not yet evaluated' in gap and 'include' in gap and '/etc/ltsp/dhcpd.conf' in gap and 'never stored' in gap
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'dhcpd')
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


def test_saved_monitor_policy_with_custom_dhcp_directories_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [DHCP_DIR, DEFAULT_DIR], 'enabled': True, 'interval_hours': 12,
                                 'expected_revision': current['revision']})
    assert saved.status_code == 200, saved.text


def test_startup_view_marks_new_files_and_keeps_custom_directory_compared(admin):
    before = inventory(scope=(*EARLIER, DHCP_DIR), entries=[entry('/etc/crontab'), entry(DHCPD, 'c')])
    after = inventory(scope=(*EARLIER, DHCP_DIR, *NEW), entries=[entry('/etc/crontab'), entry(DHCPD, 'c'),
                                                                 entry(DHCPD6, 'e'), entry(DEFAULTS, 'f')])
    status = store(before, after)
    assert status['comparison']['newly_in_scope'] == [DEFAULTS]
    rows = {r['path']: r for r in admin.get('/api/hosts/one/security/startup-inventory').json()['items']}
    assert rows[DHCPD]['change'] == 'unchanged' and rows[DHCPD]['mechanism'] == 'dhcpd'
    # The earlier custom /etc/dhcp observed the directory, so a new dhcpd6.conf in it was added there.
    assert rows[DHCPD6]['change'] == 'added' and rows[DHCPD6]['mechanism'] == 'dhcpd6'
    # The defaults file was outside the earlier scope, so it is newly covered, not added on the host.
    assert rows[DEFAULTS]['change'] == 'not_in_baseline' and rows[DEFAULTS]['mechanism'] == 'dhcpd_defaults'
