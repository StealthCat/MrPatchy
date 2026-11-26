"""/etc/hosts.allow and /etc/hosts.deny join built-in startup scope without invalidating baselines (#1390)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

WRAPPERS = ('/etc/hosts.allow', '/etc/hosts.deny')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=('/etc/cron.d', '/etc/crontab', '/etc/anacrontab'), entries=None):
    rows = [entry('/etc/cron.d/task'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=WRAPPERS):
    after = copy.deepcopy(before)
    after['scope'] += list(WRAPPERS)
    after['entries'] += [entry(path, 'c') for path in present]
    after['missing_roots'] += [path for path in WRAPPERS if path not in present]
    return after


def test_agent_built_in_scope_includes_both_wrapper_files():
    selected = agent.validate_custom_paths([])
    assert all(path in agent.PERSISTENCE_FILES and path in selected for path in WRAPPERS)


def test_agent_hashes_wrapper_files_without_parsing_or_following_symlinks(tmp_path, monkeypatch):
    allow = tmp_path / 'hosts.allow'
    allow.write_text('sshd: ALL : spawn (/usr/bin/logger %h)\n')
    deny = tmp_path / 'hosts.deny'
    deny.symlink_to(allow)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(allow), str(deny), str(tmp_path / 'absent')))
    result = agent.persistence_inventory(time.monotonic() + 5)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected' and set(rows) == {str(allow), str(deny)}
    assert rows[str(allow)]['sha256'] and rows[str(deny)]['kind'] == 'symlink' and rows[str(deny)]['target'] == str(allow)
    assert result['missing_roots'] == [str(tmp_path / 'absent')]
    assert not any('cron' in r or 'anacron' in r for r in result['entries'])
    persistence.validate(result)


@pytest.mark.parametrize('present', [WRAPPERS, ('/etc/hosts.allow',), ()])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == list(WRAPPERS)


def test_pre_anacrontab_baseline_accepts_all_promoted_files_together():
    before = inventory(scope=('/etc/cron.d', '/etc/crontab'))
    after = upgraded(before)
    after['scope'].append('/etc/anacrontab')
    result = persistence.compare(before, after)
    assert result['state'] == 'compared' and result['newly_in_scope'] == ['/etc/anacrontab', *WRAPPERS]


def test_wrapper_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-2]['sha256'] = 'd' * 64
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind']) for c in result['changes']] == [('/etc/hosts.allow', 'changed')]


@pytest.mark.parametrize('scope', [
    ['/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/hosts.allow', '/etc/hosts'],  # unreviewed addition
    ['/etc/cron.d', '/etc/crontab', '/etc/hosts.allow', '/etc/hosts.deny'],                # anacrontab removed
])
def test_non_additive_scope_changes_remain_unavailable(scope):
    result = persistence.compare(inventory(), inventory(scope=scope))
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


def test_stored_custom_wrapper_paths_stay_valid_and_are_covered_once():
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(list(WRAPPERS)) == builtin
    assert agent.validate_custom_paths(['/etc/hosts.deny', '/opt/app/startup']) == builtin + ['/opt/app/startup']
    for paths in (['/etc/hosts.allow', '/etc/hosts.allow'], ['/etc/hosts.deny', '/etc/hosts.deny']):
        with pytest.raises(ValueError):
            agent.validate_custom_paths(paths)
    agent.validate_inspection([], True, ['/etc/hosts.allow'])


def test_catalogs_label_both_files_separately():
    assert startup_inventory.mechanism('/etc/hosts.allow') == ('tcp_wrappers_allow', 'TCP wrappers allow rules')
    assert startup_inventory.mechanism('/etc/hosts.deny') == ('tcp_wrappers_deny', 'TCP wrappers deny rules')
    assert startup_inventory.mechanism('/etc/hosts') == ('additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['tcp_wrappers_allow']['observed_files'] == 1 and rows['tcp_wrappers_deny']['observed_files'] == 1
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'tcp_wrappers')
    assert mechanism['parse'] == 'metadata' and [loc['path'] for loc in mechanism['locations']] == list(WRAPPERS)
    assert any('/etc/hosts.allow' in gap and 'parse their spawn, twist and aclexec commands' in gap for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_wrapper_path_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': ['/etc/hosts.allow'], 'enabled': True, 'interval_hours': 12,
                                 'expected_revision': current['revision']})
    assert saved.status_code == 200, saved.text


def test_baseline_status_and_startup_view_mark_newly_covered_wrapper_files(admin):
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
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == list(WRAPPERS)
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows['/etc/hosts.allow']['change'] == 'not_in_baseline' and rows['/etc/hosts.allow']['mechanism'] == 'tcp_wrappers_allow'
    assert rows['/etc/hosts.deny']['change'] == 'not_in_baseline'
    assert rows['/etc/cron.d/task']['change'] == 'unchanged' and view['newly_in_scope'] == list(WRAPPERS)
