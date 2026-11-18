"""/etc/anacrontab joins built-in startup scope without invalidating earlier baselines (#826)."""
import copy
import time

import pytest

from app import persistence
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=('/etc/cron.d', '/etc/crontab'), entries=None):
    rows = [entry('/etc/cron.d/task'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, anacrontab=True):
    after = copy.deepcopy(before)
    after['scope'].append('/etc/anacrontab')
    if anacrontab:
        after['entries'].append(entry('/etc/anacrontab', 'c'))
    else:
        after['missing_roots'].append('/etc/anacrontab')
    return after


def test_agent_built_in_scope_includes_anacrontab():
    assert '/etc/anacrontab' in agent.PERSISTENCE_FILES
    assert '/etc/anacrontab' in agent.validate_custom_paths([])


def test_agent_inventories_anacrontab_file(tmp_path, monkeypatch):
    table = tmp_path / 'anacrontab'
    table.write_text('1 5 cron.daily run-parts /etc/cron.daily\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(table), str(tmp_path / 'absent')))
    result = agent.persistence_inventory(time.monotonic() + 5)
    assert result['state'] == 'collected' and [r['path'] for r in result['entries']] == [str(table)]
    assert result['entries'][0]['sha256'] and result['missing_roots'] == [str(tmp_path / 'absent')]
    assert 'cron' not in result['entries'][0]


def test_additive_built_in_scope_compares_within_earlier_scope():
    before = inventory()
    result = persistence.compare(before, upgraded(before))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == ['/etc/anacrontab']
    absent = persistence.compare(before, upgraded(before, anacrontab=False))
    assert absent['state'] == 'compared' and absent['changes'] == [] and absent['newly_in_scope'] == ['/etc/anacrontab']


def test_additive_scope_still_reports_real_changes_in_earlier_scope():
    before = inventory()
    after = upgraded(before)
    after['entries'][0]['sha256'] = 'b' * 64
    after['entries'].append(entry('/etc/cron.d/new'))
    result = persistence.compare(before, after)
    assert result['state'] == 'compared'
    assert [(c['path'], c['kind']) for c in result['changes']] == [('/etc/cron.d/new', 'added'), ('/etc/cron.d/task', 'changed')]


def test_same_scope_comparisons_are_unchanged():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-1]['sha256'] = 'd' * 64
    result = persistence.compare(before, after)
    assert result['state'] == 'compared' and 'newly_in_scope' not in result
    assert [(c['path'], c['kind']) for c in result['changes']] == [('/etc/anacrontab', 'changed')]


@pytest.mark.parametrize('scope', [
    ['/etc/cron.d', '/etc/crontab', '/etc/profile.d'],             # unknown addition
    ['/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/opt/x'],  # promoted plus custom addition
    ['/etc/cron.d', '/etc/anacrontab'],                            # removal
])
def test_non_additive_scope_changes_remain_unavailable(scope):
    before = inventory()
    after = inventory(scope=scope, entries=[entry('/etc/cron.d/task')])
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    before = upgraded(after)
    assert persistence.compare(before, after)['state'] == 'unavailable'


def test_stored_custom_anacrontab_path_stays_valid_and_is_covered_once(tmp_path, monkeypatch):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(['/etc/anacrontab']) == builtin
    assert agent.validate_custom_paths(['/etc/anacrontab', '/opt/app/startup']) == builtin + ['/opt/app/startup']
    for paths in (['/etc/anacrontab', '/etc/anacrontab'], ['/etc/crontab'], ['/etc']):
        with pytest.raises(ValueError):
            agent.validate_custom_paths(paths)
    agent.validate_inspection([], True, ['/etc/anacrontab'])
    table = tmp_path / 'anacrontab'
    table.write_text('@daily 5 job true\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(table),))
    monkeypatch.setattr(agent, 'PROMOTED_PERSISTENCE_FILES', (str(table),))
    result = agent.persistence_inventory(time.monotonic() + 5, [str(table)])
    assert result['scope'] == [str(table)] and [r['path'] for r in result['entries']] == [str(table)]
    persistence.validate(result)


def test_saved_monitor_policy_with_promoted_path_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': ['/etc/anacrontab'], 'enabled': True, 'interval_hours': 12,
                                 'expected_revision': current['revision']})
    assert saved.status_code == 200, saved.text


def test_baseline_status_and_startup_view_mark_newly_covered_paths(admin):
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
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == ['/etc/anacrontab']
    assert 'not reported as added' in status['comparison']['note']
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows['/etc/anacrontab']['change'] == 'not_in_baseline' and rows['/etc/anacrontab']['mechanism'] == 'anacron'
    assert rows['/etc/cron.d/task']['change'] == 'unchanged' and view['newly_in_scope'] == ['/etc/anacrontab']
