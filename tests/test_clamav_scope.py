"""ClamAV configuration joins built-in startup scope without invalidating baselines (#1607)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

DEBIAN = '/etc/clamav'
CLAMD_D = '/etc/clamd.d'
FRESHCLAM = '/etc/freshclam.conf'
NEW = (DEBIAN, CLAMD_D, FRESHCLAM)
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/hosts.allow', '/etc/hosts.deny',
           '/etc/rsnapshot.conf', '/etc/gitconfig', '/etc/kdump.conf', '/etc/auto.master',
           '/etc/request-key.d', '/etc/request-key.conf')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    after = copy.deepcopy(before)
    after['scope'] += [DEBIAN, CLAMD_D, FRESHCLAM]
    if present:
        after['entries'] += [entry(DEBIAN + '/clamd.conf', 'c'), entry(DEBIAN + '/freshclam.conf', 'e')]
        after['missing_roots'] += [CLAMD_D, FRESHCLAM]
    else:
        after['missing_roots'] += [DEBIAN, CLAMD_D, FRESHCLAM]
    return after


def test_agent_built_in_scope_includes_both_layouts():
    assert DEBIAN in agent.PERSISTENCE_ROOTS and CLAMD_D in agent.PERSISTENCE_ROOTS and FRESHCLAM in agent.PERSISTENCE_FILES
    assert set(NEW) <= set(agent.validate_custom_paths([]))
    assert set(NEW) <= set(persistence.ADDITIVE_BUILTIN_SCOPE)


def test_agent_hashes_clamav_files_without_running_their_commands(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    debian = tmp_path / 'clamav'
    (debian / 'onupdateexecute.d').mkdir(parents=True)
    (debian / 'onerrorexecute.d').mkdir()
    (debian / 'clamd.conf').write_text(f'VirusEvent /usr/bin/touch {marker}\nUser clamav\n')
    (debian / 'freshclam.conf').write_text(f'OnUpdateExecute /usr/bin/touch {marker}\nDatabaseOwner clamav\n')
    hook = debian / 'onupdateexecute.d' / 'reload'
    hook.write_text(f'#!/bin/sh\ntouch {marker}\n')
    hook.chmod(0o755)
    clamd_d = tmp_path / 'clamd.d'
    clamd_d.mkdir()
    (clamd_d / 'scan.conf').write_text(f'VirusEvent /usr/bin/touch {marker}\n')
    (clamd_d / 'alias.conf').symlink_to(clamd_d / 'scan.conf')
    freshclam = tmp_path / 'freshclam.conf'
    freshclam.write_text(f'OnErrorExecute /usr/bin/touch {marker}\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(debian), str(clamd_d), str(tmp_path / 'absent.d')))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(freshclam), str(tmp_path / 'absent.conf')))
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected'
    assert set(rows) == {str(debian / 'clamd.conf'), str(debian / 'freshclam.conf'), str(hook),
                         str(clamd_d / 'scan.conf'), str(clamd_d / 'alias.conf'), str(freshclam)}
    assert rows[str(hook)]['sha256'] and rows[str(hook)]['mode'] == 0o755
    assert rows[str(clamd_d / 'alias.conf')]['kind'] == 'symlink'
    assert result['missing_roots'] == [str(tmp_path / 'absent.d'), str(tmp_path / 'absent.conf')]
    assert not marker.exists()
    # Hashing only: no parsed detail is attached, even with job parsing enabled.
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    persistence.validate(result)


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == sorted(NEW) and 'previously_custom' not in result


def test_pre_request_key_baseline_accepts_every_promoted_path_together():
    before = inventory(scope=('/etc/cron.d', '/etc/crontab'))
    after = upgraded(before)
    after['scope'] += list(EARLIER[2:])
    result = persistence.compare(before, after)
    assert result['state'] == 'compared'
    assert result['newly_in_scope'] == sorted([*EARLIER[2:], *NEW])


def test_clamav_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-1]['sha256'] = 'd' * 64
    after['entries'].append(entry(DEBIAN + '/onupdateexecute.d/reload'))
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind']) for c in result['changes']] == [
        (DEBIAN + '/freshclam.conf', 'changed'), (DEBIAN + '/onupdateexecute.d/reload', 'added')]


@pytest.mark.parametrize('stored', [[DEBIAN], [DEBIAN + '/clamd.conf'], [CLAMD_D + '/scan.conf'], [FRESHCLAM, CLAMD_D]])
def test_earlier_custom_clamav_path_is_still_compared_after_promotion(stored):
    customs = [entry(DEBIAN + '/clamd.conf', 'c')] if stored[0].startswith(DEBIAN) else [entry(CLAMD_D + '/scan.conf', 'c')]
    before = inventory(scope=(*EARLIER, *stored), entries=[entry('/etc/crontab'), *customs])
    after = inventory(scope=(*EARLIER, *NEW), entries=[entry('/etc/crontab'), *copy.deepcopy(customs)])
    after['entries'][-1]['sha256'] = 'f' * 64
    result = persistence.compare(before, after)
    # A stored path equal to a new built-in path stays in scope; only paths inside one were removed.
    assert result['state'] == 'compared' and result.get('previously_custom', []) == sorted(set(stored) - set(NEW))
    assert result['newly_in_scope'] == sorted(set(NEW) - set(stored))
    # The earlier custom file was observed, so its change is evidence rather than newly covered.
    assert [(c['path'], c['kind']) for c in result['changes']] == [(customs[0]['path'], 'changed')]


@pytest.mark.parametrize('extra', ['/etc/clamav-unofficial-sigs', '/etc/clamd.conf', '/etc/clamd.d.bak',
                                   '/etc/freshclam.conf.rpmnew', '/etc/mail/clamav-milter.conf', '/var/lib/clamav'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


@pytest.mark.parametrize('stored', [[DEBIAN], [DEBIAN + '/clamd.conf', DEBIAN + '/onupdateexecute.d'],
                                    [CLAMD_D], [CLAMD_D + '/scan.conf'], [FRESHCLAM]])
def test_stored_custom_paths_stay_valid_and_are_covered_once(stored):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(stored) == builtin
    assert agent.validate_custom_paths([*stored, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    agent.validate_inspection([], True, stored)


@pytest.mark.parametrize('stored', [[DEBIAN, DEBIAN], [FRESHCLAM, FRESHCLAM]])
def test_duplicate_promoted_paths_are_rejected(stored):
    with pytest.raises(ValueError):
        agent.validate_custom_paths(stored)


@pytest.mark.parametrize('value', ['/etc/clamav-unofficial-sigs', '/etc/clamd.d.bak/x', '/etc/clamd.conf'])
def test_sibling_paths_are_not_promoted_and_stay_additional_scope(value):
    assert not agent.promoted_custom_path(value)
    assert agent.validate_custom_paths([value])[-1] == value


@pytest.mark.parametrize('value', [DEBIAN + '/../shadow', DEBIAN + '/', CLAMD_D + '//x', CLAMD_D + '/a\nb'])
def test_non_canonical_paths_inside_the_directories_are_not_promoted(value):
    assert not agent.promoted_custom_path(value)
    with pytest.raises(ValueError):
        agent.validate_custom_paths([value])


def test_catalogs_label_paths_and_state_the_gap():
    assert startup_inventory.mechanism(DEBIAN + '/clamd.conf') == ('clamav', 'ClamAV configuration')
    assert startup_inventory.mechanism(CLAMD_D + '/scan.conf') == ('clamav_clamd_d', 'ClamAV clamd configuration')
    assert startup_inventory.mechanism(FRESHCLAM) == ('clamav_freshclam', 'ClamAV freshclam configuration')
    assert startup_inventory.mechanism('/etc/clamav-unofficial-sigs/x.conf') == ('additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['clamav']['observed_files'] == 2
    assert rows['clamav_clamd_d']['observed_files'] == 0 and rows['clamav_freshclam']['observed_files'] == 0
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'clamav')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'event' and mechanism['scope'] == 'system'
    assert [(loc['path'], loc['families']) for loc in mechanism['locations']] == [
        (DEBIAN, ('debian',)), (CLAMD_D, ('rpm',)), (FRESHCLAM, ('rpm',))]
    assert DEBIAN in startup_catalog._all_locations('debian') and CLAMD_D in startup_catalog._all_locations('rpm')
    assert any(DEBIAN in gap and CLAMD_D in gap and FRESHCLAM in gap and 'VirusEvent' in gap and 'not yet parsed' in gap
               for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [DEBIAN, CLAMD_D + '/scan.conf', FRESHCLAM], 'enabled': True,
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
    assert rows[DEBIAN + '/clamd.conf']['change'] == 'not_in_baseline' and rows[DEBIAN + '/clamd.conf']['mechanism'] == 'clamav'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged'


def test_startup_view_keeps_earlier_custom_clamav_directory_compared(admin):
    before = inventory(scope=(*EARLIER, DEBIAN), entries=[entry('/etc/crontab'), entry(DEBIAN + '/clamd.conf', 'c')])
    after = inventory(scope=(*EARLIER, *NEW), entries=[entry('/etc/crontab'), entry(DEBIAN + '/clamd.conf', 'c'),
                                                       entry(FRESHCLAM, 'e')])
    status = store(before, after)
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == [CLAMD_D, FRESHCLAM]
    rows = {r['path']: r for r in admin.get('/api/hosts/one/security/startup-inventory').json()['items']}
    assert rows[DEBIAN + '/clamd.conf']['change'] == 'unchanged' and rows[FRESHCLAM]['change'] == 'not_in_baseline'
