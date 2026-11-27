"""runit service directories join built-in startup scope without invalidating baselines (#1628)."""
import copy
import os
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

SERVICE, RUNIT, SV = '/etc/service', '/etc/runit', '/etc/sv'
RUNIT_PATHS = (SERVICE, RUNIT, SV)
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/hosts.allow', '/etc/hosts.deny',
           '/etc/rsnapshot.conf', '/etc/gitconfig', '/etc/kdump.conf', '/etc/auto.master',
           '/etc/request-key.d', '/etc/request-key.conf', '/etc/clamav', '/etc/clamd.d', '/etc/freshclam.conf',
           '/etc/dovecot')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o755, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def link(path, target):
    return {'path': path, 'kind': 'symlink', 'uid': 0, 'gid': 0, 'mode': 0o777, 'size': len(target), 'mtime_ns': 1,
            'target': target}


def inventory(scope=EARLIER, entries=None):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    after = copy.deepcopy(before)
    after['scope'] += list(RUNIT_PATHS)
    if present:
        # Ubuntu 24.04 runit 2.1.2-59ubuntu1 layout.
        after['entries'] += [link(SERVICE, 'runit/runsvdir/current'), entry(RUNIT + '/2', 'b'),
                             link(RUNIT + '/runsvdir/current', 'default'),
                             link(RUNIT + '/runsvdir/default/ssh', '/etc/sv/ssh'),
                             entry(SV + '/ssh/run', 'c'), link(SV + '/ssh/supervise', '/run/runit/supervise/ssh')]
    else:
        after['missing_roots'] += list(RUNIT_PATHS)
    return after


def test_agent_built_in_scope_includes_the_runit_paths():
    for path in RUNIT_PATHS:
        assert path in agent.PERSISTENCE_ROOTS and path in agent.PROMOTED_PERSISTENCE_ROOTS
        assert path in agent.validate_custom_paths([]) and path in persistence.ADDITIVE_BUILTIN_SCOPE
    assert agent.SYMLINK_RECORDED_ROOTS == (SERVICE,)


def runit_tree(tmp_path, marker):
    etc = tmp_path / 'etc'
    sv = etc / 'sv' / 'getty-5'
    (sv / 'log').mkdir(parents=True)
    (sv / 'control').mkdir()
    for path, text in ((sv / 'run', f'#!/bin/sh\ntouch {marker}\nexec chpst -u nobody true\n'),
                       (sv / 'finish', f'#!/bin/sh\ntouch {marker}\n'), (sv / 'log' / 'run', '#!/bin/sh\n'),
                       (sv / 'control' / 'u', f'#!/bin/sh\ntouch {marker}\n')):
        path.write_text(text)
        path.chmod(0o755)
    (sv / 'down').write_text('')
    (sv / 'supervise').symlink_to('/run/runit/supervise/getty-5')
    os.mkfifo(sv / 'control' / 'fifo')  # A special file must be excluded, never opened.
    runsvdir = etc / 'runit' / 'runsvdir'
    (runsvdir / 'default').mkdir(parents=True)
    (runsvdir / 'default' / 'getty-5').symlink_to('/etc/sv/getty-5')
    (runsvdir / 'current').symlink_to('default')
    stage = etc / 'runit' / '2'
    stage.write_text(f'#!/bin/sh\ntouch {marker}\nexec runsvdir -P /etc/service\n')
    stage.chmod(0o755)
    return etc


@pytest.mark.parametrize('service_is_link', [True, False])
def test_agent_hashes_runit_files_without_running_or_following_them(tmp_path, monkeypatch, service_is_link):
    marker = tmp_path / 'ran'
    etc = runit_tree(tmp_path, marker)
    service = etc / 'service'
    if service_is_link:
        service.symlink_to('runit/runsvdir/current')
    else:
        service.mkdir()
        (service / 'getty-5').symlink_to('/etc/sv/getty-5')
    roots = (str(etc / 'sv'), str(etc / 'runit'), str(service), str(tmp_path / 'absent'))
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', roots)
    monkeypatch.setattr(agent, 'SYMLINK_RECORDED_ROOTS', (str(service), str(tmp_path / 'absent')))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    started = time.monotonic()
    result = agent.persistence_inventory(started + 5, cron_jobs=True)
    assert time.monotonic() - started < 4
    rows = {r['path']: r for r in result['entries']}
    sv = str(etc / 'sv' / 'getty-5')
    expected = {sv + '/run', sv + '/finish', sv + '/log/run', sv + '/control/u', sv + '/down', sv + '/supervise',
                str(etc / 'runit' / '2'), str(etc / 'runit' / 'runsvdir' / 'default' / 'getty-5'),
                str(etc / 'runit' / 'runsvdir' / 'current')}
    expected |= {str(service)} if service_is_link else {str(service / 'getty-5')}
    assert set(rows) == expected
    if service_is_link:
        assert rows[str(service)]['kind'] == 'symlink' and rows[str(service)]['target'] == 'runit/runsvdir/current'
    assert rows[sv + '/supervise'] == {**rows[sv + '/supervise'], 'kind': 'symlink',
                                       'target': '/run/runit/supervise/getty-5'}
    assert rows[sv + '/run']['mode'] == 0o755 and rows[sv + '/down']['size'] == 0
    # The FIFO is disclosed as an excluded special file; nothing else is a gap.
    assert result['gaps'] == [sv + '/control/fifo: Non-regular entry excluded'] and result['state'] == 'incomplete'
    assert result['missing_roots'] == [str(tmp_path / 'absent')]
    assert not marker.exists()
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    assert 'chpst' not in repr(result)
    persistence.validate(result)


def test_symlinked_ancestor_of_the_recorded_root_is_a_gap(tmp_path, monkeypatch):
    real = tmp_path / 'real'
    real.mkdir()
    (real / 'service').symlink_to('runit/runsvdir/current')
    (tmp_path / 'etc').symlink_to(real)
    root = str(tmp_path / 'etc' / 'service')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (root,))
    monkeypatch.setattr(agent, 'SYMLINK_RECORDED_ROOTS', (root,))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    assert result['entries'] == [] and result['gaps'] == [root + ': Persistence root inaccessible']


def test_other_symlinked_built_in_roots_stay_gaps(tmp_path, monkeypatch):
    (tmp_path / 'target').mkdir()
    (tmp_path / 'target' / 'x.conf').write_text('x')
    (tmp_path / 'cron.d').symlink_to(tmp_path / 'target')
    root = str(tmp_path / 'cron.d')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (root,))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    result = agent.persistence_inventory(time.monotonic() + 5)
    assert result['entries'] == [] and result['gaps'] == [root + ': Persistence root inaccessible or symlinked']


def test_full_custom_scope_is_accepted_by_the_controller():
    # #1666: on main 5a77984 the built-in scope plus 16 saved custom paths (41 paths) exceeded the controller's
    # 32-path bound, so every comparison and the startup view rejected the inventory as invalid.
    scope = agent.validate_custom_paths([f'/opt/app{i}' for i in range(16)])
    assert len(scope) == len(agent.PERSISTENCE_ROOTS) + len(agent.PERSISTENCE_FILES) + 16
    assert len(scope) <= persistence.MAX_SCOPE
    before = inventory(scope=scope, entries=[entry('/etc/crontab'), entry('/opt/app3/start')])
    after = copy.deepcopy(before)
    after['entries'][1]['sha256'] = 'f' * 64
    persistence.validate(before)
    result = persistence.compare(before, after)
    assert result['state'] == 'compared' and [(c['path'], c['kind']) for c in result['changes']] == [
        ('/opt/app3/start', 'changed')]
    with pytest.raises(ValueError):
        persistence.validate(inventory(scope=[f'/opt/p{i}' for i in range(persistence.MAX_SCOPE + 1)], entries=[]))


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == sorted(RUNIT_PATHS) and 'previously_custom' not in result


def test_runit_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    rows = {r['path']: r for r in after['entries']}
    rows[SV + '/ssh/run']['sha256'] = 'd' * 64
    rows[SERVICE]['target'] = 'runit/runsvdir/svmanaged'
    after['entries'].append(entry(SV + '/backdoor/run'))
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert sorted((c['path'], c['kind']) for c in result['changes']) == [
        (SERVICE, 'changed'), (SV + '/backdoor/run', 'added'), (SV + '/ssh/run', 'changed')]


@pytest.mark.parametrize(('stored', 'observed'), [
    ([SV], SV + '/ssh/run'), ([SV + '/ssh/run'], SV + '/ssh/run'), ([RUNIT + '/2', SV + '/ssh'], SV + '/ssh/run'),
    ([SERVICE + '/ssh'], SERVICE + '/ssh/run')])
def test_earlier_custom_runit_path_is_still_compared_after_promotion(stored, observed):
    customs = [entry(observed, 'c')]
    before = inventory(scope=(*EARLIER, *stored), entries=[entry('/etc/crontab'), *customs])
    after = inventory(scope=(*EARLIER, *RUNIT_PATHS), entries=[entry('/etc/crontab'), *copy.deepcopy(customs)])
    after['entries'][-1]['sha256'] = 'f' * 64
    result = persistence.compare(before, after)
    assert result['state'] == 'compared' and result.get('previously_custom', []) == sorted(set(stored) - set(RUNIT_PATHS))
    assert result.get('newly_in_scope', []) == sorted(set(RUNIT_PATHS) - set(stored))
    assert [(c['path'], c['kind']) for c in result['changes']] == [(customs[0]['path'], 'changed')]


@pytest.mark.parametrize('extra', ['/etc/services', '/etc/sv.bak', '/etc/runit-services', '/usr/share/runit/sv',
                                   '/run/runit', '/etc/default/runit'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


@pytest.mark.parametrize('stored', [[SV], [SERVICE], [RUNIT + '/2', SV + '/ssh'], [SERVICE + '/ssh/run']])
def test_stored_custom_paths_stay_valid_and_are_covered_once(stored):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(stored) == builtin
    assert agent.validate_custom_paths([*stored, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    agent.validate_inspection([], True, stored)


@pytest.mark.parametrize('value', ['/etc/services', '/etc/sv.bak', '/etc/runit-services/purge-sv', '/usr/share/runit/sv'])
def test_sibling_paths_are_not_promoted_and_stay_additional_scope(value):
    assert not agent.promoted_custom_path(value)
    assert agent.validate_custom_paths([value])[-1] == value


@pytest.mark.parametrize('value', [SV + '/../shadow', SV + '/', SERVICE + '//x', RUNIT + '/a\nb'])
def test_non_canonical_paths_inside_the_directories_are_not_promoted(value):
    assert not agent.promoted_custom_path(value)
    with pytest.raises(ValueError):
        agent.validate_custom_paths([value])


def test_catalogs_label_paths_and_state_the_gap():
    assert startup_inventory.mechanism(SERVICE) == ('runit', 'runit service directory')
    assert startup_inventory.mechanism(RUNIT + '/2') == ('runit_stages', 'runit stages and run levels')
    assert startup_inventory.mechanism(SV + '/ssh/run') == ('runit_sv', 'runit service definitions')
    assert startup_inventory.mechanism('/etc/services') == ('additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert (rows['runit']['observed_files'], rows['runit_stages']['observed_files'], rows['runit_sv']['observed_files']) == (1, 3, 2)
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'runit')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'boot' and mechanism['scope'] == 'system'
    assert [loc['path'] for loc in mechanism['locations']] == list(RUNIT_PATHS)
    for family in ('debian', 'rpm'):
        assert set(RUNIT_PATHS) <= set(startup_catalog._all_locations(family))
    assert any(SERVICE in gap and 'not yet evaluated' in gap and '/usr/share/runit/sv' in gap and 'chpst' in gap
               for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [SV + '/ssh', SERVICE], 'enabled': True,
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
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == sorted(RUNIT_PATHS)
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows[SERVICE]['change'] == 'not_in_baseline' and rows[SERVICE]['mechanism'] == 'runit'
    assert rows[SV + '/ssh/run']['mechanism'] == 'runit_sv'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged'
