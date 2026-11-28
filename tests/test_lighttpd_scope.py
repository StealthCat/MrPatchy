"""lighttpd configuration joins built-in startup scope without invalidating baselines (#1603)."""
import copy
import time

import pytest

from app import lighttpd_commands, persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

LIGHTTPD = '/etc/lighttpd'
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/hosts.allow', '/etc/hosts.deny',
           '/etc/rsnapshot.conf', '/etc/gitconfig', '/etc/kdump.conf', '/etc/auto.master',
           '/etc/request-key.d', '/etc/request-key.conf', '/etc/clamav', '/etc/clamd.d', '/etc/freshclam.conf',
           '/etc/dovecot', '/etc/swanctl', '/etc/strongswan')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    after = copy.deepcopy(before)
    after['scope'].append(LIGHTTPD)
    if present:
        after['entries'] += [entry(LIGHTTPD + '/lighttpd.conf', 'c'), entry(LIGHTTPD + '/conf-enabled/10-fastcgi.conf', 'e')]
    else:
        after['missing_roots'].append(LIGHTTPD)
    return after


def test_agent_built_in_scope_includes_the_directory():
    assert LIGHTTPD in agent.PERSISTENCE_ROOTS and LIGHTTPD in agent.PROMOTED_PERSISTENCE_ROOTS
    assert LIGHTTPD in agent.validate_custom_paths([])
    assert LIGHTTPD in persistence.ADDITIVE_BUILTIN_SCOPE
    # The contract's default configuration lies inside the collected directory.
    assert lighttpd_commands.DEFAULT_CONFIG.startswith(LIGHTTPD + '/')


def test_agent_hashes_lighttpd_files_without_running_or_parsing_them(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = tmp_path / 'lighttpd'
    (root / 'conf-available').mkdir(parents=True)
    (root / 'conf-enabled').mkdir()
    (root / 'lighttpd.conf').write_text(
        f'server.username = "www-data"\ninclude_shell "/usr/bin/touch {marker}"\n'
        f'server.errorlog = "|/usr/bin/touch {marker}"\ninclude "conf-enabled/*.conf"\n')
    fastcgi = root / 'conf-available' / '10-fastcgi.conf'
    fastcgi.write_text(f'fastcgi.server = ( ".php" => (( "bin-path" => "/usr/bin/touch {marker}" )))\n')
    (root / 'conf-enabled' / '10-fastcgi.conf').symlink_to('../conf-available/10-fastcgi.conf')
    script = root / 'helper.pl'
    script.write_text(f'#!/bin/sh\ntouch {marker}\n')
    script.chmod(0o755)
    key = root / 'server.pem'
    key.write_text('-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n')
    key.chmod(0o600)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root), str(tmp_path / 'absent.d')))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected'
    link = str(root / 'conf-enabled' / '10-fastcgi.conf')
    assert set(rows) == {str(root / 'lighttpd.conf'), str(fastcgi), link, str(script), str(key)}
    assert rows[str(script)]['mode'] == 0o755 and rows[str(key)]['mode'] == 0o600
    # The Debian conf-enabled symlink target is recorded, not followed.
    assert rows[link]['kind'] == 'symlink' and rows[link]['target'] == '../conf-available/10-fastcgi.conf'
    assert result['missing_roots'] == [str(tmp_path / 'absent.d')]
    assert not marker.exists()
    # Metadata and SHA-256 only: no file content is attached.
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    assert 'PRIVATE' not in repr(result) and 'not-a-real-key' not in repr(result)
    assert 'www-data' not in repr(result) and 'include_shell' not in repr(result)
    persistence.validate(result)


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == [LIGHTTPD] and 'previously_custom' not in result


def test_pre_request_key_baseline_accepts_every_promoted_path_together():
    before = inventory(scope=('/etc/cron.d', '/etc/crontab'))
    after = upgraded(before)
    after['scope'] += list(EARLIER[2:])
    result = persistence.compare(before, after)
    assert result['state'] == 'compared'
    assert result['newly_in_scope'] == sorted([*EARLIER[2:], LIGHTTPD])


def test_lighttpd_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-1]['sha256'] = 'd' * 64
    after['entries'].append(entry(LIGHTTPD + '/conf-enabled/99-local.conf'))
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind']) for c in result['changes']] == [
        (LIGHTTPD + '/conf-enabled/10-fastcgi.conf', 'changed'), (LIGHTTPD + '/conf-enabled/99-local.conf', 'added')]


@pytest.mark.parametrize(('stored', 'observed'), [
    ([LIGHTTPD], LIGHTTPD + '/lighttpd.conf'), ([LIGHTTPD + '/lighttpd.conf'], LIGHTTPD + '/lighttpd.conf'),
    ([LIGHTTPD + '/conf-enabled', LIGHTTPD + '/conf-available'], LIGHTTPD + '/conf-enabled/10-fastcgi.conf')])
def test_earlier_custom_lighttpd_path_is_still_compared_after_promotion(stored, observed):
    customs = [entry(observed, 'c')]
    before = inventory(scope=(*EARLIER, *stored), entries=[entry('/etc/crontab'), *customs])
    after = inventory(scope=(*EARLIER, LIGHTTPD), entries=[entry('/etc/crontab'), *copy.deepcopy(customs)])
    after['entries'][-1]['sha256'] = 'f' * 64
    result = persistence.compare(before, after)
    # A stored path equal to the new built-in directory stays in scope; only paths inside it were removed.
    assert result['state'] == 'compared' and result.get('previously_custom', []) == sorted(set(stored) - {LIGHTTPD})
    assert result.get('newly_in_scope', []) == sorted({LIGHTTPD} - set(stored))
    # The earlier custom file was observed, so its change is evidence rather than newly covered.
    assert [(c['path'], c['kind']) for c in result['changes']] == [(customs[0]['path'], 'changed')]


@pytest.mark.parametrize('extra', ['/etc/lighttpd.bak', '/etc/lighttpd-old', '/usr/share/lighttpd',
                                   '/usr/lib/lighttpd', '/var/lib/lighttpd', '/var/cache/lighttpd'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


@pytest.mark.parametrize('stored', [[LIGHTTPD], [LIGHTTPD + '/lighttpd.conf', LIGHTTPD + '/conf-enabled'],
                                    [LIGHTTPD + '/conf-available/10-fastcgi.conf']])
def test_stored_custom_paths_stay_valid_and_are_covered_once(stored):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(stored) == builtin
    assert agent.validate_custom_paths([*stored, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    agent.validate_inspection([], True, stored)


def test_duplicate_promoted_paths_are_rejected():
    with pytest.raises(ValueError):
        agent.validate_custom_paths([LIGHTTPD, LIGHTTPD])


@pytest.mark.parametrize('value', ['/etc/lighttpd.bak', '/etc/lighttpd-old/x', '/usr/share/lighttpd/create-mime.conf.pl'])
def test_sibling_paths_are_not_promoted_and_stay_additional_scope(value):
    assert not agent.promoted_custom_path(value)
    assert agent.validate_custom_paths([value])[-1] == value


@pytest.mark.parametrize('value', [LIGHTTPD + '/../shadow', LIGHTTPD + '/', LIGHTTPD + '//x', LIGHTTPD + '/a\nb'])
def test_non_canonical_paths_inside_the_directory_are_not_promoted(value):
    assert not agent.promoted_custom_path(value)
    with pytest.raises(ValueError):
        agent.validate_custom_paths([value])


def test_catalogs_label_paths_and_state_the_gap():
    label = ('lighttpd', 'lighttpd configuration')
    assert startup_inventory.mechanism(LIGHTTPD + '/lighttpd.conf') == label
    assert startup_inventory.mechanism(LIGHTTPD + '/conf-enabled/10-fastcgi.conf') == label
    assert startup_inventory.mechanism('/etc/lighttpd.bak/x.conf') == ('additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['lighttpd']['observed_files'] == 2
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'lighttpd')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'boot' and mechanism['scope'] == 'system'
    assert [(loc['path'], loc['families']) for loc in mechanism['locations']] == [(LIGHTTPD, ('debian', 'rpm'))]
    assert LIGHTTPD in startup_catalog._all_locations('debian') and LIGHTTPD in startup_catalog._all_locations('rpm')
    assert any(LIGHTTPD in gap and 'include_shell' in gap and 'from the hashed bytes' in gap and 'bin-path' in gap
               for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [LIGHTTPD + '/lighttpd.conf', LIGHTTPD + '/conf-enabled'], 'enabled': True,
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
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == [LIGHTTPD]
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows[LIGHTTPD + '/lighttpd.conf']['change'] == 'not_in_baseline' and rows[LIGHTTPD + '/lighttpd.conf']['mechanism'] == 'lighttpd'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged'
