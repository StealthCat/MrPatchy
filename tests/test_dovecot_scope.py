"""Dovecot configuration joins built-in startup scope without invalidating baselines (#1620)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

DOVECOT = '/etc/dovecot'
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/hosts.allow', '/etc/hosts.deny',
           '/etc/rsnapshot.conf', '/etc/gitconfig', '/etc/kdump.conf', '/etc/auto.master',
           '/etc/request-key.d', '/etc/request-key.conf', '/etc/clamav', '/etc/clamd.d', '/etc/freshclam.conf')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    after = copy.deepcopy(before)
    after['scope'].append(DOVECOT)
    if present:
        after['entries'] += [entry(DOVECOT + '/dovecot.conf', 'c'), entry(DOVECOT + '/conf.d/10-master.conf', 'e')]
    else:
        after['missing_roots'].append(DOVECOT)
    return after


def test_agent_built_in_scope_includes_the_directory():
    assert DOVECOT in agent.PERSISTENCE_ROOTS and DOVECOT in agent.PROMOTED_PERSISTENCE_ROOTS
    assert DOVECOT in agent.validate_custom_paths([])
    assert DOVECOT in persistence.ADDITIVE_BUILTIN_SCOPE


def test_agent_hashes_dovecot_files_without_running_or_parsing_them(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = tmp_path / 'dovecot'
    (root / 'conf.d').mkdir(parents=True)
    (root / 'private').mkdir(mode=0o700)
    (root / 'dovecot.conf').write_text('!include conf.d/*.conf\n!include_try local.conf\n')
    (root / 'conf.d' / '10-master.conf').write_text(
        f'service imap {{\n  executable = /usr/bin/touch {marker}\n  process_min_avail = 1\n}}\n')
    script = root / 'quota-warning.sh'
    script.write_text(f'#!/bin/sh\ntouch {marker}\n')
    script.chmod(0o755)
    key = root / 'private' / 'dovecot.key'
    key.write_text('-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n')
    key.chmod(0o600)
    (root / 'private' / 'dovecot.pem').symlink_to('/etc/ssl/certs/ssl-cert-snakeoil.pem')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root), str(tmp_path / 'absent.d')))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected'
    assert set(rows) == {str(root / 'dovecot.conf'), str(root / 'conf.d' / '10-master.conf'), str(script),
                         str(key), str(root / 'private' / 'dovecot.pem')}
    assert rows[str(script)]['mode'] == 0o755 and rows[str(key)]['mode'] == 0o600
    # The symlink target is recorded, not followed.
    assert rows[str(root / 'private' / 'dovecot.pem')]['kind'] == 'symlink'
    assert rows[str(root / 'private' / 'dovecot.pem')]['target'] == '/etc/ssl/certs/ssl-cert-snakeoil.pem'
    assert result['missing_roots'] == [str(tmp_path / 'absent.d')]
    assert not marker.exists()
    # Metadata and SHA-256 only: no file content is attached. Dovecot statements (#1620 increment 3) are
    # reduced only when DOVECOT_DIR matches, which this temporary root does not.
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    assert 'PRIVATE' not in repr(result) and 'not-a-real-key' not in repr(result)
    persistence.validate(result)


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == [DOVECOT] and 'previously_custom' not in result


def test_pre_request_key_baseline_accepts_every_promoted_path_together():
    before = inventory(scope=('/etc/cron.d', '/etc/crontab'))
    after = upgraded(before)
    after['scope'] += list(EARLIER[2:])
    result = persistence.compare(before, after)
    assert result['state'] == 'compared'
    assert result['newly_in_scope'] == sorted([*EARLIER[2:], DOVECOT])


def test_dovecot_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-1]['sha256'] = 'd' * 64
    after['entries'].append(entry(DOVECOT + '/conf.d/99-local.conf'))
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind']) for c in result['changes']] == [
        (DOVECOT + '/conf.d/10-master.conf', 'changed'), (DOVECOT + '/conf.d/99-local.conf', 'added')]


@pytest.mark.parametrize(('stored', 'observed'), [
    ([DOVECOT], DOVECOT + '/dovecot.conf'), ([DOVECOT + '/dovecot.conf'], DOVECOT + '/dovecot.conf'),
    ([DOVECOT + '/conf.d', DOVECOT + '/local.conf'], DOVECOT + '/conf.d/10-master.conf')])
def test_earlier_custom_dovecot_path_is_still_compared_after_promotion(stored, observed):
    customs = [entry(observed, 'c')]
    before = inventory(scope=(*EARLIER, *stored), entries=[entry('/etc/crontab'), *customs])
    after = inventory(scope=(*EARLIER, DOVECOT), entries=[entry('/etc/crontab'), *copy.deepcopy(customs)])
    after['entries'][-1]['sha256'] = 'f' * 64
    result = persistence.compare(before, after)
    # A stored path equal to the new built-in directory stays in scope; only paths inside it were removed.
    assert result['state'] == 'compared' and result.get('previously_custom', []) == sorted(set(stored) - {DOVECOT})
    assert result.get('newly_in_scope', []) == sorted({DOVECOT} - set(stored))
    # The earlier custom file was observed, so its change is evidence rather than newly covered.
    assert [(c['path'], c['kind']) for c in result['changes']] == [(customs[0]['path'], 'changed')]


@pytest.mark.parametrize('extra', ['/etc/dovecot.bak', '/etc/dovecot-old', '/usr/share/dovecot/protocols.d',
                                   '/usr/lib/dovecot', '/var/lib/dovecot', '/etc/pki/dovecot'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


@pytest.mark.parametrize('stored', [[DOVECOT], [DOVECOT + '/dovecot.conf', DOVECOT + '/conf.d'],
                                    [DOVECOT + '/conf.d/10-master.conf']])
def test_stored_custom_paths_stay_valid_and_are_covered_once(stored):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(stored) == builtin
    assert agent.validate_custom_paths([*stored, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    agent.validate_inspection([], True, stored)


def test_duplicate_promoted_paths_are_rejected():
    with pytest.raises(ValueError):
        agent.validate_custom_paths([DOVECOT, DOVECOT])


@pytest.mark.parametrize('value', ['/etc/dovecot.bak', '/etc/dovecot-old/x', '/usr/share/dovecot/protocols.d'])
def test_sibling_paths_are_not_promoted_and_stay_additional_scope(value):
    assert not agent.promoted_custom_path(value)
    assert agent.validate_custom_paths([value])[-1] == value


@pytest.mark.parametrize('value', [DOVECOT + '/../shadow', DOVECOT + '/', DOVECOT + '//x', DOVECOT + '/a\nb'])
def test_non_canonical_paths_inside_the_directory_are_not_promoted(value):
    assert not agent.promoted_custom_path(value)
    with pytest.raises(ValueError):
        agent.validate_custom_paths([value])


def test_catalogs_label_paths_and_state_the_gap():
    assert startup_inventory.mechanism(DOVECOT + '/dovecot.conf') == ('dovecot', 'Dovecot configuration')
    assert startup_inventory.mechanism(DOVECOT + '/conf.d/10-master.conf') == ('dovecot', 'Dovecot configuration')
    assert startup_inventory.mechanism('/etc/dovecot.bak/x.conf') == ('additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['dovecot']['observed_files'] == 2
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'dovecot')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'event' and mechanism['scope'] == 'system'
    assert [(loc['path'], loc['families']) for loc in mechanism['locations']] == [(DOVECOT, ('debian', 'rpm'))]
    assert DOVECOT in startup_catalog._all_locations('debian') and DOVECOT in startup_catalog._all_locations('rpm')
    assert any(DOVECOT in gap and 'drop_priv_before_exec' in gap and 'parsed statements' in gap
               and '/usr/share/dovecot/protocols.d' in gap for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [DOVECOT + '/dovecot.conf', DOVECOT + '/conf.d'], 'enabled': True,
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
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == [DOVECOT]
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows[DOVECOT + '/dovecot.conf']['change'] == 'not_in_baseline' and rows[DOVECOT + '/dovecot.conf']['mechanism'] == 'dovecot'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged'
