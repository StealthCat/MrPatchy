"""/etc/request-key.conf and /etc/request-key.d join built-in startup scope without invalidating baselines (#1632)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

CONF = '/etc/request-key.conf'
DROPINS = '/etc/request-key.d'
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/hosts.allow', '/etc/hosts.deny',
           '/etc/rsnapshot.conf', '/etc/gitconfig', '/etc/kdump.conf')


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    after = copy.deepcopy(before)
    after['scope'] += [DROPINS, CONF]
    if present:
        after['entries'] += [entry(CONF, 'c'), entry(DROPINS + '/cifs.idmap.conf', 'e')]
    else:
        after['missing_roots'] += [DROPINS, CONF]
    return after


def test_agent_built_in_scope_includes_conf_and_dropins():
    assert CONF in agent.PERSISTENCE_FILES and DROPINS in agent.PERSISTENCE_ROOTS
    scope = agent.validate_custom_paths([])
    assert CONF in scope and DROPINS in scope


def test_agent_hashes_request_key_files_without_running_their_programs(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    conf = tmp_path / 'request-key.conf'
    conf.write_text(f'create user * * /usr/bin/touch {marker}\n')
    dropins = tmp_path / 'request-key.d'
    dropins.mkdir()
    (dropins / 'mpk.conf').write_text(f'create * mpk:* * |/usr/bin/touch {marker}\n')
    (dropins / 'alias.conf').symlink_to(conf)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(dropins), str(tmp_path / 'absent.d')))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(conf),))
    result = agent.persistence_inventory(time.monotonic() + 5)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected'
    assert set(rows) == {str(conf), str(dropins / 'mpk.conf'), str(dropins / 'alias.conf')}
    assert rows[str(dropins / 'mpk.conf')]['sha256'] and rows[str(dropins / 'alias.conf')]['kind'] == 'symlink'
    assert result['missing_roots'] == [str(tmp_path / 'absent.d')]
    assert not marker.exists()
    persistence.validate(result)


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == [CONF, DROPINS] and 'previously_custom' not in result


def test_dropin_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-1]['sha256'] = 'd' * 64
    after['entries'].append(entry(DROPINS + '/new.conf'))
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind']) for c in result['changes']] == [
        (DROPINS + '/cifs.idmap.conf', 'changed'), (DROPINS + '/new.conf', 'added')]


def test_earlier_custom_dropin_path_is_still_compared_after_promotion():
    custom = DROPINS + '/cifs.idmap.conf'
    before = inventory(scope=(*EARLIER, custom), entries=[entry('/etc/crontab'), entry(custom, 'e')])
    after = upgraded(inventory(scope=EARLIER, entries=[entry('/etc/crontab')]))
    after['entries'][-1]['sha256'] = 'f' * 64
    result = persistence.compare(before, after)
    assert result['state'] == 'compared' and result['previously_custom'] == [custom]
    # The earlier custom file was observed, so its change is evidence; the new conf file is newly covered.
    assert [(c['path'], c['kind']) for c in result['changes']] == [(custom, 'changed')]


@pytest.mark.parametrize('extra', ['/etc/request-key.d.bak', '/etc/request-key.conf.dpkg-old', '/sbin/request-key',
                                   '/etc/keyutils', '/etc/request-keys'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_narrowed_scope_outside_new_built_in_directories_is_not_comparable():
    before = inventory(scope=(*EARLIER, '/opt/app/startup'))
    assert persistence.compare(before, upgraded(inventory()))['state'] == 'unavailable'


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


@pytest.mark.parametrize('stored', [[CONF], [DROPINS], [DROPINS + '/a.conf', DROPINS + '/b.conf'], [DROPINS + '/sub/x']])
def test_stored_custom_paths_stay_valid_and_are_covered_once(stored):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(stored) == builtin
    assert agent.validate_custom_paths([*stored, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    agent.validate_inspection([], True, stored)


@pytest.mark.parametrize('stored', [[DROPINS, DROPINS], [DROPINS + '/a.conf'] * 2])
def test_duplicate_promoted_paths_are_rejected(stored):
    with pytest.raises(ValueError):
        agent.validate_custom_paths(stored)


@pytest.mark.parametrize('value', [DROPINS + '/../shadow', DROPINS + '/a/../b', DROPINS + '/a\nb', DROPINS + '/', DROPINS + '//x'])
def test_non_canonical_paths_inside_the_directory_are_not_promoted(value):
    assert not agent.promoted_custom_path(value)
    with pytest.raises(ValueError):
        agent.validate_custom_paths([value])


def test_sibling_path_is_not_promoted_and_stays_additional_scope():
    sibling = '/etc/request-key.d.bak/x'
    assert not agent.promoted_custom_path(sibling)
    assert agent.validate_custom_paths([sibling])[-1] == sibling


def test_promoted_custom_dropin_is_not_traversed_twice(tmp_path, monkeypatch):
    dropins = tmp_path / 'request-key.d'
    dropins.mkdir()
    (dropins / 'one.conf').write_text('create user * * /bin/true\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(dropins),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    monkeypatch.setattr(agent, 'PROMOTED_PERSISTENCE_ROOTS', (str(dropins),))
    result = agent.persistence_inventory(time.monotonic() + 5, [str(dropins / 'one.conf')])
    assert [r['path'] for r in result['entries']] == [str(dropins / 'one.conf')]


def test_catalogs_label_paths_and_state_the_gap():
    assert startup_inventory.mechanism(CONF) == ('request_key', 'keyutils request-key configuration')
    assert startup_inventory.mechanism(DROPINS + '/x.conf') == ('request_key_d', 'keyutils request-key drop-ins')
    assert startup_inventory.mechanism('/etc/request-key.conf.dpkg-old') == ('additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['request_key']['observed_files'] == 1 and rows['request_key_d']['observed_files'] == 1
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'request_key')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'event' and mechanism['scope'] == 'system'
    assert [loc['path'] for loc in mechanism['locations']] == [DROPINS, CONF]
    for family in ('debian', 'rpm'):
        assert CONF in startup_catalog._all_locations(family) and DROPINS in startup_catalog._all_locations(family)
    assert any(CONF in gap and DROPINS in gap and 'not yet parsed' in gap for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [CONF, DROPINS + '/cifs.idmap.conf'], 'enabled': True, 'interval_hours': 12,
                                 'expected_revision': current['revision']})
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
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == [CONF, DROPINS]
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows[CONF]['change'] == 'not_in_baseline' and rows[CONF]['mechanism'] == 'request_key'
    assert rows[DROPINS + '/cifs.idmap.conf']['change'] == 'not_in_baseline'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged'


def test_startup_view_keeps_earlier_custom_dropin_compared(admin):
    custom = DROPINS + '/cifs.idmap.conf'
    before = inventory(scope=(*EARLIER, custom), entries=[entry('/etc/crontab'), entry(custom, 'e')])
    status = store(before, upgraded(inventory(scope=EARLIER, entries=[entry('/etc/crontab')])))
    assert status['state'] == 'matches' and status['comparison']['previously_custom'] == [custom]
    rows = {r['path']: r for r in admin.get('/api/hosts/one/security/startup-inventory').json()['items']}
    assert rows[custom]['change'] == 'unchanged' and rows[CONF]['change'] == 'not_in_baseline'
