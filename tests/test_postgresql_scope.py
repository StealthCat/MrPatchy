"""PostgreSQL cluster configuration joins built-in startup scope without invalidating baselines (#1597)."""
import copy
import hashlib
import os
import time
from pathlib import Path

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

PG = '/etc/postgresql'
CONF = PG + '/16/main/postgresql.conf'
# The built-in scope an agent reported before this increment.
EARLIER = tuple(p for p in agent.validate_custom_paths([]) if p != PG)


def entry(path, sha='a', mode=0o644):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': mode, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    after = copy.deepcopy(before)
    after['scope'].append(PG)
    if present:
        # Ubuntu 24.04 postgresql-16 / postgresql-common 257 layout created by pg_createcluster.
        after['entries'] += [entry(CONF, 'b'), entry(PG + '/16/main/pg_hba.conf', 'c', 0o640),
                             entry(PG + '/16/main/start.conf', 'd'), entry(PG + '/16/main/environment', 'e')]
    else:
        after['missing_roots'].append(PG)
    return after


def test_agent_built_in_scope_includes_postgresql():
    assert PG in agent.PERSISTENCE_ROOTS and PG in agent.PROMOTED_PERSISTENCE_ROOTS
    assert PG in agent.validate_custom_paths([]) and PG in persistence.ADDITIVE_BUILTIN_SCOPE
    assert PG not in agent.SYMLINK_RECORDED_ROOTS
    # The RPM data directory is not built-in scope: it holds the whole database cluster.
    assert not any(p.startswith('/var/lib/pgsql') for p in agent.validate_custom_paths([]))
    assert len(agent.validate_custom_paths([f'/opt/app{i}' for i in range(16)])) <= persistence.MAX_SCOPE


def cluster_tree(tmp_path, marker):
    main = tmp_path / 'etc' / 'postgresql' / '16' / 'main'
    (main / 'conf.d').mkdir(parents=True)
    (main / 'postgresql.conf').write_text(
        "data_directory = '/var/lib/postgresql/16/main'\narchive_mode = on\n"
        f"archive_command = 'touch {marker}'\ninclude_dir = 'conf.d'\n")
    (main / 'conf.d' / 'zz.conf').write_text(f"ssl_passphrase_command = 'touch {marker}'\n")
    (main / 'pg_hba.conf').write_text('host all all 0.0.0.0/0 password-secret-marker\n')
    (main / 'pg_hba.conf').chmod(0o640)
    (main / 'start.conf').write_text('auto\n')
    (main / 'conf.d' / 'link.conf').symlink_to('/var/lib/postgresql/16/main/postgresql.auto.conf')
    os.mkfifo(main / 'conf.d' / 'fifo')  # A special file must be excluded, never opened.
    return tmp_path / 'etc' / 'postgresql'


def test_agent_hashes_cluster_files_without_running_or_following_them(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root = cluster_tree(tmp_path, marker)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root), str(tmp_path / 'absent')))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    main = str(root / '16' / 'main')
    assert set(rows) == {main + '/postgresql.conf', main + '/conf.d/zz.conf', main + '/pg_hba.conf',
                         main + '/start.conf', main + '/conf.d/link.conf'}
    conf = (root / '16' / 'main' / 'postgresql.conf').read_bytes()
    assert rows[main + '/postgresql.conf']['sha256'] == hashlib.sha256(conf).hexdigest()
    assert rows[main + '/pg_hba.conf']['mode'] == 0o640
    assert rows[main + '/conf.d/link.conf'] == {**rows[main + '/conf.d/link.conf'], 'kind': 'symlink',
                                                 'target': '/var/lib/postgresql/16/main/postgresql.auto.conf'}
    assert result['gaps'] == [main + '/conf.d/fifo: Non-regular entry excluded'] and result['state'] == 'incomplete'
    assert result['missing_roots'] == [str(tmp_path / 'absent')]
    assert not marker.exists()
    # Metadata and SHA-256 only: no configuration text, commands or pg_hba.conf content are stored.
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    assert 'archive_command' not in repr(result) and 'password-secret-marker' not in repr(result)
    persistence.validate(result)


@pytest.mark.skipif(not Path(CONF).is_file() or os.geteuid() != 0,
                    reason='needs a native Debian PostgreSQL 16 cluster and root, as the agent runs')
def test_native_debian_cluster_layout_is_hashed(monkeypatch):
    # Ubuntu 24.04 postgresql-16 cluster created by pg_createcluster (postgresql-common 257).
    # pg_hba.conf and pg_ident.conf are 0640 postgres, so only root (the agent's account) reads them.
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (PG,))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    result = agent.persistence_inventory(time.monotonic() + 30)
    rows = {r['path']: r for r in result['entries']}
    names = {Path(p).name for p in rows if p.startswith(PG + '/16/main/')}
    assert {'postgresql.conf', 'pg_hba.conf', 'pg_ident.conf', 'start.conf', 'pg_ctl.conf', 'environment'} <= names
    assert rows[CONF]['sha256'] == hashlib.sha256(Path(CONF).read_bytes()).hexdigest()
    assert PG in result['scope'] and PG not in result['missing_roots']
    assert not any(g.startswith(PG) for g in result['gaps'])
    persistence.validate(result)


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == [PG] and 'previously_custom' not in result


def test_postgresql_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    rows = {r['path']: r for r in after['entries']}
    rows[CONF]['sha256'] = 'f' * 64
    after['entries'].append(entry(PG + '/16/main/conf.d/archive.conf'))
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert sorted((c['path'], c['kind']) for c in result['changes']) == [
        (PG + '/16/main/conf.d/archive.conf', 'added'), (CONF, 'changed')]


@pytest.mark.parametrize('stored', [[PG], [CONF], [PG + '/16/main', '/opt/app/startup']])
def test_earlier_custom_postgresql_path_is_still_compared_after_promotion(stored):
    customs = [entry(CONF, 'c')]
    before = inventory(scope=(*EARLIER, *stored), entries=[entry('/etc/crontab'), *customs])
    after = inventory(scope=(*EARLIER, PG, *[p for p in stored if not p.startswith(PG)]),
                      entries=[entry('/etc/crontab'), *copy.deepcopy(customs)])
    after['entries'][-1]['sha256'] = 'f' * 64
    result = persistence.compare(before, after)
    pg_stored = [p for p in stored if p.startswith(PG)]
    assert result['state'] == 'compared' and result.get('previously_custom', []) == sorted(set(pg_stored) - {PG})
    assert result.get('newly_in_scope', []) == ([] if PG in stored else [PG])
    assert [(c['path'], c['kind']) for c in result['changes']] == [(CONF, 'changed')]


@pytest.mark.parametrize('extra', ['/etc/postgresql-common', '/etc/postgresql.bak', '/var/lib/pgsql/data',
                                   '/var/lib/postgresql/16/main/postgresql.auto.conf'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


@pytest.mark.parametrize('stored', [[PG], [CONF], [PG + '/16/main/conf.d', '/etc/sv/ssh']])
def test_stored_custom_paths_stay_valid_and_are_covered_once(stored):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(stored) == builtin
    assert agent.validate_custom_paths([*stored, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    agent.validate_inspection([], True, stored)


@pytest.mark.parametrize('value', ['/etc/postgresql-common/pg_upgradecluster.d', '/etc/postgresql.bak',
                                   '/var/lib/pgsql/data/postgresql.conf', '/var/lib/pgsql/data',
                                   '/var/lib/postgresql/16/main/postgresql.auto.conf'])
def test_neighbouring_and_data_directory_paths_stay_additional_scope(value):
    # The RPM-family and Debian data-directory files can still be hashed as custom paths,
    # and a saved custom /var/lib/pgsql/data stays valid (it does not overlap built-in scope).
    assert not agent.promoted_custom_path(value)
    assert agent.validate_custom_paths([value])[-1] == value


@pytest.mark.parametrize('value', [PG + '/../shadow', PG + '/', PG + '//16', PG + '/a\nb'])
def test_non_canonical_paths_inside_the_directory_are_not_promoted(value):
    assert not agent.promoted_custom_path(value)
    with pytest.raises(ValueError):
        agent.validate_custom_paths([value])


def test_catalogs_label_paths_and_state_the_gap():
    assert startup_inventory.mechanism(CONF) == ('postgresql', 'PostgreSQL cluster configuration')
    assert startup_inventory.mechanism('/etc/postgresql-common/createcluster.conf') == (
        'additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['postgresql']['observed_files'] == 4
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'postgresql')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'event' and mechanism['scope'] == 'system'
    assert [(loc['path'], loc['families']) for loc in mechanism['locations']] == [
        (PG, ('debian',)), ('/var/lib/pgsql/data', ('rpm',))]
    assert PG in startup_catalog._all_locations('debian') and PG not in startup_catalog._all_locations('rpm')
    assert any(PG in gap and 'evaluate' in gap and 'blocking gap' in gap and 'postgresql.auto.conf' in gap and '/var/lib/pgsql' in gap
               for gap in startup_inventory.GAPS)


def test_rpm_data_directory_is_reported_as_not_collected():
    scope = agent.validate_custom_paths([])
    result = startup_catalog.coverage('rpm', scope, [])
    row = next(m for m in result['mechanisms'] if m['id'] == 'postgresql')
    assert {loc['path']: loc['state'] for loc in row['locations']} == {'/var/lib/pgsql/data': 'not_collected'}


def test_saved_monitor_policy_with_promoted_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [CONF, '/var/lib/pgsql/data'], 'enabled': True,
                                 'interval_hours': 12, 'expected_revision': current['revision']})
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
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == [PG]
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    assert rows[CONF]['change'] == 'not_in_baseline' and rows[CONF]['mechanism'] == 'postgresql'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged'
