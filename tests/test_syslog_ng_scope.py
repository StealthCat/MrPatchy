"""syslog-ng configuration joins built-in startup scope without invalidating baselines (#1570)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

ROOT = '/etc/syslog-ng'
DEFAULTS = '/etc/default/syslog-ng'
SYSCONFIG = '/etc/sysconfig/syslog-ng'
FILES = (DEFAULTS, SYSCONFIG)
NEW = (ROOT, *FILES)
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/kdump.conf', '/etc/auto.master',
           '/etc/dovecot', '/etc/lighttpd')
METADATA = {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}


def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None, missing=()):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0,
            'missing_roots': list(missing)}


def upgraded(before):
    """A newer Debian-family agent: the directory and the defaults file present, sysconfig absent."""
    after = copy.deepcopy(before)
    after['scope'] += list(NEW)
    after['entries'] += [entry(ROOT + '/syslog-ng.conf', 'c'), entry(ROOT + '/conf.d/remote.conf', 'e'),
                         entry(DEFAULTS, 'b')]
    after['missing_roots'].append(SYSCONFIG)
    return after


def test_agent_built_in_scope_holds_the_directory_and_option_files():
    assert ROOT in agent.PERSISTENCE_ROOTS and ROOT in agent.PROMOTED_PERSISTENCE_ROOTS
    assert set(FILES) <= set(agent.PERSISTENCE_FILES) and set(FILES) <= set(agent.PROMOTED_PERSISTENCE_FILES)
    assert set(FILES) <= set(agent.NESTED_PERSISTENCE_FILES)
    assert set(NEW) <= set(agent.validate_custom_paths([]))
    assert set(NEW) <= set(persistence.ADDITIVE_BUILTIN_SCOPE)
    # Neither options directory, nor the SCL or the program() commands themselves, is built-in.
    for path in ('/etc/default', '/etc/sysconfig', '/usr/share/syslog-ng', '/usr/share/syslog-ng/include'):
        assert path not in agent.PERSISTENCE_ROOTS and path not in agent.PERSISTENCE_FILES
        assert path not in persistence.ADDITIVE_BUILTIN_SCOPE


def _tree(tmp_path, marker):
    root = tmp_path / 'syslog-ng'
    (root / 'conf.d').mkdir(parents=True)
    (root / 'patterndb.d').mkdir()
    (root / 'syslog-ng.conf').write_text(
        '@version: 4.3\n@include "scl.conf"\n@include "/etc/syslog-ng/conf.d/*.conf"\n'
        f'destination d_probe {{ program("/usr/bin/touch {marker}"); }};\n'
        'log { source(s_src); destination(d_probe); };\n')
    (root / 'scl.conf').write_text('@include "scl/*/*.conf"\n')
    (root / 'conf.d' / 'remote.conf').write_text(
        f'destination d_remote {{ network("192.0.2.10" hook-commands(startup("touch {marker}"))'
        ' tls(key-file("/etc/syslog-ng/key.d/client.key"))); };\n')
    (root / 'patterndb.d' / 'local.xml').write_text('<patterndb version="4"/>\n')
    (root / 'key.d').mkdir(mode=0o700)
    key = root / 'key.d' / 'client.key'
    key.write_text('-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n')
    key.chmod(0o600)
    (root / 'cert.d').mkdir()
    (root / 'cert.d' / 'ca.pem').symlink_to('/etc/ssl/certs/ca-certificates.crt')
    defaults = tmp_path / 'default' / 'syslog-ng'
    defaults.parent.mkdir()
    defaults.write_text(f'SYSLOGNG_OPTS="--user=root --no-caps -f /opt/{marker.name}.conf"\n')
    return root, key, defaults


def test_agent_hashes_syslog_ng_files_without_running_or_parsing_them(tmp_path, monkeypatch):
    marker = tmp_path / 'ran'
    root, key, defaults = _tree(tmp_path, marker)
    sysconfig = tmp_path / 'sysconfig' / 'syslog-ng'
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root),))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(defaults), str(sysconfig)))
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected'
    assert set(rows) == {str(root / 'syslog-ng.conf'), str(root / 'scl.conf'), str(root / 'conf.d' / 'remote.conf'),
                         str(root / 'patterndb.d' / 'local.xml'), str(key), str(root / 'cert.d' / 'ca.pem'),
                         str(defaults)}
    assert rows[str(key)]['mode'] == 0o600 and all(rows[p]['sha256'] for p in rows if p != str(root / 'cert.d' / 'ca.pem'))
    # The symlink target is recorded, not followed.
    assert rows[str(root / 'cert.d' / 'ca.pem')]['kind'] == 'symlink'
    assert rows[str(root / 'cert.d' / 'ca.pem')]['target'] == '/etc/ssl/certs/ca-certificates.crt'
    assert result['missing_roots'] == [str(sysconfig)]
    assert not marker.exists()
    # Metadata and SHA-256 only: no content or parsed detail is attached, even with job parsing enabled.
    assert all(set(row) <= METADATA for row in result['entries'])
    text = repr(result)
    assert 'PRIVATE' not in text and 'not-a-real-key' not in text and 'touch' not in text and 'SYSLOGNG_OPTS' not in text
    persistence.validate(result)


def test_absent_syslog_ng_paths_are_missing_not_gaps(tmp_path, monkeypatch):
    paths = (str(tmp_path / 'syslog-ng'),)
    files = (str(tmp_path / 'default' / 'syslog-ng'), str(tmp_path / 'sysconfig' / 'syslog-ng'))
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', paths)
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    result = agent.persistence_inventory(time.monotonic() + 5)
    assert result['state'] == 'collected' and not result['entries'] and not result['gaps']
    assert sorted(result['missing_roots']) == sorted([*paths, *files])


@pytest.mark.parametrize('directory', ['default', 'sysconfig'])
def test_custom_options_directory_leaves_the_option_file_to_built_in_scope(tmp_path, monkeypatch, directory):
    options = tmp_path / directory
    options.mkdir()
    (options / 'syslog-ng').write_text('SYSLOGNG_OPTS="--no-caps"\n')
    (options / 'other-package').write_text('OPTS=""\n')
    files = (str(options / 'syslog-ng'),)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', files)
    monkeypatch.setattr(agent, 'NESTED_PERSISTENCE_FILES', files)
    assert agent.validate_custom_paths([str(options)]) == [*files, str(options)]
    result = agent.persistence_inventory(time.monotonic() + 5, custom_paths=[str(options)])
    paths = [r['path'] for r in result['entries']]
    assert result['state'] == 'collected'
    assert sorted(paths) == sorted([*files, str(options / 'other-package')]) and len(paths) == len(set(paths))
    persistence.validate({**result, 'scope': [*files, str(options)]})


def test_earlier_baseline_compares_within_its_scope_and_lists_new_paths():
    before = inventory()
    comparison = persistence.compare(before, upgraded(before))
    assert comparison['state'] == 'compared' and comparison['changes'] == []
    assert comparison['newly_in_scope'] == sorted(NEW) and 'previously_custom' not in comparison


def test_syslog_ng_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-2]['sha256'] = 'd' * 64
    after['entries'][-1]['sha256'] = 'f' * 64
    after['entries'].append(entry(ROOT + '/conf.d/zz-exfil.conf'))
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind']) for c in result['changes']] == [
        (DEFAULTS, 'changed'), (ROOT + '/conf.d/remote.conf', 'changed'), (ROOT + '/conf.d/zz-exfil.conf', 'added')]


@pytest.mark.parametrize(('stored', 'observed'), [
    ([ROOT], ROOT + '/syslog-ng.conf'), ([ROOT + '/syslog-ng.conf'], ROOT + '/syslog-ng.conf'),
    ([ROOT + '/conf.d', ROOT + '/syslog-ng.conf'], ROOT + '/conf.d/remote.conf'),
    (['/etc/default'], DEFAULTS), ([DEFAULTS], DEFAULTS), (['/etc/sysconfig'], SYSCONFIG)])
def test_earlier_custom_path_is_still_compared_after_promotion(stored, observed):
    customs = [entry(observed, 'c')]
    before = inventory(scope=(*EARLIER, *stored), entries=[entry('/etc/crontab'), *customs])
    after = inventory(scope=(*EARLIER, *[p for p in stored if p not in NEW and not p.startswith(ROOT + '/')], *NEW),
                      entries=[entry('/etc/crontab'), *copy.deepcopy(customs)])
    after['entries'][-1]['sha256'] = 'f' * 64
    result = persistence.compare(before, after)
    assert result['state'] == 'compared'
    # A stored path inside the new built-in directory is covered by it; /etc/default and /etc/sysconfig stay custom.
    assert result.get('previously_custom', []) == sorted(p for p in stored if p.startswith(ROOT + '/'))
    assert result.get('newly_in_scope', []) == sorted(p for p in NEW if not any(p == s or p.startswith(s + '/') for s in stored))
    # The earlier custom path observed the file, so its change is evidence rather than newly covered.
    assert [(c['path'], c['kind']) for c in result['changes']] == [(observed, 'changed')]


@pytest.mark.parametrize('extra', ['/etc/default', '/etc/sysconfig', '/etc/syslog-ng.bak', '/etc/syslog-ng-old',
                                   '/usr/share/syslog-ng', '/etc/default/syslog', '/etc/sysconfig/syslog',
                                   '/etc/rsyslog.conf', '/var/lib/syslog-ng'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


@pytest.mark.parametrize('stored', [[ROOT], [ROOT + '/syslog-ng.conf', ROOT + '/conf.d'], [DEFAULTS],
                                    [SYSCONFIG, ROOT + '/scl.conf']])
def test_stored_promoted_paths_stay_valid_and_are_covered_once(stored):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(stored) == builtin
    assert agent.validate_custom_paths([*stored, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    agent.validate_inspection([], True, stored)


@pytest.mark.parametrize('stored', [['/etc/default'], ['/etc/sysconfig'], ['/etc/default', '/etc/sysconfig']])
def test_stored_options_directories_stay_valid_as_custom_scope(stored):
    scope = agent.validate_custom_paths(list(stored))
    assert scope[-len(stored):] == stored and set(FILES) <= set(scope) and len(set(scope)) == len(scope)


@pytest.mark.parametrize('path', [ROOT, DEFAULTS, SYSCONFIG])
def test_duplicate_promoted_paths_are_rejected(path):
    with pytest.raises(ValueError):
        agent.validate_custom_paths([path, path])


@pytest.mark.parametrize('stored', [['/etc'], ['/etc/default', '/etc/default/locale'], ['/etc/syslog-ng/'],
                                    ['/etc/syslog-ng/../cron.d'], [ROOT + '/a\nb']])
def test_overlapping_or_non_canonical_paths_are_rejected(stored):
    with pytest.raises(ValueError):
        agent.validate_custom_paths(list(stored))


@pytest.mark.parametrize('value', ['/etc/syslog-ng.bak', '/etc/syslog-ng-old/x', '/etc/default/syslog',
                                   '/etc/sysconfig/syslog', '/usr/share/syslog-ng/include'])
def test_sibling_paths_are_not_promoted_and_stay_additional_scope(value):
    assert not agent.promoted_custom_path(value)
    assert agent.validate_custom_paths([value])[-1] == value


def test_catalogs_label_paths_and_state_the_gap():
    assert startup_inventory.mechanism(ROOT + '/syslog-ng.conf') == ('syslog_ng', 'syslog-ng configuration')
    assert startup_inventory.mechanism(ROOT + '/conf.d/remote.conf') == ('syslog_ng', 'syslog-ng configuration')
    assert startup_inventory.mechanism(DEFAULTS) == ('syslog_ng_defaults', 'syslog-ng command-line defaults')
    assert startup_inventory.mechanism(SYSCONFIG) == ('syslog_ng_sysconfig', 'syslog-ng command-line options')
    for other in ('/etc/syslog-ng.bak/x.conf', '/etc/default/syslog', '/usr/share/syslog-ng/include/scl/x.conf'):
        assert startup_inventory.mechanism(other)[0] == 'additional'
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['syslog_ng']['observed_files'] == 2 and rows['syslog_ng_defaults']['observed_files'] == 1
    assert rows['syslog_ng_sysconfig']['observed_files'] == 0
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'syslog_ng')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'boot' and mechanism['scope'] == 'system'
    assert [(loc['path'], loc['families']) for loc in mechanism['locations']] == [
        (ROOT, ('debian', 'rpm')), (DEFAULTS, ('debian',)), (SYSCONFIG, ('rpm',))]
    assert ROOT in startup_catalog._all_locations('debian') and ROOT in startup_catalog._all_locations('rpm')
    assert DEFAULTS in startup_catalog._all_locations('debian') and DEFAULTS not in startup_catalog._all_locations('rpm')
    assert SYSCONFIG in startup_catalog._all_locations('rpm') and SYSCONFIG not in startup_catalog._all_locations('debian')
    gap = next(g for g in startup_inventory.GAPS if g.startswith('syslog-ng:'))
    assert 'not yet evaluated' in gap and 'program()' in gap and 'hook-commands()' in gap and 'confgen' in gap
    assert '/usr/share/syslog-ng/include' in gap and '--user' in gap and DEFAULTS in gap and SYSCONFIG in gap


def test_saved_monitor_policy_with_promoted_and_options_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [ROOT + '/syslog-ng.conf', ROOT + '/conf.d', '/etc/default'],
                                 'enabled': True, 'interval_hours': 12, 'expected_revision': current['revision']})
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
    rows = {r['path']: r for r in admin.get('/api/hosts/one/security/startup-inventory').json()['items']}
    conf = rows[ROOT + '/syslog-ng.conf']
    assert conf['change'] == 'not_in_baseline' and conf['mechanism'] == 'syslog_ng'
    assert rows[DEFAULTS]['change'] == 'not_in_baseline' and rows[DEFAULTS]['mechanism'] == 'syslog_ng_defaults'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged'
