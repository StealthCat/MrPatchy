"""strongSwan swanctl configuration joins built-in startup scope without invalidating baselines (#1624)."""
import copy
import time

import pytest

from app import persistence, startup_catalog, startup_inventory
from app.db import Host, Session, Setting
from app.incidents import Inspection, PersistenceBaseline, digest
from target import agent

SWANCTL = '/etc/swanctl'
RPM = '/etc/strongswan'
ROOTS = (SWANCTL, RPM)
EARLIER = ('/etc/cron.d', '/etc/crontab', '/etc/anacrontab', '/etc/hosts.allow', '/etc/hosts.deny',
           '/etc/rsnapshot.conf', '/etc/gitconfig', '/etc/kdump.conf', '/etc/auto.master',
           '/etc/request-key.d', '/etc/request-key.conf', '/etc/clamav', '/etc/clamd.d', '/etc/freshclam.conf',
           '/etc/dovecot')




def entry(path, sha='a'):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'size': 4, 'mtime_ns': 1, 'sha256': sha * 64}


def inventory(scope=EARLIER, entries=None):
    rows = [entry('/etc/cron.d/etckeeper'), entry('/etc/crontab')] if entries is None else entries
    return {'scope': list(scope), 'state': 'collected', 'entries': rows, 'gaps': [], 'skipped': 0, 'missing_roots': []}


def upgraded(before, present=True):
    """A newer agent: Debian layout present, the RPM-family directory absent."""
    after = copy.deepcopy(before)
    after['scope'] += list(ROOTS)
    if present:
        after['entries'] += [entry(SWANCTL + '/swanctl.conf', 'c'), entry(SWANCTL + '/conf.d/site.conf', 'e')]
        after['missing_roots'].append(RPM)
    else:
        after['missing_roots'] += list(ROOTS)
    return after


def test_agent_built_in_scope_includes_both_directories():
    for root in ROOTS:
        assert root in agent.PERSISTENCE_ROOTS and root in agent.PROMOTED_PERSISTENCE_ROOTS
        assert root in agent.validate_custom_paths([])
        assert root in persistence.ADDITIVE_BUILTIN_SCOPE
    # The Debian-family strongswan.conf and its drop-ins are not in built-in scope yet.
    for path in ('/etc/strongswan.conf', '/etc/strongswan.d', '/etc/ipsec.conf', '/etc/ipsec.d'):
        assert path not in agent.PERSISTENCE_ROOTS and path not in agent.PERSISTENCE_FILES


def _tree(root, marker, nested=''):
    base = root / nested if nested else root
    (base / 'conf.d').mkdir(parents=True)
    (base / 'private').mkdir(mode=0o700)
    (base / 'swanctl.conf').write_text('include conf.d/*.conf\n')
    (base / 'conf.d' / 'site.conf').write_text(
        f'connections {{ site {{ children {{ net {{ updown = /usr/bin/touch {marker} }} }} }} }}\n')
    script = base / 'updown.sh'
    script.write_text(f'#!/bin/sh\ntouch {marker}\n')
    script.chmod(0o755)
    key = base / 'private' / 'site.key'
    key.write_text('-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n')
    key.chmod(0o600)
    (base / 'x509').mkdir()
    (base / 'x509' / 'site.pem').symlink_to('/etc/ssl/certs/ssl-cert-snakeoil.pem')
    return base, script, key


@pytest.mark.parametrize('nested', ['', 'swanctl'])
def test_agent_hashes_swanctl_files_without_running_or_parsing_them(tmp_path, monkeypatch, nested):
    marker = tmp_path / 'ran'
    root = tmp_path / 'strongswan'
    base, script, key = _tree(root, marker, nested)
    extra = set()
    if nested:
        # RPM-family layout: swanctl/ sits beside strongswan.conf and strongswan.d.
        (root / 'strongswan.conf').write_text('charon { plugins { updown { load = yes } } }\n')
        (root / 'strongswan.d').mkdir()
        (root / 'strongswan.d' / 'charon.conf').write_text('charon { }\n')
        extra = {str(root / 'strongswan.conf'), str(root / 'strongswan.d' / 'charon.conf')}
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', (str(root), str(tmp_path / 'absent.d')))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    rows = {r['path']: r for r in result['entries']}
    assert result['state'] == 'collected'
    assert set(rows) == {str(base / 'swanctl.conf'), str(base / 'conf.d' / 'site.conf'), str(script), str(key),
                         str(base / 'x509' / 'site.pem'), *extra}
    assert rows[str(script)]['mode'] == 0o755 and rows[str(key)]['mode'] == 0o600
    # The symlink target is recorded, not followed.
    assert rows[str(base / 'x509' / 'site.pem')]['kind'] == 'symlink'
    assert rows[str(base / 'x509' / 'site.pem')]['target'] == '/etc/ssl/certs/ssl-cert-snakeoil.pem'
    assert result['missing_roots'] == [str(tmp_path / 'absent.d')]
    assert not marker.exists()
    # Metadata and SHA-256 only: no content or parsed detail is attached, even with job parsing enabled.
    assert all(set(row) <= {'path', 'kind', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'sha256', 'target'}
               for row in result['entries'])
    assert 'PRIVATE' not in repr(result) and 'not-a-real-key' not in repr(result) and 'touch' not in repr(result)
    persistence.validate(result)


@pytest.mark.parametrize('present', [True, False])
def test_earlier_baseline_compares_within_its_scope(present):
    before = inventory()
    result = persistence.compare(before, upgraded(before, present))
    assert result['state'] == 'compared' and result['changes'] == []
    assert result['newly_in_scope'] == sorted(ROOTS) and 'previously_custom' not in result


def test_pre_request_key_baseline_accepts_every_promoted_path_together():
    before = inventory(scope=('/etc/cron.d', '/etc/crontab'))
    after = upgraded(before)
    after['scope'] += list(EARLIER[2:])
    result = persistence.compare(before, after)
    assert result['state'] == 'compared'
    assert result['newly_in_scope'] == sorted([*EARLIER[2:], *ROOTS])


def test_swanctl_changes_are_reported_once_both_inventories_cover_them():
    before = upgraded(inventory())
    after = copy.deepcopy(before)
    after['entries'][-1]['sha256'] = 'd' * 64
    after['entries'].append(entry(SWANCTL + '/conf.d/zz-local.conf'))
    result = persistence.compare(before, after)
    assert 'newly_in_scope' not in result
    assert [(c['path'], c['kind']) for c in result['changes']] == [
        (SWANCTL + '/conf.d/site.conf', 'changed'), (SWANCTL + '/conf.d/zz-local.conf', 'added')]


@pytest.mark.parametrize(('stored', 'observed'), [
    ([SWANCTL], SWANCTL + '/swanctl.conf'), ([SWANCTL + '/swanctl.conf'], SWANCTL + '/swanctl.conf'),
    ([SWANCTL + '/conf.d', SWANCTL + '/swanctl.conf'], SWANCTL + '/conf.d/site.conf'),
    ([RPM + '/swanctl'], RPM + '/swanctl/swanctl.conf'), ([RPM], RPM + '/strongswan.conf')])
def test_earlier_custom_swanctl_path_is_still_compared_after_promotion(stored, observed):
    customs = [entry(observed, 'c')]
    before = inventory(scope=(*EARLIER, *stored), entries=[entry('/etc/crontab'), *customs])
    after = inventory(scope=(*EARLIER, *ROOTS), entries=[entry('/etc/crontab'), *copy.deepcopy(customs)])
    after['entries'][-1]['sha256'] = 'f' * 64
    result = persistence.compare(before, after)
    # A stored path equal to a new built-in directory stays in scope; only paths inside one were removed.
    assert result['state'] == 'compared' and result.get('previously_custom', []) == sorted(set(stored) - set(ROOTS))
    assert result.get('newly_in_scope', []) == sorted(set(ROOTS) - set(stored))
    # The earlier custom file was observed, so its change is evidence rather than newly covered.
    assert [(c['path'], c['kind']) for c in result['changes']] == [(customs[0]['path'], 'changed')]


@pytest.mark.parametrize('extra', ['/etc/strongswan.conf', '/etc/strongswan.d', '/etc/ipsec.conf', '/etc/ipsec.d',
                                   '/etc/swanctl.bak', '/etc/strongswan-old', '/usr/lib/ipsec', '/var/lib/strongswan'])
def test_unreviewed_neighbouring_paths_remain_non_additive(extra):
    before = inventory()
    after = upgraded(before)
    after['scope'].append(extra)
    result = persistence.compare(before, after)
    assert result['state'] == 'unavailable' and 'scope changed' in result['note']


def test_agent_downgrade_is_not_additive():
    after = inventory()
    assert persistence.compare(upgraded(after), after)['state'] == 'unavailable'


@pytest.mark.parametrize('stored', [[SWANCTL], [SWANCTL + '/swanctl.conf', SWANCTL + '/conf.d'],
                                    [RPM], [RPM + '/swanctl/conf.d/site.conf', RPM + '/strongswan.conf']])
def test_stored_custom_paths_stay_valid_and_are_covered_once(stored):
    builtin = agent.validate_custom_paths([])
    assert agent.validate_custom_paths(stored) == builtin
    assert agent.validate_custom_paths([*stored, '/opt/app/startup']) == builtin + ['/opt/app/startup']
    agent.validate_inspection([], True, stored)


@pytest.mark.parametrize('root', ROOTS)
def test_duplicate_promoted_paths_are_rejected(root):
    with pytest.raises(ValueError):
        agent.validate_custom_paths([root, root])


@pytest.mark.parametrize('value', ['/etc/strongswan.conf', '/etc/strongswan.d', '/etc/swanctl.bak',
                                   '/etc/strongswan-old/x', '/etc/ipsec.d'])
def test_sibling_paths_are_not_promoted_and_stay_additional_scope(value):
    assert not agent.promoted_custom_path(value)
    assert agent.validate_custom_paths([value])[-1] == value


@pytest.mark.parametrize('value', [SWANCTL + '/../shadow', SWANCTL + '/', RPM + '//x', RPM + '/a\nb'])
def test_non_canonical_paths_inside_the_directory_are_not_promoted(value):
    assert not agent.promoted_custom_path(value)
    with pytest.raises(ValueError):
        agent.validate_custom_paths([value])


def test_catalogs_label_paths_and_state_the_gap():
    assert startup_inventory.mechanism(SWANCTL + '/swanctl.conf') == ('strongswan', 'strongSwan swanctl configuration')
    assert startup_inventory.mechanism(SWANCTL + '/conf.d/site.conf') == ('strongswan', 'strongSwan swanctl configuration')
    assert startup_inventory.mechanism(RPM + '/swanctl/swanctl.conf') == ('strongswan_rpm', 'strongSwan configuration')
    for other in ('/etc/strongswan.conf', '/etc/strongswan.d/charon.conf', '/etc/swanctl.bak/x.conf'):
        assert startup_inventory.mechanism(other) == ('additional', 'Additional inventory scope')
    rows = {r['id']: r for r in startup_inventory.catalog_rows(upgraded(inventory()))}
    assert rows['strongswan']['observed_files'] == 2 and rows['strongswan_rpm']['observed_files'] == 0
    mechanism = next(m for m in startup_catalog._MECHANISMS if m['id'] == 'strongswan')
    assert mechanism['parse'] == 'metadata' and mechanism['trigger'] == 'event' and mechanism['scope'] == 'system'
    assert [(loc['path'], loc['families']) for loc in mechanism['locations']] == [(SWANCTL, ('debian',)),
                                                                                  (RPM, ('rpm',))]
    assert SWANCTL in startup_catalog._all_locations('debian') and RPM not in startup_catalog._all_locations('debian')
    assert RPM in startup_catalog._all_locations('rpm') and SWANCTL not in startup_catalog._all_locations('rpm')
    assert any(SWANCTL in gap and RPM in gap and 'updown' in gap and 'This view evaluates swanctl.conf' in gap and 'secrets, is dropped' in gap
               and '/etc/strongswan.conf' in gap and 'leftupdown' in gap for gap in startup_inventory.GAPS)


def test_saved_monitor_policy_with_promoted_paths_is_accepted(admin):
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.commit()
    url = '/api/hosts/one/security/persistence-monitor'
    current = admin.get(url).json()
    saved = admin.put(url, json={'custom_paths': [SWANCTL + '/swanctl.conf', SWANCTL + '/conf.d', RPM + '/swanctl'],
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
    assert status['state'] == 'matches' and status['comparison']['newly_in_scope'] == sorted(ROOTS)
    view = admin.get('/api/hosts/one/security/startup-inventory').json()
    rows = {r['path']: r for r in view['items']}
    conf = rows[SWANCTL + '/swanctl.conf']
    assert conf['change'] == 'not_in_baseline' and conf['mechanism'] == 'strongswan'
    assert rows['/etc/cron.d/etckeeper']['change'] == 'unchanged'
