"""#1375 increment 3: agent-reported master-map text and stat observations, resolved by the controller."""
import copy
import os
import time

import pytest

from app import autofs_program_maps, persistence, startup_inventory
from target import agent

MASTER = '/etc/auto.master'


def program_file(tmp_path, name='auto.prog', mode=0o755):
    marker = tmp_path / f'{name}.ran'
    path = tmp_path / name
    path.write_text(f'#!/bin/sh\ntouch {marker}\n')
    path.chmod(mode)
    return path, marker


def report(text, stats, truncated=False, mode=0o644):
    return {'text': text, 'error': None, 'stats': {MASTER: {'kind': 'regular', 'mode': mode}, **stats},
            'stats_truncated': truncated}


def entry(autofs, mode=0o644):
    return {'path': MASTER, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': mode, 'size': 10, 'mtime_ns': 1,
            'sha256': 'a' * 64, 'autofs': autofs}


def inventory(row):
    return {'scope': [MASTER], 'entries': [row], 'gaps': [], 'missing_roots': [], 'skipped': 0, 'state': 'collected'}


# --- agent -----------------------------------------------------------------

def test_agent_reports_text_and_stats_without_running_or_reading_maps(tmp_path):
    prog, marker = program_file(tmp_path)
    text_map = tmp_path / 'auto.text'
    text_map.write_text('k -fstype=nfs host:/x\n')
    text_map.chmod(0o600)
    text = (f'/net -hosts\n/prog program:{prog}\n/direct {prog} --timeout=60\n/text file:{text_map}\n'
            f'/gone {tmp_path}/absent\n# /commented {tmp_path}/hidden\n+auto.master\n')
    result = agent.parse_autofs_master(text.encode(), 0o644, time.monotonic() + 5)
    assert result['text'] == text and result['error'] is None and not result['stats_truncated']
    assert result['stats'][MASTER] == {'kind': 'regular', 'mode': 0o644}
    assert result['stats'][str(prog)] == {'kind': 'regular', 'mode': 0o755}
    assert result['stats'][str(text_map)] == {'kind': 'regular', 'mode': 0o600}
    assert result['stats'][f'{tmp_path}/absent'] == {'kind': 'missing', 'mode': 0}
    assert f'{tmp_path}/hidden' not in result['stats']
    assert not marker.exists()
    validated = entry(result)
    assert persistence.validate_autofs(result, MASTER, 0o644) == len(result['stats'])
    persistence.validate(inventory(validated))


def test_agent_never_stats_paths_at_or_below_a_mount_point(tmp_path, monkeypatch):
    calls = []
    real = os.stat
    monkeypatch.setattr(agent.os, 'stat', lambda p, *a, **k: calls.append(p) or real(p, *a, **k))
    mount = tmp_path / 'mnt'
    mount.mkdir()
    text = f'{mount} program:{mount}/inner\n{tmp_path}/other {mount}/deeper/map\n/ file:/etc/whatever\n'
    assert agent.autofs_candidates(f'{mount} program:{mount}/inner\n') == []
    agent.parse_autofs_master(text.encode(), 0o644)
    assert not any(str(c).startswith(str(mount)) for c in calls)
    # A "/" mount point covers every path, so nothing is stat-ed at all.
    assert calls == []


def test_agent_candidates_cover_typed_relative_and_include_names():
    text = '/a auto.misc\n/b file,sun:auto.x\n/c //ldap/map\n+dir:/etc/auto.master.d\n/d -hosts nobind\n'
    found = agent.autofs_candidates(text)
    assert found[:3] == ['/etc/auto.misc', '/etc/auto.x', '/etc/auto.master.d']
    assert not any(p.startswith('//') or p.startswith('/a') or p.startswith('/d') for p in found)


@pytest.mark.parametrize('data,error', [(b'x' * (agent.AUTOFS_TEXT_LIMIT + 1), 'over_limit'), (b'/a b\x00\n', 'binary')])
def test_agent_refuses_oversized_or_binary_master_maps(data, error):
    result = agent.parse_autofs_master(data, 0o644)
    assert result == {'text': None, 'error': error, 'stats': {}, 'stats_truncated': False}
    assert persistence.validate_autofs(result, MASTER, 0o644) == 0


def test_agent_stat_limit_and_deadline_truncate():
    text = '\n'.join(f'/m{i} /srv/maps/m{i}' for i in range(200))
    assert agent.parse_autofs_master(text.encode(), 0o644)['stats_truncated']
    result = agent.parse_autofs_master(text.encode(), 0o644, time.monotonic() - 1)
    assert result['stats_truncated'] and list(result['stats']) == [MASTER]


def test_agent_inventory_attaches_report_only_with_job_parsing(tmp_path, monkeypatch):
    prog, marker = program_file(tmp_path)
    master = tmp_path / 'auto.master'
    master.write_text(f'/prog program:{prog}\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(master),))
    monkeypatch.setattr(agent, 'AUTOFS_MASTER', str(master))
    plain = agent.persistence_inventory(time.monotonic() + 5)
    assert 'autofs' not in plain['entries'][0]
    parsed = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)['entries'][0]
    assert parsed['autofs']['text'] == master.read_text()
    assert parsed['autofs']['stats'][str(prog)] == {'kind': 'regular', 'mode': 0o755}
    assert not marker.exists()


# --- controller validation -------------------------------------------------

@pytest.mark.parametrize('mutate', [
    lambda r: r.update(extra=1),
    lambda r: r.update(text='a\x00'),
    lambda r: r.update(text='Ā'),
    lambda r: r.update(text='x' * (persistence.AUTOFS_TEXT_LIMIT + 1)),
    lambda r: r.update(error='other', text=None, stats={}),
    lambda r: r.update(error='binary'),
    lambda r: r.update(stats_truncated=1),
    lambda r: r['stats'].pop(MASTER),
    lambda r: r['stats'].update({MASTER: {'kind': 'regular', 'mode': 0o755}}),
    lambda r: r['stats'].update({'relative': {'kind': 'missing', 'mode': 0}}),
    lambda r: r['stats'].update({'//ldap': {'kind': 'missing', 'mode': 0}}),
    lambda r: r['stats'].update({'/x/': {'kind': 'missing', 'mode': 0}}),
    lambda r: r['stats'].update({'/x': {'kind': 'socket', 'mode': 0}}),
    lambda r: r['stats'].update({'/x': {'kind': 'missing', 'mode': 0o644}}),
    lambda r: r['stats'].update({'/x': {'kind': 'regular', 'mode': 0o17777}}),
    lambda r: r['stats'].update({'/x': {'kind': 'regular', 'mode': True}}),
    lambda r: r['stats'].update({f'/m{i}': {'kind': 'missing', 'mode': 0} for i in range(200)}),
])
def test_controller_rejects_malformed_reports(mutate):
    row = report('/a /x\n', {'/x': {'kind': 'regular', 'mode': 0o755}})
    persistence.validate_autofs(copy.deepcopy(row), MASTER, 0o644)
    mutate(row)
    with pytest.raises(ValueError):
        persistence.validate(inventory(entry(row)))


def test_controller_rejects_report_on_other_paths_or_symlinks():
    row = report('/a /x\n', {})
    with pytest.raises(ValueError):
        persistence.validate_autofs(row, '/etc/auto.misc', 0o644)
    bad = entry(row)
    bad.update(kind='symlink', target='/x')
    bad.pop('sha256')
    with pytest.raises(ValueError):
        persistence.validate(inventory(bad))


def test_report_is_excluded_from_baseline_metadata():
    assert 'autofs' not in persistence.metadata(entry(report('/a /x\n', {})))


# --- view ------------------------------------------------------------------

def test_view_resolves_program_maps_and_keeps_result_incomplete():
    text = '/net -hosts\n/prog program:/usr/lib/autofs/prog\n/direct /usr/local/bin/map\n/misc auto.misc\n/refused program:/srv/noexec\n'
    stats = {'/usr/lib/autofs/prog': {'kind': 'regular', 'mode': 0o755},
             '/usr/local/bin/map': {'kind': 'regular', 'mode': 0o744},
             '/etc/auto.misc': {'kind': 'regular', 'mode': 0o644},
             '/srv/noexec': {'kind': 'regular', 'mode': 0o644}}
    view = startup_inventory.autofs_view(entry(report(text, stats)))
    assert [p['path'] for p in view['programs']] == ['/usr/lib/autofs/prog', '/usr/local/bin/map']
    assert view['programs'][0] == {'path': '/usr/lib/autofs/prog', 'argv': ['/usr/lib/autofs/prog', '<key>'],
                                   'user': 'root', 'cwd': '/prog', 'trigger': 'every lookup of a key under the mount point'}
    resolved = {e['mount_point']: e['resolved'] for e in view['entries']}
    assert resolved == {'/net': 'hosts', '/prog': 'program', '/direct': 'program', '/misc': 'file', '/refused': 'refused'}
    codes = {g['code'] for g in view['gaps'] if g['blocking']}
    assert {'nsswitch_not_observed', 'autofs_conf_not_observed', 'map_text_not_observed'} <= codes
    assert view['complete'] is False and view['origin'] == 'not_assessed' and view['authorizes_response'] is False


def test_view_fails_closed_on_unobserved_stats_and_includes():
    text = '/a /srv/unseen\n+auto.extra\n'
    view = startup_inventory.autofs_view(entry(report(text, {}, truncated=True)))
    assert view['programs'] == []
    codes = {g['code'] for g in view['gaps']}
    assert {'stat_not_observed', 'stats_truncated', 'master_file_not_observed'} <= codes


def test_view_matches_the_contract_for_the_same_observations(tmp_path):
    prog, _ = program_file(tmp_path)
    text = f'/prog {prog}\n/b program:{prog}\n'
    reported = agent.parse_autofs_master(text.encode(), 0o644)
    direct = autofs_program_maps.evaluate_master(files={MASTER: text}, stats=reported['stats'])
    assert [p['path'] for p in startup_inventory.autofs_view(entry(reported))['programs']] == \
        [p['path'] for p in direct['programs']] == [str(prog), str(prog)]


def test_state_and_search_text_for_older_and_refused_reports():
    old = entry(None)
    old.pop('autofs')
    assert startup_inventory.autofs_state(old) == 'not_reported'
    refused = entry({'text': None, 'error': 'binary', 'stats': {}, 'stats_truncated': False})
    assert startup_inventory.autofs_state(refused) == 'binary' and startup_inventory.autofs_text(refused) == ''
    good = entry(report('/prog program:/opt/p\n', {'/opt/p': {'kind': 'regular', 'mode': 0o700}}))
    assert startup_inventory.autofs_state(good) == 'resolved' and '/opt/p' in startup_inventory.autofs_text(good)
    rows = {r['id']: r for r in startup_inventory.catalog_rows(inventory(good))}
    assert '1 program map' in rows['autofs']['label']
    rows = {r['id']: r for r in startup_inventory.catalog_rows(inventory(old))}
    assert 'not reported by this agent version' in rows['autofs']['label']
