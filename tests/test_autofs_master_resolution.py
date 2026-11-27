"""#1375 increment 3: agent-reported master-map text, listed by the controller without any map lookup."""
import builtins
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


def report(text):
    return {'text': text, 'error': None}


def entry(autofs, mode=0o644):
    return {'path': MASTER, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': mode, 'size': 10, 'mtime_ns': 1,
            'sha256': 'a' * 64, 'autofs': autofs}


def inventory(row):
    return {'scope': [MASTER], 'entries': [row], 'gaps': [], 'missing_roots': [], 'skipped': 0, 'state': 'collected'}


class InertFilesystem:
    """Records every path-taking filesystem call and refuses the ones under watched roots, so an unverified
    candidate path can never reach a real lookup (which could trigger an automount or a program map)."""

    NAMES = ('stat', 'lstat', 'open', 'access', 'listdir', 'scandir', 'readlink', 'statvfs')

    def __init__(self, monkeypatch, watched):
        self.calls, self.watched = [], [str(w) for w in watched]
        for name in self.NAMES:
            real = getattr(os, name)
            monkeypatch.setattr(os, name, self.wrap(real))
        monkeypatch.setattr(builtins, 'open', self.wrap(builtins.open))
        for name in ('exists', 'isfile', 'isdir', 'islink', 'realpath', 'getsize'):
            monkeypatch.setattr(os.path, name, self.wrap(getattr(os.path, name)))

    def wrap(self, real):
        def call(path, *args, **kwargs):
            text = os.fsdecode(path) if isinstance(path, (str, bytes, os.PathLike)) else ''
            if any(text == w or text.startswith(w + '/') for w in self.watched):
                self.calls.append(text)
                raise AssertionError(f'unverified candidate path reached a real lookup: {text}')
            return real(path, *args, **kwargs)
        return call


# --- agent -----------------------------------------------------------------

def test_agent_reports_only_the_text_and_never_looks_up_map_paths(tmp_path, monkeypatch):
    prog, marker = program_file(tmp_path)
    text_map = tmp_path / 'auto.text'
    text_map.write_text('k -fstype=nfs host:/x\n')
    text = (f'/net -hosts\n/prog program:{prog}\n/direct {prog} --timeout=60\n/text file:{text_map}\n'
            f'/gone {tmp_path}/absent\n{tmp_path}/mnt {tmp_path}/mnt/inner\n+auto.master\n/rel auto.misc\n')
    fs = InertFilesystem(monkeypatch, [tmp_path, '/etc/auto.misc', '/etc/auto.master'])
    result = agent.parse_autofs_master(text.encode())
    monkeypatch.undo()
    assert result == {'text': text, 'error': None}
    assert fs.calls == [] and not marker.exists()
    assert persistence.validate_autofs(result, MASTER) == 1
    persistence.validate(inventory(entry(result)))


@pytest.mark.parametrize('data,error', [(b'x' * (agent.AUTOFS_TEXT_LIMIT + 1), 'over_limit'), (b'/a b\x00\n', 'binary')])
def test_agent_refuses_oversized_or_binary_master_maps(data, error):
    result = agent.parse_autofs_master(data)
    assert result == {'text': None, 'error': error}
    assert persistence.validate_autofs(result, MASTER) == 0


def test_agent_text_is_latin1_round_trip():
    data = '/a /x \xe9\n'.encode('latin-1')
    assert agent.parse_autofs_master(data)['text'].encode('latin-1') == data


def test_agent_inventory_touches_only_the_master_map(tmp_path, monkeypatch):
    (tmp_path / 'maps').mkdir()
    prog, marker = program_file(tmp_path / 'maps')
    master = tmp_path / 'auto.master'
    master.write_text(f'/prog program:{prog}\n/misc {tmp_path}/maps/auto.misc\n')
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(master),))
    monkeypatch.setattr(agent, 'AUTOFS_MASTER', str(master))
    plain = agent.persistence_inventory(time.monotonic() + 5)
    assert 'autofs' not in plain['entries'][0]
    fs = InertFilesystem(monkeypatch, [tmp_path / 'maps'])
    parsed = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)['entries'][0]
    monkeypatch.undo()
    assert parsed['autofs'] == {'text': master.read_text(), 'error': None}
    assert fs.calls == [] and not marker.exists()


def test_inert_adapter_catches_a_lookup(tmp_path, monkeypatch):
    """The adapter is a meaningful guard: a stat of a watched candidate fails loudly."""
    fs = InertFilesystem(monkeypatch, [tmp_path / 'mnt'])
    with pytest.raises(AssertionError):
        os.stat(tmp_path / 'mnt' / 'key')
    assert fs.calls == [str(tmp_path / 'mnt' / 'key')]


# --- controller validation -------------------------------------------------

@pytest.mark.parametrize('mutate', [
    lambda r: r.update(extra=1),
    lambda r: r.update(stats={MASTER: {'kind': 'regular', 'mode': 0o644}}),
    lambda r: r.update(stats_truncated=False),
    lambda r: r.pop('error'),
    lambda r: r.update(text='a\x00'),
    lambda r: r.update(text='Ā'),
    lambda r: r.update(text=b'/a /x\n'),
    lambda r: r.update(text='x' * (persistence.AUTOFS_TEXT_LIMIT + 1)),
    lambda r: r.update(error='other', text=None),
    lambda r: r.update(error='binary'),
])
def test_controller_rejects_malformed_reports(mutate):
    row = report('/a /x\n')
    persistence.validate_autofs(copy.deepcopy(row), MASTER)
    mutate(row)
    with pytest.raises(ValueError):
        persistence.validate(inventory(entry(row)))


def test_controller_rejects_report_on_other_paths_or_symlinks():
    row = report('/a /x\n')
    with pytest.raises(ValueError):
        persistence.validate_autofs(row, '/etc/auto.misc')
    bad = entry(row)
    bad.update(kind='symlink', target='/x')
    bad.pop('sha256')
    with pytest.raises(ValueError):
        persistence.validate(inventory(bad))


def test_report_is_excluded_from_baseline_metadata():
    assert 'autofs' not in persistence.metadata(entry(report('/a /x\n')))


# --- view ------------------------------------------------------------------

def test_view_lists_entries_and_leaves_every_map_path_unobserved():
    text = ('/net -hosts\n/prog program:/usr/lib/autofs/prog\n/direct /usr/local/bin/map\n/misc auto.misc\n'
            '/remote yp:auto.home\n')
    view = startup_inventory.autofs_view(entry(report(text)))
    assert view['programs'] == []
    resolved = {e['mount_point']: e['resolved'] for e in view['entries']}
    assert resolved == {'/net': 'hosts', '/prog': 'unknown', '/direct': 'unknown', '/misc': 'unknown', '/remote': 'remote'}
    unobserved = {g['path'] for g in view['gaps'] if g['code'] == 'stat_not_observed'}
    assert unobserved == {'/usr/lib/autofs/prog', '/usr/local/bin/map', '/etc/auto.misc'}
    blocking = {g['code'] for g in view['gaps'] if g['blocking']}
    assert {'map_paths_not_observed', 'nsswitch_not_observed', 'autofs_conf_not_observed'} <= blocking
    assert view['complete'] is False and view['origin'] == 'not_assessed' and view['authorizes_response'] is False


def test_view_matches_the_contract_with_only_the_master_observed():
    text = '/a /srv/unseen\n+auto.extra\n/b program:/opt/p\n'
    view = startup_inventory.autofs_view(entry(report(text)))
    direct = autofs_program_maps.evaluate_master(files={MASTER: text}, stats={MASTER: {'kind': 'regular', 'mode': 0o644}})
    assert [e['resolved'] for e in view['entries']] == [e['resolved'] for e in direct['entries']]
    assert {g['code'] for g in direct['gaps']} <= {g['code'] for g in view['gaps']}
    assert 'master_file_not_observed' in {g['code'] for g in view['gaps']}


def test_state_search_and_catalog_for_reported_older_and_refused():
    old = entry(None)
    old.pop('autofs')
    assert startup_inventory.autofs_state(old) == 'not_reported'
    refused = entry({'text': None, 'error': 'binary'})
    assert startup_inventory.autofs_state(refused) == 'binary' and startup_inventory.autofs_text(refused) == ''
    good = entry(report('/prog program:/opt/p\n'))
    assert startup_inventory.autofs_state(good) == 'resolved'
    assert '/prog' in startup_inventory.autofs_text(good) and '/opt/p' in startup_inventory.autofs_text(good)
    rows = {r['id']: r for r in startup_inventory.catalog_rows(inventory(good))}
    assert '1 master-map entry · map paths not looked up' in rows['autofs']['label']
    rows = {r['id']: r for r in startup_inventory.catalog_rows(inventory(old))}
    assert 'not reported by this agent version' in rows['autofs']['label']
