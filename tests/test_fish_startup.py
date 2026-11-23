"""Tests for the pure fish startup-file contract (#1415)."""
from __future__ import annotations

import functools
import os
import random
import shutil
import stat
import subprocess

import pytest

from app import fish_startup as fs

HOME = '/home/alice'
CFG = f'{HOME}/.config/fish'
UDATA = f'{HOME}/.local/share/fish'
DATA = '/usr/share/fish'
SYSCONF = '/etc/fish'
EXTRA = '/usr/share/fish/vendor_conf.d'
ENV = {'HOME': HOME, 'XDG_CONFIG_HOME': None, 'XDG_DATA_HOME': None, 'XDG_DATA_DIRS': None,
       'FISH_UNIT_TESTS_RUNNING': None}


def entry(name, kind='file', readable=True, **extra):
    return {'name': name, 'type': kind, 'readable': readable, **extra}


def listing(*entries):
    return {'type': 'directory', 'complete': True, 'entries': list(entries)}


def payload(conf=None, sysconf=None, vendor=None, env=None, files=None, options=(), version='3.7.0', **listings):
    base = {
        CFG: listing(), UDATA: listing(),
        f'{CFG}/conf.d': listing(*(conf or [])),
        f'{SYSCONF}/conf.d': listing(*(sysconf or [])),
        f'{UDATA}/vendor_conf.d': {'type': 'absent'},
        f'{DATA}/vendor_conf.d': listing(*(vendor or [])),
    }
    base.update(listings)
    cfg_files = {f'{DATA}/config.fish': {'type': 'file', 'readable': True},
                 f'{SYSCONF}/config.fish': {'type': 'file', 'readable': True},
                 f'{CFG}/config.fish': {'type': 'absent'}}
    cfg_files.update(files or {})
    return {'version': version, 'options': list(options),
            'paths': {'data_dir': DATA, 'sysconf_dir': SYSCONF, 'extra_confdir': EXTRA},
            'environment': {**ENV, **(env or {})}, 'listings': base, 'files': cfg_files}


def runs(result):
    return [r['path'] for r in result['runs']]


def codes(result):
    return {g['code'] for g in result['gaps']}


def decision(result, path):
    return next(e for e in result['sequence'] if e['path'] == path)['decision']


def test_default_order_user_admin_vendor_then_config_files():
    result = fs.evaluate(payload(conf=[entry('z.fish')], sysconf=[entry('a.fish')], vendor=[entry('nix.fish')],
                                 files={f'{CFG}/config.fish': {'type': 'file', 'readable': True}}))
    assert result['complete'] is True, result['gaps']
    assert runs(result) == [f'{DATA}/config.fish', f'{CFG}/conf.d/z.fish', f'{SYSCONF}/conf.d/a.fish',
                            f'{EXTRA}/nix.fish', f'{SYSCONF}/config.fish', f'{CFG}/config.fish']
    assert result['origin'] == 'not_assessed'
    # The extra confdir equals <data>/vendor_conf.d, so it is listed once.
    assert result['directories']['conf_d'] == [f'{CFG}/conf.d', f'{SYSCONF}/conf.d', f'{UDATA}/vendor_conf.d',
                                               EXTRA]


@pytest.mark.parametrize('kind,readable,expected', [
    ('directory', True, 'skipped_not_regular'), ('dangling', True, 'skipped_not_regular'),
    ('other', True, 'skipped_not_regular'), ('file', False, 'skipped_unreadable'),
])
def test_unsourced_entry_still_masks_lower_precedence_file(kind, readable, expected):
    result = fs.evaluate(payload(conf=[entry('nix.fish', kind, readable)], vendor=[entry('nix.fish')]))
    assert decision(result, f'{CFG}/conf.d/nix.fish') == expected
    masked = next(e for e in result['sequence'] if e['path'] == f'{EXTRA}/nix.fish')
    assert masked['decision'] == 'masked' and masked['masked_by'] == f'{CFG}/conf.d/nix.fish'
    assert f'{EXTRA}/nix.fish' not in runs(result)
    assert result['complete'] is True


def test_glob_skips_hidden_and_other_suffixes():
    result = fs.evaluate(payload(conf=[entry('.hidden.fish'), entry('x.FISH'), entry('x.fish.bak'), entry('.fish'),
                                       entry('ok.fish')]))
    assert [e['path'] for e in result['sequence'] if e['phase'] == 'conf.d'] == [f'{CFG}/conf.d/ok.fish']


def test_glob_order_is_natural_and_case_insensitive():
    names = ['B.fish', 'a.fish', '10.fish', '9.fish', '09.fish', '1 2.fish', '1 10.fish', 'a_b.fish', 'a-b.fish',
             'aZ.fish', 'z.fish']
    result = fs.evaluate(payload(conf=[entry(n) for n in names]))
    # Observed from fish 3.7.0.
    assert [p.rsplit('/', 1)[1] for p in runs(result) if '/conf.d/' in p] == [
        '1 10.fish', '1 2.fish', '09.fish', '9.fish', '10.fish', 'a-b.fish', 'a.fish', 'a_b.fish', 'aZ.fish',
        'B.fish', 'z.fish']


def test_logically_equal_names_fall_back_to_code_points():
    assert fs.glob_compare('A.fish', 'a.fish') < 0
    assert fs.glob_compare('01.fish', '1.fish') < 0
    assert fs.glob_compare('a.fish', 'a.fish') == 0


def test_xdg_data_dirs_components():
    env = {'XDG_DATA_DIRS': '/opt/a/:/opt/b//::/', 'XDG_CONFIG_HOME': '/cfg', 'XDG_DATA_HOME': '/dh'}
    result = fs.evaluate(payload(env=env))
    assert result['directories']['conf_d'] == [
        '/cfg/fish/conf.d', f'{SYSCONF}/conf.d', '/dh/fish/vendor_conf.d', '/opt/a/fish/vendor_conf.d',
        '/opt/b///fish/vendor_conf.d', '/fish/vendor_conf.d', '//fish/vendor_conf.d', EXTRA]
    # Every one of those directories needs a listing.
    assert 'listing_not_observed' in codes(result) and result['complete'] is False


def test_empty_xdg_data_dirs_is_one_empty_component():
    result = fs.evaluate(payload(env={'XDG_DATA_DIRS': ''}, **{'/fish/vendor_conf.d': {'type': 'absent'}}))
    assert result['directories']['conf_d'][-2:] == ['/fish/vendor_conf.d', EXTRA]
    assert result['complete'] is True


def test_unit_tests_variable_drops_vendor_dirs():
    result = fs.evaluate(payload(env={'FISH_UNIT_TESTS_RUNNING': ''}, vendor=[entry('nix.fish')]))
    assert result['directories']['conf_d'] == [f'{CFG}/conf.d', f'{SYSCONF}/conf.d']
    assert f'{EXTRA}/nix.fish' not in runs(result)


@pytest.mark.parametrize('option', ['-N', '--no-config', '-n', '--no-execute'])
def test_no_config_runs_nothing(option):
    result = fs.evaluate(payload(conf=[entry('a.fish')], options=['-l', option]))
    assert result['runs'] == [] and result['config_runs'] is False and result['complete'] is True


def test_unknown_option_blocks():
    result = fs.evaluate(payload(options=['--print-rusage-self']))
    assert 'options_unverified' in codes(result) and result['complete'] is False


def test_unreadable_data_config_skips_conf_d_but_not_later_config_files():
    result = fs.evaluate(payload(conf=[entry('a.fish')],
                                 files={f'{DATA}/config.fish': {'type': 'file', 'readable': False}}))
    assert runs(result) == [f'{SYSCONF}/config.fish']
    assert result['complete'] is True


def test_readable_directory_config_fails_to_source():
    result = fs.evaluate(payload(files={f'{CFG}/config.fish': {'type': 'directory', 'readable': True}}))
    assert decision(result, f'{CFG}/config.fish') == 'source_fails'
    assert f'{CFG}/config.fish' not in runs(result)


def test_owner_and_mode_observations_are_reported():
    result = fs.evaluate(payload(conf=[entry('a.fish', uid=1000, mode=0o100666)]))
    run = next(r for r in result['runs'] if r['path'].endswith('/a.fish'))
    assert run['uid'] == 1000 and run['mode'] == 0o100666


@pytest.mark.parametrize('version', [None, '4.0.2', '3.6.1', 37])
def test_unsupported_or_missing_version_blocks(version):
    result = fs.evaluate(payload(version=version))
    assert codes(result) & {'version_not_observed', 'version_unsupported'} and result['complete'] is False


@pytest.mark.parametrize('mutate,code', [
    (lambda p: p['environment'].pop('XDG_DATA_DIRS'), 'environment_not_observed'),
    (lambda p: p['environment'].update(XDG_CONFIG_HOME='rel'), 'directory_relative'),
    (lambda p: p['environment'].update(HOME=None), 'directory_unset'),
    (lambda p: p['listings'].pop(f'{SYSCONF}/conf.d'), 'listing_not_observed'),
    (lambda p: p['listings'][f'{SYSCONF}/conf.d'].update(complete=False), 'listing_incomplete'),
    (lambda p: p['listings'].pop(CFG), 'directory_not_observed'),
    (lambda p: p['listings'].update({CFG: {'type': 'absent'}}), 'directory_would_be_created'),
    (lambda p: p['files'].pop(f'{SYSCONF}/config.fish'), 'file_not_observed'),
    (lambda p: p['paths'].pop('extra_confdir'), 'paths_not_observed'),
    (lambda p: p['listings'][f'{CFG}/conf.d']['entries'].extend([entry('é.fish'), entry('e.fish')]),
     'order_not_modelled'),
    (lambda p: p['listings'][f'{CFG}/conf.d']['entries'].append(entry('a\nb.fish')), 'input_malformed'),
    (lambda p: p['listings'][f'{CFG}/conf.d']['entries'].extend([entry('d.fish'), entry('d.fish')]),
     'input_malformed'),
])
def test_fail_closed_gaps(mutate, code):
    p = payload()
    mutate(p)
    result = fs.evaluate(p)
    assert code in codes(result) and result['complete'] is False


def test_unresolved_listing_leaves_later_entries_unresolved():
    p = payload(vendor=[entry('nix.fish')])
    p['listings'].pop(f'{SYSCONF}/conf.d')
    result = fs.evaluate(p)
    assert decision(result, f'{EXTRA}/nix.fish') == 'unresolved'
    assert f'{EXTRA}/nix.fish' not in runs(result)


@pytest.mark.parametrize('bad', [None, [], 'x', {'version': '3.7'}])
def test_malformed_payload_never_complete(bad):
    assert fs.evaluate(bad)['complete'] is False


def test_comparator_is_a_total_order_on_random_names():
    rng = random.Random(1415)
    names = list({''.join(rng.choice('aAbZ019 _-') for _ in range(rng.randint(1, 6))) + '.fish'
                  for _ in range(300)})
    ordered = sorted(names, key=functools.cmp_to_key(fs.glob_compare))
    for i, a in enumerate(ordered):
        for b in ordered[i + 1:]:
            assert fs.glob_compare(a, b) < 0 < fs.glob_compare(b, a)


# ---------------------------------------------------------------------------------------------------------------
# Differential against a real fish 3.7 binary. Skipped when fish 3.7 is not installed.

FISH = shutil.which('fish')


def _fish_37():
    if not FISH:
        return False
    out = subprocess.run([FISH, '--version'], capture_output=True, text=True, check=False).stdout
    return ' 3.7.' in out


def _observe_dir(path):
    if not os.path.lexists(path):
        return {'type': 'absent'}
    entries = []
    for name in os.listdir(path):
        full = os.path.join(path, name)
        try:
            mode = os.stat(full).st_mode
        except OSError:
            entries.append({'name': name, 'type': 'dangling'})
            continue
        kind = 'file' if stat.S_ISREG(mode) else 'directory' if stat.S_ISDIR(mode) else 'other'
        entries.append({'name': name, 'type': kind, 'readable': os.access(full, os.R_OK)})
    return {'type': 'directory', 'complete': True, 'entries': entries}


def _observe_file(path):
    if not os.path.exists(path):
        return {'type': 'absent'}
    mode = os.stat(path).st_mode
    kind = 'file' if stat.S_ISREG(mode) else 'directory' if stat.S_ISDIR(mode) else 'other'
    return {'type': kind, 'readable': os.access(path, os.R_OK)}


@pytest.mark.skipif(not _fish_37(), reason='fish 3.7 is not installed')
@pytest.mark.parametrize('seed', range(40))
def test_differential_against_real_fish(tmp_path, seed):
    rng = random.Random(seed)
    log = tmp_path / 'log'
    roots = {'cfg': tmp_path / 'cfg', 'dh': tmp_path / 'dh', 'd1': tmp_path / 'd1', 'd2': tmp_path / 'd2'}
    conf_dirs = [roots['cfg'] / 'fish' / 'conf.d', roots['dh'] / 'fish' / 'vendor_conf.d',
                 roots['d1'] / 'fish' / 'vendor_conf.d', roots['d2'] / 'fish' / 'vendor_conf.d']
    pool = ['nix.fish', '00debian-profile.fish', 'a.fish', 'A.fish', 'x.FISH', '.h.fish', 'b.txt'] + [
        ''.join(rng.choice('aAbZ019 _-') for _ in range(rng.randint(1, 5))) + '.fish' for _ in range(12)]
    pool = list(dict.fromkeys(pool))
    (roots['cfg'] / 'fish').mkdir(parents=True)
    (roots['dh'] / 'fish').mkdir(parents=True)
    for directory in conf_dirs:
        if rng.random() < 0.15:
            continue
        directory.mkdir(parents=True, exist_ok=True)
        for name in rng.sample(pool, rng.randint(0, 8)):
            target = directory / name
            kind = rng.choice(['file'] * 6 + ['dir', 'dangling', 'fifo', 'link'])
            if kind == 'dir':
                target.mkdir()
            elif kind == 'dangling':
                target.symlink_to(tmp_path / 'missing')
            elif kind == 'fifo':
                os.mkfifo(target)
            else:
                real = target if kind == 'file' else tmp_path / f'real-{rng.random()}'
                real.write_text(f'echo {str(target)!r} >> {str(log)!r}\n')
                if kind == 'link':
                    target.symlink_to(real)
    if rng.random() < 0.5:
        (roots['cfg'] / 'fish' / 'config.fish').write_text(f'echo user-config >> {str(log)!r}\n')
    xdg = ':'.join(str(roots[k]) + rng.choice(['', '/']) for k in ('d1', 'd2'))
    env = {'HOME': str(tmp_path / 'home'), 'XDG_CONFIG_HOME': str(roots['cfg']), 'XDG_DATA_HOME': str(roots['dh']),
           'XDG_DATA_DIRS': xdg, 'FISH_UNIT_TESTS_RUNNING': None}
    subprocess.run([FISH, '-c', 'true'], env={k: v for k, v in env.items() if v is not None}, check=True,
                   timeout=30, capture_output=True)
    observed = log.read_text().splitlines() if log.exists() else []

    data, sysconf = '/usr/share/fish', '/etc/fish'
    paths = {'data_dir': data, 'sysconf_dir': sysconf,
             'extra_confdir': f'{data}/vendor_conf.d' if os.path.exists(f'{data}/__fish_build_paths.fish') else None}
    result = fs.evaluate({'version': '3.7.0', 'options': [], 'paths': paths, 'environment': env, 'files': {},
                          'listings': {}})
    dirs = result['directories']
    listings = {d: _observe_dir(d) for d in dirs['conf_d'] + [dirs['config'], dirs['user_data']]}
    files = {f'{d}/config.fish': _observe_file(f'{d}/config.fish') for d in (data, sysconf, dirs['config'])}
    result = fs.evaluate({'version': '3.7.0', 'options': [], 'paths': paths, 'environment': env, 'files': files,
                          'listings': listings})
    assert result['complete'] is True, result['gaps']
    predicted = ['user-config' if r['path'] == f'{dirs["config"]}/config.fish' else r['path']
                 for r in result['runs'] if r['path'].startswith(str(tmp_path))]
    assert predicted == observed
