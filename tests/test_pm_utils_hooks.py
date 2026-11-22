"""Tests for the pure pm-utils hook contract (#1367)."""
from __future__ import annotations

import os
import random
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from app import pm_utils_hooks as pm

ETC, LIB = '/etc/pm', '/usr/lib/pm-utils'


def f(name, uid=0, mode=0o755, kind='file', ltype=None):
    target = {'type': kind} if kind == 'missing' else {'type': kind, 'uid': uid, 'mode': mode}
    return {'name': name, 'type': ltype or ('symlink' if kind == 'missing' else kind), 'target': target}


def listings(sleep_etc=(), sleep_lib=(), power_etc=(), power_lib=(), config=None):
    out = {f'{ETC}/{d}': {'exists': False} for d in ('config.d', 'pm-suspend.config.d', 'pm-powersave.config.d')}
    if config is not None:
        out[f'{ETC}/config.d'] = {'exists': True, 'entries': list(config)}
    for path, entries in ((f'{ETC}/sleep.d', sleep_etc), (f'{LIB}/sleep.d', sleep_lib),
                          (f'{ETC}/power.d', power_etc), (f'{LIB}/power.d', power_lib)):
        out[path] = {'exists': True, 'entries': list(entries)}
    return out


def steps(result, kind='sleep', index=0):
    return [(s['name'], s['status'], s['path']) for s in result['hooks'][kind]['passes'][index]['steps']]


def test_merges_directories_in_c_order_and_etc_copy_wins():
    r = pm.resolve(listings(sleep_etc=[f('10b'), f('Zed')], sleep_lib=[f('10b'), f('00a'), f('a1')]))
    assert r['complete'] is True and r['upper_bound'] is True and r['origin'] == 'not_assessed'
    assert steps(r) == [('00a', 'runs', f'{LIB}/sleep.d/00a'), ('10b', 'runs', f'{ETC}/sleep.d/10b'),
                        ('Zed', 'runs', f'{ETC}/sleep.d/Zed'), ('a1', 'runs', f'{LIB}/sleep.d/a1')]
    assert r['hooks']['sleep']['passes'][0]['steps'][1]['shadows'] == f'{LIB}/sleep.d/10b'
    wake = r['hooks']['sleep']['passes'][1]
    assert wake['phase'] == 'after_wake' and wake['args'] == ['resume', 'suspend']
    assert [s[0] for s in steps(r, index=1)] == ['a1', 'Zed', '10b', '00a']
    assert [p['path'] for p in r['programs']] == [f'{LIB}/sleep.d/00a', f'{ETC}/sleep.d/10b',
                                                  f'{ETC}/sleep.d/Zed', f'{LIB}/sleep.d/a1']


def test_arguments_for_each_program_and_power_event():
    r = pm.resolve(listings(power_lib=[f('cpufreq')]))
    args = [(p['program'], p['phase'], p['args']) for p in r['hooks']['sleep']['passes']]
    assert ('pm-hibernate', 'after_wake', ['thaw', 'hibernate']) in args
    assert ('pm-suspend-hybrid', 'before_sleep', ['suspend', 'suspend_hybrid']) in args
    assert ('pm-suspend --help', 'help', ['help']) in args
    power = [(p['phase'], p['args']) for p in r['hooks']['power']['passes']]
    assert power == [('battery', ['true']), ('ac', ['false']), ('help', ['help'])]


def test_glob_and_owner_filters():
    r = pm.resolve(listings(sleep_etc=[f('.hidden'), f('old~'), f('user', uid=1000)],
                            sleep_lib=[f('ok'), f('dangling', kind='missing')]))
    assert steps(r) == [('ok', 'runs', f'{LIB}/sleep.d/ok')]
    assert r['complete'] is True


def test_non_root_etc_copy_runs_as_root_when_lib_copy_is_root_owned():
    r = pm.resolve(listings(sleep_etc=[f('50svc', uid=1000)], sleep_lib=[f('50svc')]))
    assert steps(r) == [('50svc', 'runs', f'{ETC}/sleep.d/50svc')]
    assert r['programs'][0]['root_owned'] is False
    assert [n['code'] for n in r['notes']] == ['selected_not_root_owned']


def test_non_executable_and_previous_hook_repeat():
    r = pm.resolve(listings(sleep_lib=[f('00dir', kind='dir'), f('10a'), f('20d', kind='dir'),
                                       f('30n', mode=0o644)]))
    assert steps(r) == [('00dir', 'not_run', None), ('10a', 'runs', f'{LIB}/sleep.d/10a'),
                        ('20d', 'repeats_previous', f'{LIB}/sleep.d/10a'), ('30n', 'not_run', f'{LIB}/sleep.d/30n')]
    assert 'repeats_previous' in [n['code'] for n in r['notes']]


def test_symlink_follows_target_owner_and_type():
    link = {'name': 'link', 'type': 'symlink', 'target': {'type': 'file', 'uid': 0, 'mode': 0o755}}
    r = pm.resolve(listings(sleep_etc=[link]))
    assert steps(r) == [('link', 'runs', f'{ETC}/sleep.d/link')]


@pytest.mark.parametrize('name', ['a b', 'a\tb', 'x*', 'q?', 'b[1]', 'back\\n', '-n', '-x'])
def test_names_echo_would_alter_are_blocking(name):
    r = pm.resolve(listings(sleep_lib=[f(name)]))
    assert r['complete'] is False and r['hooks']['sleep'] is None
    assert any(g['code'] == 'unsafe_name' for g in r['gaps'])


def test_ignored_unsafe_names_do_not_block():
    assert pm.resolve(listings(sleep_lib=[f('.a b'), f('x y~')]))['complete'] is True


def test_config_files_are_sourced_and_block():
    r = pm.resolve(listings(config=[f('blacklist', mode=0o644), f('sub', kind='dir'), f('x~')]))
    assert [s['path'] for s in r['sourced']] == [f'{ETC}/config.d/blacklist']
    assert r['sourced'][0]['by'] == ['pm-suspend', 'pm-powersave']
    assert r['complete'] is False
    assert [g['code'] for g in r['gaps'] if g['blocking']] == ['config_sourced_not_evaluated']


def test_unobserved_and_invalid_input_fail_closed():
    base = listings(sleep_lib=[f('a')])
    del base[f'{ETC}/power.d']
    r = pm.resolve(base)
    assert r['complete'] is False and r['hooks']['power'] is None and r['hooks']['sleep'] is not None
    assert {'code': 'listing_not_observed', 'path': f'{ETC}/power.d', 'detail': '', 'blocking': True} in r['gaps']
    bad = listings(sleep_lib=[{'name': 'a', 'type': 'file'}])
    assert pm.resolve(bad)['gaps'][0]['code'] == 'target_not_observed'
    for entry in ({'name': 'a/b', 'type': 'file', 'target': {'type': 'file', 'uid': 0, 'mode': 0o755}},
                  {'name': 'a', 'type': 'file', 'target': {'type': 'file', 'uid': True, 'mode': 0o755}},
                  {'name': 'a', 'type': 'file', 'target': {'type': 'missing'}}):
        r = pm.resolve(listings(sleep_lib=[entry]))
        assert r['complete'] is False and r['gaps'][0]['code'] == 'entry_invalid'
    many = listings(sleep_lib=[f(f'h{i}') for i in range(pm.MAX_ENTRIES + 1)])
    assert pm.resolve(many)['gaps'][0]['code'] == 'too_many_entries'


def test_digest_is_deterministic_and_libdir_is_configurable():
    a = pm.resolve(listings(sleep_lib=[f('a')]))
    assert a['digest'] == pm.resolve(listings(sleep_lib=[f('a')]))['digest']
    r = pm.resolve({}, libdir='/usr/lib64/pm-utils/')
    assert r['libdir'] == '/usr/lib64/pm-utils'
    assert any(g['path'] == '/usr/lib64/pm-utils/sleep.d' for g in r['gaps'])


# --- Differential against the real pm-utils 1.4.1 _run_hooks under dash -------------

_HARNESS = r'''
NA=254; NX=253; DX=252; LC_COLLATE=C; export LC_COLLATE
log() { :; }
inhibit() { :; }
inhibited() { false; }
update_parameters() { :; }
command_exists() { false; }
hook_exit_status(){
	case $1 in
		0)   log "success." ;;
		$NA) log "not applicable." ;;
		$NX) log "not executable." ;;
		$DX) log "disabled." ;;
		*)   log "Returned exit code $1."; return 1 ;;
	esac
}
hook_ok()
{
	local hook="${1##*/}"
	[ -f "$STORAGEDIR/disable_hook:$hook" ] && return $DX
	[ -f "$STORAGEDIR/disable_hook:${hook#[0-9][0-9]}" ] && return $DX
	[ -x "$1" ] || return $NX
	return 0
}
_run_hook() {
	log "Running hook $*:"
	hook_ok "$1" && "$@"
	log ""
	log -n "$*: "
	hook_exit_status $? && LAST_HOOK="${1##*/}" || inhibit
}
run_hook() { _run_hook "$@"; }
_run_hooks() {
	local syshooks="${PM_UTILS_ETCDIR}/$1.d"
	local phooks="${PM_UTILS_LIBDIR}/$1.d"
	command_exists before_hooks && before_hooks
	local sort="sort"
	local base
	local hook
	local oifs="${IFS}"
	local nifs="
"
	IFS="${nifs}"
	[ "$3" = "reverse" ] && sort="sort -r"
	for base in $(IFS="${oifs}"; for f in "$syshooks/"*[!~] "$phooks/"*[!~];
		do [ -O "$f" ] && echo ${f##*/} ; done | $sort | uniq) ;
	do
		IFS="${oifs}"
		[ "$3" -a "$3" = "reverse" -a "$LAST_HOOK" ] && \
		    [ "$base" \> "$LAST_HOOK" ] && continue
		[ ! "$3" ] && inhibited && break
		update_parameters
		if [ -f "$syshooks/$base" ]; then
			hook="$syshooks/$base"
		elif [ -f "$phooks/$base" ]; then
			hook="$phooks/$base"
		fi
		run_hook "$hook" $2
		IFS="${nifs}"
	done
	IFS="${oifs}"
	inhibited && return 1 || return 0
}
_run_hooks sleep "$ACTIONARGS" $DIRECTION
'''


def _capture(root: Path) -> dict:
    out = {}
    for d in root.rglob('*'):
        if d.is_dir() and not d.is_symlink() and d.name.endswith('.d') and d.parent.name in ('pm', 'pm-utils'):
            entries = []
            for e in sorted(d.iterdir()):
                lt = os.lstat(e)
                ltype = ('symlink' if stat.S_ISLNK(lt.st_mode) else 'file' if stat.S_ISREG(lt.st_mode)
                         else 'dir' if stat.S_ISDIR(lt.st_mode) else 'other')
                try:
                    st = os.stat(e)
                    target = {'type': 'file' if stat.S_ISREG(st.st_mode) else 'dir' if stat.S_ISDIR(st.st_mode)
                              else 'other', 'uid': st.st_uid, 'mode': stat.S_IMODE(st.st_mode)}
                except FileNotFoundError:
                    target = {'type': 'missing'}
                entries.append({'name': e.name, 'type': ltype, 'target': target})
            out[str(d)] = {'exists': True, 'entries': entries}
    return out


@pytest.mark.skipif(os.geteuid() != 0 or not shutil.which('dash'), reason='needs root and dash for -O and chown')
def test_differential_against_real_run_hooks():
    rng = random.Random(1367)
    alphabet = ['00', '10', '5', 'A', 'a', 'Z', 'z', '_', '.', '~', '-', 'b9']
    trees = 0
    for _ in range(120):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            etc, lib = root / 'etc' / 'pm', root / 'usr' / 'pm-utils'
            log = root / 'log'
            for base in (etc, lib):
                (base / 'sleep.d').mkdir(parents=True)
            names = {''.join(rng.choice(alphabet) for _ in range(rng.randint(1, 3))) for _ in range(rng.randint(0, 8))}
            names = [n for n in names if not n.startswith('-') and n not in ('.', '..')]
            for name in names:
                for base in rng.sample([etc, lib], rng.randint(1, 2)):
                    p = base / 'sleep.d' / name
                    kind = rng.choice(['file', 'file', 'file', 'dir', 'link', 'dangling'])
                    if kind == 'dir':
                        p.mkdir()
                    elif kind in ('link', 'dangling'):
                        tgt = root / f'tgt-{rng.random()}'
                        if kind == 'link':
                            tgt.write_text(f'#!/bin/sh\necho "$0 $*" >> {log}\n')
                            tgt.chmod(rng.choice([0o755, 0o644]))
                            os.chown(tgt, rng.choice([0, 0, 1000]), 0)
                        p.symlink_to(tgt)
                    else:
                        p.write_text(f'#!/bin/sh\necho "$0 $*" >> {log}\n')
                        p.chmod(rng.choice([0o755, 0o755, 0o644]))
                        os.chown(p, rng.choice([0, 0, 1000]), 0)
            captured = _capture(root)
            for d in ('config.d', 'pm-suspend.config.d', 'pm-powersave.config.d', 'power.d'):
                captured[f'{etc}/{d}'] = {'exists': False}
            captured[f'{lib}/power.d'] = {'exists': False}
            result = pm.resolve(captured, etcdir=str(etc), libdir=str(lib))
            assert result['complete'] is True, result['gaps']
            for index, direction in ((0, ''), (1, 'reverse')):
                log.write_text('')
                pass_ = result['hooks']['sleep']['passes'][index]
                env = {'PATH': os.environ['PATH'], 'PM_UTILS_ETCDIR': str(etc), 'PM_UTILS_LIBDIR': str(lib),
                       'STORAGEDIR': str(root / 'storage'), 'ACTIONARGS': ' '.join(pass_['args']),
                       'DIRECTION': direction}
                subprocess.run(['dash', '-c', _HARNESS], env=env, cwd=tmp, check=True, timeout=30)
                expected = [f'{s["path"]} {" ".join(pass_["args"])}' for s in pass_['steps']
                            if s['status'] in ('runs', 'repeats_previous')]
                # A symlinked hook reports $0 as the link path, which is the path the model gives.
                assert log.read_text().splitlines() == expected
            trees += 1
    assert trees == 120
