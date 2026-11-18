import os
import shutil
import subprocess

import pytest

from app import initramfs_hooks as ih

PKG = ih.PACKAGE_DIR
LOCAL = ih.LOCAL_DIR

# Pinned from dash 0.5.12 (Ubuntu 24.04) evaluating set_initlist's own case pattern
# `*[![:alnum:]\._-]*` over these names. Dot-names never reach the case: the glob skips them.
KEPT = ('-x', '0', 'A', 'README', 'Z9', '_x', 'a', 'a-b', 'a.b', 'a_b', 'hook.sh', 'x.dpkg-old')
REJECTED = ('a b', 'a%b', 'a+b', 'a,b', 'a:b', 'a=b', 'a@b', 'a~')


def hook(name, mode=0o755, syntax=True, **extra):
    return {'name': name, 'type': 'file', 'mode': mode, 'shell_syntax_ok': syntax, **extra}


def listed(*entries, complete=True, noexec=False):
    return {'state': 'listed', 'complete': complete, 'noexec': noexec, 'entries': list(entries)}


def run(pkg=(), local=(), config=None, **over):
    obs = {'family': 'debian', 'initramfs_tools': True,
           'directories': {PKG: listed(*pkg), LOCAL: listed(*local)}, 'config': config}
    obs.update(over)
    return ih.evaluate(obs)


def entry(result, path):
    return next(e for p in result['passes'] for e in p['entries'] if e['path'] == path)


def codes(result):
    return [g['code'] for g in result['gaps']]


@pytest.mark.parametrize('name', KEPT)
def test_names_set_initlist_keeps(name):
    assert ih.name_listed(name) is True


@pytest.mark.parametrize('name', REJECTED + ('.hidden',))
def test_names_set_initlist_ignores(name):
    assert ih.name_listed(name) is False


def test_non_ascii_name_is_locale_dependent_and_unresolved():
    assert ih.name_listed('é') is None
    assert ih.name_listed('é+') is False
    result = run(local=[hook('é')])
    assert entry(result, f'{LOCAL}/é')['reason'] == 'unresolved'
    assert 'locale_dependent_name' in codes(result) and not result['complete']


def test_both_passes_run_and_same_name_does_not_override():
    result = run(pkg=[hook('fsck'), hook('resume')], local=[hook('fsck')])
    assert result['covered'] and result['complete'] and result['applicable'] is True
    assert result['runs'] == [f'{PKG}/fsck', f'{PKG}/resume', f'{LOCAL}/fsck']
    assert [p['directory'] for p in result['passes']] == [PKG, LOCAL]
    assert result['passes'][0]['environment'] == ['STAGE_KERNEL_MODULE_COPYING=1']
    assert result['passes'][1]['environment'] == []
    assert entry(result, f'{LOCAL}/fsck')['invocations'] == [[f'{LOCAL}/fsck', 'prereqs'], [f'{LOCAL}/fsck']]
    assert result['order']['established'] is False and result['runs_as'] == 'root'
    assert result['action_authorized'] is False


def test_skip_reasons():
    result = run(local=[
        hook('nox', mode=0o644), hook('bad', syntax=False), {'name': 'dir', 'type': 'directory'},
        {'name': 'dangle', 'type': 'symlink', 'target': None},
        {'name': 'todir', 'type': 'symlink', 'target': {'type': 'directory'}},
        {'name': 'tofile', 'type': 'symlink', 'target': {'type': 'file', 'mode': 0o700}, 'shell_syntax_ok': True},
        hook('.hidden'), hook('a+b'), hook('ne', noexec=True),
    ])
    reasons = {e['name']: e['reason'] for e in result['passes'][1]['entries']}
    assert reasons == {'nox': 'not_executable', 'bad': 'bad_syntax', 'dir': 'directory', 'dangle': 'dangling_symlink',
                       'todir': 'directory', 'tofile': 'runs', '.hidden': 'hidden', 'a+b': 'name_rejected',
                       'ne': 'noexec_mount'}
    assert result['runs'] == [f'{LOCAL}/tofile']
    assert result['prereq_invocations'] == [[f'{LOCAL}/tofile', 'prereqs']]


def test_execute_bit_for_root_is_any_x_bit():
    result = run(local=[hook('other', mode=0o601), hook('group', mode=0o610)])
    assert result['runs'] == [f'{LOCAL}/group', f'{LOCAL}/other']


def test_directory_noexec_applies_when_entry_does_not_say():
    result = ih.evaluate({'family': 'debian', 'initramfs_tools': True,
                          'directories': {PKG: listed(hook('a'), noexec=True), LOCAL: {'state': 'absent'}}})
    assert entry(result, f'{PKG}/a')['reason'] == 'noexec_mount'
    assert result['covered'] and result['runs'] == []


def test_excluded_regular_files_may_still_run_as_prereqs():
    result = run(local=[hook('nox', mode=0o644), hook('a+b')])
    assert entry(result, f'{LOCAL}/nox')['runs_if_named_as_prereq'] is True
    assert entry(result, f'{LOCAL}/a+b')['runs_if_named_as_prereq'] is True
    gap = next(g for g in result['gaps'] if g['code'] == 'excluded_file_may_run_as_prereq')
    assert gap['path'] == LOCAL and gap['blocking'] is False


def test_option_value_mirrors_sed():
    assert ih.option_value([], False) is None
    assert ih.option_value(['OPTION=FRAMEBUFFER  \t'], False) == 'FRAMEBUFFER'
    assert ih.option_value(['OPTION=FRAMEBUFFER'], True) is None
    assert ih.option_value(['OPTION=A', 'OPTION=B'], True) == 'A'
    assert ih.option_value(['OPTION=A', 'OPTION=B'], False) == 'A\nB'
    assert ih.option_value(['OPTION='], False) == ''


def test_option_gate():
    fb = hook('framebuffer', option_lines=['OPTION=FRAMEBUFFER'])
    off = run(pkg=[fb], config={'FRAMEBUFFER': 'n'})
    e = entry(off, f'{PKG}/framebuffer')
    assert e['reason'] == 'gated_off' and e['invocations'] == [[f'{PKG}/framebuffer', 'prereqs']]
    assert off['runs'] == [] and off['prereq_invocations'] == [[f'{PKG}/framebuffer', 'prereqs']]
    assert run(pkg=[fb], config={'FRAMEBUFFER': ''})['runs'] == []
    assert run(pkg=[fb], config={'FRAMEBUFFER': 'y'})['runs'] == [f'{PKG}/framebuffer']
    unknown = run(pkg=[fb])
    assert entry(unknown, f'{PKG}/framebuffer')['reason'] == 'gate_unknown'
    assert unknown['conditional'] == [f'{PKG}/framebuffer'] and unknown['runs'] == []
    last = run(pkg=[hook('x', option_lines=['OPTION=FRAMEBUFFER'], last_line_is_option=True)],
               config={'FRAMEBUFFER': 'n'})
    assert last['runs'] == [f'{PKG}/x']
    multi = run(pkg=[hook('x', option_lines=['OPTION=A', 'OPTION=B'])], config={'A': 'y', 'B': 'y'})
    assert entry(multi, f'{PKG}/x')['reason'] == 'gate_invalid' and multi['conditional'] == [f'{PKG}/x']
    bad = run(pkg=[hook('x', option_lines=['OPTION=$(id)'])])
    assert entry(bad, f'{PKG}/x')['reason'] == 'gate_invalid'


def test_absent_directories_are_covered_with_no_hooks():
    result = ih.evaluate({'family': 'debian', 'initramfs_tools': True,
                          'directories': {PKG: {'state': 'absent'}, LOCAL: {'state': 'not_directory'}}})
    assert result['covered'] and result['runs'] == [] and result['gaps'] == []


@pytest.mark.parametrize('obs,code', [
    (None, 'input_malformed'),
    ({}, 'family_not_observed'),
    ({'family': 'bsd'}, 'family_unsupported'),
    ({'family': 'debian'}, 'generator_not_observed'),
    ({'family': 'debian', 'initramfs_tools': 'yes'}, 'input_malformed'),
    ({'family': 'debian', 'initramfs_tools': True}, 'input_malformed'),
    ({'family': 'debian', 'initramfs_tools': True, 'directories': {}}, 'directory_not_observed'),
    ({'family': 'debian', 'initramfs_tools': True,
      'directories': {PKG: {'state': 'unreadable'}, LOCAL: {'state': 'absent'}}}, 'directory_unreadable'),
    ({'family': 'debian', 'initramfs_tools': True,
      'directories': {PKG: listed(complete=False), LOCAL: {'state': 'absent'}}}, 'listing_incomplete'),
    ({'family': 'debian', 'initramfs_tools': True,
      'directories': {PKG: listed(hook('a'), hook('a')), LOCAL: {'state': 'absent'}}}, 'duplicate_name'),
    ({'family': 'debian', 'initramfs_tools': True,
      'directories': {PKG: listed({'name': 'a/b', 'type': 'file', 'mode': 0o755}), LOCAL: {'state': 'absent'}}},
     'input_malformed'),
    ({'family': 'debian', 'initramfs_tools': True,
      'directories': {PKG: listed({'name': 'a', 'type': 'file'}), LOCAL: {'state': 'absent'}}}, 'metadata_missing'),
    ({'family': 'debian', 'initramfs_tools': True, 'config': {'A': 1},
      'directories': {PKG: {'state': 'absent'}, LOCAL: {'state': 'absent'}}}, 'input_malformed'),
])
def test_blocking_gaps_are_never_covered(obs, code):
    result = ih.evaluate(obs)
    assert code in codes(result)
    assert not result['complete'] and not result['covered']


def test_unknown_syntax_and_mount_are_unresolved():
    result = ih.evaluate({'family': 'debian', 'initramfs_tools': True, 'directories': {
        PKG: {'state': 'listed', 'complete': True, 'entries': [hook('m')]},
        LOCAL: listed(hook('s', syntax=None))}})
    assert {entry(result, f'{PKG}/m')['reason'], entry(result, f'{LOCAL}/s')['reason']} == {'unresolved'}
    assert {'mount_not_observed', 'syntax_not_observed'} <= set(codes(result))
    assert not result['complete'] and result['runs'] == []


def test_rpm_and_dracut_are_not_covered():
    rpm = ih.evaluate({'family': 'rpm'})
    assert rpm['applicable'] is False and not rpm['covered'] and 'generator_not_covered' in codes(rpm)
    dracut = ih.evaluate({'family': 'debian', 'initramfs_tools': False})
    assert dracut['applicable'] is False and not dracut['covered']


def test_limits():
    many = [hook(f'h{i}') for i in range(ih.MAX_ENTRIES + 5)]
    result = run(local=many)
    assert 'too_many_entries' in codes(result) and not result['covered']
    assert len(result['passes'][1]['entries']) == ih.MAX_ENTRIES
    gappy = run(local=[hook(f'h{i}', syntax=None) for i in range(ih.MAX_GAPS * 2)])
    assert len(gappy['gaps']) == ih.MAX_GAPS and gappy['gaps'][-1]['code'] == 'gaps_truncated'


@pytest.mark.parametrize('star', [hook('*'), {'name': '*', 'type': 'directory'}, hook('*', mode=0o644)])
def test_entry_named_star_stops_listing_and_blocks(star):
    # set_initlist's `[ "$si_x" = "$initdir/*" ] && return` matches a real entry named "*" whatever its type.
    result = run(pkg=[hook('fsck')], local=[star, hook('aa'), hook('zz', option_lines=['OPTION=X']),
                                             hook('off', mode=0o644)])
    assert 'glob_literal_entry' in codes(result)
    gap = next(g for g in result['gaps'] if g['code'] == 'glob_literal_entry')
    assert gap['blocking'] is True and gap['path'] == f'{LOCAL}/*'
    assert result['runs'] == [f'{PKG}/fsck']
    assert result['conditional'] == []
    assert result['prereq_invocations'] == [[f'{PKG}/fsck', 'prereqs']]
    for name in ('aa', 'zz'):
        assert entry(result, f'{LOCAL}/{name}')['reason'] == 'unresolved'
        assert entry(result, f'{LOCAL}/{name}')['invocations'] == []
    assert entry(result, f'{LOCAL}/off')['reason'] == 'not_executable'
    assert result['complete'] is False and result['covered'] is False
    # The packaged pass is unaffected.
    assert entry(result, f'{PKG}/fsck')['reason'] == 'runs'


# The shipped functions from initramfs-tools-core 0.142ubuntu25.8 hook-functions, verbatim apart from
# dropping the verbose echo lines, plus mkinitramfs' two hook passes.
_HOOK_FUNCTIONS = r'''
get_source()
{
	if [ -z "$scriptdir" ]; then
		echo "${initdir}/$1"
	elif [ -f "${CONFDIR}${scriptdir}/$1" ]; then
		echo "${CONFDIR}${scriptdir}/$1"
	else
		echo "/usr/share/initramfs-tools${scriptdir}/$1"
	fi
}
set_initlist()
{
	unset initlist
	for si_x in "${initdir}"/*; do
		[ "${si_x}" = "${initdir}/*" ] && return
		case "${si_x#"${initdir}"/}" in
		*[![:alnum:]\._-]*)
			continue
			;;
		esac
		if [ -d "${si_x}" ]; then
			continue
		fi
		si_x="$(get_source "${si_x#"${initdir}"/}")"
		if [ ! -x "${si_x}" ]; then
			continue
		fi
		if ! sh -n "${si_x}" 2>/dev/null; then
			continue
		fi
		initlist="${initlist:-} ${si_x##*/}"
	done
}
get_prereq_pairs()
{
	set_initlist
	for gp_x in ${initlist:-}; do
		echo "${gp_x} ${gp_x}"
		gp_src="$(get_source "$gp_x")"
		prereqs=$("${gp_src}" prereqs)
		for prereq in ${prereqs}; do
			echo "${prereq} ${gp_x}"
		done
	done
}
call_scripts()
{
	set -e
	for cs_x in ${runlist}; do
		[ -f "${initdir}/${cs_x}" ] || continue
		if [ "$call_scripts_optional" = "y" ]; then
			option=$(sed '/^OPTION=/!d;$d;s/^OPTION=//;s/[[:space:]]*$//' "${initdir}/${cs_x}")
			[ -z "${option}" ] || eval test -n \"\${$option}\" -a \"\${$option}\" != \"n\" || continue
		fi
		"${initdir}/${cs_x}" && ec=$? || ec=$?
		if [ "$ec" -ne 0 ]; then
			[ -n "${version}" ] && exit "$ec"
		fi
	done
	set +e
}
run_scripts()
{
	scriptdir=${2:-}
	initdir=${1}
	[ ! -d "${initdir}" ] && return
	runlist=$(get_prereq_pairs | tsort)
	call_scripts "$scriptdir"
}
run_scripts_optional()
{
	call_scripts_optional=y
	run_scripts "$@"
}
run_scripts_optional "$PKGDIR"
run_scripts_optional "$LOCALDIR"
'''


@pytest.mark.skipif(shutil.which('dash') is None or shutil.which('tsort') is None or os.geteuid() != 0,
                    reason='needs dash, tsort and root (execute-bit semantics are root\'s)')
def test_live_hook_functions_agree(tmp_path):
    log = tmp_path / 'log'
    pkg, local = tmp_path / 'pkg', tmp_path / 'local'
    pkg.mkdir()
    local.mkdir()
    body = '#!/bin/sh\n{option}echo "$0 ${{1:-run}}" >> ' + str(log) + '\n'
    specs = {
        pkg: [('fsck', 0o755, ''), ('framebuffer', 0o755, 'OPTION=FRAMEBUFFER\n'), ('nox', 0o644, ''),
              ('a+b', 0o755, ''), ('.hidden', 0o755, ''), ('lastopt', 0o755, None)],
        local: [('fsck', 0o755, ''), ('bad', 0o755, 'if then\n'), ('x.dpkg-old', 0o701, ''), ('gated', 0o755,
                                                                                               'OPTION=ENABLED\n')],
    }
    observed = {}
    for directory, items in specs.items():
        entries = []
        for name, mode, option in items:
            path = directory / name
            if option is None:
                path.write_text(f'#!/bin/sh\necho "$0 ${{1:-run}}" >> {log}\nOPTION=FRAMEBUFFER\n')
                lines, last = ['OPTION=FRAMEBUFFER'], True
            else:
                path.write_text(body.format(option=option))
                lines = [ln for ln in option.splitlines() if ln.startswith('OPTION=')]
                last = False
            path.chmod(mode)
            entries.append(hook(name, mode=mode, syntax=name != 'bad', option_lines=lines,
                                last_line_is_option=last))
        (directory / 'subdir').mkdir()
        entries.append({'name': 'subdir', 'type': 'directory'})
        (directory / 'dangle').symlink_to(tmp_path / 'missing')
        entries.append({'name': 'dangle', 'type': 'symlink', 'target': None})
        observed[directory] = listed(*entries)
    env = {'PATH': os.environ['PATH'], 'PKGDIR': str(pkg), 'LOCALDIR': str(local), 'FRAMEBUFFER': 'n',
           'ENABLED': 'y'}
    subprocess.run(['dash', '-c', _HOOK_FUNCTIONS], env=env, check=True, capture_output=True)
    lines = log.read_text().splitlines()

    original = (ih.PACKAGE_DIR, ih.LOCAL_DIR, ih.HOOK_DIRS, ih.PASS_ENV)
    try:
        ih.PACKAGE_DIR, ih.LOCAL_DIR, ih.HOOK_DIRS = str(pkg), str(local), (str(pkg), str(local))
        ih.PASS_ENV = {str(pkg): (), str(local): ()}
        result = ih.evaluate({'family': 'debian', 'initramfs_tools': True,
                              'directories': {str(pkg): observed[pkg], str(local): observed[local]},
                              'config': {'FRAMEBUFFER': 'n', 'ENABLED': 'y'}})
    finally:
        ih.PACKAGE_DIR, ih.LOCAL_DIR, ih.HOOK_DIRS, ih.PASS_ENV = original
    expected_prereqs = sorted(f'{p} prereqs' for p, _ in result['prereq_invocations'])
    expected_runs = sorted(f'{p} run' for p in result['runs'])
    assert sorted(ln for ln in lines if ln.endswith(' prereqs')) == expected_prereqs
    assert sorted(ln for ln in lines if ln.endswith(' run')) == expected_runs
    assert sorted(result['runs']) == sorted([f'{pkg}/fsck', f'{pkg}/lastopt', f'{local}/fsck',
                                             f'{local}/x.dpkg-old', f'{local}/gated'])
    # Packaged hooks all run before local hooks.
    run_lines = [ln for ln in lines if ln.endswith(' run')]
    assert max(i for i, ln in enumerate(run_lines) if ln.startswith(str(pkg) + '/')) < min(
        i for i, ln in enumerate(run_lines) if ln.startswith(str(local) + '/'))


@pytest.mark.skipif(shutil.which('dash') is None or shutil.which('tsort') is None or os.geteuid() != 0,
                    reason='needs dash, tsort and root (execute-bit semantics are root\'s)')
def test_live_entry_named_star_stops_the_pass(tmp_path):
    log = tmp_path / 'log'
    pkg, local = tmp_path / 'pkg', tmp_path / 'local'
    for directory, names in ((pkg, ('aa', 'zz')), (local, ('*', 'aa', 'zz'))):
        directory.mkdir()
        for name in names:
            path = directory / name
            path.write_text(f'#!/bin/sh\necho "$0 ${{1:-run}}" >> {log}\n')
            path.chmod(0o755)
    env = {'PATH': os.environ['PATH'], 'PKGDIR': str(pkg), 'LOCALDIR': str(local), 'LC_ALL': 'C'}
    subprocess.run(['dash', '-c', _HOOK_FUNCTIONS], env=env, check=True, capture_output=True)
    lines = log.read_text().splitlines()
    assert lines and all(ln.startswith(str(pkg) + '/') for ln in lines)

    original = (ih.PACKAGE_DIR, ih.LOCAL_DIR, ih.HOOK_DIRS, ih.PASS_ENV)
    try:
        ih.PACKAGE_DIR, ih.LOCAL_DIR, ih.HOOK_DIRS = str(pkg), str(local), (str(pkg), str(local))
        ih.PASS_ENV = {str(pkg): (), str(local): ()}
        result = ih.evaluate({'family': 'debian', 'initramfs_tools': True, 'directories': {
            str(pkg): listed(hook('aa'), hook('zz')), str(local): listed(hook('*'), hook('aa'), hook('zz'))}})
    finally:
        ih.PACKAGE_DIR, ih.LOCAL_DIR, ih.HOOK_DIRS, ih.PASS_ENV = original
    # Nothing the contract reports as running is absent from the real run, and the pass is not complete.
    assert sorted(f'{p} run' for p in result['runs']) == sorted(ln for ln in lines if ln.endswith(' run'))
    assert result['complete'] is False
