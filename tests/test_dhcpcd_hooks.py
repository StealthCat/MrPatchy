import os
import random
import shutil
import subprocess

import pytest

from app import dhcpcd_hooks as dh

SHA = '00014efd2b2044d95c3d7452df23e291bbb40b75734f8ebb268e3cef70f290e8'
NEW_SHA = '56b4d366ccc7713f96f106c253792ec94d599a90f718c4d1e54d0268cebd5cb5'
DIR = '/usr/lib/dhcpcd/dhcpcd-hooks'

# The hook loop from dhcpcd-run-hooks in dhcpcd-base 10.0.6-1ubuntu3.2, verbatim except for the
# three paths, which the differential test points at a fixture tree.
REFERENCE_LOOP = r'''for hook in \
	@ENTER@ \
	@DIR@/* \
	@EXIT@
do
	case "$hook" in
		*/*~)	continue;;
	esac
	for skip in $skip_hooks; do
		case "$hook" in
			*/"$skip")			continue 2;;
			*/[0-9][0-9]"-$skip")		continue 2;;
			*/[0-9][0-9]"-$skip.sh")	continue 2;;
		esac
	done
	if [ -f "$hook" ]; then
		. "$hook"
	fi
done
'''


def f(path, kind='file', **extra):
    return {'path': path, 'type': kind, **extra}


def run(files, absent=(dh.ENTER_HOOK, dh.EXIT_HOOK), **kw):
    kw.setdefault('script_sha256', SHA)
    kw.setdefault('hook_dir_state', 'listed')
    return dh.evaluate(files, absent=absent, **kw)


def paths(result):
    return [hook['path'] for hook in result['hooks']]


def test_packaged_hooks_are_sourced_in_byte_order_between_enter_and_exit():
    files = [f(f'{DIR}/50-ntp.conf'), f(f'{DIR}/20-resolv.conf'), f(f'{DIR}/01-test'), f(f'{DIR}/B'),
             f(f'{DIR}/a'), f(dh.ENTER_HOOK), f(dh.EXIT_HOOK)]
    result = run(files, absent=())
    assert result['complete'] is True
    assert paths(result) == [dh.ENTER_HOOK, f'{DIR}/01-test', f'{DIR}/20-resolv.conf', f'{DIR}/50-ntp.conf',
                             f'{DIR}/B', f'{DIR}/a', dh.EXIT_HOOK]
    assert [hook['source'] for hook in result['hooks']][::6] == ['enter_hook', 'exit_hook']
    assert result['run_as'] == 'root' and result['origin'] == 'not_assessed'


def test_newer_package_uses_libexec_hook_directory():
    files = [f('/usr/libexec/dhcpcd-hooks/20-resolv.conf'), f(f'{DIR}/20-resolv.conf')]
    result = run(files, script_sha256=NEW_SHA)
    assert paths(result) == ['/usr/libexec/dhcpcd-hooks/20-resolv.conf']
    assert result['files'][1]['reason_code'] == 'not_a_hook_location'


def test_any_name_without_exec_bit_is_sourced_but_backup_hidden_and_non_regular_are_not():
    files = [f(f'{DIR}/hook.sh'), f(f'{DIR}/x~'), f(f'{DIR}/.hidden'), f(f'{DIR}/sub', 'directory'),
             f(f'{DIR}/sub/inner'), f(f'{DIR}/dev', 'other'),
             f(f'{DIR}/to-file', 'symlink', target={'type': 'file'}, link_target='/tmp/evil'),
             f(f'{DIR}/to-dir', 'symlink', target={'type': 'directory'}),
             f(f'{DIR}/dangling', 'symlink', target=None)]
    result = run(files)
    assert result['complete'] is True
    assert paths(result) == [f'{DIR}/hook.sh', f'{DIR}/to-file']
    assert result['hooks'][1]['link_target'] == '/tmp/evil'
    reasons = {r['path'].rsplit('/', 1)[1]: r['reason_code'] for r in result['files']}
    assert reasons == {'hook.sh': 'sourced', 'x~': 'backup_name', '.hidden': 'hidden_name', 'sub': 'not_regular',
                       'inner': 'nested_entry', 'dev': 'not_regular', 'to-file': 'sourced', 'to-dir': 'not_regular',
                       'dangling': 'unresolvable_symlink', 'dhcpcd.enter-hook': 'absent',
                       'dhcpcd.exit-hook': 'absent'}


def test_nohook_words_skip_exact_numbered_and_sh_names_including_enter_hook():
    files = [f(f'{DIR}/20-resolv.conf'), f(f'{DIR}/30-hostname.sh'), f(f'{DIR}/ntp'), f(f'{DIR}/2-ntp'),
             f(f'{DIR}/x20-ntp'), f(f'{DIR}/50-ntp.conf'), f(dh.ENTER_HOOK)]
    result = run(files, absent=(dh.EXIT_HOOK,), nohook=['resolv.conf hostname', 'ntp', 'dhcpcd.enter-hook'])
    assert result['complete'] is True and result['nohook_observed'] is True
    assert paths(result) == [f'{DIR}/2-ntp', f'{DIR}/50-ntp.conf', f'{DIR}/x20-ntp']
    skipped = {r['path']: r.get('nohook_word') for r in result['files'] if r['reason_code'] == 'skipped_by_nohook'}
    assert skipped == {f'{DIR}/20-resolv.conf': 'resolv.conf', f'{DIR}/30-hostname.sh': 'hostname',
                       f'{DIR}/ntp': 'ntp', dh.ENTER_HOOK: 'dhcpcd.enter-hook'}


def test_unobserved_nohook_over_reports_without_blocking():
    result = run([f(f'{DIR}/20-resolv.conf')])
    assert result['complete'] is True and result['nohook_observed'] is False
    assert paths(result) == [f'{DIR}/20-resolv.conf']


@pytest.mark.parametrize('kw, code', [
    ({'script_sha256': None}, 'script_not_observed'),
    ({'script_sha256': '0' * 64}, 'script_not_reference'),
    ({'script_sha256': 'XYZ'}, 'input_malformed'),
    ({'hook_dir_state': None}, 'directory_not_observed'),
    ({'hook_dir_state': 'unreadable'}, 'directory_unreadable'),
    ({'nohook': ['*']}, 'nohook_glob'),
    ({'nohook': 'resolv.conf'}, 'input_malformed'),
    ({'absent': ()}, 'hook_not_observed'),
])
def test_blocking_gaps_are_never_complete(kw, code):
    result = run([f(f'{DIR}/a'), f(f'{DIR}/b', 'symlink')], **kw) if 'absent' not in kw else \
        dh.evaluate([f(f'{DIR}/a')], script_sha256=SHA, hook_dir_state='listed', **kw)
    assert code in [gap['code'] for gap in result['gaps']]
    assert result['complete'] is False


def test_unobserved_symlink_target_and_duplicates_block():
    result = run([f(f'{DIR}/a', 'symlink'), f(f'{DIR}/c'), f(f'{DIR}/c')])
    codes = [gap['code'] for gap in result['gaps']]
    assert 'symlink_target_unobserved' in codes and 'duplicate_path' in codes and result['complete'] is False
    assert paths(result) == [f'{DIR}/c']


def test_malformed_input_and_limits():
    result = run([{'path': 'relative', 'type': 'file'}, {'path': f'{DIR}/../x', 'type': 'file'}, 'x'])
    assert [gap['code'] for gap in result['gaps']].count('input_malformed') == 3 and not result['complete']
    many = run([f(f'{DIR}/h{i}') for i in range(dh.MAX_FILES + 1)])
    assert 'too_many_files' in [gap['code'] for gap in many['gaps']] and not many['complete']


def _build(root, rng):
    """Create a random hook tree; return (files metadata, nohook words, absent list)."""
    hook_dir, enter, exitp = f'{root}/hooks', f'{root}/enter-hook', f'{root}/exit-hook'
    os.mkdir(hook_dir)
    os.mkdir(f'{root}/adir')
    open(f'{root}/afile', 'w').close()
    names = ['01-test', '20-resolv.conf', '30-hostname', '30-hostname.sh', 'ntp', '50-ntp.conf', 'x~', '.dot',
             'B', 'a', '7-ntp', '99-ntp.sh', 'hostname', 'Z~z', 'résolv', '_x', '10-a.sh~']
    files = []
    for name in rng.sample(names, rng.randint(0, len(names))):
        path = f'{hook_dir}/{name}'
        kind = rng.choice(['file', 'file', 'file', 'dir', 'link_file', 'link_dir', 'dangling'])
        if kind == 'file':
            open(path, 'w').close()
            files.append(f(path))
        elif kind == 'dir':
            os.mkdir(path)
            files.append(f(path, 'directory'))
        else:
            target = {'link_file': f'{root}/afile', 'link_dir': f'{root}/adir', 'dangling': f'{root}/missing'}[kind]
            os.symlink(target, path)
            files.append(f(path, 'symlink', target={'link_file': {'type': 'file'}, 'link_dir': {'type': 'directory'},
                                                    'dangling': None}[kind]))
    absent = []
    for path in (enter, exitp):
        if rng.random() < 0.5:
            open(path, 'w').close()
            files.append(f(path))
        else:
            absent.append(path)
    words = rng.sample(['ntp', 'resolv.conf', 'hostname', 'hooks/a', 'enter-hook', 'test', 'B'], rng.randint(0, 3))
    return hook_dir, enter, exitp, files, words, absent


@pytest.mark.skipif(shutil.which('sh') is None, reason='needs /bin/sh')
def test_differential_against_reference_hook_loop(tmp_path, monkeypatch):
    rng = random.Random(1363)
    for trial in range(150):
        root = tmp_path / str(trial)
        root.mkdir()
        hook_dir, enter, exitp, files, words, absent = _build(str(root), rng)
        loop = REFERENCE_LOOP.replace('@ENTER@', enter).replace('@DIR@', hook_dir).replace('@EXIT@', exitp)
        # Sourcing is observed by recording "$hook" just before the "." would run.
        loop = loop.replace('\t\t. "$hook"', '\t\tprintf "%s\\n" "$hook"')
        out = subprocess.run(['sh', '-c', loop], env={'PATH': os.environ['PATH'], 'skip_hooks': ' '.join(words)},
                             cwd=str(root), capture_output=True, check=True).stdout.decode('utf-8').splitlines()
        monkeypatch.setattr(dh, 'ENTER_HOOK', enter)
        monkeypatch.setattr(dh, 'EXIT_HOOK', exitp)
        monkeypatch.setitem(dh.REFERENCES, SHA, {**dh.REFERENCES[SHA], 'hook_dir': hook_dir})
        result = dh.evaluate(files, script_sha256=SHA, hook_dir_state='listed', absent=absent, nohook=words)
        assert result['complete'] is True
        assert paths(result) == out, (trial, words, files)
