import os
import shutil
import subprocess

import pytest

from app import dhclient_hooks as dh

ENTER_D = dh.ENTER_DIR
EXIT_D = dh.EXIT_DIR
ALL_DIRS = [{'path': path, 'state': 'listed'} for path in dh.OBSERVED_DIRS]
GOOD = {'version': '4.4.3-P1-4ubuntu2', 'family': 'debian', 'script_sha256': dh.REFERENCE['script_sha256']}


def f(path, type='file'):
    return {'path': path, 'type': type}


def link(path, target_type, text='target'):
    item = {'path': path, 'type': 'symlink', 'link_target': text}
    if target_type is not ...:
        item['target'] = None if target_type is None else {'type': target_type}
    return item


def run(files, directories=ALL_DIRS, **kwargs):
    return dh.evaluate(files, directories=directories, **{**GOOD, **kwargs})


def status(result):
    return {r['path']: (r['status'], r['reason_code']) for r in result['files']}


def hooks(result, phase):
    return [(h['path'], h['source']) for h in result['phases'][phase]['hooks']]


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def test_ubuntu_package_defaults_are_sourced_in_order():
    result = run([
        f(f'{ENTER_D}/debug'), f(f'{ENTER_D}/resolved-enter'),
        f(f'{EXIT_D}/debug'), f(f'{EXIT_D}/resolved'), f(f'{EXIT_D}/rfc3442-classless-routes'),
        f('/etc/dhcp/dhclient.conf'), f(ENTER_D, 'directory'), f(EXIT_D, 'directory'),
    ])
    assert result['complete'] is True and result['gaps'] == []
    assert result['script_matches_reference'] is True
    assert hooks(result, 'enter') == [(f'{ENTER_D}/debug', 'directory'), (f'{ENTER_D}/resolved-enter', 'directory')]
    assert [p for p, _ in hooks(result, 'exit')] == [
        f'{EXIT_D}/debug', f'{EXIT_D}/resolved', f'{EXIT_D}/rfc3442-classless-routes']
    assert status(result)['/etc/dhcp/dhclient.conf'] == ('ignored', 'not_a_hook_location')
    assert result['origin'] == 'not_assessed'
    assert 'not a safety verdict' in result['note']


def test_single_hook_files_run_before_their_directory():
    result = run([f(f'{ENTER_D}/a'), f(dh.ENTER_FILE), f(f'{EXIT_D}/a'), f(dh.EXIT_FILE)])
    assert hooks(result, 'enter') == [(dh.ENTER_FILE, 'file'), (f'{ENTER_D}/a', 'directory')]
    assert hooks(result, 'exit') == [(dh.EXIT_FILE, 'file'), (f'{EXIT_D}/a', 'directory')]
    assert [r['order'] for r in result['files']] == [1, 0, 1, 0]


def test_run_parts_name_filter_and_byte_order():
    names = ['b', 'A', 'a', 'Z_9-x', 'hook.sh', '.hidden', 'x~', 'x.dpkg-old', 'sp ace', 'ü']
    result = run([f(f'{EXIT_D}/{name}') for name in names])
    assert [p.rsplit('/', 1)[1] for p, _ in hooks(result, 'exit')] == ['A', 'Z_9-x', 'a', 'b']
    for name in ('hook.sh', '.hidden', 'x~', 'x.dpkg-old', 'sp ace', 'ü'):
        assert status(result)[f'{EXIT_D}/{name}'] == ('ignored', 'name_filtered')
    assert result['complete'] is True


def test_file_types_and_symlinks():
    result = run([
        link(f'{ENTER_D}/to-file', 'file'), link(f'{ENTER_D}/to-dir', 'directory'),
        link(f'{ENTER_D}/dangling', None), f(f'{ENTER_D}/sub', 'directory'), f(f'{ENTER_D}/fifo', 'other'),
        f(f'{ENTER_D}/sub/inner'), link(dh.EXIT_FILE, 'file', '/opt/x'), f(dh.ENTER_FILE, 'directory'),
    ])
    s = status(result)
    assert s[f'{ENTER_D}/to-file'] == ('sourced', 'sourced')
    assert s[f'{ENTER_D}/to-dir'] == ('ignored', 'not_regular')
    assert s[f'{ENTER_D}/dangling'] == ('ignored', 'unresolvable_symlink')
    assert s[f'{ENTER_D}/sub'] == ('ignored', 'not_regular')
    assert s[f'{ENTER_D}/fifo'] == ('ignored', 'not_regular')
    assert s[f'{ENTER_D}/sub/inner'] == ('ignored', 'nested_entry')
    assert s[dh.ENTER_FILE] == ('ignored', 'not_regular')
    assert result['phases']['exit']['hooks'] == [
        {'order': 0, 'path': dh.EXIT_FILE, 'source': 'file', 'link_target': '/opt/x'}]
    assert result['complete'] is True


def test_absent_hook_directory_is_not_used_and_absent_conf_dir_implies_absent_hook_dirs():
    dirs = [{'path': dh.CONF_DIR, 'state': 'listed'}, {'path': ENTER_D, 'state': 'absent'},
            {'path': EXIT_D, 'state': 'listed'}]
    result = run([f(dh.ENTER_FILE)], directories=dirs)
    assert hooks(result, 'enter') == [(dh.ENTER_FILE, 'file')] and result['complete'] is True
    result = run([], directories=[{'path': dh.CONF_DIR, 'state': 'absent'}])
    assert result['complete'] is True and result['gaps'] == []
    result = run([f(f'{ENTER_D}/x')], directories=dirs)
    assert status(result)[f'{ENTER_D}/x'] == ('ignored', 'directory_not_used')
    assert 'input_malformed' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('kwargs,code', [
    ({'version': None}, 'version_not_observed'),
    ({'version': '4.3.5-3'}, 'version_unsupported'),
    ({'version': 'banana'}, 'version_unsupported'),
    ({'family': None}, 'family_not_observed'),
    ({'family': 'rpm'}, 'family_unsupported'),
])
def test_environment_gaps_block(kwargs, code):
    result = run([f(f'{EXIT_D}/x')], **kwargs)
    assert code in codes(result) and result['complete'] is False


def test_epoch_and_debian_revisions_are_accepted():
    for version in ('4.4.3-P1-2', '1:4.4.1-2.3+deb11u2', '4.4.3-P1-4ubuntu2'):
        assert run([], version=version)['complete'] is True


def test_unverified_script_is_a_non_blocking_gap():
    result = run([f(f'{EXIT_D}/x')], script_sha256=None)
    assert result['script_matches_reference'] is None
    assert codes(result) == ['script_not_reference'] and result['complete'] is True
    result = run([f(f'{EXIT_D}/x')], script_sha256='0' * 64)
    assert result['script_matches_reference'] is False and result['complete'] is True
    result = run([], script_sha256='XYZ')
    assert 'input_malformed' in codes(result) and result['complete'] is False


def test_fail_closed_inputs():
    result = run([link(f'{EXIT_D}/x', ...), {'path': f'{EXIT_D}/y', 'type': 'symlink', 'target': {'type': 'pipe'}}])
    assert status(result)[f'{EXIT_D}/x'] == ('unresolved', 'unresolved')
    assert status(result)[f'{EXIT_D}/y'] == ('unresolved', 'unresolved')
    assert codes(result).count('symlink_target_unobserved') == 2 and result['complete'] is False
    assert hooks(result, 'exit') == []

    result = run([f(f'{EXIT_D}/x'), f(f'{EXIT_D}/x'), {'path': 'relative', 'type': 'file'}, 'junk'])
    assert codes(result).count('duplicate_path') == 1 and codes(result).count('input_malformed') == 2

    result = run([f(f'{EXIT_D}/x')], directories=[{'path': dh.CONF_DIR, 'state': 'listed'}])
    assert codes(result).count('directory_not_observed') == 2 and result['complete'] is False

    result = run([], directories=[*ALL_DIRS[:2], {'path': EXIT_D, 'state': 'unreadable'}])
    assert 'directory_unreadable' in codes(result) and result['complete'] is False

    result = run('nope', directories='nope')
    assert codes(result).count('input_malformed') == 2 and result['complete'] is False

    result = run([f(f'{EXIT_D}/h{i}') for i in range(dh.MAX_FILES + 1)])
    assert 'too_many_files' in codes(result) and len(hooks(result, 'exit')) == dh.MAX_FILES


def test_hook_directory_metadata_must_agree_with_its_directory_observation():
    for item in (f(ENTER_D), f(ENTER_D, 'other'), link(ENTER_D, 'file'), link(ENTER_D, None)):
        result = run([item, f(f'{ENTER_D}/a')])
        assert 'input_malformed' in codes(result) and result['complete'] is False
    dirs = [{'path': dh.CONF_DIR, 'state': 'listed'}, {'path': ENTER_D, 'state': 'absent'},
            {'path': EXIT_D, 'state': 'listed'}]
    result = run([f(ENTER_D, 'directory')], directories=dirs)
    assert 'input_malformed' in codes(result) and result['complete'] is False
    for item in (f(ENTER_D, 'directory'), link(ENTER_D, 'directory')):
        result = run([item, f(f'{ENTER_D}/a')])
        assert result['complete'] is True and hooks(result, 'enter') == [(f'{ENTER_D}/a', 'directory')]
    result = run([f(ENTER_D)], directories=dirs)  # a regular file there is "absent" to [ -d ]
    assert result['complete'] is True


def test_gaps_are_bounded():
    result = run([link(f'{EXIT_D}/h{i}', ...) for i in range(200)])
    assert len(result['gaps']) == dh.MAX_GAPS and result['gaps'][-1]['code'] == 'gaps_truncated'


# Live comparison: the hook functions below are copied from /sbin/dhclient-script in
# isc-dhcp-client 4.4.3-P1-4ubuntu2, with the /etc/dhcp prefix replaced by $BASE and the
# logger call removed. Each fixture hook appends its own path to $LOG when sourced.
_SCRIPT = r'''
run_hook() {
    local script="$1"
    local exit_status=0
    if [ -f $script ]; then
        . $script
        exit_status=$?
    fi
    return $exit_status
}
run_hookdir() {
    local dir="$1"
    local exit_status=0
    if [ -d "$dir" ]; then
        for script in $(run-parts --list $dir); do
            run_hook $script
            exit_status=$((exit_status|$?))
        done
    fi
    return $exit_status
}
run_hook $BASE/dhclient-enter-hooks
run_hookdir $BASE/dhclient-enter-hooks.d
echo PHASE >> "$LOG"
run_hook $BASE/dhclient-exit-hooks
run_hookdir $BASE/dhclient-exit-hooks.d
'''


@pytest.mark.skipif(shutil.which('run-parts') is None or shutil.which('sh') is None,
                    reason='debianutils run-parts and sh required')
def test_live_dhclient_script_hook_sourcing_matches_contract(tmp_path):
    base = tmp_path / 'dhcp'
    enter, exit_ = base / 'dhclient-enter-hooks.d', base / 'dhclient-exit-hooks.d'
    enter.mkdir(parents=True)
    exit_.mkdir()
    (tmp_path / 'elsewhere').mkdir()
    log = tmp_path / 'log'

    def hook(path, label=None):
        path.write_text(f'echo {label or path.relative_to(base)} >> "$LOG"\n')

    hook(base / 'dhclient-enter-hooks')
    (base / 'dhclient-exit-hooks').mkdir()  # a directory is not sourced
    for name in ('b', 'A', 'a', 'Z_9-x', 'hook.sh', '.hidden', 'x~', 'x.dpkg-old', 'noexec'):
        hook(enter / name)
    (enter / 'subdir').mkdir()
    hook(enter / 'subdir' / 'inner')
    os.mkfifo(enter / 'fifo')
    (enter / 'dangling').symlink_to(tmp_path / 'missing')
    (enter / 'loop1').symlink_to(enter / 'loop2')
    (enter / 'loop2').symlink_to(enter / 'loop1')
    (enter / 'todir').symlink_to(tmp_path / 'elsewhere')
    hook(tmp_path / 'elsewhere' / 'target', 'elsewhere-target')
    (exit_ / 'tofile').symlink_to(tmp_path / 'elsewhere' / 'target')
    hook(exit_ / 'zz')
    for name in ('A', 'Z_9-x', 'a', 'b'):
        (enter / name).chmod(0o755)

    env = {'PATH': os.environ['PATH'], 'BASE': str(base), 'LOG': str(log)}
    subprocess.run(['sh', '-c', _SCRIPT], env=env, check=True, capture_output=True, timeout=30)
    lines = log.read_text().split()
    split = lines.index('PHASE')
    live_enter, live_exit = lines[:split], lines[split + 1:]

    files, prefix = [], str(base)
    for root, dirnames, filenames in os.walk(base):
        for name in dirnames + filenames:
            path = os.path.join(root, name)
            item = {'path': dh.CONF_DIR + path[len(prefix):]}
            if os.path.islink(path):
                item['type'] = 'symlink'
                if not os.path.exists(path):  # stat fails: dangling or looping
                    item['target'] = None
                else:
                    item['target'] = {'type': 'file' if os.path.isfile(path) else
                                      'directory' if os.path.isdir(path) else 'other'}
            else:
                item['type'] = ('file' if os.path.isfile(path) else
                                'directory' if os.path.isdir(path) else 'other')
            files.append(item)
    result = run(files)
    assert result['complete'] is True

    def rel(phase):
        return [h['path'][len(dh.CONF_DIR) + 1:] for h in result['phases'][phase]['hooks']]

    # A symlinked hook logs its target's own relative path, so compare by the hook that runs.
    assert rel('enter') == live_enter == [
        'dhclient-enter-hooks', 'dhclient-enter-hooks.d/A', 'dhclient-enter-hooks.d/Z_9-x',
        'dhclient-enter-hooks.d/a', 'dhclient-enter-hooks.d/b', 'dhclient-enter-hooks.d/noexec']
    assert rel('exit') == ['dhclient-exit-hooks.d/tofile', 'dhclient-exit-hooks.d/zz']
    assert live_exit == ['elsewhere-target', 'dhclient-exit-hooks.d/zz']
