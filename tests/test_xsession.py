import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from app import xsession as xs

D = xs.SESSION_DIR
O = xs.OPTIONS_DIR
REF = xs.REFERENCE_PARTS
ALL_DIRS = [{'path': D, 'state': 'listed'}, {'path': O, 'state': 'absent'}]
OPTIONS = 'allow-failsafe\nallow-user-resources\nallow-user-xsession\nuse-ssh-agent\nuse-session-dbus\n'


def f(path, mode=0o644, uid=0, size=10, sha256=None, text=None, type='file'):
    item = {'path': path, 'type': type, 'mode': mode, 'uid': uid, 'size': size}
    if sha256 is not None:
        item['sha256'] = sha256
    if text is not None:
        item['text'] = text
    return item


def stat(**kwargs):
    item = f('/x', **kwargs)
    item.pop('path')
    return item


def part(name, **kwargs):
    kwargs.setdefault('sha256', REF.get(name, 'a' * 64))
    return f(f'{D}/{name}', **kwargs)


def reference_parts():
    return [part(name) for name in REF]


def options(text=OPTIONS, **kwargs):
    return f(xs.OPTIONS_FILE, text=text, **kwargs)


def run(files, directories=ALL_DIRS, sha=xs.REFERENCE_XSESSION_SHA256):
    return xs.evaluate(files, directories=directories, xsession_sha256=sha)


def hooks(result):
    return {h['path']: h['status'] for h in result['user_hooks']}


def codes(result):
    return [g['code'] for g in result['gaps']]


def status(result):
    return {r['path']: (r['status'], r['reason_code']) for r in result['files']}


def test_reference_install_sources_parts_in_byte_order_and_runs_user_hooks():
    files = [part('90gpg-agent'), part('15B'), part('15_b'), part('15b'), *reference_parts(), options()]
    result = run(files)
    assert result['determined'] is True and result['gaps'] == []
    assert [p['name'] for p in result['session_parts']] == [
        '15B', '15_b', '15b', '20x11-common_process-args', '40x11-common_xsessionrc',
        '50x11-common_determine-startup', '90gpg-agent']
    assert [p['order'] for p in result['session_parts']] == list(range(1, 8))
    assert hooks(result) == {'~/.xsessionrc': 'sourced', '~/.xsession': 'runs_for_default_session',
                             '~/.Xsession': 'runs_for_default_session'}
    assert result['options'] == {option: True for option in xs.KNOWN_OPTIONS}
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['note']


def test_names_outside_run_parts_rules_are_skipped_but_executable_bit_is_not_needed():
    files = [part('10ok', mode=0o600 | 0o044), part('20b.sh'), part('30c~'), part('.40d'), part('50é'),
             part('60x.dpkg-old'), *reference_parts(), options()]
    result = run(files)
    got = status(result)
    assert got[f'{D}/10ok'] == ('sourced', 'sourced')
    for name in ('20b.sh', '30c~', '.40d', '50é', '60x.dpkg-old'):
        assert got[f'{D}/{name}'] == ('ignored', 'name_filtered')


def test_symlinks_are_followed_and_non_regular_entries_skipped():
    files = [
        {'path': f'{D}/10link', 'type': 'symlink', 'link_target': '/opt/x', 'target': stat(sha256='b' * 64)},
        {'path': f'{D}/11null', 'type': 'symlink', 'link_target': '/dev/null'},
        {'path': f'{D}/12gone', 'type': 'symlink', 'link_target': '/nonexistent', 'target': None},
        {'path': f'{D}/13dirlink', 'type': 'symlink', 'link_target': '/opt', 'target': stat(type='directory')},
        f(f'{D}/14dir', type='directory'), *reference_parts(), options()]
    result = run(files)
    got = status(result)
    assert got[f'{D}/10link'] == ('sourced', 'sourced')
    assert got[f'{D}/11null'] == ('ignored', 'dev_null_link')
    assert got[f'{D}/12gone'] == ('ignored', 'dangling_symlink')
    assert got[f'{D}/13dirlink'] == ('ignored', 'not_regular')
    assert got[f'{D}/14dir'] == ('ignored', 'not_regular')
    assert result['determined'] is True


def test_observations_flag_unsafe_parts_without_verdicts():
    files = [part('10mine', uid=1000), part('11open', mode=0o666), part('12private', mode=0o600),
             part('40x11-common_xsessionrc', sha256='c' * 64), part('20x11-common_process-args'),
             part('50x11-common_determine-startup'), options()]
    result = run(files)
    obs = {p['name']: [o['code'] for o in p['observations']] for p in result['session_parts']}
    assert obs['10mine'] == ['not_root_owned']
    assert obs['11open'] == ['group_or_other_writable']
    assert obs['12private'] == ['not_world_readable']
    assert obs['40x11-common_xsessionrc'] == ['modified_reference_part']
    assert hooks(result)['~/.xsessionrc'] == 'undetermined'
    assert hooks(result)['~/.xsession'] == 'runs_for_default_session'


@pytest.mark.parametrize('text, expected', [
    ('allow-user-xsession\n', True),
    ('allow-user-xsession\nno-allow-user-xsession\n', False),
    ('no-allow-user-xsession\nallow-user-xsession', True),
    ('allow-user-xsessionfoo\n', False),
    ('allow-user-xsession_x\n', False),
    ('allow-user-xsession-extra\n', True),
    ('allow-user-xsession # comment\n', True),
    (' allow-user-xsession\n', False),
    ('# allow-user-xsession\n', False),
    ('allow-user-xsession\r\n', True),
    ('', False),
])
def test_has_option_matches_grep_word_boundaries_and_last_match(text, expected):
    assert xs.has_option(text, 'allow-user-xsession') is expected


def test_has_option_is_undetermined_for_locale_dependent_word_boundary():
    assert xs.has_option('allow-user-xsessioné\n', 'allow-user-xsession') is None
    assert xs.has_option('allow-user-xsessioné\nno-allow-user-xsession\n', 'allow-user-xsession') is False


def test_options_directory_is_concatenated_after_main_file_without_separators():
    dirs = [{'path': D, 'state': 'listed'}, {'path': O, 'state': 'listed'}]
    files = [*reference_parts(), options('allow-user-xsession\n'),
             f(f'{O}/b.conf', text='no-allow-user-xsession\n'), f(f'{O}/a.conf', text='allow-user-xsession'),
             f(f'{O}/z.disabled', text='no-allow-failsafe\n')]
    result = run(files, directories=dirs)
    # a.conf has no trailing newline, so cat joins it with b.conf: "allow-user-xsessionno-allow-..."
    # is one line whose option name is followed by a word character, and b.conf's line is lost.
    assert result['options']['allow-user-xsession'] is True
    assert status(result)[f'{O}/z.disabled'] == ('ignored', 'option_name_filtered')
    assert result['options']['allow-failsafe'] is False
    files[5] = f(f'{O}/a.conf', text='allow-user-xsession\n')
    result = run(files, directories=dirs)
    assert result['options']['allow-user-xsession'] is False
    assert hooks(result)['~/.xsession'] == 'disabled'


def test_absent_options_file_disables_user_xsession():
    files = [*reference_parts(), {'path': xs.OPTIONS_FILE, 'type': 'absent'}]
    result = run(files)
    assert result['determined'] is True
    assert result['options']['allow-user-xsession'] is False
    assert hooks(result) == {'~/.xsessionrc': 'sourced', '~/.xsession': 'disabled', '~/.Xsession': 'disabled'}


@pytest.mark.parametrize('opt, code', [
    (None, 'options_not_observed'),
    (options(text=None), 'option_text_missing'),
    (options(mode=0o600), 'option_text_missing'),
    (options(text='allow-user-xsession\x00'), 'option_text_binary'),
    (options(text='x\\nallow-user-xsession'), 'option_text_escape'),
    (options(text='a' * (xs.MAX_OPTION_TEXT + 1)), 'option_text_too_large'),
])
def test_unusable_option_text_fails_closed(opt, code):
    files = reference_parts() + ([opt] if opt else [])
    result = run(files)
    assert code in codes(result) and result['determined'] is False
    assert set(result['options'].values()) == {None}
    assert hooks(result)['~/.xsession'] == 'undetermined'
    assert hooks(result)['~/.xsessionrc'] == 'sourced'


@pytest.mark.parametrize('sha, code', [(None, 'xsession_not_observed'), ('0' * 64, 'xsession_unverified')])
def test_unverified_wrapper_blocks_user_hook_conclusions(sha, code):
    result = run([*reference_parts(), options()], sha=sha)
    assert code in codes(result) and result['determined'] is False
    assert set(hooks(result).values()) == {'undetermined'}


def test_missing_reference_parts_are_not_assumed_to_run_hooks():
    result = run([part('20x11-common_process-args'), options()])
    assert hooks(result) == {'~/.xsessionrc': 'not_by_reference', '~/.xsession': 'not_by_reference',
                             '~/.Xsession': 'not_by_reference'}
    unhashed = run([part('20x11-common_process-args'), part('40x11-common_xsessionrc', sha256=None),
                    part('50x11-common_determine-startup'), options()])
    assert hooks(unhashed)['~/.xsessionrc'] == 'undetermined'
    modified_args = run([part('20x11-common_process-args', sha256='d' * 64), part('40x11-common_xsessionrc'),
                         part('50x11-common_determine-startup'), options()])
    assert hooks(modified_args)['~/.xsession'] == 'undetermined'


@pytest.mark.parametrize('directories, code', [
    ([], 'directory_not_observed'),
    ([{'path': D, 'state': 'unreadable'}, {'path': O, 'state': 'absent'}], 'directory_unreadable'),
    ([{'path': D, 'state': 'bogus'}, {'path': O, 'state': 'absent'}], 'input_malformed'),
    ('nope', 'input_malformed'),
])
def test_directory_gaps_block_and_never_report_hooks_as_covered(directories, code):
    result = run([*reference_parts(), options()], directories=directories)
    assert code in codes(result) and result['determined'] is False
    assert 'runs_for_default_session' not in hooks(result).values()
    assert 'sourced' not in hooks(result).values()


def test_absent_session_directory_aborts_the_session():
    result = run([options()], directories=[{'path': D, 'state': 'absent'}, {'path': O, 'state': 'absent'}])
    assert result['session_aborts'] is True and result['session_parts'] == []
    assert set(hooks(result).values()) == {'not_run'}


def test_malformed_missing_duplicate_and_over_limit_input_fail_closed():
    result = run([{'path': 'relative', 'type': 'file'}, {'path': f'{D}/10x', 'type': 'file'},
                  part('11y'), part('11y'), *reference_parts(), options()])
    assert {'input_malformed', 'metadata_missing', 'duplicate_path'} <= set(codes(result))
    assert result['determined'] is False
    assert status(result)[f'{D}/10x'] == ('unresolved', 'unresolved')
    assert 'runs_for_default_session' not in hooks(result).values()
    many = [part(f'p{i:04d}') for i in range(xs.MAX_FILES + 1)]
    assert 'too_many_files' in codes(run(many + [options()]))
    assert 'input_malformed' in codes(run('nope'))


def test_files_outside_xsession_directories_are_ignored():
    result = run([f('/etc/X11/Xreset.d/10x'), *reference_parts(), options()])
    assert status(result)['/etc/X11/Xreset.d/10x'] == ('ignored', 'outside_directories')


def test_gaps_are_bounded():
    result = run([{'path': f'rel{i}', 'type': 'file'} for i in range(200)])
    assert len(result['gaps']) == xs.MAX_GAPS and result['gaps'][-1]['code'] == 'gaps_truncated'


@pytest.mark.skipif(shutil.which('run-parts') is None, reason='debianutils run-parts required')
def test_listing_matches_native_run_parts(tmp_path):
    names = ['10a', '15B', '15_b', '15b', '20b.sh', '30c~', '.40d', '50E-x_y', '80noexec', '99x.dpkg-old', '50é']
    for name in names:
        (tmp_path / name).write_text('x\n')
        os.chmod(tmp_path / name, 0o600)
    (tmp_path / '60dir').mkdir()
    os.symlink('10a', tmp_path / '70lnk')
    os.symlink('/nonexistent-target', tmp_path / '90dangling')
    os.symlink('/dev/null', tmp_path / '95null')
    os.symlink('60dir', tmp_path / '97dirlnk')
    native = subprocess.run(['run-parts', '--list', str(tmp_path)], capture_output=True, text=True,
                            env={'PATH': os.environ.get('PATH', ''), 'LC_ALL': 'C.UTF-8'}, check=False)
    expected = [line.rsplit('/', 1)[1] for line in native.stdout.splitlines()]
    files = [part(name) for name in names] + [
        f(f'{D}/60dir', type='directory'),
        {'path': f'{D}/70lnk', 'type': 'symlink', 'link_target': '10a', 'target': stat(sha256='a' * 64)},
        {'path': f'{D}/90dangling', 'type': 'symlink', 'link_target': '/nonexistent-target', 'target': None},
        {'path': f'{D}/95null', 'type': 'symlink', 'link_target': '/dev/null'},
        {'path': f'{D}/97dirlnk', 'type': 'symlink', 'link_target': '60dir', 'target': stat(type='directory')},
        options()]
    assert [p['name'] for p in run(files)['session_parts']] == expected


@pytest.mark.skipif(shutil.which('grep') is None, reason='GNU grep required')
@pytest.mark.parametrize('text', [
    'allow-user-xsession\n', 'allow-user-xsession\nno-allow-user-xsession\n', 'allow-user-xsessionfoo\n',
    'allow-user-xsession-extra\n', 'allow-user-xsession_x\n', ' allow-user-xsession\n', 'no-allow-user-xsession',
    'allow-user-xsession\r\n', 'xallow-user-xsession\nallow-user-xsession.x\n',
])
def test_has_option_matches_native_shell_function(text):
    script = ('has_option() { if [ "$(echo "$OPTIONS" | grep -Eo "^(no-)?$1\\>" | tail -n 1)" = "$1" ]; '
              'then echo yes; else echo no; fi; }; has_option allow-user-xsession')
    native = subprocess.run(['sh', '-c', script], capture_output=True, text=True, check=False,
                            env={'PATH': os.environ.get('PATH', ''), 'LC_ALL': 'C', 'OPTIONS': text})
    assert (native.stdout.strip() == 'yes') is xs.has_option(text, 'allow-user-xsession')


@pytest.mark.skipif(not os.path.isfile('/etc/X11/Xsession'), reason='installed x11-common not available')
def test_reference_hashes_match_installed_x11_common_when_it_is_the_reference_version():
    digest = hashlib.sha256(Path('/etc/X11/Xsession').read_bytes()).hexdigest()
    if digest != xs.REFERENCE_XSESSION_SHA256:
        pytest.skip('installed x11-common is not the reference version')
    for name, sha in REF.items():
        assert hashlib.sha256(Path(f'/etc/X11/Xsession.d/{name}').read_bytes()).hexdigest() == sha
