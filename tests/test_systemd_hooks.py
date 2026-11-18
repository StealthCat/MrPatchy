import os
import stat as stat_module

import pytest

from app import systemd_hooks as sh

SLEEP_DIR = '/usr/lib/systemd/system-sleep'
SHUTDOWN_DIR = '/usr/lib/systemd/system-shutdown'


def f(name, mode=0o755, size=120, uid=0):
    return {'name': name, 'type': 'file', 'mode': mode, 'size': size, 'uid': uid}


def link(name, target=..., text='/opt/hook'):
    item = {'name': name, 'type': 'symlink', 'link_target': text}
    if target is not ...:
        item['target'] = target
    return item


def listed(*entries, complete=True):
    return {'state': 'listed', 'complete': complete, 'entries': list(entries)}


EMPTY = listed()


def run(sleep=EMPTY, shutdown=EMPTY, version=255, merged_usr=True, **kwargs):
    return sh.evaluate(systemd_version=version, merged_usr=merged_usr, sleep=sleep, shutdown=shutdown, **kwargs)


def by_name(result, kind='sleep'):
    return {entry['name']: entry for entry in result['mechanisms'][kind]['entries']}


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def test_runnable_hooks_with_arguments_order_and_root_execution():
    result = run(sleep=listed(f('zz-last'), f('10-first'), f('hdparm')),
                 shutdown=listed(f('mdadm.shutdown')))
    assert result['complete'] is True
    assert result['origin'] == 'not_assessed'
    sleep = result['mechanisms']['sleep']
    assert sleep['directory'] == SLEEP_DIR
    assert sleep['program'] == 'systemd-sleep'
    assert sleep['runs_as'] == 'root'
    assert sleep['execution'] == 'parallel'
    assert sleep['errors'] == 'ignored'
    assert sleep['timeout_seconds'] == 90
    assert [hook['name'] for hook in sleep['hooks']] == ['10-first', 'hdparm', 'zz-last']
    assert [hook['start_order'] for hook in sleep['hooks']] == [0, 1, 2]
    assert ['pre', 'suspend'] in sleep['invocations']
    assert ['post', 'suspend-then-hibernate'] in sleep['invocations']
    assert len(sleep['invocations']) == 8
    assert sleep['environment'] == ['SYSTEMD_SLEEP_ACTION']
    shutdown = result['mechanisms']['shutdown']
    assert shutdown['directory'] == SHUTDOWN_DIR
    assert shutdown['invocations'] == [['halt'], ['poweroff'], ['reboot'], ['kexec'], ['exit']]
    assert [hook['path'] for hook in shutdown['hooks']] == [f'{SHUTDOWN_DIR}/mdadm.shutdown']


def test_start_order_is_byte_order_not_locale_order():
    result = run(sleep=listed(f('b'), f('B'), f('a'), f('_x')))
    assert [hook['name'] for hook in result['mechanisms']['sleep']['hooks']] == ['B', '_x', 'a', 'b']


@pytest.mark.parametrize('name', [
    '.hidden', 'hook~', 'lost+found', 'aquota.user', 'aquota.group', 'hook.dpkg-old', 'hook.dpkg-new',
    'hook.dpkg-dist', 'hook.dpkg-tmp', 'hook.dpkg-bak', 'hook.dpkg-backup', 'hook.dpkg-remove', 'hook.rpmnew',
    'hook.rpmsave', 'hook.rpmorig', 'hook.ucf-new', 'hook.ucf-old', 'hook.ucf-dist', 'hook.swp', 'hook.bak',
    'hook.old', 'hook.new', 'a.b.bak',
])
def test_hidden_and_backup_names_are_skipped(name):
    result = run(sleep=listed(f(name)))
    entry = by_name(result)[name]
    assert entry['status'] == 'skipped'
    assert entry['reason_code'] == 'hidden_or_backup'
    assert result['mechanisms']['sleep']['hooks'] == []
    assert result['complete'] is True


@pytest.mark.parametrize('name', [
    'hook.sh', 'hook.py', 'Hook', 'hook.bak.sh', 'hook.old-style', 'hook-new', 'hook.dpkg-older', 'newhook',
    'hook.NEW', 'hook.dpkg', '50-UPPER', 'with space',
])
def test_other_names_are_considered(name):
    assert sh.hidden_or_backup(name) is False
    result = run(sleep=listed(f(name)))
    assert by_name(result)[name]['status'] == 'runs'


def test_masks_non_regular_and_non_executable_entries_are_skipped():
    result = run(sleep=listed(
        f('empty', size=0),
        {'name': 'null', 'type': 'char_device'},
        link('null-link', {'type': 'char_device'}, text='/dev/null'),
        {'name': 'subdir', 'type': 'directory'},
        {'name': 'fifo', 'type': 'other'},
        link('dir-link', {'type': 'directory'}),
        f('plain', mode=0o644),
        f('group-x', mode=0o610),
        f('other-x', mode=0o601),
    ))
    entries = by_name(result)
    assert entries['empty']['reason_code'] == 'mask_empty'
    assert entries['null']['reason_code'] == 'not_regular'
    assert entries['null-link']['reason_code'] == 'mask_char_device'
    assert entries['subdir']['reason_code'] == 'not_regular'
    assert entries['fifo']['reason_code'] == 'not_regular'
    assert entries['dir-link']['reason_code'] == 'not_regular'
    assert entries['plain']['reason_code'] == 'not_executable'
    # systemd checks any execute bit, not whether root may execute the file.
    assert entries['group-x']['status'] == 'runs'
    assert entries['other-x']['status'] == 'runs'
    assert [hook['name'] for hook in result['mechanisms']['sleep']['hooks']] == ['group-x', 'other-x']
    assert result['complete'] is True


def test_symlinks_are_followed_and_dangling_links_are_skipped():
    result = run(shutdown=listed(
        link('good', {'type': 'file', 'mode': 0o755, 'size': 10, 'uid': 0}, text='/usr/sbin/tool'),
        link('dangling', None),
    ))
    entries = by_name(result, 'shutdown')
    assert entries['good']['status'] == 'runs'
    assert entries['good']['link_target'] == '/usr/sbin/tool'
    assert result['mechanisms']['shutdown']['hooks'][0]['link_target'] == '/usr/sbin/tool'
    assert entries['dangling']['reason_code'] == 'unresolvable'
    assert result['complete'] is True


def test_unobserved_symlink_target_is_blocking():
    result = run(sleep=listed(link('mystery')))
    assert by_name(result)['mystery']['status'] == 'unresolved'
    assert 'symlink_target_unobserved' in codes(result)
    assert result['complete'] is False


def test_ownership_and_writability_do_not_stop_a_hook_but_are_reported():
    result = run(sleep=listed(f('user-owned', uid=1000), f('writable', mode=0o777),
                              link('linked', {'type': 'file', 'mode': 0o775, 'size': 5, 'uid': 1001}),
                              f('clean')))
    entries = by_name(result)
    assert all(entry['status'] == 'runs' for entry in entries.values())
    assert [obs['code'] for obs in entries['user-owned']['observations']] == ['not_root_owned']
    assert entries['user-owned']['observations'][0]['uid'] == 1000
    assert [obs['code'] for obs in entries['writable']['observations']] == ['group_or_world_writable']
    assert entries['writable']['observations'][0]['mode'] == '0777'
    assert [obs['code'] for obs in entries['linked']['observations']] == ['not_root_owned', 'group_or_world_writable']
    assert entries['clean']['observations'] == []
    hooks = {hook['name']: hook for hook in result['mechanisms']['sleep']['hooks']}
    assert hooks['linked']['observations'] == ['not_root_owned', 'group_or_world_writable']
    # Observations are not gaps and do not make the result incomplete.
    assert result['complete'] is True


def test_etc_and_usr_local_hooks_are_reported_as_never_run():
    result = run(unscanned={'/etc/systemd/system-sleep': ['my-resume-fix', 'a'],
                            '/usr/local/lib/systemd/system-shutdown': ['flush']})
    records = {record['path']: record for record in result['not_scanned']}
    assert set(records) == {'/etc/systemd/system-sleep/a', '/etc/systemd/system-sleep/my-resume-fix',
                            '/usr/local/lib/systemd/system-shutdown/flush'}
    assert records['/etc/systemd/system-sleep/a']['mechanism'] == 'sleep'
    assert records['/etc/systemd/system-sleep/a']['status'] == 'not_scanned'
    assert SLEEP_DIR in records['/etc/systemd/system-sleep/a']['reason']
    assert 'v255' in records['/etc/systemd/system-sleep/a']['reason']
    assert records['/usr/local/lib/systemd/system-shutdown/flush']['mechanism'] == 'shutdown'
    assert result['mechanisms']['sleep']['hooks'] == []
    assert result['complete'] is True


def test_malformed_unscanned_input_is_blocking():
    assert run(unscanned={'/etc/cron.d': ['x']})['complete'] is False
    assert run(unscanned={'/etc/systemd/system-sleep': ['a/b']})['complete'] is False
    assert run(unscanned={'/etc/systemd/system-sleep': 'x'})['complete'] is False


def test_split_usr_requires_a_stated_libexec_dir():
    result = run(sleep=listed(f('hook')), merged_usr=False)
    assert 'libexec_dir_unknown' in codes(result)
    assert result['mechanisms']['sleep']['directory'] is None
    assert result['mechanisms']['sleep']['hooks'] == []
    assert result['complete'] is False
    assert run(merged_usr=None)['complete'] is False

    stated = run(sleep=listed(f('hook')), merged_usr=False, libexec_dir='/lib/systemd')
    assert stated['complete'] is True
    assert stated['mechanisms']['sleep']['directory'] == '/lib/systemd/system-sleep'
    assert stated['mechanisms']['sleep']['hooks'][0]['path'] == '/lib/systemd/system-sleep/hook'
    assert run(libexec_dir='/etc/systemd')['complete'] is False
    assert run(merged_usr='yes')['complete'] is False


@pytest.mark.parametrize('version, expected', [
    (249, 249), (258, 258), ('252', 252), ('252.39-1~deb12u1', 252), ('255.4-1ubuntu8.6', 255),
    ('systemd 255', None), ('', None), (True, None), (0, None), (None, None),
])
def test_parse_version(version, expected):
    assert sh.parse_version(version) == expected


def test_version_gaps():
    assert 'version_not_observed' in codes(run(version=None))
    assert run(version=None)['complete'] is False
    for version in (247, 259, '245.4-4ubuntu3'):
        result = run(version=version)
        assert 'version_unsupported' in codes(result)
        assert result['complete'] is False
    assert 'input_malformed' in codes(run(version='unknown'))
    for version in sh.REFERENCE_VERSIONS:
        assert run(version=version)['complete'] is True


def test_directory_states():
    absent = run(sleep={'state': 'absent', 'entries': []})
    assert absent['complete'] is True
    assert absent['mechanisms']['sleep']['directory_state'] == 'absent'
    assert absent['mechanisms']['sleep']['hooks'] == []

    missing = run(sleep=None)
    assert 'directory_not_observed' in codes(missing)
    assert missing['complete'] is False

    unreadable = run(shutdown={'state': 'unreadable', 'entries': []})
    assert 'directory_unreadable' in codes(unreadable)
    assert unreadable['complete'] is False

    partial = run(sleep=listed(f('hook'), complete=False))
    assert 'listing_incomplete' in codes(partial)
    assert partial['complete'] is False
    assert [hook['name'] for hook in partial['mechanisms']['sleep']['hooks']] == ['hook']

    contradictory = run(sleep={'state': 'absent', 'entries': [f('hook')]})
    assert 'input_malformed' in codes(contradictory)
    assert contradictory['complete'] is False
    assert contradictory['mechanisms']['sleep']['hooks'] == []

    for bad in ({'state': 'listed', 'entries': []}, {'state': 'gone', 'entries': []},
                {'state': 'listed', 'complete': True, 'entries': 'x'}, 'listed'):
        result = run(sleep=bad)
        assert 'input_malformed' in codes(result)
        assert result['complete'] is False


def test_unreadable_directory_never_reports_supplied_entries_as_running():
    result = run(sleep={'state': 'unreadable', 'entries': [f('hook')]})
    assert result['mechanisms']['sleep']['hooks'] == []
    assert by_name(result)['hook']['status'] == 'unresolved'


@pytest.mark.parametrize('item', [
    {'name': 'x', 'type': 'file', 'mode': 0o755, 'size': 1},
    {'name': 'x', 'type': 'file', 'mode': 0o755, 'uid': 0},
    {'name': 'x', 'type': 'file', 'mode': 0o17777, 'size': 1, 'uid': 0},
    {'name': 'x', 'type': 'file', 'mode': True, 'size': 1, 'uid': 0},
    {'name': 'x', 'type': 'symlink', 'target': {'type': 'file', 'mode': 0o755}},
    {'name': 'x', 'type': 'symlink', 'target': {'type': 'symlink'}},
])
def test_missing_metadata_is_blocking(item):
    result = run(sleep=listed(item))
    assert by_name(result)['x']['status'] == 'unresolved'
    assert 'metadata_missing' in codes(result)
    assert result['complete'] is False
    assert result['mechanisms']['sleep']['hooks'] == []


@pytest.mark.parametrize('item', [
    'x', {'type': 'file'}, {'name': 'a/b', 'type': 'file'}, {'name': '..', 'type': 'file'},
    {'name': 'x', 'type': 'socket'}, {'name': 'x' * 256, 'type': 'file'},
])
def test_malformed_entries_are_blocking(item):
    result = run(sleep=listed(item))
    assert 'input_malformed' in codes(result)
    assert result['complete'] is False


def test_hidden_name_wins_over_missing_metadata():
    result = run(sleep=listed({'name': '.keep', 'type': 'file'}))
    assert by_name(result)['.keep']['reason_code'] == 'hidden_or_backup'
    assert result['complete'] is True


def test_duplicates_and_limits():
    duplicate = run(sleep=listed(f('hook'), f('hook', mode=0o644)))
    assert 'duplicate_name' in codes(duplicate)
    assert by_name(duplicate)['hook']['status'] == 'runs'
    assert duplicate['complete'] is False

    many = run(sleep=listed(*[f(f'h{index:04d}') for index in range(sh.MAX_ENTRIES + 1)]))
    assert 'too_many_entries' in codes(many)
    assert len(many['mechanisms']['sleep']['entries']) == sh.MAX_ENTRIES
    assert many['complete'] is False

    gaps = run(sleep=listed(*[link(f'l{index}') for index in range(sh.MAX_GAPS + 10)]))
    assert len(gaps['gaps']) == sh.MAX_GAPS
    assert gaps['gaps'][-1]['code'] == 'gaps_truncated'
    assert gaps['complete'] is False


def test_result_never_carries_contents_or_authorization():
    result = run(sleep=listed(f('hook')))
    text = repr(result).lower()
    assert 'authoriz' not in text
    assert 'quarantine' not in text
    assert result['note'].startswith('File metadata only')
    assert result['unobserved']


def _observe(directory):
    """Build an observation the way a read-only collector would, with lstat and stat only."""
    entries = []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if stat_module.S_ISLNK(info.st_mode):
            try:
                target_info = os.stat(path)
            except OSError:
                target = None
            else:
                target = _describe(target_info)
            entries.append({'name': name, 'type': 'symlink', 'link_target': os.readlink(path), 'target': target})
        else:
            entries.append({'name': name, **_describe(info)})
    return {'state': 'listed', 'complete': True, 'entries': entries}


def _describe(info):
    if stat_module.S_ISREG(info.st_mode):
        return {'type': 'file', 'mode': stat_module.S_IMODE(info.st_mode), 'size': info.st_size, 'uid': info.st_uid}
    if stat_module.S_ISDIR(info.st_mode):
        return {'type': 'directory'}
    if stat_module.S_ISCHR(info.st_mode):
        return {'type': 'char_device'}
    return {'type': 'other'}


def test_real_directory_layout(tmp_path):
    hooks = tmp_path / 'system-sleep'
    hooks.mkdir()
    (hooks / 'nvidia').write_text('#!/bin/sh\n')
    (hooks / 'nvidia').chmod(0o755)
    (hooks / 'notes.txt').write_text('read me\n')
    (hooks / 'notes.txt').chmod(0o644)
    (hooks / 'old.dpkg-old').write_text('#!/bin/sh\n')
    (hooks / 'old.dpkg-old').chmod(0o755)
    (hooks / 'masked').symlink_to('/dev/null')
    (hooks / 'gone').symlink_to(tmp_path / 'missing')
    (hooks / 'empty').write_text('')
    (hooks / 'empty').chmod(0o755)
    (hooks / 'nested').mkdir()
    result = run(sleep=_observe(hooks))
    entries = by_name(result)
    assert [hook['name'] for hook in result['mechanisms']['sleep']['hooks']] == ['nvidia']
    assert entries['notes.txt']['reason_code'] == 'not_executable'
    assert entries['old.dpkg-old']['reason_code'] == 'hidden_or_backup'
    assert entries['masked']['reason_code'] == 'mask_char_device'
    assert entries['gone']['reason_code'] == 'unresolvable'
    assert entries['empty']['reason_code'] == 'mask_empty'
    assert entries['nested']['reason_code'] == 'not_regular'
    assert result['complete'] is True
