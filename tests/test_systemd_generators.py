import os
import stat as stat_module

import pytest

from app import systemd_generators as sg

RUN = '/run/systemd/system-generators'
ETC = '/etc/systemd/system-generators'
LOCAL = '/usr/local/lib/systemd/system-generators'
VENDOR = '/usr/lib/systemd/system-generators'
SPLIT_VENDOR = '/lib/systemd/system-generators'


def f(name, mode=0o755, size=120, uid=0):
    return {'name': name, 'type': 'file', 'mode': mode, 'size': size, 'uid': uid}


def link(name, target=..., text='/opt/gen'):
    item = {'name': name, 'type': 'symlink', 'link_target': text}
    if target is not ...:
        item['target'] = target
    return item


def listed(*entries, complete=True):
    return {'state': 'listed', 'complete': complete, 'entries': list(entries)}


ABSENT = {'state': 'absent', 'entries': []}


def observed(kind='system', libexec='/usr/lib/systemd', **overrides):
    """Return every directory of ``kind`` as absent, with ``overrides`` keyed by path."""
    dirs = {path: ABSENT for path in sg.directories_for(kind, libexec)}
    dirs.update(overrides.pop('dirs', {}))
    return dirs


def run(dirs, version=255, merged_usr=True, kinds=('system',), **kwargs):
    return sg.evaluate(systemd_version=version, merged_usr=merged_usr, directories=dirs, kinds=list(kinds),
                       **kwargs)


def entries(result, kind='system'):
    return {(e['name'], e['directory_priority']): e for e in result['kinds'][kind]['entries']}


def names(result, kind='system'):
    return [g['name'] for g in result['kinds'][kind]['generators']]


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def test_vendor_generators_run_in_byte_order_as_root_with_output_directories():
    result = run(observed(dirs={VENDOR: listed(f('systemd-fstab-generator'), f('Zz'), f('systemd-getty-generator'))}))
    assert result['complete'] is True
    assert result['origin'] == 'not_assessed'
    kind = result['kinds']['system']
    assert kind['complete'] is True
    assert kind['runs_as'] == 'root'
    assert kind['execution'] == 'parallel'
    assert kind['timeout_seconds'] == 90
    assert kind['arguments'] == ['/run/systemd/generator', '/run/systemd/generator.early',
                                 '/run/systemd/generator.late']
    assert names(result) == ['Zz', 'systemd-fstab-generator', 'systemd-getty-generator']
    assert [g['start_order'] for g in kind['generators']] == [0, 1, 2]
    assert [d['path'] for d in kind['directories']] == [RUN, ETC, LOCAL, VENDOR]


def test_higher_directory_overrides_same_name_and_records_it():
    dirs = observed(dirs={ETC: listed(f('gen')), VENDOR: listed(f('gen'), f('other'))})
    result = run(dirs)
    by = entries(result)
    assert by[('gen', 1)]['status'] == 'runs'
    assert by[('gen', 3)]['status'] == 'skipped'
    assert by[('gen', 3)]['reason_code'] == 'overridden'
    assert by[('gen', 3)]['shadowed_by'] == f'{ETC}/gen'
    gen = result['kinds']['system']['generators'][0]
    assert gen['path'] == f'{ETC}/gen'
    assert gen['overrides'] == [f'{VENDOR}/gen']
    assert 'overrides_lower' in gen['observations']
    assert names(result) == ['gen', 'other']


def test_run_directory_wins_over_etc_and_is_flagged_runtime():
    result = run(observed(dirs={RUN: listed(f('gen')), ETC: listed(f('gen'))}))
    gen = result['kinds']['system']['generators'][0]
    assert gen['path'] == f'{RUN}/gen'
    assert 'runtime_directory' in gen['observations']
    assert entries(result)[('gen', 1)]['reason_code'] == 'overridden'


@pytest.mark.parametrize('mask, code', [
    (f('gen', size=0), 'mask_empty'),
    (f('gen', mode=0o644, size=0), 'mask_empty'),
    (link('gen', {'type': 'char_device'}, '/dev/null'), 'mask_char_device'),
    ({'name': 'gen', 'type': 'char_device'}, 'mask_char_device'),
])
def test_masks_hide_the_name_in_every_lower_directory(mask, code):
    result = run(observed(dirs={ETC: listed(mask), LOCAL: listed(f('gen')), VENDOR: listed(f('gen'))}))
    by = entries(result)
    assert by[('gen', 1)]['status'] == 'masks'
    assert by[('gen', 1)]['reason_code'] == code
    assert by[('gen', 1)]['masks'] == [f'{LOCAL}/gen', f'{VENDOR}/gen']
    assert by[('gen', 2)]['reason_code'] == 'masked'
    assert by[('gen', 3)]['reason_code'] == 'masked'
    assert by[('gen', 3)]['shadowed_by'] == f'{ETC}/gen'
    assert names(result) == []
    assert result['complete'] is True


@pytest.mark.parametrize('higher, code', [
    (f('gen', mode=0o644), 'not_executable'),
    ({'name': 'gen', 'type': 'directory'}, 'not_regular'),
    ({'name': 'gen', 'type': 'other'}, 'not_regular'),
    (link('gen', None), 'unresolvable'),
    (link('gen', {'type': 'directory'}), 'not_regular'),
])
def test_skipped_entries_do_not_shadow_lower_directories(higher, code):
    result = run(observed(dirs={ETC: listed(higher), VENDOR: listed(f('gen'))}))
    by = entries(result)
    assert by[('gen', 1)]['status'] == 'skipped'
    assert by[('gen', 1)]['reason_code'] == code
    assert by[('gen', 3)]['status'] == 'runs'
    assert result['kinds']['system']['generators'][0]['path'] == f'{VENDOR}/gen'


def test_dangling_dev_null_symlink_masks_only_from_v258():
    dirs = observed(dirs={ETC: listed(link('gen', None, '/dev/null')), VENDOR: listed(f('gen'))})
    old = run(dirs, version=257)
    assert entries(old)[('gen', 1)]['reason_code'] == 'unresolvable'
    assert names(old) == ['gen']
    new = run(dirs, version='258.1-1')
    assert entries(new)[('gen', 1)]['reason_code'] == 'mask_dev_null_symlink'
    assert names(new) == []
    unknown = sg.evaluate(merged_usr=True, directories=dirs, kinds=['system'])
    assert entries(unknown)[('gen', 1)]['status'] == 'unresolved'
    assert entries(unknown)[('gen', 3)]['reason_code'] == 'shadow_undetermined'
    assert names(unknown) == []
    assert unknown['complete'] is False


def test_hidden_and_backup_names_are_skipped_and_do_not_shadow():
    result = run(observed(dirs={ETC: listed(f('.gen'), f('gen.dpkg-old'), f('gen~'), f('gen.bak')),
                                VENDOR: listed(f('gen'))}))
    by = entries(result)
    for name in ('.gen', 'gen.dpkg-old', 'gen~', 'gen.bak'):
        assert by[(name, 1)]['reason_code'] == 'hidden_or_backup'
    assert names(result) == ['gen']


def test_ownership_and_writability_are_observations_not_skips():
    result = run(observed(dirs={LOCAL: listed(f('gen', mode=0o777, uid=1000))}))
    gen = result['kinds']['system']['generators'][0]
    assert gen['observations'] == ['not_root_owned', 'group_or_world_writable']
    detail = entries(result)[('gen', 2)]['observations'][0]['detail']
    assert 'root' in detail


def test_environment_generators_run_serially_and_user_kinds_run_as_each_user():
    dirs = {}
    for kind in sg.KINDS:
        dirs.update(observed(kind))
    dirs['/usr/lib/systemd/user-environment-generators'] = listed(f('30-systemd-environment-d-generator'))
    dirs['/etc/systemd/system-environment-generators'] = listed(f('10-env'))
    dirs['/etc/systemd/user-generators'] = listed(f('user-gen'))
    result = sg.evaluate(systemd_version=252, merged_usr=True, directories=dirs)
    assert result['complete'] is True
    kinds = result['kinds']
    assert set(kinds) == set(sg.KINDS)
    assert kinds['system_environment']['execution'] == 'serial'
    assert kinds['system_environment']['runs_as'] == 'root'
    assert kinds['system_environment']['arguments'] == []
    assert kinds['user_environment']['execution'] == 'serial'
    assert kinds['user_environment']['runs_as'].startswith('each user')
    assert kinds['user']['execution'] == 'parallel'
    assert kinds['user']['arguments'][0] == '$XDG_RUNTIME_DIR/systemd/generator'
    assert names(result, 'user_environment') == ['30-systemd-environment-d-generator']
    assert names(result, 'system_environment') == ['10-env']
    assert names(result, 'user') == ['user-gen']


def test_split_usr_vendor_directory_follows_libexec_and_only_for_system_generators():
    dirs = {path: ABSENT for path in sg.directories_for('system', '/lib/systemd')}
    dirs[SPLIT_VENDOR] = listed(f('gen'))
    result = run(dirs, merged_usr=False, libexec_dir='/lib/systemd')
    assert result['complete'] is True
    assert result['kinds']['system']['generators'][0]['path'] == f'{SPLIT_VENDOR}/gen'
    assert sg.directories_for('user', '/lib/systemd')[-1] == '/usr/lib/systemd/user-generators'
    assert sg.directories_for('system_environment', '/lib/systemd')[-1] == \
        '/usr/lib/systemd/system-environment-generators'


def test_unknown_split_usr_layout_is_a_blocking_gap_for_system_generators_only():
    dirs = {path: ABSENT for path in sg.directories_for('system', None) if path}
    dirs[ETC] = listed(f('gen'))
    result = run(dirs, merged_usr=None)
    assert 'libexec_dir_unknown' in codes(result)
    assert result['complete'] is False
    assert result['kinds']['system']['complete'] is False
    # Higher-priority directories are still certain.
    assert names(result) == ['gen']
    user = sg.evaluate(systemd_version=255, merged_usr=None, directories=observed('user'), kinds=['user'])
    assert user['complete'] is True


@pytest.mark.parametrize('observation, code', [
    (None, 'directory_not_observed'),
    ({'state': 'unreadable', 'entries': []}, 'directory_unreadable'),
    (listed(complete=False), 'listing_incomplete'),
    ({'state': 'bogus', 'entries': []}, 'input_malformed'),
    ({'state': 'absent', 'entries': [f('x')]}, 'input_malformed'),
])
def test_unobserved_higher_directory_makes_lower_generators_undetermined(observation, code):
    dirs = observed(dirs={VENDOR: listed(f('gen'), f('.hidden'))})
    if observation is None:
        del dirs[ETC]
    else:
        dirs[ETC] = observation
    result = run(dirs)
    assert code in codes(result)
    assert result['complete'] is False
    assert result['kinds']['system']['complete'] is False
    by = entries(result)
    assert by[('gen', 3)]['status'] == 'unresolved'
    assert by[('gen', 3)]['reason_code'] == 'higher_directory_unobserved'
    assert by[('.hidden', 3)]['reason_code'] == 'hidden_or_backup'
    assert names(result) == []


def test_entries_seen_in_an_incomplete_listing_still_shadow_lower_ones():
    dirs = observed(dirs={ETC: listed(f('gen'), complete=False), VENDOR: listed(f('gen'), f('other'))})
    result = run(dirs)
    by = entries(result)
    assert by[('gen', 1)]['status'] == 'runs'
    assert by[('gen', 3)]['reason_code'] == 'overridden'
    assert by[('other', 3)]['reason_code'] == 'higher_directory_unobserved'
    assert names(result) == ['gen']
    assert result['complete'] is False


@pytest.mark.parametrize('entry, code', [
    ({'name': 'gen', 'type': 'file', 'mode': 0o755}, 'metadata_missing'),
    (link('gen'), 'symlink_target_unobserved'),
    (link('gen', {'type': 'file', 'mode': 0o755}), 'metadata_missing'),
])
def test_missing_metadata_is_blocking_and_leaves_lower_same_name_undetermined(entry, code):
    result = run(observed(dirs={ETC: listed(entry), VENDOR: listed(f('gen'))}))
    assert code in codes(result)
    assert result['complete'] is False
    by = entries(result)
    assert by[('gen', 1)]['status'] == 'unresolved'
    assert by[('gen', 3)]['reason_code'] == 'shadow_undetermined'
    assert names(result) == []


def test_malformed_and_duplicate_entries_are_blocking():
    result = run(observed(dirs={VENDOR: listed(f('gen'), f('gen'), {'name': 'a/b', 'type': 'file'}, 'x')}))
    assert codes(result).count('input_malformed') == 2
    assert 'duplicate_name' in codes(result)
    assert result['complete'] is False


def test_version_gaps_and_inputs():
    dirs = observed()
    assert 'version_not_observed' in codes(sg.evaluate(merged_usr=True, directories=dirs, kinds=['system']))
    assert 'version_unsupported' in codes(run(dirs, version=248))
    assert 'version_unsupported' in codes(run(dirs, version=259))
    assert 'input_malformed' in codes(run(dirs, version='garbage'))
    assert run(dirs, version='252.39-1~deb12u1')['systemd_version'] == 252
    assert 'input_malformed' in codes(run(dirs, kinds=['bogus']))
    assert 'input_malformed' in codes(run(dirs, libexec_dir='/opt/systemd'))
    assert 'input_malformed' in codes(run({**dirs, '/etc/systemd/system-sleep': ABSENT}))
    assert 'input_malformed' in codes(sg.evaluate(systemd_version=255, merged_usr=True, directories=[],
                                                  kinds=['system']))


def test_bounded_input_and_gap_truncation():
    many = listed(*[f(f'g{index:05d}') for index in range(sg.MAX_ENTRIES + 5)])
    result = run(observed(dirs={VENDOR: many}))
    assert 'too_many_entries' in codes(result)
    assert len(result['kinds']['system']['generators']) == sg.MAX_ENTRIES
    assert result['complete'] is False
    noisy = listed(*[{'name': f'x{index}', 'type': 'nope'} for index in range(200)])
    truncated = run(observed(dirs={VENDOR: noisy}))
    assert len(truncated['gaps']) == sg.MAX_GAPS
    assert truncated['gaps'][-1]['code'] == 'gaps_truncated'


def test_result_is_never_a_safety_verdict():
    result = run(observed(dirs={VENDOR: listed(f('gen'))}))
    assert result['origin'] == 'not_assessed'
    assert 'not a safety verdict' in result['note']
    assert any('SYSTEMD_GENERATOR_PATH' in line for line in result['unobserved'])
    flat = repr(result).lower()
    assert 'safe' not in flat.replace('not a safety verdict', '')


def _observe(root, path):
    """Observe one real directory with lstat/stat the way an agent collector would."""
    full = os.path.join(root, path.lstrip('/'))
    if not os.path.exists(full):
        return ABSENT
    items = []
    for name in sorted(os.listdir(full)):
        entry_path = os.path.join(full, name)
        st = os.lstat(entry_path)

        def meta(s):
            if stat_module.S_ISREG(s.st_mode):
                return {'type': 'file', 'mode': stat_module.S_IMODE(s.st_mode), 'size': s.st_size, 'uid': 0}
            if stat_module.S_ISDIR(s.st_mode):
                return {'type': 'directory'}
            if stat_module.S_ISCHR(s.st_mode):
                return {'type': 'char_device'}
            return {'type': 'other'}

        if stat_module.S_ISLNK(st.st_mode):
            try:
                target = meta(os.stat(entry_path))
            except OSError:
                target = None
            items.append({'name': name, 'type': 'symlink', 'link_target': os.readlink(entry_path),
                          'target': target})
        else:
            items.append({'name': name, **meta(st)})
    return listed(*items)


def test_real_directory_layout(tmp_path):
    root = str(tmp_path)

    def put(path, body=b'#!/bin/sh\n', mode=0o755):
        full = os.path.join(root, path.lstrip('/'))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'wb') as handle:
            handle.write(body)
        os.chmod(full, mode)
        return full

    put(f'{VENDOR}/systemd-fstab-generator')
    put(f'{VENDOR}/systemd-getty-generator')
    put(f'{VENDOR}/vendor-replaced')
    put(f'{VENDOR}/noexec-above')
    put(f'{ETC}/vendor-replaced')
    put(f'{ETC}/noexec-above', mode=0o644)
    os.symlink('/dev/null', os.path.join(root, ETC.lstrip('/'), 'systemd-getty-generator'))
    put(f'{LOCAL}/zz-planted.dpkg-old')
    put(f'{LOCAL}/empty-mask', body=b'')
    put(f'{VENDOR}/empty-mask')
    dirs = {path: _observe(root, path) for path in sg.directories_for('system', '/usr/lib/systemd')}
    result = run(dirs)
    assert result['complete'] is True
    gens = {g['name']: g['path'] for g in result['kinds']['system']['generators']}
    assert gens == {
        'noexec-above': f'{VENDOR}/noexec-above',
        'systemd-fstab-generator': f'{VENDOR}/systemd-fstab-generator',
        'vendor-replaced': f'{ETC}/vendor-replaced',
    }
    by = entries(result)
    assert by[('systemd-getty-generator', 1)]['reason_code'] == 'mask_char_device'
    assert by[('systemd-getty-generator', 3)]['reason_code'] == 'masked'
    assert by[('empty-mask', 3)]['reason_code'] == 'masked'
    assert by[('zz-planted.dpkg-old', 2)]['reason_code'] == 'hidden_or_backup'
