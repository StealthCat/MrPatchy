import pytest

from app import nm_dispatcher as nd

ETC = nd.ETC_BASE
LIB = nd.LIB_BASE
ALL_DIRS = [{'path': path, 'state': 'listed'} for path in nd.SCANNED_DIRS + nd.DEVICE_DIRS]


def f(path, mode=0o755, uid=0, size=10, type='file'):
    return {'path': path, 'type': type, 'mode': mode, 'uid': uid, 'size': size}


def link(path, target, stat=..., **extra):
    item = {'path': path, 'type': 'symlink', 'link_target': target, **extra}
    if stat is not ...:
        item['target'] = stat
    return item


def stat(mode=0o755, uid=0, size=10, type='file'):
    return {'type': type, 'mode': mode, 'uid': uid, 'size': size}


def run(files, version='1.46.0', directories=ALL_DIRS):
    return nd.evaluate(files, version=version, directories=directories)


def status(result):
    return {r['path']: (r['status'], r['reason_code']) for r in result['files']}


def codes(result):
    return [g['code'] for g in result['gaps']]


def names(result, group='main'):
    return [s['name'] for s in result['groups'][group]['scripts']]


@pytest.mark.parametrize('name,considered', [
    ('10-script', True), ('script.sh', True), ('.hidden', False), ('a~', False), ('a.rpmsave', False),
    ('a.rpmorig', False), ('a.rpmnew', False), ('a.swp', False), ('a.dpkg-old', False), ('a.dpkg-dist', False),
    ('a.dpkg-old.sh', True), ('a.dpkg-x.dpkg-new', False), ('a.dpkg-', False), ('dpkg-old', True),
    ('a.swp.sh', True), ('~a', True), ('', False),
])
def test_name_filter_matches_check_filename(name, considered):
    assert nd.name_considered(name) is considered


def test_scripts_run_in_byte_order_and_groups_follow_subdirectories():
    result = run([
        f(f'{ETC}/b'), f(f'{ETC}/B'), f(f'{ETC}/10-a'), f(f'{LIB}/é'), f(f'{LIB}/09-z'),
        f(f'{ETC}/pre-up.d/up'), f(f'{LIB}/pre-down.d/down'),
        f(f'{ETC}/pre-up.d', type='directory'),
    ])
    assert result['complete'] is True and result['gaps'] == []
    assert names(result) == ['09-z', '10-a', 'B', 'b', 'é']
    assert [s['order'] for s in result['groups']['main']['scripts']] == [0, 1, 2, 3, 4]
    assert names(result, 'pre_up') == ['up'] and names(result, 'pre_down') == ['down']
    assert status(result)[f'{ETC}/pre-up.d'] == ('ignored', 'not_regular')
    assert result['origin'] == 'not_assessed' and result['unobserved']


def test_etc_overrides_and_unusable_etc_entry_masks_usr_lib():
    result = run([
        f(f'{LIB}/same'), f(f'{ETC}/same'),
        f(f'{LIB}/nulled'), link(f'{ETC}/nulled', '/dev/null'),
        f(f'{LIB}/emptied'), f(f'{ETC}/emptied', size=0),
        f(f'{LIB}/dir'), f(f'{ETC}/dir', type='directory'),
        f(f'{LIB}/perm'), f(f'{ETC}/perm', mode=0o775),
        f(f'{LIB}/gone'), link(f'{ETC}/gone', '/nonexistent', None),
        f(f'{LIB}/keep.dpkg-old'), f(f'{ETC}/keep.dpkg-old'),
    ])
    got = status(result)
    assert got[f'{ETC}/same'] == ('runs', 'runs') and got[f'{LIB}/same'] == ('overridden', 'overridden')
    assert got[f'{ETC}/nulled'] == ('ignored', 'dev_null_link')
    assert got[f'{ETC}/emptied'] == ('ignored', 'empty_file')
    assert got[f'{ETC}/dir'] == ('ignored', 'not_regular')
    assert got[f'{ETC}/perm'] == ('rejected', 'unsafe_mode')
    assert got[f'{ETC}/gone'] == ('ignored', 'dangling_symlink')
    for name in ('nulled', 'emptied', 'dir', 'perm', 'gone'):
        assert got[f'{LIB}/{name}'] == ('masked', 'masked')
    assert got[f'{ETC}/keep.dpkg-old'] == got[f'{LIB}/keep.dpkg-old'] == ('ignored', 'name_filtered')
    assert names(result) == ['same']
    masks = {r['path']: r.get('masks') for r in result['files'] if r.get('masks')}
    assert masks[f'{ETC}/perm'] == f'{LIB}/perm'
    assert result['complete'] is True


@pytest.mark.parametrize('kwargs,expected', [
    ({'uid': 1000}, ('rejected', 'not_root_owned')),
    ({'mode': 0o775}, ('rejected', 'unsafe_mode')),
    ({'mode': 0o757}, ('rejected', 'unsafe_mode')),
    ({'mode': 0o4755}, ('rejected', 'unsafe_mode')),
    ({'mode': 0o644}, ('rejected', 'not_owner_executable')),
    ({'mode': 0o100}, ('runs', 'runs')),
    ({'mode': 0o2755}, ('runs', 'runs')),
    ({'mode': 0o1755}, ('runs', 'runs')),
    ({'size': 0}, ('ignored', 'empty_file')),
    ({'type': 'other'}, ('ignored', 'not_regular')),
    ({'uid': 1000, 'size': 0}, ('ignored', 'empty_file')),
])
def test_file_checks_match_check_file_and_check_permissions(kwargs, expected):
    result = run([f(f'{ETC}/x', **kwargs)])
    assert status(result)[f'{ETC}/x'] == expected
    assert names(result) == (['x'] if expected[0] == 'runs' else [])


def test_symlinks_are_followed_for_checks_and_no_wait_is_detected():
    result = run([
        link(f'{ETC}/async', 'no-wait.d/async', stat()),
        link(f'{ETC}/abs', f'{ETC}/no-wait.d/abs', stat(), link_dir_realpath=f'{ETC}/no-wait.d'),
        link(f'{ETC}/moved', '/opt/tools/run', stat(), link_dir_realpath='/srv/no-wait.d'),
        link(f'{ETC}/looks', '/x/no-wait.d/run', stat(), link_dir_realpath='/x/real'),
        link(f'{ETC}/plain', '/opt/tools/run', stat()),
        link(f'{ETC}/user', '/home/u/run', stat(uid=1000)),
        link(f'{ETC}/dirlink', '/opt', stat(type='directory')),
        f(f'{ETC}/no-wait.d/async'),
        f(f'{ETC}/no-wait.d', type='directory'),
    ])
    waits = {s['name']: s['wait'] for s in result['groups']['main']['scripts']}
    assert waits == {'abs': False, 'async': False, 'looks': True, 'moved': False, 'plain': True}
    got = status(result)
    assert got[f'{ETC}/user'] == ('rejected', 'not_root_owned')
    assert got[f'{ETC}/dirlink'] == ('ignored', 'not_regular')
    assert got[f'{ETC}/no-wait.d/async'] == ('ignored', 'no_wait_target')
    # Deciding from the link text alone is disclosed, but does not change whether a script runs.
    assert codes(result) == ['no_wait_lexical'] and result['complete'] is True
    basis = {r['path']: r.get('wait_basis') for r in result['files'] if r['status'] == 'runs'}
    assert basis[f'{ETC}/async'] == 'lexical' and basis[f'{ETC}/abs'] == 'observed'


def test_device_handlers_prefer_etc_and_fall_back_without_masking():
    result = run([
        f(f'{ETC}/device/both'), f(f'{LIB}/device/both'),
        f(f'{ETC}/device/broken', mode=0o644), f(f'{LIB}/device/broken'),
        f(f'{LIB}/device/only'),
        f(f'{ETC}/device/.dot'), f(f'{ETC}/device/x~'), f(f'{ETC}/device/my handler'), f(f'{LIB}/device/my handler'),
        f(f'{ETC}/device/\u00e9'), f(f'{ETC}/device/ok_1.sh-'), f(f'{ETC}/device/-lead'),
        f(f'{ETC}/device/sub/deep'),
    ])
    assert [(h['name'], h['path']) for h in result['device_handlers']] == [
        ('-lead', f'{ETC}/device/-lead'), ('both', f'{ETC}/device/both'), ('broken', f'{LIB}/device/broken'),
        ('ok_1.sh-', f'{ETC}/device/ok_1.sh-'), ('only', f'{LIB}/device/only')]
    assert all(h['conditions'] == ['connection_names_handler'] for h in result['device_handlers'])
    got = status(result)
    assert got[f'{LIB}/device/both'] == ('overridden', 'overridden')
    assert got[f'{ETC}/device/broken'] == ('rejected', 'not_owner_executable')
    assert got[f'{LIB}/device/broken'] == ('runs', 'device_handler_fallback')
    # NetworkManager rejects a connection naming these, so no connection can run them.
    for path in (f'{ETC}/device/.dot', f'{ETC}/device/x~', f'{ETC}/device/my handler', f'{LIB}/device/my handler',
                 f'{ETC}/device/\u00e9'):
        assert got[path] == ('ignored', 'device_handler_name_invalid')
    assert got[f'{ETC}/device/sub/deep'] == ('ignored', 'outside_scanned_directories')
    assert names(result) == [] and result['complete'] is True


def test_device_handlers_depend_on_the_version():
    files = [f(f'{ETC}/device/h'), f(f'{ETC}/s')]
    old = run(files, version='1.36.6')
    assert status(old)[f'{ETC}/device/h'] == ('ignored', 'device_handlers_unsupported')
    assert old['device_handlers'] == [] and names(old) == ['s'] and old['complete'] is True
    for version in ('1.38.0', '1.42.4-1ubuntu2', '1.44.2'):
        stable = run(files, version=version)
        assert status(stable)[f'{ETC}/device/h'] == ('ignored', 'device_handlers_unsupported')
        assert stable['device_handlers'] == [] and stable['complete'] is True and stable['gaps'] == []
    development = run(files, version='1.45.90')
    assert status(development)[f'{ETC}/device/h'] == ('unresolved', 'unresolved')
    assert 'device_handler_version_unverified' in codes(development) and development['complete'] is False
    assert names(development) == ['s']
    for version in ('1.46.0', '1.52.0', '1.54.3', '1.58.1'):
        current = run(files, version=version)
        assert [h['name'] for h in current['device_handlers']] == ['h'] and current['gaps'] == []


@pytest.mark.parametrize('version,code,complete', [
    (None, 'version_not_observed', False), ('1.30.0', 'version_unsupported', False),
    ('banana', 'version_unsupported', False), (1.46, 'version_unsupported', False),
    ('1.59.1', 'version_newer_than_reference', True), ('2.0', 'version_newer_than_reference', True),
])
def test_version_gaps(version, code, complete):
    result = run([f(f'{ETC}/s')], version=version)
    assert code in codes(result) and result['complete'] is complete


def test_missing_metadata_and_unobserved_targets_fail_closed():
    result = run([
        {'path': f'{ETC}/nomode', 'type': 'file', 'uid': 0, 'size': 4},
        {'path': f'{ETC}/boolmode', 'type': 'file', 'mode': True, 'uid': 0, 'size': 4},
        link(f'{ETC}/unseen', '/opt/run'),
        link(f'{ETC}/badtarget', '/opt/run', {'type': 'symlink', 'mode': 0o755, 'uid': 0, 'size': 4}),
        {'path': f'{ETC}/nolink', 'type': 'symlink'},
        f(f'{LIB}/unseen'),
        f(f'{ETC}/ok'),
    ])
    got = status(result)
    for name in ('nomode', 'boolmode', 'unseen', 'badtarget', 'nolink'):
        assert got[f'{ETC}/{name}'] == ('unresolved', 'unresolved')
    # The /usr/lib script may or may not be masked, so it is not reported as running.
    assert got[f'{LIB}/unseen'] == ('unresolved', 'unresolved')
    assert names(result) == ['ok'] and result['complete'] is False
    assert set(codes(result)) == {'metadata_missing', 'symlink_target_unobserved'}


def test_directories_must_be_observed():
    result = nd.evaluate([f(f'{ETC}/s')], version='1.46.0')
    assert codes(result).count('directory_not_observed') == len(nd.SCANNED_DIRS + nd.DEVICE_DIRS)
    assert result['complete'] is False and names(result) == ['s']
    partial = [dict(d) for d in ALL_DIRS]
    partial[0]['state'] = 'unreadable'
    partial[1]['state'] = 'absent'
    result = run([f(f'{LIB}/pre-up.d/x')], directories=partial)
    assert 'directory_unreadable' in codes(result) and 'input_malformed' in codes(result)
    assert result['complete'] is False
    for bad in ('nope', [{'path': '/etc', 'state': 'listed'}], ALL_DIRS + ALL_DIRS[:1],
                [{'path': ETC, 'state': 'maybe'}]):
        assert 'input_malformed' in codes(run([], directories=bad))


def test_malformed_duplicate_outside_and_oversized_input():
    result = run([
        f(f'{ETC}/s'), f(f'{ETC}/s', mode=0o644),
        f('/opt/NetworkManager/dispatcher.d/x'),
        f(f'{ETC}/../evil'), f('relative'), f(f'{ETC}/a\nb'), 'text', {'path': f'{ETC}/t', 'type': 'socket'},
    ])
    assert codes(result).count('input_malformed') == 5 and 'duplicate_path' in codes(result)
    assert status(result) == {f'{ETC}/s': ('runs', 'runs'),
                              '/opt/NetworkManager/dispatcher.d/x': ('ignored', 'outside_dispatcher_directories')}
    assert result['complete'] is False
    assert 'input_malformed' in codes(run('nope'))
    many = run([f(f'{ETC}/s{i}') for i in range(nd.MAX_FILES + 1)])
    assert 'too_many_files' in codes(many) and many['complete'] is False
    assert len(many['files']) == nd.MAX_FILES
    noisy = run([{'path': 1}] * 200)
    assert len(noisy['gaps']) == nd.MAX_GAPS and noisy['gaps'][-1]['code'] == 'gaps_truncated'
