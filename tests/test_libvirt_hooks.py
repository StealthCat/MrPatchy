"""Tests for the pure libvirt hook-script contract (#1455).

Expected outcomes follow virHookCheck, virHookInitialize and virHookCall in
libvirt 10.0.0 src/util/virhook.c, and virFileIsExecutable and virDirRead in
src/util/virfile.c.
"""
from app import libvirt_hooks as lh

H = lh.HOOK_DIR
MISSING = {'type': 'missing'}
DIR = {'type': 'directory'}


def exe(mode=0o755, symlink=False):
    return {'type': 'file', 'mode': mode, 'symlink': symlink}


def base():
    """Every driver path observed and absent."""
    stats = {}
    for driver in lh.DRIVERS:
        stats[f'{H}/{driver}'] = MISSING
        stats[f'{H}/{driver}.d'] = MISSING
    return stats


def driver(result, name):
    return next(d for d in result['drivers'] if d['driver'] == name)


def paths(record):
    return [s['path'] for s in record['scripts']]


def codes(result):
    return {g['code'] for g in result['gaps']}


def test_no_hooks_is_complete_and_runs_nothing():
    result = lh.evaluate(base())
    assert result['complete'] is True
    assert result['scripts'] == []
    assert {d['status'] for d in result['drivers']} == {'no_hooks'}
    assert [d['driver'] for d in result['drivers']] == list(lh.DRIVERS)
    assert driver(result, 'network')['operations'] == [
        'start', 'started', 'stopped', 'port-created', 'port-deleted', 'updated']


def test_main_script_then_dropins_in_strcmp_order_including_hidden_names():
    stats = base()
    stats[f'{H}/qemu'] = exe()
    stats[f'{H}/qemu.d'] = DIR
    names = ['b', 'A', '.hidden', 'a.sh', '10-x', '9-y', 'Ä']
    for name in names:
        stats[f'{H}/qemu.d/{name}'] = exe(0o100)
    result = lh.evaluate(stats, {f'{H}/qemu.d': ['.', '..', *names]})
    qemu = driver(result, 'qemu')
    assert result['complete'] is True
    assert qemu['status'] == 'runs'
    assert paths(qemu) == [f'{H}/qemu'] + [f'{H}/qemu.d/{n}' for n in ['.hidden', '10-x', '9-y', 'A', 'a.sh', 'b', 'Ä']]
    assert [s['order'] for s in qemu['scripts']] == list(range(1, 9))
    assert qemu['scripts'][0]['kind'] == 'main' and qemu['scripts'][1]['hidden'] is True
    assert qemu['scripts'][0]['argv'] == [f'{H}/qemu', '<id>', '<op>', '<subop>', '<extra>']
    assert result['execution']['runs_after_failure'] is True


def test_executable_means_regular_file_with_any_execute_bit_after_following_symlinks():
    stats = base()
    stats[f'{H}/lxc.d'] = DIR
    entries = {
        'other-x': exe(0o001), 'group-x': exe(0o010), 'no-x': exe(0o644), 'setuid-no-x': exe(0o4644),
        'link': exe(0o700, symlink=True), 'dangling': {'type': 'missing', 'symlink': True},
        'subdir': DIR, 'fifo': {'type': 'other'},
    }
    for name, observed in entries.items():
        stats[f'{H}/lxc.d/{name}'] = observed
    result = lh.evaluate(stats, {f'{H}/lxc.d': list(entries)})
    lxc = driver(result, 'lxc')
    assert paths(lxc) == [f'{H}/lxc.d/{n}' for n in ('group-x', 'link', 'other-x')]
    assert lxc['scripts'][1]['symlink'] is True
    assert {s['name']: s['reason'] for s in lxc['skipped']} == {
        'dangling': 'dangling_symlink', 'fifo': 'other', 'no-x': 'not_executable',
        'setuid-no-x': 'not_executable', 'subdir': 'directory'}
    assert result['complete'] is True


def test_non_executable_main_does_not_hide_executable_dropins():
    stats = base()
    stats[f'{H}/network'] = exe(0o644)
    stats[f'{H}/network.d'] = DIR
    stats[f'{H}/network.d/up'] = exe()
    result = lh.evaluate(stats, {f'{H}/network.d': ['up']})
    network = driver(result, 'network')
    assert network['main']['state'] == 'not_executable'
    assert paths(network) == [f'{H}/network.d/up']
    assert network['skipped'][0]['path'] == f'{H}/network'


def test_dropin_dir_with_only_non_executable_entries_has_no_hooks():
    stats = base()
    stats[f'{H}/daemon.d'] = DIR
    stats[f'{H}/daemon.d/x'] = exe(0o600)
    result = lh.evaluate(stats, {f'{H}/daemon.d': ['x']})
    assert driver(result, 'daemon')['status'] == 'no_hooks'
    assert result['complete'] is True


def test_dropin_path_that_is_not_a_directory():
    # Main runs, then opendir(ENOTDIR) makes the call fail.
    stats = base()
    stats[f'{H}/qemu'] = exe()
    stats[f'{H}/qemu.d'] = exe(0o644)
    result = lh.evaluate(stats)
    qemu = driver(result, 'qemu')
    assert paths(qemu) == [f'{H}/qemu'] and qemu['call_error_after_main'] is True
    assert 'dropin_not_directory' in codes(result) and result['complete'] is True

    # Without a main script a non-executable file makes virHookCheck return 0.
    stats[f'{H}/qemu'] = MISSING
    result = lh.evaluate(stats)
    assert driver(result, 'qemu')['status'] == 'no_hooks' and result['complete'] is True


def test_executable_regular_dropin_path_fails_initialization_for_later_drivers():
    stats = base()
    stats[f'{H}/lxc.d'] = exe()
    stats[f'{H}/bhyve'] = exe()
    result = lh.evaluate(stats)
    assert result['initialize_failed'] is True and result['complete'] is False
    assert driver(result, 'qemu')['status'] == 'no_hooks'
    assert driver(result, 'lxc')['status'] == 'unresolved' and driver(result, 'lxc')['check_error'] is True
    for later in ('network', 'libxl', 'bhyve'):
        assert driver(result, later)['status'] == 'unresolved'
        assert driver(result, later)['not_checked_after'] == 'lxc'
    assert result['scripts'] == []


def test_executable_main_skips_the_dropin_check_at_initialization():
    stats = base()
    stats[f'{H}/lxc'] = exe()
    stats[f'{H}/lxc.d'] = exe()
    result = lh.evaluate(stats)
    assert result['initialize_failed'] is False
    assert driver(result, 'lxc')['call_error_after_main'] is True


def test_fail_closed_on_unobserved_state():
    stats = base()
    del stats[f'{H}/libxl']
    result = lh.evaluate(stats)
    assert result['complete'] is False and driver(result, 'libxl')['status'] == 'unresolved'
    assert driver(result, 'qemu')['status'] == 'no_hooks'

    stats = base()
    stats[f'{H}/qemu'] = {'type': 'file'}
    assert 'mode_not_observed' in codes(lh.evaluate(stats))

    stats = base()
    stats[f'{H}/qemu.d'] = DIR
    result = lh.evaluate(stats)
    assert 'listing_not_observed' in codes(result) and driver(result, 'qemu')['status'] == 'unresolved'

    result = lh.evaluate(stats, {f'{H}/qemu.d': {'state': 'unreadable'}})
    assert 'listing_unreadable' in codes(result) and result['complete'] is False

    result = lh.evaluate(stats, {f'{H}/qemu.d': ['x']})
    assert 'stat_not_observed' in codes(result) and driver(result, 'qemu')['status'] == 'unresolved'

    stats[f'{H}/qemu.d/x'] = exe()
    result = lh.evaluate(stats, {f'{H}/qemu.d': ['x', 'x']})
    assert 'duplicate_entry' in codes(result) and result['complete'] is False
    result = lh.evaluate(stats, {f'{H}/qemu.d': ['x', 'a/b']})
    assert 'malformed_entry' in codes(result) and result['complete'] is False
    result = lh.evaluate(stats, {f'{H}/qemu.d': ['y'] * (lh.MAX_ENTRIES + 1)})
    assert 'entries_over_limit' in codes(result)

    assert 'hook_dir_relative' in codes(lh.evaluate(base(), hook_dir='etc/libvirt/hooks'))
    assert lh.evaluate(None)['complete'] is False


def test_names_that_are_not_driver_hooks_never_run():
    stats = base()
    stats[f'{H}/qemu'] = exe()
    result = lh.evaluate(stats, hook_dir_listing=['qemu', 'qemu.d', 'storage', 'qemu.bak', 'QEMU', '.', '..'])
    assert [n['name'] for n in result['not_run']] == ['QEMU', 'qemu.bak', 'storage']
    assert result['complete'] is True
    assert paths(driver(result, 'qemu')) == [f'{H}/qemu']


def test_result_never_authorizes_or_classifies():
    stats = base()
    stats[f'{H}/daemon'] = exe()
    result = lh.evaluate(stats)
    assert result['origin'] == 'not_assessed'
    assert all(s['origin'] == 'not_assessed' and s['runs_as'] == 'daemon_user' for s in result['scripts'])
    assert 'authorized' not in str(result).lower()
