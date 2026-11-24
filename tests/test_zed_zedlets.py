import pytest

from app import zed_zedlets as zz

ZED_DIR = '/etc/zfs/zed.d'
ARGV = ['/usr/sbin/zed', '-F']


def f(name, mode=0o755, uid=0):
    return {'name': name, 'type': 'file', 'mode': mode, 'uid': uid}


def link(name, target=..., text='/usr/lib/zfs-linux/zed.d/x.sh'):
    item = {'name': name, 'type': 'symlink', 'link_target': text}
    if target is not ...:
        item['target'] = target
    return item


def listed(*entries, complete=True, path=None):
    observation = {'state': 'listed', 'complete': complete, 'entries': list(entries)}
    if path is not None:
        observation['path'] = path
    return observation


def run(directory=None, argv=ARGV, version='2.2.2-0ubuntu9.1', **kwargs):
    return zz.evaluate(zfs_version=version, zed_argv=argv,
                       directory=listed() if directory is None else directory, **kwargs)


def by_name(result):
    return {entry['name']: entry for entry in result['entries']}


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def test_ubuntu_default_zedlets_register_and_run_as_root_for_their_events():
    result = run(listed(link('all-syslog.sh', f('t')), link('zed-functions.sh', f('t', mode=0o644)),
                        f('zed.rc', mode=0o644), link('statechange-notify.sh', f('t')),
                        link('checksum-notify.sh', f('t')), link('data-notify.sh', f('t'))),
                 event_classes=['ereport.fs.zfs.checksum', 'resource.fs.zfs.statechange'])
    assert result['complete'] is True
    assert result['zedlet_dir'] == ZED_DIR
    assert result['runs_as'] == 'root'
    assert result['origin'] == 'not_assessed'
    assert result['invocation']['argv'] == ['<name>']
    assert result['invocation']['max_parallel'] == 16
    assert [z['name'] for z in result['zedlets']] == ['all-syslog.sh', 'checksum-notify.sh', 'data-notify.sh',
                                                     'statechange-notify.sh']
    entries = by_name(result)
    assert entries['zed.rc']['reason_code'] == 'not_executable'
    assert entries['zed-functions.sh']['reason_code'] == 'not_executable'
    checksum, statechange = result['events']
    assert checksum['subclass'] == 'checksum'
    assert checksum['match_strings'] == ['ereport.fs.zfs.checksum', 'checksum', 'all']
    assert [(r['name'], r['matched']) for r in checksum['runs']] == [('all-syslog.sh', 'all'),
                                                                      ('checksum-notify.sh', 'checksum')]
    assert [r['name'] for r in statechange['runs']] == ['all-syslog.sh', 'statechange-notify.sh']
    data = next(z for z in result['zedlets'] if z['name'] == 'data-notify.sh')
    assert data['event_classes'] == [] and data['observations'] == ['never_matches']


@pytest.mark.parametrize('name,expected', [
    ('all', True), ('all-x.sh', True), ('all_x', True), ('all1.sh', True), ('all.sh', True),
    ('allx.sh', False), ('All-x.sh', False), ('al', False), ('xall', False), ('all\xe9', True),
])
def test_all_prefix_requires_a_non_ascii_letter_after_it(name, expected):
    assert zz.matches(name, 'all') is expected


def test_pool_import_subclass_with_underscore_and_full_class_names():
    names = ['pool_import-a.sh', 'pool-x.sh', 'sysevent.fs.zfs.pool_import.sh', 'pool_importer.sh']
    result = run(listed(*[f(name) for name in names]), event_classes=['sysevent.fs.zfs.pool_import'])
    runs = result['events'][0]['runs']
    assert [(r['name'], r['matched']) for r in runs] == [('pool_import-a.sh', 'pool_import'),
                                                          ('sysevent.fs.zfs.pool_import.sh',
                                                           'sysevent.fs.zfs.pool_import')]


def test_a_zedlet_matching_two_strings_runs_twice():
    result = run(listed(f('a.b.c.d-x')), event_classes=['a.b.c.d'])
    # class 'a.b.c.d' has subclass 'd'; the name starts with the class and not with 'd'.
    assert [r['matched'] for r in result['events'][0]['runs']] == ['a.b.c.d']
    result = run(listed(f('x-1')), event_classes=['x.y.z.x'])
    assert [r['matched'] for r in result['events'][0]['runs']] == ['x']
    result = run(listed(f('x')), event_classes=['x'])
    assert result['events'][0]['subclass'] is None
    assert [r['matched'] for r in result['events'][0]['runs']] == ['x']
    result = run(listed(f('all')), event_classes=['all.fs.zfs.all'])
    assert [r['matched'] for r in result['events'][0]['runs']] == ['all', 'all']


def test_order_is_strcmp_byte_order():
    result = run(listed(f('b-x'), f('B-x'), f('a-x'), f('_x'), f('all-z')))
    assert [z['name'] for z in result['zedlets']] == ['B-x', '_x', 'a-x', 'all-z', 'b-x']
    assert [z['order'] for z in result['zedlets']] == [0, 1, 2, 3, 4]


@pytest.mark.parametrize('name', ['checksum-notify.sh.dpkg-old', 'all-syslog.sh~', 'all-syslog.sh.bak',
                                  'all.rpmsave', 'all-x.dpkg-dist'])
def test_backup_names_are_not_filtered_and_still_run(name):
    result = run(listed(f(name)))
    entry = by_name(result)[name]
    assert entry['status'] == 'registered'
    assert [obs['code'] for obs in entry['observations']] == ['backup_name_runs']


@pytest.mark.parametrize('item,code', [
    (f('.all-x'), 'hidden'),
    (f('..all'), 'hidden'),
    (f('all-x', mode=0o644), 'not_executable'),
    (f('all-x', mode=0o011), 'not_executable'),
    (f('all-x', uid=1000), 'not_root_owned'),
    (f('all-x', mode=0o775), 'group_writable'),
    (f('all-x', mode=0o757), 'other_writable'),
    (f('all-x', mode=0o777, uid=5), 'not_root_owned'),
    ({'name': 'all-d', 'type': 'directory'}, 'not_regular'),
    ({'name': 'all-c', 'type': 'char_device'}, 'not_regular'),
    (link('all-dangling', None), 'unresolvable'),
    (link('all-dir', {'type': 'directory'}), 'not_regular'),
    (link('all-null', {'type': 'char_device'}), 'not_regular'),
    (link('all-user', f('t', uid=1000)), 'not_root_owned'),
])
def test_ignored_entries_and_reasons(item, code):
    result = run(listed(item))
    entry = by_name(result)[item['name']]
    assert entry['status'] == 'ignored'
    assert entry['reason_code'] == code
    assert result['zedlets'] == []
    assert result['complete'] is True


def test_owner_execute_bit_is_required_even_with_group_and_other_execute():
    assert by_name(run(listed(f('all-x', mode=0o655))))['all-x']['reason_code'] == 'not_executable'
    assert by_name(run(listed(f('all-x', mode=0o700))))['all-x']['status'] == 'registered'
    assert by_name(run(listed(f('all-x', mode=0o4755))))['all-x']['status'] == 'registered'


def test_force_waives_owner_and_write_checks_but_not_execute_or_type():
    argv = ['/usr/sbin/zed', '-F', '-f']
    result = run(listed(f('all-a', mode=0o777, uid=1000), f('all-b', mode=0o666, uid=0),
                        {'name': 'all-c', 'type': 'fifo'}), argv=argv)
    entries = by_name(result)
    assert entries['all-a']['status'] == 'registered'
    assert {obs['code'] for obs in entries['all-a']['observations']} == {'force_waived_owner', 'force_waived_write'}
    assert entries['all-b']['reason_code'] == 'not_executable'
    assert entries['all-c']['reason_code'] == 'not_regular'
    assert result['daemon']['force'] is True


def test_dash_d_changes_the_scanned_directory_and_relative_uses_working_directory():
    result = run(listed(f('all-x'), path='/opt/zed'), argv=['/usr/sbin/zed', '-d', '/opt/zed'])
    assert result['zedlet_dir'] == '/opt/zed'
    assert result['zedlets'][0]['path'] == '/opt/zed/all-x'
    result = run(listed(f('all-x')), argv=['/usr/sbin/zed', '-dzed.d', '-d', 'x/../y'], working_directory='/srv')
    assert result['zedlet_dir'] == '/srv/x/../y'
    result = run(listed(f('all-x')), argv=['/usr/sbin/zed', '-d', 'rel'], working_directory=None)
    assert 'working_directory_unknown' in codes(result)
    assert result['complete'] is False


def test_listing_for_the_wrong_directory_is_blocking():
    result = run(listed(f('all-x'), path='/etc/zfs/zed.d'), argv=['/usr/sbin/zed', '-d', '/tmp/evil'])
    assert 'directory_mismatch' in codes(result)
    assert result['zedlets'] == []
    assert result['complete'] is False


@pytest.mark.parametrize('argv,reason', [
    (['zed', '-h'], 'exits'), (['zed', '-V'], 'exits'), (['zed', '-FL'], 'exits'),
    (['zed', '-x'], 'Unknown'), (['zed', '-d'], 'no argument'), (['zed', '-j', '0'], 'zero'),
    (['zed', '-j', 'abc'], 'zero'), (['zed', '-j', '32768'], 'too many'), (['zed', '-j', '-1'], 'too many'),
    (['zed', '-b', '2147483648'], 'too large'), (['zed', '-:'], 'Unknown'),
])
def test_command_lines_that_make_zed_exit_run_nothing(argv, reason):
    result = run(listed(f('all-x')), argv=argv)
    assert result['daemon']['starts'] is False
    assert reason in result['daemon']['exit_reason']
    assert result['zedlets'] == [] and result['entries'] == []
    assert result['complete'] is True


def test_dash_b_is_unknown_before_2_2():
    assert run(argv=['zed', '-b', '5'], version='2.1.5-1ubuntu6')['daemon']['starts'] is False
    assert run(argv=['zed', '-b', '5'], version='2.2.2')['daemon']['starts'] is True


@pytest.mark.parametrize('value,jobs', [('4', 4), ('0x10', 16), ('010', 8), (' 7', 7), ('+3', 3), ('5abc', 5),
                                        ('32767', 32767)])
def test_max_jobs_uses_strtoul_base_zero(value, jobs):
    assert run(argv=['zed', '-j', value])['invocation']['max_parallel'] == jobs


def test_getopt_permutes_non_options_and_stops_at_double_dash():
    result = run(listed(f('all-x'), path='/a'), argv=['zed', 'junk', '-d', '/a', 'more', '--', '-h', '-x'])
    assert result['daemon']['starts'] is True
    assert result['zedlet_dir'] == '/a'
    assert result['daemon']['ignored_arguments'] == ['junk', 'more', '-h', '-x']
    result = run(listed(path='//-F'), argv=['zed', '-d', '-F'])
    assert result['zedlet_dir'] == '//-F'
    assert result['daemon']['dir_option'] == '-F'
    assert result['daemon']['foreground'] is False


def test_path_override_is_reported():
    result = run(argv=['zed', '-P', '/tmp/bin:/usr/bin'])
    assert result['invocation']['path'] == '/tmp/bin:/usr/bin'


@pytest.mark.parametrize('kwargs,code', [
    ({'version': None}, 'version_not_observed'),
    ({'version': '0.8.6'}, 'version_unsupported'),
    ({'version': 'banana'}, 'input_malformed'),
    ({'argv': None}, 'argv_not_observed'),
    ({'argv': []}, 'input_malformed'),
    ({'directory': {'state': 'unreadable', 'entries': []}}, 'directory_unreadable'),
    ({'directory': listed(f('all-x'), complete=False)}, 'listing_incomplete'),
    ({'directory': {'state': 'weird'}}, 'input_malformed'),
    ({'directory': listed(link('all-x'))}, 'symlink_target_unobserved'),
    ({'directory': listed({'name': 'all-x', 'type': 'file', 'mode': 0o755})}, 'metadata_missing'),
    ({'directory': listed(f('all-x'), f('all-x'))}, 'duplicate_name'),
    ({'directory': listed({'name': 'a/b', 'type': 'file'})}, 'input_malformed'),
    ({'directory': listed(*[f(f'all-{i}') for i in range(zz.MAX_ENTRIES + 1)])}, 'too_many_entries'),
])
def test_blocking_gaps_are_never_complete(kwargs, code):
    result = run(**kwargs)
    assert code in codes(result)
    assert result['complete'] is False


def test_unobserved_directory_is_blocking():
    result = zz.evaluate(zfs_version='2.2.2', zed_argv=ARGV)
    assert 'directory_not_observed' in codes(result)
    assert result['complete'] is False


def test_absent_directory_registers_nothing_and_is_complete():
    result = run({'state': 'absent', 'entries': []})
    assert result['directory_state'] == 'absent'
    assert result['zedlets'] == [] and result['complete'] is True


def test_unreadable_listing_never_reports_registered_zedlets():
    result = run({'state': 'unreadable', 'entries': [f('all-x')]})
    assert by_name(result)['all-x']['status'] == 'unresolved'
    assert result['zedlets'] == []


def test_path_max_is_enforced():
    long_dir = '/' + 'd' * 3900
    name = 'all-' + 'x' * 200
    result = run(listed(f(name), path=long_dir), argv=['zed', '-d', long_dir])
    assert by_name(result)[name]['reason_code'] == 'path_too_long'


def test_gaps_are_bounded():
    result = run(listed(*[{'name': f'all-{i}', 'type': 'file'} for i in range(200)]))
    assert len(result['gaps']) == zz.MAX_GAPS
    assert result['gaps'][-1]['code'] == 'gaps_truncated'


def test_subclass_and_strtoul_helpers():
    assert zz.subclass('ereport.fs.zfs.io') == 'io'
    assert zz.subclass('sysevent.fs.zfs.history_event') == 'history_event'
    assert zz.subclass('a.b.c') is None
    assert zz.subclass('a.b.c.') == ''
    assert zz.strtoul('0x') == (0, False)
    assert zz.strtoul('99999999999999999999999') == (zz.ULONG_MAX, True)
