"""Tests for the pure networkd-dispatcher script contract (#1126)."""
from app import networkd_dispatcher as nd

ETC, LIB = nd.DEFAULT_SCRIPT_DIRS
ROOT_DIR = {'type': 'directory', 'mode': 0o755, 'uid': 0, 'gid': 0}
DEBIAN_DEFAULTS = {'state': 'present', 'text': '# Specify command line options here.\n'
                                              'networkd_dispatcher_args="--run-startup-triggers"\n'}


def script(path, mode=0o755, uid=0, gid=0):
    return {'path': path, 'type': 'file', 'mode': mode, 'uid': uid, 'gid': gid}


def dirs(etc=('routable.d',), lib=('routable.d',), lstat=None, extra=()):
    """Observe both default bases with the given subdirectories, each listed with root 0755 lstat."""
    out = [{'path': ETC, 'state': 'listed', 'subdirectories': list(etc)},
           {'path': LIB, 'state': 'listed', 'subdirectories': list(lib)}]
    for base, names in ((ETC, etc), (LIB, lib)):
        for name in names:
            out.append({'path': f'{base}/{name}', 'state': 'listed', 'lstat': (lstat or {}).get(base, ROOT_DIR)})
    return out + list(extra)


def run(files, directories=None, defaults=DEBIAN_DEFAULTS):
    return nd.evaluate(files, directories=dirs() if directories is None else directories, defaults=defaults)


def names(result, state='routable'):
    return [entry['path'] for entry in result['states'][state]['scripts']]


def by_path(result):
    return {record['path']: record for record in result['files']}


def test_union_is_sorted_by_code_point_and_etc_overrides_lib():
    result = run([script(f'{LIB}/routable.d/50-b'), script(f'{ETC}/routable.d/50-b'),
                  script(f'{ETC}/routable.d/Z'), script(f'{LIB}/routable.d/10-a'), script(f'{ETC}/routable.d/a')])
    assert result['complete'] is True
    assert names(result) == [f'{LIB}/routable.d/10-a', f'{ETC}/routable.d/50-b', f'{ETC}/routable.d/Z',
                             f'{ETC}/routable.d/a']
    record = by_path(result)[f'{LIB}/routable.d/50-b']
    assert record['status'] == 'overridden' and record['overridden_by'] == f'{ETC}/routable.d/50-b'
    first = result['states']['routable']['scripts'][0]
    assert first['argv'] == [f'{LIB}/routable.d/10-a'] and first['user'] == 'root' and first['shell'] is False
    assert result['startup_triggers'] is True and result['service_condition'] == 'met'


def test_no_name_filter_hidden_and_backup_names_run():
    result = run([script(f'{ETC}/routable.d/.hidden'), script(f'{ETC}/routable.d/x.dpkg-old'),
                  script(f'{ETC}/routable.d/y~')])
    assert len(names(result)) == 3


def test_permissions_must_be_exactly_0755_root_root_and_failure_falls_through():
    result = run([script(f'{ETC}/routable.d/a', mode=0o700), script(f'{LIB}/routable.d/a'),
                  script(f'{ETC}/routable.d/b', mode=0o4755), script(f'{ETC}/routable.d/c', gid=4),
                  script(f'{ETC}/routable.d/d', uid=1000), script(f'{ETC}/routable.d/e', mode=0o775)])
    records = by_path(result)
    assert names(result) == [f'{LIB}/routable.d/a']
    for name in 'abcde':
        assert records[f'{ETC}/routable.d/{name}']['reason_code'] == 'file_permissions'
    assert records[f'{LIB}/routable.d/a']['status'] == 'runs'


def test_state_directory_permissions_and_symlinked_directory_fail():
    link = {'type': 'symlink', 'mode': 0o777, 'uid': 0, 'gid': 0}
    result = run([script(f'{ETC}/routable.d/a'), script(f'{LIB}/routable.d/a')],
                 dirs(lstat={ETC: link}))
    assert names(result) == [f'{LIB}/routable.d/a']
    assert by_path(result)[f'{ETC}/routable.d/a']['reason_code'] == 'directory_permissions'
    loose = run([script(f'{ETC}/routable.d/a')], dirs(lib=(), lstat={ETC: {**ROOT_DIR, 'mode': 0o775}}))
    assert names(loose) == [] and loose['complete'] is True


def test_symlinks_follow_to_target_and_non_regular_entries_are_skipped():
    files = [{'path': f'{ETC}/routable.d/link', 'type': 'symlink', 'link_target': '/opt/x',
              'target': {'type': 'file', 'mode': 0o755, 'uid': 0, 'gid': 0}},
             {'path': f'{ETC}/routable.d/dangling', 'type': 'symlink', 'target': None},
             {'path': f'{ETC}/routable.d/sub', 'type': 'directory', 'mode': 0o755, 'uid': 0, 'gid': 0},
             {'path': f'{ETC}/routable.d/badlink', 'type': 'symlink',
              'target': {'type': 'file', 'mode': 0o777, 'uid': 0, 'gid': 0}},
             script(f'{LIB}/routable.d/sub')]
    result = run(files)
    records = by_path(result)
    assert names(result) == [f'{ETC}/routable.d/link', f'{LIB}/routable.d/sub']
    assert records[f'{ETC}/routable.d/link']['link_target'] == '/opt/x'
    assert records[f'{ETC}/routable.d/dangling']['reason_code'] == 'dangling_symlink'
    assert records[f'{ETC}/routable.d/sub']['reason_code'] == 'not_regular'
    assert records[f'{ETC}/routable.d/badlink']['reason_code'] == 'file_permissions'


def test_only_known_states_are_dispatched():
    result = run([script(f'{ETC}/up.d/x'), script(f'{ETC}/degraded-carrier.d/y')],
                 dirs(etc=('up.d', 'degraded-carrier.d'), lib=()))
    assert by_path(result)[f'{ETC}/up.d/x']['status'] == 'never_run'
    assert names(result, 'degraded-carrier') == [f'{ETC}/degraded-carrier.d/y']
    assert result['states']['degraded-carrier']['kind'] == 'operational'
    assert result['states']['configured']['kind'] == 'administrative'
    assert [item['path'] for item in result['unknown_state_directories']] == [f'{ETC}/up.d']
    assert len(nd.STATE_KIND) == 16


def test_environment_marks_radio_supplied_values():
    result = run([])
    assert 'ESSID' in result['environment'] and result['radio_supplied_environment'] == ['ESSID', 'json']


def test_defaults_file_controls_startup_triggers_and_script_dirs():
    assert run([], defaults={'state': 'absent'})['startup_triggers'] is False
    custom = {'state': 'present', 'text': "networkd_dispatcher_args='-T -S /srv/nd:/etc/networkd-dispatcher'\n"}
    directories = dirs(lib=()) + [{'path': '/srv/nd', 'state': 'listed', 'subdirectories': ['routable.d']},
                                  {'path': '/srv/nd/routable.d', 'state': 'listed', 'lstat': ROOT_DIR}]
    result = run([script('/srv/nd/routable.d/a'), script(f'{ETC}/routable.d/a'), script(f'{LIB}/routable.d/b')],
                 directories, custom)
    assert result['script_directories'] == ['/srv/nd', ETC] and result['startup_triggers'] is True
    assert names(result) == ['/srv/nd/routable.d/a']
    assert by_path(result)[f'{LIB}/routable.d/b']['reason_code'] == 'outside_script_directories'
    assert result['complete'] is True


def test_argument_parsing_follows_argparse():
    parse = nd.parse_arguments
    assert parse(['--script-dir=/a', '--run']) == {'script_dir': '/a', 'startup_triggers': True}
    assert parse(['-vvT', '-S/a']) == {'script_dir': '/a', 'startup_triggers': True}
    assert parse(['--scr', '/a', '-q']) == {'script_dir': '/a', 'startup_triggers': False}
    for bad in (['--bogus'], ['-x'], ['--help'], ['-S'], ['positional'], ['--run-startup-triggers=1']):
        assert parse(bad) is None


def test_unparseable_or_unobserved_arguments_fail_closed():
    for defaults in (None, {'state': 'unreadable'}, {'state': 'present', 'text': 'networkd_dispatcher_args="$X"'},
                     {'state': 'present', 'text': 'networkd_dispatcher_args="-S /srv/$X"'},
                     {'state': 'present', 'text': 'networkd_dispatcher_args="-S rel/dir"'},
                     {'state': 'present', 'text': 'networkd_dispatcher_args=--unknown'},
                     {'state': 'present', 'text': 'networkd_dispatcher_args="a \\\n b"'}):
        result = run([script(f'{ETC}/routable.d/a')], defaults=defaults)
        assert result['complete'] is False
        assert result['startup_triggers'] is None and result['script_directories_source'] == 'default_unconfirmed'


def test_unobserved_directories_and_metadata_fail_closed():
    missing = run([script(f'{ETC}/routable.d/a')], dirs()[:3])
    assert missing['complete'] is False
    assert any(gap['code'] == 'directory_not_observed' for gap in missing['gaps'])
    no_lstat = dirs()
    no_lstat[2] = {'path': f'{ETC}/routable.d', 'state': 'listed'}
    result = run([script(f'{ETC}/routable.d/a'), script(f'{LIB}/routable.d/a')], no_lstat)
    assert result['complete'] is False and names(result) == []
    records = by_path(result)
    assert records[f'{ETC}/routable.d/a']['status'] == 'unresolved'
    assert records[f'{LIB}/routable.d/a']['status'] == 'unresolved'
    partial = run([{'path': f'{ETC}/routable.d/a', 'type': 'file', 'mode': 0o755}])
    assert partial['complete'] is False


def test_service_condition_glob():
    assert run([], dirs(etc=(), lib=()))['service_condition'] == 'not_met'
    assert run([script(f'{ETC}/routable.d/.x')])['service_condition'] == 'not_met'
    assert run([script(f'{ETC}/up.d/x')], dirs(etc=('up.d',), lib=()))['service_condition'] == 'met'
    unobserved = [{'path': ETC, 'state': 'listed', 'subdirectories': []}]
    assert run([], unobserved)['service_condition'] == 'not_determined'


def test_limits_and_malformed_input():
    assert run('x')['complete'] is False
    over = run([script(f'{ETC}/routable.d/{index}') for index in range(nd.MAX_FILES + 1)])
    assert over['complete'] is False and any(gap['code'] == 'too_many_files' for gap in over['gaps'])
    dup = run([script(f'{ETC}/routable.d/a'), script(f'{ETC}/routable.d/a')])
    assert dup['complete'] is False


def test_report_never_claims_origin_or_verdict():
    result = run([script(f'{ETC}/routable.d/a')])
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['note']
    assert any('overrides' in item for item in result['unobserved'])


def test_unlisted_higher_directory_leaves_lower_script_unresolved():
    # scripts_in_path takes the first directory holding a name, so a lower
    # entry cannot be reported as running while a higher <state>.d is unlisted.
    lower = [script(f'{LIB}/routable.d/50-x')]
    for etc in ({'path': f'{ETC}/routable.d', 'state': 'unreadable'}, None):
        directories = [{'path': ETC, 'state': 'listed', 'subdirectories': ['routable.d']},
                       {'path': LIB, 'state': 'listed', 'subdirectories': ['routable.d']},
                       {'path': f'{LIB}/routable.d', 'state': 'listed', 'lstat': ROOT_DIR}]
        if etc is not None:
            directories.append(etc)
        result = run(lower, directories)
        assert result['complete'] is False
        assert names(result) == []
        assert by_path(result)[f'{LIB}/routable.d/50-x']['status'] == 'unresolved'
    unreadable_base = run(lower, [{'path': ETC, 'state': 'unreadable'},
                                  {'path': LIB, 'state': 'listed', 'subdirectories': ['routable.d']},
                                  {'path': f'{LIB}/routable.d', 'state': 'listed', 'lstat': ROOT_DIR}])
    assert names(unreadable_base) == [] and unreadable_base['complete'] is False
    # A higher base that is absent, or lists no such state directory, cannot shadow.
    for etc in ({'path': ETC, 'state': 'absent'}, {'path': ETC, 'state': 'listed', 'subdirectories': []}):
        result = run(lower, [etc, {'path': LIB, 'state': 'listed', 'subdirectories': ['routable.d']},
                             {'path': f'{LIB}/routable.d', 'state': 'listed', 'lstat': ROOT_DIR}])
        assert names(result) == [f'{LIB}/routable.d/50-x'] and result['complete'] is True
