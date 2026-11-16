import inspect

from app import dynamic_loader as dl


def f(path, text='', **extra):
    return {'path': path, 'text': text, **extra}


def codes(result):
    return [g['code'] for g in result['gaps']]


def preload(text, **extra):
    return dl.resolve_preload({'type': 'file', 'text': text, **extra})


def names(result):
    return [e['entry'] for e in result['entries']]


def paths(result):
    return [d['path'] for d in result['directories']]


def test_preload_entries_split_only_on_space_tab_newline_and_colon():
    result = preload(b'/a.so /b.so:/c.so\t/d.so\n/e.so')
    assert names(result) == ['/a.so', '/b.so', '/c.so', '/d.so', '/e.so']
    assert [e['line'] for e in result['entries']] == [1, 1, 1, 1, 2]
    assert result['complete'] is True and result['file']['status'] == 'parsed'
    # Carriage return, vertical tab, form feed, comma and semicolon are part of an entry (glibc 2.39).
    result = preload(b'/a\r\n/b\x0b/c\x0c/d,/e;/f\n')
    assert names(result) == ['/a\r', '/b\x0b/c\x0c/d,/e;/f']
    assert [e['control_characters'] for e in result['entries']] == [True, True]


def test_preload_first_comment_is_removed_and_empty_inputs_have_no_entries():
    assert names(preload(b'/a # note /hidden\n/b\n')) == ['/a', '/b']
    assert names(preload(b'/a#')) == ['/a']
    for empty in (b'', b'#', b'\n', b' \t:\n'):
        result = preload(empty)
        assert result['entries'] == [] and result['complete'] is True


def test_preload_later_comments_outside_glibc_window_are_loaded_and_marked():
    # Native glibc 2.39 output for this exact input; the second and third comments are not removed.
    result = preload(b'/nx/a # c /nx/hid\n/nx/b\n#x\n/nx/c # y /nx/hid2\n/nx/d\n# z /nx/hid3\n/nx/e\n')
    assert names(result) == ['/nx/a', '/nx/b', '/nx/c', '#', 'y', '/nx/hid2', '/nx/d', '#', 'z', '/nx/hid3',
                             '/nx/e']
    marked = [e['entry'] for e in result['entries'] if e['after_comment_marker']]
    assert marked == ['#', 'y', '/nx/hid2', '#', 'z', '/nx/hid3']
    assert result['complete'] is True
    # A late comment that is still inside the window is removed.
    assert names(preload(b'#1\n/nx/pad\n/nx/pad\n/nx/pad\n#late /nx/evil.so\n/nx/after\n')) == [
        '/nx/pad', '/nx/pad', '/nx/pad', '/nx/after']
    assert names(preload(b'/nx/a\n#c\n#c\n#c\n#c\n#c\n/nx/z # /nx/hid\n')) == ['/nx/a', '#c', '#c', '/nx/z', '#',
                                                                                 '/nx/hid']


def test_preload_entry_fields():
    result = preload('libfoo.so $ORIGIN/x.so /opt/${LIB}/y.so /p/$PLATFORMX rel/z.so libfoo.so\n')
    by_name = {e['entry']: e for e in result['entries'][:5]}
    assert by_name['libfoo.so']['kind'] == 'library_name' and by_name['libfoo.so']['absolute'] is False
    assert by_name['$ORIGIN/x.so']['dynamic_tokens'] == ['ORIGIN'] and by_name['$ORIGIN/x.so']['kind'] == 'path'
    assert by_name['/opt/${LIB}/y.so']['dynamic_tokens'] == ['LIB'] and by_name['/opt/${LIB}/y.so']['absolute']
    assert by_name['/p/$PLATFORMX']['dynamic_tokens'] == []
    assert by_name['rel/z.so']['kind'] == 'path' and by_name['rel/z.so']['absolute'] is False
    assert result['entries'][5]['duplicate_of'] == 0 and result['entries'][0]['duplicate_of'] is None
    assert len(result['entries'][0]['entry_sha256']) == 64
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['note']
    assert {u['code'] for u in result['unobserved']} >= {'environment_and_options', 'library_files'}


def test_preload_fails_closed():
    assert codes(dl.resolve_preload(None)) == ['file_not_supplied']
    assert dl.resolve_preload(None)['complete'] is False
    absent = dl.resolve_preload({'type': 'absent'})
    assert absent['complete'] is True and absent['file']['status'] == 'absent' and absent['entries'] == []
    for item, code in (({'type': 'symlink'}, 'symlink_not_followed'), ({'type': 'file'}, 'file_unreadable'),
                       ({'type': 'fifo', 'text': b'/a'}, 'file_unreadable'),
                       ({'type': 'directory'}, 'file_unreadable'),
                       ({'type': 'file', 'text': b'/a\x00/b'}, 'nul_byte'),
                       ({'type': 'file', 'text': b'/a\xff'}, 'invalid_utf8'),
                       ({'type': 'file', 'text': b'a' * (dl.MAX_TEXT + 1)}, 'text_over_limit'),
                       ({'path': '/etc/other', 'text': b'/a'}, 'file_not_supplied')):
        result = dl.resolve_preload(item)
        assert codes(result) == [code], item
        assert result['complete'] is False and result['entries'] == []
    followed = dl.resolve_preload({'type': 'symlink', 'text': b'/a.so\n'})
    assert names(followed) == ['/a.so'] and followed['complete'] is True
    many = preload(b'x ' * (dl.MAX_ENTRIES + 1))
    assert len(many['entries']) == dl.MAX_ENTRIES and codes(many) == ['too_many_entries']
    assert many['complete'] is False
    long = preload(b'/' + b'a' * (dl.MAX_FIELD + 10))
    assert long['entries'][0]['entry_truncated'] is True and len(long['entries'][0]['entry']) == dl.MAX_FIELD


def test_conf_directory_lines_match_ldconfig():
    # Native "ldconfig -N -X -v -r" (glibc 2.39) reads each of these lines as the directory listed.
    result = dl.resolve_search_paths([f('/etc/ld.so.conf', (
        '  /a/  # comment\n/a b\n/b:/c\n/c,/d\nINCLUDE /e\nincludex /e\nhwcap 1 foo\nHWCAP\t2 bar\nrel\n/f///  \t\n'
        '/a\ninclude\ninclude \n/a/../b\n\t/g\r\n/\n#x\n\nhwcapx\n/last'))])
    assert paths(result) == ['/a', '/a b', '/b:/c', '/c,/d', 'INCLUDE /e', 'includex /e', 'rel', '/f', '/a',
                             'include', '/a/../b', '/g', 'hwcapx', '/last']
    assert result['complete'] is True
    assert result['ignored_lines'] == [
        {'file': '/etc/ld.so.conf', 'line': 7, 'reason': 'hwcap_directive'},
        {'file': '/etc/ld.so.conf', 'line': 8, 'reason': 'hwcap_directive'},
        {'file': '/etc/ld.so.conf', 'line': 16, 'reason': 'empty_after_trimming'}]
    entries = {d['order']: d for d in result['directories']}
    assert entries[0]['line'] == 1 and entries[0]['absolute'] is True
    assert entries[6]['absolute'] is False
    assert entries[8]['duplicate_of'] == 0
    assert result['includes'] == []
    assert {u['code'] for u in result['unobserved']} >= {'built_cache', 'built_in_directories', 'directory_state'}


def test_conf_trailing_whitespace_is_removed_before_trailing_slashes_and_only_once():
    # Native ldconfig (glibc 2.39) scans the directory shown for each line; a space left in front of the
    # removed slashes stays part of the name, so a look-alike of a system directory is not shown as that directory.
    cases = [('/lib /', '/lib '), ('/lib / ', '/lib '), ('/lib //  ', '/lib '), ('/lib/ /', '/lib/ '),
             ('/lib\t/', '/lib\t'), ('/d /sub/ /', '/d /sub/ '), ('/lib/ ', '/lib'), ('/lib// \t', '/lib'),
             ('/lib/ # c', '/lib'), ('/ /', '/ ')]
    for line, expected in cases:
        result = dl.resolve_search_paths([f('/etc/ld.so.conf', line + '\n')])
        assert paths(result) == [expected], line
        assert result['complete'] is True
    for line in ('/', '// ', ' / \t'):
        result = dl.resolve_search_paths([f('/etc/ld.so.conf', line + '\n')])
        assert paths(result) == [] and result['ignored_lines'][0]['reason'] == 'empty_after_trimming'
    legacy = dl.resolve_search_paths([f('/etc/ld.so.conf', '/lib /=libc6 /\n')])
    assert paths(legacy) == ['/lib /=libc6 '] and legacy['directories'][0]['legacy_path'] == '/lib '


def test_conf_wildcard_include_ending_in_a_slash_selects_directories_only():
    # Native ldconfig (glibc 2.39): "include /etc/c.d/*.conf/" reads no file, "include /etc/c.d/x.conf/" reads x.conf.
    files = [f('/etc/c.d/x.conf', '/from-x\n'), f('/etc/c.d/d.conf', None, type='directory')]
    for pattern, expected, matched in (
            ('/etc/c.d/*.conf/', [], ['/etc/c.d/d.conf']), ('/etc/c.d/x.con?/', [], []),
            ('/etc/c.d/*.conf//', [], ['/etc/c.d/d.conf']), ('c.d/*/', [], ['/etc/c.d/d.conf']),
            ('/etc/c.d/*.conf', ['/from-x'], ['/etc/c.d/d.conf', '/etc/c.d/x.conf']),
            ('/etc/c.d/x.conf/', ['/from-x'], ['/etc/c.d/x.conf'])):
        result = dl.resolve_search_paths([f('/etc/ld.so.conf', f'include {pattern}\n/after\n'), *files], ('/etc/c.d',))
        assert paths(result) == expected + ['/after'], pattern
        assert result['includes'][0]['matches'] == matched, pattern
        assert result['complete'] is True


def test_conf_includes_are_relative_sorted_nested_and_skip_hidden_names():
    result = dl.resolve_search_paths([
        f('/etc/ld.so.conf', '/first\ninclude ld.so.conf.d/*.conf\ninclude\t/etc/sub/z.conf   /etc/sub/none.conf\n'
                             '/last\n'),
        f('/etc/ld.so.conf.d/b.conf', '/b\ninclude /etc/sub/?.conf\n'),
        f('/etc/ld.so.conf.d/a.conf', '/a1\r\n/a2\n'),
        f('/etc/ld.so.conf.d/B.conf', '/upper\n'),
        f('/etc/ld.so.conf.d/.hidden.conf', '/hidden\n'),
        f('/etc/ld.so.conf.d/noext', '/noext\n'),
        f('/etc/ld.so.conf.d/dir.conf', None, type='directory'),
        f('/etc/sub/z.conf', '/z'),
        f('/etc/sub/y.conf', '/y\n'),
    ], ('/etc/ld.so.conf.d', '/etc/sub'))
    assert paths(result) == ['/first', '/upper', '/a1', '/a2', '/b', '/y', '/z', '/z', '/last']
    assert result['complete'] is True
    status = {r['path']: r['status'] for r in result['files']}
    assert status['/etc/ld.so.conf.d/.hidden.conf'] == 'not_included'
    assert status['/etc/ld.so.conf.d/noext'] == 'not_included'
    assert status['/etc/ld.so.conf.d/dir.conf'] == 'directory'
    assert status['/etc/sub/z.conf'] == 'parsed'
    z = next(r for r in result['files'] if r['path'] == '/etc/sub/z.conf')
    assert z['included_from'] == ['/etc/ld.so.conf.d/b.conf', '/etc/ld.so.conf'] and len(z['sha256']) == 64
    assert all('_data' not in r for r in result['files'])
    first = result['includes'][0]
    assert first['pattern'] == 'ld.so.conf.d/*.conf' and first['status'] == 'resolved'
    assert first['matches'] == ['/etc/ld.so.conf.d/B.conf', '/etc/ld.so.conf.d/a.conf', '/etc/ld.so.conf.d/b.conf',
                                '/etc/ld.so.conf.d/dir.conf']
    assert result['includes'][-1]['matches'] == []
    # A dot pattern selects hidden names, and a slash-heavy pattern is the same directory.
    hidden = dl.resolve_search_paths([f('/etc/ld.so.conf', 'include //etc//ld.so.conf.d//.h*\n'),
                                      f('/etc/ld.so.conf.d/.hidden.conf', '/hidden\n')])
    assert paths(hidden) == ['/hidden'] and hidden['complete'] is True


def test_conf_missing_or_absent_main_file():
    assert codes(dl.resolve_search_paths([])) == ['file_not_supplied']
    absent = dl.resolve_search_paths([{'path': '/etc/ld.so.conf', 'type': 'absent'},
                                      f('/etc/ld.so.conf.d/a.conf', '/a\n')])
    assert absent['complete'] is True and absent['directories'] == []
    assert {r['path']: r['status'] for r in absent['files']} == {'/etc/ld.so.conf': 'absent',
                                                                 '/etc/ld.so.conf.d/a.conf': 'not_included'}


def test_conf_uninterpreted_or_unlisted_includes_are_gaps_not_empty_matches():
    for line, code in (('include /etc/ld.so.conf.d/[ab].conf', 'include_pattern_not_interpreted'),
                       ('include /etc/ld.so.conf.d/a\\*.conf', 'include_pattern_not_interpreted'),
                       ('include /etc/*/a.conf', 'include_pattern_not_interpreted'),
                       ('include ../etc/ld.so.conf.d/a.conf', 'include_pattern_not_interpreted'),
                       ('include /etc/ld.so.conf.d/*.conf\r', 'include_pattern_not_interpreted'),
                       ('include /opt/app/*.conf', 'include_directory_not_listed'),
                       ('include /opt/app/lib.conf', 'include_target_not_supplied'),
                       ('include /etc/ld.so.conf.d/?.conf', 'include_pattern_not_interpreted')):
        result = dl.resolve_search_paths([f('/etc/ld.so.conf', line + '\n/after\n'),
                                          f('/etc/ld.so.conf.d/a.conf', '/a\n'),
                                          f('/etc/ld.so.conf.d/\u00e9.conf', '/e\n')])
        assert codes(result) == [code], line
        assert result['complete'] is False and result['includes'][0]['status'] == 'not_resolved'
        assert paths(result) == ['/after']
    # A supplied file outside the listed directories is read when named exactly.
    exact = dl.resolve_search_paths([f('/etc/ld.so.conf', 'include /opt/app/lib.conf\n'),
                                     f('/opt/app/lib.conf', '/opt/app/lib\n')])
    assert paths(exact) == ['/opt/app/lib'] and exact['complete'] is True


def test_conf_unreadable_included_files_and_equals_sign_fail_closed():
    result = dl.resolve_search_paths([
        f('/etc/ld.so.conf', 'include /etc/ld.so.conf.d/*.conf\n/d=libc6\n/e/ = x\n'),
        f('/etc/ld.so.conf.d/a.conf', None, type='symlink'),
        f('/etc/ld.so.conf.d/b.conf', b'/b\xff\n'),
        f('/etc/ld.so.conf.d/c.conf', b'/c\x00\n'),
        f('/etc/ld.so.conf.d/d.conf', None),
        f('/etc/ld.so.conf.d/e.conf', b'/e\n', type='socket'),
        f('/etc/ld.so.conf.d/f.conf', b'/followed\n', type='symlink'),
    ])
    assert codes(result) == ['symlink_not_followed', 'invalid_utf8', 'nul_byte', 'file_unreadable',
                             'file_unreadable', 'equals_sign_version_dependent', 'equals_sign_version_dependent']
    assert result['complete'] is False
    assert paths(result) == ['/followed', '/d=libc6', '/e/ = x']
    assert [d['legacy_path'] for d in result['directories']] == [None, '/d', '/e']
    reasons = {r['path']: r.get('reason') for r in result['files']}
    assert reasons['/etc/ld.so.conf.d/a.conf'] == 'symlink_not_followed'
    assert reasons['/etc/ld.so.conf.d/c.conf'] == 'nul_byte'


def test_conf_include_loops_and_limits_are_bounded():
    loop = dl.resolve_search_paths([f('/etc/ld.so.conf', '/a\ninclude /etc/ld.so.conf\n')])
    assert 'include_depth_exceeded' in codes(loop) and loop['complete'] is False
    assert len(loop['directories']) == dl.MAX_DEPTH + 1
    fan = dl.resolve_search_paths(
        [f('/etc/ld.so.conf', 'include /etc/ld.so.conf.d/*\n' * 40)]
        + [f(f'/etc/ld.so.conf.d/{i}.conf', '/x\n') for i in range(40)])
    assert codes(fan) == ['resolution_budget_exceeded'] and fan['complete'] is False
    too_many = dl.resolve_search_paths([f(f'/etc/ld.so.conf.d/{i}', '') for i in range(dl.MAX_FILES + 1)])
    assert codes(too_many) == ['too_many_files'] and too_many['files'] == []
    entries = dl.resolve_search_paths([f('/etc/ld.so.conf', '/x\n' * (dl.MAX_ENTRIES + 5))])
    assert len(entries['directories']) == dl.MAX_ENTRIES and codes(entries) == ['too_many_entries']
    long = dl.resolve_search_paths([f('/etc/ld.so.conf', '/' + 'a' * dl.MAX_FIELD + '\n/ok\n')])
    assert codes(long) == ['field_over_limit'] and paths(long) == ['/ok']


def test_conf_malformed_input():
    assert codes(dl.resolve_search_paths(None)) == ['input_malformed']
    result = dl.resolve_search_paths([f('/etc/ld.so.conf', '/a\n'), f('/etc/ld.so.conf', '/b\n'), 'x',
                                      f('etc/rel', ''), f('/etc/../x', ''), f('//etc/x', ''), f('/etc/a\nb', '')])
    assert codes(result) == ['duplicate_path'] + ['input_malformed'] * 5
    assert paths(result) == ['/a'] and result['complete'] is False
    gaps = dl.resolve_search_paths([f('/etc/ld.so.conf', 'include /opt/x.conf\n' * 100)])
    assert len(gaps['gaps']) == dl.MAX_GAPS and gaps['gaps'][-1]['code'] == 'gaps_truncated'
    assert gaps['complete'] is False


def test_contract_is_pure():
    source = inspect.getsource(dl)
    for forbidden in ('import os', 'import subprocess', 'open(', 'import socket', 'import ctypes', 'app.'):
        assert forbidden not in source.replace('app.dynamic_loader', '')
    assert dl.CONTRACT_VERSION == 1
