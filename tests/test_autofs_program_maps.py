"""Pure autofs program-map resolution contract (roadmap F slice, #1375)."""
from app import autofs_program_maps as ap

REG_X = {'kind': 'regular', 'mode': 0o100755}
REG = {'kind': 'regular', 'mode': 0o100644}
MISSING = {'kind': 'missing'}


def entry(mount='/misc', map_='/etc/auto.misc', type_=None, fmt=None):
    return {'mount_point': mount, 'type': type_, 'format': fmt, 'map': map_}


def codes(r):
    return [g['code'] for g in r['gaps']]


def test_executable_absolute_map_is_program_run_as_root_with_key():
    r = ap.evaluate([entry(map_='/etc/auto.smb')], stats={'/etc/auto.smb': REG_X})
    [p] = r['programs']
    assert p == {'path': '/etc/auto.smb', 'argv': ['/etc/auto.smb', '<key>'], 'user': 'root', 'cwd': '/misc',
                 'trigger': 'every lookup of a key under the mount point'}
    assert r['complete'] and r['origin'] == 'not_assessed' and r['authorizes_response'] is False


def test_owner_execute_bit_alone_selects_program_map():
    # read_file_source_instance tests S_IEXEC (owner execute) only.
    group_only = {'kind': 'regular', 'mode': 0o100654}
    owner_only = {'kind': 'regular', 'mode': 0o100744}
    r = ap.evaluate([entry(map_='/etc/a'), entry('/b', '/etc/b')], stats={'/etc/a': group_only, '/etc/b': owner_only},
                    map_texts={'/etc/a': 'x -rw srv:/x\n'})
    assert [e['resolved'] for e in r['entries']] == ['file', 'program'] and r['complete']


def test_relative_name_uses_etc_through_files_source_and_default_nsswitch():
    r = ap.evaluate([entry(map_='auto.net')], stats={'/etc/auto.net': REG_X})
    assert r['programs'][0]['path'] == '/etc/auto.net' and r['complete']
    r = ap.evaluate([entry(map_='auto.net')], stats={'/etc/auto.net': REG_X}, nss_sources=[])
    assert r['programs'] == [] and r['entries'][0]['resolved'] == 'not_found' and r['complete']


def test_relative_name_with_slash_is_not_found_by_files():
    r = ap.evaluate([entry(map_='sub/auto.x')], stats={'/etc/sub/auto.x': REG_X})
    assert r['entries'][0]['resolved'] == 'not_found' and r['programs'] == []


def test_missing_files_map_falls_through_to_unobservable_remote_source():
    r = ap.evaluate([entry(map_='auto.home')], stats={'/etc/auto.home': MISSING}, nss_sources=['files', 'nis'])
    assert r['entries'][0]['resolved'] == 'remote' and not r['complete']
    assert codes(r) == ['remote_source_unobserved']


def test_remote_source_before_files_blocks_completion():
    r = ap.evaluate([entry(map_='auto.home')], stats={'/etc/auto.home': REG_X}, nss_sources=['ldap', 'files'])
    assert r['programs'] == [] and not r['complete']


def test_unknown_nsswitch_sources_are_ignored_like_nss_parse():
    r = ap.evaluate([entry(map_='auto.x')], stats={'/etc/auto.x': REG_X}, nss_sources=['dns', 'files'])
    assert r['programs'][0]['path'] == '/etc/auto.x' and r['complete']


def test_explicit_program_type_needs_absolute_executable():
    stats = {'/usr/sbin/fedfs-map-nfs4': {'kind': 'regular', 'mode': 0o100701}, '/opt/m': REG}
    r = ap.evaluate([entry('/nfs4', '/usr/sbin/fedfs-map-nfs4', 'program'), entry('/r', 'rel', 'program'),
                     entry('/n', '/opt/m', 'program')], stats=stats)
    assert [e['resolved'] for e in r['entries']] == ['program', 'refused', 'refused']
    assert len(r['programs']) == 1 and r['complete']


def test_explicit_file_type_never_executes():
    r = ap.evaluate([entry(map_='auto.x', type_='file')], stats={'/etc/auto.x': REG_X},
                    map_texts={'/etc/auto.x': 'k -ro srv:/k\n'})
    assert r['entries'][0]['resolved'] == 'file' and r['entries'][0]['path'] == '/etc/auto.x'
    assert r['programs'] == [] and r['complete']


def test_hosts_and_missing_absolute_maps_run_nothing():
    r = ap.evaluate([entry('/net', None, 'hosts'), entry(map_='/etc/gone'), entry('/d', '/etc/dir')],
                    stats={'/etc/gone': MISSING, '/etc/dir': {'kind': 'directory', 'mode': 0o40755}})
    assert [e['resolved'] for e in r['entries']] == ['hosts', 'not_found', 'not_found']
    assert r['programs'] == [] and r['complete']


def test_fail_closed_gaps():
    r = ap.evaluate([entry(map_='/etc/unseen')])
    assert codes(r) == ['stat_not_observed'] and not r['complete']
    r = ap.evaluate([entry(map_='//ldap.example/ou=auto')])
    assert r['entries'][0]['resolved'] == 'remote' and not r['complete']
    r = ap.evaluate([entry(map_='amd.home', fmt='amd')])
    assert codes(r) == ['amd_search_path_unobserved']
    r = ap.evaluate([entry(map_='/etc/a', type_='multi')])
    assert codes(r) == ['multi_map_not_modelled']
    r = ap.evaluate([entry(map_='auto.x', type_='yp')])
    assert codes(r) == ['remote_source_unobserved']
    r = ap.evaluate([{'mount_point': 'rel', 'map': '/x'}, entry(map_=None)])
    assert codes(r) == ['invalid_entry', 'invalid_entry'] and not r['complete']


def test_text_maps_need_captured_contents_without_nested_maps():
    stats = {'/etc/auto.misc': REG}
    r = ap.evaluate([entry()], stats=stats)
    assert codes(r) == ['map_text_not_observed'] and not r['complete']
    r = ap.evaluate([entry()], stats=stats, map_texts={'/etc/auto.misc': '# c\ncd -fstype=iso9660 :/dev/cdrom\n'})
    assert r['complete']
    for text in ('+auto.other\n', 'sub -fstype=autofs program:/opt/evil\n', 'x -fstype = autofs /etc/m\n'):
        r = ap.evaluate([entry()], stats=stats, map_texts={'/etc/auto.misc': text})
        assert codes(r) == ['nested_map_unresolved'] and not r['complete'], text
    r = ap.evaluate([entry()], stats=stats, map_texts={'/etc/auto.misc': 'a\x00b'})
    assert codes(r) == ['over_limit']


def test_unobserved_or_malformed_stat_is_a_gap():
    for seen in ({'kind': 'regular'}, {'kind': 'regular', 'mode': True}, {'kind': 'weird', 'mode': 0}, 'x'):
        r = ap.evaluate([entry()], stats={'/etc/auto.misc': seen})
        assert codes(r) == ['stat_not_observed'] and r['programs'] == [], seen


def test_entry_and_gap_limits():
    r = ap.evaluate([entry(f'/m{i}', f'/u{i}') for i in range(ap.MAX_ENTRIES + 1)])
    assert len(r['entries']) == ap.MAX_ENTRIES and len(r['gaps']) == ap.MAX_GAPS
    assert 'over_limit' in codes(r) and codes(r)[-1] == 'gaps_truncated' and not r['complete']


# --- increment 2: reading the master map -----------------------------------

DIR = {'kind': 'directory', 'mode': 0o40755}


def bufs(r):
    return [rec['buffer'] for rec in r['records']]


def test_master_records_follow_read_one_comments_continuations_and_indented_lines():
    text = ('# comment\n'
            '/misc /etc/auto.misc --timeout=60\n'
            '/net \\\n  -hosts\n'
            '   \n'
            '/home auto.home\n'
            '  indented continuation is swallowed\n'
            '/smb /etc/auto.smb')
    r = ap.read_master(files={'/etc/auto.master': text}, stats={'/etc/auto.master': REG})
    assert bufs(r) == ['/misc /etc/auto.misc --timeout=60', '/net -hosts', '/smb /etc/auto.smb']
    assert r['complete'] and r['master_map_name'] == 'auto.master' and r['authorizes_response'] is False


def test_unset_master_map_name_falls_back_to_auto_underscore_master():
    stats = {'/etc/auto.master': MISSING, '/etc/auto_master': REG}
    r = ap.read_master(files={'/etc/auto_master': '/x /etc/auto.x\n'}, stats=stats)
    assert bufs(r) == ['/x /etc/auto.x'] and r['complete']
    r = ap.read_master('auto.master', files={'/etc/auto_master': '/x /etc/auto.x\n'}, stats=stats)
    assert bufs(r) == [] and r['complete']


def test_plus_includes_recurse_in_order_and_self_include_is_skipped():
    files = {'/etc/auto.master': '/a /etc/auto.a\n+auto.extra\n+auto.master\n/z /etc/auto.z\n',
             '/etc/auto.extra': '/b /etc/auto.b\n'}
    stats = {'/etc/auto.master': REG, '/etc/auto.extra': REG}
    r = ap.read_master(files=files, stats=stats)
    assert bufs(r) == ['/a /etc/auto.a', '/b /etc/auto.b', '/z /etc/auto.z'] and r['complete']
    assert [rec['depth'] for rec in r['records']] == [0, 1, 0]


def test_plus_include_options_on_the_same_line_become_their_own_record():
    # read_one returns "+name" at the first blank; the rest of the line is read as a new record.
    files = {'/etc/auto.master': '+/etc/inc /extra /etc/auto.e\n', '/etc/inc': ''}
    r = ap.read_master(files=files, stats={'/etc/auto.master': REG, '/etc/inc': REG})
    assert bufs(r) == ['/extra /etc/auto.e']


def test_dir_include_reads_dot_autofs_files_in_version_order():
    files = {'/etc/auto.master': '+dir:/etc/auto.master.d\n',
             '/etc/auto.master.d/a10.autofs': '/ten /etc/t\n', '/etc/auto.master.d/a9.autofs': '/nine /etc/n\n'}
    stats = {'/etc/auto.master': REG, '/etc/auto.master.d': DIR,
             '/etc/auto.master.d/a10.autofs': REG, '/etc/auto.master.d/a9.autofs': REG}
    dirs = {'/etc/auto.master.d': ['a10.autofs', 'a9.autofs', '.hidden.autofs', 'x.conf', '.autofs']}
    r = ap.read_master(files=files, stats=stats, dirs=dirs)
    assert bufs(r) == ['/nine /etc/n', '/ten /etc/t'] and r['complete']


def test_include_depth_limit_stops_reading_like_automount():
    files = {f'/etc/m{i}': f'/k{i} /etc/x\n+/etc/m{i + 1}\n' for i in range(20)}
    stats = {f'/etc/m{i}': REG for i in range(21)}
    r = ap.read_master('/etc/m0', files=files, stats=stats)
    assert len(r['records']) == 17 and 'include_depth_exceeded' in codes(r)


def test_master_reading_fails_closed_on_unobserved_remote_and_overflowing_input():
    r = ap.read_master(stats={})
    assert not r['complete'] and codes(r) == ['master_file_not_observed'] * 2  # auto.master, then auto_master
    r = ap.read_master(stats={'/etc/auto.master': REG})
    assert not r['complete']
    r = ap.read_master(nss_sources=['ldap', 'files'], files={'/etc/auto.master': '/a b\n'},
                       stats={'/etc/auto.master': REG})
    assert not r['complete'] and 'remote_source_unobserved' in codes(r)
    files = {'/etc/auto.master': '+dir:/etc/d\n+ldap:ou=auto.master,dc=x\n+file,sun:/etc/y\n'}
    r = ap.read_master(files=files, stats={'/etc/auto.master': REG, '/etc/d': DIR})
    assert codes(r) == ['master_dir_not_observed', 'remote_source_unobserved', 'master_source_not_modelled']
    overflow = '/' + 'k' * 253 + '\\v rest\n'
    r = ap.read_master('/etc/auto.master', files={'/etc/auto.master': overflow}, stats={'/etc/auto.master': REG})
    assert not r['complete'] and codes(r) == ['over_limit']


def test_strverscmp_matches_glibc_examples():
    assert ap._versionsort(['a10', 'a9', 'a09', 'a1', 'a']) == ['a', 'a09', 'a1', 'a9', 'a10']


# --- increment 3: entry grammar -------------------------------------------------

def test_parse_entry_common_forms():
    assert ap.parse_entry('/misc /etc/auto.misc --timeout=60') == {
        'status': 'entry', 'mount_point': '/misc', 'type': None, 'format': None, 'map': '/etc/auto.misc',
        'options': []}
    p = ap.parse_entry('/net -hosts -nobind,-rw')
    assert (p['type'], p['map'], p['options']) == ('hosts', None, ['-rw'])
    p = ap.parse_entry('/x/ exec:/usr/local/bin/m -rw,soft -t5')
    assert (p['mount_point'], p['type'], p['map'], p['options']) == ('/x', 'program', '/usr/local/bin/m',
                                                                     ['-rw', 'soft'])
    p = ap.parse_entry('/y nis,sun:auto.y')
    assert (p['type'], p['format'], p['map']) == ('nis', 'sun', 'auto.y')
    # OPTIONSTR is longer than OPTTOUT+NUMBER here, so this is a mount option.
    assert ap.parse_entry('/x foo -t=5x')['options'] == ['-t=5x']


def test_parse_entry_fails_closed_on_scanner_quirks_and_syntax_errors():
    for buf in ['/x file -rw',          # keyword then blank lexes as MAPTYPE
                '/x file:nis -rw',      # second MAPTYPE: syntax error
                '/x a-hosts',           # "-hosts" starts MAPHOSTS mid-name
                '/x a--',               # MULTISEP / not modelled
                '/x /etc//auto.x',      # "//" switches to DNSTR
                '/x a:b', '/x foo,rw',  # COLON / name punctuation
                '/x foo ,rw', '/x foo rw,', '/x foo rw,,ro',  # options syntax errors
                '/x foo # c',           # '#' is skipped by the default rule
                '/x foo -D X=1',        # MACROSTR with a blank
                '/x multi /a -- /b',    # multi maps
                '/x "q"', '/x a\\b', 'x /etc/auto.x', '/ foo', '/x', '/x ldap:ou=a,dc=b']:
        assert ap.parse_entry(buf)['status'] == 'unmodelled', buf


def test_entries_apply_null_duplicate_and_poison_rules():
    recs = [{'buffer': b} for b in ['/a -null', '/a /etc/auto.a', '/b /etc/auto.b', '/b /etc/auto.b2',
                                    '/- /etc/auto.d1', '/- /etc/auto.d2', '/c foo:bar', '/d /etc/auto.d']]
    out = ap.entries_from_records(recs, amd_mount_paths=())
    assert [e['map'] for e in out['entries']] == ['/etc/auto.b', '/etc/auto.d1', '/etc/auto.d2']
    assert [r['status'] for r in out['parsed']] == ['null', 'nulled', 'entry', 'duplicate', 'entry', 'entry',
                                                     'unmodelled', 'unmodelled']
    assert [g['code'] for g in out['gaps']] == ['entry_grammar_not_modelled']


def test_amd_mount_sections_set_format_and_unobserved_config_blocks_relative_names():
    recs = [{'buffer': '/amd auto.amd'}, {'buffer': '/abs /etc/auto.abs'}]
    out = ap.entries_from_records(recs, amd_mount_paths=['/amd/'])
    assert [e['format'] for e in out['entries']] == ['amd', None] and out['gaps'] == []
    out = ap.entries_from_records(recs, amd_mount_paths=None)
    assert [(g['code'], g['mount_point']) for g in out['gaps']] == [('amd_sections_not_observed', '/amd')]


def test_evaluate_master_end_to_end_finds_root_program_maps():
    files = {'/etc/auto.master': '/misc /etc/auto.misc --timeout=60\n/net -hosts\n/smb auto.smb\n'
                                 '/p program:/opt/m -rw\n+dir:/etc/auto.master.d\n',
             '/etc/auto.master.d/x.autofs': '/x /etc/auto.x\n',
             '/etc/auto.misc': 'cd -fstype=iso9660,ro :/dev/cdrom\n'}
    stats = {'/etc/auto.master': REG, '/etc/auto.master.d': {'kind': 'directory', 'mode': 0o40755},
             '/etc/auto.master.d/x.autofs': REG, '/etc/auto.misc': REG, '/etc/auto.smb': REG_X,
             '/opt/m': REG_X, '/etc/auto.x': REG_X}
    dirs = {'/etc/auto.master.d': ['x.autofs', '.y.autofs', 'z.conf']}
    r = ap.evaluate_master(None, files, stats, dirs, amd_mount_paths=())
    assert r['complete']
    # Without autofs.conf, the relative auto.smb could be amd format.
    r2 = ap.evaluate_master(None, files, stats, dirs)
    assert not r2['complete'] and [g['code'] for g in r2['gaps']] == ['amd_sections_not_observed']
    assert [(p['path'], p['cwd']) for p in r['programs']] == [('/etc/auto.smb', '/smb'), ('/opt/m', '/p'),
                                                               ('/etc/auto.x', '/x')]
    assert r['entries'][3]['options'] == ['-rw']
    assert r['complete'] and r['authorizes_response'] is False and r['origin'] == 'not_assessed'


def test_evaluate_master_unmodelled_entry_poisons_later_entries_and_blocks():
    files = {'/etc/auto.master': '/a weird:map\n/b /etc/auto.b\n'}
    stats = {'/etc/auto.master': REG, '/etc/auto.b': REG_X}
    r = ap.evaluate_master(None, files, stats, amd_mount_paths=())
    assert r['programs'] == [] and not r['complete']
    assert [g['code'] for g in r['gaps']] == ['entry_grammar_not_modelled']
