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
