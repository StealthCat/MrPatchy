"""Tests for the pure acpid event-rule contract (#1079).

Expected outcomes follow event.c and acpid.c in acpid 2.0.28-2.0.34.
"""
from app import acpid_events as ae

LISTED = {'path': ae.DEFAULT_CONFDIR, 'state': 'listed'}
# Debian's shipped example, /usr/share/doc/acpid/examples/powerbtn.
POWERBTN = """# /etc/acpi/events/powerbtn
# This is called when the user presses the power button and calls
# /etc/acpi/powerbtn.sh for further processing.

# Optionally you can specify the placeholder %e. It will pass
# through the whole kernel event message to the program you've
# specified.

# We need to react on "button power.*" and "button/power.*" because
# of kernel changes.

event=button[ /]power
action=/etc/acpi/powerbtn.sh
"""


def f(name, kind='file', target=None):
    entry = {'name': name, 'type': kind}
    if kind == 'symlink':
        entry['target_type'] = target
    return entry


def run(entries, texts, options='', directory=LISTED):
    return ae.evaluate(entries, directory=directory, options=options, texts=texts)


def status(result):
    return {r['name']: (r['status'], r['reason']) for r in result['files']}


def codes(result):
    return [g['code'] for g in result['gaps']]


def one(text, **kw):
    return ae.parse_rule('r', text, **kw)


def test_debian_powerbtn_example_loads_and_runs_as_root_through_sh():
    result = run([f('powerbtn')], {'powerbtn': POWERBTN})
    assert result['complete'] and result['acpid_starts'] and not result['gaps']
    assert result['rules'] == [{
        'name': 'powerbtn', 'path': '/etc/acpi/events/powerbtn', 'event': 'button[ /]power',
        'event_flags': ['REG_EXTENDED', 'REG_ICASE', 'REG_NOSUB', 'REG_NEWLINE'],
        'action': '/etc/acpi/powerbtn.sh', 'action_sha256': result['rules'][0]['action_sha256'],
        'action_truncated': False, 'event_truncated': False, 'event_substitution': False,
        'first_word': '/etc/acpi/powerbtn.sh', 'origin': 'not_assessed'}]
    assert result['execution']['argv'] == ['/bin/sh', '-c', '<action>']
    assert result['execution']['user'] == 'root' and result['execution']['umask'] == '0077'
    assert result['origin'] == 'not_assessed' and result['not_observed']


def test_name_filter_matches_run_parts_convention():
    names = ['ok_name-1', 'UPPER', 'power.conf', 'backup~', '.hidden', 'a b', 'naïve', 'x.dpkg-old']
    result = run([f(n) for n in names], {n: POWERBTN for n in names})
    got = status(result)
    assert got['ok_name-1'][0] == 'loads' and got['UPPER'][0] == 'loads'
    for name in names[2:]:
        assert got[name] == ('ignored', 'name_filter'), name
    assert [r['name'] for r in result['rules']] == ['UPPER', 'ok_name-1']


def test_only_regular_files_and_links_to_them_load():
    entries = [f('plain'), f('link', 'symlink', 'file'), f('dangling', 'symlink', 'missing'),
               f('dirlink', 'symlink', 'directory'), f('sub', 'directory'), f('fifo', 'other')]
    result = run(entries, {e['name']: POWERBTN for e in entries})
    assert status(result) == {
        'plain': ('loads', None), 'link': ('loads', None), 'dangling': ('skipped_non_file', 'dangling_symlink'),
        'dirlink': ('skipped_non_file', 'symlink_to_directory'), 'sub': ('skipped_non_file', 'directory'),
        'fifo': ('skipped_non_file', 'other')}
    assert result['complete']


def test_unobserved_link_target_type_or_text_is_unresolved_and_blocking():
    result = run([f('link', 'symlink', None), f('notext'), f('odd', 'unknown')], {})
    assert status(result) == {'link': ('unresolved', 'target_not_observed'),
                              'notext': ('unresolved', 'text_not_observed'),
                              'odd': ('unresolved', 'type_not_observed')}
    assert not result['complete']
    assert set(codes(result)) == {'target_not_observed', 'text_not_observed', 'type_not_observed'}


def test_key_is_case_insensitive_but_whitespace_significant():
    assert one('EVENT=ac_adapter\nAction=/bin/true\n')['status'] == 'loads'
    spaced = one('event = ac_adapter\naction=/bin/true\n')
    assert spaced['status'] == 'skipped_incomplete' and spaced['reason'] == 'missing_event'
    assert spaced['lines'][0]['outcome'] == 'unknown_key' and spaced['lines'][0]['key'] == 'event '


def test_leading_whitespace_comments_and_value_whitespace():
    rule = one('   \t# comment\n\n  event= button/lid \naction=/sbin/x %e\r\n')
    assert rule['status'] == 'loads'
    # The value keeps its leading space, trailing space and a CR from CRLF files.
    assert rule['event']['value'] == ' button/lid '
    assert rule['action']['value'] == '/sbin/x %e\r'
    assert rule['action']['event_substitution'] is True


def test_unparsable_lines_are_skipped_not_fatal():
    rule = one('=nokey\nevent=\njunk line\nevent=x\naction=y\n')
    assert rule['status'] == 'loads'
    assert [n['outcome'] for n in rule['lines']] == ['unparsed', 'unparsed', 'unparsed', 'event', 'action']


def test_last_event_and_action_win():
    rule = one('event=first\naction=/bin/first\nevent=second\naction=/bin/second\n')
    assert rule['event']['value'] == 'second' and rule['action']['value'] == '/bin/second'
    assert rule['event']['line'] == 3 and rule['action']['line'] == 4


def test_incomplete_files_are_skipped():
    assert one('event=x\n')['reason'] == 'missing_action'
    assert one('action=/bin/x\n')['reason'] == 'missing_event'
    assert one('')['status'] == 'skipped_incomplete'


def test_invalid_escape_rejects_file_even_if_later_action_replaces_it():
    rule = one('event=x\naction=/bin/echo %d\naction=/bin/ok\n')
    assert rule['status'] == 'rejected' and rule['reason'] == 'invalid_escape' and rule['action'] is None
    assert one('event=x\naction=/bin/echo 50%\n')['status'] == 'rejected'
    ok = one('event=x\naction=/bin/echo 100%% "%e" %%e\n')
    assert ok['status'] == 'loads' and ok['action']['event_substitution'] is True
    assert one('event=x\naction=/bin/echo %%e\n')['action']['event_substitution'] is False


def test_key_longer_than_63_bytes_does_not_parse():
    assert one('k' * 63 + '=v\nevent=x\naction=y\n')['lines'][0] == {
        'line': 1, 'continues_long_line': False, 'outcome': 'unknown_key', 'key': 'k' * 63}
    assert one('k' * 64 + '=v\nevent=x\naction=y\n')['lines'][0]['outcome'] == 'unparsed'


def test_value_is_truncated_at_255_bytes():
    command = '/bin/true ' + 'a' * 300
    rule = one(f'event=x\naction={command}\n')
    assert rule['action']['value'] == command[:255] and rule['action']['truncated'] is True
    result = run([f('long')], {'long': f'event=x\naction={command}\n'})
    assert result['rules'][0]['action_truncated'] is True


def test_line_over_510_bytes_is_parsed_in_fgets_pieces():
    # The piece after byte 510 is parsed as its own line, so it can set the action.
    first = 'action=/bin/benign ' + '#' * (510 - len('action=/bin/benign '))
    rule = one(f'event=x\n{first}action=/tmp/evil\n')
    assert rule['status'] == 'loads'
    assert rule['action']['value'] == '/tmp/evil'
    assert rule['action']['line'] == 3 and rule['action']['continues_long_line'] is True
    exact = 'action=' + 'b' * (509 - len('action='))
    assert one(f'event=x\n{exact}\n')['action']['value'] == 'b' * 255


def test_drop_rules_use_the_drop_action_exactly():
    result = run([f('mute'), f('crlf')], {'mute': 'event=button/mute\naction=<drop>\n',
                                          'crlf': 'event=button/mute\r\naction=<drop>\r\n'})
    assert [r['name'] for r in result['drop_rules']] == ['mute']
    # A CRLF file's action is "<drop>\r", which is not the drop action, so it runs through the shell.
    assert [r['name'] for r in result['rules']] == ['crlf']
    custom = run([f('mute')], {'mute': 'event=x\naction=IGNORE\n'}, options='-r IGNORE')
    assert custom['dropaction'] == 'IGNORE' and custom['drop_rules'][0]['name'] == 'mute'


def test_confdir_and_dropaction_options():
    for options in ('-c /srv/acpi', '-c/srv/acpi', '--confdir=/srv/acpi', '--confdir /srv/acpi', '--conf=/srv/acpi',
                    '-fdc /srv/acpi', 'stray -c /srv/acpi'):
        assert ae.parse_options(options)['confdir'] == '/srv/acpi', options
    assert ae.parse_options('-e /proc/acpi/event -c /x -r -c')['confdir'] == '/x'
    assert ae.parse_options('-r -c')['dropaction'] == '-c'
    assert ae.parse_options('-- -c /x')['confdir'] == ae.DEFAULT_CONFDIR
    assert ae.parse_options('-L /run/lock')['lockfile'] == '/run/lock'
    result = run([f('powerbtn')], {'powerbtn': POWERBTN}, options='-c /srv/acpi',
                 directory={'path': '/srv/acpi', 'state': 'listed'})
    assert result['complete'] and result['rules'][0]['path'] == '/srv/acpi/powerbtn'


def test_invalid_options_make_acpid_exit():
    for options in ('--c=/x', '--bogus', '-x', '-c', '--confdir', '--debug=1', '-v', '--help'):
        parsed = ae.parse_options(options)
        assert parsed['starts'] is False and parsed['error'], options
    result = run([f('powerbtn')], {'powerbtn': POWERBTN}, options='-z')
    assert result['acpid_starts'] is False and result['rules'] == [] and 'option_exits' in codes(result)
    assert result['complete']


def test_listing_must_match_the_effective_confdir():
    result = run([f('powerbtn')], {'powerbtn': POWERBTN}, options='-c /srv/acpi')
    assert not result['complete'] and codes(result) == ['directory_mismatch'] and result['rules'] == []
    relative = run([f('powerbtn')], {'powerbtn': POWERBTN}, options='-c events')
    assert not relative['complete'] and codes(relative) == ['confdir_relative']


def test_directory_states():
    absent = run([], {}, directory={'path': ae.DEFAULT_CONFDIR, 'state': 'absent'})
    assert absent['complete'] and absent['acpid_starts'] is False and codes(absent) == ['directory_absent']
    for directory in (None, {'path': ae.DEFAULT_CONFDIR, 'state': 'unreadable'}, {'path': ae.DEFAULT_CONFDIR}):
        result = run([f('powerbtn')], {'powerbtn': POWERBTN}, directory=directory)
        assert not result['complete'] and result['rules'] == []


def test_options_not_observed_is_blocking_but_still_reports_default_directory():
    result = ae.evaluate([f('powerbtn')], directory=LISTED, options=None, texts={'powerbtn': POWERBTN})
    assert not result['complete'] and codes(result) == ['options_not_observed']
    assert result['rules'][0]['name'] == 'powerbtn'


def test_fail_closed_text():
    entries = [f('nul'), f('latin'), f('big')]
    result = run(entries, {'nul': b'event=x\x00\naction=y\n', 'latin': b'event=x\naction=\xe9\n',
                           'big': 'event=x\naction=y\n' + '#' * ae.MAX_TEXT})
    assert status(result) == {'nul': ('unresolved', 'binary'), 'latin': ('unresolved', 'invalid_utf8'),
                              'big': ('unresolved', 'over_limit')}
    assert not result['complete']


def test_malformed_and_duplicate_entries():
    result = run([f('a'), f('a'), {'name': 'x/y', 'type': 'file'}, 'junk', f('.'), f('..')], {'a': POWERBTN})
    assert [r['name'] for r in result['files']] == ['a']
    assert codes(result) == ['duplicate_entry', 'malformed_entry', 'malformed_entry']
    assert not result['complete']
    over = run([f(f'n{i}') for i in range(ae.MAX_ENTRIES + 1)], {})
    assert codes(over) == ['entries_over_limit'] and over['files'] == []


def test_files_are_reported_in_byte_order_with_no_safety_verdict():
    result = run([f('b'), f('B'), f('a')], {'a': POWERBTN, 'b': POWERBTN, 'B': POWERBTN})
    assert [r['name'] for r in result['files']] == ['B', 'a', 'b']
    assert all(r['origin'] == 'not_assessed' for r in result['files'] + result['rules'])
    assert not any(key in result for key in ('safe', 'verdict', 'approved'))
