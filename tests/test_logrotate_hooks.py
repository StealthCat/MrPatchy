"""Pure logrotate contract (#980). Expected values were compared with logrotate 3.21.0."""
from app import logrotate_hooks as lh

D = '/etc/logrotate.d'


def main(text):
    return {'present': True, 'content': text}


def directory(*entries):
    return {D: {'type': 'dir', 'entries': [
        {'name': name, 'type': kind, 'content': content} for name, kind, content in entries]}}


def codes(result):
    return [gap['code'] for gap in result['gaps']]


BASE_GAPS = ['invocation_unobserved', 'rotation_not_evaluated']


def test_section_scripts_with_patterns_lines_and_sharedscripts():
    text = ('weekly\n'
            '/var/log/a.log "/var/log/b c.log"\n'
            '{\n'
            '  sharedscripts\n'
            '  postrotate\n'
            '    systemctl reload a\n'
            '  endscript\n'
            '  firstaction echo one\n'
            '\tendscript missingok\n'
            '}\n')
    result = lh.resolve(main(text))
    assert result['logrotate_reading'] == 'determined'
    assert codes(result) == BASE_GAPS
    post, first = result['scripts']
    assert post == {'kind': 'postrotate', 'script': '\n    systemctl reload a\n', 'truncated': False,
                    'empty': False, 'scope': 'section', 'patterns': ['/var/log/a.log', '/var/log/b c.log'],
                    'sharedscripts': True,
                    'path': lh.MAIN_FILE, 'line': 5}
    # Text on the keyword line belongs to the script; parsing continues after endscript.
    assert (first['kind'], first['script'], first['line']) == ('firstaction', ' echo one\n', 8)
    assert result['files'] == [{'path': lh.MAIN_FILE, 'state': 'parsed'}]
    assert 'not a safety verdict' in result['not_a_verdict']


def test_endscript_must_be_the_first_word_of_a_later_line():
    text = ('/l {\n prerotate\n echo a; endscript\n # c\n endscriptx\n }\n   endscript   \n}\n'
            '/m { postrotate\n endscript }\n')
    result = lh.resolve(main(text))
    assert result['logrotate_reading'] == 'determined'
    assert result['scripts'][0]['script'] == '\n echo a; endscript\n # c\n endscriptx\n }\n'
    assert (result['scripts'][1]['patterns'], result['scripts'][1]['empty']) == (['/m'], True)


def test_sharedscripts_is_inherited_and_overridden_per_section():
    text = ('sharedscripts\n/a { postrotate\n x\n endscript\n}\n'
            '/b { postrotate\n x\n endscript\n nosharedscripts }\n'
            'nosharedscripts\n/c { postrotate\n x\n endscript\n}\n')
    assert [s['sharedscripts'] for s in lh.resolve(main(text))['scripts']] == [True, False, False]


def test_command_identity_and_shred_directives_in_both_scopes():
    text = ('compresscmd /usr/local/bin/pack\nsu root adm\n'
            '/a { uncompresscmd /opt/un\n shred\n noshred\n su bob staff\n rotate 3\n}\n')
    result = lh.resolve(main(text))
    assert result['logrotate_reading'] == 'determined'
    assert [(d['directive'], d['value'], d['scope'], d['patterns'], d['line']) for d in result['directives']] == [
        ('compresscmd', '/usr/local/bin/pack', 'global', None, 1),
        ('su', 'root adm', 'global', None, 2),
        ('uncompresscmd', '/opt/un', 'section', ['/a'], 3),
        ('shred', None, 'section', ['/a'], 4),
        ('su', 'bob staff', 'section', ['/a'], 6)]


def test_include_directory_order_and_ignored_entries():
    section = '/{0} {{ postrotate\n echo {0}\n endscript\n}}\n'
    includes = directory(
        ('b.conf', 'file', section.format('b')), ('a', 'file', section.format('a')),
        ('.hid', 'file', section.format('hid')), ('Z', 'file', section.format('Z')),
        ('c.bak', 'file', section.format('bak')), ('d.dpkg-old', 'file', section.format('old')),
        ('e~', 'file', section.format('tilde')), ('f,v', 'file', section.format('rcs')),
        ('j.rhn-cfg-tmp-1', 'file', section.format('rhn')), ('k.orig', 'file', section.format('orig')),
        ('empty', 'file', ''), ('sub', 'dir', None), ('gone', 'missing', None))
    result = lh.resolve(main(f'include {D}/\n/last {{ }}\n'), includes)
    assert result['logrotate_reading'] == 'determined'
    # Byte order, hidden names included; .orig is not taboo.
    assert [s['patterns'] for s in result['scripts']] == [['/hid'], ['/Z'], ['/a'], ['/b'], ['/orig']]
    ignored = {f['path'].rsplit('/', 1)[1]: f['reason'] for f in result['files'] if f['state'] == 'ignored'}
    assert ignored == {'c.bak': 'taboo', 'd.dpkg-old': 'taboo', 'e~': 'taboo', 'f,v': 'taboo',
                       'j.rhn-cfg-tmp-1': 'taboo', 'empty': 'empty', 'sub': 'not_regular_file',
                       'gone': 'dangling_link'}
    assert result['files'][0] == {'path': lh.MAIN_FILE, 'state': 'parsed'}


def test_include_file_missing_and_uncollected_targets():
    includes = {'/etc/extra.conf': {'type': 'file', 'content': '/x { lastaction\n echo x\n endscript\n}\n'},
                '/etc/absent': {'type': 'missing'}}
    result = lh.resolve(main('include /etc/extra.conf\ninclude /etc/absent\n'), includes)
    assert result['logrotate_reading'] == 'determined'
    assert [(s['kind'], s['path'], s['line']) for s in result['scripts']] == [('lastaction', '/etc/extra.conf', 1)]
    result = lh.resolve(main('include /etc/unknown\ninclude relative.d\ninclude ~/x\n/a { preremove\n y\n endscript\n}\n'),
                        includes)
    assert result['logrotate_reading'] == 'undetermined'
    assert codes(result)[2:] == ['include_not_collected', 'include_not_resolved', 'include_not_resolved']
    assert [s['kind'] for s in result['scripts']] == ['preremove']  # later content stays visible


def test_include_loop_and_depth_are_gaps():
    includes = {'/etc/loop': {'type': 'file', 'content': f'include {lh.MAIN_FILE}\ninclude /etc/loop\n'},
                lh.MAIN_FILE: {'type': 'file', 'content': 'include /etc/loop\n'}}
    result = lh.resolve(main('include /etc/loop\n'), includes)
    assert result['logrotate_reading'] == 'undetermined'
    assert codes(result)[2:] == ['include_loop', 'include_loop']
    chain = {f'/etc/c{i}': {'type': 'file', 'content': f'include /etc/c{i + 1}\n'} for i in range(12)}
    assert 'include_too_deep' in codes(lh.resolve(main('include /etc/c0\n'), chain))


def test_taboo_change_stops_ignoring_names():
    includes = directory(('x.bak', 'file', '/x { postrotate\n echo x\n endscript\n}\n'))
    result = lh.resolve(main(f'tabooext + .foo\ninclude {D}\n'), includes)
    assert result['logrotate_reading'] == 'undetermined'
    assert 'taboo_changed' in codes(result)
    assert [s['path'] for s in result['scripts']] == [f'{D}/x.bak']


def test_include_inside_a_section_is_still_parsed():
    # logrotate 3.21.0 reads the target; hiding it would hide scripts that run.
    includes = directory(('a', 'file', '/a { postrotate\n echo a\n endscript\n}\n'))
    result = lh.resolve(main(f'/m {{\n include {D}\n}}\n'), includes)
    assert result['logrotate_reading'] == 'undetermined'
    assert 'include_in_section' in codes(result)
    assert [s['patterns'] for s in result['scripts']] == [['/a']]


def test_malformed_input_is_reported_and_later_content_kept():
    text = ('prerotate\n echo global\nendscript\n'
            '/a {\n bogus 1\n endscript\n {\n postrotate\n one\n endscript\n postrotate\n two\n endscript\n}\n'
            '}\n'
            '/b "unclosed {\n lastaction\n z\n endscript\n}\n'
            '/c { firstaction\n never closed\n')
    result = lh.resolve(main(text))
    assert result['logrotate_reading'] == 'undetermined'
    assert codes(result)[2:] == ['script_outside_section', 'unknown_directive', 'unexpected_endscript',
                                 'unexpected_brace', 'duplicate_script', 'unexpected_brace', 'unbalanced_quote',
                                 'script_without_endscript', 'unknown_directive', 'unterminated_section']
    assert [gap.get('line') for gap in result['gaps'][2:]] == [1, 5, 6, 7, 11, 15, 16, 21, 22, 22]
    # logrotate keeps a script outside a section as the default of later sections, so it is listed.
    assert [(s['kind'], s['scope'], s['patterns']) for s in result['scripts']] == [
        ('prerotate', 'global', None), ('postrotate', 'section', ['/a']), ('postrotate', 'section', ['/a']),
        ('lastaction', 'section', [])]
    assert result['scripts'][0]['script'] == '\n echo global\n'
    assert result['files'] == [{'path': lh.MAIN_FILE, 'state': 'gaps'}]
    for text in ('/a {\n postrotate\n x\n endscript\n', '/var/log/a.log\n', 'a\x00b\n'):
        assert lh.resolve(main(text))['logrotate_reading'] == 'undetermined'


def test_script_swallowing_a_later_script_is_a_gap():
    # The first script has no endscript, so it runs to the next one. logrotate 3.21.0 runs neither script.
    text = '/a {\n prerotate\n echo lost\n}\n/b {\n lastaction\n echo b\n endscript\n}\n'
    result = lh.resolve(main(text))
    assert result['logrotate_reading'] == 'undetermined'
    assert codes(result)[2:] == ['script_contains_script_keyword']
    assert 'echo b' in result['scripts'][0]['script']  # still visible


def test_content_after_a_script_without_endscript_stays_visible():
    # logrotate 3.21.0 skips the broken section and still reads the include that follows.
    includes = directory(('a', 'file', '/a { postrotate\n echo a\n endscript\n}\n'))
    result = lh.resolve(main(f'/m {{\n prerotate\n echo lost\n}}\ninclude {D}\n'), includes)
    assert result['logrotate_reading'] == 'undetermined'
    assert codes(result)[2:4] == ['script_without_endscript', 'unknown_directive']
    assert [s['patterns'] for s in result['scripts']] == [['/a']]


def test_comments_only_where_a_directive_can_start():
    result = lh.resolve(main('# postrotate\n/a { # prerotate\n postrotate\n # kept\n endscript\n}\n'))
    assert result['logrotate_reading'] == 'determined'
    assert [(s['kind'], s['script']) for s in result['scripts']] == [('postrotate', '\n # kept\n')]


def test_observation_problems_fail_closed():
    assert codes(lh.resolve(None))[2:] == ['main_not_collected']
    assert codes(lh.resolve({'present': 'yes'}))[2:] == ['invalid_observation']
    absent = lh.resolve({'present': False})
    assert (absent['logrotate_reading'], absent['scripts'], absent['files']) == ('determined', [], [])
    assert codes(lh.resolve(main(None)))[2:] == ['file_unreadable']
    assert codes(lh.resolve(main('#' * (lh.MAX_FILE_BYTES + 1))))[2:] == ['file_too_large']
    bad = {D: {'type': 'dir', 'entries': [{'name': '../x', 'type': 'file', 'content': 'weekly\n'}, 'junk',
                                           {'name': 'ok', 'type': 'file', 'content': None}]}}
    result = lh.resolve(main(f'include {D}\n'), bad)
    assert codes(result)[2:] == ['invalid_entry', 'invalid_entry', 'file_unreadable']
    assert codes(lh.resolve(main(f'include {D}\n'), {D: {'type': 'dir', 'entries': None}}))[2:] == [
        'include_not_collected']
    assert codes(lh.resolve(main(f'include {D}\n'), 'junk'))[2:] == ['include_not_collected']


def test_caps_are_gaps():
    script = ' postrotate\n' + 'x' * (lh.MAX_SCRIPT_CHARS + 5) + '\n endscript\n'
    result = lh.resolve(main('/a {' + script + '}\n'))
    assert (result['scripts'][0]['truncated'], len(result['scripts'][0]['script'])) == (True, lh.MAX_SCRIPT_CHARS)
    many = ''.join(f'/l{i} {{ shred }}\n' for i in range(lh.MAX_ENTRIES + 3))
    result = lh.resolve(main(many))
    assert len(result['directives']) == lh.MAX_ENTRIES and codes(result)[-1] == 'entry_limit'
    patterns = ' '.join(f'/p{i}' for i in range(lh.MAX_PATTERNS + 1))
    assert 'pattern_limit' in codes(lh.resolve(main(patterns + ' { }\n')))
    noisy = lh.resolve(main('bogus\n' * (lh.MAX_GAPS + 50)))
    assert len(noisy['gaps']) == lh.MAX_GAPS + 1 and codes(noisy)[-1] == 'gap_limit'


def test_helpers():
    assert lh.taboo('x.rpmsave') == '*.rpmsave' and lh.taboo('x.rpmsave.conf') is None
    assert lh.taboo('a.rhn-cfg-tmp-9') == '*.rhn-cfg-tmp-*' and lh.taboo('.hidden') is None
    assert lh.split_patterns(' /a\t"/b c" \'/d\'\n/e*') == ['/a', '/b c', '/d', '/e*']
    assert lh.split_patterns('/a "open') is None


def test_hidden_names_are_never_taboo():
    # logrotate matches taboo patterns with FNM_PERIOD, so "*" does not cover a leading period.
    # 3.21.0 reads every one of these names and runs their scripts.
    names = ('.bak', '.swp', '.x.bak', '.x~', '.~', '.,v', '.rpmsave', '.disabled', '.dpkg-old', '.rhn-cfg-tmp-1')
    assert [lh.taboo(name) for name in names] == [None] * len(names)
    includes = directory(*((name, 'file', f'/l{i} {{ postrotate\n echo {i}\n endscript\n}}\n')
                           for i, name in enumerate(names)),
                         ('x.bak', 'file', '/no { postrotate\n echo no\n endscript\n}\n'))
    result = lh.resolve(main(f'include {D}\n'), includes)
    assert result['logrotate_reading'] == 'determined'
    assert sorted(s['path'] for s in result['scripts']) == sorted(f'{D}/{name}' for name in names)
    assert [f['path'] for f in result['files'] if f['state'] == 'ignored'] == [f'{D}/x.bak']


def test_equals_separates_a_directive_from_its_value():
    includes = {'/etc/extra': {'type': 'file', 'content': '/x { postrotate\n echo x\n endscript\n}\n'}}
    text = ('include=/etc/extra\ncompresscmd=/bin/a\n'
            '/a {\n rotate=1\n compresscmd = /bin/b\n uncompresscmd\t=/bin/c\n su root adm\n}\n')
    result = lh.resolve(main(text), includes)
    assert result['logrotate_reading'] == 'determined'
    assert codes(result) == BASE_GAPS
    assert [(s['path'], s['patterns']) for s in result['scripts']] == [('/etc/extra', ['/x'])]
    assert [(d['directive'], d['value'], d['scope']) for d in result['directives']] == [
        ('compresscmd', '/bin/a', 'global'), ('compresscmd', '/bin/b', 'section'),
        ('uncompresscmd', '/bin/c', 'section'), ('su', 'root adm', 'section')]
    for form in ('include = /etc/extra\n', 'include\t=\t/etc/extra\n'):
        assert [s['path'] for s in lh.resolve(main(form), includes)['scripts']] == ['/etc/extra']


def test_input_logrotate_rejects_is_undetermined_and_later_content_kept():
    script = ' postrotate\n echo x\n endscript\n'
    cases = {
        '/a {\r\n' + script.replace('\n', '\r\n') + '}\r\n': 'control_whitespace',
        'var/log/x {\n' + script + '}\n': 'keyword_not_separated',
        '*.log {\n' + script + '}\n': 'unexpected_line_start',
        '/a {\n postrotate/x\n' + script + '}\n': 'keyword_not_separated',
        '/a {\n compresscmd:/bin/true\n' + script + '}\n': 'keyword_not_separated',
        '/a {\n \x0bmissingok\n' + script + '}\n': 'control_whitespace',
        '﻿/a {\n' + script + '}\n': 'unexpected_line_start',
        '/a { rotate 1 } /b {\n' + script + '}\n': 'brace_in_value',
    }
    for text, code in cases.items():
        result = lh.resolve(main(text))
        assert result['logrotate_reading'] == 'undetermined', text
        assert code in codes(result), text
        # Listed as an upper bound, so a rejected line cannot hide a script.
        assert [s['kind'] for s in result['scripts']] == ['postrotate'], text
    # A rejected top-level line does not swallow the include that follows it.
    includes = {'/etc/extra': {'type': 'file', 'content': '/x { lastaction\n echo x\n endscript\n}\n'}}
    result = lh.resolve(main('*junk\ninclude /etc/extra\n/a { }\n'), includes)
    assert codes(result)[2:] == ['unexpected_line_start']
    assert [s['path'] for s in result['scripts']] == ['/etc/extra']


def test_endscript_followed_by_a_non_letter_ends_the_script():
    # logrotate 3.21.0 takes the letters at the start of a line as its first word: "endscript;" ends the
    # script, the section closes and the include that follows is read.
    includes = {'/etc/extra': {'type': 'file', 'content': '/x { postrotate\n echo x\n endscript\n}\n'}}
    for tail in (';', '}', '#c', '=', '/', '.', '1'):
        text = ('/a {\n rotate 1\n postrotate\n  echo one\n endscript' + tail + '\n}\n'
                'include /etc/extra\n/b {\n su nobody nogroup\n compresscmd /bin/evil\n}\nendscript\n}\n')
        result = lh.resolve(main(text), includes)
        assert result['logrotate_reading'] == 'undetermined', tail
        assert 'endscript_not_separated' in codes(result), tail
        assert [(s['path'], s['script']) for s in result['scripts']] == [
            (lh.MAIN_FILE, '\n  echo one\n'), ('/etc/extra', '\n echo x\n')], tail
        assert [(d['directive'], d['value']) for d in result['directives']] == [
            ('su', 'nobody nogroup'), ('compresscmd', '/bin/evil')], tail
    # A following letter keeps the word going, so the line stays script text.
    result = lh.resolve(main('/a { postrotate\n endscriptX\n endscript\n}\n'))
    assert (result['logrotate_reading'], result['scripts'][0]['script']) == ('determined', '\n endscriptX\n')


def test_endscript_on_the_script_keyword_line_ends_the_script():
    # logrotate 3.21.0 skips the one character after the keyword and then finds endscript on the same
    # line: compresscmd is a directive and the stray endscript is only reported. It also keeps the whole
    # rest of the file as the script text.
    includes = {'/etc/extra': {'type': 'file', 'content': '/x { postrotate\n echo x\n endscript\n}\n'}}
    for head in ('postrotate endscript', 'postrotate\t \tendscript', 'postrotate=endscript',
                 'postrotate endscript;'):
        text = '/a {\n ' + head + '\n compresscmd /bin/evil\n endscript\n}\ninclude /etc/extra\n'
        result = lh.resolve(main(text), includes)
        assert result['logrotate_reading'] == 'undetermined', head
        assert 'endscript_on_keyword_line' in codes(result), head
        assert [(s['path'], s['script']) for s in result['scripts']] == [
            (lh.MAIN_FILE, text[len('/a {\n postrotate'):]), ('/etc/extra', '\n echo x\n')], head
        assert [(d['directive'], d['value']) for d in result['directives']] == [('compresscmd', '/bin/evil')], head
    # The rest of the keyword line is parsed after endscript.
    result = lh.resolve(main('/a {\n postrotate endscript compresscmd /bin/evil\n}\n'))
    assert [(d['directive'], d['value']) for d in result['directives']] == [('compresscmd', '/bin/evil')]
    # endscript later on the keyword line, or followed by a letter, is script text.
    for head in ('postrotate echo a endscript', 'postrotate endscriptX'):
        result = lh.resolve(main('/a {\n ' + head + '\n compresscmd /bin/x\n endscript\n}\n'))
        assert (result['logrotate_reading'], result['directives']) == ('determined', []), head
        assert result['scripts'][0]['script'] == head[len('postrotate'):] + '\n compresscmd /bin/x\n', head


def test_equals_after_a_flag_keeps_the_rest_of_the_line():
    # logrotate 3.21.0 reads "compress=include /path" as the flag followed by the include.
    includes = {'/etc/extra': {'type': 'file', 'content': '/x { postrotate\n echo x\n endscript\n}\n'}}
    result = lh.resolve(main('compress=include /etc/extra\n'), includes)
    assert (result['logrotate_reading'], codes(result)) == ('determined', BASE_GAPS)
    assert [s['path'] for s in result['scripts']] == ['/etc/extra']
    result = lh.resolve(main('/a {\n compress=compresscmd /bin/evil\n sharedscripts=postrotate\n echo a\n endscript\n}\n'))
    assert (result['logrotate_reading'], codes(result)) == ('determined', BASE_GAPS)
    assert [(d['directive'], d['value']) for d in result['directives']] == [('compresscmd', '/bin/evil')]
    assert [(s['script'], s['sharedscripts']) for s in result['scripts']] == [('\n echo a\n', True)]
    # Only one "=" directly after the flag is accepted; logrotate rejects the other forms.
    for text in ('compress==include /etc/extra\n', 'compress = include /etc/extra\n'):
        result = lh.resolve(main(text), includes)
        assert (result['logrotate_reading'], result['scripts']) == ('undetermined', []), text


def test_closing_brace_in_log_patterns_does_not_swallow_later_lines():
    # logrotate 3.21.0 reports "unexpected }" and stops reading the file. The include and the next
    # section are still listed as an upper bound instead of being taken as log patterns.
    includes = {'/etc/extra': {'type': 'file', 'content': '/x { postrotate\n echo x\n endscript\n}\n'}}
    for head in ('/a }', '"/a" "}"', '/a # }'):
        text = head + '\ninclude /etc/extra\n/b {\n postrotate\n  echo b\n endscript\n}\n'
        result = lh.resolve(main(text), includes)
        assert result['logrotate_reading'] == 'undetermined', head
        assert 'brace_in_patterns' in codes(result), head
        assert [(s['path'], s['patterns']) for s in result['scripts']] == [
            ('/etc/extra', ['/x']), (lh.MAIN_FILE, ['/b'])], head
    # The same holds when no opening brace follows at all.
    result = lh.resolve(main('/a {\n} /b }\ninclude /etc/extra\ncompresscmd /bin/evil\n'), includes)
    assert (result['logrotate_reading'], 'brace_in_patterns' in codes(result)) == ('undetermined', True)
    assert [s['path'] for s in result['scripts']] == ['/etc/extra']
    assert [(d['directive'], d['value']) for d in result['directives']] == [('compresscmd', '/bin/evil')]


def test_endscript_skips_the_next_character_whatever_it_is():
    # logrotate 3.21.0 skips the one character after endscript, so "endscript;postrotate" starts a new
    # script that it runs.
    text = '/a {\n postrotate\n  echo one\n endscript;postrotate\n  /usr/bin/hidden\n endscript\n}\n'
    result = lh.resolve(main(text))
    assert result['logrotate_reading'] == 'undetermined'
    assert 'endscript_not_separated' in codes(result)
    assert [(s['kind'], s['script'], s['patterns']) for s in result['scripts']] == [
        ('postrotate', '\n  echo one\n', ['/a']), ('postrotate', '\n  /usr/bin/hidden\n', ['/a'])]
    # "endscript}" does not close the section: the next directive stays in it.
    result = lh.resolve(main('/a {\n postrotate\n x\n endscript}\n compresscmd /bin/x\n}\n'))
    assert [(d['directive'], d['scope']) for d in result['directives']] == [('compresscmd', 'section')]
    assert 'unexpected_brace' not in codes(result)


def test_comment_lines_between_log_patterns_and_the_brace_are_skipped():
    # logrotate 3.21.0 skips whole "#" lines while reading log patterns, braces included.
    text = '/var/log/a\n# hi }\n  # {\n{\n postrotate\n  echo a\n endscript\n}\n'
    result = lh.resolve(main(text))
    assert (result['logrotate_reading'], codes(result)) == ('determined', BASE_GAPS)
    assert [(s['scope'], s['patterns']) for s in result['scripts']] == [('section', ['/var/log/a'])]
    result = lh.resolve(main('/a.log\n# hi\n/b.log\n{ postrotate\n x\n endscript\n}\n'))
    assert result['scripts'][0]['patterns'] == ['/a.log', '/b.log']


def test_su_value_logrotate_rejects_is_a_gap():
    # logrotate 3.21.0 reads "su=root root" as user "=root" and rejects "su = root root" as extra
    # arguments; both skip the section. The script stays listed as an upper bound.
    for line in ('su=root root', 'su = root root', 'su root root extra'):
        result = lh.resolve(main('/a.log {\n ' + line + '\n postrotate\n x\n endscript\n}\n'))
        assert result['logrotate_reading'] == 'undetermined', line
        assert 'invalid_value' in codes(result), line
        assert [s['kind'] for s in result['scripts']] == ['postrotate'], line
    result = lh.resolve(main('/a.log {\n su root adm\n}\n'))
    assert (result['logrotate_reading'], codes(result)) == ('determined', BASE_GAPS)
