import unittest

from app import mdadm_program as m


def file(text):
    return {'state': 'file', 'text': text}


ABSENT = {'state': 'absent'}


def debian(text, drop_ins=None, *, main=ABSENT):
    """Debian layout: /etc/mdadm.conf absent, config under /etc/mdadm/."""
    return {
        m.CONF_FILE: main,
        m.ALT_CONF_FILE: file(text) if isinstance(text, str) else text,
        m.ALT_CONF_DIR: {'state': 'directory', 'entries': drop_ins} if drop_ins is not None else ABSENT,
        m.CONF_DIR: ABSENT,
    }


class TokenizerTests(unittest.TestCase):
    """Vectors derived from lib.c conf_word/conf_line in mdadm 4.3."""

    def words(self, text):
        return [words for _, words in m._conf_lines(text)]

    def test_continuation_comments_and_blank_lines(self):
        text = 'PROGRAM /a\n# comment\n\n  /b\nMAILADDR root\n'
        self.assertEqual(self.words(text), [['PROGRAM', '/a', '/b'], ['MAILADDR', 'root']])

    def test_indented_first_line_starts_a_line(self):
        self.assertEqual(self.words('   PROGRAM /x\n'), [['PROGRAM', '/x']])

    def test_quotes_are_removed_and_keep_spaces(self):
        self.assertEqual(self.words('PROGRAM "/opt/my prog" x\'y z\'w\n'),
                         [['PROGRAM', '/opt/my prog', 'xy zw']])

    def test_unterminated_quote_ends_at_newline(self):
        self.assertEqual(self.words('PROGRAM "/a b\nMAIL root\n'), [['PROGRAM', '/a b'], ['MAIL', 'root']])

    def test_hash_inside_word_is_literal_but_starts_comment_after_space(self):
        self.assertEqual(self.words('PROGRAM /a#b #c d\n'), [['PROGRAM', '/a#b']])

    def test_empty_quoted_word_is_a_word(self):
        self.assertEqual(self.words('PROGRAM ""\n'), [['PROGRAM', '']])

    def test_line_numbers_point_at_keyword(self):
        self.assertEqual([line for line, _ in m._conf_lines('\n# x\n  PROG /a\n\nMAILADDR r\n')], [3, 5])

    def test_mdstat_active_hack(self):
        self.assertEqual(self.words('x active(auto-read-only)\n'), [['x', 'active', '(auto-read-only)']])

    def test_crlf_carriage_return_is_part_of_the_word(self):
        self.assertEqual(self.words('PROGRAM /a\r\n'), [['PROGRAM', '/a\r']])


class KeywordTests(unittest.TestCase):
    def test_prefix_of_at_least_three_case_insensitive(self):
        self.assertEqual(m.match_keyword('PRO'), 'program')
        self.assertEqual(m.match_keyword('pRoGrAm'), 'program')
        self.assertEqual(m.match_keyword('mai'), 'mailaddr')
        self.assertEqual(m.match_keyword('MAILF'), 'mailfrom')
        self.assertEqual(m.match_keyword('par'), 'part-policy')
        self.assertIsNone(m.match_keyword('pr'))
        self.assertIsNone(m.match_keyword('programs'))
        self.assertIsNone(m.match_keyword('PROGRAMİ'))


class ResolutionTests(unittest.TestCase):
    def test_debian_program_resolves_to_root_execl(self):
        result = m.assess(debian('DEVICE partitions\nMAILADDR root\nPROGRAM /usr/local/sbin/raid-alert\n'))
        self.assertTrue(result['complete'])
        self.assertTrue(result['monitor_runs'])
        command = result['command']
        self.assertEqual(command['program'], '/usr/local/sbin/raid-alert')
        self.assertEqual(command['argv'], ['/usr/local/sbin/raid-alert', 'EVENT', 'MD_DEVICE', '[COMPONENT_DEVICE]'])
        self.assertEqual(command['runs_as'], 'root')
        self.assertFalse(command['shell'])
        self.assertEqual(command['source'], {'path': m.ALT_CONF_FILE, 'line': 3, 'keyword': 'PROGRAM'})
        self.assertIn('Fail', command['events'])
        self.assertEqual(result['mailaddr'], 'root')
        self.assertEqual(result['configuration']['directory'], m.ALT_CONF_DIR)
        self.assertFalse(result['authorizes_response'])
        self.assertEqual(result['origin'], 'not_assessed')

    def test_first_program_word_wins_across_lines_and_files(self):
        result = m.assess(debian('PROGRAM /first /extra\nPROG /second\n',
                                 {'00-x.conf': file('PROGRAM /dropin\n')}))
        self.assertEqual(result['command']['program'], '/first')
        self.assertEqual([i['value'] for i in result['ignored_program_words']], ['/extra', '/second', '/dropin'])

    def test_drop_in_supplies_program_in_byte_order(self):
        result = m.assess(debian('MAILADDR root\n', {
            'b.conf': file('PROGRAM /b\n'), 'B.conf': file('PROGRAM /B\n'), '.a.conf': file('PROGRAM /hidden\n'),
            'x.conf.bak': file('PROGRAM /bak\n'), 'sub.conf': {'state': 'directory'},
        }))
        self.assertEqual(result['command']['program'], '/B')
        self.assertEqual(result['configuration']['parsed'],
                         [m.ALT_CONF_FILE, f'{m.ALT_CONF_DIR}/B.conf', f'{m.ALT_CONF_DIR}/b.conf'])

    def test_planted_etc_mdadm_conf_hides_debian_file(self):
        paths = debian('PROGRAM /legit\n', main=file('PROGRAM /planted\n'))
        result = m.assess(paths)
        self.assertEqual(result['configuration']['file'], m.CONF_FILE)
        self.assertEqual(result['configuration']['directory'], m.CONF_DIR)
        self.assertEqual(result['command']['program'], '/planted')
        self.assertEqual(result['configuration']['parsed'], [m.CONF_FILE])

    def test_both_main_files_absent_still_reads_upstream_drop_in(self):
        result = m.assess({
            m.CONF_FILE: ABSENT, m.ALT_CONF_FILE: ABSENT,
            m.CONF_DIR: {'state': 'directory', 'entries': {'evil.conf': file('PROGRAM /tmp/x\n')}},
        })
        self.assertTrue(result['complete'])
        self.assertEqual(result['command']['program'], '/tmp/x')
        self.assertTrue(result['command']['absolute'])

    def test_main_path_that_is_a_directory_is_read_as_one(self):
        result = m.assess({
            m.CONF_FILE: {'state': 'directory', 'entries': {'p.conf': file('PROGRAM /d\n')}},
            m.CONF_DIR: ABSENT,
        })
        self.assertEqual(result['command']['program'], '/d')

    def test_no_program_or_mail_means_monitor_exits(self):
        result = m.assess(debian('DEVICE partitions\nARRAY /dev/md0 UUID=x\n'))
        self.assertTrue(result['complete'])
        self.assertFalse(result['monitor_runs'])
        self.assertIsNone(result['command'])

    def test_empty_and_relative_programs_are_explained(self):
        empty = m.assess(debian('PROGRAM ""\n'))['command']
        self.assertTrue(empty['executable_name_empty'])
        relative = m.assess(debian('PROGRAM alert.sh\n'))['command']
        self.assertFalse(relative['absolute'])
        self.assertIn('(/)', relative['note'])

    def test_unknown_keywords_are_listed(self):
        result = m.assess(debian('PROGRAMS /x\nPR /y\n'))
        self.assertIsNone(result['command'])
        self.assertEqual([u['word'] for u in result['unknown_keywords']], ['PROGRAMS', 'PR'])


class GapTests(unittest.TestCase):
    def assert_blocked(self, paths, code):
        result = m.assess(paths)
        self.assertFalse(result['complete'])
        self.assertIn(code, result['blocking_gaps'])
        self.assertIsNone(result['command'])
        self.assertIsNone(result['monitor_runs'])
        return result

    def test_missing_observations_block(self):
        self.assert_blocked(None, 'input_malformed')
        self.assert_blocked({}, 'path_not_observed')
        self.assert_blocked({m.CONF_FILE: ABSENT}, 'path_not_observed')
        self.assert_blocked({m.CONF_FILE: ABSENT, m.ALT_CONF_FILE: file('PROGRAM /x\n')}, 'path_not_observed')

    def test_unreadable_and_odd_paths_block(self):
        self.assert_blocked(debian({'state': 'unreadable'}), 'path_unreadable')
        self.assert_blocked(debian('PROGRAM /x\n', {'a.conf': {'state': 'unreadable'}}), 'entry_unreadable')
        self.assert_blocked(debian('', main={'state': 'other'}), 'path_other_type')
        self.assert_blocked(debian('', main={'state': 'bogus'}), 'input_malformed')

    def test_limits_block(self):
        self.assert_blocked(debian('#' * (m.MAX_BYTES + 1)), 'too_large')
        many = {f'{i}.conf': file('') for i in range(m.MAX_DIR_ENTRIES + 1)}
        self.assert_blocked(debian('', many), 'too_many_entries')

    def test_gaps_are_capped(self):
        entries = {f'{i:03}.conf': {'state': 'unreadable'} for i in range(m.MAX_GAPS + 5)}
        result = self.assert_blocked(debian('', entries), 'gaps_truncated')
        self.assertEqual(len(result['gaps']), m.MAX_GAPS)


if __name__ == '__main__':
    unittest.main()
