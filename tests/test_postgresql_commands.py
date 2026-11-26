"""Tests for the pure PostgreSQL server command contract (roadmap F slice, #1597)."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import postgresql_commands as pc  # noqa: E402

ETC = '/etc/postgresql/16/main'
CONF = ETC + '/postgresql.conf'
DATA = '/var/lib/postgresql/16/main'
AUTO = DATA + '/postgresql.auto.conf'
HEAD = "data_directory = '%s'\n" % DATA


def run(main, extra=None, auto=None, dirs=None, **kwargs):
    files = {CONF: {'state': 'regular', 'text': main}}
    for path, text in (extra or {}).items():
        files[path] = text if isinstance(text, dict) else {'state': 'regular', 'text': text}
    files[AUTO] = {'state': 'absent'} if auto is None else {'state': 'regular', 'text': auto}
    return pc.assess(files, config_file=CONF, directories=dirs, **kwargs)


def effective(result, name='archive_command'):
    row = result['settings'].get(name)
    return row['value'] if row else None


def command(result, name='archive_command'):
    rows = [row for row in result['commands'] if row['setting'] == name]
    return rows[0] if rows else None


class NativeParseTest(unittest.TestCase):
    """Each case replays ``postgres -c config_file=... -C <name>`` on Ubuntu 24.04
    PostgreSQL 16.15: either the printed value or "configuration file contains errors"."""

    accepted = {
        "archive_command = 'cp \\\\x %p ''q'' \\\\101\\\\t'\n": "cp \\x %p 'q' \\101\\t",
        "archive_command = 'a\\tb''c\\101'\n": "a\tb'cA",
        'archive_command cp\n': 'cp',
        'archive_command = foo.bar.baz\n': 'foo.bar.baz',
        "archive_command = 'a'\nARCHIVE_Command = 'b'\n": 'b',
        "archive_command = 'a' # comment\n": 'a',
        'archive_command = 10kB\n': '10kB',
        'archive_command = -1.5e3\n': '-1.5e3',
        'archive_command = 0x1fz\n': '0x1fz',
        'archive_command = éte\n': 'éte',
        "archive_command='a'": 'a',
    }
    rejected = (
        'archive_command = foo.conf\n',        # qualified ID is not a value token
        'archive_command = /bin/true\n',       # "/" cannot start an unquoted string
        "archive_command = 'a' 'b'\narchive_command = 'z'\n",
        "archive_command = 'a\narchive_command = 'b'\n",
        'archive_command =\n',
        'archive_command = a$b\n',
        "archive_command = 'a\\\\'b'\n",
        "'archive_command' = 'a'\n",
        'archive_command = 1.5e\n',
        'archive_command cp\nARCHIVE_COMMAND="x"\n',
    )

    def test_accepted_values_match_native(self):
        for text, expected in self.accepted.items():
            with self.subTest(text=text):
                result = run(HEAD + text)
                self.assertFalse(result['has_errors'], result['errors'])
                self.assertEqual(effective(result), expected)

    def test_rejected_files_match_native(self):
        for text in self.rejected:
            with self.subTest(text=text):
                result = run(HEAD + text)
                self.assertTrue(result['has_errors'])
                self.assertFalse(result['server_starts'])
                self.assertEqual(result['start_blocker'], 'configuration_file_contains_errors')

    def test_syntax_error_keeps_parsing_later_lines(self):
        result = run(HEAD + 'archive_command = /x\narchive_mode = on\n')
        self.assertEqual([e['reason'] for e in result['errors']], ['syntax_error'])
        self.assertEqual(result['errors'][0]['line'], 2)
        self.assertEqual(result['settings']['archive_mode']['value'], 'on')

    def test_enum_and_bool_values_match_native(self):
        for text, ok in (('archive_mode = yes\n', True), ('archive_mode = maybe\n', False),
                         ('ssl = of\n', True), ('ssl = t\n', True), ('ssl = o\n', False),
                         ("ssl = ' on'\n", False)):
            with self.subTest(text=text):
                self.assertEqual(not run(HEAD + text)['has_errors'], ok)


class NativeIncludeTest(unittest.TestCase):
    def test_relative_include_in_place_and_last_wins(self):
        sub = {ETC + '/sub/x.conf': "archive_command = 'inc'\n"}
        before = run(HEAD + "include 'sub/x.conf'\narchive_command = 'm'\n", sub)
        after = run(HEAD + "archive_command = 'm'\ninclude 'sub/x.conf'\n", sub)
        self.assertEqual((effective(before), effective(after)), ('m', 'inc'))
        self.assertEqual(after['settings']['archive_command']['file'], ETC + '/sub/x.conf')
        self.assertEqual(after['settings']['archive_command']['superseded'],
                         [{'value': 'm', 'file': CONF, 'line': 2}])
        self.assertEqual(after['files_read'], [CONF, ETC + '/sub/x.conf'])

    def test_missing_include_rejects_but_if_exists_skips(self):
        missing = {ETC + '/nope.conf': {'state': 'absent'}}
        self.assertTrue(run(HEAD + "include 'nope.conf'\n", missing)['has_errors'])
        skipped = run(HEAD + "include_if_exists 'nope.conf'\narchive_command='m'\n", missing)
        self.assertFalse(skipped['has_errors'])
        self.assertEqual(effective(skipped), 'm')
        unreadable = {ETC + '/nope.conf': {'state': 'unreadable'}}
        self.assertFalse(run(HEAD + "include_if_exists 'nope.conf'\n", unreadable)['has_errors'])

    def test_include_dir_order_and_filters(self):
        d = ETC + '/conf.d'
        names = {'b.conf': 'b', 'a.conf': 'a', '.z.conf': 'dot', 'z.cnf': 'cnf',
                 'B.conf': 'B', '.conf': 'short'}
        extra = {d + '/' + n: "archive_command = '%s'\n" % v for n, v in names.items()}
        entries = [{'name': n, 'kind': 'file'} for n in names] + [{'name': 'zz.conf', 'kind': 'dir'}]
        result = run(HEAD + "include_dir 'conf.d'\n", extra,
                     dirs={d: {'state': 'present', 'entries': entries}})
        self.assertFalse(result['has_errors'])
        self.assertEqual(effective(result), 'b')  # strcmp order: B.conf, a.conf, b.conf
        self.assertEqual(result['files_read'][1:], [d + '/B.conf', d + '/a.conf', d + '/b.conf'])

    def test_recursion_depth_and_blank_names_are_errors(self):
        self.assertTrue(run(HEAD + "include 'postgresql.conf'\n")['has_errors'])
        cycle = run(HEAD + "include 'a.conf'\n", {ETC + '/a.conf': "include 'b.conf'\n",
                                                  ETC + '/b.conf': "include 'a.conf'\n"})
        self.assertIn('maximum_nesting_depth_exceeded', [e['reason'] for e in cycle['errors']])
        self.assertTrue(run(HEAD + "include ''\n")['has_errors'])

    def test_auto_conf_is_read_last_and_its_errors_count(self):
        result = run(HEAD + "archive_command = 'm'\n", auto="archive_command = 'auto'\n")
        self.assertEqual(effective(result), 'auto')
        self.assertEqual(result['settings']['archive_command']['file'], AUTO)
        self.assertEqual(result['auto_conf'], AUTO)
        self.assertTrue(run(HEAD + "archive_command = 'm'\n", auto='archive_command = /x\n')
                        ['has_errors'])

    def test_data_directory_fallback_and_gaps(self):
        files = {CONF: {'state': 'regular', 'text': "archive_command = 'm'\n"},
                 '/srv/pg/postgresql.auto.conf': {'state': 'regular',
                                                  'text': "archive_command = 'a'\n"}}
        result = pc.assess(files, config_file=CONF, data_dir='/srv/pg')
        self.assertEqual((result['data_directory'], effective(result)), ('/srv/pg', 'a'))
        self.assertTrue(result['complete'])
        unknown = pc.assess({CONF: files[CONF]}, config_file=CONF)
        self.assertFalse(unknown['complete'])
        self.assertIn('data_directory_unknown', [g['reason'] for g in unknown['gaps']])
        unobserved = pc.assess({CONF: {'state': 'regular', 'text': HEAD}}, config_file=CONF)
        self.assertIn('auto_conf_not_observed', [g['reason'] for g in unobserved['gaps']])


class NativeRuntimeTest(unittest.TestCase):
    """Each case replays a ``pg_ctl start`` of PostgreSQL 16.15 followed by
    ``pg_switch_wal()``, reading the server log and the archive_command output."""

    def test_archive_command_runs_through_shell(self):
        result = run(HEAD + "archive_mode = on\narchive_command = 'cp %p /arch/%f'\n")
        row = command(result)
        self.assertTrue(result['server_starts'])
        self.assertTrue(row['active'])
        self.assertEqual(row['invocation'], ['/bin/sh', '-c', 'cp %p /arch/%f'])
        self.assertEqual(row['run_as'], 'server_os_user')
        self.assertEqual(row['conditions'], ['archive_mode_on', 'not_while_standby'])
        self.assertFalse(result['authorizes_response'])

    def test_archive_mode_off_keeps_archive_command_inactive(self):
        row = command(run(HEAD + "archive_command = 'cp %p /arch/%f'\n"))
        self.assertEqual((row['active'], row['inactive_reason']), (False, 'archive_mode_off'))

    def test_unknown_placeholder_fails_instead_of_running(self):
        # FATAL: invalid value for parameter "archive_command" ... unexpected placeholder "%x"
        row = command(run(HEAD + "archive_mode = on\narchive_command = 'echo %f %x'\n"))
        self.assertFalse(row['active'])
        self.assertEqual(row['placeholder_error'], 'unexpected_placeholder_%x')
        self.assertEqual(pc.placeholder_problem('a %', 'fp'), 'string_ends_after_percent')
        self.assertIsNone(pc.placeholder_problem('a %% %r', 'r'))

    def test_both_archive_command_and_library_run_neither(self):
        # FATAL: both archive_command and archive_library set
        result = run(HEAD + "archive_mode = on\narchive_command = 'x'\n"
                     "archive_library = 'basic_archive'\n")
        self.assertEqual(command(result)['inactive_reason'], 'archive_library_also_set')
        lib = [r for r in result['libraries'] if r['setting'] == 'archive_library'][0]
        self.assertEqual((lib['active'], lib['inactive_reason']), (False, 'archive_command_also_set'))

    def test_archive_mode_with_minimal_wal_stops_the_server(self):
        # FATAL: WAL archival cannot be enabled when wal_level is "minimal"
        result = run(HEAD + "archive_mode = on\nwal_level = minimal\nmax_wal_senders = 0\n"
                     "shared_preload_libraries = 'x'\n")
        self.assertFalse(result['server_starts'])
        self.assertEqual(result['start_blocker'], 'archive_mode_requires_wal_level_above_minimal')
        self.assertFalse(result['libraries'][0]['active'])

    def test_invalid_preload_list_is_logged_and_loads_nothing(self):
        # LOG: invalid list syntax in parameter "shared_preload_libraries"; server starts.
        result = run(HEAD + "shared_preload_libraries = 'nonexistent_lib,,x'\n")
        self.assertTrue(result['server_starts'])
        self.assertEqual([(r['library'], r['inactive_reason']) for r in result['libraries']],
                         [(None, 'invalid_list_syntax_nothing_loaded')])

    def test_preload_libraries_and_list_quoting(self):
        result = run(HEAD + "shared_preload_libraries = 'a, \"b,c\" ,d'\n"
                     "session_preload_libraries = '$libdir/x'\n")
        self.assertEqual([(r['setting'], r['library'], r['when']) for r in result['libraries']], [
            ('shared_preload_libraries', 'a', 'postmaster_start'),
            ('shared_preload_libraries', 'b,c', 'postmaster_start'),
            ('shared_preload_libraries', 'd', 'postmaster_start'),
            ('session_preload_libraries', '$libdir/x', 'each_session_start')])
        self.assertEqual(result['dynamic_library_path'], '$libdir')


class ContractTest(unittest.TestCase):
    def test_recovery_and_ssl_commands_report_conditions(self):
        result = run(HEAD + "restore_command = 'cp /arch/%f %p'\nssl = on\n"
                     "ssl_passphrase_command = 'cat /k'\narchive_cleanup_command = 'x %r'\n")
        restore = command(result, 'restore_command')
        self.assertTrue(restore['active'])
        self.assertEqual(restore['conditions'], ['recovery_or_standby_signal_file_present'])
        self.assertEqual(command(result, 'ssl_passphrase_command')['conditions'],
                         ['ssl_key_file_has_passphrase', 'start_only'])
        self.assertTrue(command(result, 'archive_cleanup_command')['active'])
        off = command(run(HEAD + "ssl_passphrase_command = 'cat /k'\n"), 'ssl_passphrase_command')
        self.assertEqual(off['inactive_reason'], 'ssl_off')

    def test_unobserved_and_unsafe_input_are_gaps(self):
        for state in ('unknown', 'not_regular'):
            with self.subTest(state=state):
                result = run(HEAD + "include 'x.conf'\n", {ETC + '/x.conf': {'state': state}})
                self.assertFalse(result['complete'])
        self.assertFalse(run(HEAD + 'a = 1\0\n')['complete'])
        self.assertFalse(run(HEAD + "include_dir 'd'\n")['complete'])
        big = run(HEAD + '#' * (pc.MAX_TEXT + 1))
        self.assertIn('file_too_large', [g['reason'] for g in big['gaps']])
        self.assertFalse(pc.assess({}, config_file='relative.conf')['complete'])

    def test_never_runs_anything(self):
        marker = '/tmp/mrpatchy-postgresql-contract-marker'
        if os.path.exists(marker):
            os.remove(marker)
        run(HEAD + "archive_mode = on\narchive_command = 'touch %s'\n"
            "include_dir 'd'\n" % marker)
        self.assertFalse(os.path.exists(marker))


if __name__ == '__main__':
    unittest.main()
