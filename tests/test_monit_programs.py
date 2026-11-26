"""Tests for the pure Monit control-file program contract (roadmap F slice, #1611).

Cases marked "native" replay Ubuntu 24.04 monit 1:5.33.0-2build2: parsed values as printed by
``monit -v -t -c FILE`` and argv/uid observed by running ``monit -I`` with an exec action that
records its arguments and ``id -u``.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import monit_programs as mp  # noqa: E402

NATIVE_RC = (
    'set daemon 30\n'
    'check process sshd with pidfile /run/sshd.pid\n'
    "  start program = \"/usr/sbin/service ssh start 'two words' a'b'c\" as uid nobody with timeout 20 seconds\n"
    '  stop program "/bin/true stop"\n'
    '  if failed port 22 then exec "/bin/echo x" as uid nobody repeat every 3 cycles\n'
    "check program chk with path \"/bin/ls -q 'a b'\"\n"
    '  if status != 0 then alert\n'
)


class MonitProgramsTest(unittest.TestCase):
    def test_native_service_commands_and_accounts(self):
        r = mp.resolve(control_file=NATIVE_RC, daemon_account='root')
        self.assertTrue(r['complete'])
        got = [(c['service'], c['kind'], c['argv'], c['account']['user']) for c in r['commands']]
        self.assertEqual(got, [
            ('sshd', 'start', ['/usr/sbin/service', 'ssh', 'start', 'two words', "a'b'c"], 'nobody'),
            ('sshd', 'stop', ['/bin/true', 'stop'], 'root'),
            ('sshd', 'exec', ['/bin/echo', 'x'], 'nobody'),
            ('chk', 'check_program', ['/bin/ls', '-q', 'a b'], 'root'),
        ])
        self.assertEqual(r['origin'], 'not_assessed')
        self.assertFalse(r['authorizes_response'])

    def test_native_exec_argv_trace(self):
        rc = ('check program t with path "/bin/false" # comment "x"\n'
              "  if status != 0 then exec \"/usr/local/bin/argv.sh a  'b c' d'e'f '  g\\tq  ' #h 'x\"y'\" as uid nobody\n")
        r = mp.resolve(control_file=rc, daemon_account='root')
        self.assertTrue(r['complete'])
        self.assertEqual(r['commands'][0]['argv'], ['/bin/false'])
        self.assertEqual(r['commands'][1]['argv'],
                         ['/usr/local/bin/argv.sh', 'a', 'b c', "d'e'f", 'g\tq', '#h', 'x"y'])
        self.assertEqual(r['commands'][1]['account']['user'], 'nobody')

    def test_native_comments_are_not_commands(self):
        rc = ('# start program = "/bin/evil"\n'
              'check process a with pidfile "/run/a.pid"\n'
              '  start "/bin/a" # stop "/bin/evil2"\n')
        r = mp.resolve(control_file=rc, daemon_account='root')
        self.assertEqual([c['argv'] for c in r['commands']], [['/bin/a']])

    def test_keywords_are_case_sensitive_and_need_a_quote(self):
        rc = 'check process a with pidfile /run/a.pid\n  START program = "/bin/x"\n  starting "y"\n'
        r = mp.resolve(control_file=rc, daemon_account='root')
        self.assertEqual(r['commands'], [])

    def test_path_is_a_command_only_in_check_program(self):
        rc = 'check file f with path "/etc/passwd"\n  if changed checksum then exec "/bin/notify"\n'
        r = mp.resolve(control_file=rc, daemon_account='root')
        self.assertEqual([(c['kind'], c['argv']) for c in r['commands']], [('exec', ['/bin/notify'])])
        self.assertEqual(r['commands'][0]['service_type'], 'file')

    def test_bare_check_is_a_process_check(self):
        r = mp.resolve(control_file='check web with pidfile /run/w.pid\n start "/bin/w"\n', daemon_account='root')
        self.assertEqual((r['commands'][0]['service'], r['commands'][0]['service_type']), ('web', 'process'))

    def test_gid_and_numeric_uid(self):
        rc = 'check process a with pidfile /run/a.pid\n restart program = "/bin/r" as uid 33 and gid "www-data"\n'
        acct = mp.resolve(control_file=rc, daemon_account='root')['commands'][0]['account']
        self.assertEqual(acct, {'user': '33', 'group': 'www-data', 'source': 'option'})

    def test_blocking_gaps(self):
        cases = {
            'include_not_resolved': 'include /etc/monit/conf.d/*\n',
            'unbalanced_quote': 'check process a with pidfile /run/a.pid\n start "/bin/a \'\n',
            'unterminated_command': 'check process a with pidfile /run/a.pid\n start "/bin/a\n',
            'nul_byte': 'start "/bin/a"\0',
            'unsupported_escape': "check process a with pidfile /run/a.pid\n start \"/bin/a '\\0x41'\"\n",
            'empty_command': 'check process a with pidfile /run/a.pid\n start ""\n',
        }
        for kind, rc in cases.items():
            with self.subTest(kind=kind):
                r = mp.resolve(control_file=rc, daemon_account='root')
                self.assertFalse(r['complete'])
                self.assertIn(kind, [g['kind'] for g in r['gaps']])
        r = mp.resolve(control_file=None)
        self.assertEqual([g['kind'] for g in r['gaps']], ['configuration_not_observed'])
        r = mp.resolve(control_file='x' * (mp.MAX_TEXT + 1))
        self.assertEqual([g['kind'] for g in r['gaps']], ['over_limit'])

    def test_unknown_daemon_account_blocks_completion(self):
        r = mp.resolve(control_file=NATIVE_RC)
        self.assertFalse(r['complete'])
        self.assertIn('daemon_account_unknown', [g['kind'] for g in r['gaps']])
        self.assertIsNone(r['commands'][1]['account']['user'])

    def test_include_is_reported(self):
        r = mp.resolve(control_file='include "/etc/monit/conf-enabled/*"\n', daemon_account='root')
        self.assertEqual(r['includes'], ['/etc/monit/conf-enabled/*'])


if __name__ == '__main__':
    unittest.main()
