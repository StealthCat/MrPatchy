"""Tests for the pure strongSwan swanctl updown contract (roadmap F slice, #1624)."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import strongswan_updown as su

CONF = '/etc/swanctl/swanctl.conf'
T = '/usr/local/sbin/trace.sh'


def conf(children: str, conn: str = 'site') -> str:
    return (f'connections {{\n {conn} {{\n  remote_addrs = 10.9.0.2\n'
            f'  local {{ auth = psk }}\n  remote {{ auth = psk }}\n  children {{\n{children}\n  }}\n }}\n}}\n')


def run(text, files=None, directories=None, **kwargs):
    captured = {CONF: text}
    captured.update(files or {})
    return su.evaluate(files=captured, directories=directories or {}, **kwargs)


def commands(result):
    return {(r['connection'], r['child']): r['command'] for r in result['commands'] if r['runs']}


def codes(entries):
    return [e['code'] for e in entries]


class NativeRunTest(unittest.TestCase):
    """Each case replays a native run of Ubuntu 24.04 charon-systemd / strongswan-swanctl
    5.9.13-2ubuntu4.24.04.5: two daemons in separate network namespaces with kernel-libipsec
    established every CHILD_SA, and the updown script recorded its uid, its parent's
    command line (``/proc/$PPID/cmdline``) and its arguments."""

    def test_words_and_quoted_strings_join_with_single_spaces(self):
        # native: parent '/bin/sh -c 2>&1 trace.sh a b c d e', args [a][b][c][d][e], uid=0
        result = run(conf(f'   c1 {{ updown = {T} a"b c"d  e\n    local_ts = 10.1.1.0/24 }}'))
        row = result['commands'][0]
        self.assertEqual(row['command'], f'{T} a b c d e')
        self.assertEqual(row['argv'], ['/bin/sh', '-c', f'2>&1 {T} a b c d e'])
        self.assertEqual(row['uid'], 0)
        self.assertEqual(result['root_commands'], [0])
        self.assertTrue(result['complete'])

    def test_fully_quoted_value_keeps_shell_quoting_and_escapes(self):
        # native: parent '/bin/sh -c 2>&1 trace.sh \'x y\' "q" z', args [x y][q][z]
        result = run(conf(f'   c2 {{ updown = "{T} \'x y\' \\"q\\" z" }}'))
        row = result['commands'][0]
        self.assertEqual(row['command'], f'{T} \'x y\' "q" z')
        self.assertIsNone(row['program'])
        self.assertIn("'", row['shell_metacharacters'])

    def test_comment_ends_value_and_comma_is_literal(self):
        # native: [k] for 'k # comment here'; [a,b,][c] for 'a,b, c'
        result = run(conf(f'   c3 {{ updown = {T} k # comment here\n }}\n   c7 {{ updown = {T} a,b, c }}'))
        self.assertEqual(commands(result), {('site', 'c3'): f'{T} k', ('site', 'c7'): f'{T} a,b, c'})
        self.assertEqual(result['commands'][0]['program'], T)

    def test_later_value_wins(self):
        # native: only [second] ran
        result = run(conf(f'   c4 {{ updown = {T} first\n    updown = {T} second }}'))
        self.assertEqual(commands(result), {('site', 'c4'): f'{T} second'})

    def test_shell_metacharacters_run_further_commands(self):
        # native: '; echo injected >> trace.out' appended 'injected' as a second command
        result = run(conf(f'   c6 {{ updown = {T} semi; echo injected >> /tmp/out }}'))
        row = result['commands'][0]
        self.assertTrue(row['runs'])
        self.assertIsNone(row['program'])
        self.assertEqual(row['shell_metacharacters'], [';', '>'])

    def test_multiline_value_discards_whole_connection(self):
        # native: "loading connection 'site' failed: invalid value for: updown, config discarded"
        result = run(conf(f'   c1 {{ updown = {T} ok }}\n   c5 {{ updown = "{T} multi\nline" }}'))
        self.assertEqual(commands(result), {})
        self.assertTrue(all(r['connection_discarded'] for r in result['commands']))
        self.assertIn('connection_discarded', codes(result['notes']))
        self.assertTrue(result['complete'])

    def test_include_merges_children_and_later_include_overrides(self):
        # native: c8 from inc/extra.conf ran ([merged]); c1's main-file command no longer ran
        main = conf(f'   c1 {{ updown = {T} main }}') + 'include inc/*.conf\n'
        extra = (f'connections {{ site {{ children {{ c8 {{ updown = {T} merged }}\n'
                 f' c1 {{ updown = {T} fromInclude }} }} }} }}\n')
        result = run(main, files={'/etc/swanctl/inc/extra.conf': extra},
                     directories={'/etc/swanctl/inc': ['extra.conf', '.hidden.conf', 'skip.txt']})
        self.assertEqual(commands(result), {('site', 'c1'): f'{T} fromInclude', ('site', 'c8'): f'{T} merged'})
        self.assertEqual(result['files'], [CONF, '/etc/swanctl/inc/extra.conf'])
        self.assertEqual(result['commands'][1]['file'], '/etc/swanctl/inc/extra.conf')
        # glob(3) skips '.hidden.conf' for '*.conf', so it is not an unobserved include.
        self.assertTrue(result['complete'])

    def test_child_without_updown_runs_nothing(self):
        # native: net2 without updown established and produced no trace
        result = run(conf('   net2 { local_ts = 10.1.1.0/24 }'))
        self.assertEqual(result['commands'], [])
        self.assertTrue(result['complete'])


class NativeLoadConnTest(unittest.TestCase):
    """Each case replays the updown value that native Ubuntu 24.04 ``swanctl --load-conns``
    (strongswan-swanctl 5.9.13-2ubuntu4.24.04.5) sent in its vici ``load-conn`` request,
    captured from a stub socket in place of charon."""

    def test_glob_includes_load_in_sorted_order(self):
        drop = 'connections {{ site {{ children {{ c1 {{ updown = {} }} }} }} }}\n'
        result = run(conf('   c1 { updown = /main }') + 'include conf.d/*.conf\n',
                     files={'/etc/swanctl/conf.d/b.conf': drop.format('/fromB'),
                            '/etc/swanctl/conf.d/a.conf': drop.format('/fromA')},
                     directories={'/etc/swanctl/conf.d': ['b.conf', 'a.conf']})
        self.assertEqual(commands(result), {('site', 'c1'): '/fromB'})
        self.assertTrue(result['complete'])

    def test_tab_escape_brace_end_and_semicolon_words(self):
        result = run(conf('   c1 { updown = "/x\\ty $HOME" }\n   c2 { updown = /x arg}\n'
                          '   c3 { updown = /x;/y "a;b" }'))
        self.assertEqual(commands(result), {('site', 'c1'): '/x\ty $HOME', ('site', 'c2'): '/x arg',
                                            ('site', 'c3'): '/x;/y a;b'})
        self.assertTrue(result['complete'])


class GapTest(unittest.TestCase):
    def test_unobserved_include_directory_and_file_block(self):
        result = run(conf('') + 'include conf.d/*.conf\ninclude /etc/extra.conf\n')
        self.assertFalse(result['complete'])
        self.assertEqual(codes(result['gaps']), ['directory_not_observed', 'file_not_observed'])

    def test_absent_directory_and_no_match_include_nothing(self):
        result = run(conf('') + 'include conf.d/*.conf\ninclude none/*.conf\n',
                     directories={'/etc/swanctl/conf.d': [], '/etc/swanctl/none': None})
        self.assertTrue(result['complete'])

    def test_lexing_and_structure_gaps(self):
        cases = {
            'unterminated_quote': conf('   c1 { updown = "x }'),
            'escape_sequence': conf('   c1 { updown = "a\\qb" }'),
            'unbalanced_braces': conf('   c1 { updown = x }') + '}\n',
            'nul_byte': conf('   c1 { updown = x\x00 }'),
            'include_pattern_unsupported': 'include */x.conf\n',
            'syntax': conf('   c1 { updown = a = b }'),
        }
        for code, text in cases.items():
            with self.subTest(code=code):
                result = run(text)
                self.assertFalse(result['complete'])
                self.assertIn(code, codes(result['gaps']))
        self.assertIn('unbalanced_braces', codes(run('connections { site {\n')['gaps']))

    def test_limits_and_daemon_account(self):
        self.assertIn('text_too_large', codes(run('#' * (su.MAX_TEXT + 1))['gaps']))
        loop = run('include swanctl.conf\n')
        self.assertIn('include_depth', codes(loop['gaps']))
        self.assertIn('charon_not_root', codes(run(conf(''), charon_uid=1)['gaps']))
        self.assertIn('charon_uid_invalid', codes(run(conf(''), charon_uid=True)['gaps']))
        # An invalid daemon uid must never be reported as root.
        invalid = run(conf(f'   c1 {{ updown = {T} }}'), charon_uid='0')
        self.assertIn('charon_uid_invalid', codes(invalid['gaps']))
        self.assertIsNone(invalid['charon_uid'])
        self.assertIsNone(invalid['commands'][0]['uid'])
        self.assertEqual(invalid['root_commands'], [])

    def test_result_never_authorizes_response(self):
        result = run(conf(f'   c1 {{ updown = {T} }}'))
        self.assertEqual(result['origin'], 'not_assessed')
        self.assertFalse(result['authorizes_response'])
        self.assertEqual(len(result['command_sha256']), 64)
        same = run(conf(f'   c1 {{ updown = {T} }}'))
        self.assertEqual(same['command_sha256'], result['command_sha256'])
        other = run(conf(f'   c1 {{ updown = {T} x }}'))
        self.assertNotEqual(other['command_sha256'], result['command_sha256'])


if __name__ == '__main__':
    unittest.main()
