"""Tests for the pure collectd exec-plugin contract (roadmap F slice, #1551)."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import collectd_exec as ce  # noqa: E402

CONF = '/etc/collectd/collectd.conf'
PROG = '/usr/local/lib/collectd/prog.sh'
PASSWD = ('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
          'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'
          'toor:x:0:0::/:/bin/sh\n')
GROUP = 'root:x:0:\ndaemon:x:1:\nnogroup:x:65534:\n'
HEAD = 'Interval 1\nLoadPlugin logfile\nLoadPlugin exec\n'


def run(text=None, files=None, **kwargs):
    kwargs.setdefault('passwd_text', PASSWD)
    kwargs.setdefault('group_text', GROUP)
    captured = {} if text is None else {CONF: text}
    captured.update(files or {})
    return ce.evaluate(files=captured, **kwargs)


def started(result):
    return [row['argv'] for row in result['programs'] if row['starts']]


def codes(entries):
    return [entry['code'] for entry in entries]


class NativeRunTest(unittest.TestCase):
    """Each case replays a native run of Ubuntu 24.04 collectd-core 5.12.0-17.1build2
    (``collectd -f -C`` as root under ``strace -f -e trace=execve,setgroups,setgid,setuid``)."""

    def test_argument_formatting_and_accounts(self):
        # Native: execve(..., ["prog.sh", "a b", "5.000000", "755.000000", "16.000000",
        # "true", "On", "1.500000"]); setgroups(2, [65534, 1]) for nobody:daemon;
        # setgroups(1, [65534]) for the unknown group; setgroups(2, [1, 0]) for daemon:root;
        # "Cowardly refusing to exec program as root"; "No such user".
        result = run(HEAD + '<Plugin exec>\n'
                     f'  Exec "nobody" "{PROG}" "a b" 5 0755 0x10 true On 1.5\n'
                     f'  Exec "nobody:daemon" "{PROG}" "grp"\n'
                     f'  Exec "nobody:nosuchgroup" "{PROG}" "badgrp"\n'
                     f'  Exec "root" "{PROG}" "asroot"\n'
                     f'  Exec "toor" "{PROG}" "alias"\n'
                     f'  Exec "nosuchuser" "{PROG}" "baduser"\n'
                     '  exec "nobody:" "prog.sh" "nopath"\n'
                     f'  NotificationExec "daemon:root" "{PROG}" "notif"\n'
                     '  Exec "nobody"\n'
                     '  Foo "x"\n'
                     '</Plugin>\n')
        self.assertTrue(result['complete'])
        self.assertTrue(result['config_accepted'])
        rows = {row['argv'][-1]: row for row in result['programs']}
        self.assertEqual(rows['1.500000']['argv'],
                         ['prog.sh', 'a b', '5.000000', '755.000000', '16.000000', 'true', 'On', '1.500000'])
        self.assertEqual(rows['grp']['supplementary_gids'], [65534, 1])
        self.assertEqual(rows['grp']['effective_gid'], 1)
        self.assertEqual(rows['badgrp']['supplementary_gids'], [65534])
        self.assertEqual(rows['badgrp']['group_status'], 'unknown_group_ignored')
        self.assertTrue(rows['badgrp']['starts'])
        self.assertEqual(rows['asroot']['refused'], 'root_user')
        self.assertEqual(rows['alias']['refused'], 'root_user')
        self.assertEqual(rows['baduser']['refused'], 'unknown_user')
        self.assertFalse(rows['baduser']['starts'])
        self.assertTrue(rows['nopath']['path_search'])
        self.assertEqual(rows['nopath']['supplementary_gids'], [65534])
        notif = rows['notif']
        self.assertEqual(notif['kind'], 'notification_exec')
        self.assertEqual((notif['uid'], notif['gid'], notif['supplementary_gids']), (1, 1, [1, 0]))
        self.assertTrue(notif['runs_with_root_group'])
        self.assertEqual(result['root_group_programs'], [result['programs'].index(notif)])
        self.assertEqual(codes(result['notes'])[:2], ['exec_option_invalid', 'exec_option_unknown'])
        self.assertFalse(result['authorizes_response'])
        self.assertEqual(result['origin'], 'not_assessed')

    def test_last_line_without_newline_rejects_the_file(self):
        # Native: "syntax error, unexpected end of file, expecting EOL"; collectd exits.
        result = run(HEAD + f'<Plugin exec>\n  Exec "nobody" "{PROG}" "last"\n</Plugin>')
        self.assertFalse(result['config_accepted'])
        self.assertEqual(result['files'][0]['status'], 'parse_error')
        self.assertEqual(started(result), [])
        self.assertFalse(result['programs'][0]['starts'] if result['programs'] else False)

    def test_unquoted_path_is_a_parse_error(self):
        # Native: "syntax error, unexpected SLASH".
        result = run(HEAD + '<Plugin exec>\n  Exec nobody /bin/prog\n</Plugin>\n')
        self.assertFalse(result['config_accepted'])

    def test_block_close_is_case_sensitive(self):
        # Native: "block_begin = Plugin; block_end = plugin; ... block not closed".
        result = run(HEAD + f'<Plugin exec>\n  Exec nobody "{PROG}" "x"\n</plugin>\n')
        self.assertFalse(result['config_accepted'])
        self.assertEqual(result['files'][0]['reason'], 'block_not_closed')

    def test_block_before_load_echoed_bytes_and_multiline_strings(self):
        # Native: only the second block's program ran, as
        # ["prog.sh", "foo", "bar", "baz", "multiline", "1.2.3.4", "-5.000000", "x"].
        result = run('Interval 1\n'
                     f'<Plugin exec>\n  Exec nobody "{PROG}" "before-load"\n</Plugin>\n'
                     'LoadPlugin exec\n'
                     f'<Plugin exec>\n  Exec nobody "{PROG}" foo-bar.baz "multi\\\n'
                     '     line" 1.2.3.4 -5 +x\n</Plugin>\n')
        self.assertEqual(started(result),
                         [['prog.sh', 'foo', 'bar', 'baz', 'multiline', '1.2.3.4', '-5.000000', 'x']])
        self.assertIn('exec_block_before_load', codes(result['notes']))

    def test_autoload_and_include_inside_a_plugin_block(self):
        # Native: the program ran; "exec plugin: Unknown config option `Include'".
        result = run('AutoLoadPlugin true\n<Plugin "exec">\n'
                     f'  Exec nobody "{PROG}" "autoload"\n  Include "/etc/collectd/d"\n</Plugin>\n')
        self.assertEqual(started(result), [['prog.sh', 'autoload']])
        self.assertTrue(result['exec_plugin_loaded'])
        self.assertIn('exec_option_unknown', codes(result['notes']))


def block(tag):
    return f'<Plugin exec>\n  Exec nobody "{PROG}" "{tag}"\n</Plugin>\n'


DROPINS = {
    '/etc/collectd/d/10-a.conf': block('d10'),
    '/etc/collectd/d/20-bad.conf': block('d20').replace('</Plugin>', '</plugin>'),
    '/etc/collectd/d/30-c.conf': block('d30'),
    '/etc/collectd/d/40.txt': block('dtxt'),
    '/etc/collectd/d/.hidden.conf': block('dot'),
    '/etc/collectd/d/sub/50.conf': block('dsub'),
    '/etc/collectd/g/x1.conf': block('g1'),
    '/etc/collectd/g/x2.cfg': block('g2'),
    '/etc/collectd/missing.conf': None,
}
LISTINGS = {
    '/etc/collectd/d': ['30-c.conf', '10-a.conf', '.hidden.conf', '20-bad.conf', 'sub', '40.txt'],
    '/etc/collectd/d/sub': ['50.conf'],
    '/etc/collectd/g': ['x2.cfg', 'x1.conf'],
}


class IncludeTest(unittest.TestCase):
    """Native include runs with the same tree under a scratch directory."""

    def test_directory_filter_glob_and_missing_targets(self):
        # Native: d10, d30, dsub, g1 and g2 ran; 20-bad.conf "block not closed" was skipped;
        # "stat (.../missing.conf) failed" was skipped.
        result = run(HEAD + '<Include "/etc/collectd/d">\n  Filter "*.conf"\n</Include>\n'
                     'Include "/etc/collectd/g/*"\nInclude "/etc/collectd/missing.conf"\n',
                     files=DROPINS, directories=LISTINGS)
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual([argv[-1] for argv in started(result)], ['d10', 'd30', 'dsub', 'g1', 'g2'])
        status = {row['path']: row['status'] for row in result['files']}
        self.assertEqual(status['/etc/collectd/d/20-bad.conf'], 'parse_error')
        self.assertEqual(status['/etc/collectd/d/40.txt'], 'filtered_out')
        self.assertNotIn('/etc/collectd/d/.hidden.conf', status)

    def test_direct_file_not_matching_filter_rejects_the_config(self):
        # Native: "Unable to read config file ...", "Parsing the config file failed!".
        result = run(HEAD + block('main') + '<Include "/etc/collectd/g/x2.cfg">\n  Filter "*.conf"\n</Include>\n',
                     files=DROPINS, directories=LISTINGS)
        self.assertFalse(result['config_accepted'])
        self.assertEqual(started(result), [])
        self.assertEqual(result['files'][0]['status'], 'rejected')

    def test_direct_file_parse_error_rejects_the_config(self):
        # Native: 20-bad.conf "block not closed" then "Parsing the config file failed!".
        result = run(HEAD + 'Include "/etc/collectd/d/20-bad.conf"\nInclude "/etc/collectd/g/x1.conf"\n',
                     files=DROPINS, directories=LISTINGS)
        self.assertFalse(result['config_accepted'])
        self.assertEqual(started(result), [])


class GapTest(unittest.TestCase):
    def test_unobserved_include_and_accounts(self):
        result = run(HEAD + 'Include "/etc/collectd/collectd.conf.d/*.conf"\n', passwd_text=None)
        self.assertFalse(result['complete'])
        self.assertIn('listing_unobserved', codes(result['gaps']))
        self.assertIn('passwd_not_supplied', codes(result['gaps']))
        result = run(HEAD + 'Include "/etc/collectd/other.conf"\n')
        self.assertIn('path_unobserved', codes(result['gaps']))

    def test_unsupported_wordexp_and_relative_includes(self):
        result = run(HEAD + 'Include "$HOME/x.conf"\nInclude "rel.conf"\n')
        self.assertEqual(codes(result['gaps']), ['include_path_unsupported', 'include_path_relative'])
        self.assertFalse(result['complete'])

    def test_wordexp_bad_character_rejects_the_config(self):
        result = run(HEAD + 'Include "/etc/collectd/a;b"\n')
        self.assertFalse(result['config_accepted'])

    def test_relocated_plugin_dir_and_non_root_daemon(self):
        result = run('PluginDir "/opt/evil"\nLoadPlugin exec\n' + block('x'), collectd_uid=113)
        self.assertEqual(codes(result['gaps']), ['collectd_not_root', 'plugin_dir_relocated'])
        self.assertFalse(result['complete'])

    def test_include_depth_is_bounded(self):
        files = {f'/etc/collectd/l{i}.conf': f'Include "/etc/collectd/l{i + 1}.conf"\n' for i in range(10)}
        result = run('Include "/etc/collectd/l0.conf"\n', files=files)
        self.assertFalse(result['config_accepted'])
        self.assertIn('include_depth_exceeded', codes(result['notes']))

    def test_empty_config_and_fingerprint(self):
        self.assertFalse(run('# nothing\n')['config_accepted'])
        first = run(HEAD + block('x'))
        second = run(HEAD + '# comment\n' + block('x'))
        third = run(HEAD + block('y'))
        self.assertEqual(first['program_sha256'], second['program_sha256'])
        self.assertNotEqual(first['program_sha256'], third['program_sha256'])


class ScannerTest(unittest.TestCase):
    def test_tokens(self):
        kinds = [(kind, value) for kind, value, _ in ce.tokenize('A true True 0x1F 0755 -2 1.2.3 ::1 "a\\"b"\n')]
        self.assertEqual(kinds, [('UNQUOTED', 'A'), ('BOOL', True), ('UNQUOTED', 'True'),
                                 ('NUMBER', 31.0), ('NUMBER', 755.0), ('NUMBER', -2.0),
                                 ('NUMBER', 1.2), ('NUMBER', 0.3), ('UNQUOTED', '::1'),
                                 ('QUOTED', 'a"b'), ('EOL', None)])

    def test_comments_continuations_and_crlf(self):
        items = ce.parse('Key "v" # note\r\nOther \\\n "w"\r\n')
        self.assertEqual([(i['key'], i['values']) for i in items],
                         [('Key', [('string', 'v')]), ('Other', [('string', 'w')])])

    def test_empty_block_is_dropped(self):
        self.assertEqual(ce.parse('<Empty>\n</Empty>\n'), [])


if __name__ == '__main__':
    unittest.main()
