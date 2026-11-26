"""Tests for the pure lighttpd command contract (roadmap F slice, #1603)."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import lighttpd_commands as lc

CONF = '/etc/lighttpd/lighttpd.conf'
PASSWD = ('root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n'
          'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n')
GROUP = 'root:x:0:\nwww-data:x:33:\nnogroup:x:65534:\n'
REC = '/srv/lt/rec.sh'

# The configuration traced natively on Ubuntu 24.04 lighttpd 1.4.74-1ubuntu3 with
# ``strace -f -e trace=execve,setuid,setgid,setresuid lighttpd -D -f /srv/lt/lighttpd.conf``.
NATIVE = f'''server.modules = ("mod_accesslog","mod_fastcgi")
server.document-root = "/srv/lt"
server.errorlog = "|{REC} log err"
server.pid-file = "/srv/lt/pid"
server.username = "www-data"
server.groupname = "www-data"
server.port = 8089
var.p = "x" + "y"
include_shell "{REC} inc top " + server.port
include "/srv/lt/inc/*.conf"
accesslog.filename = "|{REC} log acc"
fastcgi.server = ( ".x" => (( "bin-path" => "{REC} fcgi", "socket" => "/srv/lt/fc.sock", "max-procs" => 1 )) )
$HTTP["host"] == "foo" {{ accesslog.filename = "|{REC} log cond" }}
'''

# Debian/Ubuntu stock lighttpd.conf (lighttpd 1.4.74-1ubuntu3), trimmed to its statements.
STOCK = '''server.modules = (
\t"mod_indexfile",
\t"mod_access",
\t"mod_alias",
 \t"mod_redirect",
)
server.document-root        = "/var/www/html"
server.upload-dirs          = ( "/var/cache/lighttpd/uploads" )
server.errorlog             = "/var/log/lighttpd/error.log"
server.pid-file             = "/run/lighttpd.pid"
server.username             = "www-data"
server.groupname            = "www-data"
server.port                 = 80
server.http-parseopts = (
  "header-strict"           => "enable",# default
 #"url-path-2f-reject"      => "enable",
  "url-invalid-utf8-reject" => "enable",# recommended highly
)
index-file.names            = ( "index.php", "index.html" )
url.access-deny             = ( "~", ".inc" )
include_shell "/usr/share/lighttpd/create-mime.conf.pl"
include "/etc/lighttpd/conf-enabled/*.conf"
# default listening port for IPv6 is same as default IPv4 port
include_shell "/usr/share/lighttpd/use-ipv6.pl " + server.port
index-file.names := ( "index.php", "index.html", "index.lighttpd.html" )
'''
PHP = '''server.modules += ( "mod_fastcgi" )
fastcgi.server += ( ".php" =>
\t((
\t\t"bin-path" => "/usr/bin/php-cgi",
\t\t"socket" => "/run/lighttpd/php.socket",
\t\t"max-procs" => 1,
\t\t"bin-environment" => ( "PHP_FCGI_CHILDREN" => "4" ),
\t\t"bin-copy-environment" => ( "PATH", "SHELL", "USER" ),
\t))
)
'''
MIME = '/usr/share/lighttpd/create-mime.conf.pl'
IPV6 = '/usr/share/lighttpd/use-ipv6.pl 80'
SHELL_OUT = {MIME: 'mimetype.assign = ( ".html" => "text/html" )\n',
             IPV6: '$SERVER["socket"] == "[::]:80" { }\n'}


def run(text=None, files=None, **kwargs):
    kwargs.setdefault('passwd_text', PASSWD)
    kwargs.setdefault('group_text', GROUP)
    captured = {} if text is None else {kwargs.get('config_path', CONF): text}
    captured.update(files or {})
    return lc.evaluate(files=captured, **kwargs)


def argvs(result, kind=None):
    return [row['argv'] for row in result['commands'] if kind in (None, row['kind'])]


def codes(result):
    return [gap['code'] for gap in result['gaps']]


class NativeRunTest(unittest.TestCase):
    def native(self, **kwargs):
        return run(NATIVE, config_path='/srv/lt/lighttpd.conf',
                   files={'/srv/lt/inc/a.conf': f'include_shell "{REC} inc a"\n'},
                   globs={'/srv/lt/inc/*.conf': ['/srv/lt/inc/a.conf']},
                   include_shell_output={f'{REC} inc top 8089': 'var.s_top = 1\n', f'{REC} inc a': 'var.s_a = 1\n'},
                   **kwargs)

    def test_native_trace_commands_accounts_and_order(self):
        result = self.native()
        self.assertTrue(result['complete'], result['gaps'])
        self.assertTrue(result['config_accepted'])
        # include_shell runs through the shell as root while parsing, before setuid(33).
        self.assertEqual(argvs(result, 'include_shell'),
                         [['/bin/sh', '-c', f'{REC} inc top 8089'], ['/bin/sh', '-c', f'{REC} inc a']])
        for row in result['commands']:
            if row['kind'] == 'include_shell':
                self.assertEqual((row['account'], row['runs']), ('invoking_user', 'config_parse'))
                self.assertTrue(row['privileged_at_service_start'])
        # Piped loggers (including the conditional one) and bin-path start as uid/gid 33.
        loggers = [row for row in result['commands'] if row['kind'] == 'piped_logger']
        self.assertEqual([row['argv'][2] for row in loggers],
                         [f'{REC} log err', f'{REC} log acc', f'{REC} log cond'])
        self.assertEqual(loggers[2]['condition'], '$HTTP["host"] == "foo"')
        self.assertEqual({(row['uid'], row['gid']) for row in loggers}, {(33, 33)})
        backend = [row for row in result['commands'] if row['kind'] == 'fastcgi']
        self.assertEqual([row['argv'] for row in backend], [[REC, 'fcgi']])
        self.assertEqual((backend[0]['uid'], backend[0]['extension'], backend[0]['max_procs']), (33, '.x', 1))
        self.assertEqual(result['root_commands'], [0, 1])
        self.assertFalse(result['authorizes_response'])
        self.assertEqual(result['origin'], 'not_assessed')

    def test_shell_environment_selects_interpreter(self):
        # With SHELL=/bin/bash the native trace showed /bin/bash -c for include_shell and loggers.
        result = self.native(environment={'SHELL': '/bin/bash'})
        self.assertEqual({row['argv'][0] for row in result['commands'] if row['kind'] != 'fastcgi'}, {'/bin/bash'})

    def test_fingerprint_is_stable_and_changes_with_commands(self):
        first, again = self.native(), self.native()
        self.assertEqual(first['command_sha256'], again['command_sha256'])
        changed = run(NATIVE.replace('log acc', 'log other'), config_path='/srv/lt/lighttpd.conf',
                      files={'/srv/lt/inc/a.conf': ''}, globs={'/srv/lt/inc/*.conf': ['/srv/lt/inc/a.conf']},
                      include_shell_output={f'{REC} inc top 8089': ''})
        self.assertNotEqual(first['command_sha256'], changed['command_sha256'])


class StockDebianTest(unittest.TestCase):
    def stock(self, enabled=None, **kwargs):
        enabled = enabled or {}
        kwargs.setdefault('include_shell_output', SHELL_OUT)
        return run(STOCK, files=enabled,
                   globs={'/etc/lighttpd/conf-enabled/*.conf': sorted(enabled)}, **kwargs)

    def test_stock_configuration_runs_two_root_helpers(self):
        result = self.stock()
        self.assertTrue(result['complete'], result['gaps'])
        # Native trace of the stock file (``lighttpd -tt``): the space-free helper is
        # executed directly, the one with an argument through /bin/sh -c.
        self.assertEqual(argvs(result), [[MIME], ['/bin/sh', '-c', IPV6]])
        self.assertEqual(result['root_commands'], [0, 1])
        self.assertEqual((result['server_user'], result['server_uid'], result['server_gid']), ('www-data', 33, 33))

    def test_enabled_php_module_adds_fastcgi_backend(self):
        result = self.stock({'/etc/lighttpd/conf-enabled/15-fastcgi-php.conf': PHP})
        self.assertTrue(result['complete'], result['gaps'])
        backend = [row for row in result['commands'] if row['kind'] == 'fastcgi']
        self.assertEqual([(row['argv'], row['account'], row['uid']) for row in backend],
                         [(['/usr/bin/php-cgi'], 'www-data', 33)])
        self.assertEqual(result['files'][1]['path'], '/etc/lighttpd/conf-enabled/15-fastcgi-php.conf')

    def test_uncaptured_include_shell_output_is_blocking(self):
        result = self.stock(include_shell_output={})
        self.assertFalse(result['complete'])
        self.assertEqual(codes(result).count('include_shell_output_not_captured'), 2)
        self.assertEqual(len(argvs(result)), 2)

    def test_unobserved_glob_is_blocking(self):
        result = run(STOCK, include_shell_output=SHELL_OUT)
        self.assertIn('unobserved_glob', codes(result))
        self.assertFalse(result['complete'])

    def test_shell_output_can_add_piped_logger(self):
        out = dict(SHELL_OUT)
        out[MIME] = 'accesslog.filename = "|/usr/bin/logger -t lighttpd"\n'
        result = self.stock(include_shell_output=out)
        logger = [row for row in result['commands'] if row['kind'] == 'piped_logger']
        self.assertEqual([(row['source'], row['line'], row['uid']) for row in logger], [(MIME, 1, 33)])


class DirectExecTest(unittest.TestCase):
    def test_native_direct_versus_shell_choice(self):
        # Native trace (/srv/lt3): '/srv/lt3/sh1' and '|/srv/lt3/lg' were executed directly;
        # a trailing tab or ';' made lighttpd run /bin/sh -c.
        cmd = '/srv/lt3/sh1'
        text = (f'server.username = "www-data"\nserver.port = 8091\ninclude_shell "{cmd}"\n'
                f'include_shell "{cmd};true"\ninclude_shell "{cmd}\t"\n'
                'server.errorlog = "|/srv/lt3/lg"\naccesslog.filename = "|/srv/lt3/lg;true"\n')
        result = run(text, include_shell_output={cmd: '', cmd + ';true': '', cmd + '\t': ''})
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual(argvs(result), [[cmd], ['/bin/sh', '-c', cmd + ';true'], ['/bin/sh', '-c', cmd + '\t'],
                                         ['/srv/lt3/lg'], ['/bin/sh', '-c', '/srv/lt3/lg;true']])

    def test_unverified_metacharacters_use_shell_with_note(self):
        result = run('server.username = "www-data"\nserver.errorlog = "|/bin/x>y"\n')
        self.assertEqual(argvs(result), [['/bin/sh', '-c', '/bin/x>y']])
        self.assertIn('shell_choice_not_verified', codes(result))
        self.assertTrue(result['complete'])


class RulesTest(unittest.TestCase):
    def test_relative_include_uses_including_file_directory_and_empty_glob_is_skipped(self):
        result = run('include "inc/*.conf"\ninclude "none/*.conf"\n', config_path='/srv/x/main.conf',
                     files={'/srv/x/inc/r.conf': 'server.errorlog = "|/bin/cat"\n'},
                     globs={'/srv/x/inc/*.conf': ['/srv/x/inc/r.conf'], '/srv/x/none/*.conf': []})
        self.assertTrue(result['config_accepted'])
        self.assertEqual(argvs(result), [['/bin/cat']])
        self.assertIn('no_privilege_drop', codes(result))
        self.assertTrue(result['complete'])  # no_privilege_drop is informational
        self.assertEqual(result['root_commands'], [0])

    def test_missing_plain_include_rejects_configuration(self):
        result = run('include "missing.conf"\naccesslog.filename = "|/bin/cat"\n',
                     files={'/etc/lighttpd/missing.conf': None})
        self.assertFalse(result['config_accepted'])
        self.assertIn('include_not_found', codes(result))
        self.assertEqual([row['starts'] for row in result['commands']], [False])

    def test_duplicate_assignment_rejects_but_replace_and_append_do_not(self):
        bad = run('server.errorlog = "|/a"\nserver.errorlog = "|/b"\n')
        self.assertFalse(bad['config_accepted'])
        self.assertIn('parse_error', codes(bad))
        good = run('server.username = "www-data"\nvar.c = "/a"\nvar.c := "/b"\nvar.c += " -x"\n'
                   'server.errorlog = "|" + var.c\n')
        self.assertEqual(argvs(good), [['/bin/sh', '-c', '/b -x']])

    def test_replacement_reports_only_effective_logger(self):
        # Review on 2cb8eacb: ``:=`` replaces the destination, so only the final value is opened.
        base = 'server.username = "www-data"\n'
        replaced = run(base + 'server.errorlog = "|/inert/old"\nserver.errorlog := "|/inert/new"\n')
        self.assertTrue(replaced['complete'], replaced['gaps'])
        self.assertEqual(argvs(replaced), [['/inert/new']])
        self.assertEqual(replaced['commands'][0]['line'], 3)
        to_file = run(base + 'accesslog.filename = "|/inert/pipe"\naccesslog.filename := "/var/log/a.log"\n')
        self.assertEqual(argvs(to_file), [])
        to_pipe = run(base + 'accesslog.filename = "/var/log/a.log"\naccesslog.filename := "|/inert/pipe"\n')
        self.assertEqual(argvs(to_pipe), [['/inert/pipe']])
        # A replacement in a conditional scope does not remove the global logger.
        scoped = run(base + 'accesslog.filename = "|/inert/g"\n'
                     '$HTTP["host"] == "a" { accesslog.filename = "|/inert/c1"\naccesslog.filename := "/var/log/c" }\n')
        self.assertEqual([(row['argv'], row['condition']) for row in scoped['commands']],
                         [(['/inert/g'], None)])

    def test_backend_append_keeps_entries_and_replacement_drops_them(self):
        base = 'server.username = "www-data"\n'
        appended = run(base + 'fastcgi.server = ( ".a" => (( "bin-path" => "/inert/a" )) )\n'
                       'include "conf-enabled/b.conf"\n',
                       files={'/etc/lighttpd/conf-enabled/b.conf':
                              'fastcgi.server += ( ".b" => (( "bin-path" => "/inert/b" )) )\n'})
        self.assertEqual([(row['argv'], row['source'], row['line']) for row in appended['commands']],
                         [(['/inert/a'], CONF, 2), (['/inert/b'], '/etc/lighttpd/conf-enabled/b.conf', 1)])
        replaced = run(base + 'fastcgi.server = ( ".a" => (( "bin-path" => "/inert/a" )) )\n'
                       'fastcgi.server := ( ".b" => (( "bin-path" => "/inert/b" )) )\n')
        self.assertEqual(argvs(replaced), [['/inert/b']])

    def test_global_syslog_skips_global_errorlog_only(self):
        # lighttpd 1.4.74 config_log_error_open() skips the global errorlog with syslog enabled.
        text = ('server.username = "www-data"\nserver.errorlog = "|/inert/err"\n'
                'server.errorlog-use-syslog = "enable"\nserver.breakagelog = "|/inert/brk"\n'
                '$HTTP["host"] == "a" { server.errorlog = "|/inert/cond" }\n')
        result = run(text)
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual(argvs(result), [['/inert/brk'], ['/inert/cond']])
        self.assertEqual([n['code'] for n in result['notes']], ['errorlog_replaced_by_syslog'])
        disabled = run(text.replace('"enable"', '"disable"'))
        self.assertEqual(argvs(disabled)[0], ['/inert/err'])
        unknown = run(text.replace('"enable"', '"maybe"'))
        self.assertIn('unrecognized_boolean', codes(unknown))
        self.assertFalse(unknown['complete'])
        self.assertEqual(argvs(unknown)[0], ['/inert/err'])

    def test_include_shell_observations_survive_later_replacements(self):
        text = ('server.username = "www-data"\ninclude_shell "/inert/gen"\n'
                'server.errorlog := "/var/log/e.log"\n')
        result = run(text, include_shell_output={'/inert/gen': 'server.errorlog = "|/inert/from-gen"\n'})
        self.assertEqual([(row['kind'], row['argv']) for row in result['commands']],
                         [('include_shell', ['/inert/gen'])])

    def test_escaped_quote_and_comment_inside_string(self):
        result = run('server.username = "www-data"\nserver.errorlog = "|/bin/echo \\"a#b\\"" # trailing\n')
        self.assertEqual(argvs(result), [['/bin/sh', '-c', '/bin/echo "a#b"']])

    def test_unresolved_reference_and_environment(self):
        result = run('server.username = "www-data"\nserver.errorlog = "|" + var.nope\n')
        self.assertIn('unresolved_reference', codes(result))
        self.assertFalse(result['complete'])
        self.assertEqual(argvs(result), [])
        env = run('server.username = "www-data"\nserver.errorlog = "|" + env.LOGGER\n',
                  environment={'LOGGER': '/usr/bin/logger'})
        self.assertEqual(argvs(env), [['/usr/bin/logger']])

    def test_unknown_user_and_missing_accounts(self):
        unknown = run('server.username = "ghost"\n')
        self.assertIn('unknown_user', codes(unknown))
        self.assertFalse(unknown['config_accepted'])
        missing = run('server.username = "www-data"\n', passwd_text=None)
        self.assertIn('passwd_not_captured', codes(missing))
        self.assertFalse(missing['complete'])

    def test_non_piped_logs_and_else_branches(self):
        text = ('server.username = "www-data"\nserver.errorlog = "/var/log/e.log"\n'
                '$HTTP["host"] =~ "a" { accesslog.filename = "/var/log/a" }\n'
                'else $HTTP["host"] == "b" { accesslog.filename = "|/bin/b" }\n'
                'else { accesslog.filename = "|/bin/c" }\n')
        result = run(text)
        self.assertEqual([row['condition'] for row in result['commands']],
                         ['else $HTTP["host"] == "b"', 'else of $HTTP["host"] =~ "a"'])

    def test_include_cycle_and_size_limits(self):
        loop = run('include "lighttpd.conf"\n')
        self.assertIn('input_over_limit', codes(loop))
        self.assertFalse(loop['complete'])
        big = run('#' * (lc.MAX_TEXT + 1))
        self.assertIn('input_over_limit', codes(big))

    def test_parse_error_reports_line(self):
        result = run('server.port = 80\nserver.errorlog = \n')
        gap = next(g for g in result["gaps"] if g["code"] == "parse_error")
        self.assertEqual(gap['line'], 2)

    def test_unobserved_main_file(self):
        result = lc.evaluate(files={})
        self.assertEqual(codes(result)[0], 'unobserved_file')
        self.assertFalse(result['complete'])


if __name__ == '__main__':
    unittest.main()
