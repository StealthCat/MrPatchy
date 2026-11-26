"""Tests for the pure Dovecot service contract (roadmap F slice, #1620)."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import dovecot_services as ds

CONF = '/etc/dovecot/dovecot.conf'
PASSWD = ('root:x:0:0:root:/root:/bin/bash\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n'
          'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'
          'dovecot:x:103:105:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin\n'
          'dovenull:x:104:106:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin\n')
GROUP = 'root:x:0:\nmail:x:8:\nnogroup:x:65534:\ndovecot:x:105:\ndovenull:x:106:\n'
REC = '/usr/local/bin/dvrec.sh'

# Traced natively on Ubuntu 24.04 dovecot-core 1:2.3.21+dfsg1-2ubuntu6.5 with
# ``dovecot -F -c <file>``; the recorder logged ``id -u:id -g:$0:$*``:
#   rawexe 0:0 "rawexe a1"; rootexe 0:0; internal 0:0; lazy did not start;
#   dropped 65534:65534; scr and scrd 65534:65534 with the client argument "x" appended.
NATIVE = f'''protocols =
ssl = no
service rawexe {{
  executable = {REC} rawexe a1
  user = nobody
  process_min_avail = 1
}}
service rootexe {{
  executable = {REC} rootexe
  process_min_avail = 1
}}
service internal {{
  executable = {REC} internal
  user = $default_internal_user
  process_min_avail = 1
}}
service lazy {{
  executable = {REC} lazy
  unix_listener lazy {{
    mode = 0666
  }}
}}
service dropped {{
  executable = {REC} dropped
  user = nobody
  drop_priv_before_exec = yes
  process_min_avail = 1
}}
service scr {{
  executable = script {REC} scr
  user = nobody
  unix_listener scr {{
    mode = 0666
  }}
}}
'''

# Ubuntu 24.04 stock dovecot.conf and 10-master.conf, trimmed to their statements.
STOCK = '''!include_try /usr/share/dovecot/protocols.d/*.protocol
dict {
  #quota = mysql:/etc/dovecot/dovecot-dict-sql.conf.ext
}
!include conf.d/*.conf
!include_try local.conf
'''
STOCK_MASTER = '''service imap-login {
  inet_listener imap {
    #port = 143
  }
}
service lmtp {
  unix_listener lmtp {
    #mode = 0666
  }
}
service imap {
}
service auth {
  unix_listener auth-userdb {
  }
}
service auth-worker {
}
service dict {
  unix_listener dict {
  }
}
'''


def _by_name(result):
    return {row['service']: row for row in result['services']}


def _one(text, **extra):
    return ds.evaluate(files={CONF: text}, passwd_text=PASSWD, group_text=GROUP, **extra)


class DovecotServicesTest(unittest.TestCase):
    def test_native_exec_accounts(self):
        result = _one(NATIVE)
        self.assertTrue(result['complete'], result['gaps'])
        rows = _by_name(result)
        self.assertEqual(sorted(rows), ['dropped', 'internal', 'lazy', 'rawexe', 'rootexe', 'scr'])
        for name in ('rawexe', 'rootexe', 'internal'):
            self.assertEqual((rows[name]['exec_uid'], rows[name]['program_account']), (0, 'root'), name)
            self.assertEqual(rows[name]['starts'], 'master_start')
        self.assertEqual(rows['rawexe']['argv'], [REC, 'rawexe', 'a1'])
        self.assertEqual(rows['rawexe']['service_user'], 'nobody')
        self.assertEqual(rows['internal']['service_user'], 'dovecot')
        self.assertEqual(rows['lazy']['starts'], 'on_demand')
        self.assertEqual((rows['dropped']['exec_uid'], rows['dropped']['exec_gid']), (65534, 65534))
        self.assertEqual(rows['dropped']['program_account'], 'nobody')
        scr = rows['scr']
        self.assertEqual(scr['wrapper'], 'script')
        self.assertEqual(scr['program'], '/usr/lib/dovecot/script')
        self.assertEqual(scr['wrapped']['argv'], [REC, 'scr'])
        self.assertTrue(scr['wrapped']['appends_client_arguments'])
        self.assertEqual((scr['exec_uid'], scr['program_account'], scr['program_uid']), (0, 'nobody', 65534))
        root_names = sorted(result['services'][i]['service'] for i in result['root_programs'])
        self.assertEqual(root_names, ['internal', 'lazy', 'rawexe', 'rootexe'])
        codes = [g['code'] for g in result['gaps']]
        self.assertEqual(codes.count('service_user_not_applied'), 2)
        self.assertFalse(result['authorizes_response'])
        self.assertEqual(result['origin'], 'not_assessed')

    def test_stock_ubuntu_reports_nothing(self):
        files = {CONF: STOCK, '/etc/dovecot/conf.d/10-master.conf': STOCK_MASTER, '/etc/dovecot/local.conf': None}
        globs = {'/usr/share/dovecot/protocols.d/*.protocol': [], '/etc/dovecot/conf.d/*.conf':
                 ['/etc/dovecot/conf.d/10-master.conf']}
        result = ds.evaluate(files=files, globs=globs, passwd_text=PASSWD, group_text=GROUP)
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual(result['services'], [])
        self.assertEqual([f['path'] for f in result['files']], [CONF, '/etc/dovecot/conf.d/10-master.conf'])

    def test_drop_in_merges_and_protocol_gating(self):
        files = {
            CONF: STOCK, '/etc/dovecot/local.conf': None,
            '/etc/dovecot/conf.d/10-master.conf': STOCK_MASTER,
            '/etc/dovecot/conf.d/99-x.conf': ('service imap {\n  executable = imap imap-postlogin\n}\n'
                                              'service imap-postlogin {\n  executable = script-login /x/post.sh\n'
                                              '  user = $default_internal_user\n}\n'
                                              'service qw {\n  executable = /x/qw \\\n    --flag\n}\n'
                                              'service qw {\n  process_min_avail = 2\n}\n'),
        }
        globs = {'/usr/share/dovecot/protocols.d/*.protocol': ['/usr/share/dovecot/protocols.d/imapd.protocol'],
                 '/etc/dovecot/conf.d/*.conf': ['/etc/dovecot/conf.d/99-x.conf', '/etc/dovecot/conf.d/10-master.conf']}
        files['/usr/share/dovecot/protocols.d/imapd.protocol'] = 'protocols = $protocols imap\n'
        result = ds.evaluate(files=files, globs=globs, passwd_text=PASSWD, group_text=GROUP)
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual(result['protocols'], ['imap'])
        rows = _by_name(result)
        self.assertEqual(rows['imap']['argv'], ['imap', 'imap-postlogin'])
        self.assertTrue(rows['imap']['enabled'])
        self.assertEqual(rows['imap']['exec_account_basis'], 'dovecot_binary_drops_after_start')
        self.assertEqual(rows['imap-postlogin']['program_account'], 'authenticated_mail_user')
        self.assertEqual(rows['qw']['argv'], ['/x/qw', '--flag'])
        self.assertEqual((rows['qw']['starts'], rows['qw']['process_min_avail']), ('master_start', 2))
        self.assertEqual(rows['qw']['line'], 9)
        self.assertEqual(len(rows['qw']['sections']), 2)
        # Sorted glob order: 10-master.conf is read before 99-x.conf.
        self.assertEqual(result['files'][2]['path'], '/etc/dovecot/conf.d/10-master.conf')

    def test_protocol_disabled_service(self):
        rows = _by_name(_one('service pop3 {\n  executable = /x/pop3\n}\n'))
        self.assertFalse(rows['pop3']['enabled'])
        self.assertEqual(_one('service pop3 {\n  executable = /x/pop3\n}\n')['root_programs'], [])

    def test_parser_rules_match_doveconf(self):
        # doveconf -n: "/x/a#b c" -> "/x/a"; quoted '#' kept; "\\\"" unescaped; single quotes kept verbatim.
        text = ('service a {\n  executable = /x/a#b c\n  user = nobody # y\n}\n'
                'service b {\n  executable = "/x/b # not comment"\n}\n'
                'service "c d" {\n  executable = "/x/q\\"z"\n}\n'
                "service d {\n  executable = '/x/d e'\n  user = $default_login_user\n}\n"
                'service e {\nexecutable=/x/e\nuser\t=\tnobody\n}\n')
        rows = _by_name(_one(text))
        self.assertEqual(rows['a']['executable'], '/x/a')
        self.assertEqual(rows['a']['service_user'], 'nobody')
        self.assertEqual(rows['b']['executable'], '/x/b # not comment')
        self.assertEqual(rows['c d']['executable'], '/x/q"z')
        self.assertEqual(rows['d']['argv'], ['/x/d', 'e'])
        self.assertEqual(rows['d']['service_user'], 'dovenull')
        self.assertEqual(rows['e']['service_user'], 'nobody')

    def test_continuation_rules_match_doveconf(self):
        # Seeded differential (400 configs) against native ``doveconf -h``: a line's comment is
        # removed before the trailing backslash is seen, and an empty or comment-only line
        # discards the pending continuation, so the setting is never assigned.
        rows = _by_name(_one('service s {\n  executable = /x/a c#d \\\n  user = nobody\n}\n'))
        self.assertEqual((rows['s']['executable'], rows['s']['service_user']), ('/x/a c', 'nobody'))
        rows = _by_name(_one('service s {\n  executable = /x/a \\\n  user = nobody # c\n}\n'))
        self.assertEqual((rows['s']['executable'], rows['s']['service_user']), ('/x/a user = nobody', 'root'))
        for middle in ('', '  # c'):
            result = _one(f'service s {{\n  executable = /x/e\\\n{middle}\n  user = nobody\n}}\n')
            self.assertEqual(result['services'], [], middle)
            self.assertTrue(result['complete'])

    def test_blocking_gaps(self):
        cases = {
            'service e {\n  executable = /x/e\n': 'unterminated_section',
            'service {\n  executable = /x/e\n}\n': 'service_missing_name',
            'service e { executable = /x }\n': 'parse_error',
            'protocol imap {\n  service z {\n  }\n}\n': 'service_in_filter',
            '!include missing.conf\n': 'unobserved_file',
            '!include conf.d/*.conf\n': 'unobserved_glob',
            'service c {\n  executable = <exe.txt\n}\n': 'file_value_not_assessed',
            'service c {\n  executable = /x/c\n  user = ghost\n}\n': 'unknown_user',
            'service c {\n  executable = /x/c\x00\n}\n': 'nul_byte',
        }
        for text, code in cases.items():
            result = _one(text)
            self.assertFalse(result['complete'], text)
            self.assertIn(code, [g['code'] for g in result['gaps'] if g['blocking']], text)

    def test_include_no_match_is_fatal_but_try_is_not(self):
        files = {CONF: '!include conf.d/*.conf\n'}
        result = ds.evaluate(files=files, globs={'/etc/dovecot/conf.d/*.conf': []}, passwd_text=PASSWD)
        self.assertEqual(result['config_accepted'], False)
        self.assertIn('include_not_found', [g['code'] for g in result['gaps']])
        files = {CONF: '!include_try conf.d/*.conf\n'}
        result = ds.evaluate(files=files, globs={'/etc/dovecot/conf.d/*.conf': []}, passwd_text=PASSWD)
        self.assertTrue(result['complete'])

    def test_unobserved_config_and_limits(self):
        self.assertFalse(ds.evaluate(files={})['complete'])
        self.assertIn('input_over_limit',
                      [g['code'] for g in _one('#' * (ds.MAX_TEXT + 1))['gaps']])
        loop = {CONF: '!include dovecot.conf\n'}
        self.assertIn('input_over_limit', [g['code'] for g in ds.evaluate(files=loop)['gaps']])

    def test_fingerprint_tracks_account_changes(self):
        a = _one('service q {\n  executable = /x/q\n  user = nobody\n}\n')
        b = _one('service q {\n  executable = /x/q\n  user = nobody\n  drop_priv_before_exec = yes\n}\n')
        self.assertNotEqual(a['service_sha256'], b['service_sha256'])
        self.assertEqual(a['service_sha256'], _one('service q {\n  executable = /x/q\n  user = nobody\n}\n')['service_sha256'])


if __name__ == '__main__':
    unittest.main()
