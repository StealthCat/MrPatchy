"""Tests for the pure CUPS backend contract (roadmap F slice, #1532)."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import cups_backends as cb  # noqa: E402

PASSWD = 'root:x:0:0:root:/root:/bin/bash\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n' \
         'svc:x:990:990::/:/usr/sbin/nologin\nalias0:x:0:0::/:/bin/sh\n'
GROUP = 'root:x:0:\nlp:x:7:\nsvc:x:990:\nnobody:x:65534:\n'
BACKEND_DIR = {'mode': 0o040755, 'uid': 0}


def meta(**backends):
    result = {'/usr/lib/cups/backend': BACKEND_DIR}
    for name, mode in backends.items():
        result[f'/usr/lib/cups/backend/{name}'] = None if mode is None else {'mode': mode, 'uid': 0}
    return result


def run(printers, files=None, **kwargs):
    kwargs.setdefault('passwd_text', PASSWD)
    kwargs.setdefault('group_text', GROUP)
    return cb.evaluate(printers_conf=printers, cups_files_conf=files, **kwargs)


def by_name(result):
    return {row['printer']: row for row in result['backends']}


def codes(result):
    return [gap['code'] for gap in result['gaps']]


# printers.conf exactly as written before a native run of Ubuntu 24.04
# cups-daemon 2.4.7-1.2ubuntu7.14 (cupsd -f as root, default cups-files.conf).
# Each backend recorded its uid/gid; a compiled backend recorded argv[0].
NATIVE_PRINTERS = """# test
<Printer rootq>
DeviceURI probe://alice:secret@host.example/queue#frag
State Idle
Accepting Yes
</Printer>
<Printer userq>
  deviceuri   probeuser:/plain   # trailing comment
State Idle
Accepting Yes
</Printer>
<Printer gwq>
DeviceURI probegw:/x
State Idle
Accepting Yes
</Printer>
<Printer oxq>
DeviceURI probeox:/x\\#notcomment
State Idle
Accepting Yes
</Printer>
<Printer readq>
DeviceURI proberead:/x
State Idle
Accepting Yes
</Printer>
<Printer missq>
DeviceURI nosuchbackend:/x
State Idle
Accepting Yes
</Printer>
<Printer argvq>
DeviceURI argvprobe://bob:pw@printer.example:631/ipp/print?x=1
State Idle
</Printer>
"""
NATIVE_META = meta(probe=0o100700, probeuser=0o100755, probegw=0o100775, probeox=0o100705,
                   proberead=0o100744, argvprobe=0o100700, nosuchbackend=None)


class NativeRunTest(unittest.TestCase):
    def test_matches_native_cupsd_2_4_7_run(self):
        result = run(NATIVE_PRINTERS, file_meta=NATIVE_META)
        self.assertTrue(result['complete'], result['gaps'])
        rows = by_name(result)
        # Observed: probe and proberead ran as uid 0 gid 7; probeuser and
        # probeox ran as lp (7/7); probegw was refused with "insecure
        # permissions (0100775/uid=0/gid=0)"; missq was stopped with
        # "Backend /usr/lib/cups/backend/nosuchbackend does not exist!".
        observed = {
            'rootq': (True, 'root', 0), 'readq': (True, 'root', 0), 'argvq': (True, 'root', 0),
            'userq': (False, 'lp', 7), 'oxq': (False, 'lp', 7),
        }
        for name, (root, user, uid) in observed.items():
            self.assertEqual((rows[name]['runs_as_root'], rows[name]['run_user'], rows[name]['run_uid']),
                             (root, user, uid), name)
            self.assertEqual(rows[name]['run_gid'], 7)
            self.assertTrue(rows[name]['runs_backend'])
        self.assertEqual(rows['gwq']['file_check'], 'insecure_permissions')
        self.assertFalse(rows['gwq']['runs_backend'])
        self.assertEqual((rows['missq']['state'], rows['missq']['file_check']), ('stopped', 'missing'))
        self.assertEqual(sorted(result['root_backends']), ['argvq', 'readq', 'rootq'])
        # DEVICE_URI was "probe://alice:secret@host.example/queue": "#frag" is a comment.
        self.assertEqual(rows['rootq']['argv0'], 'probe://host.example/queue')
        self.assertTrue(rows['rootq']['uri_has_credentials'])
        # Observed argv[0] of the compiled backend.
        self.assertEqual(rows['argvq']['argv0'], 'argvprobe://printer.example:631/ipp/print?x=1')
        # DEVICE_URI was "probeox:/x#notcomment" and "probeuser:/plain".
        self.assertEqual(rows['oxq']['argv0'], 'probeox:/x#notcomment')
        self.assertEqual(rows['userq']['argv0'], 'probeuser:/plain')
        self.assertEqual(rows['userq']['executable'], '/usr/lib/cups/backend/probeuser')
        self.assertFalse(result['authorizes_response'])
        self.assertEqual(result['origin'], 'not_assessed')


class LineReadingTest(unittest.TestCase):
    def test_only_first_hash_is_considered(self):
        self.assertEqual(cb.parse_conf_line(r'DeviceURI a:\#b #c'), ('DeviceURI', 'a:#b #c'))
        self.assertEqual(cb.parse_conf_line('DeviceURI a:b\t# c'), ('DeviceURI', 'a:b'))
        self.assertIsNone(cb.parse_conf_line('   # only a comment'))
        self.assertEqual(cb.parse_conf_line('#\\# x'), None)

    def test_section_lines_need_closing_bracket(self):
        self.assertEqual(cb.parse_conf_line('<Printer  q1 >'), ('<Printer', 'q1'))
        self.assertEqual(cb.parse_conf_line('<Printer q1'), ('<Printer', None))
        self.assertEqual(cb.parse_conf_line('</Printer>   '), ('</Printer>', None))

    def test_cr_ends_a_line(self):
        result = run('<Printer q>\rDeviceURI x:/a\r\nState Stopped\r</Printer>\n', file_meta=meta(x=0o100700))
        row = by_name(result)['q']
        self.assertEqual((row['executable'], row['state'], row['runs_as_root']),
                         ('/usr/lib/cups/backend/x', 'stopped', True))

    def test_overlong_line_and_nul_block(self):
        long_line = 'DeviceURI x:/' + 'a' * 4090
        result = run(f'<Printer q>\n{long_line}\n</Printer>\n', file_meta=meta(x=0o100700))
        self.assertIn('line_too_long', codes(result))
        self.assertFalse(result['complete'])
        result = run('<Printer q>\nDeviceURI x:/a\0b\n</Printer>\n', file_meta=meta(x=0o100700))
        self.assertIn('file_invalid', codes(result))
        self.assertFalse(result['complete'])


class PrintersConfTest(unittest.TestCase):
    def test_last_device_uri_wins_and_directives_are_case_insensitive(self):
        text = '<DefaultPrinter q>\nDEVICEURI a:/1\ndeviceuri b:/2\nState stopped\n</defaultprinter>\n'
        row = by_name(run(text, file_meta=meta(a=0o100755, b=0o100755)))['q']
        self.assertEqual((row['executable'], row['default'], row['state'], row['device_uri_line']),
                         ('/usr/lib/cups/backend/b', True, 'stopped', 3))

    def test_queue_without_device_uri_writes_to_dev_null(self):
        row = by_name(run('<Printer q>\n</Printer>\n'))['q']
        self.assertEqual((row['file_check'], row['runs_backend'], row['argv0']),
                         ('file_device_no_backend', False, 'file:///dev/null'))

    def test_nested_and_stray_sections_are_syntax_errors(self):
        text = ('DeviceURI stray:/x\n<Printer a>\n<Printer b>\nDeviceURI x:/1\n</Printer>\n</Printer>\n'
                '<Printer c\nDeviceURI y:/2\n</Printer>\n')
        result = run(text, file_meta=meta(x=0o100700))
        self.assertEqual(list(by_name(result)), ['a'])
        self.assertEqual(by_name(result)['a']['executable'], '/usr/lib/cups/backend/x')
        self.assertEqual(len(result['notes']), 6)
        self.assertTrue(result['complete'])

    def test_duplicate_and_unterminated_queues_block(self):
        result = run('<Printer q>\n</Printer>\n<Printer q>\n</Printer>\n<Printer r>\nDeviceURI x:/\n')
        self.assertIn('duplicate_printer_name', codes(result))
        self.assertIn('printer_unterminated', codes(result))
        self.assertFalse(result['complete'])

    def test_schemes_cupsd_cannot_map_block(self):
        for uri, code in ((':/x', 'scheme_empty'), ('a/b:/x', 'scheme_contains_slash'),
                          ('s' * 255 + ':/x', 'scheme_too_long')):
            result = run(f'<Printer q>\nDeviceURI {uri}\n</Printer>\n', file_meta=meta())
            self.assertIn(code, codes(result), uri)
            self.assertFalse(result['complete'])
        # A URI with no colon names the backend by the whole string.
        row = by_name(run('<Printer q>\nDeviceURI plain\n</Printer>\n', file_meta=meta(plain=0o100700)))['q']
        self.assertEqual(row['executable'], '/usr/lib/cups/backend/plain')

    def test_credentials_are_removed_only_before_the_resource(self):
        self.assertEqual(cb.sanitize_device_uri('smb://u:p@host/share'), 'smb://host/share')
        self.assertEqual(cb.sanitize_device_uri('lpd://host/q@x'), 'lpd://host/q@x')
        self.assertEqual(cb.sanitize_device_uri('socket:u@host'), 'socket:host')
        self.assertEqual(cb.sanitize_device_uri('nocolon@x'), 'nocolon@x')


class RunAsTest(unittest.TestCase):
    def test_permission_bits_decide_root(self):
        cases = {'root_0700': (0o100700, 'ok', True), 'root_0744': (0o100744, 'ok', True),
                 'root_0750': (0o100750, 'ok', True), 'lp_0711': (0o100711, 'ok', False),
                 'gw_0770': (0o100770, 'insecure_permissions', False),
                 'ow_0702': (0o100702, 'insecure_permissions', False),
                 'suid_4700': (0o104700, 'insecure_permissions', False),
                 'dir_entry': (0o040700, 'wrong_type', False)}
        text = ''.join(f'<Printer {n}>\nDeviceURI {n}:/x\n</Printer>\n' for n in cases)
        rows = by_name(run(text, file_meta=meta(**{n: m for n, (m, _, _) in cases.items()})))
        for name, (_, check, root) in cases.items():
            self.assertEqual((rows[name]['file_check'], rows[name]['runs_as_root']), (check, root), name)

    def test_backend_must_be_owned_by_root_and_directory_checked(self):
        files = meta(x=0o100700)
        files['/usr/lib/cups/backend/x'] = {'mode': 0o100700, 'uid': 7}
        row = by_name(run('<Printer q>\nDeviceURI x:/\n</Printer>\n', file_meta=files))['q']
        self.assertEqual(row['file_check'], 'insecure_permissions')
        files = meta(x=0o100700)
        files['/usr/lib/cups/backend'] = {'mode': 0o040777, 'uid': 0}
        row = by_name(run('<Printer q>\nDeviceURI x:/\n</Printer>\n', file_meta=files))['q']
        self.assertEqual((row['file_check'], row['runs_backend']), ('directory_insecure_permissions', False))

    def test_unobserved_metadata_blocks(self):
        result = run('<Printer q>\nDeviceURI x:/\n</Printer>\n', file_meta={})
        self.assertIn('metadata_unobserved', codes(result))
        self.assertFalse(result['complete'])
        self.assertIsNone(by_name(result)['q']['file_check'])

    def test_non_root_cupsd_runs_everything_as_itself_without_root_checks(self):
        files = meta(x=0o100777)
        row = by_name(run('<Printer q>\nDeviceURI x:/\n</Printer>\n', file_meta=files, cupsd_uid=990))['q']
        self.assertEqual((row['file_check'], row['runs_as_root'], row['run_uid']), ('ok', False, 990))


class CupsFilesConfTest(unittest.TestCase):
    PRINTER = '<Printer q>\nDeviceURI x:/\n</Printer>\n'

    def test_user_group_and_relative_server_bin(self):
        files = {'/etc/cups/alt': {'mode': 0o040755, 'uid': 0}, '/etc/cups/alt/backend': BACKEND_DIR,
                 '/etc/cups/alt/backend/x': {'mode': 0o100755, 'uid': 0}}
        result = run(self.PRINTER, 'user svc\nGROUP 990\nServerBin alt # comment\n', file_meta=files)
        row = by_name(result)['q']
        self.assertTrue(result['complete'], result['gaps'])
        self.assertEqual(row['executable'], '/etc/cups/alt/backend/x')
        self.assertEqual((row['run_user'], row['run_uid'], row['run_group'], row['run_gid']),
                         ('svc', 990, 'svc', 990))

    def test_root_user_and_unknown_accounts_are_refused(self):
        for text, code in (('User 0\n', 'user_root_refused'), ('User alias0\n', 'user_root_refused'),
                           ('User nosuch\n', 'user_unknown'), ('Group nosuch\n', 'group_unknown'),
                           ('User 12abc\n', 'user_value_not_modelled'), ('User\n', 'cups_files_value_missing')):
            result = run(self.PRINTER, text, file_meta=meta(x=0o100755))
            self.assertIn(code, codes(result), text)
            self.assertFalse(result['complete'])
            self.assertEqual(by_name(result)['q']['run_uid'], 7, text)

    def test_missing_server_bin_is_not_applied_and_server_root_blocks(self):
        files = meta(x=0o100700)
        files['/opt/none'] = None
        result = run(self.PRINTER, 'ServerBin /opt/none\nServerRoot /srv/cups\n', file_meta=files)
        self.assertEqual(by_name(result)['q']['executable'], '/usr/lib/cups/backend/x')
        self.assertIn('server_bin_missing', codes(result))
        self.assertIn('server_root_relocated', codes(result))
        self.assertFalse(result['complete'])

    def test_default_accounts_fall_back_like_cupsd(self):
        result = run(self.PRINTER, None, file_meta=meta(x=0o100755), passwd_text='root:x:0:0::/:/bin/sh\n',
                     group_text='root:x:0:\nnobody:x:65534:\n')
        row = by_name(result)['q']
        self.assertEqual((row['run_uid'], row['run_group'], row['run_gid']), (65534, 'nobody', 65534))

    def test_missing_account_databases_block_only_when_needed(self):
        result = cb.evaluate(printers_conf=self.PRINTER, file_meta=meta(x=0o100755))
        self.assertIn('run_account_unresolved', codes(result))
        self.assertFalse(result['complete'])
        self.assertEqual(by_name(result)['q']['run_user'], 'lp')


if __name__ == '__main__':
    unittest.main()
