"""Tests for the pure D-Bus bus-activation contract (#1211).

Expected outcomes were observed on the real dbus-daemon 1.14.10. The
differential at the end re-checks them against a local dbus-daemon when one is
installed and skips otherwise.
"""
import os
import shutil
import subprocess
import tempfile
import time

import pytest

from app import dbus_activation as da

EXEC = 'Exec=/bin/true\n'


def svc(name, extra='', group='[D-BUS Service]'):
    return f'{group}\nName={name}\n{EXEC}{extra}'


def d(path, files, observed=True):
    entries = {}
    for name, value in files.items():
        if isinstance(value, dict):
            entries[name] = value
        else:
            entries[name] = {'kind': 'file', 'text': value}
    return {'path': path, 'observed': observed, 'entries': entries}


def names(result):
    return {n['name']: n['status'] for n in result['names']}


def winner(result, name):
    entry = next(n for n in result['names'] if n['name'] == name)
    return entry.get('directory'), entry.get('file')


def file_status(result):
    return {(f['directory'], f['file']): (f['status'], f.get('reason')) for f in result['files']}


# Parsing vectors: (file text, activatable names) observed on dbus-daemon 1.14.10.
PARSE_VECTORS = {
    'basic': (svc('org.ex.G'), ['org.ex.G']),
    'comments_blank': ('# hi\n[D-BUS Service]\n# c\n\t\n   \nName=org.ex.G\n\n' + EXEC, ['org.ex.G']),
    'no_name': ('[D-BUS Service]\n' + EXEC, []),
    'no_exec_systemd_only': ('[D-BUS Service]\nName=org.ex.F\nSystemdService=x.service\nUser=root\n', []),
    'other_group': ('[Foo]\nName=org.ex.G\n' + EXEC, []),
    'second_group_ignored': (svc('org.ex.G') + '[Other]\nName=org.ex.H\n', ['org.ex.G']),
    'group_case': ('[d-bus service]\nName=org.ex.G\n' + EXEC, []),
    'key_case': ('[D-BUS Service]\nname=org.ex.G\n' + EXEC, []),
    'lead_ws_key': ('[D-BUS Service]\n  Name=org.ex.G\n' + EXEC, []),
    'lead_ws_group': ('  [D-BUS Service]\nName=org.ex.G\n' + EXEC, []),
    'lead_ws_comment': ('  # c\n[D-BUS Service]\nName=org.ex.G\n' + EXEC, []),
    'group_trailing_ws': ('[D-BUS Service]  \nName=org.ex.G\n' + EXEC, []),
    'group_trailing_junk': ('[D-BUS Service]x\nName=org.ex.G\n' + EXEC, []),
    'group_unclosed': (svc('org.ex.G') + '[Bad\n', []),
    'group_bad_chars': (svc('org.ex.G') + '[Bad]Group]\n', []),
    'duplicate_group': ('[D-BUS Service]\nName=org.ex.G\n[D-BUS Service]\n' + EXEC, []),
    'key_before_group': ('Name=org.ex.G\n[D-BUS Service]\n' + EXEC, []),
    'space_before_eq': ('[D-BUS Service]\nName =org.ex.G\n' + EXEC, ['org.ex.G']),
    'space_after_eq': ('[D-BUS Service]\nName= org.ex.G\n' + EXEC, ['org.ex.G']),
    'trailing_space_kept': ('[D-BUS Service]\nName=org.ex.G  \n' + EXEC, ['org.ex.G  ']),
    'tab_before_eq': ('[D-BUS Service]\nName\t=org.ex.G\n' + EXEC, []),
    'underscore_key': (svc('org.ex.G', 'Foo_Bar=1\n'), []),
    'dash_digit_keys': (svc('org.ex.G', 'Foo-Bar=1\nFoo1=1\nX-Foo=1\n'), ['org.ex.G']),
    'empty_key': (svc('org.ex.G', '=1\n'), []),
    'junk_line': (svc('org.ex.G', 'this is junk\n'), []),
    'duplicate_name_first_wins': ('[D-BUS Service]\nName=org.ex.G\nName=org.ex.H\n' + EXEC, ['org.ex.G']),
    'locale_key_ignored': ('[D-BUS Service]\nName[en]=org.ex.Z\nName=org.ex.G\n' + EXEC, ['org.ex.G']),
    'locale_only': ('[D-BUS Service]\nName[en]=org.ex.Z\n' + EXEC, []),
    'locale_unclosed': (svc('org.ex.G', 'Foo[en=1\n'), ['org.ex.G']),
    'empty_name': ('[D-BUS Service]\nName=\n' + EXEC, ['']),
    'empty_exec': ('[D-BUS Service]\nName=org.ex.G\nExec=\n', ['org.ex.G']),
    'unvalidated_names': (svc('noperiod'), ['noperiod']),
    'escape_space': ('[D-BUS Service]\nName=org.ex\\sG\n' + EXEC, ['org.ex G']),
    'escape_bad': ('[D-BUS Service]\nName=org.ex.G\nExec=/bin/a\\qb\n', []),
    'trailing_backslash': ('[D-BUS Service]\nName=org.ex.G\\\n' + EXEC, []),
    'crlf': ('[D-BUS Service]\r\nName=org.ex.G\r\nExec=/bin/true\r\n', ['org.ex.G']),
    'bare_cr_splits_line': ('[D-BUS Service]\nName=org.ex\rG\n' + EXEC, []),
    'no_trailing_newline': ('[D-BUS Service]\n' + EXEC + 'Name=org.ex.G', ['org.ex.G']),
    'empty_file': ('', []),
    'invalid_utf8': (b'[D-BUS Service]\nName=org.ex.G\nExec=/bin/\xff\n', []),
    'invalid_utf8_comment': (b'# \xff\n[D-BUS Service]\nName=org.ex.G\nExec=/bin/true\n', []),
    'nul': (b'[D-BUS Service]\nName=org.ex.G\nExec=/bin/tr\x00ue\n', []),
}


@pytest.mark.parametrize('case', sorted(PARSE_VECTORS))
def test_parse_vectors(case):
    text, expected = PARSE_VECTORS[case]
    result = da.resolve([d('/usr/share/dbus-1/system-services', {'g.service': text})])
    assert sorted(names(result)) == sorted(expected)
    assert result['complete'] is True


def test_declared_fields_and_escapes():
    text = ('[D-BUS Service]\nName=org.ex.G\nExec=/usr/lib/x --flag a\\sb\nUser=root\n'
            'SystemdService=dbus-org.ex.G.service\nExec=/bin/ignored\n')
    result = da.resolve([d('/s', {'org.ex.G.service': text})])
    entry = result['names'][0]
    assert entry['status'] == 'activatable'
    assert entry['declared'] == {'Name': 'org.ex.G', 'Exec': '/usr/lib/x --flag a b', 'User': 'root',
                                 'SystemdService': 'dbus-org.ex.G.service'}
    assert entry['origin'] == 'not_assessed'
    assert result['verdict'] is None


def test_rejection_reasons():
    result = da.resolve([d('/s', {
        'a.service': svc('org.ex.A', 'junk\n'),
        'b.service': '[D-BUS Service]\nName=org.ex.B\n',
        'c.service': b'\xff',
    })])
    status = file_status(result)
    assert status[('/s', 'a.service')] == ('rejected', 'invalid_key')
    assert status[('/s', 'b.service')] == ('skipped_incomplete', None)
    assert status[('/s', 'c.service')] == ('rejected', 'invalid_utf8')


def test_suffix_and_non_files():
    result = da.resolve([d('/s', {
        'org.ex.E.conf': svc('org.ex.E'),
        'org.ex.G.SERVICE': svc('org.ex.G'),
        '.service': svc('org.ex.H'),
        '.hid.service': svc('org.ex.I'),
        'sub.service': {'kind': 'dir'},
        'gone.service': {'kind': 'dangling'},
    })])
    assert names(result) == {'org.ex.H': 'activatable', 'org.ex.I': 'activatable'}
    status = file_status(result)
    assert status[('/s', 'org.ex.E.conf')][0] == 'not_service'
    assert status[('/s', 'sub.service')][0] == 'skipped_non_file'
    assert status[('/s', 'gone.service')][0] == 'skipped_non_file'
    assert result['complete'] is True


def test_first_directory_wins_regardless_of_file_name():
    result = da.resolve([d('/a', {'x.service': svc('org.ex.A')}),
                         d('/b', {'org.ex.A.service': svc('org.ex.A')})])
    assert winner(result, 'org.ex.A') == ('/a', 'x.service')
    status = file_status(result)
    assert status[('/b', 'org.ex.A.service')][0] == 'shadowed'


def test_exact_file_name_wins_within_directory():
    result = da.resolve([d('/a', {'a.service': svc('org.ex.A'), 'z.service': svc('org.ex.A'),
                                  'org.ex.A.service': svc('org.ex.A')})])
    assert winner(result, 'org.ex.A') == ('/a', 'org.ex.A.service')


def test_non_exact_duplicates_in_one_directory_are_ambiguous():
    result = da.resolve([d('/a', {'a.service': svc('org.ex.A'), 'z.service': svc('org.ex.A')}),
                         d('/b', {'org.ex.A.service': svc('org.ex.A')})])
    assert names(result) == {'org.ex.A': 'ambiguous'}
    status = file_status(result)
    assert status[('/a', 'a.service')] == ('ambiguous', 'readdir_order_unspecified')
    assert status[('/b', 'org.ex.A.service')][0] == 'shadowed'


def test_unobserved_inputs_fail_closed():
    later = da.resolve([d('/a', {}, observed=False), d('/b', {'org.ex.A.service': svc('org.ex.A')})])
    assert names(later) == {'org.ex.A': 'unresolved'}
    assert later['complete'] is False
    earlier = da.resolve([d('/a', {'org.ex.A.service': svc('org.ex.A')}), d('/b', {}, observed=False)])
    assert names(earlier) == {'org.ex.A': 'activatable'}
    assert earlier['complete'] is False
    missing_text = da.resolve([d('/a', {'x.service': {'kind': 'file', 'text': None}}),
                               d('/b', {'org.ex.B.service': svc('org.ex.B')})])
    assert names(missing_text) == {'org.ex.B': 'unresolved'}
    assert file_status(missing_text)[('/a', 'x.service')] == ('unresolved', 'text_not_observed')
    big = da.resolve([d('/a', {'x.service': 'x' * (da.MAX_TEXT + 1)})])
    assert big['complete'] is False
    assert file_status(big)[('/a', 'x.service')] == ('unresolved', 'text_over_limit')


# --- Differential against a local dbus-daemon -------------------------------------------------

DAEMON = shutil.which('dbus-daemon')
SEND = shutil.which('dbus-send')


def _bus_names(tmp, dirs):
    sock = os.path.join(tmp, 'sock')
    conf = os.path.join(tmp, 'bus.conf')
    with open(conf, 'w', encoding='utf-8') as fh:
        fh.write(f'<busconfig><type>session</type><listen>unix:path={sock}</listen><auth>EXTERNAL</auth>'
                 '<policy context="default"><allow send_destination="*" eavesdrop="true"/>'
                 '<allow eavesdrop="true"/><allow own="*"/><allow user="*"/></policy>'
                 + ''.join(f'<servicedir>{x}</servicedir>' for x in dirs) + '</busconfig>')
    proc = subprocess.Popen([DAEMON, f'--config-file={conf}', '--nofork', '--nopidfile'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.05)
        reply = subprocess.run([SEND, f'--bus=unix:path={sock}', '--print-reply', '--reply-timeout=3000',
                                '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus',
                                'org.freedesktop.DBus.ListActivatableNames'],
                               capture_output=True, text=True, timeout=10, check=True).stdout
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    found = [line.lstrip()[8:-1] for line in reply.splitlines() if line.lstrip().startswith('string "')]
    return sorted(n for n in found if n != 'org.freedesktop.DBus')


@pytest.mark.skipif(not (DAEMON and SEND), reason='dbus-daemon not installed')
@pytest.mark.parametrize('case', sorted(PARSE_VECTORS))
def test_differential_against_dbus_daemon(case):
    text, _expected = PARSE_VECTORS[case]
    raw = text if isinstance(text, bytes) else text.encode()
    with tempfile.TemporaryDirectory() as tmp:
        sdir = os.path.join(tmp, 'services')
        os.mkdir(sdir)
        with open(os.path.join(sdir, 'g.service'), 'wb') as fh:
            fh.write(raw)
        try:
            observed = _bus_names(tmp, [sdir])
        except (subprocess.SubprocessError, OSError) as exc:  # pragma: no cover - sandbox dependent
            pytest.skip(f'dbus-daemon unavailable here: {exc}')
    contract = sorted(names(da.resolve([d(sdir, {'g.service': raw})])))
    # dbus-send prints a value up to its first newline; compare that view.
    assert observed == sorted(n.split('\n')[0] for n in contract)
