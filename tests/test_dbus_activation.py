"""Tests for the pure D-Bus bus-activation contract (#1211).

Expected outcomes were observed on the real dbus-daemon 1.14.10. The
differential at the end re-checks them against a local dbus-daemon when one is
installed and skips otherwise.
"""
import os
import pwd
import re
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


# --- Start path: bus type, systemd activation and the system-bus launch helper ----------------

def start(result, name):
    return next(n for n in result['names'] if n['name'] == name)['start']


def test_bus_type_required_for_start_and_validated():
    result = da.resolve([d('/s', {'org.ex.A.service': svc('org.ex.A')})])
    assert start(result, 'org.ex.A') == {'status': 'not_determined', 'reason': 'bus_type_not_supplied'}
    assert result['bus'] is None
    with pytest.raises(ValueError):
        da.resolve([], bus='user')


def test_session_bus_runs_exec_as_bus_user_without_user_key():
    result = da.resolve([d('/s', {'x.service': svc('org.ex.A')})], bus='session', systemd_activation=False)
    assert start(result, 'org.ex.A') == {'status': 'starts', 'via': 'exec', 'run_as': 'bus_user',
                                         'exec': '/bin/true', 'directory': '/s', 'file': 'x.service'}


def test_system_bus_daemon_refuses_winner_without_user():
    result = da.resolve([d('/s', {'org.ex.A.service': svc('org.ex.A')})], bus='system', systemd_activation=False)
    assert start(result, 'org.ex.A') == {'status': 'refused', 'by': 'dbus-daemon', 'reason': 'user_missing'}
    # The name is still listed as activatable: ListActivatableNames does not apply the check.
    assert names(result) == {'org.ex.A': 'activatable'}


def test_system_bus_helper_runs_exact_file_as_first_user():
    result = da.resolve([d('/s', {'org.ex.A.service': svc('org.ex.A', 'User=root\nUser=nobody\n')})],
                        bus='system', systemd_activation=False)
    assert start(result, 'org.ex.A') == {'status': 'starts', 'via': 'launch_helper', 'run_as': 'root',
                                         'exec': '/bin/true', 'user_resolution': 'not_assessed',
                                         'directory': '/s', 'file': 'org.ex.A.service'}


def test_system_bus_empty_user_passes_daemon_and_reaches_helper():
    result = da.resolve([d('/s', {'org.ex.A.service': svc('org.ex.A', 'User=\n')})], bus='system',
                        systemd_activation=False)
    assert start(result, 'org.ex.A')['run_as'] == ''


def test_system_bus_non_exact_winner_starts_later_exact_file():
    result = da.resolve([d('/a', {'other.service': svc('org.ex.A', 'User=root\n')}),
                         d('/b', {'org.ex.A.service': svc('org.ex.A', 'User=nobody\n')})],
                        bus='system', systemd_activation=False)
    assert winner(result, 'org.ex.A') == ('/a', 'other.service')
    got = start(result, 'org.ex.A')
    assert (got['status'], got['directory'], got['file'], got['run_as']) == (
        'starts', '/b', 'org.ex.A.service', 'nobody')


def test_system_bus_non_exact_winner_without_exact_file_is_refused():
    result = da.resolve([d('/a', {'other.service': svc('org.ex.A', 'User=root\n')})], bus='system',
                        systemd_activation=False)
    assert start(result, 'org.ex.A') == {'status': 'refused', 'by': 'launch_helper',
                                         'reason': 'helper_file_not_found', 'file': 'org.ex.A.service'}


def test_system_bus_helper_takes_first_parsing_exact_file():
    mismatch = da.resolve([d('/a', {'org.ex.A.service': svc('org.ex.Other', 'User=root\n')}),
                           d('/b', {'org.ex.A.service': svc('org.ex.A', 'User=root\n')})],
                          bus='system', systemd_activation=False)
    assert winner(mismatch, 'org.ex.A') == ('/b', 'org.ex.A.service')
    assert start(mismatch, 'org.ex.A')['reason'] == 'helper_name_mismatch'
    assert start(mismatch, 'org.ex.A')['directory'] == '/a'
    no_exec = da.resolve([d('/a', {'org.ex.A.service': '[D-BUS Service]\nName=org.ex.A\nUser=root\n'}),
                          d('/b', {'org.ex.A.service': svc('org.ex.A', 'User=root\n')})],
                         bus='system', systemd_activation=False)
    assert start(no_exec, 'org.ex.A')['reason'] == 'helper_exec_missing'
    no_user = da.resolve([d('/a', {'other.service': svc('org.ex.A', 'User=root\n')}),
                          d('/b', {'org.ex.A.service': svc('org.ex.A')})],
                         bus='system', systemd_activation=False)
    assert start(no_user, 'org.ex.A')['reason'] == 'helper_user_missing'
    rejected = da.resolve([d('/a', {'org.ex.A.service': svc('org.ex.A', 'User=root\njunk\n')}),
                           d('/b', {'org.ex.A.service': svc('org.ex.A', 'User=root\n')})],
                          bus='system', systemd_activation=False)
    assert start(rejected, 'org.ex.A')['status'] == 'starts'
    assert start(rejected, 'org.ex.A')['directory'] == '/b'


def test_system_bus_helper_lookup_fails_closed():
    unobserved = da.resolve([d('/a', {'other.service': svc('org.ex.A', 'User=root\n')}),
                             d('/b', {}, observed=False)], bus='system', systemd_activation=False)
    assert names(unobserved) == {'org.ex.A': 'activatable'}
    assert start(unobserved, 'org.ex.A') == {'status': 'unresolved', 'reason': 'helper_directory_not_observed'}
    text_missing = da.resolve([d('/a', {'other.service': svc('org.ex.A', 'User=root\n')}),
                               d('/b', {'org.ex.A.service': {'kind': 'file', 'text': None}})],
                              bus='system', systemd_activation=False)
    assert start(text_missing, 'org.ex.A')['reason'] == 'helper_file_not_observed'
    odd = da.resolve([d('/a', {'other.service': svc('org.ex.A', 'User=root\n'),
                               'org.ex.A.service': {'kind': 'dangling'}})], bus='system', systemd_activation=False)
    assert start(odd, 'org.ex.A')['status'] == 'unresolved'
    many = [d(f'/x{i}', {}) for i in range(da.MAX_DIRECTORIES - 1)]
    many += [d('/a', {'other.service': svc('org.ex.A', 'User=root\n')}), d('/late', {})]
    assert start(da.resolve(many, bus='system', systemd_activation=False), 'org.ex.A')['status'] == 'unresolved'


def test_systemd_activation_hands_off_systemd_service_without_user():
    text = svc('org.ex.A', 'SystemdService=a.service\n')
    on = da.resolve([d('/s', {'org.ex.A.service': text})], bus='system', systemd_activation=True)
    assert start(on, 'org.ex.A') == {'status': 'starts', 'via': 'systemd', 'unit': 'a.service'}
    off = da.resolve([d('/s', {'org.ex.A.service': text})], bus='system', systemd_activation=False)
    assert start(off, 'org.ex.A') == {'status': 'refused', 'by': 'dbus-daemon', 'reason': 'user_missing'}
    unknown = da.resolve([d('/s', {'org.ex.A.service': text})], bus='system')
    assert start(unknown, 'org.ex.A') == {'status': 'unresolved', 'reason': 'systemd_activation_not_observed'}
    plain = da.resolve([d('/s', {'org.ex.B.service': svc('org.ex.B', 'User=root\n')})], bus='system',
                       systemd_activation=True)
    assert start(plain, 'org.ex.B')['via'] == 'launch_helper'


def test_start_not_determined_for_ambiguous_names():
    result = da.resolve([d('/a', {'a.service': svc('org.ex.A', 'User=root\n'),
                                  'z.service': svc('org.ex.A', 'User=root\n')})], bus='system',
                        systemd_activation=False)
    assert start(result, 'org.ex.A') == {'status': 'not_determined', 'reason': 'name_ambiguous'}


# --- System-bus differential --------------------------------------------------------------------
# The setuid launch helper ignores the bus configuration: it reads the system bus configuration and
# searches the standard system service directories, and it only runs for the configured bus user. A
# faithful differential therefore writes uniquely named files into two of those real directories, so
# it runs only as root and only when explicitly enabled (MRPATCHY_DBUS_SYSTEM_DIFFERENTIAL=1).

HELPER = '/usr/lib/dbus-1.0/dbus-daemon-launch-helper'
SYSTEM_DIRS = ('/usr/local/share/dbus-1/system-services', '/usr/share/dbus-1/system-services')


def _system_differential_available():
    if os.environ.get('MRPATCHY_DBUS_SYSTEM_DIFFERENTIAL') != '1':
        return False
    if not (DAEMON and SEND and os.path.exists(HELPER) and hasattr(os, 'geteuid') and os.geteuid() == 0):
        return False
    try:
        pwd.getpwnam('messagebus')
    except KeyError:
        return False
    return True


def _exec_line(marks, tag):
    return f'Exec=/bin/sh -c "id -un > {marks}/{tag}"\n'


def _system_scenarios(prefix):
    # (requested name, {(dir_index, filename): text with {X:tag} exec placeholders}, systemd_activation)
    def n(s):
        return f'{prefix}.{s}'

    return {
        'exact_root': (n('A'), {(1, n('A') + '.service'): ('[D-BUS Service]\nName=' + n('A') + '\n{X:A}User=root\n')}),
        'no_user': (n('B'), {(1, n('B') + '.service'): ('[D-BUS Service]\nName=' + n('B') + '\n{X:B}')}),
        'non_exact_only': (n('C'), {(1, 'x' + n('C') + '.service'):
                                    ('[D-BUS Service]\nName=' + n('C') + '\n{X:C}User=root\n')}),
        'non_exact_then_exact': (n('D'), {
            (0, 'x' + n('D') + '.service'): '[D-BUS Service]\nName=' + n('D') + '\n{X:D1}User=root\n',
            (1, n('D') + '.service'): '[D-BUS Service]\nName=' + n('D') + '\n{X:D2}User=root\n'}),
        'exact_name_mismatch': (n('E'), {
            (0, n('E') + '.service'): '[D-BUS Service]\nName=' + n('E') + 'x\n{X:E1}User=root\n',
            (1, n('E') + '.service'): '[D-BUS Service]\nName=' + n('E') + '\n{X:E2}User=root\n'}),
        'exact_rejected_then_valid': (n('K'), {
            (0, n('K') + '.service'): '[D-BUS Service]\nName=' + n('K') + '\n{X:K1}User=root\njunk\n',
            (1, n('K') + '.service'): '[D-BUS Service]\nName=' + n('K') + '\n{X:K2}User=root\n'}),
        'exact_no_exec_then_valid': (n('L'), {
            (0, n('L') + '.service'): '[D-BUS Service]\nName=' + n('L') + '\nUser=root\n',
            (1, n('L') + '.service'): '[D-BUS Service]\nName=' + n('L') + '\n{X:L2}User=root\n'}),
        'helper_exact_without_user': (n('M'), {
            (0, 'x' + n('M') + '.service'): '[D-BUS Service]\nName=' + n('M') + '\n{X:M1}User=root\n',
            (1, n('M') + '.service'): '[D-BUS Service]\nName=' + n('M') + '\n{X:M2}'}),
        'first_user_wins': (n('I'), {(1, n('I') + '.service'):
                                     '[D-BUS Service]\nName=' + n('I') + '\n{X:I}User=root\nUser=nobody\n'}),
        'systemd_service_ignored': (n('H'), {(1, n('H') + '.service'):
                                             '[D-BUS Service]\nName=' + n('H') + '\n{X:H}User=root\nSystemdService=h.service\n'}),
    }


def _render(text, marks):
    return re.sub(r'\{X:([A-Za-z0-9]+)\}', lambda m: _exec_line(marks, m.group(1)), text)


@pytest.mark.skipif(not _system_differential_available(),
                    reason='system-bus differential needs root, the launch helper and MRPATCHY_DBUS_SYSTEM_DIFFERENTIAL=1')
def test_system_bus_differential_against_launch_helper():
    prefix = f'org.mrpatchy.difftest.p{os.getpid()}'
    scenarios = _system_scenarios(prefix)
    written = []
    with tempfile.TemporaryDirectory() as tmp:
        marks = os.path.join(tmp, 'marks')
        os.mkdir(marks, 0o700)
        try:
            for path in SYSTEM_DIRS:
                os.makedirs(path, exist_ok=True)
            for _name, files in scenarios.values():
                for (index, filename), text in files.items():
                    target = os.path.join(SYSTEM_DIRS[index], filename)
                    with open(target, 'w', encoding='utf-8') as fh:
                        fh.write(_render(text, marks))
                    written.append(target)
            sock = os.path.join(tmp, 'sock')
            conf = os.path.join(tmp, 'bus.conf')
            with open(conf, 'w', encoding='utf-8') as fh:
                fh.write(f'<busconfig><type>system</type><user>messagebus</user>'
                         f'<listen>unix:path={sock}</listen><auth>EXTERNAL</auth>'
                         f'<servicehelper>{HELPER}</servicehelper>'
                         '<policy context="default"><allow send_destination="*"/><allow own="*"/>'
                         '<allow user="*"/><allow receive_sender="*"/></policy>'
                         + ''.join(f'<servicedir>{x}</servicedir>' for x in SYSTEM_DIRS) + '</busconfig>')
            proc = subprocess.Popen([DAEMON, f'--config-file={conf}', '--nofork', '--nopidfile'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    if os.path.exists(sock):
                        break
                    time.sleep(0.05)
                observed = {}
                for case, (name, _files) in scenarios.items():
                    reply = subprocess.run([SEND, f'--bus=unix:path={sock}', '--print-reply', '--reply-timeout=1500',
                                            '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus',
                                            'org.freedesktop.DBus.StartServiceByName', f'string:{name}', 'uint32:0'],
                                           capture_output=True, text=True, timeout=15, check=False)
                    observed[case] = reply.stdout + reply.stderr
            finally:
                proc.terminate()
                proc.wait(timeout=10)
            time.sleep(0.5)
            ran = {}
            for tag in os.listdir(marks):
                with open(os.path.join(marks, tag), encoding='utf-8') as fh:
                    ran[tag] = fh.read().strip()
        finally:
            for target in written:
                try:
                    os.unlink(target)
                except FileNotFoundError:
                    pass
        listings = []
        for index, path in enumerate(SYSTEM_DIRS):
            entries = {}
            for _name, files in scenarios.values():
                for (i, filename), text in files.items():
                    if i == index:
                        entries[filename] = {'kind': 'file', 'text': _render(text, marks)}
            listings.append({'path': path, 'observed': True, 'entries': entries})
        contract = da.resolve(listings, bus='system', systemd_activation=False)
    for case, (name, files) in scenarios.items():
        got = start(contract, name)
        started = [tag for tag in ran if any(f'{{X:{tag}}}' in t for t in files.values())]
        if got['status'] == 'starts':
            text = files[(SYSTEM_DIRS.index(got['directory']), got['file'])]
            tag = re.search(r'\{X:([A-Za-z0-9]+)\}', text).group(1)
            assert started == [tag], (case, observed[case], ran)
            assert ran[tag] == got['run_as'], case
        else:
            assert got['status'] == 'refused', (case, got)
            assert started == [], (case, observed[case], ran)
            assert 'org.freedesktop.DBus.Error.Spawn' in observed[case], (case, observed[case])
