"""auditd dispatcher-plugin contract (#1217).

The PARSE_VECTORS expectations were checked against audit-userspace v3.1.2
``load_pconfig`` compiled from ``audisp/audispd-pconfig.c`` with a logging
stub. A 7,000-case random differential against that build gave 0 mismatches.
"""
from __future__ import annotations

import pytest

from app import auditd_plugins as ap

CONF = ap.AUDITD_CONF
DIR = ap.DEFAULT_PLUGIN_DIR
OK_PROGRAM = {'state': 'file', 'uid': 0, 'mode': 0o750}


def _file(text: str, uid: int = 0, mode: int = 0o640) -> dict:
    return {'state': 'file', 'uid': uid, 'mode': mode, 'text': text}


def _obs(entries: dict, programs: dict | None = None, conf: dict | None = None, directory: str = DIR) -> dict:
    return {
        CONF: conf or {'state': 'absent'},
        directory: {'state': 'directory', 'entries': entries},
        'programs': programs if programs is not None else {},
    }


AF_UNIX = 'active = no\ndirection = out\npath = /sbin/audisp-af_unix\ntype = always\nargs = 0640 /var/run/audispd_events\nformat = string\n'
SYSLOG = 'active = yes\ndirection = out\npath = /sbin/audisp-syslog\ntype = always\nargs = LOG_INFO\nformat = string\n'

# (text, expected status, expected args or None). Verified against the compiled C.
PARSE_VECTORS = [
    ('active = yes\npath = /bin/true\nargs = a b c\n', 'starts', ['a', 'b']),
    ('ACTIVE = Yes\nPATH = /bin/true\n', 'starts', []),
    ('active = yes\npath = /bin/true\n# comment\n\n   \n', 'starts', []),
    ('active = yes\npath = /bin/true', 'rejected', None),  # unterminated path line skipped -> no path
    ('path = /bin/true\nactive = yes', 'inactive', None),  # unterminated active line skipped
    ('active=yes\npath = /bin/true\n', 'rejected', None),
    ('active = yes\npath\t= /bin/true\n', 'rejected', None),
    ('active = yes\npath = /bin/true\nargs\t= a\n', 'rejected', None),
    ('active = yes extra\npath = /bin/true\n', 'rejected', None),
    ('active = maybe\npath = /bin/true\n', 'rejected', None),
    ('active = yes\npath = /bin/true\ndirection = in\n', 'rejected', None),
    ('active = yes\npath = /bin/true\nbogus = 1\n', 'rejected', None),
    ('active = yes\npath = /bin/true\ntype = builtin\n', 'starts', []),
    ('active = yes\npath = /x\n', 'rejected', None),
    ('active = yes\npath = /usr/\n', 'rejected', None),
    ('active = yes\npath = /a//b\n', 'rejected', None),
    ('active = yes\npath = /bin/true\nactive = no\n', 'inactive', None),
    ('active = yes\npath = /bin/true\n' + 'x' * 170 + '\nargs = z\n', 'starts', ['z']),
    ('active = yes\npath = /bin/true\nargs = q\0junk\nargs = z\n', 'starts', []),  # NUL hides newline, swallows next
    ('active = yes\n' + 'path = /bin/true' + ' ' * 143 + '\n', 'rejected', None),  # 159 bytes: too long
    ('active = yes\n' + 'path = /bin/true' + ' ' * 142 + '\n', 'starts', []),  # 158 bytes: fits
]


@pytest.mark.parametrize('text,status,args', PARSE_VECTORS)
def test_parse_vectors_match_load_pconfig(text, status, args):
    result = ap.assess(_obs({'p': _file(text)}, {'/bin/true': {'state': 'file', 'uid': 0, 'mode': 0o755}}))
    assert result['complete'] is True
    entry = result['plugins'][0]
    assert entry['status'] == status, entry
    if args is not None:
        assert entry['command']['argv'] == ['/bin/true', *args]


def test_packaged_defaults_and_active_syslog_plugin():
    result = ap.assess(_obs({'af_unix.conf': _file(AF_UNIX), 'syslog.conf': _file(SYSLOG)},
                            {'/sbin/audisp-syslog': OK_PROGRAM}))
    assert result['complete'] is True
    assert result['plugin_dir'] == {'path': DIR, 'source': 'default'}
    by_name = {p['name']: p for p in result['plugins']}
    assert by_name['af_unix.conf']['status'] == 'inactive'
    command = by_name['syslog.conf']['command']
    assert command['argv'] == ['/sbin/audisp-syslog', 'LOG_INFO']
    assert command['runs_as'] == 'root' and command['shell'] is False and command['environment'] == 'empty'
    assert result['started_programs'] == [command]
    assert result['authorizes_response'] is False
    assert result['origin'] == 'not_assessed'


def test_names_skipped_by_dot_rules_but_no_conf_suffix_needed():
    planted = 'active = yes\npath = /usr/local/sbin/hook\n'
    entries = {'.hidden': _file(planted), 'syslog.conf.bak': _file(planted), 'a.b.c': _file(planted),
               'noext': _file(planted)}
    result = ap.assess(_obs(entries, {'/usr/local/sbin/hook': OK_PROGRAM}))
    status = {p['name']: p['status'] for p in result['plugins']}
    assert status == {'.hidden': 'skipped_name', 'syslog.conf.bak': 'skipped_name', 'a.b.c': 'skipped_name',
                      'noext': 'starts'}


@pytest.mark.parametrize('uid,mode,status', [(0, 0o640, 'starts'), (0, 0o666, 'rejected'), (1000, 0o640, 'rejected'),
                                             (0, 0o664, 'starts')])
def test_plugin_file_ownership_and_world_write(uid, mode, status):
    result = ap.assess(_obs({'x.conf': _file(SYSLOG, uid, mode)}, {'/sbin/audisp-syslog': OK_PROGRAM}))
    assert result['plugins'][0]['status'] == status


@pytest.mark.parametrize('program,status', [
    ({'state': 'file', 'uid': 0, 'mode': 0o750}, 'starts'),
    ({'state': 'file', 'uid': 0, 'mode': 0o4777}, 'starts'),
    ({'state': 'file', 'uid': 0, 'mode': 0o700}, 'rejected'),
    ({'state': 'file', 'uid': 0, 'mode': 0o740}, 'rejected'),
    ({'state': 'file', 'uid': 1000, 'mode': 0o755}, 'rejected'),
    ({'state': 'absent'}, 'rejected'),
    ({'state': 'directory'}, 'rejected'),
])
def test_program_sanity_check(program, status):
    result = ap.assess(_obs({'syslog.conf': _file(SYSLOG)}, {'/sbin/audisp-syslog': program}))
    assert result['complete'] is True
    assert result['plugins'][0]['status'] == status


def test_builtin_path_maps_to_af_unix_and_is_stat_checked():
    text = 'active = yes\npath = builtin_af_unix\n'
    result = ap.assess(_obs({'b.conf': _file(text)}, {ap.BUILTIN_PATH: OK_PROGRAM}))
    assert result['plugins'][0]['command']['program'] == ap.BUILTIN_PATH
    missing = ap.assess(_obs({'b.conf': _file(text)}, {}))
    assert missing['complete'] is False and missing['blocking_gaps'] == ['program_not_observed']


def test_relative_path_with_long_dirname_is_accepted():
    result = ap.assess(_obs({'r.conf': _file('active = yes\npath = abcd/run\n')}, {'abcd/run': OK_PROGRAM}))
    command = result['plugins'][0]['command']
    assert command['absolute'] is False and 'working directory' in command['note']


def test_plugin_dir_override_last_line_wins():
    conf = {'state': 'file', 'text': 'plugin_dir = /etc/a\nPLUGIN_DIR = /opt/plugins/\nlog_file = /x\n'}
    result = ap.assess(_obs({'s.conf': _file(SYSLOG)}, {'/sbin/audisp-syslog': OK_PROGRAM}, conf, '/opt/plugins'))
    assert result['plugin_dir'] == {'path': '/opt/plugins/', 'source': {'path': CONF, 'line': 2}}
    assert result['plugins'][0]['file'] == '/opt/plugins/s.conf'
    unobserved = ap.assess(_obs({}, {}, conf, DIR))
    assert unobserved['blocking_gaps'] == ['path_not_observed']


@pytest.mark.parametrize('state,plugins', [('absent', []), ('file', [])])
def test_missing_or_non_directory_plugin_dir_starts_nothing(state, plugins):
    result = ap.assess({CONF: {'state': 'absent'}, DIR: {'state': state}, 'programs': {}})
    assert result['complete'] is True and result['plugins'] == plugins and result['started_programs'] == []


@pytest.mark.parametrize('observations,code', [
    ({}, 'path_not_observed'),
    ({CONF: {'state': 'unreadable'}}, 'path_unreadable'),
    ({CONF: {'state': 'absent'}, DIR: {'state': 'unreadable'}}, 'path_unreadable'),
    ({CONF: {'state': 'absent'}, DIR: {'state': 'directory', 'entries': {'p': {'state': 'unreadable'}}}},
     'entry_unreadable'),
    ({CONF: {'state': 'absent'}, DIR: {'state': 'directory', 'entries': {'p': {'state': 'other'}}}},
     'entry_other_type'),
    ({CONF: {'state': 'absent'}, DIR: {'state': 'directory', 'entries': {'p': {'state': 'file'}}}},
     'input_malformed'),
    ({CONF: {'state': 'absent'}, DIR: {'state': 'directory', 'entries': {'p': _file('x' * (ap.MAX_BYTES + 1))}}},
     'too_large'),
    ({CONF: {'state': 'absent'}, DIR: {'state': 'directory',
                                      'entries': {f'f{i}': _file('') for i in range(ap.MAX_DIR_ENTRIES + 1)}}},
     'too_many_entries'),
])
def test_gaps_fail_closed(observations, code):
    result = ap.assess(observations)
    assert result['complete'] is False
    assert code in result['blocking_gaps']
    assert result['plugins'] == [] and result['started_programs'] is None
    assert result['authorizes_response'] is False


def test_line_notes_explain_dropped_and_skipped_lines():
    text = 'active = yes\npath = /bin/true\nargs = a b c\n' + 'y' * 200 + '\nformat = binary'
    entry = ap.assess(_obs({'n': _file(text)}, {'/bin/true': OK_PROGRAM}))['plugins'][0]
    effects = [(note['line'], note['effect']) for note in entry['line_notes']]
    assert (3, 'words_dropped') in effects and (4, 'skipped') in effects and (5, 'skipped') in effects
    assert entry['configuration']['format'] == 'string'


def test_malformed_top_level_input():
    assert ap.assess(None)['blocking_gaps'] == ['input_malformed']
    assert 'input_malformed' in ap.assess(_obs({'p': _file(SYSLOG)}, programs=[]))['blocking_gaps']


@pytest.mark.parametrize('path,expected', [
    (b'', b'.'), (b'x', b'.'), (b'/', b'/'), (b'//', b'//'), (b'/x', b'/'), (b'//x', b'//'), (b'///x', b'/'),
    (b'/usr/', b'/'), (b'/usr/bin', b'/usr'), (b'/a//b', b'/a'), (b'a/b/', b'a'), (b'/a/b//', b'/a'),
])
def test_glibc_dirname(path, expected):
    assert ap.glibc_dirname(path) == expected
