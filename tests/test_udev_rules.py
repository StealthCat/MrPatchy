import hashlib

from app import udev_rules as ur

PATH = '/etc/udev/rules.d/70-local.rules'

LOCAL_RULES = r'''# Local device rules
ACTION=="add", SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", \
    RUN+="/usr/local/bin/usb-hook %k $env{ID_SERIAL}"

SUBSYSTEM=="block", PROGRAM="scsi_id --whitelisted /dev/$name", RESULT=="1ATA*", SYMLINK+="disk/%c"
KERNEL=="sd*", IMPORT{program}="probe-helper $devnode", IMPORT{builtin}="blkid", IMPORT{file}="/etc/x.env"
SUBSYSTEM=="net", RUN{builtin}+="net_setup_link", ENV{ID_NET}=e"a\tb", OWNER="root", MODE:="0600"
ACTION!="add", GOTO="local_end"
TAG+="systemd", ENV{SYSTEMD_WANTS}+="backup@%k.service"
LABEL="local_end"
'''


def test_parses_rules_continuations_matches_assignments_and_labels():
    r = ur.parse_rules_file(PATH, LOCAL_RULES)
    assert r['state'] == 'parsed' and r['gaps'] == [] and r['origin'] == 'not_assessed'
    assert r['sha256'] == hashlib.sha256(LOCAL_RULES.encode()).hexdigest()
    rules = r['rules']
    assert [x['line'] for x in rules] == [2, 5, 6, 7, 8, 9, 10]
    first = rules[0]
    assert first['file'] == PATH
    assert [(m['key'], m['attr'], m['operator'], m['value']) for m in first['matches']] == [
        ('ACTION', None, '==', 'add'), ('SUBSYSTEM', None, '==', 'usb'), ('ATTRS', 'idVendor', '==', '0bda')]
    assert [(a['key'], a['operator']) for a in first['assignments']] == [('RUN', '+=')]
    net = rules[3]
    assert {a['key']: a['value'] for a in net['assignments']}['ENV'] == 'a\tb'
    assert [(a['key'], a['operator']) for a in net['assignments']][-1] == ('MODE', ':=')
    assert rules[4]['goto'] == 'local_end' and rules[6]['label'] == 'local_end'
    assert r['labels'] == ['local_end']
    assert all(rule['origin'] == 'not_assessed' for rule in rules)


def test_executions_for_run_program_and_import_program_with_search_paths():
    rules = ur.parse_rules_file(PATH, LOCAL_RULES)['rules']
    run = rules[0]['executions'][0]
    command = '/usr/local/bin/usb-hook %k $env{ID_SERIAL}'
    assert run['kind'] == 'run' and run['type'] == 'program' and run['external'] is True
    assert run['operator'] == '+=' and run['command'] == command
    assert run['command_sha256'] == hashlib.sha256(command.encode()).hexdigest()
    assert run['program'] == '/usr/local/bin/usb-hook'
    assert run['candidate_paths'] == ['/usr/local/bin/usb-hook'] and run['uses_substitutions'] is True
    assert run['origin'] == 'not_assessed'
    program = rules[1]['executions'][0]
    assert program['kind'] == 'program' and program['operator'] == '=='
    assert program['program'] == 'scsi_id'
    assert program['candidate_paths'] == ['/usr/lib/udev/scsi_id', '/lib/udev/scsi_id']
    imports = rules[2]['executions']
    assert [(e['kind'], e['type'], e['external'], e['program']) for e in imports] == [
        ('import', 'program', True, 'probe-helper'), ('import', 'builtin', False, 'blkid')]
    assert imports[1]['candidate_paths'] == []
    builtin = rules[3]['executions'][0]
    assert (builtin['kind'], builtin['type'], builtin['external'], builtin['program']) == (
        'run', 'builtin', False, 'net_setup_link')
    # Not executions: IMPORT{file}, TAG, ENV{SYSTEMD_WANTS}.
    assert sum(len(rule['executions']) for rule in rules) == 5


def test_plain_string_escapes_and_bounded_long_command():
    text = 'RUN+="/bin/sh -c \\"echo \\\\x\\""\n' + 'RUN+="/opt/x ' + 'a' * 5000 + '"\n'
    r = ur.parse_rules_file(PATH, text)
    assert r['gaps'] == []
    # udev only unescapes \" in a plain string; \\ stays two backslashes.
    assert r['rules'][0]['executions'][0]['command'] == '/bin/sh -c "echo \\\\x"'
    assert r['rules'][0]['executions'][0]['uses_substitutions'] is False
    long_run = r['rules'][1]['executions'][0]
    full = '/opt/x ' + 'a' * 5000
    assert long_run['command_truncated'] is True and len(long_run['command']) == ur.MAX_COMMAND
    assert long_run['command_sha256'] == hashlib.sha256(full.encode()).hexdigest()
    assert r['rules'][1]['assignments'][0]['value_truncated'] is True


def test_double_backslash_before_quote_does_not_hide_an_executed_program():
    # udev reads ENV{X} as a\"b and keeps the rule, so /tmp/evil runs.
    r = ur.parse_rules_file(PATH, 'ENV{X}="a\\\\"b", RUN+="/tmp/evil"\n')
    assert r['state'] == 'parsed' and r['gaps'] == []
    rule = r['rules'][0]
    assert rule['matches'] == [] and rule['assignments'][0]['value'] == 'a\\"b'
    assert [e['command'] for e in rule['executions']] == ['/tmp/evil']


def test_comment_lines_inside_a_continuation_are_dropped_and_lines_are_left_stripped():
    text = 'ACTION=="add", \\\n# note\n   RUN+="/tmp/evil"\n\tKERNEL=="sd*", \\\n  \t# x\n\tRUN+="/bin/b"\n'
    r = ur.parse_rules_file(PATH, text)
    assert r['state'] == 'parsed' and r['gaps'] == []
    assert [x['line'] for x in r['rules']] == [1, 4]
    first = r['rules'][0]
    assert [(m['key'], m['value']) for m in first['matches']] == [('ACTION', 'add')]
    assert [e['command'] for e in first['executions']] == ['/tmp/evil']
    assert [e['command'] for e in r['rules'][1]['executions']] == ['/bin/b']


def test_udev_line_size_limits():
    long_value = 'a' * (ur.UDEV_LINE_SIZE - 100)
    joined = f'KERNEL=="{long_value}", \\\nRUN+="/bin/{"b" * 200}"\nKERNEL=="ok", RUN+="/bin/ok"\n'
    r = ur.parse_rules_file(PATH, joined)
    assert [(g['line'], g['code']) for g in r['gaps']] == [(1, 'line_too_long')]
    assert [e['command'] for rule in r['rules'] for e in rule['executions']] == ['/bin/ok']
    physical = 'KERNEL=="a", RUN+="/bin/a"\n' + 'KERNEL=="' + 'x' * ur.UDEV_LINE_SIZE + '"\nRUN+="/bin/later"\n'
    r = ur.parse_rules_file(PATH, physical)
    assert r['state'] == 'partial' and [(g['line'], g['code']) for g in r['gaps']] == [(2, 'line_too_long')]
    assert [e['command'] for rule in r['rules'] for e in rule['executions']] == ['/bin/a']
    fits = ur.parse_rules_file(PATH, 'RUN+="/bin/' + 'c' * (ur.UDEV_LINE_SIZE - 20) + '"\n')
    assert fits['gaps'] == [] and len(fits['rules']) == 1

def test_malformed_rules_are_line_numbered_gaps_and_skipped():
    text = '\n'.join([
        'KERNEL=="a", RUN+="/bin/ok"',            # 1 kept
        'KERNEL=="b" RUN+="/bin/x',               # 2 unterminated
        'KERNEL=="c", RUN+=/bin/unquoted',        # 3 unquoted
        'KERNEL=="d", FROBNICATE="1", RUN+="/bin/y"',  # 4 unknown key
        'KERNEL=="e", RUN=="/bin/z"',             # 5 match op on assign-only key
        'ATTRS=="x", RUN+="/bin/w"',              # 6 missing attribute
        'KERNEL="f", RUN+="/bin/v"',              # 7 assign op on match-only key
        'RUN{shell}+="/bin/u"',                   # 8 unknown RUN type
        'IMPORT{magic}=="/bin/t"',                # 9 unknown IMPORT type
        'MODE-="0600"',                           # 10 remove op not accepted
        'KERNEL=="g"RUN+="/bin/s"',               # 11 missing separator
        'ENV{X}=e"bad\\q"',                       # 12 invalid C escape
        'GOTO="nowhere"',                         # 13 goto without label
    ])
    r = ur.parse_rules_file(PATH, text)
    assert r['state'] == 'partial'
    assert [x['line'] for x in r['rules']] == [1, 13]
    codes = [(g['line'], g['code']) for g in r['gaps']]
    assert codes == [(2, 'unterminated_value'), (3, 'unquoted_value'), (4, 'unknown_key'),
                     (5, 'invalid_operator'), (6, 'missing_attribute'), (7, 'invalid_operator'),
                     (8, 'invalid_attribute'), (9, 'invalid_attribute'), (10, 'invalid_operator'),
                     (11, 'missing_separator'), (12, 'invalid_escape'), (13, 'goto_without_label')]
    executed = [e['command'] for rule in r['rules'] for e in rule['executions']]
    assert executed == ['/bin/ok']


def test_program_written_with_assignment_still_runs_as_a_match():
    r = ur.parse_rules_file(PATH, 'PROGRAM="helper $kernel", IMPORT{program}+="other"\nPROGRAM-="x"\n')
    assert [(g['line'], g['code']) for g in r['gaps']] == [(2, 'invalid_operator')]
    rule = r['rules'][0]
    assert [(m['key'], m['operator'], m['written_operator']) for m in rule['matches']] == [
        ('PROGRAM', '==', '='), ('IMPORT', '==', '+=')]
    assert [e['program'] for e in rule['executions']] == ['helper', 'other']
    assert [e['operator'] for e in rule['executions']] == ['==', '==']


def test_over_limit_invalid_utf8_nul_and_trailing_continuation_fail_closed():
    for text, code in ((b'RUN+="/x"\n' + b'#' * ur.MAX_TEXT, 'over_limit'), (b'RUN+="\xff"', 'invalid_utf8'),
                       ('RUN+="/x"\x00', 'binary'), ('RUN+="/x"\n' * (ur.MAX_LINES + 1), 'over_limit'), (None, 'unreadable')):
        r = ur.parse_rules_file(PATH, text)
        assert r['state'] == 'unavailable' and r['rules'] == [] and r['sha256'] is None
        assert r['gaps'][0]['code'] == code
    many = ''.join(f'KERNEL=="k{i}", RUN+="/bin/x"\n' for i in range(ur.MAX_RULES + 1))
    r = ur.parse_rules_file(PATH, many)
    assert r['state'] == 'unavailable' and r['rules'] == [] and r['gaps'][-1]['code'] == 'over_limit'
    r = ur.parse_rules_file(PATH, 'KERNEL=="a", RUN+="/bin/a"\nKERNEL=="b", \\')
    assert [x['line'] for x in r['rules']] == [1]
    assert r['gaps'] == [{'code': 'unterminated_continuation', 'line': 2,
                          'detail': r['gaps'][0]['detail']}]


def test_rules_are_never_executed(monkeypatch):
    import os
    import subprocess

    def refuse(*args, **kwargs):
        raise AssertionError('udev rules must not be executed')

    for target, name in ((subprocess, 'run'), (subprocess, 'Popen'), (os, 'system'), (os, 'popen')):
        monkeypatch.setattr(target, name, refuse)
    r = ur.parse_rules_file(PATH, 'RUN+="/bin/touch /tmp/pwned"\nPROGRAM=="/bin/false"\n')
    assert len(r['rules']) == 2


def entry(directory, name, target=None):
    return {'dir': directory, 'name': name, 'target': target}


def test_effective_files_precedence_masking_ignored_and_order():
    r = ur.effective_files([
        entry('/lib/udev/rules.d', '60-persistent-storage.rules'),
        entry('/usr/lib/udev/rules.d', '60-persistent-storage.rules'),
        entry('/etc/udev/rules.d', '60-persistent-storage.rules'),
        entry('/usr/lib/udev/rules.d', '80-net-setup-link.rules'),
        entry('/run/udev/rules.d', '80-net-setup-link.rules', '/dev/null'),
        entry('/usr/local/lib/udev/rules.d', '10-local.rules'),
        entry('/usr/lib/udev/rules.d', '99-systemd.rules', 'other/99-systemd.rules'),
        entry('/etc/udev/rules.d', 'README'),
        entry('/etc/udev/rules.d', '70-old.rules.dpkg-old'),
        entry('/etc/udev/rules.d', '.99-hidden.rules'),
    ])
    assert r['state'] == 'parsed' and r['gaps'] == []
    assert [(f['name'], f['path'], f['overridden']) for f in r['files']] == [
        ('10-local.rules', '/usr/local/lib/udev/rules.d/10-local.rules', []),
        ('60-persistent-storage.rules', '/etc/udev/rules.d/60-persistent-storage.rules',
         ['/usr/lib/udev/rules.d/60-persistent-storage.rules', '/lib/udev/rules.d/60-persistent-storage.rules']),
        ('99-systemd.rules', '/usr/lib/udev/rules.d/99-systemd.rules', []),
    ]
    assert r['files'][2]['symlink'] is True
    assert [(m['path'], m['overridden']) for m in r['masked']] == [
        ('/run/udev/rules.d/80-net-setup-link.rules', ['/usr/lib/udev/rules.d/80-net-setup-link.rules'])]
    assert r['ignored'] == ['/etc/udev/rules.d/.99-hidden.rules', '/etc/udev/rules.d/70-old.rules.dpkg-old',
                            '/etc/udev/rules.d/README']
    assert all(f['origin'] == 'not_assessed' for f in r['files'] + r['masked'])


def test_effective_files_gaps_and_over_limit():
    r = ur.effective_files([
        entry('/etc/udev/other.d', 'x.rules'), entry('/etc/udev/rules.d', 'a/b.rules'),
        entry('/etc/udev/rules.d', ''), entry('/etc/udev/rules.d', 'ok.rules'),
        entry('/etc/udev/rules.d', 'ok.rules'), entry('/etc/udev/rules.d', 'bad.rules', ''), 'nonsense',
    ])
    assert r['state'] == 'partial' and [f['name'] for f in r['files']] == ['ok.rules']
    assert [g['code'] for g in r['gaps']] == ['unrecognized_directory', 'malformed_entry', 'malformed_entry',
                                              'duplicate_entry', 'invalid_target', 'malformed_entry']
    big = ur.effective_files([entry('/etc/udev/rules.d', f'{i}.rules') for i in range(ur.MAX_ENTRIES + 1)])
    assert big['state'] == 'unavailable' and big['files'] == [] and big['gaps'][0]['code'] == 'over_limit'
