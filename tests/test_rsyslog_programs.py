"""Tests for the pure rsyslog program-action contract (#1227).

Expected outcomes were observed with the real rsyslogd 8.2312.0. The live
differential at the end reruns them when ``MRPATCHY_RSYSLOGD`` names an
rsyslogd binary (and ``MRPATCHY_RSYSLOG_MODDIR`` its module directory) and the
tests run as root.
"""
import os
import shutil
import signal
import subprocess
import tempfile
import time

import pytest

from app import rsyslog_programs as rp

UBUNTU = """module(load="imuxsock") # provides support for local system logging
module(load="imklog" permitnonkernelfacility="on")
$RepeatedMsgReduction on
$FileOwner syslog
$FileGroup adm
$PrivDropToUser syslog
$PrivDropToGroup syslog
$WorkDirectory /var/spool/rsyslog
$IncludeConfig /etc/rsyslog.d/*.conf
"""


def run(main, extra=None, listings=None):
    files = {rp.DEFAULT_CONFIG: main, **(extra or {})}
    return rp.resolve(files, listings if listings is not None else {'/etc/rsyslog.d': [p.rsplit('/', 1)[1] for p in extra or {}]})


def codes(result):
    return [gap['code'] for gap in result['gaps']]


@pytest.mark.parametrize('value, expected', [
    ('/p one "two three" \'four five\' six\\ seven  eight',
     ('/p', ['one', '"two three"', "'four", "five'", 'six\\', 'seven', '', 'eight'])),
    ('/p a"b c"d e', ('/p', ['a"b c"d', 'e'])),
    ('/p x ', ('/p', ['x'])),
    ('/p x  ', ('/p', ['x', ''])),
    ('/p "" z', ('/p', ['""', 'z'])),
    ('/p "unbalanced w', ('/p', ['"unbalanced w'])),
    ('/p\ttab y', ('/p\ttab', ['y'])),
    (' /p lead', ('', ['/p', 'lead'])),
    ('/p', ('/p', [])),
])
def test_split_binary_matches_rsyslog(value, expected):
    assert rp.split_binary(value) == expected


def test_ubuntu_default_drops_to_syslog_and_runs_included_omprog():
    result = rp.resolve(
        {rp.DEFAULT_CONFIG: UBUNTU,
         '/etc/rsyslog.d/50-hook.conf': 'module(load="omprog")\n'
                                        'if $programname == "sshd" then {\n'
                                        '  action(type="omprog" binary="/usr/local/bin/hook --mode \\"a b\\"")\n'
                                        '}\n'},
        {'/etc/rsyslog.d': ['50-hook.conf', '.hidden.conf', 'README']})
    assert result['complete'] is True
    assert result['privilege']['user']['name'] == 'syslog'
    assert result['privilege']['group']['name'] == 'syslog'
    assert result['privilege']['drops_root'] is True
    [action] = result['actions']
    assert action['status'] == 'runs'
    assert action['argv'] == ['/usr/local/bin/hook', '--mode', '"a b"']
    assert action['file'] == '/etc/rsyslog.d/50-hook.conf' and action['line'] == 3
    assert action['runs_as']['user']['name'] == 'syslog'
    assert [f['path'] for f in result['files']] == [rp.DEFAULT_CONFIG, '/etc/rsyslog.d/50-hook.conf']
    assert result['origin'] == 'not_assessed'


def test_without_privilege_drop_programs_run_as_root():
    result = run('module(load="omprog")\n*.* action(type="omprog" binary="/bin/hook")\n')
    [action] = result['actions']
    assert action['runs_as']['user'] == {'name': 'root', 'id': 0, 'source': 'default', 'source_location': None}
    assert result['privilege']['drops_root'] is False


def test_user_without_group_keeps_root_group_and_last_directive_wins():
    result = run('$PrivDropToUser nobody\n$PrivDropToUser root\n$PrivDropToGroupID 4343\n')
    assert result['privilege']['user']['name'] == 'root'
    assert result['privilege']['drops_root'] is False
    assert result['privilege']['group']['id'] == 4343
    result = run('$PrivDropToUser nobody\n')
    assert result['privilege']['group']['id'] == 0


def test_privilege_position_is_global():
    result = run('*.* ^/bin/hook\n$PrivDropToUser nobody\n')
    [action] = result['actions']
    assert action['kind'] == 'shell_execute'
    assert action['argv'] == ['/bin/hook', '<formatted message>']
    assert action['runs_as']['user']['name'] == 'nobody'


def test_global_privilege_parameter_drops_nothing_in_8_2312():
    result = run('global(privilege.dropToUser="nobody")\n')
    assert result['privilege']['user']['name'] == 'root'
    assert result['notes'] and 'drops nothing' in result['notes'][0]


def test_module_must_load_before_the_action():
    result = run('*.* action(type="omprog" binary="/bin/late")\nmodule(load="omprog")\n')
    assert result['actions'][0]['status'] == 'module_not_loaded'
    result = run('$ModLoad omprog.so\nmail.* action(type="omprog" binary="/bin/x")\n')
    assert result['actions'][0]['status'] == 'runs'


def test_mmexternal_uses_the_same_split():
    result = run('module(load="mmexternal")\n*.* action(type="mmexternal" binary="/bin/m \\"q r\\" s")\n')
    assert result['actions'][0]['argv'] == ['/bin/m', '"q r"', 's']
    assert result['actions'][0]['kind'] == 'mmexternal'


def test_legacy_omprog_binary_is_one_word_and_needs_module_first():
    result = run('$ModLoad omprog\n$ActionOMProgBinary /bin/leg ignored words\n*.* :omprog:\n')
    [action] = result['actions']
    assert action['status'] == 'runs' and action['argv'] == ['/bin/leg']
    result = run('$ActionOMProgBinary /bin/leg\n$ModLoad omprog\n*.* :omprog:\n')
    assert result['actions'][0]['status'] == 'rejected'
    result = run('*.* :omprog:\n$ModLoad omprog\n')
    assert result['actions'][0]['status'] == 'module_not_loaded'


def test_empty_program_is_rejected():
    result = run('module(load="omprog")\n*.* action(type="omprog" binary=" /bin/x")\n')
    assert result['actions'][0]['status'] == 'rejected'


def test_rainerscript_strings_comments_and_rulesets():
    text = ('module(load="omprog")\n'
            '# action(type="omprog" binary="/commented")\n'
            '/* action(type="omprog" binary="/block")\n*/\n'
            'template(name="t" type="string" string="action(type=\\"omprog\\" binary=\\"/in-string\\")")\n'
            'ruleset(name="remote") {\n'
            '  :msg, contains, "x" action(type="omprog" binary="/bin/r" template="t")\n'
            '}\n'
            '& ^/bin/caret;t\n'
            'if $msg contains "y" then ^/bin/then\n')
    result = run(text)
    assert [(a['program'], a['ruleset'], a['line']) for a in result['actions']] == [
        ('/bin/r', 'remote', 7), ('/bin/caret', None, 9), ('/bin/then', None, 10)]


def test_include_order_follows_sorted_glob():
    files = {'/etc/rsyslog.d/b.conf': 'module(load="omprog")\n',
             '/etc/rsyslog.d/a.conf': '*.* action(type="omprog" binary="/bin/inc")\n'}
    result = run('include(file="/etc/rsyslog.d/*.conf")\n', files)
    assert result['actions'][0]['status'] == 'module_not_loaded'
    assert [f['path'] for f in result['files']][1:] == ['/etc/rsyslog.d/a.conf', '/etc/rsyslog.d/b.conf']


def test_glob_without_matches_includes_nothing():
    result = run('$IncludeConfig /etc/rsyslog.d/*.conf\n', listings={'/etc/rsyslog.d': []})
    assert result['complete'] is True and result['actions'] == []


@pytest.mark.parametrize('text, code', [
    ('$IncludeConfig /etc/rsyslog.d/*.conf\n', 'listing_not_observed'),
    ('$IncludeConfig /etc/rsyslog.d/\n', 'directory_include'),
    ('$IncludeConfig /etc/*/x.conf\n', 'glob_in_directory'),
    ('$IncludeConfig rsyslog.d/*.conf\n', 'relative_include'),
    ('include(file="/etc/extra.conf")\n', 'file_not_observed'),
    ('include(text="x")\n', 'include_text_unsupported'),
    ('module(load="omprog")\naction(type="omprog" binary=`echo /bin/x`)\n', 'backtick_value'),
    ('module(load="omprog")\naction(type="omprog" binary="/bin/x)\n', 'syntax'),
    ('/* open\n', 'syntax'),
])
def test_fail_closed(text, code):
    result = rp.resolve({rp.DEFAULT_CONFIG: text}, {})
    assert code in codes(result)
    assert result['complete'] is False


def test_syntax_error_leaves_earlier_actions_unresolved():
    result = run('module(load="omprog")\n*.* action(type="omprog" binary="/bin/a")\naction(type="omprog" binary=\n')
    assert result['actions'][0]['status'] == 'unresolved'


def test_unobserved_main_config_and_bad_input():
    assert codes(rp.resolve({}, {})) == ['file_not_observed']
    assert codes(rp.resolve({rp.DEFAULT_CONFIG: b'\xff'}, {})) == ['invalid_utf8']
    assert codes(rp.resolve({rp.DEFAULT_CONFIG: 'a\0b'}, {})) == ['binary']
    assert codes(rp.resolve({rp.DEFAULT_CONFIG: 'x' * (rp.MAX_TEXT + 1)}, {})) == ['over_limit']


def test_include_loop_is_bounded():
    result = rp.resolve({rp.DEFAULT_CONFIG: f'$IncludeConfig {rp.DEFAULT_CONFIG}\n'}, {})
    assert 'include_depth' in codes(result)


# --- live differential against a real rsyslogd ------------------------------------------------------------

RSYSLOGD = os.environ.get('MRPATCHY_RSYSLOGD')
MODDIR = os.environ.get('MRPATCHY_RSYSLOG_MODDIR')
LOGGER = shutil.which('logger')
PROBE = """#!/bin/sh
{ printf 'uid=%s gid=%s\\n' "$(id -u)" "$(id -g)"; for a in "$@"; do printf 'arg[%s]\\n' "$a"; done; } >> "$0.out"
cat >/dev/null
"""


def _live(body, workdir):
    conf = os.path.join(workdir, 'rsyslog.conf')
    sock = os.path.join(workdir, 'sock')
    with open(conf, 'w') as handle:
        handle.write(f'module(load="imuxsock" SysSock.Use="off")\ninput(type="imuxsock" Socket="{sock}")\n{body}')
    out = os.path.join(workdir, 'probe.sh.out')
    open(out, 'w').close()
    os.chmod(out, 0o666)
    proc = subprocess.Popen([RSYSLOGD, '-n', '-M', MODDIR, '-f', conf, '-i', os.path.join(workdir, 'pid')],
                            stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        subprocess.run([LOGGER, '-u', sock, 'hello'], check=False, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
    with open(out) as handle:
        return handle.read(), conf


def _expected(conf, probe):
    with open(conf) as handle:
        result = rp.resolve({rp.DEFAULT_CONFIG: handle.read()}, {})
    lines = []
    for action in result['actions']:
        if action['status'] != 'runs' or action['program'] != probe:
            continue
        user, group = action['runs_as']['user'], action['runs_as']['group']
        lines.append(f"uid={user['id']} gid={group['id']}")
        args = action['argv'][1:]
        lines += ['arg[<msg>]'] if action['kind'] == 'shell_execute' else [f'arg[{a}]' for a in args]
    return lines


@pytest.mark.skipif(not (RSYSLOGD and MODDIR and LOGGER and hasattr(os, 'geteuid') and os.geteuid() == 0),
                    reason='set MRPATCHY_RSYSLOGD and MRPATCHY_RSYSLOG_MODDIR and run as root')
@pytest.mark.parametrize('body', [
    'module(load="omprog")\n*.* action(type="omprog" binary="{p} one \\"two three\\" \'four five\' six  seven ")\n',
    'module(load="omprog")\n$PrivDropToUserID 4242\n$PrivDropToGroupID 4343\n'
    '*.* action(type="omprog" binary="{p} u")\n',
    'module(load="mmexternal")\n*.* action(type="mmexternal" binary="{p} m \\"q r\\" s")\n',
    '$ModLoad omprog\n$ActionOMProgBinary {p} ignored\n*.* :omprog:\n',
    '*.* ^{p};RSYSLOG_TraditionalFileFormat\n$PrivDropToUserID 4242\n',
    'module(load="omprog")\n*.* action(type="omprog" binary="{p} a\\"b c\\"d e  ")\n',
    'module(load="omprog")\nif $msg contains "hello" then ^{p}\n',
])
def test_live_differential(body):
    workdir = tempfile.mkdtemp(prefix='rsyslog-diff-', dir='/tmp')
    os.chmod(workdir, 0o755)
    try:
        probe = os.path.join(workdir, 'probe.sh')
        with open(probe, 'w') as handle:
            handle.write(PROBE)
        os.chmod(probe, 0o755)
        output, conf = _live(body.format(p=probe), workdir)
        # The shell-execute argument is the formatted message, which ends in a newline.
        observed = ['arg[<msg>]' if 'hello' in line else line for line in output.splitlines()]
        observed = [line for line in observed if line.startswith(('uid=', 'arg['))]
        assert observed == _expected(conf, probe)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
