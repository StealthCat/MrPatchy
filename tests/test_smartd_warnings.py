"""Tests for the pure smartd warning-command contract (#1207).

Expected outcomes are derived from smartmontools 7.4 ``smartd.cpp`` (ParseConfigFile,
ParseConfigLine, ParseToken, MailWarning) and the Ubuntu 24.04 package scripts.
"""
from __future__ import annotations

from app import smartd_warnings as sw

UBUNTU_DEFAULT = (
    '# Sample configuration file for smartd.  See man smartd.conf.\n'
    '#DEFAULT -a -o on -S on\n'
    'DEVICESCAN -d removable -n standby -m root -M exec /usr/share/smartmontools/smartd-runner\n'
    '/dev/sdz -a -m nobody@example\n'
)
OPTS = {'warnexec': None, 'warn_as_user': None}


def run(text, options=OPTS, state='present'):
    return sw.evaluate(text, config_state=state, daemon_options=options)


def test_ubuntu_default_runs_smartd_runner_and_run_d_as_root():
    result = run(UBUNTU_DEFAULT)
    assert result['complete'] and result['accepted']
    # DEVICESCAN ends parsing: the /dev/sdz line is never read.
    assert [entry['name'] for entry in result['entries']] == ['DEVICESCAN']
    entry = result['entries'][0]
    assert entry['devicescan'] and entry['uses_smartd_runner'] and not entry['runs_at_startup']
    steps = [step['step'] for step in entry['commands']]
    assert steps == ['warning_script', 'mailer', 'run_parts']
    assert entry['commands'][0]['command'] == '/usr/share/smartmontools/smartd_warning.sh 2>&1'
    assert all(step['user'] == 'root' for step in entry['commands'])
    assert entry['commands'][1]['arguments'] == ['-s', '<subject>', 'root']
    assert entry['commands'][2]['arguments'] == ['<message file>', '-s', '<subject>', 'root']
    assert result['origin'] == 'not_assessed'


def test_default_section_is_inherited_and_reset():
    text = ('DEFAULT -m root -M exec /opt/alert\n/dev/sda -a\nDEFAULT -a\n/dev/sdb -a\n')
    entries = run(text)['entries']
    assert [(e['name'], e['exec'], e['address']) for e in entries] == [
        ('/dev/sda', '/opt/alert', 'root'), ('/dev/sdb', '', '')]
    assert entries[1]['commands'] == []


def test_later_directives_override_and_comments_and_continuations():
    text = ('/dev/sda -a -m a@x -m b@x \\\n'
            '   -M exec /bin/one # -M exec /bin/ignored\n'
            '/dev/sdb -a -m c@x -M exec /bin/two -M exec /bin/three\n')
    entries = run(text)['entries']
    assert entries[0]['address'] == 'b@x' and entries[0]['exec'] == '/bin/one' and entries[0]['line'] == 2
    assert entries[1]['exec'] == '/bin/three'


def test_backslash_followed_by_text_is_not_a_continuation():
    result = run('/dev/sda -a \\x\n')
    assert result['accepted'] is False and not result['complete'] and result['entries'] == []


def test_syntax_errors_reject_the_whole_file():
    for text in ('/dev/sda -a\n/dev/sdb -X\n', '/dev/sda -a -m\n', '/dev/sda -M exec /bin/x\n',
                 '/dev/sda -m <nomailer>\n', '/dev/sda -m root -M bogus\n', '/dev/sda -m root -M exec\n',
                 '/dev/sda -aa\n', '/dev/sda foo\n', '/dev/sda -a\r\n'):
        result = run(text)
        assert result['accepted'] is False, text
        assert result['entries'] == [] and any(g['code'] == 'config_rejected' for g in result['gaps'])


def test_errors_after_devicescan_are_never_read():
    result = run('DEVICESCAN -m root\n/dev/sda -X\n')
    assert result['accepted'] and result['complete']


def test_line_length_limits():
    assert run('/dev/sda -a' + ' ' * (255 - 11) + '\n')['accepted']
    assert run('/dev/sda -a' + ' ' * (256 - 11) + '\n')['accepted'] is False
    # The final line without a newline may use all 256 bytes.
    assert run('/dev/sda -a' + ' ' * (256 - 11))['accepted']
    long_continued = ''.join('-a ' * 60 + '\\\n' for _ in range(6)) + '-a\n'
    assert run('/dev/sda ' + long_continued)['accepted'] is False


def test_nomailer_runs_exec_without_arguments():
    entry = run('/dev/sda -a -m <nomailer> -M exec /usr/share/smartmontools/smartd-runner\n')['entries'][0]
    mailer = entry['commands'][1]
    assert entry['address'] == '' and mailer['arguments'] == [] and mailer['stdin'] == '/dev/null'
    assert entry['commands'][2]['arguments'] == ['<message file>', '', '', '']


def test_plugins_and_plain_addresses():
    entry = run('/dev/sda -a -m @ALL,@notify,admin@x -M exec mailx\n')['entries'][0]
    steps = entry['commands']
    assert [s['step'] for s in steps] == ['warning_script', 'plugin', 'plugin', 'mailer']
    assert steps[1]['command'] == '/etc/smartmontools/smartd_warning.d/*' and steps[1]['all_plugins']
    assert steps[2]['command'] == '/etc/smartmontools/smartd_warning.d/notify'
    assert steps[3]['command'] == 'mailx' and steps[3]['resolved_via_path']
    assert steps[3]['arguments'] == ['-s', '<subject>', 'admin@x']


def test_plugins_only_skip_the_mailer_even_with_exec():
    entry = run('/dev/sda -a -m @notify -M exec /opt/hook\n')['entries'][0]
    assert [s['step'] for s in entry['commands']] == ['warning_script', 'plugin']


def test_bare_at_sign_is_a_plain_address():
    entry = run('/dev/sda -a -m @\n')['entries'][0]
    assert entry['commands'][-1]['arguments'] == ['-s', '<subject>', '@'] and entry['commands'][-1]['command'] == 'mail'


def test_test_directive_runs_at_startup():
    entry = run('/dev/sda -a -m root -M test\n')['entries'][0]
    assert entry['runs_at_startup']


def test_daemon_options():
    entry = run('/dev/sda -m root\n', {'warn_as_user': 'nobody:nogroup'})['entries'][0]
    assert {s['user'] for s in entry['commands']} == {'nobody:nogroup'}
    result = run('/dev/sda -m root\n', {'warnexec': '/opt/warn'})
    assert [s['step'] for s in result['entries'][0]['commands']] == ['warning_script']
    assert any(g['code'] == 'custom_warning_script' for g in result['gaps']) and result['complete']
    unobserved = run('/dev/sda -m root\n', None)
    assert not unobserved['complete'] and unobserved['entries']
    assert not run('/dev/sda -m root\n', {'bogus': 1})['complete']
    assert not run('/dev/sda -m root\n', {'warn_as_user': 'a b'})['complete']


def test_config_states():
    absent = run(None, state='absent')
    assert absent['complete'] and absent['entries'][0]['implicit'] and absent['entries'][0]['commands'] == []
    assert not run(None, state='unreadable')['complete']
    assert not run('x', state=None)['complete']
    assert not run('a\x00b')['complete']
    assert not run('#' * (sw.MAX_BYTES + 1))['complete']
