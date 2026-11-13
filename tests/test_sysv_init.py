from app import sysv_init as sv

SSH_SCRIPT = """#! /bin/sh

### BEGIN INIT INFO
# Provides:\t\tsshd
# Required-Start:\t$remote_fs $syslog
# Required-Stop:\t$remote_fs $syslog
# Default-Start:\t2 3 4 5
# Default-Stop:\t\t
# Short-Description:\tOpenBSD Secure Shell server
# Description: Starts the OpenBSD Secure Shell server
#  so that remote logins are accepted.
# X-Interactive: true
### END INIT INFO

set -e
SECRET_TOKEN=abc123
. /lib/lsb/init-functions
"""

DEBIAN_RC_LOCAL = """#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.

/usr/local/bin/tune-nic eth0
/opt/agent/run --daemon \\
    --config /etc/agent.conf &
if [ -x /usr/local/bin/extra ]; then
    exit 1
fi

exit 0
/usr/local/bin/never-runs
"""


def links(*rows):
    return [{'dir': d, 'name': n, 'target': t} for d, n, t in rows]


def test_debian_lsb_header_fields_without_script_body():
    r = sv.parse_init_script('ssh', SSH_SCRIPT, 0o755)
    assert r['state'] == 'parsed' and r['gaps'] == []
    assert r['interpreter'] == '/bin/sh' and r['executable'] is True and r['origin'] == 'not_assessed'
    lsb = r['lsb']
    assert lsb['provides'] == ['sshd']
    assert lsb['required_start'] == ['$remote_fs', '$syslog']
    assert lsb['default_start'] == ['2', '3', '4', '5'] and lsb['default_stop'] == []
    assert lsb['short_description'] == 'OpenBSD Secure Shell server'
    assert lsb['description'] == 'Starts the OpenBSD Secure Shell server so that remote logins are accepted.'
    assert lsb['extension_fields'] == ['X-Interactive']
    assert len(r['sha256']) == 64 and r['size'] == len(SSH_SCRIPT.encode())
    assert 'abc123' not in repr(r) and 'init-functions' not in repr(r)


def test_missing_unterminated_duplicate_and_invalid_lsb_headers_are_gaps():
    missing = sv.parse_init_script('legacy', '#!/bin/sh\necho hi\n')
    assert missing['state'] == 'partial' and missing['lsb'] is None
    assert [g['code'] for g in missing['gaps']] == ['missing_lsb_header']

    open_block = sv.parse_init_script('x', '#!/bin/sh\n### BEGIN INIT INFO\n# Provides: x\n')
    assert open_block['lsb'] is None and open_block['gaps'][0]['code'] == 'unterminated_lsb_header'

    text = ('#!/bin/sh\n### BEGIN INIT INFO\n# Default-Start: 2 3 9 s\n# Default-Stop: 3\n'
            '# Default-Start: 1\n# Bogus: y\nnot a comment\n### END INIT INFO\n### BEGIN INIT INFO\n### END INIT INFO\n')
    r = sv.parse_init_script('x', text)
    codes = [g['code'] for g in r['gaps']]
    for code in ('duplicate_lsb_header', 'invalid_runlevel', 'duplicate_lsb_field', 'unknown_lsb_field',
                 'malformed_lsb_line', 'missing_provides', 'start_stop_overlap'):
        assert code in codes
    assert r['lsb']['default_start'] == ['S', '2', '3']


def test_script_name_shebang_mode_and_input_limits():
    assert sv.parse_init_script('../evil', '#!/bin/sh\n')['state'] == 'unavailable'
    r = sv.parse_init_script('noexec', SSH_SCRIPT, 0o644)
    assert r['executable'] is False and 'not_executable' in [g['code'] for g in r['gaps']]
    r = sv.parse_init_script('plain', '### BEGIN INIT INFO\n# Provides: plain\n### END INIT INFO\n')
    assert r['interpreter'] is None and r['gaps'][0]['code'] == 'missing_shebang'
    for bad, code in ((b'\xff\xfe', 'invalid_utf8'), ('a\x00b', 'binary'), ('x' * (sv.MAX_TEXT + 1), 'over_limit'),
                      ('\n' * sv.MAX_LINES, 'over_limit'), (None, 'unreadable')):
        r = sv.parse_init_script('s', bad)
        assert r['state'] == 'unavailable' and r['lsb'] is None and r['gaps'][0]['code'] == code


def test_debian_and_rpm_runlevel_links_resolve_to_init_scripts():
    r = sv.parse_rc_links(links(
        ('/etc/rc2.d', 'S01ssh', '../init.d/ssh'),
        ('/etc/rc2.d', 'README', None),
        ('/etc/rc0.d', 'K01ssh', '../init.d/ssh'),
        ('/etc/rc.d/rc3.d/', 'S55sshd', '../init.d/sshd'),
        ('/etc/rcS.d', 'S10udev', '/etc/init.d/udev'),
    ))
    assert r['state'] == 'parsed' and r['gaps'] == []
    by_path = {l['path']: l for l in r['links']}
    assert set(by_path) == {'/etc/rc2.d/S01ssh', '/etc/rc0.d/K01ssh', '/etc/rc.d/rc3.d/S55sshd', '/etc/rcS.d/S10udev'}
    assert by_path['/etc/rc2.d/S01ssh'] | {} == {**by_path['/etc/rc2.d/S01ssh'], 'runlevel': '2', 'action': 'start',
                                                  'order': 1, 'service': 'ssh', 'target': '/etc/init.d/ssh'}
    assert by_path['/etc/rc.d/rc3.d/S55sshd']['target'] == '/etc/rc.d/init.d/sshd'
    assert by_path['/etc/rc0.d/K01ssh']['action'] == 'stop'
    assert [l['runlevel'] for l in r['links']] == ['S', '0', '2', '3']


def test_unusual_runlevel_entries_are_explicit_gaps():
    r = sv.parse_rc_links(links(
        ('/etc/rc2.d', 'S01backdoor', '/tmp/payload'),
        ('/etc/rc2.d', 'S02cron', '../init.d/anacron'),
        ('/etc/rc2.d', 'S03local', None),
        ('/etc/rc2.d', 'start-me', '../init.d/x'),
        ('/etc/rc7.d', 'S01x', '../init.d/x'),
        ('/etc/rc2.d', 'S04y', ''),
    ))
    codes = [g['code'] for g in r['gaps']]
    assert codes == ['target_outside_init_dir', 'name_target_mismatch', 'not_symlink',
                     'unrecognized_link_name', 'unrecognized_directory', 'invalid_target']
    assert r['state'] == 'partial' and len(r['links']) == 3
    payload = next(l for l in r['links'] if l['name'] == 'S01backdoor')
    assert payload['service'] is None and payload['target'] == '/tmp/payload'
    assert sv.parse_rc_links([{'dir': '/etc/rc2.d', 'name': f'S01s{i}', 'target': None}
                              for i in range(sv.MAX_LINKS + 1)]) == {
        'contract_version': 1, 'format': 'rc_links', 'state': 'unavailable', 'links': [],
        'gaps': [{'code': 'over_limit', 'line': None, 'detail': f'More than {sv.MAX_LINKS} runlevel entries.'}]}


def test_effective_services_report_enablement_and_observations():
    ssh = sv.parse_init_script('ssh', SSH_SCRIPT, 0o755)
    idle = sv.parse_init_script('idle', SSH_SCRIPT.replace('sshd', 'idle'), 0o755)
    broken = sv.parse_init_script('broken', SSH_SCRIPT, 0o644)
    rc = sv.parse_rc_links(links(
        ('/etc/rc2.d', 'S01ssh', '../init.d/ssh'), ('/etc/rc3.d', 'S01ssh', '../init.d/ssh'),
        ('/etc/rc3.d', 'K01ssh', '../init.d/ssh'), ('/etc/rc2.d', 'S02broken', '../init.d/broken'),
        ('/etc/rc2.d', 'S03gone', '../init.d/gone'),
    ))
    r = sv.effective_services([ssh, idle, broken], rc)
    services = {s['name']: s for s in r['services']}
    assert services['ssh']['enabled'] is True and services['ssh']['start_runlevels'] == ['2', '3']
    assert services['ssh']['conflicting_runlevels'] == ['3']
    assert services['ssh']['start_orders'] == {'2': 1, '3': 1}
    assert set(services['ssh']['observations']) == {'start_and_stop_links_in_same_runlevel',
                                                     'links_differ_from_lsb_default_start'}
    assert services['idle']['enabled'] is False
    assert 'start_links_to_non_executable_script' in services['broken']['observations']
    assert r['orphan_links'] == [{'path': '/etc/rc2.d/S03gone', 'target': '/etc/init.d/gone', 'service': 'gone'}]
    assert r['state'] == 'partial' and [g['code'] for g in r['gaps']] == ['orphan_links']
    assert all(s['origin'] == 'not_assessed' for s in r['services'])


def test_effective_services_unknown_when_links_unavailable():
    ssh = sv.parse_init_script('ssh', SSH_SCRIPT)
    r = sv.effective_services([ssh, sv.parse_init_script('bad', b'\xff')], {'state': 'unavailable', 'links': [], 'gaps': []})
    assert r['services'][0]['enabled'] is None and r['services'][0]['observations'] == []
    assert [g['code'] for g in r['gaps']] == ['links_unavailable', 'script_unavailable']
    assert sv.effective_services([ssh] * (sv.MAX_SCRIPTS + 1), {'links': []})['state'] == 'unavailable'


def test_rc_local_commands_exit_and_unreachable_lines():
    r = sv.parse_rc_local(DEBIAN_RC_LOCAL, 0o755)
    assert r['interpreter'] == '/bin/sh -e' and r['executable'] is True
    commands = [c['command'] for c in r['commands']]
    assert commands[0] == '/usr/local/bin/tune-nic eth0'
    assert commands[1] == '/opt/agent/run --daemon \n    --config /etc/agent.conf &'
    assert r['commands'][1]['line'] == 8 and r['commands'][1]['background'] is True
    assert 'exit 1' in commands  # indented exit inside a conditional is not the top-level exit
    assert r['exit_line'] == 14 and r['unreachable_commands'] == 1
    # Lines after the top-level exit stay visible, flagged rather than dropped.
    assert r['commands'][-1]['command'] == '/usr/local/bin/never-runs' and r['commands'][-1]['after_exit'] is True
    assert not any(c['after_exit'] for c in r['commands'][:-1])
    assert [g['code'] for g in r['gaps']] == ['unreachable_after_exit']
    assert all(len(c['command_sha256']) == 64 for c in r['commands'])


def test_rc_local_gaps_and_limits():
    r = sv.parse_rc_local('touch /x\ncat <<EOF > /y\nhi\nEOF\nrun \\', 0o600)
    codes = [g['code'] for g in r['gaps']]
    assert codes == ['missing_shebang', 'not_executable', 'heredoc_not_interpreted', 'unterminated_continuation']
    assert r['commands'][0] == {'line': 1, 'command': 'touch /x', 'command_truncated': False,
                                'command_sha256': r['commands'][0]['command_sha256'], 'background': False,
                                'after_exit': False}
    long = sv.parse_rc_local('#!/bin/sh\n' + 'a' * (sv.MAX_COMMAND + 5) + '\n')
    assert long['commands'][0]['command_truncated'] is True and len(long['commands'][0]['command']) == sv.MAX_COMMAND
    over = sv.parse_rc_local('#!/bin/sh\n' + 'true\n' * (sv.MAX_COMMANDS + 1))
    assert over['state'] == 'unavailable' and over['commands'] == []
    assert sv.parse_rc_local(b'\xff')['state'] == 'unavailable'
    assert sv.parse_rc_local('#!/bin/sh\n')['state'] == 'parsed'


def test_rc_local_unindented_exit_inside_construct_is_not_top_level():
    # Review regression: an unindented exit inside an if block must not hide
    # the boot command that runs when the condition is false.
    r = sv.parse_rc_local('#!/bin/sh -e\nif [ ! -f /run/flag ]; then\nexit 0\nfi\n/usr/local/bin/startme &\n', 0o755)
    assert r['exit_line'] is None and r['unreachable_commands'] == 0 and r['gaps'] == []
    startme = r['commands'][-1]
    assert startme['command'] == '/usr/local/bin/startme &' and startme['after_exit'] is False
    assert startme['background'] is True
    # Same for a function body, a brace group, a case arm and a subshell.
    text = ('#!/bin/sh\nf() {\nexit 1\n}\ncase "$1" in\nstop)\nexit 0\n;;\nesac\n'
            '[ -f /x ] || {\nexit 2\n}\n( cd /opt\nexit 3\n)\n/usr/bin/real\nexit 0\n/never\n')
    r = sv.parse_rc_local(text, 0o755)
    assert r['exit_line'] == 17 and r['unreachable_commands'] == 1
    assert [(c['command'], c['after_exit']) for c in r['commands'][-2:]] == [('/usr/bin/real', False), ('/never', True)]
    assert [g['code'] for g in r['gaps']] == ['unreachable_after_exit']


def test_lone_surrogate_text_is_an_invalid_utf8_gap():
    r = sv.parse_rc_local('#!/bin/sh\necho \ud800\n')
    assert r['state'] == 'unavailable' and [g['code'] for g in r['gaps']] == ['invalid_utf8']
    s = sv.parse_init_script('x', '#!/bin/sh\n\ud800')
    assert s['state'] == 'unavailable' and [g['code'] for g in s['gaps']] == ['invalid_utf8']
