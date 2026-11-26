"""Tests for the pure rsnapshot command contract (#1530).

Native evidence: rsnapshot 1.4.5-2 on Ubuntu 24.04 (perl 5.38.2, rsync 3.2.7),
run as root with ``rsnapshot -c <file> alpha`` and traced with
``strace -f -e trace=execve``. Each test that reproduces a native run says what
was observed. Hook scripts appended ``argv`` and ``pwd`` to a log.
"""
from __future__ import annotations

from app import rsnapshot_commands as rc

CONF = rc.DEFAULT_CONFIG
BASE = (
    'config_version\t1.2\n'
    'snapshot_root\t/srv/snap/\n'
    'cmd_rsync\t/usr/bin/rsync\n'
    'retain\talpha\t2\n'
    'backup\t/srv/src/\tlocal/\n'
)


def assess(text, *extra, path=CONF):
    files = [{'path': path, 'state': 'regular', 'text': text}, *extra]
    return rc.assess_config(files, config_path=path)


def cmds(result):
    return [(c['kind'], c['command']) for c in result['commands']]


def program(result, key, effective=True):
    return next(p for p in result['programs'] if p['key'] == key and p['effective'] is effective)


def test_native_hooks_order_cwd_and_dropped_field():
    """Native: pre ran with argv "pre one" from /root (the extra tab field was
    dropped), the backup_script from <snapshot_root>/tmp, the backup_exec and
    post from /root. Only post (with ``;`` and ``$``) went through /bin/sh."""
    result = assess(BASE + 'cmd_preexec\t/usr/local/sbin/hook pre one\tdropped-field\n'
                    'cmd_postexec\t/usr/local/sbin/hook post; echo $HOME >> /tmp/log\n'
                    'backup_script\t/usr/local/sbin/hook script\tscr/\n'
                    'backup_exec\t/usr/local/sbin/hook exec\n')
    assert result['complete'] is True and result['rejected_by_parser'] is False
    assert cmds(result) == [
        ('cmd_preexec', '/usr/local/sbin/hook pre one'),
        ('cmd_postexec', '/usr/local/sbin/hook post; echo $HOME >> /tmp/log'),
        ('backup_script', '/usr/local/sbin/hook script'),
        ('backup_exec', '/usr/local/sbin/hook exec'),
    ]
    pre, post, script, exec_ = result['commands']
    assert pre['dropped_fields'] == ['dropped-field']
    assert pre['via_shell'] is False and pre['argv'] == ['/usr/local/sbin/hook', 'pre', 'one']
    assert pre['cwd'] == '$HOME' and pre['on_failure'] == 'aborts_rsnapshot'
    assert post['via_shell'] is True and post['argv'][:2] == ['/bin/sh', '-c']
    assert script['cwd'] == '<snapshot_root>/tmp/' and script['destination'] == 'scr/'
    assert script['on_failure'] == 'rolls_back_destination'
    assert exec_['importance'] == 'optional' and exec_['on_failure'] == 'warning'
    assert all(c['run_as'] == 'invoking_user' for c in result['commands'])
    assert result['backup_commands_run'] == 'if_host_checks_pass'
    assert result['origin'] == 'not_assessed'


def test_native_last_preexec_wins_but_both_are_listed():
    """Native: only "second" ran."""
    result = assess(BASE + 'cmd_preexec\t/usr/local/sbin/hook first\n'
                    'cmd_preexec\t/usr/local/sbin/hook second\n')
    first, second = result['commands']
    assert first['effective'] is False and second['effective'] is True


def test_native_continuation_is_joined_with_a_tab_and_dropped_from_a_hook():
    """Native: "cmd_preexec <hook> pre" followed by "  extra-cont" ran "pre" only."""
    result = assess(BASE + 'cmd_preexec\t/usr/local/sbin/hook pre\n  extra-cont\n')
    assert result['commands'][0]['command'] == '/usr/local/sbin/hook pre'
    assert result['commands'][0]['dropped_fields'] == ['extra-cont']


def test_native_hash_led_continuation_is_not_a_comment():
    """Native: a "\\t# ..." line after backup_exec became its importance field and
    rejected the whole configuration."""
    result = assess(BASE + 'backup_exec\t/usr/local/sbin/hook\n\t# comment-like\n')
    assert result['rejected_by_parser'] is True
    assert [e['reason'] for e in result['config_errors']] == ['backup_exec_importance_invalid']
    assert result['backup_commands_run'] is False


def test_native_required_backup_exec_failure_aborts_and_optional_warns():
    """Native: a failing "required" backup_exec stopped the run before the next
    backup_exec and cmd_postexec; a failing optional one did not."""
    result = assess(BASE + 'backup_exec\t/usr/local/sbin/fail x\trequired\n'
                    'backup_exec\t/usr/local/sbin/hook after\n')
    required, optional = result['commands']
    assert required['on_failure'] == 'aborts_rsnapshot' and required['importance'] == 'required'
    assert optional['on_failure'] == 'warning'


def test_native_backup_exec_path_is_not_checked_and_may_use_the_shell():
    """Native: "echo relative-exec >> log" ran through /bin/sh."""
    result = assess(BASE + 'backup_exec\techo relative-exec >> /tmp/log\n')
    entry = result['commands'][0]
    assert entry['path_checked'] is False and entry['via_shell'] is True
    assert result['rejected_by_parser'] is False


def test_native_backtick_include_runs_even_when_the_config_is_rejected():
    """Native: with an unknown directive earlier in the file, both
    ``rsnapshot configtest`` and ``rsnapshot alpha`` still ran the include
    command, then refused to back up, so cmd_preexec never ran."""
    result = assess(BASE + 'bogus_directive\tx\n'
                    'include_conf\t`/usr/local/sbin/inc arg1`\n'
                    'cmd_preexec\t/usr/local/sbin/hook pre\n')
    inc, pre = result['commands']
    assert inc['kind'] == 'include_conf_command'
    assert inc['argv'] == ['/usr/local/sbin/inc', 'arg1']
    assert 'configtest' in inc['when'] and 'runs_only_if_config_accepted' not in inc
    assert pre['runs_only_if_config_accepted'] is True
    assert result['rejected_by_parser'] is True and result['complete'] is False
    assert [g['reason'] for g in result['gaps']] == ['include_conf_command_output_not_modelled']


def test_native_include_cycle_aborts_before_any_backup():
    """Native: a self-include failed with "Could not open config file" and
    nothing ran."""
    result = assess(BASE + f'include_conf\t{CONF}\nbackup_exec\t/usr/local/sbin/hook\n')
    assert result['rejected_by_parser'] is True
    assert result['config_errors'][0]['reason'] == 'include_conf_cycle_aborts'
    assert result['commands'] == [] and result['backup_commands_run'] is False


def test_native_final_zero_line_stops_parsing_but_a_zero_line_with_newline_is_an_error():
    """Native: a last line "0" with no newline was ignored; "0\\n" was a config error."""
    assert assess(BASE + 'backup_exec\t/bin/true\n0')['rejected_by_parser'] is False
    assert assess(BASE + 'backup_exec\t/bin/true\n0\n')['rejected_by_parser'] is True


def test_native_relative_hook_and_spaces_reject_the_config():
    """Native: both were "on line N" config errors and nothing ran."""
    rel = assess(BASE + 'cmd_preexec\tbin/hook pre\n')
    assert rel['config_errors'][0]['reason'] == 'hook_script_not_absolute'
    assert rel['commands'] == []
    spaces = assess(BASE + 'cmd_preexec /usr/local/sbin/hook\n')
    assert spaces['config_errors'][0]['reason'] == 'spaces_instead_of_tabs'


def test_included_file_is_parsed_in_place_and_records_its_parent():
    inc = {'path': '/etc/rsnapshot.d/hooks.conf', 'state': 'regular',
           'text': 'cmd_postexec\t/usr/local/sbin/hook post\n'}
    result = assess(BASE + 'include_conf\t/etc/rsnapshot.d/hooks.conf\n', inc)
    assert cmds(result) == [('cmd_postexec', '/usr/local/sbin/hook post')]
    assert result['commands'][0]['file'] == '/etc/rsnapshot.d/hooks.conf'
    assert result['files'][1]['included_from'] == {'file': CONF, 'line': 6}


def test_missing_include_rejects_and_unobserved_include_is_a_gap():
    absent = assess(BASE + 'include_conf\t/etc/x.conf\n',
                    {'path': '/etc/x.conf', 'state': 'absent'})
    assert absent['config_errors'][0]['reason'] == 'include_conf_file_not_readable'
    unseen = assess(BASE + 'include_conf\t/etc/x.conf\n')
    assert unseen['complete'] is False and unseen['gaps'][0]['reason'] == 'file_not_observed'


def test_missing_main_config_runs_nothing():
    result = rc.assess_config([{'path': CONF, 'state': 'absent'}])
    assert result['rejected_by_parser'] is True and result['commands'] == []
    assert result['programs'] == []


def test_program_paths_defaults_and_superseded_values():
    result = assess(BASE + 'cmd_cp\t/bin/cp  \ncmd_cp\t/usr/local/bin/cp\n'
                    'cmd_logger\t/usr/bin/logger\n'
                    'linux_lvm_cmd_lvcreate\t/sbin/lvcreate --verbose\n')
    assert program(result, 'cmd_rsync')['argv_prefix'] == ['/usr/bin/rsync']
    assert program(result, 'cmd_cp')['path'] == '/usr/local/bin/cp'
    assert program(result, 'cmd_cp', effective=False)['path'] == '/bin/cp'
    assert program(result, 'cmd_rm')['configured'] is False
    assert program(result, 'cmd_rm')['default'] == 'perl_native_rm_rf'
    lvm = program(result, 'linux_lvm_cmd_lvcreate')
    assert lvm['argv_prefix'] == ['/sbin/lvcreate', '--verbose'] and lvm['via_shell'] is False


def test_ssh_backup_requires_an_earlier_cmd_ssh():
    late = assess(BASE + 'backup\troot@db:/etc/\tdb/\ncmd_ssh\t/usr/bin/ssh\n')
    assert late['config_errors'][0]['reason'] == 'ssh_backup_without_cmd_ssh'
    ok = assess(BASE + 'cmd_ssh\t/usr/bin/ssh\nbackup\troot@db:/etc/\tdb/\n')
    assert ok['rejected_by_parser'] is False and ok['ssh_backup_points'] == 1


def test_backup_script_needs_snapshot_root_first_and_a_relative_destination():
    early = assess('backup_script\t/usr/local/sbin/hook\tx/\n' + BASE)
    assert early['config_errors'][0]['reason'] == 'snapshot_root_not_yet_defined'
    escape = assess(BASE + 'backup_script\t/usr/local/sbin/hook\t../x/\n')
    assert escape['config_errors'][0]['reason'] == 'backup_script_destination_not_relative'


def test_cmd_rsync_is_required():
    result = assess(BASE.replace('cmd_rsync\t/usr/bin/rsync\n', ''))
    assert any(e['reason'] == 'cmd_rsync_required' for e in result['config_errors'])


def test_perl_shell_selection_rules():
    assert rc.perl_uses_shell('/bin/x a b') is False
    assert rc.perl_uses_shell('/bin/x a\n') is False
    assert rc.perl_uses_shell('/bin/x a\nb') is True
    assert rc.perl_uses_shell('FOO=1 /bin/x') is True
    assert rc.perl_uses_shell('exec /bin/x') is True
    assert rc.perl_uses_shell('. /etc/profile') is True
    assert rc.perl_uses_shell('/bin/x ~/y') is True
    assert rc.perl_argv('  /bin/x\ta  b ') == ['/bin/x', 'a', 'b']


def test_unsafe_or_unknown_inputs_are_gaps():
    assert rc.assess_config([{'path': CONF, 'state': 'unknown'}])['complete'] is False
    assert rc.assess_config([{'path': CONF, 'state': 'weird'}])['complete'] is False
    assert assess('cmd_preexec\t/bin/x\0\n')['gaps'][0]['reason'] == 'nul_byte'
    big = assess('#' * (rc.MAX_TEXT + 1))
    assert big['gaps'][0]['reason'] == 'file_too_large'
    assert rc.assess_config(None)['gaps'][0]['reason'] == 'file_not_observed'


def test_include_depth_is_bounded():
    files = [{'path': f'/etc/r{i}.conf', 'state': 'regular',
              'text': f'include_conf\t/etc/r{i + 1}.conf\n'} for i in range(40)]
    result = assess(BASE + 'include_conf\t/etc/r0.conf\n', *files)
    assert result['complete'] is False
    assert any(g['reason'] == 'include_depth_limit' for g in result['gaps'])


def test_contract_is_pure_and_never_authorizes_response():
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(rc))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names} | {node.module for node in ast.walk(tree)
                                             if isinstance(node, ast.ImportFrom)}
    assert imported <= {'annotations', '__future__', 're', 'typing', 'Any'}
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not calls & {'open', 'exec', 'eval', '__import__'}
    result = assess(BASE)
    assert 'authorized' not in str(result).lower()
