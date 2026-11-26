"""Pure rsyncd.conf exec-command contract (#1395)."""
from app import rsyncd_exec as rx


def run(text):
    return rx.evaluate(text=text)


def cmds(result):
    return [(c['module'], c['kind'], c['command']) for c in result['commands']]


def test_module_commands_run_as_daemon_user_in_connection_order():
    r = run('[backup]\n path = /srv\n uid = nobody\n pre-xfer exec = /usr/local/bin/pre\n'
            ' post-xfer exec = /usr/local/bin/post\n early exec = /e\n name converter = /n\n')
    assert r['status'] == 'evaluated' and r['complete'] and r['origin'] == 'not_assessed'
    assert cmds(r) == [('backup', 'post-xfer exec', '/usr/local/bin/post'), ('backup', 'early exec', '/e'),
                       ('backup', 'pre-xfer exec', '/usr/local/bin/pre'), ('backup', 'name converter', '/n')]
    pre = r['commands'][2]
    assert pre['runs_as'] == 'rsync daemon starting user' and pre['module_uid_applies'] is False
    assert pre['when'] == 'before_transfer_can_refuse' and pre['line'] == 4 and not pre['from_global_default']
    assert len(pre['command_sha256']) == 64 and pre['root_dir'] == '/'


def test_daemon_uid_gid_and_chroot_are_reported():
    r = run('daemon uid = rsync\ndaemon gid = rsync\ndaemon chroot = /jail\n[m]\npath=/d\npre-xfer exec=/x\n'
            'daemon uid = root\n')
    [c] = r['commands']
    # A global parameter inside a module is ignored.
    assert r['daemon'] == {'uid': 'rsync', 'gid': 'rsync', 'chroot': '/jail'}
    assert (c['runs_as'], c['runs_as_group'], c['root_dir']) == ('rsync', 'rsync', '/jail')


def test_labels_ignore_case_and_whitespace_but_not_hyphens_or_dash_prefix():
    r = run('[m]\npath=/d\nPRE-XFER   EXEC=/a\n[n]\npath=/d\npre-xferexec = /b\n[o]\npath=/d\nprexferexec=/c\n'
            '-pre-xfer exec = /d\n')
    assert cmds(r) == [('m', 'pre-xfer exec', '/a'), ('n', 'pre-xfer exec', '/b')]


def test_global_defaults_are_copied_at_module_creation_and_final_default_fills_unset():
    r = run('pre-xfer exec = /first\n[a]\npath=/d\n[global]\npre-xfer exec = /second\npost-xfer exec = /late\n'
            '[b]\npath=/d\n')
    assert cmds(r) == [('a', 'post-xfer exec', '/late'), ('a', 'pre-xfer exec', '/first'),
                       ('b', 'post-xfer exec', '/late'), ('b', 'pre-xfer exec', '/second')]
    assert all(c['from_global_default'] for c in r['commands'])


def test_empty_value_disables_and_repeated_section_reuses_module():
    r = run('pre-xfer exec = /g\n[a]\npath=/d\npre-xfer exec =\n[ A ]\nearly exec = /e\n')
    assert r['modules'] == [{'name': 'a', 'reachable': True, 'path': '/d', 'refused': None}]
    assert cmds(r) == [('a', 'early exec', '/e')]


def test_module_without_path_and_shadowed_module_run_nothing():
    r = run('[a]\npre-xfer exec=/x\n[b]\npath=/d\nname = c\npre-xfer exec=/y\n[d]\npath=/d\nname = c\n'
            'pre-xfer exec=/z\n[c]\nearly exec=/e\n')
    # [c] reuses the module now named c (the renamed [d]); the earlier c is unreachable.
    assert [m['refused'] for m in r['modules']] == ['no_path', 'shadowed_by_later_module', None]
    assert cmds(r) == [('c', 'early exec', '/e'), ('c', 'pre-xfer exec', '/z')]


def test_continuation_comments_bogus_backslash_and_carriage_return():
    r = run('# [x]\n; pre-xfer exec = /no\n[m]\r\npath = /d\n\\pre-xfer exec = /bin/a \\\n   b\r\n'
            'lone line without equals\npost-xfer exec = /p  \n')
    assert cmds(r) == [('m', 'post-xfer exec', '/p'), ('m', 'pre-xfer exec', '/bin/a    b')]


def test_rejected_configurations_run_nothing():
    for text in ('[a/b]\npath=/d\npre-xfer exec=/x\n', '[]\n', '[open\npre-xfer exec=/x\n',
                 '[m]\npath=/d\n= value\n', '&bogus /x\n'):
        r = run(text)
        assert r['status'] == 'config_rejected' and r['commands'] == [], text


def test_fail_closed_inputs():
    assert run(None)['status'] == 'not_observed' and not run(None)['complete']
    assert run(b'[m]\npath=/d\npre-xfer exec=/x\0y\n')['gaps'][0]['code'] == 'nul_byte'
    assert run(b'#' * (rx.MAX_TEXT + 1))['gaps'][0]['code'] == 'over_limit'
    r = run('&include /etc/rsyncd.d\n[m]\npath=/d\npre-xfer exec=/x\n')
    assert not r['complete'] and r['gaps'][0]['code'] == 'include_not_modelled' and cmds(r)
    r = run('&MERGE = /etc/rsyncd.d\n')
    assert r['gaps'][0]['code'] == 'include_not_modelled'
    r = run('[m]\npath=/d\npre-xfer exec=/bin/%HOOK%\n')
    assert r['commands'][0]['env_expansion'] and r['gaps'][0]['code'] == 'env_expansion'
