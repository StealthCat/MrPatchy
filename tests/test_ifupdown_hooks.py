import os
import shutil
import subprocess

import pytest

from app import ifupdown_hooks as ih

TOP = '/etc/network/interfaces'
SCRIPT = {'type': 'file', 'mode': 0o755, 'noexec': False}


def _hook_dirs(entries=None):
    return {phase: {'state': 'listed', 'entries': list(entries or [])} for phase in ih.PHASES}


def _run(text, extra=None, directories=None, hook_dirs=None, **kw):
    files = {TOP: {'state': 'read', 'text': text}}
    files.update(extra or {})
    kw.setdefault('family', 'debian')
    kw.setdefault('ifupdown_installed', True)
    return ih.assess(files, directories, _hook_dirs() if hook_dirs is None else hook_dirs, **kw)


def _stanza(result, logical, family=None):
    return next(s for s in result['stanzas'] if s['logical'] == logical and (family is None or s['family'] == family))


def _commands(stanza, phase):
    return [h['command'] for h in stanza['hooks'][phase]]


def test_hook_aliases_order_ignore_status_and_provenance():
    result = _run(
        'auto eth0\n'
        'iface eth0 inet static\n'
        '    address 192.0.2.1/24\n'
        '    pre-up /sbin/a\n'
        '    up /sbin/b\n'
        '    post-up -/sbin/c\n'
        '    pre-down /sbin/d\n'
        '    down /sbin/e\n'
        '    post-down /sbin/f\n'
        '    pre-up /sbin/a2\n'
    )
    assert result['config_state'] == 'accepted' and result['complete'] is True
    eth0 = _stanza(result, 'eth0')
    assert _commands(eth0, 'pre-up') == ['/sbin/a', '/sbin/a2']
    assert _commands(eth0, 'up') == ['/sbin/b', '/sbin/c']
    assert eth0['hooks']['up'][1]['ignore_status'] is True and eth0['hooks']['up'][1]['written_as'] == 'post-up'
    assert _commands(eth0, 'down') == ['/sbin/d', '/sbin/e']
    assert _commands(eth0, 'post-down') == ['/sbin/f']
    assert eth0['hooks']['pre-up'][1]['line'] == 10 and eth0['hooks']['pre-up'][1]['file'] == TOP
    assert eth0['activation'] == ['auto'] and eth0['environment'] == ['IF_ADDRESS']
    assert result['up_sequence'][0] == 'hooks:pre-up' and result['down_sequence'][0] == 'run-parts:down'
    assert result['runs_as'] == 'root' and result['shell'] == ('/bin/sh', '-c')
    assert result['origin'] == 'not_assessed'


def test_comments_and_continuations_follow_get_line():
    text = (
        '   # indented comment \\\n'
        'iface eth0 inet manual\n'
        '  up echo one \\\n'
        '# not a comment once continued\n'
        '  up echo two \\  \n'
        '  up echo three # inline hash is not a comment\n'
    )
    eth0 = _stanza(_run(text), 'eth0')
    assert _commands(eth0, 'up') == [
        'echo one # not a comment once continued',
        'echo two \\',
        'echo three # inline hash is not a comment',
    ]
    assert eth0['hooks']['up'][0]['line'] == 3 and eth0['hooks']['up'][2]['line'] == 6


def test_implicit_loopback_only_without_a_loopback_stanza():
    implicit = _run('iface eth0 inet dhcp\n')
    lo = _stanza(implicit, 'lo')
    assert lo['implicit'] is True and lo['activation'] == ['auto']
    explicit = _run('auto lo\niface lo inet loopback\n  up /bin/true\n')
    assert [s['logical'] for s in explicit['stanzas']] == ['lo']
    assert explicit['stanzas'][0]['implicit'] is False


@pytest.mark.parametrize('text,line', [
    ('  up /bin/x\n', 1),
    ('iface eth0 inet dhcp\nauto eth1\n  up /bin/x\n', 3),
    ('iface eth0 inet dhcp\n  up\n', 2),
    ('iface eth0 inet bogus\n', 1),
    ('iface eth0 bogus dhcp\n', 1),
    ('iface eth0 inet\n', 1),
    ('iface eth1 inet dhcp inherits missing\n', 1),
    ('mapping eth*\n  script /x\n  script /y\n', 3),
    ('mapping eth*\n  up /x\n', 2),
])
def test_top_level_parse_errors_reject_the_whole_configuration(text, line):
    result = _run(text)
    assert result['config_state'] == 'rejected'
    assert result['stanzas'] == [] and result['mappings'] == []
    assert result['files'][0]['error']['line'] == line


def test_auto_without_arguments_keeps_the_stanza_open():
    eth0 = _stanza(_run('iface eth0 inet dhcp\nauto\nallow-hotplug\n  up /bin/x\n'), 'eth0')
    assert eth0['activation'] == ['auto', 'hotplug'] and _commands(eth0, 'up') == ['/bin/x']


def test_include_error_keeps_earlier_definitions_and_parent_continues():
    result = _run(
        'source a\niface eth9 inet manual\n  up /bin/after\n',
        {'/etc/network/a': {'state': 'read', 'text': 'iface eth1 inet manual\n  up /bin/kept\nauto eth1\n'
                                                     '  up /bin/lost\niface eth2 inet manual\n'}},
    )
    assert result['config_state'] == 'accepted'
    assert _commands(_stanza(result, 'eth1'), 'up') == ['/bin/kept']
    assert all(s['logical'] != 'eth2' for s in result['stanzas'])
    assert _commands(_stanza(result, 'eth9'), 'up') == ['/bin/after']
    assert result['include_errors'] == [{'path': '/etc/network/a', 'line': 4, 'message': 'misplaced option'}]


def test_option_after_source_line_is_misplaced():
    result = _run('iface eth0 inet manual\nsource a\n  up /bin/x\n', {'/etc/network/a': {'state': 'absent'}})
    assert result['config_state'] == 'rejected'


def test_source_glob_and_source_directory_rules():
    files = {
        '/etc/network/interfaces.d/b': {'state': 'read', 'text': 'iface b inet manual\n  up /bin/b\n'},
        '/etc/network/interfaces.d/a.cfg': {'state': 'read', 'text': 'iface a inet manual\n  up /bin/a\n'},
        '/etc/network/interfaces.d/Z': {'state': 'read', 'text': 'iface z inet manual\n'},
        '/etc/network/interfaces.d/.h': {'state': 'read', 'text': 'iface h inet manual\n'},
    }
    listing = {'/etc/network/interfaces.d': {'state': 'listed', 'names': ['b', 'a.cfg', 'Z', '.h']}}
    glob = _run('source interfaces.d/*\n', files, listing)
    assert [s['logical'] for s in glob['stanzas']] == ['lo', 'z', 'a', 'b']
    directory = _run('source-directory /etc/network/interfaces.d\n', files, listing)
    # source-directory skips names with dots and reads in byte order.
    assert [s['logical'] for s in directory['stanzas']] == ['lo', 'z', 'b']
    assert directory['complete'] is True


def test_missing_includes_are_skipped_and_a_file_is_parsed_once():
    result = _run(
        'source gone\nsource-dir /nowhere\nsource again\nsource again\n',
        {'/etc/network/gone': {'state': 'absent'},
         '/etc/network/again': {'state': 'read', 'text': 'iface x inet manual\n  up /bin/x\n'}},
        {'/nowhere': {'state': 'absent'}},
    )
    assert result['complete'] is True
    assert [s['logical'] for s in result['stanzas']] == ['lo', 'x']


def test_self_include_by_same_path_is_skipped_but_alias_loops_hit_depth_gap():
    same = _run('source interfaces\niface e inet manual\n')
    assert same['complete'] is True and [s['logical'] for s in same['stanzas']] == ['lo', 'e']
    alias = _run('source ./interfaces\n')
    assert alias['complete'] is False
    assert any(g['code'] == 'include_depth_exceeded' for g in alias['gaps'])


@pytest.mark.parametrize('rest', ['$HOME/x', '"a b"', 'a b', '`x`', 'dir*/x', 'a\\b'])
def test_unmodeled_include_patterns_are_blocking(rest):
    result = _run(f'source {rest}\n')
    assert result['complete'] is False
    assert any(g['code'] == 'include_pattern_unmodeled' for g in result['gaps'])


def test_wordexp_bad_characters_read_nothing():
    result = _run('source a;b\nsource x|y\n')
    assert result['complete'] is True and [s['logical'] for s in result['stanzas']] == ['lo']


def test_unobserved_include_file_or_directory_is_blocking():
    file_gap = _run('source a\n')
    assert file_gap['complete'] is False and file_gap['gaps'][0]['code'] == 'file_not_observed'
    dir_gap = _run('source-directory d\n')
    assert dir_gap['complete'] is False and dir_gap['gaps'][0]['code'] == 'directory_not_observed'
    glob_gap = _run('source d/*\n')
    assert glob_gap['gaps'][0]['code'] == 'directory_not_observed'


def test_inherits_copies_hooks_first_and_family_filter_applies():
    result = _run(
        'iface base inet manual\n  up /bin/base\n  mtu 9000\n'
        'iface base inet6 manual\n  up /bin/base6\n'
        'iface child inet dhcp inherits base\n  up /bin/child\n'
        'iface any inherits base\n'
        'iface fam inet6 inherits base\n'
        'iface extra inet dhcp junk inherits base\n'
    )
    child = _stanza(result, 'child')
    assert _commands(child, 'up') == ['/bin/base', '/bin/child']
    assert child['hooks']['up'][0]['inherited'] is True and child['environment'] == ['IF_MTU']
    assert child['inherits'] == {'logical': 'base', 'file': TOP, 'line': 1}
    anyfam = _stanza(result, 'any')
    assert anyfam['family'] == 'inet' and anyfam['method'] == 'manual' and _commands(anyfam, 'up') == ['/bin/base']
    fam = _stanza(result, 'fam')
    assert fam['method'] == 'manual' and _commands(fam, 'up') == ['/bin/base6']
    # A non-keyword extra word is ignored and ifupdown reads nothing after it.
    assert _stanza(result, 'extra')['inherits'] is None


def test_no_scripts_patterns_suppress_only_run_parts():
    result = _run('iface eth0 inet manual\n  up /bin/x\nno-scripts eth*\niface wlan0 inet manual\nno-scripts\n')
    eth0, wlan0 = _stanza(result, 'eth0'), _stanza(result, 'wlan0')
    assert eth0['no_scripts'] is True and _commands(eth0, 'up') == ['/bin/x']
    assert wlan0['no_scripts'] is True and _stanza(result, 'lo')['no_scripts'] is False


def test_mapping_scripts_are_reported():
    result = _run('mapping eth0 eth1\n  script /usr/local/sbin/map\n  map home eth0-home\n')
    assert result['mappings'][0]['script'] == {'command': '/usr/local/sbin/map', 'file': TOP, 'line': 2}
    assert result['mappings'][0]['matches'] == ['eth0', 'eth1']


def test_env_names_match_setlocalenv():
    assert ih.env_name('dns-nameservers') == 'IF_DNS_NAMESERVERS'
    assert ih.env_name('wpa.conf') == 'IF_WPACONF'


def test_run_parts_outcomes_and_byte_order():
    entries = [
        dict(SCRIPT, name='upstart'),
        dict(SCRIPT, name='Zed'),
        dict(SCRIPT, name='000resolvconf'),
        dict(SCRIPT, name='x.sh'),
        {'name': 'off', 'type': 'file', 'mode': 0o644, 'noexec': False},
        {'name': 'mnt', 'type': 'file', 'mode': 0o755, 'noexec': True},
        {'name': 'unk', 'type': 'file', 'mode': 0o755},
        {'name': 'sub', 'type': 'directory'},
        {'name': 'fifo', 'type': 'other'},
        {'name': 'link', 'type': 'symlink', 'target': dict(SCRIPT)},
        {'name': 'dangling', 'type': 'symlink', 'target': None},
    ]
    result = _run('', hook_dirs=_hook_dirs(entries))
    scripts = result['run_parts']['up']['scripts']
    assert [(s['name'], s['outcome']) for s in scripts] == [
        ('000resolvconf', 'runs'), ('Zed', 'runs'), ('dangling', 'stat_failed'), ('fifo', 'not_plain_file'),
        ('link', 'runs'), ('mnt', 'noexec_mount'), ('off', 'not_executable'), ('sub', 'directory'),
        ('unk', 'runs'), ('upstart', 'runs'), ('x.sh', 'name_rejected'),
    ]
    assert result['run_parts']['up']['command'] == ('/bin/run-parts', '--exit-on-error', '/etc/network/if-up.d')
    assert result['complete'] is True
    assert any(g['code'] == 'mount_flags_unobserved' for g in result['gaps'])


def test_run_parts_unobserved_or_unresolved_is_blocking():
    missing = ih.assess({TOP: {'state': 'read', 'text': ''}}, family='debian', ifupdown_installed=True)
    assert missing['complete'] is False and missing['run_parts']['pre-up']['state'] == 'not_observed'
    link = _run('', hook_dirs=_hook_dirs([{'name': 'l', 'type': 'symlink'}]))
    assert link['complete'] is False and link['run_parts']['up']['scripts'][0]['outcome'] == 'unresolved'


def test_applicability_and_fail_closed_inputs():
    assert _run('', family='rpm')['applicability'] == 'not_applicable'
    assert _run('', ifupdown_installed=False)['applicability'] == 'not_applicable'
    unknown = _run('', family=None, ifupdown_installed=None)
    assert unknown['applicability'] == 'unknown' and unknown['complete'] is False
    assert {'family_not_observed', 'implementation_not_observed'} <= {g['code'] for g in unknown['gaps']}
    absent = ih.assess({TOP: {'state': 'absent'}}, None, _hook_dirs(), family='debian', ifupdown_installed=True)
    assert absent['config_state'] == 'absent' and [s['logical'] for s in absent['stanzas']] == ['lo']
    unread = ih.assess({TOP: {'state': 'unreadable'}}, None, _hook_dirs(), family='debian', ifupdown_installed=True)
    assert unread['config_state'] == 'not_observed' and unread['complete'] is False and unread['stanzas'] == []
    assert ih.assess('nope')['complete'] is False
    truncated = ih.assess({TOP: {'state': 'read', 'text': '', 'truncated': True}}, None, _hook_dirs(),
                          family='debian', ifupdown_installed=True)
    assert truncated['complete'] is False


RUN_PARTS = shutil.which('run-parts')


@pytest.mark.skipif(RUN_PARTS is None or os.geteuid() != 0, reason='needs debianutils run-parts as root')
def test_run_parts_name_rule_and_order_match_the_real_binary(tmp_path):
    names = ['000resolvconf', 'Zed', 'upstart', 'x.sh', 'a_b-c', 'B', 'b', '_x', '-y', '.hidden', 'x~', 'a.b']
    entries = []
    for name in names:
        path = tmp_path / name
        path.write_text('#!/bin/sh\n')
        path.chmod(0o755)
        entries.append(dict(SCRIPT, name=name))
    listed = subprocess.run([RUN_PARTS, '--list', str(tmp_path)], capture_output=True, text=True, check=True,
                            env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')})
    expected = [line.rsplit('/', 1)[1] for line in listed.stdout.splitlines()]
    result = _run('', hook_dirs=_hook_dirs(entries))
    assert [s['name'] for s in result['run_parts']['up']['scripts'] if s['outcome'] == 'runs'] == expected
