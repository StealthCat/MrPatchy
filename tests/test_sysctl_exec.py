"""Tests for the pure systemd-sysctl program-execution contract (#1088)."""
from __future__ import annotations

from app import sysctl_exec as se


def f(path, text, **extra):
    return {'path': path, 'text': text, **extra}


def key(result, name):
    return next(k for k in result['keys'] if k['name'] == name)


def test_core_pattern_pipe_runs_program_from_effective_file():
    r = se.resolve([f('/usr/lib/sysctl.d/50-coredump.conf',
                      'kernel.core_pattern=|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n')])
    k = key(r, 'kernel.core_pattern')
    assert r['complete'] is True
    assert k['state'] == 'configured' and k['executes'] is True
    assert k['program'] == '/usr/lib/systemd/systemd-coredump'
    assert (k['path'], k['line'], k['via']) == ('/usr/lib/sysctl.d/50-coredump.conf', 1, 'explicit')
    assert r['executing_keys'] == ['kernel.core_pattern']
    assert k['origin'] == 'not_assessed' and 'not a safety verdict' in r['not_a_verdict']


def test_plain_core_pattern_runs_nothing():
    k = key(se.resolve([f('/etc/sysctl.d/10-core.conf', 'kernel.core_pattern = core.%p\n')]), 'kernel.core_pattern')
    assert k['executes'] is False and k['program'] is None and k['value'] == 'core.%p'


def test_same_name_in_etc_overrides_usr_lib_and_dev_null_masks():
    usr = f('/usr/lib/sysctl.d/50-coredump.conf', 'kernel.core_pattern=|/usr/lib/systemd/systemd-coredump\n')
    r = se.resolve([usr, f('/etc/sysctl.d/50-coredump.conf', 'kernel.core_pattern=|/tmp/x\n')])
    assert key(r, 'kernel.core_pattern')['program'] == '/tmp/x'
    assert next(x for x in r['files'] if x['path'] == usr['path'])['status'] == 'overridden'
    masked = se.resolve([usr, {'path': '/etc/sysctl.d/50-coredump.conf', 'type': 'symlink',
                               'link_target': '/dev/null'}])
    assert key(masked, 'kernel.core_pattern')['state'] == 'not_configured'
    assert masked['complete'] is True


def test_later_file_name_wins_across_directories():
    r = se.resolve([f('/etc/sysctl.d/10-a.conf', 'kernel.modprobe=/sbin/modprobe\n'),
                    f('/usr/lib/sysctl.d/90-b.conf', 'kernel.modprobe = /usr/local/bin/evil\n')])
    k = key(r, 'kernel.modprobe')
    assert k['program'] == '/usr/local/bin/evil' and k['path'] == '/usr/lib/sysctl.d/90-b.conf'
    assert [a['outcome'] for a in k['assignments']] == ['assigned', 'assigned']


def test_same_value_keeps_earlier_position_and_ors_ignore_failure():
    r = se.resolve([f('/etc/sysctl.d/10-a.conf', 'kernel.poweroff_cmd=/sbin/poweroff -f\n'),
                    f('/etc/sysctl.d/20-b.conf', '-kernel.poweroff_cmd=/sbin/poweroff -f\n')])
    k = key(r, 'kernel.poweroff_cmd')
    assert (k['path'], k['ignore_failure'], k['program']) == ('/etc/sysctl.d/10-a.conf', True, '/sbin/poweroff')
    assert k['assignments'][1]['outcome'] == 'same_value_kept_earlier'


def test_slash_separator_and_leading_slash_normalize():
    assert se.normalize_key('kernel.core_pattern') == 'kernel/core_pattern'
    assert se.normalize_key('kernel/core_pattern') == 'kernel/core_pattern'
    assert se.normalize_key('/kernel//core_pattern') == 'kernel/core_pattern'
    assert se.normalize_key('net.ipv4.conf.eth0/1.rp_filter') == 'net/ipv4/conf/eth0.1/rp_filter'
    r = se.resolve([f('/etc/sysctl.d/a.conf', 'kernel/hotplug = /x/helper\n')])
    k = key(r, 'kernel.hotplug')
    assert k['program'] == '/x/helper' and 'kernel_config_uevent_helper' in k['conditions']


def test_comments_blank_and_non_assignment_lines():
    text = '# kernel.modprobe=/a\n\n   \nkernel.modprobe\nkernel.modprobe = /c\r\n ; not an assignment\n'
    r = se.resolve([f('/etc/sysctl.d/a.conf', text)])
    assert key(r, 'kernel.modprobe')['program'] == '/c'
    assert [g['code'] for g in r['gaps']] == ['line_not_assignment']
    assert r['complete'] is True  # systemd ignores that line too


def test_bare_carriage_return_ends_a_line():
    r = se.resolve([f('/etc/sysctl.d/a.conf', '# comment\rkernel.modprobe=/evil')])
    assert key(r, 'kernel.modprobe')['program'] == '/evil'


def test_glob_applies_without_explicit_and_explicit_wins_regardless_of_order():
    r = se.resolve([f('/etc/sysctl.d/10-a.conf', 'kernel.core_patter? = |/glob/handler\n')])
    k = key(r, 'kernel.core_pattern')
    assert (k['via'], k['pattern'], k['program']) == ('glob', 'kernel/core_patter?', '/glob/handler')
    r = se.resolve([f('/etc/sysctl.d/10-a.conf', 'kernel.core_pattern = core\n'),
                    f('/etc/sysctl.d/90-z.conf', 'kernel.core_* = |/glob/handler\n')])
    k = key(r, 'kernel.core_pattern')
    assert (k['via'], k['executes']) == ('explicit', False)


def test_glob_does_not_cross_components_and_last_glob_written_last():
    assert se.glob_matches('kernel/*', 'kernel/modprobe')
    assert not se.glob_matches('*', 'kernel/modprobe')
    r = se.resolve([f('/etc/sysctl.d/10-a.conf', 'kernel.modprob? = /first\nkernel.mod* = /second\n')])
    assert key(r, 'kernel.modprobe')['program'] == '/second'


def test_overwritten_glob_moves_to_end_of_apply_order():
    r = se.resolve([f('/etc/sysctl.d/10-a.conf', 'kernel.mod* = /one\nkernel.modprob? = /two\n'),
                    f('/etc/sysctl.d/20-b.conf', 'kernel.mod* = /three\n')])
    assert key(r, 'kernel.modprobe')['program'] == '/three'


def test_negative_match_excludes_key_from_globs_only():
    r = se.resolve([f('/etc/sysctl.d/10-a.conf', 'kernel.* = |/glob\n-kernel.core_pattern\n')])
    assert key(r, 'kernel.core_pattern')['state'] == 'excluded_from_globs'
    assert key(r, 'kernel.core_pattern')['executes'] is None
    assert key(r, 'kernel.modprobe')['program'] == '|/glob'


def test_binfmt_register_reports_interpreter():
    r = se.resolve([f('/etc/sysctl.d/a.conf', 'fs.binfmt_misc.register = :evil:E::sh::/tmp/i:\n')])
    k = key(r, 'fs.binfmt_misc.register')
    assert k['executes'] is True and k['program'] == '/tmp/i'
    assert 'binfmt_misc_mounted_at_write_time' in k['conditions']


def test_empty_hotplug_and_modprobe_run_nothing():
    r = se.resolve([f('/etc/sysctl.d/a.conf', 'kernel.hotplug =\nkernel.modprobe = \n')])
    assert key(r, 'kernel.hotplug')['executes'] is False
    assert key(r, 'kernel.modprobe')['executes'] is False
    assert r['executing_keys'] == []


def test_ignored_entries():
    r = se.resolve([f('/etc/sysctl.d/.hidden.conf', 'kernel.modprobe=/a\n'),
                    f('/etc/sysctl.d/x.conf.bak', 'kernel.modprobe=/b\n'),
                    f('/etc/other/x.conf', 'kernel.modprobe=/c\n'),
                    {'path': '/etc/sysctl.d/d.conf', 'type': 'directory'}])
    assert [x['reason'] for x in r['files']] == ['hidden', 'not_conf_suffix', 'outside_known_directories',
                                                  'not_regular_file']
    assert key(r, 'kernel.modprobe')['state'] == 'not_configured'


def test_unreadable_winner_shadows_lower_file_and_is_incomplete():
    r = se.resolve([f('/usr/lib/sysctl.d/a.conf', 'kernel.modprobe=/usr/lib/fallback\n'),
                    f('/etc/sysctl.d/a.conf', None)])
    assert r['complete'] is False
    assert key(r, 'kernel.modprobe')['state'] == 'not_configured'
    assert any(g['code'] == 'file_unreadable' for g in r['gaps'])


def test_fail_closed_input_gaps():
    for text, code in ((b'\xff', 'invalid_utf8'), ('a\x00b', 'nul_byte'), ('x' * (se.MAX_TEXT + 1), 'text_over_limit')):
        r = se.resolve([f('/etc/sysctl.d/a.conf', text)])
        assert r['complete'] is False and r['gaps'][0]['code'] == code
    r = se.resolve([{'path': '/etc/sysctl.d/a.conf', 'type': 'symlink', 'link_target': '/opt/x.conf'}])
    assert r['complete'] is False and r['gaps'][0]['code'] == 'symlink_not_followed'
    assert se.resolve(None)['complete'] is False
    assert se.resolve([{'path': 'relative'}])['complete'] is False
    dup = se.resolve([f('/etc/sysctl.d/a.conf', ''), f('/etc/sysctl.d/a.conf', '')])
    assert dup['gaps'][0]['code'] == 'duplicate_path' and dup['complete'] is False
    many = se.resolve([f(f'/etc/sysctl.d/{i}.conf', '') for i in range(se.MAX_FILES + 1)])
    assert many['complete'] is False and many['gaps'][0]['code'] == 'too_many_files'


def test_sysctl_conf_read_through_link_or_reported_for_procps():
    conf = f('/etc/sysctl.conf', 'kernel.core_pattern=|/etc/conf/handler\n')
    link = {'path': '/etc/sysctl.d/99-sysctl.conf', 'type': 'symlink', 'link_target': '../sysctl.conf'}
    r = se.resolve([conf, link])
    k = key(r, 'kernel.core_pattern')
    assert k['program'] == '/etc/conf/handler' and k['path'] == '/etc/sysctl.d/99-sysctl.conf'
    assert r['other_readers'] == [] and r['complete'] is True
    unlinked = se.resolve([conf])
    assert key(unlinked, 'kernel.core_pattern')['state'] == 'not_configured'
    assert [o['program'] for o in unlinked['other_readers']] == ['/etc/conf/handler']
    assert any(g['code'] == 'sysctl_conf_not_linked' for g in unlinked['gaps'])


def test_split_usr_only_entry_is_reported_with_condition():
    r = se.resolve([f('/lib/sysctl.d/a.conf', 'kernel.modprobe=/lib/evil\n')])
    k = key(r, 'kernel.modprobe')
    assert k['program'] == '/lib/evil' and 'split_usr_build_only' in k['conditions']
    assert r['files'][0]['condition'] == 'split_usr_build_only'


def test_value_bounded_hashed_and_kernel_truncation_flagged():
    long = '|/h ' + 'a' * 3000
    k = key(se.resolve([f('/etc/sysctl.d/a.conf', f'kernel.core_pattern={long}\n')]), 'kernel.core_pattern')
    assert k['value_truncated'] is True and len(k['value']) == se.MAX_VALUE
    assert k['value_sha256'] == se._sha(long) and 'kernel_keeps_first_127_bytes' in k['conditions']


def test_unobserved_always_listed():
    r = se.resolve([])
    codes = {u['code'] for u in r['unobserved']}
    assert {'kernel_command_line', 'credentials', 'runtime_writes', 'live_value'} <= codes
    assert all(k['state'] == 'not_configured' for k in r['keys'])


def test_unreadable_file_reason_is_its_own_cause_after_gaps_cap_or_earlier_gaps():
    # Review finding on #1089: once MAX_GAPS is reached the last gap becomes
    # gaps_truncated, and an unreadable file's reason must not read it back.
    bad = [f(f'/etc/sysctl.d/{i:03d}.conf', b'\xff') for i in range(se.MAX_GAPS)]
    r = se.resolve(bad + [f('/etc/sysctl.d/999.conf', 'a\x00b')])
    assert r['complete'] is False and r['gaps'][-1]['code'] == 'gaps_truncated'
    reasons = {x['path']: x['reason'] for x in r['files']}
    assert reasons['/etc/sysctl.d/999.conf'] == 'nul_byte'
    assert {reasons[x['path']] for x in bad} == {'invalid_utf8'}
    # A non-regular /etc/sysctl.conf reports its own cause, not an earlier file's gap.
    r = se.resolve([f('/etc/sysctl.d/a.conf', b'\xff'), {'path': '/etc/sysctl.conf', 'type': 'directory'}])
    conf = next(x for x in r['files'] if x['path'] == '/etc/sysctl.conf')
    assert conf['status'] == 'unreadable' and conf['reason'] == 'not_regular_file'
    assert r['complete'] is False


def test_unmodelled_glob_syntax_is_a_blocking_gap_not_a_match():
    # Rows from the differential review against systemd-sysctl 255 (glob(3) with GLOB_BRACE).
    for line in ('kernel.[^m]* = |/x', 'kernel.[[:lower:]]odprobe = /x', 'kernel.[[:alpha:]_]* = /x',
                 'kernel.[![:upper:]]odprobe = /x', 'kernel.{modprobe,hotplug}* = /x', '{kernel,fs}.modprob? = /x',
                 'kernel.{}modprobe* = /x', 'kernel.{,x}modprobe* = /x', 'kernel.[[:alpha:]* = /x',
                 'kernel.mod\\* = /x'):
        r = se.resolve([f('/etc/sysctl.d/10-a.conf', line + '\n')])
        assert not r['complete'], line
        assert [g['code'] for g in r['gaps']] == ['glob_not_modelled'], line
        assert r['executing_keys'] == [], line
        for k in r['keys']:
            assert k['state'] == 'not_configured', line
            assert 'unmodelled_glob_may_apply' in k['conditions'], line


def test_unmodelled_glob_does_not_touch_explicit_keys_or_hide_modelled_globs():
    r = se.resolve([f('/etc/sysctl.d/10-a.conf',
                      'kernel.modprobe = /sbin/modprobe\nkernel.{core_pattern,x}* = |/evil\nkernel.core_patter? = core\n')])
    assert not r['complete']
    modprobe, core = key(r, 'kernel.modprobe'), key(r, 'kernel.core_pattern')
    assert modprobe['via'] == 'explicit' and 'unmodelled_glob_may_apply' not in modprobe['conditions']
    assert core['via'] == 'glob' and core['value'] == 'core'
    assert 'unmodelled_glob_may_apply' in core['conditions']


def test_negative_or_non_glob_keys_with_braces_are_not_gaps():
    # A negative glob writes nothing, and a key without *?[ is an exact key in systemd.
    r = se.resolve([f('/etc/sysctl.d/10-a.conf', '-kernel.{a,b}*\nkernel.{modprobe,hotplug} = /x\n')])
    assert r['complete'] and r['gaps'] == []
    assert all('unmodelled_glob_may_apply' not in k['conditions'] for k in r['keys'])
