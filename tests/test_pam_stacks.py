"""Pure PAM service-stack contract (#967). No I/O: every input is a literal."""
import hashlib

import pytest

from app import pam_stacks


def f(name, text, directory='/etc/pam.d'):
    return {'path': f'{directory}/{name}', 'text': text}


def run(files, family='debian', version='1.5.3', **kwargs):
    return pam_stacks.evaluate(files, family, version, **kwargs)


def service(result, name):
    return next(item for item in result['services'] if item['service'] == name)


def modules(result, name, kind=None):
    return [entry['module'] for entry in service(result, name)['entries'] if kind in (None, entry['type'])]


def codes(item):
    return [gap['code'] for gap in item['gaps']]


def test_plain_stack_keeps_order_type_control_and_source():
    result = run([f('sshd', '# comment\n\nauth required pam_env.so readenv=1\n-session optional pam_systemd.so\n'
                            'ACCOUNT Required pam_nologin.so # trailing\n')])
    assert result['complete'] and result['note'] == pam_stacks.NOT_A_VERDICT
    entries = service(result, 'sshd')['entries']
    assert [(e['type'], e['control'], e['module'], e['silent'], e['source']['line']) for e in entries] == [
        ('auth', 'required', 'pam_env.so', False, 3), ('session', 'optional', 'pam_systemd.so', True, 4),
        ('account', 'Required', 'pam_nologin.so', False, 5)]
    assert entries[0]['args'] == ['readenv=1'] and entries[2]['args'] == []
    assert all(e['status'] == 'module' and e['origin'] == 'not_assessed' and e['control_kind'] == 'simple'
               for e in entries)


def test_hash_ends_the_line_even_inside_brackets():
    result = run([f('su', 'auth [success=1 # default=ignore] pam_unix.so nullok\n')])
    entry = service(result, 'su')['entries'][0]
    assert entry['control'] == 'success=1 ' and entry['status'] == 'must_fail' and entry['reason'] == 'module_missing'


def test_bracket_fields_keep_spaces_and_unescape_closing_bracket():
    result = run([f('login', 'auth [success=ok default=bad] pam_succeed_if.so [user = a\\]b] quiet[x y]z\n')])
    entry = service(result, 'login')['entries'][0]
    assert entry['control'] == 'success=ok default=bad' and entry['control_kind'] == 'bracket_or_unknown'
    assert entry['args'] == ['user = a]b', 'quiet[x', 'y]z']
    assert pam_stacks.tokenize('[a b]c  [d') == ['a b', 'c', 'd']


def test_continuation_joins_lines_and_skips_comment_lines_inside():
    text = 'auth required \\\n# skipped\n\n   pam_exec.so \\  \n /usr/local/bin/hook\nauth optional pam_permit.so\n'
    result = run([f('cron', text)])
    entries = service(result, 'cron')['entries']
    assert [(e['module'], e['source']['line']) for e in entries] == [('pam_exec.so', 1), ('pam_permit.so', 6)]
    assert entries[0]['exec']['command'] == ['/usr/local/bin/hook']


def test_unfinished_continuation_is_a_blocking_gap():
    result = run([f('cron', 'auth required pam_unix.so \\\n')])
    assert not result['complete'] and codes(service(result, 'cron')) == ['continuation_at_eof']
    assert service(result, 'cron')['entries'] == []


@pytest.mark.parametrize('text,code', [
    ('auth required pam_unix.so\r\n', 'control_character'),
    ('auth required pam_unix.so ' + 'a' * 1001 + '\n', 'line_too_long'),
    ('auth required \\\n' * 80 + 'pam_unix.so\n', 'line_too_long'),
    (b'auth required pam_\xff.so\n', 'invalid_utf8'),
    ('auth required pam_unix.so\x00\n', 'control_character'),
    (None, 'file_unreadable'),
    ('#' * (pam_stacks.MAX_TEXT + 1), 'file_too_large'),
])
def test_unusable_files_fail_closed(text, code):
    result = run([f('sshd', text)])
    item = service(result, 'sshd')
    assert not result['complete'] and not item['complete'] and codes(item) == [code] and item['entries'] == []
    assert all(gap['blocking'] for gap in item['gaps'])


def test_invalid_lines_become_must_fail_entries_as_libpam_installs_them():
    result = run([f('x', 'bogus required pam_unix.so\nauth\nauth required\n- required pam_deny.so\n')])
    entries = service(result, 'x')['entries']
    assert [(e['type'], e['status'], e['reason']) for e in entries] == [
        ('auth', 'must_fail', 'type_invalid'), ('auth', 'must_fail', 'control_missing'),
        ('auth', 'must_fail', 'module_missing'), ('auth', 'must_fail', 'type_missing')]
    assert service(result, 'x')['must_fail'] == 4 and result['complete']


def test_include_keeps_only_the_including_type_and_records_the_chain():
    files = [f('sshd', 'auth include common\nsession substack common\n'),
             f('common', 'auth required pam_unix.so\nsession required pam_limits.so\naccount required pam_permit.so\n')]
    result = run(files)
    entries = service(result, 'sshd')['entries']
    assert [(e['type'], e['module'], e['substack_level']) for e in entries] == [
        ('auth', 'pam_unix.so', 0), ('session', 'pam_limits.so', 1)]
    assert entries[0]['via'] == [{'path': '/etc/pam.d/sshd', 'line': 1, 'kind': 'include',
                                  'target': '/etc/pam.d/common'}]
    assert entries[0]['source'] == {'path': '/etc/pam.d/common', 'line': 1}
    assert service(result, 'sshd')['uses_other_for'] == ['account', 'password']


def test_debian_at_include_keeps_every_type_and_inherits_a_filter():
    files = [f('sudo', '@include common-auth\nsession include wrapper\n'),
             f('common-auth', 'auth required pam_unix.so\naccount required pam_permit.so\n'),
             f('wrapper', '@include common-auth\nsession optional pam_umask.so\n@include tail\n'),
             f('tail', 'session required pam_limits.so\nauth required pam_deny.so\n')]
    result = run(files)
    assert [(e['type'], e['module']) for e in service(result, 'sudo')['entries']] == [
        ('auth', 'pam_unix.so'), ('account', 'pam_permit.so'), ('session', 'pam_umask.so'),
        ('session', 'pam_limits.so')]


def test_at_include_is_an_invalid_type_upstream():
    result = run([f('sudo', '@include common-auth\n'), f('common-auth', 'auth required pam_unix.so\n')],
                 family='upstream')
    entry = service(result, 'sudo')['entries'][0]
    assert (entry['type'], entry['status'], entry['reason']) == ('auth', 'must_fail', 'type_invalid')


def test_a_relative_include_is_looked_up_like_a_service_in_both_families():
    # Compiled Ubuntu libpam 1.5.3-5ubuntu5.7 loads /usr/lib/pam.d/<name> when /etc/pam.d/<name> is absent.
    files = [f('sshd', 'auth include vendor-auth\n@include vendor-auth\nauth substack vendor-auth\n'),
             f('vendor-auth', 'auth required pam_unix.so\n', '/usr/lib/pam.d')]
    debian = run(files)
    assert modules(debian, 'sshd') == ['pam_unix.so'] * 3 and debian['complete']
    assert {entry['source']['path'] for entry in service(debian, 'sshd')['entries']} == {'/usr/lib/pam.d/vendor-auth'}
    upstream = run([f('sshd', 'auth include vendor-auth\n'), files[1]], family='upstream')
    assert modules(upstream, 'sshd') == ['pam_unix.so'] and service(upstream, 'sshd')['complete']
    # /etc/pam.d wins, and a relative name with a slash stays a reported gap.
    both = run(files + [f('vendor-auth', 'auth required pam_deny.so\n')])
    assert modules(both, 'sshd') == ['pam_deny.so'] * 3
    slash = run([f('sshd', 'auth include ../pam.d/vendor-auth\n'), files[1]])
    assert codes(service(slash, 'sshd')) == ['include_relative_path'] and not service(slash, 'sshd')['complete']


def test_absolute_include_and_missing_targets():
    files = [f('a', 'auth include /opt/pam/extra\nauth include ../shadow\nauth include\nauth include gone\n'),
             {'path': '/opt/pam/extra', 'text': 'auth required /opt/lib/pam_x.so\n'}]
    result = run(files)
    item = service(result, 'a')
    assert modules(result, 'a') == ['/opt/lib/pam_x.so'] and item['absolute_modules'] == 1
    assert codes(item) == ['include_relative_path', 'include_name_missing', 'include_target_missing']
    assert [gap['line'] for gap in item['gaps']] == [2, 3, 4]
    assert [s['service'] for s in result['services']] == ['a']


def test_include_loops_and_deep_substacks_are_gaps_not_recursion():
    loop = run([f('a', 'auth include b\n'), f('b', 'auth required pam_env.so\nauth include a\n')])
    assert codes(service(loop, 'a')) == ['include_loop'] and modules(loop, 'a') == ['pam_env.so']
    self_loop = run([f('a', 'auth substack a\n')])
    assert codes(service(self_loop, 'a')) == ['include_loop']
    chain = [f(f's{i}', f'auth substack s{i + 1}\n') for i in range(20)] + [f('s20', 'auth required pam_deny.so\n')]
    deep = run(chain)
    assert codes(service(deep, 's0')) == ['include_too_deep'] and modules(deep, 's0') == []
    assert modules(deep, 's5') == ['pam_deny.so'] and service(deep, 's5')['entries'][0]['substack_level'] == 15


def test_an_unusable_included_file_marks_every_service_that_reaches_it():
    files = [f('sshd', 'auth include common\n'), f('login', 'auth required pam_unix.so\n'), f('common', None)]
    result = run(files)
    assert codes(service(result, 'sshd')) == ['file_unreadable'] and service(result, 'login')['complete']
    assert service(result, 'sshd')['gaps'][0]['path'] == '/etc/pam.d/common'


def test_etc_shadows_vendor_directories_and_an_unreadable_winner_does_not_fall_back():
    files = [f('sshd', 'auth required pam_unix.so\n'), f('sshd', 'auth required pam_deny.so\n', '/usr/lib/pam.d'),
             f('su', None), f('su', 'auth required pam_rootok.so\n', '/usr/lib/pam.d'),
             f('vend', 'auth required pam_permit.so\n', '/usr/share/pam.d')]
    result = run(files, vendor_dir='/usr/share')
    assert result['directories'] == ['/etc/pam.d', '/usr/lib/pam.d', '/usr/share/pam.d']
    assert service(result, 'sshd')['file'] == '/etc/pam.d/sshd' and modules(result, 'sshd') == ['pam_unix.so']
    assert service(result, 'sshd')['shadowed_files'] == ['/usr/lib/pam.d/sshd']
    assert modules(result, 'su') == [] and codes(service(result, 'su')) == ['file_unreadable']
    assert modules(result, 'vend') == ['pam_permit.so']
    assert 'vend' not in [s['service'] for s in run(files)['services']]


def test_other_fallback_is_reported_and_its_gaps_propagate():
    files = [f('sshd', 'auth required pam_unix.so\n'), f('other', 'auth required pam_deny.so\nsession include gone\n')]
    result = run(files)
    sshd = service(result, 'sshd')
    assert sshd['uses_other_for'] == ['account', 'password', 'session'] and sshd['other_available']
    assert codes(sshd) == ['include_target_missing'] and not sshd['complete']
    assert service(result, 'other')['uses_other_for'] == []
    alone = service(run([f('sshd', 'auth required pam_unix.so\n')]), 'sshd')
    assert alone['complete'] and not alone['other_available']


def test_uppercase_file_names_are_not_selectable_services():
    result = run([f('SSHD', 'auth required pam_unix.so\n'), f('sshd', 'auth include SSHD\n')])
    assert not service(result, 'SSHD')['selectable'] and service(result, 'sshd')['selectable']
    assert modules(result, 'sshd') == ['pam_unix.so']


def test_pam_exec_options_command_and_type_filter():
    text = ('session optional pam_exec.so Seteuid log=/var/log/x type=open_session quiet /bin/sh -c [id > /tmp/x]\n'
            'auth required pam_exec.so expose_authtok type=session /usr/bin/a\n'
            'auth required /lib/security/pam_exec.so custom-tool arg\n'
            'auth required pam_exec.so quiet\n'
            'auth required pam_execfoo.so /bin/x\n')
    entries = service(run([f('sshd', text)]), 'sshd')['entries']
    first = entries[0]['exec']
    assert first['options'] == ['Seteuid', 'log=/var/log/x', 'type=open_session', 'quiet']
    assert first['command'] == ['/bin/sh', '-c', 'id > /tmp/x'] and first['seteuid'] and first['applies']
    assert first['command_sha256'] == hashlib.sha256(b'/bin/sh\0-c\0id > /tmp/x').hexdigest()
    assert entries[1]['exec']['expose_authtok'] and not entries[1]['exec']['applies']
    assert entries[2]['exec']['command'] == ['custom-tool', 'arg'] and entries[2]['module_absolute']
    assert entries[3]['exec']['command_missing'] and entries[3]['exec']['command_sha256'] is None
    assert entries[4]['exec'] is None
    assert service(run([f('sshd', text)]), 'sshd')['exec_commands'] == 4


def test_pam_exec_needs_every_type_option_to_match():
    text = ('session optional pam_exec.so type=auth type=open_session /bin/a\n'
            'session optional pam_exec.so type=open_session type=auth /bin/b\n'
            'session optional pam_exec.so type=open_session type=open_session /bin/c\n')
    first, second, third = (entry['exec'] for entry in service(run([f('sshd', text)]), 'sshd')['entries'])
    assert not first['applies'] and first['type_filter'] == 'auth'
    assert not second['applies'] and second['type_filter'] == 'auth'
    assert third['applies'] and third['type_filter'] == 'open_session'
    assert first['command'] == ['/bin/a'] and first['options'] == ['type=auth', 'type=open_session']


def test_long_arguments_are_bounded_with_a_full_hash():
    long = 'x' * 600
    entry = service(run([f('a', f'auth required pam_exec.so /bin/{long}\n')]), 'a')['entries'][0]
    assert len(entry['args'][0]) == pam_stacks.MAX_FIELD and entry['args_truncated']
    assert entry['args_sha256'] == hashlib.sha256(f'/bin/{long}'.encode()).hexdigest()
    assert entry['exec']['command_sha256'] == entry['args_sha256']


@pytest.mark.parametrize('version', ['1.3.1', '1.7.0', '1.6.1-2', '', None, '1.5'])
def test_unverified_versions_block_completeness_but_still_report(version):
    result = run([f('sshd', 'auth required pam_unix.so\n')], version=version)
    assert codes(result) == ['version_unverified'] and not result['complete']
    assert not service(result, 'sshd')['complete'] and modules(result, 'sshd') == ['pam_unix.so']


@pytest.mark.parametrize('version', ['1.4.0', '1.5.2', '1.5.3-5ubuntu5', '1.4.0-11ubuntu2.6'])
def test_verified_versions(version):
    assert run([f('sshd', 'auth required pam_unix.so\n')], version=version)['complete']


def test_malformed_input_is_reported_not_raised():
    result = run([{'path': 'relative', 'text': ''}, {'path': '/etc/pam.d/../x', 'text': ''}, 'nope',
                  f('a', 'auth required pam_unix.so\n'), f('a', 'auth required pam_deny.so\n')])
    assert codes(result) == ['input_malformed', 'duplicate_path'] and not result['complete']
    assert modules(result, 'a') == ['pam_unix.so']
    assert codes(run('nope')) == ['input_malformed']
    many = run([f(f's{i}', '') for i in range(pam_stacks.MAX_FILES + 1)])
    assert codes(many) == ['too_many_files'] and len(many['services']) == pam_stacks.MAX_FILES


def test_bad_family_or_vendor_dir_is_a_caller_error():
    with pytest.raises(ValueError):
        run([], family='rpm')
    with pytest.raises(ValueError):
        run([], vendor_dir='usr/share')


def test_entry_and_gap_limits():
    big = run([f('a', 'auth required pam_permit.so\n' * (pam_stacks.MAX_ENTRIES + 5))])
    assert len(service(big, 'a')['entries']) == pam_stacks.MAX_ENTRIES and codes(service(big, 'a')) == ['too_many_entries']
    noisy = service(run([f('a', ''.join(f'auth include gone{i}\n' for i in range(200)))]), 'a')
    assert len(noisy['gaps']) == pam_stacks.MAX_GAPS and noisy['gaps'][-1]['code'] == 'gaps_truncated'


def test_result_names_what_is_unobserved_and_is_deterministic():
    files = [f('sshd', 'auth required pam_unix.so\n'), f('other', 'auth required pam_deny.so\n')]
    result = run(files)
    assert result == run(list(reversed(files))) and result['contract_version'] == 1
    assert any('pam.conf' in item for item in result['unobserved'])
    assert [s['service'] for s in result['services']] == ['other', 'sshd']


def test_a_substack_keeps_its_type_from_falling_back_to_other():
    # libpam 1.5.3 installs the substack marker before reading the file.
    files = [f('sshd', 'auth required pam_unix.so\nsession substack empty\naccount include empty\n'),
             f('empty', ''), f('other', 'session optional pam_exec.so /bin/x\naccount required pam_deny.so\n')]
    sshd = service(run(files), 'sshd')
    assert sshd['complete'] and sshd['uses_other_for'] == ['account', 'password']
    nested = [f('sshd', '@include mid\n'), f('mid', 'bogus substack empty\n'), f('empty', '')]
    assert service(run(nested), 'sshd')['uses_other_for'] == ['account', 'password', 'session']


def test_a_gap_in_other_blocks_every_service_even_without_fallback():
    # pam_start fails for every service when libpam cannot parse other.
    full = ''.join(f'{kind} required pam_unix.so\n' for kind in pam_stacks.TYPES)
    result = run([f('sshd', full), f('other', 'session required pam_deny.so \\')])
    sshd = service(result, 'sshd')
    assert sshd['uses_other_for'] == [] and not sshd['complete']
    assert codes(sshd) == ['continuation_at_eof'] and sshd['gaps'][0]['path'] == '/etc/pam.d/other'


def test_an_unclosed_bracket_field_keeps_the_newline_libpam_passes_on():
    # Compiled libpam 1.5.3 hands the module "zz\n" here; without a final newline, or after a "#", just "zz".
    args = lambda text: service(run([f('sshd', text)]), 'sshd')['entries'][0]['args']
    assert args('auth required pam_exec.so /bin/x [zz\n') == ['/bin/x', 'zz\n']
    assert args('auth required pam_exec.so /bin/x [zz') == ['/bin/x', 'zz']
    assert args('auth required pam_exec.so /bin/x [zz# c\n') == ['/bin/x', 'zz']
    assert args('auth required pam_exec.so /bin/x [zz \\\n\nsession optional pam_x.so\n') == [
        '/bin/x', 'zz  session optional pam_x.so\n']
    assert args('auth required pam_exec.so /bin/x [a\\]\n') == ['/bin/x', 'a]\n']
    assert pam_stacks.logical_lines('a \\\nb\nc') == [(1, 'a  b\n'), (3, 'c')]


def test_closed_brackets_next_to_other_text_still_parse():
    entry = service(run([f('sshd', 'auth required pam_x.so [a]b [] a[b a]b [[n]\n')]), 'sshd')['entries'][0]
    assert entry['args'] == ['a', 'b', '', 'a[b', 'a]b', '[n']
