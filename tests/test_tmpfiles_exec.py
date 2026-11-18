import base64

from app import tmpfiles_exec as te


def conf(path, text):
    return {'path': path, 'text': text}


def hook(result, key):
    return result['kernel_hooks'][key]


def test_core_pattern_write_runs_program_and_is_complete():
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', 'w /proc/sys/kernel/core_pattern - - - - |/tmp/x %%p\n')])
    core = hook(result, 'core_pattern')
    assert result['complete'] is True
    assert core['runs_program'] is True and core['program'] == '/tmp/x'
    assert core['last_writer']['argument']['text'] == '|/tmp/x %p'
    assert core['last_writer']['source'] == '/etc/tmpfiles.d/a.conf' and core['last_writer']['line'] == 1
    assert result['origin'] == 'not_assessed'


def test_precedence_masking_suffix_and_split_usr():
    files = [
        conf('/usr/lib/tmpfiles.d/a.conf', 'w /proc/sys/kernel/modprobe - - - - /usr/evil\n'),
        conf('/etc/tmpfiles.d/a.conf', 'w /proc/sys/kernel/modprobe - - - - /sbin/modprobe\n'),
        {'path': '/etc/tmpfiles.d/b.conf', 'type': 'symlink', 'link_target': '/dev/null'},
        conf('/usr/lib/tmpfiles.d/b.conf', 'w /proc/sys/kernel/poweroff_cmd - - - - /tmp/p\n'),
        conf('/etc/tmpfiles.d/c.txt', 'w /proc/sys/kernel/hotplug - - - - /tmp/h\n'),
        conf('/lib/tmpfiles.d/d.conf', 'w /proc/sys/kernel/hotplug - - - - /tmp/h\n'),
    ]
    result = te.resolve(files)
    assert hook(result, 'modprobe')['program'] == '/sbin/modprobe'
    assert hook(result, 'poweroff_cmd')['last_writer'] is None
    assert hook(result, 'uevent_helper')['last_writer'] is None
    status = {r['path']: r['status'] for r in result['files']}
    assert status['/usr/lib/tmpfiles.d/a.conf'] == 'overridden'
    assert status['/etc/tmpfiles.d/b.conf'] == 'masked'
    assert status['/etc/tmpfiles.d/c.txt'] == 'ignored'


def test_first_write_wins_except_w_plus_append():
    text = ('w /proc/sys/kernel/core_pattern - - - - |/first\n'
            'w /proc/sys/kernel/core_pattern - - - - |/second\n'
            'w+ /proc/sys/kernel/modprobe - - - - /a\n'
            'w+ /proc/sys/kernel/modprobe - - - - /b\n')
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    assert [w['argument']['text'] for w in hook(result, 'core_pattern')['writers']] == ['|/first']
    assert [w['argument']['text'] for w in hook(result, 'modprobe')['writers']] == ['/a', '/b']
    assert hook(result, 'modprobe')['program'] == '/b'
    assert result['lines_duplicate'] == 1
    assert any(g['code'] == 'multiple_writers' for g in result['gaps'])


def test_earlier_ignore_line_drops_later_write():
    text = 'x /proc/sys/kernel/core_pattern\nw /proc/sys/kernel/core_pattern - - - - |/x\n'
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    assert hook(result, 'core_pattern')['writers'] == []


def test_glob_order_follows_first_appearance_of_path():
    text = ('w /proc/sys/kernel/core_patter* - - - - |/glob\n'
            'w /proc/sys/kernel/core_pattern - - - - |/exact\n')
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    assert hook(result, 'core_pattern')['program'] == '/exact'
    swapped = te.resolve([conf('/etc/tmpfiles.d/a.conf', '\n'.join(reversed(text.splitlines())))])
    assert hook(swapped, 'core_pattern')['program'] == '/glob'
    assert hook(swapped, 'core_pattern')['last_writer']['glob'] is True


def test_f_only_when_absent_and_f_plus_writes():
    text = 'f /proc/sys/kernel/core_pattern - - - - |/f\nf+ /proc/sys/kernel/modprobe - - - - /fp\n'
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    core = hook(result, 'core_pattern')
    assert core['writers'] == [] and core['other_lines'][0]['argument']['text'] == '|/f'
    assert hook(result, 'modprobe')['program'] == '/fp'


def test_creating_lines_apply_before_writes():
    text = ('w /proc/sys/kernel/core_pattern - - - - |/w\n'
            'f+ /proc/sys/kernel/core_pattern - - - - |/fplus\n')
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    assert [w['type'] for w in hook(result, 'core_pattern')['writers']] == ['f', 'w']
    assert hook(result, 'core_pattern')['program'] == '/w'


def test_escapes_quotes_base64_and_binfmt():
    payload = base64.b64encode(b':evil:E::xyz::/tmp/interp:').decode()
    text = ('w "/proc/sys/kernel/core\\x5fpattern" - - - - |/tmp/a\\x41 "q"\n'
            f'w~ /proc/sys/fs/binfmt_misc/register - - - - {payload}\n')
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    assert hook(result, 'core_pattern')['last_writer']['argument']['text'] == '|/tmp/aA "q"'
    assert hook(result, 'binfmt_register')['program'] == '/tmp/interp'


def test_boot_only_and_ignore_errors_flags():
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', 'w!- /proc/sys/kernel/modprobe - - - - /m\n')])
    writer = hook(result, 'modprobe')['last_writer']
    assert writer['boot_only'] is True and writer['ignore_errors'] is True


def test_rejected_lines_have_no_effect():
    text = ('w /proc/sys/kernel/core_pattern\n'
            'w /proc/sys/kernel/core_pattern - - - - -\n'
            'f etc/cron.d/rel - - - - x\n'
            'w~ /proc/sys/kernel/modprobe - - - - !!notbase64\n'
            '# w /proc/sys/kernel/hotplug - - - - /c\n')
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    assert result['complete'] is True
    assert all(h['writers'] == [] for h in result['kernel_hooks'].values())
    assert result['startup_writes'] == []
    assert result['lines_rejected'] == 4


def test_startup_locations_simplified_paths_and_conditions():
    text = ('f /etc/cron.d//job 0644 root root - * * * * * root /tmp/x\n'
            'L+ /etc/ld.so.preload - - - - /tmp/evil.so\n'
            'C /etc/systemd/system/./x.service - - - - /tmp/unit\n'
            'w /etc/profile.d/* - - - - export X=1\n'
            'L /etc/cron.d - - - - /tmp/crondir\n'
            'f /etc/cron.d/../cron.d/up - - - - refused\n'
            'f /var/log/app.log - - - - harmless\n')
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    writes = {(w['path'], w['location'], w['when']) for w in result['startup_writes']}
    assert writes == {
        ('/etc/cron.d/job', '/etc/cron.d', 'if_absent'),
        ('/etc/ld.so.preload', '/etc/ld.so.preload', 'replace'),
        ('/etc/systemd/system/x.service', '/etc/systemd/system', 'if_absent'),
        ('/etc/profile.d/*', '/etc/profile.d', 'write_if_present'),
        ('/etc/cron.d', '/etc/cron.d', 'if_absent'),
    }


def test_f_and_w_for_same_path_both_apply():
    text = 'w /etc/cron.d/job - - - - two\nf /etc/cron.d/job - - - - one\n'
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    assert [w['type'] for w in result['startup_writes']] == ['f', 'w']


def test_unresolved_specifiers_credentials_and_modifiers_fail_closed():
    cases = {
        'f /etc/cron.d/%m - - - - x\n': 'path_specifier_unresolved',
        'w /proc/sys/kernel/core_pattern - - - - |/x %H\n': 'argument_specifier_unresolved',
        'w^ /proc/sys/kernel/core_pattern - - - - cred\n': 'credential_unobserved',
        'w$ /proc/sys/kernel/core_pattern - - - - |/x\n': 'modifier_unsupported',
        'w /proc/sys/kernel/core_pattern - - - - |/x\\q\n': 'line_unparsed',
    }
    for text, code in cases.items():
        result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
        assert result['complete'] is False, text
        assert code in {g['code'] for g in result['gaps']}, text
    credential = te.resolve([conf('/etc/tmpfiles.d/a.conf', 'w^ /proc/sys/kernel/core_pattern - - - - c\n')])
    assert hook(credential, 'core_pattern')['runs_program'] is None


def test_unreadable_input_fails_closed_without_fallback():
    files = [
        {'path': '/etc/tmpfiles.d/a.conf', 'text': None},
        conf('/usr/lib/tmpfiles.d/a.conf', 'w /proc/sys/kernel/modprobe - - - - /lower\n'),
        conf('/etc/tmpfiles.d/b.conf', b'\xff\n'),
        conf('/etc/tmpfiles.d/c.conf', 'w /x\x00\n'),
        {'path': '/etc/tmpfiles.d/d.conf', 'type': 'symlink', 'link_target': '/opt/elsewhere.conf'},
        conf('/etc/tmpfiles.d/e.conf', 'x' * (te.MAX_TEXT + 1)),
    ]
    result = te.resolve(files)
    codes = {g['code'] for g in result['gaps']}
    assert result['complete'] is False
    assert {'file_unreadable', 'invalid_utf8', 'nul_byte', 'symlink_not_followed', 'text_over_limit'} <= codes
    assert hook(result, 'modprobe')['writers'] == []


def test_malformed_and_oversized_input():
    assert te.resolve(None)['complete'] is False
    result = te.resolve([{'path': 'relative.conf'}, conf('/etc/tmpfiles.d/a.conf', ''),
                         conf('/etc/tmpfiles.d/a.conf', '')])
    assert {'input_malformed', 'duplicate_path'} <= {g['code'] for g in result['gaps']}
    many = [conf(f'/etc/tmpfiles.d/{i}.conf', '') for i in range(te.MAX_FILES + 1)]
    assert te.resolve(many)['gaps'][0]['code'] == 'too_many_files'


def test_long_argument_is_bounded_with_full_hash():
    value = '|/tmp/' + 'a' * 1000
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', f'w /proc/sys/kernel/core_pattern - - - - {value}\n')])
    argument = hook(result, 'core_pattern')['last_writer']['argument']
    assert argument['truncated'] is True and len(argument['text']) == te.MAX_SHOWN
    assert argument['length'] == len(value)
    import hashlib
    assert argument['sha256'] == hashlib.sha256(value.encode()).hexdigest()


def test_uevent_helper_paths_share_one_setting():
    text = ('w /sys/kernel/uevent_helper - - - - /tmp/u1\n'
            'w /proc/sys/kernel/hotplug - - - - /tmp/u2\n')
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', text)])
    helper = hook(result, 'uevent_helper')
    assert [w['target'] for w in helper['writers']] == ['/sys/kernel/uevent_helper', '/proc/sys/kernel/hotplug']
    assert helper['program'] == '/tmp/u2'


def test_core_pattern_without_pipe_runs_nothing():
    result = te.resolve([conf('/etc/tmpfiles.d/a.conf', 'w /proc/sys/kernel/core_pattern - - - - core.%%p\n')])
    assert hook(result, 'core_pattern')['runs_program'] is False
    assert hook(result, 'core_pattern')['program'] is None


def test_glob_matching_does_not_cross_slash_or_match_hidden():
    assert te.glob_matches('/proc/sys/kernel/*', '/proc/sys/kernel/modprobe')
    assert not te.glob_matches('/proc/sys/*', '/proc/sys/kernel/modprobe')
    assert not te.glob_matches('/etc/cron.d/*', '/etc/cron.d/.hidden')
    assert te.startup_location('/etc/cron.d/*', True) == '/etc/cron.d'
    assert te.startup_location('/etc/*/job', True) is not None
    assert te.startup_location('/var/tmp/*', True) is None


def test_result_lists_unobserved_and_never_authorizes():
    result = te.resolve([])
    assert result['complete'] is True
    assert result['unobserved'] and 'safety verdict' in result['not_a_verdict']
    assert 'authorized' not in str(result).lower()
