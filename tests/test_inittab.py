"""Tests for the pure sysvinit inittab contract (#1110).

Expected outcomes follow read_inittab() and spawn() in sysvinit 3.14 and 3.15 src/init.c.
"""
from app import inittab as it

OBSERVED = {'inittab_d': {'state': 'absent'}, 'initscript': 'absent'}
# Abridged from Debian's sysvinit-core /usr/share/sysvinit/inittab.
DEBIAN = """# /etc/inittab: init(8) configuration.
id:2:initdefault:

si::sysinit:/etc/init.d/rcS
~~:S:wait:/sbin/sulogin --force

l0:0:wait:/etc/init.d/rc 0
l2:2:wait:/etc/init.d/rc 2
z6:6:respawn:/sbin/sulogin --force

ca:12345:ctrlaltdel:/sbin/shutdown -t1 -a -r now
pf::powerwait:/etc/init.d/powerfail start

1:2345:respawn:/sbin/getty --noclear 38400 tty1
"""


def run(text, **kwargs):
    return it.evaluate(text, **{**OBSERVED, **kwargs})


def by_id(result):
    return {e['id']: e for e in result['entries']}


def reasons(result):
    return [(r['line'], r['reason'], r['detail']) for r in result['rejected']]


def test_debian_layout_resolves_each_entry():
    result = run(DEBIAN)
    assert result['complete'] and result['origin'] == 'not_assessed'
    entries = by_id(result)
    assert entries['si']['runlevels'] == '#' and entries['si']['init_waits']
    assert entries['si']['command']['argv'] == ['/etc/init.d/rcS']
    assert entries['l2']['command'] == {**entries['l2']['command'], 'mode': 'exec',
                                        'argv': ['/etc/init.d/rc', '2']}
    assert entries['1']['action'] == 'respawn' and entries['1']['user'] == 'root'
    assert entries['pf']['runlevels'] == 'S0123456789'
    assert entries['ca']['runlevels'] == '12345'
    assert not entries['id']['runs'] and entries['id']['command'] is None
    assert result['default_runlevel'] == '2' and result['default_runlevel_prompt'] is False
    assert result['implicit_sulogin'] is False and result['rejected'] == []


def test_field_split_keeps_colons_in_process_and_checks_lengths():
    text = ('a:2:respawn:/bin/x --opt=a:b\n'
            'abcde:2:once:/bin/x\n'
            'b:123456789012:once:/bin/x\n'
            'c:2:' + 'w' * 33 + ':/bin/x\n'
            'd:2:once:' + 'p' * 257 + '\n'
            ':2:once:/bin/x\n'
            'e:2:once\n'
            'f:2::/bin/x\n'
            'g::once:\n')
    result = run(text)
    assert by_id(result)['a']['process'] == '/bin/x --opt=a:b'
    assert by_id(result)['a']['command']['mode'] == 'shell'
    assert [r[2] for r in reasons(result)] == [
        'id field too long (max 4 characters)', 'rlevel field too long (max 11 characters)',
        'action field too long', 'No newline within 255 bytes, or a final line without a newline.',
        'missing id field', 'missing process field', 'missing action field']
    # An empty process is accepted, then has nothing to exec.
    assert by_id(result)['g']['notes'] == ['empty_process'] and by_id(result)['g']['command']['argv'] == []


def test_process_limit_is_unreachable_behind_the_line_buffer():
    # init's 256-byte process limit cannot trigger: the 255-byte fgets line rejects first.
    head = 'd:2:once:'
    assert reasons(run(head + 'p' * (254 - len(head)) + '\n')) == []
    assert reasons(run(head + 'p' * (255 - len(head)) + '\n'))[0][1] == 'too_long_or_unterminated'
    assert it._reject(head + 'p' * 257 + '\n')[0] == 'process field too long (max 256 characters)'


def test_unknown_action_duplicate_id_and_case_insensitive_action():
    text = 'a:2:Respawn:/bin/a\na:3:once:/bin/b\nb:2:spawn:/bin/c\n~~:S:wait:/bin/d\n~~:S:wait:/bin/e\n'
    result = run(text)
    assert by_id(result)['a']['action'] == 'respawn'
    assert reasons(result) == [(2, 'duplicate_id', 'a'), (3, 'unknown_action', 'spawn')]
    assert [e['process'] for e in result['entries'] if e['id'] == '~~'] == ['/bin/d', '/bin/e']


def test_comments_leading_whitespace_and_fgets_limit():
    long_line = 'x:2:once:/bin/' + 'y' * 250 + '\n'
    text = '  \t# comment\n\n  a:2:once:/bin/a\n' + long_line + 'b:2:once:/bin/b\n' + 'c:2:once:/bin/c'
    result = run(text)
    assert set(by_id(result)) == {'a', 'b', '~~'}
    # The over-long line and the final line without a newline are both skipped.
    assert [(r[0], r[1]) for r in reasons(result)] == [(4, 'too_long_or_unterminated'),
                                                        (6, 'too_long_or_unterminated')]
    # 254 bytes plus a newline still fits.
    fits = 'x:2:once:/bin/' + 'y' * (254 - len('x:2:once:/bin/')) + '\n'
    assert run(fits)['rejected'] == []


def test_implicit_sulogin_and_lowercase_s():
    result = run('a:s:once:/bin/a\n')
    entries = result['entries']
    assert result['implicit_sulogin'] is True
    assert entries[-1] == {**entries[-1], 'implicit': True, 'id': '~~', 'runlevels': 'S', 'action': 'wait',
                           'process': '/sbin/sulogin'}
    assert entries[0]['notes'] == ['lowercase_s_is_not_single_user']
    # A power entry with empty runlevels already covers S.
    assert run('p::powerfail:/bin/p\n')['implicit_sulogin'] is False
    assert run(None, state='absent')['implicit_sulogin'] is True


def test_default_runlevel():
    assert run('id:35:initdefault:\n')['default_runlevel'] == '5'
    assert run('id:s:initdefault:\n')['default_runlevel'] == 'S'
    assert run('id::initdefault:\n')['default_runlevel'] == '9'
    assert run('id:a:initdefault:\n')['default_runlevel_prompt'] is True
    assert run('a:2:once:/bin/a\n')['default_runlevel_prompt'] is True
    assert run('id:3:initdefault:\ni2:5:initdefault:\n')['default_runlevel'] == '3'


def test_spawn_dispatch():
    assert it.command('/bin/a b')['mode'] == 'exec'
    shell = it.command('/bin/a > /dev/null')
    assert shell['mode'] == 'shell' and shell['argv'] == ['/bin/sh', '-c', '/bin/a > /dev/null']
    for ch in it.SHELL_CHARS:
        assert it.command(f'/bin/a {ch}')['mode'] == 'shell', ch
    at = it.command('@/bin/a $HOME')
    assert at['mode'] == 'exec' and at['argv'] == ['/bin/a', '$HOME']
    plus = it.command('+/bin/getty tty1')
    assert plus['utmp_records'] is False and plus['argv'] == ['/bin/getty', 'tty1']
    assert it.command('+@/bin/a ;')['argv'] == ['/bin/a', ';']
    assert it.command('/bin/a b#c d')['argv'] == ['/bin/a', 'b']
    assert it.command('/bin/a #c')['argv'] == ['/bin/a', '']
    many = it.command('/bin/a ' + ' '.join(str(n) for n in range(20)))
    assert len(many['argv']) == 14 and many['words_dropped'] == 7


def test_initscript_wraps_entries_outside_single_user():
    result = run('a:2:respawn:@/bin/a x\n', initscript='readable')
    entry = by_id(result)['a']
    assert entry['command']['mode'] == 'initscript'
    assert entry['command']['argv'] == ['/bin/sh', '/etc/initscript', '<id>', '<runlevels>', '<action>', '/bin/a x']
    assert entry['command_single_user']['mode'] == 'exec'


def test_fail_closed_inputs():
    assert not it.evaluate(DEBIAN)['complete']
    codes = {g['code'] for g in it.evaluate(DEBIAN)['gaps']}
    assert codes == {'inittab_d_not_observed', 'initscript_not_observed'}
    assert not run(None)['complete'] and run(None)['entries'] == []
    assert run(b'a:2:once:/bin/a\n\x00')['gaps'][0]['code'] == 'binary'
    assert run(b'a:2:once:/bin/\xff\n')['gaps'][0]['code'] == 'invalid_utf8'
    assert run('#' * (it.MAX_TEXT + 1))['gaps'][0]['code'] == 'over_limit'
    tabs = run(DEBIAN, inittab_d={'state': 'listed', 'names': ['x.tab', 'README', '.tab']})
    assert not tabs['complete'] and tabs['gaps'][0]['code'] == 'inittab_d_not_modelled'
    assert run(DEBIAN, inittab_d={'state': 'listed', 'names': ['README']})['complete']
    many = run(''.join(f'{n}:2:once:/bin/a\n' for n in range(it.MAX_ENTRIES + 1)))
    assert not many['complete'] and many['entries'] == []
