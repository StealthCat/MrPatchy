"""Pure dpkg configuration contract (#970).

The expected values in the parametrized tables were recorded from dpkg 1.22.6
(Ubuntu 24.04) by writing each line to /etc/dpkg/dpkg.cfg.d in a disposable
container and running ``dpkg --configure -a`` with a recording ``sh``.
"""
import pytest

from app import dpkg_hooks

PARTS = dpkg_hooks.PARTS_DIR
MAIN = dpkg_hooks.MAIN_FILE


def part(name, content, kind='file'):
    return {'name': name, 'type': kind, 'content': content}


def resolve(*files, main=None):
    return dpkg_hooks.resolve(list(files), main if main is not None else {'present': False})


def codes(result):
    return [g['code'] for g in result['gaps']]


ALWAYS = ['user_config_unobserved', 'invocation_unobserved']


@pytest.mark.parametrize('name,read,reason', [
    ('excludes', True, None),
    ('docker-apt-speedup', True, None),
    ('a_b', True, None),
    ('Z9', True, None),
    ('0', True, None),
    ('-', True, None),
    ('_', True, None),
    ('.hid', False, 'hidden'),
    ('a.conf', False, 'invalid_name'),
    ('x~', False, 'invalid_name'),
    ('a b', False, 'invalid_name'),
    ('x.dpkg-old', False, 'invalid_name'),
    ('café', False, 'invalid_name'),
])
def test_file_name_eligibility_matches_dpkg(name, read, reason):
    assert dpkg_hooks.eligibility(name) == {'read': read, 'reason': reason}


# line -> the value dpkg passed to the hook
@pytest.mark.parametrize('line,value', [
    ('pre-invoke=echo one', 'echo one'),
    ('pre-invoke echo two', 'echo two'),
    ('pre-invoke="echo three"', 'echo three'),
    ("pre-invoke='sq'", 'sq'),
    ('pre-invoke = spaced', 'spaced'),
    ('pre-invoke=  lead', 'lead'),
    ('pre-invoke=trail   ', 'trail'),
    ('pre-invoke=@x\r', '@x'),
    ('pre-invoke==x', 'x'),
    ('pre-invoke===@x', '=@x'),
    ('pre-invoke  ==@x', '==@x'),
    ('pre-invoke= =@x', '=@x'),
    ('pre-invoke=\t @x', '@x'),
    ('pre-invoke= "@x"', '@x'),
    ('pre-invoke="@x" ', '@x'),
    ('pre-invoke\ttab', 'tab'),
    ('pre-invoke:x', 'x'),
    ('pre-invoke\x0c@x', '@x'),
    ('pre-invoke=a"', 'a"'),
    ('pre-invoke=a # b', 'a # b'),
    ('pre-invoke=@a\\', '@a\\'),
    ('pre-invoke="a b" ', 'a b'),
    ('pre-invoke=" x "', ' x '),
    ('pre-invoke=', ''),
    ('pre-invoke=""', ''),
    ('pre-invoke="', ''),
    ("pre-invoke='", ''),
])
def test_hook_value_matches_dpkg(line, value):
    assert dpkg_hooks.parse_line(line) == {'option': 'pre-invoke', 'value': value}


@pytest.mark.parametrize('line', ['', '   ', '\t', '\r', '#', '# c', '# c\r', '#pre-invoke=x'])
def test_skipped_lines(line):
    assert dpkg_hooks.parse_line(line) is None


@pytest.mark.parametrize('line,detail', [
    (' pre-invoke=x', "unknown option ''"),
    ('  # c', "unknown option ''"),
    ('=x', "unknown option ''"),
    ('pre-invoke', "'pre-invoke' needs a value"),
    ('post-invoke', "'post-invoke' needs a value"),
    ('status-logger', "'status-logger' needs a value"),
    ('root', "'root' needs a value"),
    ('admindir', "'admindir' needs a value"),
    ('log', "'log' needs a value"),
    ('pre-invoke="q" x', "unbalanced quotes in 'pre-invoke'"),
    ('pre-invoke="a', "unbalanced quotes in 'pre-invoke'"),
    ('pre-invoke=\'@x"', "unbalanced quotes in 'pre-invoke'"),
    ('pre-invoke="@x\'', "unbalanced quotes in 'pre-invoke'"),
    ("pre-invoke=''@", "unbalanced quotes in 'pre-invoke'"),
    ('Pre-Invoke=x', "unknown option 'Pre-Invoke'"),
    ('bogus', "unknown option 'bogus'"),
    ('pre_invoke=x', "unknown option 'pre'"),
    ('D=1', "unknown option 'D'"),
    ('B', "unknown option 'B'"),
    ('unsafe-io', "unknown option 'unsafe-io'"),
    ('no-debsig=1', "'no-debsig' does not take a value"),
    ('no-debsig=', "'no-debsig' does not take a value"),
    ('install=x', "'install' does not take a value"),
    ('force-depends,bogus', "unknown option 'force-depends'"),
    ('force-depends=x', "unknown option 'force-depends'"),
    ('assert-multi-arch=1', "unknown option 'assert-multi-arch'"),
    ('force-', "unknown force/refuse option ''"),
    ('force-bogus', "unknown force/refuse option 'bogus'"),
    ('force=depends,bogus', "unknown force/refuse option 'bogus'"),
    ('force=depends,', "unknown force/refuse option ''"),
    ('refuse-', "unknown force/refuse option ''"),
    ('verify-format=RPM', "invalid value for 'verify-format'"),
    ('verify-format=', "invalid value for 'verify-format'"),
    ('abort-after=x', "invalid value for 'abort-after'"),
    ('abort-after=-1', "invalid value for 'abort-after'"),
    ('abort-after=08', "invalid value for 'abort-after'"),
    ('status-fd=x', "invalid value for 'status-fd'"),
    ('debug=8', "invalid value for 'debug'"),
    ('debug=', "invalid value for 'debug'"),
    ('ignore-depends=x,', "invalid value for 'ignore-depends'"),
    ('ignore-depends=x y', "invalid value for 'ignore-depends'"),
    ('ignore-depends=-x', "invalid value for 'ignore-depends'"),
    ('ignore-depends=x:', "invalid value for 'ignore-depends'"),
    ('ignore-depends=x:bogus_arch', "invalid value for 'ignore-depends'"),
])
def test_lines_dpkg_rejects(line, detail):
    assert dpkg_hooks.parse_line(line) == {'error': 'config_error', 'detail': detail}


@pytest.mark.parametrize('line', ['configure', 'unpack', 'help', 'version', 'compare-versions', 'triggers-only',
                                  'assert-multi-arch', 'assert-'])
def test_action_in_a_configuration_file_is_rejected(line):
    parsed = dpkg_hooks.parse_line(line)
    assert parsed['error'] == 'config_error' and 'is an action' in parsed['detail']


def test_force_help_is_not_treated_as_accepted():
    assert dpkg_hooks.parse_line('force-help')['error'] == 'config_error'
    assert dpkg_hooks.parse_line('force=depends,help')['error'] == 'config_error'


@pytest.mark.parametrize('line,option,value', [
    ('no-debsig', 'no-debsig', None),
    ('no-debsig ', 'no-debsig', None),
    ('no-debsig\r', 'no-debsig', None),
    ('force-all', 'force', 'all'),
    ('force all', 'force', 'all'),
    ('force=all', 'force', 'all'),
    ('force=depends,overwrite', 'force', 'depends,overwrite'),
    ('force-unsafe-io', 'force', 'unsafe-io'),
    ('no-force-all', 'no-force', 'all'),
    ('no-force-depends', 'no-force', 'depends'),
    ('refuse-downgrade', 'refuse', 'downgrade'),
    ('refuse-all', 'refuse', 'all'),
    ('root=/x', 'root', '/x'),
    ('admindir=/var/lib/dpkg', 'admindir', '/var/lib/dpkg'),
    ('instdir=/', 'instdir', '/'),
    ('log /var/log/dpkg.log', 'log', '/var/log/dpkg.log'),
    ('path-exclude=/x', 'path-exclude', '/x'),
    ('path-exclude=', 'path-exclude', ''),
    ('ignore-depends=x,y', 'ignore-depends', 'x,y'),
    ('ignore-depends=x:amd64', 'ignore-depends', 'x:amd64'),
    ('ignore-depends=a.b+c-d', 'ignore-depends', 'a.b+c-d'),
    ('ignore-depends=', 'ignore-depends', ''),
    ('verify-format=rpm', 'verify-format', 'rpm'),
    ('abort-after=3', 'abort-after', '3'),
    ('abort-after= 5', 'abort-after', '5'),
    ('debug=0', 'debug', '0'),
    ('no-triggers', 'no-triggers', None),
    ('dry-run', 'dry-run', None),
    ('auto-deconfigure', 'auto-deconfigure', None),
])
def test_accepted_options_match_dpkg(line, option, value):
    assert dpkg_hooks.parse_line(line) == {'option': option, 'value': value}


def test_uninterpreted_lines_fail_closed():
    assert dpkg_hooks.parse_line('pre-invoke=a\x00b')['error'] == 'nul_byte'
    assert dpkg_hooks.parse_line('pre-invoke x')['error'] == 'non_ascii_separator'
    assert dpkg_hooks.parse_line('#' + 'a' * 1021) is None  # 1022 bytes: dpkg reads it whole
    assert dpkg_hooks.parse_line('#' + 'a' * 1022)['error'] == 'line_too_long'  # dpkg splits it
    assert dpkg_hooks.parse_line('#' + 'é' * 511)['error'] == 'line_too_long'  # bytes, not characters
    assert dpkg_hooks.parse_line('pre-invoke=café') == {'option': 'pre-invoke', 'value': 'café'}


def test_directory_is_read_in_byte_order_before_the_main_file():
    # Recorded order for these names and a hook in dpkg.cfg: - 0 B Z9 _ a-b a_b aa ab, then main.
    names = ['aa', 'B', 'a_b', 'a-b', 'Z9', '0', 'ab', '_', '-']
    result = resolve(*(part(n, f'pre-invoke=echo {n}\n') for n in names),
                     part('a.conf', 'pre-invoke=echo dot\n'), part('.hid', 'pre-invoke=echo hid\n'),
                     main={'present': True, 'content': '# c\nlog /var/log/dpkg.log\npre-invoke=echo main\n'})
    assert [c['command'] for c in result['commands']] == [
        f'echo {n}' for n in ['-', '0', 'B', 'Z9', '_', 'a-b', 'a_b', 'aa', 'ab', 'main']]
    assert result['commands'][-1] == {'option': 'pre-invoke', 'path': MAIN, 'line': 3, 'command': 'echo main',
                                      'empty': False}
    assert result['dpkg_behavior'] == 'determined'
    assert result['other_options'] == 1
    assert codes(result) == ALWAYS + ['collation_order_assumed']
    ignored = {f['path']: f['reason'] for f in result['files'] if f['state'] == 'ignored'}
    assert ignored == {f'{PARTS}/a.conf': 'invalid_name', f'{PARTS}/.hid': 'hidden'}


def test_commands_relocations_and_behavior_changes_are_reported_with_sources():
    text = ('pre-invoke=/usr/local/bin/pre\n'
            'post-invoke="/usr/local/bin/post --flag"\n'
            'status-logger=cat > /dev/null\n'
            'pre-invoke=\n'
            'root=/mnt\nadmindir=/tmp/db\ninstdir /srv\nroot=/other\n'
            'force-overwrite\nforce=depends,bad-verify\nrefuse-downgrade\nno-force-all\n'
            'no-debsig\nignore-depends=libc6\nno-act\nsimulate\nno-triggers\npath-exclude=/usr/share/doc/*\n'
            'path-include=/usr/share/doc/*/copyright\nlog=/dev/null\nno-pager\n')
    result = resolve(part('hooks', text))
    assert result['dpkg_behavior'] == 'determined' and codes(result) == ALWAYS
    path = f'{PARTS}/hooks'
    assert result['commands'] == [
        {'option': 'pre-invoke', 'path': path, 'line': 1, 'command': '/usr/local/bin/pre', 'empty': False},
        {'option': 'post-invoke', 'path': path, 'line': 2, 'command': '/usr/local/bin/post --flag', 'empty': False},
        {'option': 'status-logger', 'path': path, 'line': 3, 'command': 'cat > /dev/null', 'empty': False},
        {'option': 'pre-invoke', 'path': path, 'line': 4, 'command': '', 'empty': True},
    ]
    assert [(r['option'], r['value'], r['line']) for r in result['relocations']] == [
        ('root', '/mnt', 5), ('admindir', '/tmp/db', 6), ('instdir', '/srv', 7), ('root', '/other', 8)]
    assert [(c['kind'], c.get('things', c.get('value')), c['option']) for c in result['behavior_changes']] == [
        ('force', ['overwrite'], 'force'), ('force', ['depends', 'bad-verify'], 'force'),
        ('refuse', ['downgrade'], 'refuse'), ('refuse', ['all'], 'no-force'),
        ('no_debsig', None, 'no-debsig'), ('ignore_depends', 'libc6', 'ignore-depends'),
        ('no_act', None, 'no-act'), ('no_act', None, 'simulate'), ('no_triggers', None, 'no-triggers'),
        ('path_filter', '/usr/share/doc/*', 'path-exclude'),
        ('path_filter', '/usr/share/doc/*/copyright', 'path-include')]
    assert result['other_options'] == 2
    assert result['not_a_verdict'] == dpkg_hooks.NOT_A_VERDICT


def test_stock_ubuntu_configuration_is_determined_without_commands():
    main = ('# dpkg configuration file\n#\n\n# Do not enable debsig-verify by default.\nno-debsig\n\n'
            '# Log status changes and actions to a file.\nlog /var/log/dpkg.log\n')
    result = resolve(part('excludes', 'path-exclude=/usr/share/man/*\npath-include=/usr/share/doc/*/copyright\n'),
                     part('docker-apt-speedup', 'force-unsafe-io\n'), main={'present': True, 'content': main})
    assert result['dpkg_behavior'] == 'determined' and result['commands'] == [] and result['relocations'] == []
    assert [c['kind'] for c in result['behavior_changes']] == ['force', 'path_filter', 'path_filter', 'no_debsig']
    assert [f['state'] for f in result['files']] == ['parsed', 'parsed', 'parsed']


def test_rejected_line_is_undetermined_and_keeps_other_hooks_visible():
    result = resolve(part('a', 'pre-invoke=echo a\nbogus\npost-invoke=echo later\n'), part('b', 'pre-invoke=echo b\n'))
    assert result['dpkg_behavior'] == 'undetermined'
    assert [c['command'] for c in result['commands']] == ['echo a', 'echo later', 'echo b']
    gap = next(g for g in result['gaps'] if g['code'] == 'config_error')
    assert (gap['path'], gap['line'], gap['reason']) == (f'{PARTS}/a', 2, "unknown option 'bogus'")
    assert [f['state'] for f in result['files']] == ['error', 'parsed']


def test_line_numbers_count_blank_and_comment_lines_and_a_missing_final_newline():
    result = resolve(part('a', '\n\n# c\npre-invoke=echo nn'))
    assert result['commands'][0]['line'] == 4 and result['dpkg_behavior'] == 'determined'


def test_entry_types():
    result = resolve(part('dangling', None, 'missing'), part('dir', None, 'directory'), part('u', 'pre-invoke=u\n'))
    assert [(f['path'].rsplit('/', 1)[1], f['state'], f.get('reason')) for f in result['files']] == [
        ('dangling', 'ignored', 'dangling_link'), ('dir', 'not_regular_file', None), ('u', 'parsed', None)]
    assert result['dpkg_behavior'] == 'undetermined' and 'not_regular_file' in codes(result)
    # A dangling link alone is skipped silently, as dpkg does.
    assert resolve(part('dangling', None, 'missing'))['dpkg_behavior'] == 'determined'
    # An ineligible name is never opened, whatever it is.
    assert resolve(part('x.d', None, 'directory'))['dpkg_behavior'] == 'determined'


def test_missing_observations_fail_closed():
    assert 'parts_not_collected' in codes(dpkg_hooks.resolve(None, {'present': False}))
    assert 'main_not_collected' in codes(dpkg_hooks.resolve([], None))
    assert dpkg_hooks.resolve(None, None)['dpkg_behavior'] == 'undetermined'
    assert 'invalid_observation' in codes(dpkg_hooks.resolve('x', {'present': False}))
    assert 'invalid_observation' in codes(dpkg_hooks.resolve([], {'present': 'yes'}))
    assert 'invalid_entry' in codes(resolve({'name': 'a/b', 'type': 'file', 'content': ''}))
    assert 'invalid_entry' in codes(resolve('nope'))
    unreadable = resolve(part('a', None))
    assert unreadable['dpkg_behavior'] == 'undetermined' and 'file_unreadable' in codes(unreadable)
    assert 'file_unreadable' in codes(resolve(main={'present': True, 'content': None}))
    empty = dpkg_hooks.resolve([], {'present': False})
    assert empty['dpkg_behavior'] == 'determined' and codes(empty) == ALWAYS and empty['files'] == []


def test_caps_fail_closed():
    big = resolve(part('a', '#' + 'a' * 1000 + '\n' + '# x\n' * (dpkg_hooks.MAX_FILE_BYTES // 4)))
    assert 'file_too_large' in codes(big) and big['dpkg_behavior'] == 'undetermined'
    many = resolve(*(part(f'f{i:04d}', '') for i in range(dpkg_hooks.MAX_FILES + 1)))
    assert 'file_limit' in codes(many) and many['dpkg_behavior'] == 'undetermined'
    hooks = resolve(part('a', 'pre-invoke=x\n' * (dpkg_hooks.MAX_ENTRIES + 3)))
    assert len(hooks['commands']) == dpkg_hooks.MAX_ENTRIES and 'entry_limit' in codes(hooks)
    assert hooks['dpkg_behavior'] == 'undetermined'
    noisy = resolve(part('a', 'bogus\n' * (dpkg_hooks.MAX_GAPS + 10)))
    assert len(noisy['gaps']) == dpkg_hooks.MAX_GAPS + 1 and noisy['gaps'][-1]['code'] == 'gap_limit'
    chunk = '#' + 'a' * 1000 + '\n'
    parts = [part(f'f{i:02d}', chunk * 250) for i in range(18)]
    total = resolve(*parts)
    assert 'file_total_limit' in codes(total) and total['dpkg_behavior'] == 'undetermined'


def test_result_is_deterministic_and_does_not_mutate_input():
    files = [part('b', 'pre-invoke=b\n'), part('a', 'force-all\n')]
    snapshot = [dict(f) for f in files]
    first = dpkg_hooks.resolve(files, {'present': False})
    assert first == dpkg_hooks.resolve(list(reversed(files)), {'present': False})
    assert files == snapshot
