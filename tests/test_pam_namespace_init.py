"""Tests for the pure pam_namespace init-script contract (#1564).

Cases marked "native" replay runs of Ubuntu 24.04 ``libpam-modules
1.5.3-5ubuntu5.7`` (pam_namespace synced to Linux-PAM 1.7 with the CVE-2025-6020
fixes). A ctypes ``pam_open_session`` driver ran the stack
``session required pam_namespace.so [args]`` for user ``nsuser`` inside
``unshare -m``, and every init script logged its argv.
"""
import pytest

from app import pam_namespace_init as ns

INIT = '/etc/security/namespace.init'
A = '/etc/security/namespace.d/a.sh'
B = '/etc/security/namespace.d/b.sh'


def _obs(conf, d=None, scripts=None, args=(), model='1.7', conf_state=None):
    namespace_conf = {'state': conf_state} if conf_state else {'state': 'regular', 'text': conf}
    entries = {name: {'state': 'regular', 'text': text} for name, text in (d or {}).items()}
    return {
        'model': model,
        'namespace_conf': namespace_conf,
        'namespace_d': {'state': 'listed', 'entries': entries},
        'scripts': {INIT: 'executable', A: 'executable', B: 'executable', **(scripts or {})},
        'module_args': list(args),
    }


def _ran(result):
    return [(c['script'], c['argv'][1], c['argv'][2]) for c in result['commands'] if c['reachable'] is True]


def test_native_default_and_relative_iscript_argv():
    result = ns.resolve(_obs('/tmp/poly1 /tmp/inst/ user\n/tmp/poly2 x tmpfs:iscript=a.sh\n'))
    assert result['complete'] and not result['authorizes_response']
    first, second = result['commands']
    # native: namespace.init|/tmp/poly1|/tmp/inst/nsuser|1|nsuser|1|1
    assert first['argv'] == [INIT, '/tmp/poly1', '/tmp/inst/<user_or_hash>', '<newdir:0|1>', '<user>',
                             '<polydir_safe:0|1>', '<instance_safe:0|1>']
    # native: namespace.d/rel.sh|/tmp/poly2|tmpfs|1|nsuser|1|0
    assert second['argv'] == [A, '/tmp/poly2', 'tmpfs', '1', '<user>', '<polydir_safe:0|1>', '0']
    assert second['per_directory_iscript'] and second['environment'] == {}
    assert all(c['runs_as'] == 'root' and c['exit_status_ignored'] and c['origin'] == 'not_assessed'
               for c in result['commands'])
    assert result['reachable_commands'] == 2 and result['config_outcome'] == 'ok'


def test_legacy_model_passes_four_arguments_and_rejects_root_polydir():
    result = ns.resolve(_obs('/tmp/p1 /tmp/inst/ user\n/ /tmp/inst/ user\n', model='1.5', args=['ignore_config_error']))
    command, = result['commands']
    assert len(command['argv']) == 5
    assert result['invalid_lines'][0]['error'] == 'invalid_polydir'


def test_native_root_polydir_and_trailing_slashes_are_valid_in_1_7():
    result = ns.resolve(_obs('/ /tmp/inst/ user\n/tmp/p1// /tmp/inst/ user\n'))
    assert [d['polydir'] for d in result['directories']] == ['/', '/tmp/p1']


def test_native_invalid_line_fails_every_session_without_ignore_config_error():
    conf = '/tmp/p1 /tmp/inst/ bogus\n/tmp/p2 /tmp/inst/ user\n'
    failing = ns.resolve(_obs(conf))
    assert failing['config_outcome'] == 'every_session_fails' and _ran(failing) == []
    assert failing['invalid_lines'][0]['error'] == 'unknown_method'
    ignored = ns.resolve(_obs(conf, args=['ignore_config_error']))
    assert ignored['config_outcome'] == 'ok' and _ran(ignored) == [(INIT, '/tmp/p2', '/tmp/inst/<user_or_hash>')]
    unknown = ns.resolve({**_obs(conf), 'module_args': None})
    assert unknown['config_outcome'] == 'depends_on_ignore_config_error'
    assert unknown['commands'][0]['reachable'] is None and unknown['reachable_commands'] == 0


def test_native_hash_ends_the_line_even_inside_quotes():
    result = ns.resolve(_obs('"/tmp/p1#x" /tmp/inst/ user\n'))
    assert result['invalid_lines'][0]['error'] == 'missing_instance_prefix'
    assert result['config_outcome'] == 'every_session_fails'


def test_native_iscript_last_non_empty_wins_and_noinit_suppresses():
    conf = ('/tmp/p1 /tmp/inst/ user:iscript=a.sh:iscript=b.sh\n'
            '/tmp/p2 /tmp/inst/ user:iscript=a.sh:iscript=\n'
            '/tmp/p3 /tmp/inst/ user:iscriptX\n'
            '/tmp/p4 /tmp/inst/ user:noinit:iscript=a.sh\n')
    result = ns.resolve(_obs(conf))
    assert [(c['script'], c['argv'][1]) for c in result['commands']] == [
        (B, '/tmp/p1'), (A, '/tmp/p2'), (INIT, '/tmp/p3')]
    assert result['directories'][3]['effect'] == 'noinit'


def test_native_flags_match_by_prefix_and_extra_fields_are_ignored():
    conf = '/tmp/p1 /tmp/inst/ user:createfoo:noinitbar\n/tmp/p2 /tmp/inst/ ::user:bogusflag extra fields here\n'
    result = ns.resolve(_obs(conf))
    assert result['directories'][0]['flags'] == ['create', 'noinit']
    assert _ran(result) == [(INIT, '/tmp/p2', '/tmp/inst/<user_or_hash>')]
    assert result['directories'][1]['applies_to'] == {'mode': 'all_except_listed', 'users': ['extra']}


@pytest.mark.parametrize('line, error', [
    ('/tmp/p1 /tmp/inst/ User', 'unknown_method'),             # native
    ('/tmp/p1 inst/ user', 'path_not_absolute'),               # native
    ('/tmp/p1 /tmp/inst/../inst/ user', 'path_contains_dotdot'),  # native
    ('$USER/x /tmp/inst/ user', 'path_not_absolute'),
    ('"" /tmp/inst/ user', 'invalid_polydir'),
    ('/tmp/p1', 'missing_instance_prefix'),
    ('/tmp/p1 /tmp/inst/', 'missing_method'),
    ('/tmp/' + 'a' * 4100 + ' /tmp/inst/ user', 'path_too_long'),
])
def test_invalid_lines(line, error):
    result = ns.resolve(_obs(line + '\n'))
    assert result['invalid_lines'][0]['error'] == error


def test_native_method_without_name_crashes_and_is_a_gap():
    result = ns.resolve(_obs('/tmp/p1 /tmp/inst/ :\n'))
    assert result['invalid_lines'][0]['error'] == 'method_without_name_crashes'
    assert not result['complete'] and result['gaps'][0]['code'] == 'method_without_name_crashes'


def test_native_tmpfs_instance_may_be_relative_and_expansions_are_reported():
    result = ns.resolve(_obs('/tmp/p1 /tmp/inst/ tmpdir\n/tmp/p2 rel tmpfs:mntopts=size=1m\n'
                             '$HOME/x /tmp/inst/$USERz- user\n'))
    assert [c['argv'][2] for c in result['commands']] == ['/tmp/inst/<random6>', 'tmpfs',
                                                          '/tmp/inst/$USERz-<user_or_hash>']
    assert result['directories'][2]['expansions'] == ['$HOME', '$USER']


def test_native_override_lists():
    conf = ('/tmp/p1 /tmp/inst/ user ~root\n/tmp/p2 /tmp/inst/ user nsuser,ghost\n')
    first, second = ns.resolve(_obs(conf))['commands']
    assert first['applies_to'] == {'mode': 'only_listed', 'users': ['root']}
    assert second['applies_to'] == {'mode': 'all_except_listed', 'users': ['nsuser', 'ghost']}


def test_native_missing_script_runs_nothing_and_non_executable_stops_later_directories():
    conf = '/tmp/p0 /tmp/inst/ user:iscript=nope.sh\n/tmp/p2 /tmp/inst/ user\n/tmp/p1 /tmp/inst/ user:iscript=a.sh\n/tmp/p3 /tmp/inst/ user\n'
    result = ns.resolve(_obs(conf, scripts={'/etc/security/namespace.d/nope.sh': 'absent', A: 'not_executable'}))
    assert [d['effect'] for d in result['directories']] == [
        'script_absent_nothing_runs', 'runs_as_root', 'session_fails_here', 'runs_as_root']
    assert result['session_stops_at'] == {'path': ns.CONF, 'line': 3}
    assert _ran(result) == [(INIT, '/tmp/p2', '/tmp/inst/<user_or_hash>')]
    assert result['commands'][1]['after_failure_point'] and result['commands'][1]['reachable'] is False


def test_native_dropins_follow_namespace_conf_in_strcmp_order_and_skip_hidden():
    result = ns.resolve(_obs('/tmp/p1 /tmp/inst/ user\n', d={
        'b.conf': '/tmp/p3 /tmp/inst/ user\n', 'a.conf': '/tmp/p2 /tmp/inst/ user\n',
        '.h.conf': '/tmp/p4 /tmp/inst/ user\n', 'notes.txt': '/tmp/p5 /tmp/inst/ user\n'}))
    assert [c['argv'][1] for c in result['commands']] == ['/tmp/p1', '/tmp/p2', '/tmp/p3']


def test_native_missing_namespace_conf_fails_even_with_dropins():
    result = ns.resolve(_obs(None, d={'a.conf': '/tmp/p2 /tmp/inst/ user\n'}, conf_state='absent',
                             args=['ignore_config_error']))
    assert result['config_outcome'] == 'every_session_fails'
    assert result['config_fatal'] == {'path': ns.CONF, 'reason': 'cannot_open'} and _ran(result) == []


def test_unmnt_only_runs_nothing():
    result = ns.resolve(_obs('/tmp/p1 /tmp/inst/ user\n', args=['unmnt_only']))
    assert result['commands'][0]['reachable'] is False


def test_argv_parse_quotes_and_escapes():
    assert ns.argv_parse('a"b c"d e\\tf \\"g "h\\i"') == ['ab cd', 'e\tf', '"g', 'h\\i']
    assert ns.argv_parse('  ') == []


def test_comment_blank_and_carriage_return_lines():
    result = ns.resolve(_obs('# x\n\n   \n/tmp/p1 /tmp/inst/ user\r\n'))
    assert [d['polydir'] for d in result['directories']] == ['/tmp/p1']


@pytest.mark.parametrize('change, code', [
    ({'namespace_conf': None}, 'file_unobserved'),
    ({'namespace_d': None}, 'listing_unobserved'),
    ({'namespace_d': {'state': 'unreadable'}}, 'listing_not_modelled'),
    ({'scripts': {}}, 'script_unobserved'),
    ({'model': '1.6'}, 'version_unverified'),
    ({'vendor_dir': '/usr/lib'}, 'vendor_dir_not_modelled'),
    ({'namespace_conf': {'state': 'regular', 'text': '/tmp/p1 /tmp/inst/ user\x00\n'}}, 'nul_byte'),
    ({'namespace_conf': {'state': 'regular', 'text': '/tmp/p1 /tmp/inst/ user:create=0700,bin,adm\n'}},
     'create_account_unchecked'),
])
def test_gaps_make_the_result_incomplete(change, code):
    result = ns.resolve({**_obs('/tmp/p1 /tmp/inst/ user\n'), **change})
    assert not result['complete'] and code in [gap['code'] for gap in result['gaps']]


@pytest.mark.parametrize('observation', [
    None, {'bogus': 1}, {'namespace_conf': {'state': 'weird'}},
    {'namespace_conf': {'state': 'absent', 'text': 'x'}},
    {'namespace_d': {'state': 'listed', 'entries': {'a/b.conf': {'state': 'absent'}}}},
    {'scripts': {'relative': 'executable'}}, {'scripts': {'/x': 'maybe'}},
    {'module_args': 'ignore_config_error'},
    {'namespace_conf': {'state': 'regular', 'text': 'x' * (ns.MAX_TEXT + 1)}},
])
def test_invalid_observations(observation):
    with pytest.raises(ns.Invalid):
        ns.resolve(observation)
