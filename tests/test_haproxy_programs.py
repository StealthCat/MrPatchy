"""Tests for the pure HAProxy program-section contract (#1555)."""
from __future__ import annotations

from app import haproxy_programs as hp

CFG = '/etc/haproxy/haproxy.cfg'
GLOBAL = 'global\n    master-worker\n'

# Native run: Ubuntu 24.04 haproxy 2.8.30-0ubuntu0.24.04.2 started as root with
# ``haproxy -W -f a.cfg -f b.cfg``. Each program was an argv/uid-recording script.
NATIVE_A = 'global\n    master-worker\n    user haproxy\n    group haproxy\ndefaults\n    mode tcp\n    timeout connect 1s\n    timeout client 1s\n    timeout server 1s\nfrontend f\n    bind 127.0.0.1:18080\nprogram quoting\n    command /usr/local/bin/hap-rec "a b" \'c d\' \\x41\\ B "q\\"x" "it\'s" "\\$HOME" ${.SECTION} "${.LINE}" x#y # comment\n    user nobody\n    user daemon\nprogram emptyword\n    command hap-rec one "" two\n.if 0\nprogram dropped\n    command /usr/local/bin/hap-rec dropped\n.elif 1\nprogram elif\n    command /usr/local/bin/hap-rec first\n    command /usr/local/bin/hap-rec "${.FILE}" replaced\n.else\nprogram else\n    command /usr/local/bin/hap-rec else\n.endif\n'
NATIVE_B = 'program second-file\n    no option start-on-reload\n    group nogroup\n    command /usr/local/bin/hap-rec "${.SECTION}" tab\\tx\n'
# argv[1:] and ids each recorded process reported (argv[0] is rewritten by the
# script interpreter, so the native run compares the remaining words). uid/gid
# are numeric: nobody=65534, nogroup=65534, root=0.
NATIVE_OBSERVED = [
    (['a b', 'c d', 'A B', 'q"x', "it's", '$HOME', '${.SECTION}', '13', 'x'], 65534, 0),
    (['one'], 0, 0),
    (['a.cfg', 'replaced'], 0, 0),
    (['second-file', 'tab\tx'], 0, 65534),
]
IDS = {'nobody': 65534, 'nogroup': 65534, None: 0}


def run(*texts):
    if len(texts) == 1:
        return hp.evaluate([{'path': CFG, 'text': texts[0]}])
    return hp.evaluate([{'path': path, 'text': text} for path, text in texts])


def codes(result):
    return {g['code'] for g in result['gaps']}


def argvs(result):
    return {p['id']: p['argv'] for p in result['programs']}


def test_native_master_worker_run_matches_contract():
    result = run(('a.cfg', NATIVE_A), ('b.cfg', NATIVE_B))
    assert result['complete'] is True and result['gaps'] == []
    got = sorted((p['argv'][1:], IDS[p['user']], IDS[p['group']]) for p in result['programs'])
    assert got == sorted(NATIVE_OBSERVED)
    assert [p['id'] for p in result['programs']] == ['quoting', 'emptyword', 'elif', 'second-file']
    assert result['master_worker_in_config'] == {'path': 'a.cfg', 'line': 2}


def test_native_run_details():
    programs = {p['id']: p for p in run(('a.cfg', NATIVE_A), ('b.cfg', NATIVE_B))['programs']}
    assert programs['quoting']['user'] == 'nobody'  # the repeated "user daemon" only alerts
    assert programs['emptyword']['argv'] == ['hap-rec', 'one'] and programs['emptyword']['path_lookup'] is True
    assert programs['elif']['command_location'] == {'path': 'a.cfg', 'line': 24}
    assert programs['second-file']['start_on_reload'] is False
    assert programs['second-file']['runs_as']['supplementary_groups_dropped'] is True
    assert 'user_note' in programs['second-file']['runs_as']
    assert 'user_note' not in programs['quoting']['runs_as']


def test_tokenizer_quotes_escapes_and_comments():
    assert hp.parse_line('a "b c" \'d e\' f\\ g # x', {}) == ['a', 'b c', 'd e', 'f g']
    assert hp.parse_line('a\\ b \\x41\\x62 "\\$x" \'\\n\'', {}) == ['a b', 'Ab', '$x', '\\n']
    assert hp.parse_line('x#y z', {}) == ['x']
    assert hp.parse_line('a \\q', {}) == ['a', '\\q']
    assert hp.parse_line('a\x0bb\x0cc', {}) == ['a', 'b', 'c']
    assert hp.parse_line('a "" b ""', {}) == ['a', '', 'b']
    assert hp.parse_line('a $HOME', {}) == ['a', '$HOME']
    assert hp.parse_line('"${.S-dflt}" "${.L}"', {'.S': None, '.L': '7'}) == ['dflt', '7']
    assert hp.parse_line('"${.X[*]}"', {'.X': 'p  q'}) == ['p', 'q']


def test_tokenizer_errors():
    for line, code in (('a "b', 'quote_unmatched'), ("a 'b", 'quote_unmatched'), ('a \\xZ1', 'hex_escape_invalid'),
                       ('a "$1"', 'variable_name_invalid'), ('a "${.L"', 'brace_unmatched'),
                       ('a "${.L[x]}"', 'word_expand_invalid'), ('a "$.NOPE"', 'variable_name_invalid'),
                       ('a "$HOME"', 'environment_variable'), (' '.join(['w'] * 65), 'too_many_words')):
        try:
            hp.parse_line(line, {'.L': '1'})
        except hp._TokenError as exc:
            assert exc.code == code, line
        else:
            raise AssertionError(line)
    assert len(hp.parse_line(' '.join(['w'] * 64), {})) == 64


def test_rejected_configurations_are_blocking_gaps():
    # Each of these makes "haproxy -c" exit 1 on the native 2.8.30 build.
    cases = {
        GLOBAL + 'program p\n    command /bin/true': 'missing_final_lf',
        GLOBAL + 'program p\n    command /bin/true\nprogram p\n    command /bin/true\n': 'program_duplicate',
        GLOBAL + 'program p\n': 'program_without_command',
        '    command /bin/true\nglobal\n': 'out_of_section',
        GLOBAL + 'program p\n    no command /bin/true\n': 'modifier_not_supported',
        GLOBAL + 'program p\n    command /bin/true \\xZZ\n': 'hex_escape_invalid',
        GLOBAL + 'program p\n    command /bin/true\n.else\n': 'condition_malformed',
        GLOBAL + 'program p\n    commnd /bin/true\n': 'program_malformed',
        GLOBAL + 'program p x\n': 'program_malformed',
        GLOBAL + '.alert "stop"\n': 'config_alert',
        GLOBAL + '.if 1\n': 'unterminated_condition',
        GLOBAL + '.if 0\n.else\nprogram p\n    command /bin/p\n.elif 1\n.endif\n': 'condition_malformed',
        GLOBAL + 'program p\n    command /bin/true\x00\n': 'nul_byte',
    }
    for text, code in cases.items():
        result = run(text)
        assert code in codes(result), (text, result['gaps'])
        assert result['complete'] is False


def test_conditions():
    body = 'program a\n    command /bin/a\n'
    assert argvs(run(GLOBAL + '.if 2\n' + body + '.endif\n')) == {'a': ['/bin/a']}
    assert argvs(run(GLOBAL + '.if 010\n' + body + '.endif\n')) == {'a': ['/bin/a']}
    assert argvs(run(GLOBAL + '.if 0x0\n' + body + '.endif\n')) == {}
    nested = GLOBAL + '.if 0\n.if 1\n' + body + '.endif\n.else\nprogram b\n    command /bin/b\n.endif\n'
    assert argvs(run(nested)) == {'b': ['/bin/b']}
    unknown = run(GLOBAL + '.if defined(HAPROXY_LOCALPEER)\n' + body + '.endif\n')
    assert 'condition_unevaluated' in codes(unknown) and unknown['complete'] is False
    assert argvs(unknown) == {'a': ['/bin/a']}  # shown, but never complete


def test_program_rules():
    result = run(GLOBAL + 'program p\n    command /bin/one\n    command run "two words"\n'
                 '    group adm\n    group staff\n    option start-on-reload\n    no option start-on-reload\n'
                 '    default option start-on-reload\n')
    (program,) = result['programs']
    assert program['argv'] == ['run', 'two words'] and program['path_lookup'] is True
    assert program['group'] == 'adm' and program['user'] is None and program['start_on_reload'] is False
    assert result['complete'] is True


def test_sections_reset_per_file_and_programs_outside_master_worker_config():
    result = run((CFG, 'program p\n    command /bin/p\n'), ('/etc/haproxy/conf.d/x.cfg', '    user root\n'))
    assert 'out_of_section' in codes(result)
    assert result['programs'][0]['user'] is None
    only_programs = run('program p\n    command /bin/p\n')
    assert only_programs['complete'] is True and only_programs['master_worker_in_config'] is None


def test_scope_and_unknown_directives_are_gaps():
    assert 'scope_directive' in codes(run(GLOBAL + '[scope]\n'))
    assert 'unknown_directive' in codes(run(GLOBAL + '.bogus\n'))


# Increment 2 native run: Ubuntu 24.04 haproxy 2.8.30-0ubuntu0.24.04.2 started as root
# with ``haproxy -W -f a.cfg -f b.cfg``. The check command recorded ``id -u``, ``id -g``,
# ``id -G``, $PATH, $HAPROXY_PROXY_NAME and its arguments.
EXT_A = """global
    master-worker
    external-check
    insecure-fork-wanted
    user nobody
    group nogroup
defaults
    mode tcp
    timeout connect 1s
    timeout client 1s
    timeout server 1s
    timeout check 1s
    option external-check
    external-check command /usr/local/bin/hc-rec
backend inherit
    server s1 127.0.0.1:9 check inter 700
backend relative
    external-check path "/usr/local/bin:/bin"
    external-check command hc-rec
    server s2 127.0.0.2:10 check inter 700
backend replaced
    option httpchk
    server s3 127.0.0.3:11 check inter 700
listen withbind
    bind 127.0.0.1:18081
    server s4 127.0.0.4:12 check inter 700
backend nocheck
    server s5 127.0.0.5:13
"""
EXT_B = 'backend secondfile\n    server s6 127.0.0.6:14 check inter 700\n'
# (proxy, PATH, argv[1:]) each recorded process reported, all as uid/gid/groups 65534.
EXT_OBSERVED = {
    ('inherit', '', ('NOT_USED', 'NOT_USED', '127.0.0.1', '9')),
    ('relative', '/usr/local/bin:/bin', ('NOT_USED', 'NOT_USED', '127.0.0.2', '10')),
    ('withbind', '', ('127.0.0.1', '18081', '127.0.0.4', '12')),
    ('secondfile', '', ('NOT_USED', 'NOT_USED', '127.0.0.6', '14')),
}


def checks(result):
    return {c['proxy']: c for c in result['external_checks']}


def test_native_external_check_run_matches_contract():
    result = run(('a.cfg', EXT_A), ('b.cfg', EXT_B))
    assert result['complete'] is True and result['gaps'] == []
    found = checks(result)
    # "replaced" switched to httpchk, so its inherited command is ignored (HAProxy warns).
    # "nocheck" has no server with "check"; per-server activation is not evaluated, so it is listed.
    assert set(found) == {'inherit', 'relative', 'withbind', 'secondfile', 'nocheck'}
    observed_proxies = {proxy for proxy, _, _ in EXT_OBSERVED}
    for proxy, path_env, _ in EXT_OBSERVED:
        check = found[proxy]
        assert check['path_env'] == path_env
        assert check['runs_as']['user'] == 'nobody' and check['runs_as']['group'] == 'nogroup'
        assert check['runs_as']['supplementary_groups_dropped'] is True and 'user_note' not in check['runs_as']
        assert check['fork'] == 'allowed' and check['environment'] == 'only_path_and_haproxy_variables'
        assert len(check['argv_template']) == 5 and check['argv_template'][0] == check['command']
    assert observed_proxies < set(found)
    assert found['inherit']['command'] == '/usr/local/bin/hc-rec' and found['inherit']['path_lookup'] is False
    assert found['inherit']['command_location'] == {'path': 'a.cfg', 'line': 14}  # from defaults
    assert found['secondfile']['command_location'] == {'path': 'a.cfg', 'line': 14}  # defaults span files
    assert found['relative']['command'] == 'hc-rec' and found['relative']['path_lookup'] is True
    assert found['relative']['path_location'] == {'path': 'a.cfg', 'line': 18}
    assert [s['name'] for s in found['withbind']['servers']] == ['s4']
    assert result['external_check_global'] == {'enabled': {'path': 'a.cfg', 'line': 3}, 'preserve_env': False,
                                               'insecure_fork_wanted': True}


def test_native_external_check_identity_and_fork_gate():
    # Native runs of variants of EXT_A (single file):
    # - no user/group and no insecure-fork-wanted: checks ran as 0:0:0 (root ignores RLIMIT_NPROC 0);
    # - user nobody, group nogroup, no insecure-fork-wanted: "Failed to fork process for external health
    #   check (likely caused by missing 'insecure-fork-wanted')", nothing ran;
    # - user nobody only: checks ran as 65534:0 with root's supplementary groups;
    # - "external-check preserve-env" without master-worker: same identity and PATH.
    no_fork = EXT_A.replace('    insecure-fork-wanted\n', '')
    root = checks(run(no_fork.replace('    user nobody\n', '').replace('    group nogroup\n', '')))['inherit']
    assert root['fork'] == 'allowed_for_root_worker_only' and root['runs_as']['user'] is None
    assert root['runs_as']['supplementary_groups_dropped'] is False and 'user_note' in root['runs_as']
    assert checks(run(no_fork))['inherit']['fork'] == 'fails_unless_user_resolves_to_root'
    user_only = checks(run(EXT_A.replace('    group nogroup\n', '')))['inherit']['runs_as']
    assert user_only['user'] == 'nobody' and user_only['supplementary_groups_dropped'] is False
    preserved = run(EXT_A.replace('    external-check\n', '    external-check preserve-env\n')
                    .replace('    master-worker\n', ''))
    assert checks(preserved)['inherit']['environment'] == 'preserved_and_merged'
    assert preserved['master_worker_in_config'] is None
    later = run(EXT_A.replace('    insecure-fork-wanted\n', '    insecure-fork-wanted\n    no insecure-fork-wanted\n'))
    assert checks(later)['inherit']['fork'] == 'fails_unless_user_resolves_to_root'
    chroot = checks(run(EXT_A.replace('    user nobody\n', '    user nobody\n    chroot /var/lib/haproxy\n'
                                                         '    chroot /ignored\n')))
    assert chroot['inherit']['chroot'] == '/var/lib/haproxy'


EXT_G = 'global\n    external-check\n'
EXT_D = 'defaults\n    mode tcp\n'


def test_rejected_external_check_configurations_are_blocking_gaps():
    # Each of these makes "haproxy -c" exit 1 on the native 2.8.30 build.
    cases = {
        EXT_G + EXT_D + 'backend b\n    no option external-check\n': 'external_check_malformed',
        EXT_G + 'backend b\n    option external-check\n    external-check command /bin/a\n'
        '    default option external-check\n': 'external_check_malformed',
        EXT_G + 'backend b\n    option external-check\n    external-check command /bin/x\n'
        '    option external-check extra\n': 'external_check_malformed',
        EXT_G + 'backend b\n    option external-check\n    external-check command /bin/x y\n':
            'external_check_malformed',
        EXT_G + 'backend b\n    option external-check\n    external-check foo /bin/x\n': 'external_check_malformed',
        EXT_G + 'backend b\n    option external-check\n    external-check command ""\n':
            'external_check_malformed',
        'global\n    external-check bogus\n': 'external_check_malformed',
        EXT_G + 'backend b\n    option external-check\n    external-check command rel\n':
            'external_check_relative_without_path',
        EXT_G + 'backend b\n    external-check command rel\n': 'external_check_relative_without_path',
        EXT_G + 'defaults\n    external-check command rel\nbackend b\n    option httpchk\n':
            'external_check_relative_without_path',
        'global\n' + EXT_D + 'backend b\n    option external-check\n    external-check command /bin/x\n':
            'external_check_not_enabled',
        'global\nfrontend f\n    bind 127.0.0.1:18090\n    option external-check\n': 'external_check_not_enabled',
        EXT_G + 'backend b\n    option external-check\n': 'external_check_without_command',
        EXT_G + 'defaults\n    option external-check\nbackend b\n    server s 127.0.0.1:1 check\n':
            'external_check_without_command',
    }
    for text, code in cases.items():
        result = run(text)
        assert code in codes(result), (text, result['gaps'])
        assert result['complete'] is False


def test_accepted_external_check_configurations():
    # Each of these passes "haproxy -c" on the native 2.8.30 build (warnings only).
    # A defaults section is never post-parsed, and a frontend has no servers.
    for text in ('global\ndefaults\n    option external-check\n    external-check command rel\n',
                 EXT_G + 'frontend f\n    bind 127.0.0.1:18090\n    option external-check\n'
                 '    external-check command /bin/x\n'):
        result = run(text)
        assert result['complete'] is True and result['external_checks'] == [], (text, result['gaps'])
    # Repeats: the last command and path win.
    repeats = run(EXT_G + 'backend b\n    option external-check\n    external-check command /bin/a\n'
                  '    external-check command /bin/b\n    external-check path /x\n    external-check path /y\n')
    assert repeats['complete'] is True
    assert (checks(repeats)['b']['command'], checks(repeats)['b']['path_env']) == ('/bin/b', '/y')
    # A later check-type option replaces the external check, and vice versa.
    assert checks(run(EXT_G + 'backend b\n    option external-check\n    option httpchk\n'
                      '    external-check command /bin/a\n')) == {}
    assert set(checks(run(EXT_G + 'backend b\n    option httpchk\n    option external-check\n'
                          '    external-check command /bin/a\n'))) == {'b'}
    # A new defaults section starts empty, so later proxies no longer inherit the external check.
    fresh = run(EXT_G + 'defaults\n    option external-check\n    external-check command /bin/a\n'
                'backend one\ndefaults\nbackend two\n')
    assert set(checks(fresh)) == {'one'} and fresh['complete'] is True


def test_external_check_unmodelled_inputs_fail_closed():
    named = run(EXT_G + 'defaults d1\n    external-check command /bin/x\ndefaults\nbackend b from d1\n'
                '    option external-check\n')
    assert 'defaults_from_unmodelled' in codes(named) and named['complete'] is False
    # "user root" leaves uid 0, so a second "user" would win; names are not resolved.
    repeated = run(EXT_A.replace('    user nobody\n', '    user nobody\n    uid 0\n'))
    assert 'global_identity_ambiguous' in codes(repeated) and repeated['complete'] is False
    assert checks(repeated)['inherit']['runs_as']['user'] == 'nobody'
    # Without any external check, a repeated identity does not matter to this contract.
    assert run('global\n    user a\n    user b\n')['complete'] is True


def test_input_limits():
    assert codes(hp.evaluate('nope')) == {'input_malformed'}
    assert codes(hp.evaluate([{'path': CFG}])) == {'input_malformed'}
    assert codes(hp.evaluate([{'path': CFG, 'text': 'x' * (hp.MAX_TEXT + 1)}])) == {'text_too_large'}
    assert codes(hp.evaluate([{'path': str(i), 'text': ''} for i in range(hp.MAX_FILES + 1)])) == {'too_many_files'}
    assert hp.evaluate([])['complete'] is True
    result = run(GLOBAL + ''.join(f'.warning "w{i}" extra\n' for i in range(40)))
    assert len(result['gaps']) == hp.MAX_GAPS + 1 and result['gaps'][-1]['code'] == 'gaps_truncated'
    assert result['not_a_verdict'] and result['unobserved']


def test_escaped_nul_ends_the_c_string_word():
    # Native run (Ubuntu haproxy 2.8.30-0ubuntu0.24.04.2, ``haproxy -W`` as root):
    # HAProxy's words are C strings, so a NUL produced by \x00 cuts the word there,
    # and a word that is only \x00 is empty and ends the command's argv.
    assert hp.parse_line('a "ab\\x00cd" b\\x00 \\x00', {}) == ['a', 'ab', 'b']
    result = run(GLOBAL + 'program p1\n    command rec.sh p1 "ab\\x00cd" two\n'
                 'program p2\n    command rec.sh p2 x "\\x00" y\n')
    assert argvs(result) == {'p1': ['rec.sh', 'p1', 'ab', 'two'], 'p2': ['rec.sh', 'p2', 'x']}
    assert result['complete'] is True and result['gaps'] == []
    # "'command' expects a command": rejected, so the contract is incomplete.
    result = run(GLOBAL + 'program p3\n    command "\\x00" x\n')
    assert {'program_malformed', 'program_without_command'} <= codes(result)
    assert result['complete'] is False and argvs(result) == {'p3': None}
