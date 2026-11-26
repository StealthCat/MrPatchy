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


def test_external_check_and_scope_are_unmodelled():
    for line in ('    option external-check\n', '    external-check command /bin/check\n',
                 '    no option external-check\n'):
        assert 'external_check_unmodelled' in codes(run(GLOBAL + 'backend b\n' + line))
    assert 'scope_directive' in codes(run(GLOBAL + '[scope]\n'))
    assert 'unknown_directive' in codes(run(GLOBAL + '.bogus\n'))


def test_input_limits():
    assert codes(hp.evaluate('nope')) == {'input_malformed'}
    assert codes(hp.evaluate([{'path': CFG}])) == {'input_malformed'}
    assert codes(hp.evaluate([{'path': CFG, 'text': 'x' * (hp.MAX_TEXT + 1)}])) == {'text_too_large'}
    assert codes(hp.evaluate([{'path': str(i), 'text': ''} for i in range(hp.MAX_FILES + 1)])) == {'too_many_files'}
    assert hp.evaluate([])['complete'] is True
    result = run(GLOBAL + ''.join(f'.warning "w{i}" extra\n' for i in range(40)))
    assert len(result['gaps']) == hp.MAX_GAPS + 1 and result['gaps'][-1]['code'] == 'gaps_truncated'
    assert result['not_a_verdict'] and result['unobserved']
