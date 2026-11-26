"""Tests for the pure Monit control-file program contract (#1373)."""
from __future__ import annotations

import pytest

from app import monit_programs as mp

RC = '/etc/monit/monitrc'


def run(text, includes=None):
    return mp.evaluate({'control': {'path': RC, 'text': text}, 'includes': includes or {}})


def cmds(result):
    return [(c['service'], c['role'], c['argv'], c['uid'], c['gid']) for c in result['commands']]


def codes(result):
    return {g['code'] for g in result['gaps']}


def test_process_start_stop_restart_with_user_and_timeout():
    result = run('check process web with pidfile /run/web.pid\n'
                 '  start program = "/usr/sbin/web start" as uid www and gid 33 with timeout 12 seconds\n'
                 '  stop "/usr/sbin/web stop"\n'
                 '  restart = "/usr/sbin/web reload"\n')
    assert cmds(result) == [('web', 'start', ['/usr/sbin/web', 'start'], 'www', 33),
                            ('web', 'stop', ['/usr/sbin/web', 'stop'], None, None),
                            ('web', 'restart', ['/usr/sbin/web', 'reload'], None, None)]
    assert result['commands'][0]['timeout_seconds'] == 12
    assert result['services'] == [{'kind': 'process', 'name': 'web', 'file': RC, 'line': 1}]
    assert result['complete'] is True


def test_keywords_are_case_insensitive_and_program_equals_optional():
    result = run('check process a with pidfile /p\n  START PROGRAM"/bin/a"\n  stopprogram="/bin/b"\n')
    assert [c['role'] for c in result['commands']] == ['start', 'stop']


def test_argument_splitting_follows_the_lexer():
    result = run("check process a with pidfile /p\n"
                 "  start \"/bin/echo   'x  y'  z#q 'p'q x'y\n   '  sp  ' \"\n")
    assert result['commands'][0]['argv'] == ['/bin/echo', 'x  y', 'z#q', "'p'q", "x'y", 'sp']
    assert result['complete'] is True


def test_check_program_path_and_exec_actions():
    result = run('check program probe with path "/usr/local/bin/probe --fast" as uid nobody timeout 7 seconds\n'
                 '  if status != 0 then exec "/usr/local/bin/page oncall" as uid 0\n'
                 '     else if succeeded then execute "/bin/true"\n')
    assert cmds(result) == [('probe', 'check', ['/usr/local/bin/probe', '--fast'], 'nobody', None),
                            ('probe', 'exec', ['/usr/local/bin/page', 'oncall'], 0, None),
                            ('probe', 'exec', ['/bin/true'], None, None)]


def test_path_outside_check_program_is_not_a_command():
    result = run('check file conf with path "/etc/app.conf"\n  if changed checksum then alert\n')
    assert result['commands'] == [] and result['complete'] is True


def test_comments_hide_commands_outside_argument_lists():
    result = run('# start program = "/bin/hidden"\ncheck process a with pidfile /p  # stop "/bin/no"\n'
                 '  start "/bin/echo #kept"\n')
    assert cmds(result) == [('a', 'start', ['/bin/echo', '#kept'], None, None)]


def test_includes_are_lexed_in_supplied_order_and_loops_skipped():
    inc = {'/etc/monit/conf.d/*': [
        {'path': '/etc/monit/conf.d/a', 'text': 'check process a with pidfile /a\n  start "/bin/a"\n'},
        {'path': RC, 'text': 'check process loop with pidfile /x\n  start "/bin/loop"\n'},
        {'path': '/etc/monit/conf.d/b', 'text': 'check process b with pidfile /b\n  start "/bin/b"\n'},
        {'path': '/etc/monit/conf.d/b~', 'text': 'check process bak with pidfile /b\n  start "/bin/bak"\n'},
        {'path': '/etc/monit/conf.d/sub/', 'text': None},
    ], '/etc/monit/empty/*': []}
    result = run('include /etc/monit/conf.d/*\ninclude "\'/etc/monit/empty/*\'"\n', inc)
    assert [c['service'] for c in result['commands']] == ['a', 'b']
    assert result['commands'][1]['file'] == '/etc/monit/conf.d/b'


@pytest.mark.parametrize('line,pattern', [("include '/etc/monit/x/*'", '/etc/monit/x/*'),
                                          ('include " /etc/monit/x/* "', '/etc/monit/x/*'),
                                          ('include "/etc/monit/x/"*', '"/etc/monit/x/"*')])
def test_include_pattern_quoting(line, pattern):
    inc = {pattern: [{'path': '/etc/monit/x/1', 'text': 'check process a with pidfile /a\n  start "/bin/a"\n'}]}
    result = run(line + '\n', inc)
    assert len(result['commands']) == 1 and result['complete'] is True


@pytest.mark.parametrize('text,code', [
    ('include /etc/monit/conf.d/*\n', 'include_not_observed'),
    ('check process a with pidfile /p\n  start program = /bin/a\n', 'unquoted_arguments'),
    ("check process a with pidfile /p\n  if cpu > 5% then exec '/bin/a'\n", 'unquoted_arguments'),
    ('check program a with path /bin/a\n', 'unquoted_arguments'),
    ('check process a with pidfile /p\n  start "/bin/a" "extra"\n', 'extra_arguments'),
    ('check process a with pidfile /p\n  start "/bin/a" /bin/b\n', 'extra_arguments'),
    ("check process a with pidfile /p\n  start \"/bin/a 'x\\ty'\"\n", 'escape_sequence'),
    ("check process a with pidfile /p\n  start \"/bin/a ' \"\n", 'unbalanced_quotes'),
    ('check process a with pidfile /p\n  start "/bin/a\n', 'unterminated_arguments'),
    ('check process a with pidfile /p\n  start ""\n', 'empty_arguments'),
    ('check process a with pidfile /p\r\n  start "/bin/a"\n', 'carriage_return'),
    ('start "/bin/a"\n', 'command_outside_service'),
    ('check process a with pidfile /p\n  start "/bin/a" as uid\n', 'user_option_malformed'),
    ('check process a with pidfile /p\n  start "' + 'x ' * mp.ARGMAX + '"\n', 'too_many_arguments'),
])
def test_unmodelled_forms_are_blocking(text, code):
    result = run(text)
    assert code in codes(result) and result['complete'] is False


def test_backslash_in_a_plain_word_is_literal():
    result = run('check process a with pidfile /p\n  start "/bin/echo \\t"\n')
    assert result['commands'][0]['argv'] == ['/bin/echo', '\\t'] and result['complete'] is True


def test_over_limit_text_and_malformed_payloads():
    assert 'text_too_large' in codes(run('#' * (mp.MAX_TEXT + 1)))
    for payload in ('nope', {'control': {'text': ''}}, {'control': {'path': RC, 'text': ''}, 'includes': []}):
        result = mp.evaluate(payload)
        assert 'input_malformed' in codes(result) and result['complete'] is False
    assert 'input_malformed' in codes(run(None))


def test_include_depth_is_bounded():
    inc = {f'/i{d}': [{'path': f'/f{d}', 'text': f'include /i{d + 1}\n'}] for d in range(40)}
    result = run('include /i0\n', inc)
    assert 'include_too_deep' in codes(result) and result['complete'] is False


def test_gap_list_is_bounded():
    gaps: list = []
    for i in range(60):
        mp._gap(gaps, 'unquoted_arguments', {'file': RC, 'line': i})
    assert len(gaps) == mp.MAX_GAPS and gaps[-1]['code'] == 'gaps_truncated'


def test_limits_disclosed_and_no_verdict():
    result = run('')
    assert result['complete'] is True and result['commands'] == []
    assert any('getpwnam' in line for line in result['unobserved'])
    assert 'not a safety verdict' in result['note']


TAIL = ('check process x with pidfile /run/x.pid\n'
        '  start program = "/bin/start"\n'
        "  stop program = \"/bin/stop 'a b'\"\n")


@pytest.mark.parametrize('head, trailer', [
    ("set mail-format { message: Monit's alert }\n", "# it's fine\n"),
    ('set mail-format {\n  message: line one\n  "quoted\n  it\'s\n}\n', "# it's\n"),
    ('set mail-format { subject: 5" disk }\n', '# say "hi\n'),
    ("set mail-format { from: O'Brien <ob@example.com> }\n", "# it's\n"),
    ("set mail-format {\n  reply-to: it's@example.com\n}\n", "# it's\n"),
    ("check host h with address 1.2.3.4\n  if failed url http://h/it's then alert\n", "# it's\n"),
    ("check host h with address 1.2.3.4\n  if failed port 80 protocol http http headers [X-A: it's] then alert\n",
     ''),
])
def test_quotes_inside_mail_fields_urls_and_headers_do_not_hide_programs(head, trailer):
    # l.l consumes these contexts whole, so their quote characters never open a string (monit 5.33.0).
    result = run(head + TAIL + trailer)
    assert [c['argv'] for c in result['commands']] == [['/bin/start'], ['/bin/stop', 'a b']]


def test_quoted_http_headers_are_blocking():
    result = run('check host h with address 1.2.3.4\n'
                 '  if failed port 80 protocol http http headers [X-A: "v"] then alert\n' + TAIL)
    assert 'unmodelled_http_headers' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('url', ['http://h/a\tb', 'http://u\nx:p@h/', 'http://h:a\nb@x/'])
def test_urls_not_ended_by_space_or_newline_are_blocking(url):
    result = run(f'check host h with address 1.2.3.4\n  if failed url {url} then alert\n' + TAIL)
    assert 'unmodelled_url' in codes(result) and result['complete'] is False


def test_mail_field_words_without_colon_are_ordinary():
    result = run('check process message with pidfile /p\n  start program = "/bin/m"\n')
    assert [c['argv'] for c in result['commands']] == [['/bin/m']] and result['complete'] is True


@pytest.mark.parametrize('option,key,gap', [
    ('as uid', 'uid', 'user_option_malformed'),
    ('and gid', 'gid', 'user_option_malformed'),
    ('with timeout', 'timeout_seconds', 'timeout_option_malformed'),
])
@pytest.mark.parametrize('value', ['\N{SUPERSCRIPT TWO}', '\N{ARABIC-INDIC DIGIT TWO}', '2147483648'])
def test_unmodelled_numeric_program_option_leaves_a_gap(option, key, gap, value):
    result = run('check process web with pidfile /run/web.pid\n'
                 f'  start "/bin/true" {option} {value}\n'
                 '  stop "/bin/true"\n')
    assert not result['complete']
    assert gap in codes(result)
    assert result['commands'][0].get(key) is None
    assert [command['role'] for command in result['commands']] == ['start', 'stop']


def test_numeric_program_options_accept_ascii_digits_with_leading_zeroes():
    result = run('check process web with pidfile /run/web.pid\n'
                 '  start "/bin/true" as uid 00100 and gid 00033 with timeout 00012 seconds\n')
    assert result['complete']
    command = result['commands'][0]
    assert (command['uid'], command['gid'], command['timeout_seconds']) == (100, 33, 12)


# Native evidence (#1611): Ubuntu 24.04 monit 1:5.33.0-2build2, recorded by the #1612 session from
# ``monit -v -t -c FILE`` and from an ``monit -I`` exec action that logged its argv and ``id -u``.
NATIVE_RC = ('set daemon 30\n'
             'check process sshd with pidfile /run/sshd.pid\n'
             "  start program = \"/usr/sbin/service ssh start 'two words' a'b'c\" as uid nobody"
             ' with timeout 20 seconds\n'
             '  stop program "/bin/true stop"\n'
             '  if failed port 22 then exec "/bin/echo x" as uid nobody repeat every 3 cycles\n'
             "check program chk with path \"/bin/ls -q 'a b'\"\n"
             '  if status != 0 then alert\n')


def test_native_service_commands_and_accounts():
    result = run(NATIVE_RC)
    assert cmds(result) == [
        ('sshd', 'start', ['/usr/sbin/service', 'ssh', 'start', 'two words', "a'b'c"], 'nobody', None),
        ('sshd', 'stop', ['/bin/true', 'stop'], None, None),
        ('sshd', 'exec', ['/bin/echo', 'x'], 'nobody', None),
        ('chk', 'check', ['/bin/ls', '-q', 'a b'], None, None),
    ]
    assert result['commands'][0]['timeout_seconds'] == 20
    assert result['complete'] is True


def test_native_exec_argv_trace():
    result = run('check program t with path "/bin/false" # comment "x"\n'
                 "  if status != 0 then exec \"/usr/local/bin/argv.sh a  'b c' d'e'f #h 'x\"y'\" as uid nobody\n")
    assert cmds(result) == [('t', 'check', ['/bin/false'], None, None),
                            ('t', 'exec', ['/usr/local/bin/argv.sh', 'a', 'b c', "d'e'f", '#h', 'x"y'],
                             'nobody', None)]
    assert result['complete'] is True


def test_native_escape_rewrite_stays_a_blocking_gap():
    # Natively, Util_handleEscapes turned '  g\tq  ' into the argument 'g<TAB>q'. That rewrite is not modelled,
    # so the contract must not report the argument as complete.
    result = run("check program t with path \"/bin/false\"\n"
                 "  if status != 0 then exec \"/bin/argv.sh '  g\\tq  '\"\n")
    assert 'escape_sequence' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('text', [
    'check process a with pidfile /p\n  start "/bin/a\0b"\n',
    'check process a with pidfile /p\n  start "/bin/a"\0 stop "/bin/b"\n',
])
def test_nul_byte_blocks_and_reports_no_truncated_program(text):
    result = run(text)
    assert 'nul_byte' in codes(result) and result['complete'] is False
    assert result['commands'] == []


def test_nul_byte_in_an_include_blocks_completion():
    inc = {'/etc/monit/conf.d/*': [{'path': '/etc/monit/conf.d/a',
                                    'text': 'check process a with pidfile /a\n  start "/bin/a\0x"\n'}]}
    result = run('include /etc/monit/conf.d/*\n', inc)
    assert {g['code']: g.get('file') for g in result['gaps']}.get('nul_byte') == '/etc/monit/conf.d/a'
    assert result['complete'] is False and result['commands'] == []
