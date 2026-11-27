"""Pure keyutils request-key callout contract (#1632).

Expected values come from Ubuntu 24.04 ``keyutils 1.6.3-3build1``: a real
kernel upcall with a recorder program, and ``request-key -d -l -v`` runs.
"""
from app import request_key_callouts as rk

CONF = rk.CONF_PATH
VALUES = {'key_id': '7', 'requester_uid': '1000', 'requester_gid': '1000', 'thread_keyring': '0',
          'process_keyring': '0', 'session_keyring': '0'}


def run(text, entries=None, exists=True):
    dropins = {'exists': entries is not None, 'entries': entries or []}
    return rk.evaluate(conf={'exists': exists, 'text': text}, dropins=dropins)


def pick(result, key_type='user', description='x', callout='s'):
    return rk.select_rule(result, key_type, description, callout, values=VALUES)


def test_unprivileged_request_runs_callout_as_root_with_requester_description_and_callout():
    # Native: uid 65534 ran ``keyctl request2 user 'mpk:x;y' 'cal lout'``; the
    # recorder logged uid=0 gid=0 and argv "<key> <session> mpk:x;y cal lout 65534".
    r = run('', [{'name': 'mpk.conf', 'kind': 'regular',
                  'text': 'create user mpk:* * /usr/local/bin/rk-rec %k %S %d %c %u\n'}])
    assert (r['status'], r['complete'], r['origin'], r['authorizes_response']) == ('runs', True, 'not_assessed', False)
    rule = r['rules'][0]
    assert (rule['source'], rule['runs_as'], rule['code_runs'], rule['argv0']) == (
        '/etc/request-key.d/mpk.conf:1', 'root', 'on_matching_request', 'rk-rec')
    assert rule['requester_controlled'] == ['callout_info', 'description']
    assert r['requester_controlled'] == ['callout_info', 'description']
    chosen = rk.select_rule(r, 'user', 'mpk:x;y', 'cal lout', values={**VALUES, 'requester_uid': '65534'})
    assert chosen['argv'] == ['rk-rec', '7', '0', 'mpk:x;y', 'cal lout', '65534'] and chosen['runs_as'] == 'root'


def test_pipe_program_receives_callout_info_on_stdin():
    # Native: ``|/usr/local/bin/rk-pipe %d`` ran as uid 0 with stdin=secretcallout.
    r = run('negate * * * /bin/neg\ncreate * * * |/bin/cat %% %P\n')
    neg, cat = r['rules']
    assert (neg['kernel_upcall'], neg['code_runs']) == (False, 'never')
    assert (cat['pipe'], cat['requester_controlled']) == (True, ['stdin_callout_info'])
    assert pick(r) == {'outcome': 'runs', 'source': f'{CONF}:2', 'program': '/bin/cat', 'pipe': True,
                       'argv': ['cat', '%', '0'], 'runs_as': 'root', 'wildness': [0, 4, 1, 1]}


def test_symlinked_dot_and_non_conf_dropins_are_skipped_and_conf_is_read_last():
    # Native on ext4: a symlinked ``link.conf`` was not read (no callout ran).
    r = run('create * * * /bin/main\n', [
        {'name': 'link.conf', 'kind': 'symlink'},
        {'name': '.hidden.conf', 'kind': 'regular', 'text': 'create * * * /bin/h\n'},
        {'name': 'notes.txt', 'kind': 'regular', 'text': 'create * * * /bin/t\n'},
        {'name': 'a.conf', 'kind': 'regular', 'text': 'create * * * /bin/a\n'},
    ])
    assert [f['path'] for f in r['files']] == ['/etc/request-key.d/a.conf', CONF]
    assert [s['reason'] for s in r['skipped']] == ['symlink_not_read', 'name_not_read', 'name_not_read']
    # Equal wildness: the first line read (the drop-in) wins.
    assert pick(r)['source'] == '/etc/request-key.d/a.conf:1'


def test_best_match_prefers_smaller_wildcard_skips_left_to_right():
    # Native: line 3 won with (0,0,3,3) over (0,0,9,5) and (0,0,3,5).
    r = run('create user * * /bin/any\ncreate user debug:* * /bin/dbg %d\ncreate user debug:* sp* /bin/later\n')
    assert pick(r, description='debug:abc', callout='spoon')['source'] == f'{CONF}:3'
    assert pick(r, description='debug:abc', callout='x')['argv'] == ['dbg', 'debug:abc']
    assert pick(r, description='other', callout='spoon')['argv'] == ['any']


def test_end_match_compares_against_the_pattern_start():
    # Native: ``c*e`` matched type ``cxc`` and not ``cxe``.
    assert rk.match('c*e', 'cxc') == 1 and rk.match('c*e', 'cxe') is None
    r = run('create c*e * * /bin/q\n')
    assert pick(r, key_type='cxc')['outcome'] == 'runs'
    assert pick(r, key_type='cxe')['outcome'] == 'no_match'
    assert rk.match('*', '') == 0 and rk.match('debug:*', 'debug:') == 0 and rk.match('*er', 'user') == 2


def test_last_line_without_newline_loses_its_last_byte_and_leading_blank_lines_are_comments():
    # Native: ``create user * * /bin/last`` with no newline ran ``/bin/las``;
    # `` create`` alone was ignored rather than a syntax error.
    r = run('create user * * /bin/last')
    assert r['rules'][0]['program'] == '/bin/las'
    assert [g['code'] for g in r['gaps']] == ['last_byte_dropped'] and r['complete']
    lead = run(' create\n\tcreate * * * /bin/tab\n#create\n')
    assert (lead['rules'], lead['aborts'], lead['status']) == ([], [], 'no_runnable_rules')
    assert pick(lead)['outcome'] == 'no_match'


def test_short_lines_abort_lookups_matching_the_fields_read_before_the_end():
    # Native: ``create user`` aborted a ``logon`` lookup too; ``create user `` (trailing
    # blank) aborted only ``user`` lookups.
    bare = run('create user\ncreate * * * /bin/ok\n')
    assert bare['aborts'][0]['scope'] == ['create'] and bare['universal_aborts'] == [f'{CONF}:1']
    assert bare['status'] == 'all_lookups_abort' and bare['rules'][0]['code_runs'] == 'lookup_aborts'
    assert pick(bare, key_type='logon')['outcome'] == 'aborts'
    trailing = run('create user \ncreate * * * /bin/ok\n')
    assert trailing['aborts'][0]['scope'] == ['create', 'user'] and trailing['status'] == 'runs'
    assert pick(trailing, key_type='logon')['outcome'] == 'runs'
    assert pick(trailing, key_type='user') == {'outcome': 'aborts', 'source': f'{CONF}:1', 'reason': 'syntax_error'}
    one = run('negate\n')
    assert one['aborts'][0]['universal'] and pick(one)['outcome'] == 'aborts'
    assert run('negate user\n')['aborts'][0]['universal'] is False


def test_overlong_line_aborts_every_lookup_even_after_a_match():
    long_line = 'create * * * /bin/long ' + 'y' * (rk.LINE_ABORT_BYTES - 24)
    assert len(long_line) + 1 == rk.LINE_ABORT_BYTES
    r = run('', [{'name': 'a.conf', 'kind': 'regular', 'text': 'create * * * /bin/a\n'},
                 {'name': 'b.conf', 'kind': 'regular', 'text': long_line + '\n'}])
    assert r['status'] == 'all_lookups_abort' and pick(r)['reason'] == 'line_too_long'
    ok = run(long_line[:-1] + '\n')
    assert ok['status'] == 'runs' and not ok['aborts']


def test_selection_time_failures_are_reported_per_rule():
    # Native: ``echo hi`` died on SIGSEGV; ``%x`` and ``%`` are fatal; ``%xy`` is literal.
    r = run('create a * * echo hi\ncreate b * * /bin/e %x\ncreate c * * /bin/e %\n'
            'create d * * /bin/e %{user}\ncreate e * * /bin/e %xy %{user:k}\n')
    assert [x['fails_when_selected'] for x in r['rules']] == [
        'program_without_slash', 'unsupported_macro', 'missing_macro_name', 'malformed_keysub', None]
    assert [x['code_runs'] for x in r['rules']][:4] == ['fails_when_selected'] * 4
    assert pick(r, key_type='a')['outcome'] == 'fails'
    keysub = r['rules'][4]
    assert keysub['args'][0]['value'] == '%xy' and keysub['args'][1]['keysub'] == {'type': 'user', 'description': 'k'}
    assert keysub['requester_controlled'] == ['keysub_payload']
    rel = run('create * * * bin/rel\n')
    assert [g['code'] for g in rel['gaps']] == ['program_not_absolute'] and rel['complete']


def test_fail_closed_capture_gaps():
    unchecked = rk.evaluate(conf={'exists': None}, dropins=None)
    assert unchecked['status'] == 'unresolved' and not unchecked['complete']
    assert {g['code'] for g in unchecked['gaps']} == {'conf_not_checked', 'dropins_not_checked'}
    assert rk.select_rule(unchecked, 'user', 'x', 's') == {'outcome': 'unresolved'}
    for text, code in ((b'create * * * /bin/a\x00\n', 'nul_byte'), (b'\xff\n', 'invalid_utf8'),
                       ('#' * (rk.MAX_TEXT_BYTES + 1), 'text_over_limit'), (None, 'text_not_captured')):
        r = run(text)
        assert r['gaps'][0]['code'] == code and not r['complete'] and r['files'][0]['state'] == 'unreadable'
    odd = run('', [{'name': 'x.conf', 'kind': 'fifo'}])
    assert odd['gaps'][0]['code'] == 'entry_kind_unknown' and not odd['complete']
    absent = rk.evaluate(conf={'exists': False}, dropins={'exists': False})
    assert (absent['status'], absent['complete'], absent['rules']) == ('absent', True, [])
