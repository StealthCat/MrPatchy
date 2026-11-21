"""keepalived script-line contract, first increment (#1307), against traced keepalived 2.2.8 semantics."""
from app import keepalived_scripts as ks


def texts(conf, **kw):
    r = ks.logical_lines(conf, **kw)
    return [line['text'].decode() for line in r['lines']], r


def test_comments_quotes_and_escaped_comment_characters():
    assert ks.decomment(b'  notify /bin/x # c') == (b'notify /bin/x', False)
    assert ks.decomment(b'notify "/bin/x # kept" ! c') == (b'notify "/bin/x # kept"', False)
    assert ks.decomment(b'notify /bin/x\\#y') == (b'notify /bin/x#y', False)
    assert ks.decomment(b'notify "/bin/x\\#y"') == (b'notify "/bin/x\\#y"', False)
    assert ks.decomment(b'notify "/bin/x')[1] is True


def test_braces_are_split_onto_their_own_lines():
    lines, r = texts('vrrp_instance VI_1 {\n  notify_master /bin/m } \n{ state BACKUP }\n')
    assert lines == ['vrrp_instance VI_1', '{', 'notify_master /bin/m', '}', '{', 'state BACKUP', '}']
    assert r['complete']
    lines, _ = texts('notify "/bin/sh -c \'echo }\'"\n')
    assert lines == ['notify "/bin/sh -c \'echo }\'"']


def test_unmodelled_preprocessing_fails_closed():
    for conf, code in (('include /etc/keepalived/conf.d/*.conf\n', 'include'),
                       ('$IF=eth0\n', 'definition'),
                       ('notify /bin/x $_RANDOM\n', 'parameter_expansion'),
                       ('notify /bin/x ${_INSTANCE}\n', 'parameter_expansion'),
                       ('~SEQ(i,1,3) notify /bin/x\n', 'sequence'),
                       ('@node1 notify /bin/x\n', 'conditional_unresolved'),
                       ('notify /bin/x \\\n', 'continuation'),
                       ('notify /bin/' + 'x' * 1100 + '\n', 'line_over_buffer')):
        r = ks.logical_lines(conf)
        assert not r['complete'] and r['gaps'][0]['code'] == code, conf
    for raw, code in ((b'a\0b', 'binary'), (b'\xff', 'invalid_utf8'), (b'x' * (ks.MAX_TEXT + 1), 'over_limit')):
        assert ks.logical_lines(raw)['gaps'][0]['code'] == code


def test_dollar_that_no_standard_definition_matches_is_left_alone():
    lines, r = texts('notify "/bin/sh -c \'echo $1 $HOME\'"\n')
    assert r['complete'] and lines == ['notify "/bin/sh -c \'echo $1 $HOME\'"']


def test_conditional_lines_follow_the_observed_config_id():
    conf = '@node1 notify /bin/a\n@^node1 notify /bin/b\n@node2 notify /bin/c\n@node1\n'
    lines, r = texts(conf, config_id='node1')
    assert lines == ['notify /bin/a'] and r['complete']
    lines, _ = texts(conf, config_id='node2')
    assert lines == ['notify /bin/b', 'notify /bin/c']


def test_line_at_buffer_limit_is_whole():
    line = 'notify /bin/' + 'x' * (ks.MAXBUF - 1 - len('notify /bin/'))
    assert len(line) == ks.MAXBUF - 1
    assert ks.logical_lines(line + '\n')['complete']
    assert not ks.logical_lines(line + 'x\n')['complete']


def test_quoted_escaped_split_matches_keepalived_escapes():
    q = ks.split_quoted_escaped
    assert q(b"a 'b c' \"d e\" f\\ g") == [b'a', b'b c', b'd e', b'f g']
    assert q(b'\\x41\\101\\cA\\t\\q') == [b'AA\x01\tq']
    assert q(b'\\x4142') == [b'B']  # hex digits accumulate into one byte
    assert q(b'a\\0b c') == [b'a', b'c']  # STRNDUP stops at the escaped NUL
    assert q(b"'it\\'s'") == [b"it's"]
    assert q(b'"unterminated') is None and q(b'end\\') is None and q(b'   ') is None


def test_script_line_reparses_the_script_word_and_reads_user_group():
    r = ks.script_line(b'notify_master "/usr/local/bin/m \\"a b\\" c" svc grp extra')
    assert r == {'status': 'ok', 'reason': None, 'argv': ['/usr/local/bin/m', 'a b', 'c'],
                 'user': 'svc', 'group': 'grp'}
    r = ks.script_line(b"startup_script '/bin/echo hi'")
    assert r['argv'] == ['/bin/echo', 'hi'] and r['user'] is None and r['group'] is None
    assert ks.script_line(b'notify')['status'] == 'ignored'
    assert ks.script_line(b'notify "/bin/x \'oops"')['reason'] == 'no_script'


def test_double_quoted_keyword_tokenizing():
    assert ks.split_words(b'vrrp_script "chk web" {') == [b'vrrp_script', b'chk web', b'{']
    assert ks.split_words(b'a "b') == [b'a']
    assert ks.split_words(b'a"b"') == [b'a', b'b']
