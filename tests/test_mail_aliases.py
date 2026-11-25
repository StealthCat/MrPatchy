"""Tests for the pure Postfix aliases delivery contract (#1215).

Expected outcomes follow readlline.c, postalias.c, tok822_parse.c,
local/alias.c and local/token.c in Postfix 3.8.6.
"""
import pytest

from app import mail_aliases as ma

ROOT = {'trusted': True, 'user': 'root'}
DEBIAN_DEFAULT = """# See man 5 aliases for format
postmaster:    root
"""


def run(text, **extra):
    return ma.resolve({'path': '/etc/aliases', 'observed': True, 'text': text, 'owner': ROOT, **extra})


def by_name(result):
    return {e['name']: e for e in result['entries'] if 'name' in e}


def test_debian_default_has_no_executions_and_is_complete():
    result = run(DEBIAN_DEFAULT)
    assert result['complete'] is True
    assert result['executions'] == []
    entry = by_name(result)['postmaster']
    assert entry['targets'] == [{'status': 'parsed', 'kind': 'address', 'value': 'root'}]
    assert result['origin'] == 'not_assessed' and result['verdict'] is None


def test_quoted_command_runs_as_default_privs_for_root_owned_database():
    result = run('backup: "|/usr/local/bin/ingest --mode=mail, fast", admin\n')
    assert result['executions'] == [{
        'name': 'backup', 'kind': 'command', 'value': '/usr/local/bin/ingest --mode=mail, fast',
        'run_as': 'nobody', 'delivery_rights': 'default_privs', 'origin': 'not_assessed'}]
    assert [t['kind'] for t in by_name(result)['backup']['targets']] == ['command', 'address']


def test_custom_default_privs_and_non_root_owner():
    assert run('a: "|/x"\n', default_privs='mailnull')['executions'][0]['run_as'] == 'mailnull'
    result = run('a: "|/x"\n', owner={'trusted': False, 'user': 'list'})
    assert result['executions'][0]['run_as'] == 'list'
    assert result['executions'][0]['delivery_rights'] == 'database_owner'


def test_unknown_owner_defers_delivery_and_records_no_execution():
    result = run('a: "|/x"\n', owner=None)
    target = by_name(result)['a']['targets'][0]
    assert target['run_as'] is None and target['delivery_rights'] == 'deferred_owner_unknown'
    assert result['executions'] == []


def test_restricted_commands_and_files_are_not_executions():
    result = run('a: "|/x", /var/log/a\n', allow_mail_to_commands='forward', allow_mail_to_files='forward,include')
    targets = by_name(result)['a']['targets']
    assert [t['delivery_rights'] for t in targets] == ['restricted', 'restricted']
    assert result['executions'] == []
    assert run('a: "|/x"\n', allow_mail_to_commands='ALIAS')['executions']


def test_unquoted_single_word_command_and_files():
    result = run('a: |/opt/hook\nb: /var/spool/b, ~/mbox\n')
    assert result['executions'][0]['value'] == '/opt/hook'
    kinds = [t['kind'] for t in by_name(result)['b']['targets']]
    assert kinds == ['file', 'home_file']


def test_home_files_bounce_without_a_home_directory():
    # Root-owned database: default_privs carries no home, so "~/..." bounces.
    result = run('b: ~/mbox, ~bob/mbox\n')
    targets = by_name(result)['b']['targets']
    assert [t['delivery_rights'] for t in targets] == ['bounced', 'bounced']
    assert [t['bounce_reason'] for t in targets] == ['no_home_with_default_privs', 'home_user_syntax']
    assert result['executions'] == []
    # A non-root owner supplies a home: "~/..." is delivered, "~user" still bounces.
    owned = run('b: ~/mbox, ~bob/mbox\n', owner={'trusted': False, 'user': 'list'})
    assert [(e['kind'], e['value'], e['run_as']) for e in owned['executions']] == [('home_file', '~/mbox', 'list')]
    assert by_name(owned)['b']['targets'][1]['delivery_rights'] == 'bounced'


def test_unquoted_command_with_arguments_is_unresolved_not_guessed():
    result = run('a: |/opt/hook arg\n')
    assert by_name(result)['a']['status'] == 'unresolved'
    assert result['complete'] is False
    assert result['executions'] == []


def test_include_is_a_gap_in_any_case():
    result = run('list: :INCLUDE:/etc/mail/list\n')
    target = by_name(result)['list']['targets'][0]
    assert target['kind'] == 'include' and target['value'] == '/etc/mail/list'
    assert target['followed'] is False
    assert result['complete'] is False
    assert result['gaps'][0]['reason'] == 'include_not_followed'


def test_continuation_comments_and_blank_lines():
    text = 'a: b,\n# comment inside\n\n   "|/run me"\n  # indented comment\nc: d\n'
    result = run(text)
    assert [t['value'] for t in by_name(result)['a']['targets']] == ['b', '/run me']
    assert 'c' in by_name(result)


def test_leading_continuation_without_text_is_dropped():
    result = run('   "|/orphan"\nx: y\n')
    assert list(by_name(result)) == ['x']
    assert result['executions'] == []


def test_keys_fold_to_lowercase_and_first_duplicate_wins():
    result = run('Root: "|/first"\nroot: "|/second"\n')
    statuses = [(e['name'], e['status']) for e in result['entries']]
    assert statuses == [('root', 'active'), ('root', 'duplicate_ignored')]
    assert [e['value'] for e in result['executions']] == ['/first']


@pytest.mark.parametrize('line,reason', [
    ('no colon here', 'need_name_value_pair'),
    (': value', 'need_name_value_pair'),
    ('name:', 'need_name_value_pair'),
    ('a, b: c', 'need_name_value_pair'),
    ('a@example.com: c', 'name_must_be_local'),
    ('a%b: c', 'name_must_be_local'),
])
def test_invalid_lines_are_skipped(line, reason):
    entry = run(line + '\n')['entries'][0]
    assert entry == {'logical_line': 1, 'origin': 'not_assessed', 'status': 'skipped', 'reason': reason}


def test_quoted_key_and_escapes():
    result = run('"odd name": "|/bin/a\\"b"\n')
    assert result['executions'][0]['name'] == 'odd name'
    assert result['executions'][0]['value'] == '/bin/a"b'


def test_comment_token_in_target_is_unresolved():
    result = run('a: b (note)\n')
    assert by_name(result)['a']['status'] == 'unresolved'
    assert result['complete'] is False


def test_tokenizer_matches_tok822_scan():
    assert ma.tokenize('a.b@[1.2] "q\\"x" (c (n)) |') == [
        ('atom', 'a'), ('op', '.'), ('atom', 'b'), ('op', '@'), ('domlit', '1.2'),
        ('qstring', 'q"x'), ('comment', '(c (n))'), ('op', '|')]


def test_unobserved_and_over_limit_fail_closed():
    for source in ({'observed': False, 'text': None},
                   {'observed': True, 'text': 'a: b\n' * (ma.MAX_TEXT // 4)}):
        result = ma.resolve({'owner': ROOT, **source})
        assert result['complete'] is False and result['executions'] == [] and result['entries'] == []
