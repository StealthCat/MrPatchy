import json

import pytest

from app import dotforward_commands as df

POSTCONF = {
    'forward_path': '$home/.forward${recipient_delimiter}${extension}, $home/.forward',
    'allow_mail_to_commands': 'alias, forward',
    'recipient_delimiter': '',
    'default_privs': 'nobody',
    'local_command_shell': '',
    'local_transport': 'local:$myhostname',
    'line_length_limit': '2048',
}
USERS = [
    {'name': 'root', 'uid': 0, 'gid': 0, 'home': '/root'},
    {'name': 'alice', 'uid': 1000, 'gid': 1000, 'home': '/home/alice'},
    {'name': 'nobody', 'uid': 65534, 'gid': 65534, 'home': '/nonexistent'},
]
FILE = {'type': 'file', 'uid': 1000, 'mode': 0o644}


def _forward(name='.forward', content='', **kw):
    return dict(FILE, name=name, content=content, **kw)


def _listed(*entries):
    return {'state': 'listed', 'entries': list(entries)}


def _run(alice=None, root=None, postconf=None, users=None, **conf):
    homes = {'alice': alice or {'state': 'absent'}, 'root': root or {'state': 'absent'},
             'nobody': {'state': 'absent'}}
    return df.assess(True, dict(postconf or POSTCONF, **conf), USERS if users is None else users, homes)


def _codes(result):
    return {g['code'] for g in result['gaps']}


def test_quoted_and_bare_commands_run_as_the_recipient():
    result = _run(_listed(_forward(content='# comment\n"|/usr/bin/procmail -f-", alice@example.org\n'
                                           '|/home/alice/bin/hook.sh\n/home/alice/mail.log\n')))
    assert result['complete'] and result['commands_allowed'] is True
    commands = [(c['command'], c['line'], c['run_as']['uid'], c['recipient']) for c in result['commands']]
    assert commands == [('/usr/bin/procmail -f-', 2, 1000, 'alice'), ('/home/alice/bin/hook.sh', 3, 1000, 'alice')]
    selection = result['users'][0]['selections'][0]
    assert selection['outcome'] == 'read' and selection['addresses'] == 1
    assert selection['files'] == [{'line': 4, 'path': '/home/alice/mail.log'}]


def test_root_forward_commands_run_as_default_privs():
    root = _listed(_forward(content='"|/usr/local/bin/notify"\n', uid=0))
    result = _run(root=root)
    [command] = result['commands']
    assert command['run_as'] == {'user': 'nobody', 'uid': 65534, 'gid': 65534, 'default_privs': True}
    assert result['complete']


def test_unresolved_default_privs_is_blocking():
    result = _run(root=_listed(_forward(content='"|/x"\n', uid=0)), default_privs='mailnull')
    assert 'default_privs_unresolved' in result['blocking']
    assert result['commands'][0]['run_as'] is None


@pytest.mark.parametrize('entry, outcome', [
    (dict(FILE, type='symlink'), 'not_regular'),
    (dict(FILE, type='directory'), 'not_regular'),
    (dict(FILE, uid=1001), 'bad_owner'),
    (dict(FILE, mode=0o646), 'world_writable'),
])
def test_refused_files_run_nothing(entry, outcome):
    result = _run(_listed(dict(entry, name='.forward', content='"|/bin/evil"\n')))
    selection = result['users'][0]['selections'][0]
    assert selection['outcome'] == outcome and result['commands'] == [] and result['complete']


def test_root_owned_file_is_accepted_for_a_user():
    result = _run(_listed(_forward(content='"|/bin/hook"\n', uid=0)))
    assert result['commands'][0]['run_as']['uid'] == 1000


def test_commands_refused_without_forward_class():
    result = _run(_listed(_forward(content='"|/bin/hook"\n')), allow_mail_to_commands='alias')
    assert result['commands_allowed'] is False and result['commands'][0]['allowed'] is False


def test_unknown_command_class_is_blocking():
    result = _run(_listed(_forward(content='"|/bin/hook"\n')), allow_mail_to_commands='alias, Forward')
    assert 'unknown_command_class' in result['blocking'] and result['commands'] == []


def test_extension_file_is_chosen_first_and_blocks_fallback():
    alice = _listed(_forward(content='"|/bin/plain"\n'),
                    _forward('.forward+lists', content='"|/bin/lists"\n', mode=0o666))
    result = _run(alice, recipient_delimiter='+')
    selections = {s['recipient']: s for s in result['users'][0]['selections']}
    assert selections['alice']['outcome'] == 'read'
    assert selections['alice+lists']['outcome'] == 'world_writable'
    assert [c['recipient'] for c in result['commands']] == ['alice']


def test_extension_file_ignored_without_delimiter():
    alice = _listed(_forward('.forward+lists', content='"|/bin/lists"\n'))
    result = _run(alice)
    assert result['users'] == [] and result['commands'] == []


def test_plain_forward_path_skips_extension_files():
    alice = _listed(_forward('.forward-x', content='"|/bin/x"\n'))
    result = _run(alice, recipient_delimiter='-', forward_path='$home/.forward')
    assert result['commands'] == [] and result['complete']


@pytest.mark.parametrize('line', [
    'alice (comment)', '<alice@example.org>', 'group: a, b;', '"|/bin/a \\" b"', '"|/bin/unterminated',
    '|/usr/bin/procmail -f-', '"|/bin/a" extra',
])
def test_unsupported_syntax_is_a_blocking_gap(line):
    result = _run(_listed(_forward(content=line + '\n')))
    assert 'line_unparsed' in result['blocking'] and result['commands'] == []


def test_include_needs_resolution_only_when_include_commands_allowed():
    content = ':include:/etc/mail/list\n'
    default = _run(_listed(_forward(content=content)))
    assert default['complete']
    assert default['users'][0]['selections'][0]['includes'] == [
        {'line': 1, 'path': '/etc/mail/list', 'commands_allowed': False}]
    allowed = _run(_listed(_forward(content=content)), allow_mail_to_commands='alias forward include')
    assert 'include_not_resolved' in allowed['blocking']


def test_indented_hash_is_an_address_not_a_comment():
    result = _run(_listed(_forward(content='  #"|/bin/x"\n')))
    assert 'line_unparsed' in result['blocking']
    plain = _run(_listed(_forward(content='  #note\n')))
    assert plain['users'][0]['selections'][0]['addresses'] == 1


def test_long_line_is_blocking():
    result = _run(_listed(_forward(content='"|/bin/' + 'x' * 3000 + '"\n')))
    assert 'line_too_long' in result['blocking']


@pytest.mark.parametrize('key, value, code', [
    ('forward_path', '$home/.forward, $home/.mail-forward', 'nondefault_forward_path'),
    ('line_length_limit', '4096', 'nondefault_line_limit'),
    ('local_transport', 'lmtp:unix:private/dovecot-lmtp', 'nondefault_local_transport'),
])
def test_nondefault_parameters_are_blocking(key, value, code):
    assert code in _run(_listed(_forward(content='"|/x"\n')), **{key: value})['blocking']


def test_command_shell_is_reported():
    result = _run(_listed(_forward(content='"|/x"\n')), local_command_shell='/bin/bash -c')
    assert result['command_shell'] == '/bin/bash -c' and result['commands'][0]['shell'] == '/bin/bash -c'


def test_missing_inputs_are_blocking():
    assert df.assess(None)['blocking'] == ['postfix_not_observed']
    absent = df.assess(False)
    assert absent['postfix'] == 'absent' and absent['complete']
    assert 'config_not_observed' in df.assess(True, {'forward_path': ''})['blocking']
    assert 'users_not_observed' in df.assess(True, POSTCONF)['blocking']
    homes = df.assess(True, POSTCONF, USERS, {'root': {'state': 'absent'}})
    assert 'home_not_observed' in homes['blocking']
    unreadable = _run({'state': 'unreadable'})
    assert 'home_unreadable' in unreadable['blocking']
    no_meta = _run(_listed({'name': '.forward', 'content': '"|/x"'}))
    assert 'metadata_missing' in no_meta['blocking']
    no_text = _run(_listed(dict(FILE, name='.forward')))
    assert 'content_not_observed' in no_text['blocking']


def test_malformed_inputs_are_rejected():
    assert 'input_malformed' in df.assess(True, POSTCONF, [{'name': 'x'}], {})['blocking']
    assert 'input_malformed' in _run(_listed({'name': 'notes', **FILE}))['blocking']
    assert 'too_many_entries' in _run(_listed(*[_forward(f'.forward+{i}') for i in range(65)]))['blocking']


def test_first_passwd_entry_wins_for_duplicate_names():
    users = USERS + [{'name': 'alice', 'uid': 0, 'gid': 0, 'home': '/home/alice'}]
    result = _run(_listed(_forward(content='"|/x"\n')), users=users)
    assert result['commands'][0]['run_as']['uid'] == 1000


def test_gaps_are_bounded():
    users = [{'name': f'u{i}', 'uid': 2000 + i, 'gid': 2000 + i, 'home': f'/home/u{i}'} for i in range(100)]
    users.append({'name': 'nobody', 'uid': 65534, 'gid': 65534, 'home': '/nonexistent'})
    result = df.assess(True, POSTCONF, users, {'nobody': {'state': 'absent'}})
    assert len(result['gaps']) == df.MAX_GAPS and result['gaps'][-1]['code'] == 'gaps_truncated'


def test_never_authorizes_actions():
    result = _run(_listed(_forward(content='"|/x"\n')))
    assert 'authorized' not in str(result).lower() and result['not_a_verdict']


def test_lone_surrogate_text_is_a_blocking_gap_and_other_users_stay_usable():
    bad = json.loads(r'"\ud800"')
    result = _run(_listed(_forward(content=bad)), root=_listed(_forward(content='"|/x"\n', uid=0)))
    assert 'content_malformed' in result['blocking'] and not result['complete']
    alice = next(u for u in result['users'] if u['user'] == 'alice')
    assert alice['selections'][0]['outcome'] == 'unresolved'
    assert [c['user'] for c in result['commands']] == ['root']


def test_surrogateescape_bytes_still_parse():
    text = b'"|/bin/caf\xe9"\n'.decode('utf-8', 'surrogateescape')
    result = _run(_listed(_forward(content=text)))
    assert result['complete'] and result['commands'][0]['command'] == '/bin/caf\udce9'


def test_case_folding_makes_upper_case_users_and_extensions_unreachable():
    users = USERS + [{'name': 'Alice', 'uid': 1001, 'gid': 1001, 'home': '/home/Alice'},
                     {'name': 'bob', 'uid': 1002, 'gid': 1002, 'home': '/home/bob'}]
    homes = {u['name']: {'state': 'absent'} for u in USERS}
    homes['Alice'] = _listed(_forward(content='"|/bin/a"\n', uid=1001))
    homes['bob'] = _listed(_forward('.forward+Work', content='"|/bin/w"\n', uid=1002),
                           _forward('.forward+home', content='"|/bin/h"\n', uid=1002))
    result = df.assess(True, dict(POSTCONF, recipient_delimiter='+'), users, homes)
    assert result['complete']
    assert [(c['user'], c['recipient'], c['command']) for c in result['commands']] == [('bob', 'bob+home', '/bin/h')]
    assert [u['user'] for u in result['unreachable_users']] == ['Alice']


def test_username_with_delimiter_is_unreachable():
    users = USERS + [{'name': 'mail-admin', 'uid': 1003, 'gid': 1003, 'home': '/home/ma'}]
    homes = {u['name']: {'state': 'absent'} for u in USERS}
    homes['mail-admin'] = _listed(_forward(content='"|/bin/x"\n', uid=1003))
    result = df.assess(True, dict(POSTCONF, recipient_delimiter='-'), users, homes)
    assert result['commands'] == [] and result['unreachable_users'][0]['user'] == 'mail-admin'
    plain = df.assess(True, POSTCONF, users, homes)
    assert [c['user'] for c in plain['commands']] == ['mail-admin']


def test_non_ascii_names_and_upper_case_delimiters_are_blocking():
    users = USERS + [{'name': 'jos\u00e9', 'uid': 1004, 'gid': 1004, 'home': '/home/jose'}]
    homes = {u['name']: {'state': 'absent'} for u in users}
    assert 'casefold_not_modeled' in df.assess(True, POSTCONF, users, homes)['blocking']
    ext = _run(_listed(_forward('.forward+caf\u00e9', content='"|/x"\n')), recipient_delimiter='+')
    assert 'casefold_not_modeled' in ext['blocking']
    assert 'casefold_not_modeled' in _run(recipient_delimiter='X')['blocking']
