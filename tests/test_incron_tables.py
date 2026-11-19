from app import incron_tables as it

ALLOW_MISSING = {'state': 'missing'}
ACCOUNTS = {'root': {'uid': 0}, 'alice': {'uid': 1000}, 'bob': {'uid': 1001}}


def _file(name):
    return {'name': name, 'd_type': 'file'}


def test_parse_table_fields_mask_words_and_flags():
    entries = it.parse_table('/etc IN_MODIFY,IN_CLOSE_WRITE,recursive=false,dotdirs=true /usr/bin/x $@/$# $%\n')
    assert len(entries) == 1
    entry = entries[0]
    assert entry['path'] == '/etc'
    assert entry['events'] == ['IN_MODIFY', 'IN_CLOSE_WRITE']
    assert entry['recursive'] is False and entry['dotdirs'] is True
    assert entry['command'] == '/usr/bin/x $@/$# $%'
    assert entry['status'] == 'loads'


def test_table_has_no_comment_syntax_and_short_lines_are_skipped():
    entries = it.parse_table('# just a note\n#single\n/only two\n/tmp IN_CREATE\n')
    # "# just a note" is three fields: path "#", unknown mask word "just", command "a note".
    assert [entry['path'] for entry in entries] == ['#']
    assert entries[0]['status'] == 'rejected_mask'
    assert entries[0]['notes'][0].startswith('Unknown mask words')


def test_escaped_space_does_not_protect_the_path_with_two_delimiters():
    entries = it.parse_table('/srv/my\\ dir IN_CREATE echo hi\n')
    # The tokenizer toggles its escape state twice per character, so the space still splits.
    assert entries[0]['path'] == '/srv/my'
    assert entries[0]['mask_field'] == 'dir'
    assert entries[0]['status'] == 'rejected_mask'


def test_backslashes_are_stripped_from_the_path_but_not_the_command():
    entries = it.parse_table('/a\\\\b\\c IN_DELETE rm \\x\n')
    assert entries[0]['path'] == '/a\\bc'
    assert entries[0]['command'] == 'rm \\x'


def test_numeric_masks_use_strtoul_semantics_and_default_flags():
    assert it.parse_mask('8')['mask'] == 8
    assert it.parse_mask('  12abc')['mask'] == 12
    assert it.parse_mask('-1')['mask'] == 0xFFFFFFFF
    numeric = it.parse_mask('256,recursive=false')
    assert numeric['mask'] == 256 and numeric['recursive'] is True and numeric['numeric']


def test_loopable_is_recorded_but_loop_suppression_is_not_compiled():
    entry = it.parse_table('/x IN_MODIFY,loopable=true cmd\n')[0]
    assert entry['loopable'] is True and entry['loop_suppression_compiled'] is False


def test_long_lines_are_parsed_as_separate_fgets_pieces():
    tail = ' /etc IN_ATTRIB second\n'
    line = '/a IN_OPEN ' + 'x' * (it.TABLE_CHUNK - 11) + tail
    entries = it.parse_table(line)
    assert len(entries) == 2
    assert entries[1]['path'] == '/etc' and entries[1]['command'] == 'second'


def test_config_first_value_wins_comments_and_defaults():
    config = it.parse_config('# c\nsystem_table_dir = /x/sys\nsystem_table_dir=/y\n  allowed_users ==/a  \n'
                             'user_table_dir # not a comment = /u\n')
    values = config['values']
    assert values['system_table_dir'] == '/x/sys'
    assert values['allowed_users'] == '/a'
    assert values['denied_users'] == '/etc/incron.deny'
    assert values['user_table_dir'] == '/var/spool/incron'
    assert any('keeps the first value' in note for note in config['notes'])


def test_config_overlong_line_stops_reading():
    config = it.parse_config('x=' + 'a' * 1100 + '\nsystem_table_dir=/late\n')
    assert config['values']['system_table_dir'] == '/etc/incron.d'
    assert config['gaps'] == []


def test_config_overlong_line_is_truncated_and_still_parsed():
    # getline(s, 1023) keeps the first 1022 bytes and sets failbit; IncronCfg::Load parses that buffer
    # before the loop stops, so the setting applies and later lines are ignored.
    text = 'system_table_dir = /tmp/x' + ' ' * 1000 + 'TAIL\nuser_table_dir = /late\n'
    config = it.parse_config(text)
    assert config['values']['system_table_dir'] == '/tmp/x'
    assert config['values']['user_table_dir'] == '/var/spool/incron'
    assert config['gaps'] == []
    result = it.resolve(text, [], [], {}, ACCOUNTS, ALLOW_MISSING, {'state': 'missing'})
    assert result['config']['system_table_dir'] == '/tmp/x'
    assert result['complete'] is True


def test_config_line_of_exactly_limit_is_read_whole():
    line = 'system_table_dir=/' + 'd' * (it.CONFIG_LINE_MAX - 18)
    assert len(line) == it.CONFIG_LINE_MAX
    config = it.parse_config(line + '\nuser_table_dir=/u\n')
    assert config['values']['system_table_dir'] == line.split('=', 1)[1]
    assert config['values']['user_table_dir'] == '/u'


def test_config_overlong_line_splitting_utf8_fails_closed():
    text = 'system_table_dir=/' + 'a' * (it.CONFIG_LINE_MAX - 19) + '\u00e9tail\n'
    config = it.parse_config(text)
    assert [gap['code'] for gap in config['gaps']] == ['config_over_limit']
    result = it.resolve(text, [], [], {}, ACCOUNTS, ALLOW_MISSING, {'state': 'missing'})
    assert any(gap['code'] == 'config_over_limit' and gap['blocking'] for gap in result['gaps'])
    assert result['complete'] is False


def test_check_user_allow_then_deny_rules():
    gaps = []
    assert it.check_user('alice', {'state': 'present', 'text': 'alice\n'}, None, gaps) is True
    assert it.check_user('bob', {'state': 'present', 'text': 'alice\n'}, None, gaps) is False
    assert it.check_user('bob', ALLOW_MISSING, {'state': 'missing'}, gaps) is True
    assert it.check_user('bob', ALLOW_MISSING, {'state': 'present', 'text': '  bob extra\n'}, gaps) is False
    assert it.check_user('bob', {'state': 'unreadable'}, {'state': 'missing'}, gaps) is False
    assert it.check_user('bob', ALLOW_MISSING, {'state': 'unreadable'}, gaps) is False
    assert gaps == []
    assert it.check_user('bob', ALLOW_MISSING, None, gaps) is None and gaps[0]['blocking']


def test_resolve_system_and_user_tables():
    result = it.resolve(
        '',
        [_file('backup'), _file('.hidden'), {'name': 'link', 'd_type': 'symlink'},
         {'name': 'odd', 'd_type': 'unknown', 'stat_type': 'file'}, {'name': '.', 'd_type': 'directory'}],
        [_file('alice'), _file('mallory'), _file('bob')],
        tables={'/etc/incron.d/backup': '/etc IN_CLOSE_WRITE /usr/local/bin/sync $@/$#\n',
                '/etc/incron.d/odd': '/var/log IN_CREATE logger new\n',
                '/var/spool/incron/alice': '/home/alice IN_MOVED_TO /home/alice/bin/run\n'},
        accounts=ACCOUNTS, allow={'state': 'present', 'text': 'alice\n'}, deny={'state': 'missing'})
    assert result['complete'] and result['starts'] is True and result['origin'] == 'not_assessed'
    status = {table['path']: table['status'] for table in result['tables']}
    assert status == {
        '/etc/incron.d/backup': 'loads', '/etc/incron.d/.hidden': 'skipped_dotfile',
        '/etc/incron.d/link': 'skipped_non_file', '/etc/incron.d/odd': 'loads',
        '/var/spool/incron/alice': 'loads', '/var/spool/incron/mallory': 'user_unknown',
        '/var/spool/incron/bob': 'user_refused',
    }
    commands = {(command['runs_as'], command['shell'], command['command']) for command in result['commands']}
    assert commands == {
        ('root', '/bin/sh', '/usr/local/bin/sync $@/$#'), ('root', '/bin/sh', 'logger new'),
        ('alice', '/bin/bash', '/home/alice/bin/run'),
    }
    alice = next(table for table in result['tables'] if table['name'] == 'alice')
    assert alice['environment'] == 'reset'


def test_unopenable_directories():
    result = it.resolve('', 'unopenable', 'unopenable', accounts=ACCOUNTS)
    assert result['starts'] is False and result['commands'] == []
    assert result['complete']


def test_fail_closed_on_unobserved_inputs():
    assert not it.resolve(None, [], [])['complete']
    missing_table = it.resolve('', [_file('job')], [], accounts=ACCOUNTS)
    assert not missing_table['complete']
    assert missing_table['tables'][0]['status'] == 'unresolved'
    unknown_type = it.resolve('', [{'name': 'x', 'd_type': 'unknown'}], [], accounts=ACCOUNTS)
    assert not unknown_type['complete'] and unknown_type['tables'][0]['status'] == 'unresolved'
    no_accounts = it.resolve('', [], [_file('alice')], tables={'/var/spool/incron/alice': ''})
    assert not no_accounts['complete']
    binary = it.resolve('', [_file('job')], [], tables={'/etc/incron.d/job': 'a\0b'}, accounts=ACCOUNTS)
    assert any(gap['code'] == 'binary' for gap in binary['gaps'])
    not_listed = it.resolve('', None, [], accounts=ACCOUNTS)
    assert not not_listed['complete']


def test_config_relocates_table_directories():
    result = it.resolve('system_table_dir = /opt/inc/\n', [_file('t')], [],
                        tables={'/opt/inc/t': '/x IN_DELETE_SELF cmd\n'}, accounts=ACCOUNTS)
    assert result['tables'][0]['path'] == '/opt/inc/t'
    assert result['commands'][0]['events'] == ['IN_DELETE_SELF']
