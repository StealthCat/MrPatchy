from app import nss_modules as nss


def resolve(text, **extra):
    return nss.resolve_nss_modules({'type': 'file', 'text': text, **extra})


def db(result, name):
    return next(e for e in result['databases'] if e['database'] == name)


def module(result, library):
    return next(m for m in result['modules'] if m['library'] == library)


def services(result, name):
    return [s['service'] for s in db(result, name)['services']]


def libraries(result):
    return [m['library'] for m in result['modules']]


def test_stock_ubuntu_file_loads_only_systemd_and_built_ins():
    text = ('# /etc/nsswitch.conf\n#\n# Example configuration of GNU Name Service Switch functionality.\n\n'
            'passwd:         files systemd\ngroup:          files systemd\nshadow:         files systemd\n'
            'gshadow:        files systemd\n\nhosts:          files dns\nnetworks:       files\n\n'
            'protocols:      db files\nservices:       db files\nethers:         db files\nrpc:            db files\n\n'
            'netgroup:       nis\n')
    result = resolve(text)
    assert result['complete'] is True and result['file']['status'] == 'parsed'
    assert services(result, 'passwd') == ['files', 'systemd']
    assert db(result, 'passwd')['line'] == 5 and db(result, 'passwd')['source'] == 'file'
    assert [s['builtin'] for s in db(result, 'hosts')['services']] == [True, True]
    assert set(libraries(result)) == {'libnss_systemd.so.2', 'libnss_db.so.2', 'libnss_nis.so.2',
                                      'libnss_nisplus.so.2'}
    systemd = module(result, 'libnss_systemd.so.2')
    assert systemd['databases'] == ['group', 'gshadow', 'initgroups', 'passwd', 'shadow']
    assert db(result, 'initgroups')['source'] == 'uses_group'
    assert result['origin'] == 'not_assessed' and result['unobserved']


def test_there_are_no_comments_after_the_database_name():
    # glibc 2.39 loads libnss_#.so.2 and libnss_note.so.2 for this line.
    result = resolve('passwd: files # note\n#group: evil\n')
    assert services(result, 'passwd') == ['files', '#', 'note']
    assert module(result, 'libnss_#.so.2')['databases'] == ['passwd', 'shadow']
    assert module(result, 'libnss_note.so.2')['service'] == 'note'
    assert services(result, 'group') == ['files']  # "#group" is not a database
    assert result['ignored_lines'] == []


def test_names_are_case_sensitive_last_line_wins_and_unknown_names_are_ignored():
    result = resolve('passwd: files foo\nPASSWD: evil\nsudoers: files ldap\npasswd: bar\n')
    assert services(result, 'passwd') == ['bar'] and db(result, 'passwd')['line'] == 4
    assert [i['name'] for i in result['ignored_lines']] == ['PASSWD', 'sudoers']
    assert 'libnss_evil.so.2' not in libraries(result) and 'libnss_ldap.so.2' not in libraries(result)


def test_unterminated_final_line_and_name_without_separator():
    result = resolve('group: files a\npasswd: files evil')
    assert services(result, 'passwd') == ['files'] and db(result, 'passwd')['source'] == 'default'
    assert result['ignored_lines'] == [{'line': 2, 'reason': 'no_final_newline'}]
    # A terminated database name with no list gives that database no services at all.
    result = resolve('passwd\n')
    assert db(result, 'passwd')['empty'] is True and db(result, 'shadow')['empty'] is True


def test_separator_runs_and_bracket_without_service_end_the_list():
    result = resolve('passwd :: :\tfoo[UNAVAIL=continue]bar\ngroup: [NOTFOUND=return] evil\n')
    assert services(result, 'passwd') == ['foo', 'bar']
    assert services(result, 'group') == [] and db(result, 'group')['empty'] is True


def test_criteria_negation_case_and_spacing():
    result = resolve('passwd: files [ !success = Return  notfound=MERGE ] foo\n')
    files = db(result, 'passwd')['services'][0]
    assert files['actions'] == {'SUCCESS': 'RETURN', 'NOTFOUND': 'MERGE', 'UNAVAIL': 'RETURN', 'TRYAGAIN': 'RETURN'}
    assert files['default_actions'] is False
    assert db(result, 'passwd')['services'][1]['default_actions'] is True


def test_one_syntax_error_rejects_the_whole_file():
    for bad in ('[BAD=return]', '[NOTFOUND]', '[NOTFOUND=stop]', '[NOTFOUND=return', '[ ]', '[ſUCCESS=return]'):
        result = resolve(f'passwd: files foo\ngroup: files {bad} bar\n')
        assert result['file']['status'] == 'rejected', bad
        assert result['file']['rejected_line'] == 2
        assert result['databases'] == [] and result['modules'] == []
        assert result['complete'] is True
    # A syntax error on an ignored database name is never parsed.
    assert resolve('sudoers: files [BAD=x]\n')['file']['status'] == 'parsed'


def test_defaults_and_inheritance():
    result = resolve('passwd: files evil\ngroup: files grp\n')
    assert services(result, 'shadow') == ['files', 'evil'] and db(result, 'shadow')['inherited_from'] == 'passwd'
    assert services(result, 'gshadow') == ['files', 'grp']
    assert services(result, 'initgroups') == ['files', 'grp']
    assert services(result, 'hosts') == ['files', 'dns'] and services(result, 'publickey') == ['nis', 'nisplus']
    assert services(result, 'passwd_compat') == ['nis'] and services(result, 'aliases') == ['files']
    # An explicit empty initgroups line stops the fallback to group.
    assert services(resolve('group: files grp\ninitgroups:\n'), 'initgroups') == []
    for kind in ('absent', 'directory', 'unopenable'):
        result = nss.resolve_nss_modules({'type': kind})
        assert result['file']['status'] == kind and result['complete'] is True
        assert services(result, 'passwd') == ['files']
        assert libraries(result) == ['libnss_nis.so.2', 'libnss_nisplus.so.2']


def test_path_like_service_and_control_characters_are_flagged():
    result = resolve('passwd: x/../../tmp/evil q\x01\n')
    rows = db(result, 'passwd')['services']
    assert rows[0]['library'] == 'libnss_x/../../tmp/evil.so.2' and rows[0]['library_is_path'] is True
    assert rows[1]['control_characters'] is True
    assert module(result, 'libnss_x/../../tmp/evil.so.2')['library_is_path'] is True


def test_fail_closed_inputs():
    cases = [({'type': 'file', 'text': b'passwd: a\x00\n'}, 'nul_byte'),
             ({'type': 'file', 'text': b'passwd: \xff\n'}, 'invalid_utf8'),
             ({'type': 'file', 'text': 'x' * (nss.MAX_TEXT + 1)}, 'text_over_limit'),
             ({'type': 'symlink'}, 'symlink_not_followed'),
             ({'type': 'fifo'}, 'file_unreadable'),
             (None, 'file_not_supplied'),
             ({'path': '/etc/other', 'text': ''}, 'file_not_supplied')]
    for item, code in cases:
        result = nss.resolve_nss_modules(item)
        assert result['complete'] is False, code
        assert [g['code'] for g in result['gaps']] == [code]
        assert result['databases'] == [] and result['modules'] == []


def test_service_limit_marks_result_incomplete():
    result = resolve('passwd: ' + ' '.join(f's{i}' for i in range(nss.MAX_SERVICES + 5)) + '\n')
    assert result['complete'] is False
    assert [g['code'] for g in result['gaps']] == ['too_many_services']
