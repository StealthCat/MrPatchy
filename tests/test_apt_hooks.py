"""Pure APT configuration hook contract (#950)."""
import pytest

from app import apt_hooks

PARTS = apt_hooks.PARTS_DIR


def part(name, content, kind='file'):
    return {'name': name, 'type': kind, 'content': content}


def resolve(*files, main=None):
    return apt_hooks.resolve(list(files), main if main is not None else {'present': False})


def commands(result, option=None):
    return [(h['option'], h['value']) for h in result['hooks']
            if h['kind'] == 'command' and h['executed'] and (option is None or h['option'] == option)]


def codes(result):
    return [g['code'] for g in result['gaps']]


@pytest.mark.parametrize('name,read,reason,notice', [
    ('20listchanges', True, None, False),
    ('50unattended-upgrades.conf', True, None, False),
    ('01:colon_ok', True, None, False),
    ('.hidden', False, 'hidden', False),
    ('99local.txt', False, 'extension', True),
    ('20hook.conf.bak', False, 'extension', False),
    ('20hook.dpkg-old', False, 'extension', False),
    ('20hook.ucf-dist', False, 'extension', False),
    ('20hook.disabled', False, 'extension', False),
    ('20hook.distUpgrade', False, 'extension', False),
    ('20hook~', False, 'invalid_character', False),
    ('20 hook', False, 'invalid_character', True),
    ('20hook+x', False, 'invalid_character', True),
])
def test_file_eligibility_follows_apt_parts_rules(name, read, reason, notice):
    assert apt_hooks.eligibility(name) == {'read': read, 'reason': reason, 'notice': notice}


def test_ignored_and_non_regular_files_are_listed_and_never_applied():
    result = resolve(part('99evil.txt', 'DPkg::Post-Invoke { "a"; };'),
                     part('50dir', None, kind='directory'),
                     part('.x', 'DPkg::Post-Invoke { "b"; };'),
                     part('10ok', 'DPkg::Post-Invoke { "c"; };'))
    assert commands(result) == [('DPkg::Post-Invoke', 'c')]
    states = {f['path']: (f['state'], f.get('reason')) for f in result['files']}
    assert states[PARTS + '/99evil.txt'] == ('ignored', 'extension')
    assert states[PARTS + '/50dir'] == ('ignored', 'not_regular_file')
    assert states[PARTS + '/.x'] == ('ignored', 'hidden')
    assert result['apt_behavior'] == 'determined'


def test_files_are_read_in_byte_order_and_main_file_last():
    result = resolve(part('b', 'Acquire::http::Proxy-Auto-Detect "/b";'),
                     part('B', 'Acquire::http::Proxy-Auto-Detect "/upper";'),
                     part('a', 'Acquire::http::Proxy-Auto-Detect "/a";'))
    # Byte order is B < a < b, so b wins.
    [hook] = result['hooks']
    assert (hook['value'], hook['source']['path']) == ('/b', PARTS + '/b')
    assert [f['path'] for f in result['files']] == [PARTS + '/B', PARTS + '/a', PARTS + '/b']
    result = resolve(part('z', 'Acquire::http::Proxy-Auto-Detect "/z";'),
                     main={'present': True, 'content': 'Acquire::http::Proxy-Auto-Detect "/main";'})
    [hook] = result['hooks']
    assert (hook['value'], hook['source']['path']) == ('/main', apt_hooks.MAIN_FILE)


def test_list_items_append_across_files_and_keys_are_case_insensitive():
    result = resolve(part('10a', '''
        DPkg::Post-Invoke { "first"; "second"; };
        dpkg { post-invoke { "nested"; }; };
    '''), part('20b', 'DPKG::POST-INVOKE:: "appended";'))
    assert commands(result, 'DPkg::Post-Invoke') == [
        ('DPkg::Post-Invoke', v) for v in ('first', 'second', 'nested', 'appended')]
    assert all(h['shell'] for h in result['hooks'])


def test_every_command_list_is_recognized_with_source_lines():
    text = '\n'.join(f'{name} {{ "cmd{i}"; }};' for i, name in enumerate(apt_hooks.COMMAND_LISTS.values()))
    result = resolve(part('30all', text))
    assert commands(result) == [(name, f'cmd{i}') for i, name in enumerate(apt_hooks.COMMAND_LISTS.values())]
    assert [h['source']['line'] for h in result['hooks']] == list(range(1, 7))


def test_tagged_child_and_scalar_repeat_override_earlier_values():
    result = resolve(part('10a', 'DPkg::Pre-Invoke::mine "old"; Dir::Bin::dpkg "/usr/bin/dpkg";'),
                     part('20b', 'DPkg::Pre-Invoke::MINE "new"; Dir::Bin::dpkg "/opt/fake-dpkg";'))
    assert commands(result) == [('DPkg::Pre-Invoke', 'new')]
    [binary] = [h for h in result['hooks'] if h['kind'] == 'binary_override']
    assert (binary['option'], binary['value'], binary['source']['path']) == (
        'Dir::Bin::dpkg', '/opt/fake-dpkg', PARTS + '/20b')


def test_clear_removes_the_subtree_and_later_items_still_apply():
    result = resolve(part('10a', 'APT::Update::Post-Invoke { "a"; "b"; };'),
                     part('20b', '#clear APT::Update::Post-Invoke;\nAPT::Update::Post-Invoke { "c"; };'))
    assert commands(result) == [('APT::Update::Post-Invoke', 'c')]


def test_scalar_on_a_hook_list_node_is_reported_inert():
    result = resolve(part('10a', 'DPkg::Post-Invoke "never run";'))
    [hook] = result['hooks']
    assert (hook['executed'], hook['shell'], hook['value']) == (False, False, 'never run')
    assert commands(result) == []


def test_binary_scope_and_other_recognized_kinds():
    result = resolve(part('10a', '''
        Binary::apt-get::DPkg::Pre-Invoke { "scoped"; };
        Acquire::https::ProxyAutoDetect "/usr/bin/detect";
        DPkg::Path "/tmp/evil:/usr/bin";
        DPkg::Options { "--force-confold"; };
        Dir::Bin::methods "/opt/methods";
    '''))
    found = {(h['kind'], h['option'], h['scope'], h['value']) for h in result['hooks']}
    assert found == {
        ('command', 'Binary::apt-get::DPkg::Pre-Invoke', 'apt-get', 'scoped'),
        ('proxy_command', 'Acquire::https::ProxyAutoDetect', None, '/usr/bin/detect'),
        ('path_override', 'DPkg::Path', None, '/tmp/evil:/usr/bin'),
        ('dpkg_options', 'DPkg::Options', None, '--force-confold'),
        ('binary_override', 'Dir::Bin::methods', None, '/opt/methods'),
    }


def test_comments_are_stripped_outside_quotes_only():
    result = resolve(part('10a', '''
        // DPkg::Post-Invoke { "line comment"; };
        # DPkg::Post-Invoke { "hash comment"; };
        /* DPkg::Post-Invoke { "block";
           "comment"; }; */
        DPkg::Post-Invoke { "echo '#x' // kept"; }; # trailing
        DPkg::Post-Invoke /* inline */ { "after"; };
    '''))
    assert commands(result) == [('DPkg::Post-Invoke', "echo '#x' // kept"), ('DPkg::Post-Invoke', 'after')]
    assert result['apt_behavior'] == 'determined'


def test_unquoted_values_and_empty_assignment():
    result = resolve(part('10a', 'Dir::Bin::dpkg /opt/dpkg; DPkg::Path;'))
    assert [(h['option'], h['value']) for h in result['hooks']] == [('Dir::Bin::dpkg', '/opt/dpkg')]


@pytest.mark.parametrize('text,line', [
    ('DPkg::Post-Invoke { "visible"; };\nDPkg::Post-Invoke { "open;\n" };', 2),
    ('DPkg::Post-Invoke { "visible"; };\nDPkg::Pre-Invoke { "x";', 2),
    ('DPkg::Post-Invoke { "visible"; };\nAPT::Foo "a" "b";', 2),
    ('DPkg::Post-Invoke { "visible"; };\n};', 2),
    ('DPkg::Post-Invoke { "visible"; };\n/* never closed', 2),
    ('DPkg::Post-Invoke { "visible"; };\nA::::B "x";', 2),
    ('DPkg::Post-Invoke { "visible"; };\n#clear "";', 2),
    ('DPkg::Post-Invoke { "visible"; };\n#include;', 2),
])
def test_syntax_errors_make_behavior_undetermined_but_keep_earlier_hooks(text, line):
    result = resolve(part('10a', text))
    assert result['apt_behavior'] == 'undetermined'
    assert result['files'][0]['state'] == 'syntax_error'
    [gap] = [g for g in result['gaps'] if g['code'] == 'syntax_error']
    assert (gap['path'], gap['line']) == (PARTS + '/10a', line)
    assert ('DPkg::Post-Invoke', 'visible') in commands(result)


def test_include_is_never_followed_and_directory_overrides_are_gaps():
    result = resolve(part('10a', '#include "/tmp/other.conf";\nDir::Etc::Parts "/tmp/parts";'))
    assert result['apt_behavior'] == 'undetermined'
    gaps = {g['code']: g for g in result['gaps']}
    assert gaps['include_not_followed']['target'] == '/tmp/other.conf'
    assert gaps['directory_override']['line'] == 2


def test_unreadable_oversized_and_invalid_observations_fail_closed():
    big = 'x' * (apt_hooks.MAX_FILE_BYTES + 1)
    result = resolve(part('10a', None), part('20b', big), {'name': '../x', 'type': 'file', 'content': ''})
    assert result['apt_behavior'] == 'undetermined'
    assert {'file_unreadable', 'file_too_large', 'invalid_entry'} <= set(codes(result))
    assert [f['state'] for f in result['files']] == ['unreadable', 'too_large']


def test_uncollected_inputs_are_gaps_not_empty_configuration():
    result = apt_hooks.resolve(None, None)
    assert result['apt_behavior'] == 'undetermined'
    assert {'parts_not_collected', 'main_not_collected', 'apt_config_env_unobserved'} <= set(codes(result))
    assert result['hooks'] == []
    clean = resolve()
    assert clean['apt_behavior'] == 'determined'
    assert codes(clean) == ['apt_config_env_unobserved']
    assert 'not a safety verdict' in clean['not_a_verdict']


def test_bounds_on_files_values_and_hooks():
    many = [part(f'{i:04d}', '') for i in range(apt_hooks.MAX_FILES + 1)]
    result = apt_hooks.resolve(many, {'present': False})
    assert 'file_limit' in codes(result) and len(result['files']) == apt_hooks.MAX_FILES
    long = 'y' * (apt_hooks.MAX_VALUE + 10)
    [hook] = resolve(part('10a', f'DPkg::Post-Invoke {{ "{long}"; }};'))['hooks']
    assert hook['truncated'] and len(hook['value']) == apt_hooks.MAX_VALUE
    items = ' '.join(f'"c{i}";' for i in range(apt_hooks.MAX_HOOKS + 1))
    result = resolve(part('10a', f'DPkg::Post-Invoke {{ {items} }};'))
    assert len(result['hooks']) == apt_hooks.MAX_HOOKS and 'hook_limit' in codes(result)


@pytest.mark.parametrize('text,expected', [
    ('DPkg::Post-Invoke { /tmp/evil; };', [('DPkg::Post-Invoke', '/tmp/evil')]),
    ('DPkg::Post-Invoke { "ok"; evil; "ok2"; };',
     [('DPkg::Post-Invoke', 'ok'), ('DPkg::Post-Invoke', 'evil'), ('DPkg::Post-Invoke', 'ok2')]),
    ('APT::Update::Pre-Invoke { evil; };', [('APT::Update::Pre-Invoke', 'evil')]),
])
def test_unquoted_word_inside_a_block_is_an_untagged_item(text, expected):
    # apt-config 2.8.3 dumps a bare word in a block as an untagged list item and runs it.
    result = resolve(part('10a', text))
    assert commands(result) == expected
    assert result['apt_behavior'] == 'determined'


def test_clear_with_trailing_separator_clears_nothing():
    # apt-config 2.8.3 keeps both items after ``#clear DPkg::Post-Invoke::;``.
    result = resolve(part('10a', 'DPkg::Post-Invoke {"a";};\nDPkg::Post-Invoke::t "t";\n#clear DPkg::Post-Invoke::;'))
    assert sorted(v for _, v in commands(result, 'DPkg::Post-Invoke')) == ['a', 't']
    assert result['apt_behavior'] == 'determined'


@pytest.mark.parametrize('text', [
    'DPkg { #clear Post-Invoke; };',
    'DPkg::Post-Invoke { "a"; #clear DPkg::Post-Invoke; "b"; };',
    'DPkg { #include "/etc/x"; };',
    'DPkg::Pre-Invoke { "p"; };\nDPkg::Post-Invoke { "q"; };\n#clear DPkg::Pre-Invoke DPkg::Post-Invoke;',
])
def test_directives_apt_rejects_are_syntax_errors(text):
    # APT fails with "Directives can only be done at the top level" or "Extra junk after value".
    result = resolve(part('10a', text))
    assert result['apt_behavior'] == 'undetermined'
    assert 'syntax_error' in codes(result)


@pytest.mark.parametrize('text,expected', [
    ('DPkg::Post-Invoke { ev/*x*/il; };', [('DPkg::Post-Invoke', 'evil')]),
    ('DPkg::Post-/*c*/Invoke { "a"; };', [('DPkg::Post-Invoke', 'a')]),
    # A comment that spans lines still separates: the line break is a separator in APT too.
    ('DPkg::Post-Invoke { ev/*x\ny*/il; };', [('DPkg::Post-Invoke', 'il')]),
    ('DPkg::Post-Invoke { "a" /*c*/ ; /* d */ "b"; };', [('DPkg::Post-Invoke', 'a'), ('DPkg::Post-Invoke', 'b')]),
])
def test_same_line_block_comment_joins_the_text_around_it(text, expected):
    # apt-config 2.8.3 deletes a /* */ comment without leaving a space.
    result = resolve(part('10a', text))
    assert commands(result) == expected
    assert result['apt_behavior'] == 'determined'


def test_block_comment_inside_a_tagged_word_sets_no_hook():
    # apt-config 2.8.3 reads ``DPkg::Post-Invoke::tef;`` and sets an empty-named root option; nothing runs.
    result = resolve(part('10a', 'DPkg::Post-Invoke::te/*c*/f;'))
    assert commands(result) == []


@pytest.mark.parametrize('text', [
    'DPkg::Post-Invoke::"b c";',
    'DPkg::Post-Invoke {"a";};\n#clear"DPkg::Post-Invoke";',
    'DPkg::Post-Invoke { x"a"; };',
    'DPkg::Post-Invoke { "a"x; };',
    'DPkg::Post-Invoke { "a"/*c*/x; };',
    'DPkg::Post-Invoke "a""b";',
    # apt-config 2.8.3 rejects the first two and drops the item in the third.
    'DPkg::Post-Invoke { a/*c*//*d*/b; };',
    'DPkg::Post-Invoke { a/*c*//b; };',
    'DPkg::Post-Invoke { /*c*//*d*/a; };',
])
def test_text_this_contract_does_not_interpret_fails_closed(text):
    # APT joins a word and a touching quote into one word (``x"a"`` runs ``xa``; ``#clear"A"`` clears nothing).
    result = resolve(part('10a', text))
    assert result['apt_behavior'] == 'undetermined'
    assert 'syntax_error' in codes(result)


def test_hooks_before_a_touching_quote_stay_visible():
    result = resolve(part('10a', 'DPkg::Post-Invoke {"a";};\n#clear"DPkg::Post-Invoke";'))
    assert commands(result) == [('DPkg::Post-Invoke', 'a')]
