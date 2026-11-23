import json
import os
import random
import subprocess

import pytest

from app import sddm_display_scripts as sd

SYS = sd.SYSTEM_CONFIG_DIR
ETC = sd.CONFIG_DIR
MAIN = sd.CONFIG_FILE


def _file(name, **kw):
    return dict({'name': name, 'type': 'file'}, **kw)


def _run(files=None, sys_listing=None, etc_listing=None, main=None, **kw):
    """files maps a full path to its text; listings are derived from it unless given."""
    kw.setdefault('family', 'debian')
    kw.setdefault('sddm_installed', True)
    kw.setdefault('exec_start', ['/usr/bin/sddm'])
    files = dict(files or {})
    sources = {}
    for directory, listing in ((SYS, sys_listing), (ETC, etc_listing)):
        if listing is None:
            names = [p[len(directory) + 1:] for p in files if p.startswith(directory + '/')]
            listing = {'state': 'listed', 'entries': [_file(n) for n in names]} if names else {'state': 'absent'}
        sources[directory] = listing
    for path, text in files.items():
        sources[path] = {'state': 'read', 'text': text}
    sources[MAIN] = main if main is not None else {'state': 'absent'}
    return sd.assess(sources, **kw)


def _codes(result):
    return {g['code'] for g in result['gaps']}


def _cmd(result, setting):
    return next(c for c in result['commands'] if c['setting'] == setting)


def test_packaged_defaults_run_xsetup_xstop_and_x_server_as_root():
    result = _run()
    assert result['complete'] and result['applicability'] == 'applicable' and result['runs_as'] == 'root'
    assert result['display_server'] == {'value': 'x11', 'effective': 'x11', 'fallback': False}
    setup = _cmd(result, 'X11.DisplayCommand')
    assert setup['argv'] == ('/usr/share/sddm/scripts/Xsetup',) and setup['packaged_default']
    assert setup['stage'] == 'after_server_start' and setup['timeout_seconds'] == 30
    stop = _cmd(result, 'X11.DisplayStopCommand')
    assert stop['argv'] == ('/usr/share/sddm/scripts/Xstop',) and stop['timeout_seconds'] == 5
    server = _cmd(result, 'X11.ServerPath')
    assert server['argv'][:3] == ('/usr/bin/X', '-nolisten', 'tcp') and server['packaged_default']
    assert server['argv'][3:] == sd.SERVER_TRAILING_ARGS
    # Ubuntu patches DefaultPath to the spartan /bin:/usr/bin.
    assert result['script_environment']['PATH'] == '/bin:/usr/bin'


def test_load_order_later_file_wins_and_records_source_line():
    result = _run({
        f'{SYS}/50-vendor.conf': '[X11]\nDisplayCommand=/usr/lib/vendor/setup\n',
        f'{ETC}/10-local.conf': '[X11]\nDisplayCommand=/usr/local/bin/local-setup\n',
    }, main={'state': 'read', 'text': '# main\n[X11]\nDisplayStopCommand=/usr/local/bin/stop --now\n'})
    assert result['complete']
    setup = _cmd(result, 'X11.DisplayCommand')
    assert setup['argv'] == ('/usr/local/bin/local-setup',)
    assert setup['source'] == {'path': f'{ETC}/10-local.conf', 'line': 2} and not setup['packaged_default']
    stop = _cmd(result, 'X11.DisplayStopCommand')
    assert stop['argv'] == ('/usr/local/bin/stop', '--now') and stop['source'] == {'path': MAIN, 'line': 3}


def test_main_config_overrides_directories():
    result = _run({f'{ETC}/z.conf': '[X11]\nDisplayCommand=/a\n'},
                  main={'state': 'read', 'text': '[X11]\nDisplayCommand=/b\n'})
    assert _cmd(result, 'X11.DisplayCommand')['argv'] == ('/b',)


def test_any_file_name_is_loaded_but_hidden_dirs_special_and_broken_links_are_not():
    listing = {'state': 'listed', 'entries': [
        _file('settings.txt'), _file('.hidden.conf'), {'name': 'sub', 'type': 'directory'},
        {'name': 'fifo', 'type': 'other'}, {'name': 'dangling', 'type': 'symlink', 'target': None},
        {'name': 'link.conf', 'type': 'symlink', 'target': {'type': 'file'}},
    ]}
    files = {f'{ETC}/settings.txt': '[X11]\nDisplayStopCommand=/from/txt\n',
             f'{ETC}/link.conf': '[X11]\nDisplayCommand=/from/link\n'}
    result = _run(files, etc_listing=listing)
    assert result['complete']
    assert _cmd(result, 'X11.DisplayStopCommand')['argv'] == ('/from/txt',)
    assert _cmd(result, 'X11.DisplayCommand')['argv'] == ('/from/link',)
    reasons = {f['path'].rsplit('/', 1)[1]: f.get('reason') for f in result['loaded'][1]['files']}
    assert reasons['.hidden.conf'] == 'hidden' and reasons['sub'] == 'not_a_file:directory'
    assert reasons['fifo'] == 'not_a_file:other' and reasons['dangling'] == 'not_a_file:broken'


def test_line_parsing_matches_config_reader():
    text = (
        'DisplayServer = X11   \n'              # implicit General section; lower-cased
        '[X11]\n'
        'displaycommand=/ignored/case\n'        # keys are case-sensitive
        '  DisplayCommand =  /opt/a  "b c"  # trailing comment\n'
        '#DisplayStopCommand=/commented\n'
        'DisplayStopCommand=/opt/stop#nocomment-space\n'
        '[x11]\n'                               # section names are case-sensitive
        'DisplayCommand=/wrong/section\n'
        '[X11=still assignment]\n'              # '=' is checked before section headers
        'DisplayCommand=/opt/a  "b c"\r\n'
    )
    result = _run({f'{ETC}/a.conf': text})
    assert result['display_server']['effective'] == 'x11'
    setup = _cmd(result, 'X11.DisplayCommand')
    assert setup['argv'] == ('/opt/a', 'b c') and setup['source']['line'] == 4
    assert _cmd(result, 'X11.DisplayStopCommand')['argv'] == ('/opt/stop',)


def test_xdisplay_alias_and_last_assignment_in_a_file_wins():
    text = '[XDisplay]\nDisplayCommand=/first\nDisplayCommand=/second\n'
    result = _run({f'{ETC}/a.conf': text})
    assert _cmd(result, 'X11.DisplayCommand')['argv'] == ('/second',)


def test_each_file_starts_in_general_section():
    result = _run({f'{ETC}/a.conf': '[X11]\n', f'{ETC}/b.conf': 'DisplayCommand=/not/x11\n'})
    assert _cmd(result, 'X11.DisplayCommand')['packaged_default']


def test_unknown_display_server_falls_back_to_x11():
    result = _run({f'{ETC}/a.conf': 'DisplayServer=bogus\n'})
    assert result['complete'] and result['display_server'] == {'value': 'bogus', 'effective': 'x11',
                                                               'fallback': True}


@pytest.mark.parametrize('mode', ['x11-user', 'Wayland'])
def test_helper_modes_are_blocking_and_report_no_commands(mode):
    result = _run({f'{ETC}/a.conf': f'DisplayServer={mode}\n'})
    assert not result['complete'] and 'display_server_not_modeled' in _codes(result)
    assert result['commands'] == []


def test_server_path_and_arguments():
    result = _run({f'{ETC}/a.conf': '[X11]\nServerPath=/opt/X server\nServerArguments=-a\t-b  "c d"\n'})
    server = _cmd(result, 'X11.ServerPath')
    # setProgram keeps spaces in the path; ServerArguments splits on ' ' only, not tabs or quotes.
    assert server['program'] == '/opt/X server'
    assert server['argv'][:4] == ('/opt/X server', '-a\t-b', '"c', 'd"')
    assert server['arguments_source'] == {'path': f'{ETC}/a.conf', 'line': 3}


@pytest.mark.parametrize('value,code', [
    ('', 'empty_command'), ('   ""  ', 'empty_command'), ('xsetup-tool --x', 'program_path_search'),
    ('bin/setup', 'relative_program'),
])
def test_unresolvable_commands_are_blocking(value, code):
    result = _run({f'{ETC}/a.conf': f'[X11]\nDisplayCommand={value}\n'})
    assert not result['complete'] and code in _codes(result)


def test_empty_server_path_is_blocking():
    result = _run({f'{ETC}/a.conf': '[X11]\nServerPath=\n'})
    assert 'empty_command' in _codes(result) and _cmd(result, 'X11.ServerPath')['runs'] is None


def test_same_directory_disagreement_is_ambiguous_unless_overridden():
    files = {f'{ETC}/a.conf': '[X11]\nDisplayCommand=/a\n', f'{ETC}/B.conf': '[X11]\nDisplayCommand=/b\n'}
    result = _run(files)
    assert not result['complete'] and 'order_ambiguous' in _codes(result)
    assert _cmd(result, 'X11.DisplayCommand')['argv'] is None
    # Agreement is not ambiguous, and a later group decides regardless.
    same = _run({f'{ETC}/a.conf': '[X11]\nDisplayCommand=/a\n', f'{ETC}/b.conf': '[X11]\nDisplayCommand=/a\n'})
    assert same['complete']
    later = _run(files, main={'state': 'read', 'text': '[X11]\nDisplayCommand=/main\n'})
    assert later['complete'] and _cmd(later, 'X11.DisplayCommand')['argv'] == ('/main',)


def test_ambiguous_display_server_blocks_commands():
    result = _run({f'{ETC}/a.conf': 'DisplayServer=wayland\n', f'{ETC}/b.conf': 'DisplayServer=x11\n'})
    assert 'order_ambiguous' in _codes(result) and result['commands'] == []


@pytest.mark.parametrize('obs,code', [
    ({'state': 'unreadable'}, 'config_unreadable'),
    ({'state': 'read', 'text': 'a\0b'}, 'config_nul'),
    ({'state': 'read', 'text': 'x\udcff'}, 'config_invalid_utf8'),
    ({'state': 'read', 'text': 'x' * (sd.MAX_FILE_CHARS + 1)}, 'config_too_large'),
    ({'state': 'read'}, 'input_malformed'),
    ({'state': 'weird'}, 'input_malformed'),
])
def test_bad_file_observations_are_blocking(obs, code):
    result = _run(main=obs)
    assert not result['complete'] and code in _codes(result)


@pytest.mark.parametrize('listing,code', [
    (None, 'directory_not_observed'), ({'state': 'unreadable'}, 'directory_unreadable'),
    ({'state': 'listed', 'entries': [], 'truncated': True}, 'listing_incomplete'),
    ({'state': 'listed', 'entries': [_file(str(i)) for i in range(sd.MAX_ENTRIES + 1)]}, 'too_many_entries'),
    ({'state': 'listed', 'entries': [_file('a'), _file('a')]}, 'input_malformed'),
    ({'state': 'listed', 'entries': [{'name': 'a', 'type': 'symlink'}]}, 'symlink_target_unobserved'),
    ({'state': 'listed', 'entries': [{'name': 'a'}]}, 'metadata_missing'),
])
def test_bad_listings_are_blocking(listing, code):
    sources = {SYS: {'state': 'absent'}, ETC: listing, MAIN: {'state': 'absent'}}
    result = sd.assess(sources, family='debian', sddm_installed=True, exec_start=['/usr/bin/sddm'])
    assert not result['complete'] and code in _codes(result)


def test_listed_file_without_observation_is_blocking():
    sources = {SYS: {'state': 'absent'}, ETC: {'state': 'listed', 'entries': [_file('a.conf')]},
               MAIN: {'state': 'absent'}}
    result = sd.assess(sources, family='debian', sddm_installed=True, exec_start=['/usr/bin/sddm'])
    assert 'config_not_observed' in _codes(result) and not result['complete']


@pytest.mark.parametrize('kw,code', [
    ({'family': None}, 'family_not_observed'), ({'family': 'rhel'}, 'family_unsupported'),
    ({'sddm_installed': None}, 'implementation_not_observed'), ({'exec_start': None}, 'exec_start_not_observed'),
    ({'exec_start': ['/usr/bin/sddm', '--test-mode']}, 'nondefault_exec_start'),
    ({'exec_start': 'sddm'}, 'input_malformed'),
])
def test_context_gaps_are_blocking(kw, code):
    result = _run(**kw)
    assert not result['complete'] and code in _codes(result)


def test_not_installed_is_not_applicable_and_inputs_untouched():
    files = {f'{ETC}/a.conf': '[X11]\nDisplayCommand=/a\n'}
    snapshot = json.dumps(files, sort_keys=True)
    result = _run(files, sddm_installed=False)
    assert result['applicability'] == 'not_applicable' and result['complete']
    assert json.dumps(files, sort_keys=True) == snapshot
    assert result['origin'] == 'not_assessed' and result['not_a_verdict']


def test_gap_list_is_bounded():
    entries = [{'name': f'l{i}', 'type': 'symlink'} for i in range(200)]
    result = _run(etc_listing={'state': 'listed', 'entries': entries})
    assert len(result['gaps']) == sd.MAX_GAPS and result['gaps'][-1]['code'] == 'gaps_truncated'


@pytest.mark.parametrize('command,expected', [
    ('a b', ['a', 'b']), ('"a b" c', ['a b', 'c']), ('"""', ['"']), ('a""b', ['ab']),
    ('"a """ b"', ['a " b']), ('a b', ['a', 'b']), ('a\x1cb', ['a\x1cb']), ('a\u0085b', ['a', 'b']),
    ('"unterminated b', ['unterminated b']), ('', []), ('""', []),
])
def test_split_command_examples(command, expected):
    assert sd.split_command(command) == expected


def test_qt_trimmed_uses_qchar_isspace():
    assert sd.qt_trimmed(' \t x  ') == 'x'
    assert sd.qt_trimmed('\x1cx\x1f') == '\x1cx\x1f'


QT_PYTHON = os.environ.get('MRPATCHY_QT_PYTHON')


@pytest.mark.skipif(not QT_PYTHON, reason='set MRPATCHY_QT_PYTHON to a python with PySide6 for the Qt differential')
def test_split_command_matches_real_qt():
    rng = random.Random(1421)
    alphabet = ['a', 'b', ' ', '\t', '"', '"', ' ', '\x1c', ' ', '\n', '\u0085', '/']
    cases = [''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 14))) for _ in range(3000)]
    script = ('import json,sys\nfrom PySide6.QtCore import QProcess\n'
              'print(json.dumps([QProcess.splitCommand(c) for c in json.load(sys.stdin)]))')
    out = subprocess.run([QT_PYTHON, '-I', '-c', script], input=json.dumps(cases), capture_output=True, text=True,
                         check=True, timeout=120)
    qt = json.loads(out.stdout)
    mismatches = [(c, q, sd.split_command(c)) for c, q in zip(cases, qt) if q != sd.split_command(c)]
    assert not mismatches, mismatches[:5]


def test_unobserved_main_config_is_recorded_and_blocking():
    sources = {SYS: {'state': 'absent'}, ETC: {'state': 'absent'}}
    result = sd.assess(sources, family='debian', sddm_installed=True, exec_start=['/usr/bin/sddm'])
    assert result['loaded'][-1] == {'path': MAIN, 'kind': 'file', 'state': 'not_observed'}
    assert 'config_not_observed' in _codes(result) and not result['complete']


def test_bracketed_line_with_equals_is_an_assignment_not_a_section():
    result = _run({f'{ETC}/a.conf': '[X11]\n[a=b]\nDisplayCommand=/kept/in/x11\n'})
    assert _cmd(result, 'X11.DisplayCommand')['argv'] == ('/kept/in/x11',)
