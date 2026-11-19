"""Pure DNF post-transaction-actions contract (#1101)."""
import glob
import os
import random

import pytest

from app import dnf_actions as da

DIR = da.DEFAULT_ACTIONDIR


def entry(name, content, kind='file'):
    return {'name': name, 'type': kind, 'content': content}


def resolve(*files, conf=None, dnf=None, installed=True):
    return da.resolve(list(files), {'present': False} if conf is None else conf,
                      {'present': False} if dnf is None else dnf, plugin_installed=installed)


def present(text):
    return {'present': True, 'content': text}


def codes(result):
    return [g['code'] for g in result['gaps']]


def test_default_installation_runs_actions_with_metadata_substitution():
    result = resolve(entry('log.action', '# comment\n*:any:echo ${state} $name >> /var/log/x\n'))
    assert result['plugin'] == {'name': 'post-transaction-actions', 'state': 'enabled', 'reason': 'enabled',
                                'installed': True, 'actiondir': DIR}
    assert result['complete'] is True
    [action] = result['actions']
    assert action['path'] == DIR + 'log.action' and action['line'] == 2
    assert (action['package_filter'], action['state']) == ('*', 'any')
    assert action['command']['value'] == 'echo ${state} $name >> /var/log/x'
    assert len(action['command']['sha256']) == 64
    assert action['substitutes'] == ['state', 'name']
    assert action['package_metadata_in_shell'] is True
    assert action['runs'] is True and action['origin'] == 'not_assessed'
    assert {'cli_options_unobserved', 'dnf5_actions_not_modelled',
            'execution_order_transaction_dependent'} <= set(codes(result))
    assert result['file_order'] == 'directory_order_unspecified'
    assert 'not a safety verdict' in result['not_a_verdict']


def test_line_splitting_matches_plugin():
    text = ('  kernel*:in:/usr/local/bin/x a:b:c  \n'   # split(':', 2) keeps later colons in the command
            '\t# indented comment\n'
            'no-colon-line\n'                         # fewer than two colons: logged and skipped
            'pkg:IN:cmd\n'                            # state is case-sensitive
            'pkg: in:cmd\n'                           # parts are not stripped individually
            'pkg:out:\n'                              # empty command still parses
            '/usr/bin/foo:any:run $names ${repoid:-x}\r\n'
            'a:in:one\rb:out:two\n'                   # universal newlines split a lone \r
            ';semi:in:not a comment\n'                 # only '#' starts a comment
            'c:in:x\x0cd:out:y\u2028z\n')              # readlines() does not split on \f or U+2028
    actions, rejected = da.parse_action_file(text)
    assert [(a['line'], a['package_filter'], a['state'], a['command']['value']) for a in actions] == [
        (1, 'kernel*', 'in', '/usr/local/bin/x a:b:c'),
        (6, 'pkg', 'out', ''),
        (7, '/usr/bin/foo', 'any', 'run $names ${repoid:-x}'),
        (8, 'a', 'in', 'one'),
        (9, 'b', 'out', 'two'),
        (10, ';semi', 'in', 'not a comment'),
        (11, 'c', 'in', 'x\x0cd:out:y\u2028z'),
    ]
    assert actions[2]['substitutes'] == ['repoid']  # $names is not a known variable
    assert [(r['line'], r['reason']) for r in rejected] == [
        (3, 'bad_action_line'), (4, 'bad_transaction_state'), (5, 'bad_transaction_state')]


@pytest.mark.parametrize('name,state', [
    ('a.action', 'parsed'),
    ('.hidden.action', 'ignored'),
    ('.action', 'ignored'),
    ('a.action.rpmsave', 'ignored'),
    ('a.ACTION', 'ignored'),
    ('README', 'ignored'),
])
def test_file_eligibility(name, state):
    [record] = resolve(entry(name, 'x:in:y\n'))['files']
    assert record['state'] == state


def test_non_regular_unreadable_and_nul_entries_are_blocking():
    result = resolve(entry('dir.action', None, 'directory'), entry('u.action', None),
                     entry('n.action', 'a:in:b\x00\n'), entry('ok.action', 'a:in:b\n'))
    assert result['complete'] is False
    assert {'action_entry_not_regular', 'action_file_unreadable', 'action_file_nul'} <= set(codes(result))
    assert [a['path'] for a in result['actions']] == [DIR + 'ok.action']


def test_oversized_file_is_blocking():
    result = resolve(entry('big.action', 'a:in:b\n' * (da.MAX_FILE_BYTES // 7 + 1)))
    assert 'action_file_too_large' in codes(result) and result['actions'] == []


@pytest.mark.parametrize('conf,state,reason', [
    ('[main]\nenabled = 0\n', 'disabled', 'plugin_conf_disabled'),
    ('[main]\nenabled=OFF\n', 'disabled', 'plugin_conf_disabled'),
    ('[main]\nenabled = "no"\n', 'disabled', 'plugin_conf_disabled'),   # outer quotes are trimmed
    ('[main]\nenabled = 0\nenabled = 1\n', 'enabled', 'enabled'),       # the last value wins
    ('[main]\nEnabled = 0\n', 'enabled', 'enabled'),                    # keys are case-sensitive
    ('[Main]\nenabled = 0\n', 'enabled', 'enabled'),                    # sections too
    ('[other]\nenabled = 0\n', 'enabled', 'enabled'),
    ('[main]\nenabled = 0\n  1\n', 'config_error', 'plugin_conf_invalid_enabled'),  # continuation joins
    ('[main]\nenabled = maybe\n', 'config_error', 'plugin_conf_invalid_enabled'),
    ('enabled = 0\n', 'config_error', 'plugin_conf_parse_error'),       # missing section header
    ('[main]\nenabled\n', 'config_error', 'plugin_conf_parse_error'),   # missing '='
    ('[main\n', 'config_error', 'plugin_conf_parse_error'),
    ('[main] xy\n', 'config_error', 'plugin_conf_parse_error'),
    ('[main]x\nenabled=0\n', 'disabled', 'plugin_conf_disabled'),     # libdnf skips the last character
    ('[main] x\nenabled=0\n', 'disabled', 'plugin_conf_disabled'),
    ('[main]  xy \n', 'config_error', 'plugin_conf_parse_error'),
    ('[main] ; ok\n# c\n;c\nenabled=1\n', 'enabled', 'enabled'),
    ('﻿[main]\nenabled=false\n', 'disabled', 'plugin_conf_disabled'),
])
def test_plugin_conf_enablement(conf, state, reason):
    result = resolve(entry('a.action', 'a:in:b\n'), conf=present(conf))
    assert (result['plugin']['state'], result['plugin']['reason']) == (state, reason)
    assert result['actions'][0]['runs'] is (state == 'enabled')


@pytest.mark.parametrize('text,sections', [
    ('[main]x\na=1\n', {'main': {'a': '1'}}),
    ('[main] x\na=1\n', {'main': {'a': '1'}}),
    ('[;=]a\nb=2\n', {';=': {'b': '2'}}),
    ('[main]x \t\r\na=1\n', {'main': {'a': '1'}}),
])
def test_single_trailing_character_after_section_is_accepted_like_libdnf(text, sections):
    assert da.parse_ini(text) == sections


@pytest.mark.parametrize('text', ['[main] xy\n', '[main]xy\n', '[main] x y\n'])
def test_text_after_section_is_still_rejected(text):
    with pytest.raises(da._IniError):
        da.parse_ini(text)


def test_single_trailing_character_in_dnf_conf_keeps_actions_running():
    result = resolve(entry('a.action', '*:in:/usr/bin/touch /tmp/pwn\n'), dnf=present('[main]x\ngpgcheck=1\n'))
    assert result['plugin']['state'] == 'enabled'
    assert result['actions'][0]['runs'] is True


def test_dnf_conf_global_switch_and_overrides():
    off = resolve(entry('a.action', 'a:in:b\n'), dnf=present('[main]\nplugins=False\n'))
    assert off['plugin']['state'] == 'disabled' and off['actions'][0]['runs'] is False
    assert off['complete'] is True
    override = resolve(entry('a.action', 'a:in:b\n'), dnf=present('[main]\npluginconfpath=/opt/p\n'))
    assert 'pluginconfpath_override' in codes(override) and override['complete'] is False
    broken = resolve(entry('a.action', 'a:in:b\n'), dnf=present('[main]\nplugins=sometimes\n'))
    assert broken['plugin']['state'] == 'config_error'


def test_actiondir_override_is_blocking_and_glob_is_concatenated():
    result = resolve(entry('a.action', 'a:in:b\n'), conf=present('[main]\nactiondir=/srv/hooks\n'))
    [gap] = [g for g in result['gaps'] if g['code'] == 'actiondir_override']
    assert gap['glob'] == '/srv/hooks*.action'
    assert result['actions'] == [] and result['complete'] is False


def test_missing_inputs_fail_closed():
    result = da.resolve(None)
    assert result['complete'] is False and result['plugin']['state'] == 'unknown'
    assert {'actions_dir_not_collected', 'plugin_conf_not_collected', 'dnf_conf_not_collected',
            'plugin_installation_unknown'} <= set(codes(result))
    unknown = resolve(entry('a.action', 'a:in:b\n'), installed=None)
    assert unknown['plugin']['state'] == 'unknown' and unknown['actions'][0]['runs'] is False
    dormant = resolve(entry('a.action', 'a:in:b\n'), installed=False)
    assert dormant['plugin']['state'] == 'not_installed' and dormant['complete'] is True
    assert dormant['actions'][0]['runs'] is False


def test_invalid_names_and_malformed_observations():
    result = da.resolve([{'name': '../x.action', 'type': 'file', 'content': 'a:in:b'}, 'junk'],
                        {'present': False}, {'present': False}, plugin_installed=True)
    assert codes(result).count('invalid_entry') == 2 and result['complete'] is False
    assert 'invalid_observation' in codes(da.resolve({}, {'present': False}, {'present': False},
                                                      plugin_installed=True))


def _reference(directory):
    """The plugin's own _parse_actions, run against a real directory."""
    tuples = []
    for file_name in glob.glob(directory + '*.action'):
        for line in open(file_name, encoding='utf-8').readlines():  # dnf runs in a UTF-8 locale
            line = line.strip()
            if line and line[0] != '#':
                try:
                    key, state, command = line.split(':', 2)
                except ValueError:
                    continue
                if state in ('in', 'out', 'any'):
                    tuples.append((os.path.basename(file_name), key, state, command))
    return sorted(tuples)


def test_randomized_agreement_with_plugin_parser(tmp_path):
    rng = random.Random(1101)
    atoms = ['a', '*', 'kern?l', ':', '::', ' ', '\t', '#', 'in', 'out', 'any', 'IN', '$name', '${arch}',
             '\r', '\r\n', '\n', '\x0c', '\u2028', ';', 'x y', '\'q\'']
    names = ['a.action', 'b.action', '.h.action', 'c.actions', 'd.action~', 'e', 'f.action']
    for trial in range(300):
        root = tmp_path / str(trial)
        root.mkdir()
        listing = []
        for name in rng.sample(names, rng.randint(1, len(names))):
            text = ''.join(rng.choice(atoms) for _ in range(rng.randint(0, 40)))
            (root / name).write_bytes(text.encode())
            listing.append(entry(name, text))
        expected = _reference(str(root) + '/')
        got = resolve(*listing)
        assert sorted((a['path'].rsplit('/', 1)[1], a['package_filter'], a['state'], a['command']['value'])
                      for a in got['actions']) == expected, trial
