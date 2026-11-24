import os
import random
import shutil
import subprocess

import pytest

from app import ifplugd_init as ii


def _entry(name, device=True, type_state='regular', type_text='1\n'):
    return {'name': name, 'device': device, 'type_state': type_state, 'type_text': type_text}


def _obs(text=None, entries=(), state=None):
    config = {'state': state or ('regular' if text is not None else 'absent')}
    if text is not None:
        config['text'] = text
    return {'config': config, 'interfaces': list(entries)}


def _codes(result):
    return [gap['code'] for gap in result['gaps']]


DEBCONF = (
    '# This file is maintained by debconf.\n'
    'INTERFACES="eth0 wlan0"\n'
    'HOTPLUG_INTERFACES=""\n'
    'ARGS="-q -f -u0 -d10 -w -I"\n'
    'SUSPEND_ACTION="stop"\n'
)


def test_debconf_style_config_starts_each_listed_interface_with_args():
    result = ii.resolve(_obs(DEBCONF, [_entry('eth0'), _entry('wlan0')]))
    assert result['complete'] and result['config_sourced_as_root']
    assert [(s['interface'], s['args'], s['args_source']) for s in result['starts']] == [
        ('eth0', '-q -f -u0 -d10 -w -I', 'ARGS'), ('wlan0', '-q -f -u0 -d10 -w -I', 'ARGS')]
    assert all(s['daemon'] == '/usr/sbin/ifplugd' for s in result['starts'])


def test_missing_config_or_empty_interfaces_starts_nothing():
    result = ii.resolve(_obs(None, [_entry('eth0')]))
    assert result['complete'] and not result['starts'] and not result['config_sourced_as_root']
    other = ii.resolve(_obs(None, [_entry('eth0')], state='other'))
    assert other['complete'] and not other['config_sourced_as_root']


def test_unobserved_config_is_a_gap():
    result = ii.resolve({'config': {'state': 'unknown'}, 'interfaces': []})
    assert not result['complete'] and _codes(result) == ['config_unobserved']


def test_per_interface_args_replace_only_the_first_dash_and_fall_back_when_empty():
    text = 'INTERFACES="br-lan-1 eth0"\nARGS=-q\nARGS_eth0=""\n'
    result = ii.resolve(_obs(text, [_entry('br-lan-1'), _entry('eth0')]))
    # br-lan-1 becomes ${ARGS_br_lan-1}, which dash parses as a default-value expansion.
    assert _codes(result) == ['interface_name_evaluated']
    assert [(s['interface'], s['args'], s['args_source']) for s in result['starts']] == [
        ('eth0', '-q', 'ARGS')]
    text = 'INTERFACES="br-lan eth0"\nARGS=-q\nARGS_br_lan="  -f   -w "\n'
    result = ii.resolve(_obs(text, [_entry('br-lan'), _entry('eth0')]))
    assert result['complete']
    assert [(s['interface'], s['args'], s['args_source']) for s in result['starts']] == [
        ('br-lan', '-f -w', 'ARGS_br_lan'), ('eth0', '-q', 'ARGS')]


def test_absent_interfaces_are_skipped_and_auto_selects_eth_and_wlan_with_device_and_type_1():
    text = 'INTERFACES=auto\nARGS="-q"\n'
    entries = [_entry('wlan0'), _entry('eth1', type_text='772\n'), _entry('eth0'),
               _entry('lo'), _entry('eth2', device=False), _entry('eth3', type_state='absent'),
               _entry('enp1s0'), _entry('.eth9')]
    result = ii.resolve(_obs(text, entries))
    assert result['complete'] and result['interfaces_mode'] == 'auto'
    assert [s['interface'] for s in result['starts']] == ['eth0', 'eth3', 'wlan0']
    listed = ii.resolve(_obs('INTERFACES="eth0 eth7"\n', [_entry('eth0')]))
    assert listed['skipped'] == [{'interface': 'eth7', 'reason': 'not_present'}]
    unknown = ii.resolve(_obs(text, [_entry('eth0', type_state='unknown')]))
    assert _codes(unknown) == ['interface_type_unknown'] and not unknown['starts']


@pytest.mark.parametrize('line', [
    'INTERFACES=$(reboot)', 'ARGS="-q $X"', 'ARGS=`id`', 'A=1 B=2', 'A=1; reboot',
    'reboot', 'f() { :; }', 'ARGS=~/x', 'ARGS="-q', 'ARGS=-q\r', 'ARGS=a\\', 'export ARGS=-q',
    'ARGS=-q#x',
])
def test_non_simple_config_lines_are_blocking_gaps(line):
    result = ii.resolve(_obs(line + '\n', [_entry('eth0')]))
    assert 'config_not_simple_assignment' in _codes(result) and not result['complete']


def test_comments_quotes_and_concatenation_are_understood():
    variables, gaps = ii.parse_config(
        "  # c\n\tA='x y'\"z\"w  # trailing\nB=\nC=a=b:c\nA=last\n")
    assert not gaps and variables == {'A': 'last', 'B': '', 'C': 'a=b:c'}


def test_daemon_override_and_shell_environment_changes_are_gaps():
    result = ii.resolve(_obs('IFPLUGD=/tmp/evil\nIFS=,\nPATH=/tmp\nINTERFACES=eth0\n',
                             [_entry('eth0')]))
    assert _codes(result) == ['config_changes_shell_environment',
                              'config_changes_shell_environment', 'daemon_overridden']
    assert result['starts'][0]['daemon'] == '/tmp/evil'


@pytest.mark.parametrize('interfaces,code', [
    ('"eth*"', 'interface_word_not_modelled'), ('"../x"', 'interface_word_not_modelled'),
    ('..', 'interface_word_not_modelled'), ('-n', 'interface_word_not_modelled'),
    ("'a\\b'", 'interface_word_not_modelled'), ('a.b', 'interface_name_evaluated'),
])
def test_interface_words_dash_would_reinterpret_are_gaps(interfaces, code):
    names = ['eth0', '-n', 'a\\b', 'a.b']
    result = ii.resolve(_obs(f'INTERFACES={interfaces}\n', [_entry(n) for n in names]))
    assert code in _codes(result) and not result['starts']


@pytest.mark.parametrize('value', ['"-q *"', "'-n -q'", "'-q \\t'"])
def test_args_values_echo_or_glob_would_change_are_gaps(value):
    result = ii.resolve(_obs(f'INTERFACES=eth0\nARGS_eth0={value}\n', [_entry('eth0')]))
    assert _codes(result) == ['args_not_modelled'] and not result['starts']


@pytest.mark.parametrize('value, reason', [
    ('"-f *"', 'pathname_expansion'), ("'-q -w?'", 'pathname_expansion'),
    ("'-q [ab]'", 'pathname_expansion'), ("'-q \\x'", 'unquoted_backslash')])
def test_plain_args_fallback_the_unquoted_daemon_line_would_change_is_a_gap(value, reason):
    # $IFPLUGD -i $IF $A leaves $A unquoted, so dash globs the ARGS fallback too.
    result = ii.resolve(_obs(f'INTERFACES=eth0\nARGS={value}\n', [_entry('eth0')]))
    assert result['gaps'] == [{'code': 'args_not_modelled', 'reason': reason,
                               'variable': 'ARGS', 'interface': 'eth0'}]
    assert not result['complete'] and not result['starts']


def test_glob_in_args_is_harmless_when_the_per_interface_args_win():
    result = ii.resolve(_obs("INTERFACES=eth0\nARGS='-f *'\nARGS_eth0=-q\n", [_entry('eth0')]))
    assert result['complete'] and result['starts'][0]['args'] == '-q'


@pytest.mark.parametrize('observation', [
    None, {}, {'config': {'state': 'regular'}}, {'config': {'state': 'bogus'}},
    {'config': {'state': 'absent'}, 'interfaces': [{'name': 'a/b', 'device': True,
                                                     'type_state': 'absent'}]},
    {'config': {'state': 'absent'}, 'interfaces': [_entry('a'), _entry('a')]},
    {'config': {'state': 'absent'}, 'interfaces': [{'name': 'a', 'device': 1,
                                                     'type_state': 'absent'}]},
    {'config': {'state': 'regular', 'text': 'x' * (ii.MAX_CONFIG_BYTES + 1)}},
])
def test_malformed_observations_are_invalid(observation):
    with pytest.raises(ii.Invalid):
        ii.resolve(observation)


def test_unobserved_interfaces_are_gaps_not_empty_results():
    result = ii.resolve({'config': {'state': 'regular', 'text': 'INTERFACES=auto\n'}})
    assert _codes(result) == ['interfaces_unobserved']
    result = ii.resolve({'config': {'state': 'regular', 'text': 'INTERFACES=eth0\n'}})
    assert _codes(result) == ['interfaces_unobserved']


# --- Differential against the shipped init script under real dash ---------------

INIT_SCRIPT = os.environ.get('IFPLUGD_INIT_SCRIPT', '')
_TOKENS = ['eth0', 'eth1', 'wlan0', 'br-lan', 'br-x-y', 'enp1', 'a.b', 'eth-2', '-q', '-f',
           '-u0', '-d10', '-w', '-I', '', 'x']


def _random_case(rng):
    names = rng.sample(['eth0', 'eth1', 'wlan0', 'br-lan', 'br-x-y', 'enp1', 'eth-2', 'lo', 'wlan1'],
                       rng.randint(0, 6))
    entries = []
    for name in names:
        state = rng.choice(['regular', 'absent', 'other'])
        entries.append(_entry(name, device=rng.random() < 0.8, type_state=state,
                              type_text=rng.choice(['1\n', '772\n', '2\n1\n', '1'])))
    lines = []
    if rng.random() < 0.5:
        lines.append('INTERFACES=' + rng.choice(['auto', 'all', '"auto "']))
    else:
        words = rng.sample(_TOKENS[:8] + ['nope'], rng.randint(0, 4))
        lines.append('INTERFACES="' + ' '.join(words) + '"')
    lines.append('ARGS="' + ' '.join(rng.sample(_TOKENS[8:], rng.randint(0, 3))) + '"')
    for name in ['eth0', 'wlan0', 'br_lan', 'eth_2', 'br_x']:
        if rng.random() < 0.4:
            lines.append(f"ARGS_{name}='" + '  '.join(rng.sample(_TOKENS[8:], 2)) + "'")
    if rng.random() < 0.2:
        lines.append('# comment')
    return '\n'.join(lines) + '\n', entries


def _run_dash(tmp, text, entries):
    root = tmp / 'root'
    shutil.rmtree(root, ignore_errors=True)
    net = root / 'net'
    net.mkdir(parents=True)
    for entry in entries:
        directory = net / entry['name']
        directory.mkdir()
        if entry['device']:
            (directory / 'device').mkdir()
        if entry['type_state'] == 'regular':
            (directory / 'type').write_text(entry['type_text'])
        elif entry['type_state'] == 'other':
            (directory / 'type').mkdir()
    (root / 'cfg').write_text(text)
    log = root / 'log'
    daemon = root / 'ifplugd'
    daemon.write_text('#!/bin/sh\nfor a; do [ "$a" = -c ] && exit 1; done\n'
                      f'printf "%s\\n" "$*" >> {log}\n')
    daemon.chmod(0o755)
    (root / 'lsb').write_text('log_action_begin_msg() { :; }\nlog_action_cont_msg() { :; }\n'
                              'log_action_end_msg() { :; }\n')
    with open(INIT_SCRIPT) as handle:
        script = handle.read()
    script = (script.replace('IFPLUGD=/usr/sbin/$DAEMON_NAME', f'IFPLUGD={daemon}')
              .replace('CFG=/etc/default/$DAEMON_NAME', f'CFG={root}/cfg')
              .replace('/sys/class/net', str(net))
              .replace('. /lib/lsb/init-functions', f'. {root}/lsb'))
    (root / 'init').write_text(script)
    subprocess.run(['dash', str(root / 'init'), 'start'], cwd='/', check=True,
                   env={'PATH': '/usr/bin:/bin'}, capture_output=True, timeout=10)
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.skipif(not (INIT_SCRIPT and shutil.which('dash') and os.geteuid() == 0),
                    reason='needs the shipped init script, dash and root')
def test_differential_against_dash_running_the_shipped_init_script(tmp_path):
    rng = random.Random(1377)
    compared = 0
    for _ in range(400):
        text, entries = _random_case(rng)
        result = ii.resolve(_obs(text, entries))
        if not result['complete']:
            continue
        expected = [' '.join(f"-i {s['interface']} {s['args']}".split()) for s in result['starts']]
        assert _run_dash(tmp_path, text, entries) == expected, (text, entries)
        compared += 1
    assert compared > 200
