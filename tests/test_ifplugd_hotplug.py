import os
import random
import shutil
import subprocess

import pytest

from app import ifplugd_hotplug as ih


def _obs(text=None, interfaces=('eth0',), state=None, executable=True):
    config = {'state': state or ('regular' if text is not None else 'absent')}
    if text is not None:
        config['text'] = text
    return {'config': config, 'daemon_executable': executable,
            'interfaces': None if interfaces is None else list(interfaces)}


def _codes(result):
    return [gap['code'] for gap in result['gaps']]


def _starts(result):
    return {item['interface']: item['add']['args'] for item in result['hotplug']}


def test_hotplug_interface_gets_a_root_daemon_on_add_and_a_kill_on_remove():
    text = 'INTERFACES="eth0"\nHOTPLUG_INTERFACES="wlan0"\nARGS="-q -f"\n'
    result = ih.resolve(_obs(text, ['eth0', 'wlan0', 'lo']))
    assert result['complete'] and result['config_sourced_as_root']
    assert result['hotplug'] == [{
        'interface': 'wlan0', 'matched': 'name', 'daemon': '/usr/sbin/ifplugd',
        'add': {'args': '-q -f', 'args_source': 'ARGS'},
        'remove': {'argv': ['-k', '-i', 'wlan0']},
    }]
    assert result['skipped'] == [{'interface': 'eth0', 'reason': 'statically_managed'},
                                 {'interface': 'lo', 'reason': 'not_hotplug'}]


def test_hotplug_all_has_no_eth_or_wlan_filter_and_static_all_wins():
    names = ['docker0', 'eth0', 'lo', 'veth1a2b']
    result = ih.resolve(_obs('HOTPLUG_INTERFACES=all\n', names))
    assert [item['interface'] for item in result['hotplug']] == names
    assert {item['matched'] for item in result['hotplug']} == {'all'}
    result = ih.resolve(_obs('INTERFACES=all\nHOTPLUG_INTERFACES=all\n', names))
    assert result['hotplug'] == [] and {s['reason'] for s in result['skipped']} == {
        'statically_managed'}


def test_static_auto_does_not_claim_interfaces_in_the_agent():
    result = ih.resolve(_obs('INTERFACES=auto\nHOTPLUG_INTERFACES="eth0"\n', ['eth0']))
    assert _starts(result) == {'eth0': ''}


def test_per_interface_args_replace_only_the_first_dash_and_fall_back_when_empty():
    text = ("HOTPLUG_INTERFACES='br-lan eth-2 wlan0'\nARGS=-q\n"
            "ARGS_br_lan='-f   -u0'\nARGS_eth_2=-w\nARGS_wlan0=''\n")
    result = ih.resolve(_obs(text, ['br-lan', 'eth-2', 'wlan0']))
    assert _starts(result) == {'br-lan': '-f -u0', 'eth-2': '-w', 'wlan0': '-q'}
    assert [item['add']['args_source'] for item in result['hotplug']] == [
        'ARGS_br_lan', 'ARGS_eth_2', 'ARGS']


@pytest.mark.parametrize('observation, reason', [
    (_obs('HOTPLUG_INTERFACES=all\n', executable=False), 'daemon_not_executable'),
    (_obs(None), 'config_not_regular_file'),
    (_obs(None, state='other'), 'config_not_regular_file'),
])
def test_agent_exits_before_the_config_without_a_daemon_or_regular_config(observation, reason):
    result = ih.resolve(observation)
    assert result['complete'] and result['exits_before_config'] == reason
    assert result['hotplug'] == [] and not result['config_sourced_as_root']


def test_unobserved_inputs_are_gaps_not_empty_results():
    assert _codes(ih.resolve(_obs(None, state='unknown'))) == ['config_unobserved']
    result = ih.resolve(_obs('HOTPLUG_INTERFACES=all\n', None))
    assert _codes(result) == ['interfaces_unobserved'] and not result['complete']
    result = ih.resolve(_obs('HOTPLUG_INTERFACES=eth0\n', executable=None))
    assert _codes(result) == ['daemon_executable_unobserved']
    assert _starts(result) == {'eth0': ''}


def test_config_overrides_of_daemon_udev_environment_and_shell_are_gaps():
    text = 'DAEMON=/tmp/x\nINTERFACE=eth0\nACTION=add\nPATH=/tmp\nHOTPLUG_INTERFACES=eth0\n'
    result = ih.resolve(_obs(text))
    assert _codes(result) == ['config_changes_shell_environment',
                              'config_overrides_udev_environment',
                              'config_overrides_udev_environment', 'daemon_overridden']
    assert result['hotplug'][0]['daemon'] == '/tmp/x'
    # IFPLUGD is the init script's variable; the agent ignores it.
    assert ih.resolve(_obs('IFPLUGD=/tmp/x\nHOTPLUG_INTERFACES=eth0\n'))['complete']


@pytest.mark.parametrize('line', ['export ARGS=-q', 'ARGS=$(id)', 'ARGS=`id`', 'f() { :; }',
                                  'ARGS="a$b"', '. /tmp/evil'])
def test_non_simple_config_lines_are_blocking_gaps(line):
    result = ih.resolve(_obs('HOTPLUG_INTERFACES=eth0\n' + line + '\n'))
    assert 'config_not_simple_assignment' in _codes(result) and not result['complete']


@pytest.mark.parametrize('text, names, code', [
    ('HOTPLUG_INTERFACES="eth*"\n', ['eth0'], 'interface_word_not_modelled'),
    ('INTERFACES="[e]th0"\n', ['eth0'], 'interface_word_not_modelled'),
    ('HOTPLUG_INTERFACES=all\n', ['e*'], 'interface_word_not_modelled'),
    ('HOTPLUG_INTERFACES=all\n', ['a\\b'], 'interface_word_not_modelled'),
    ('HOTPLUG_INTERFACES=all\n', ['-n'], 'interface_word_not_modelled'),
    ('HOTPLUG_INTERFACES=all\n', ['br-x-y'], 'interface_name_evaluated'),
    ('HOTPLUG_INTERFACES=all\n', ['eth.1'], 'interface_name_evaluated'),
    ("HOTPLUG_INTERFACES=all\nARGS_eth0='-q *'\n", ['eth0'], 'args_not_modelled'),
    ("HOTPLUG_INTERFACES=all\nARGS_eth0='-n -q'\n", ['eth0'], 'args_not_modelled'),
])
def test_words_dash_would_reinterpret_are_gaps(text, names, code):
    result = ih.resolve(_obs(text, names))
    assert code in _codes(result) and not result['complete']


@pytest.mark.parametrize('observation', [
    None, [], {'config': {'state': 'regular'}},
    {'config': {'state': 'nope'}},
    {'config': {'state': 'absent'}, 'daemon_executable': 'yes'},
    _obs('', ['eth0', 'eth0']), _obs('', ['a/b']), _obs('', ['a b']), _obs('', ['a:1']),
    _obs('', ['']), _obs('', ['.']), _obs('', ['x' * 16]),
    {'config': {'state': 'absent'}, 'interfaces': 'eth0'},
    _obs('', [1]), _obs('', ['eth0'] * (ih.MAX_INTERFACES + 1)),
    _obs('x' * 70000),
])
def test_malformed_observations_are_invalid(observation):
    with pytest.raises(ih.Invalid):
        ih.resolve(observation)


def test_results_never_authorize_and_list_what_is_not_modelled():
    result = ih.resolve(_obs('HOTPLUG_INTERFACES=all\n'))
    assert 'inherited_udev_environment' in result['not_modelled']
    assert not any('authoriz' in key for key in result)


# --- Differential against the shipped udev agent under real dash -----------------

AGENT_SCRIPT = os.environ.get('IFPLUGD_AGENT_SCRIPT', '')
_NAMES = ['eth0', 'eth1', 'wlan0', 'lo', 'br-lan', 'eth-2', 'veth9', 'docker0']
_ARGS = ['-q', '-f', '-u0', '-d10', '-w', '-I']


def _random_case(rng):
    def words():
        pool = _NAMES + ['all', 'auto', 'nope']
        return ' '.join(rng.sample(pool, rng.choice([0, 0, 1, 2, 3])))

    lines = [f'INTERFACES="{words()}"', f"HOTPLUG_INTERFACES='{words()}'",
             'ARGS="' + ' '.join(rng.sample(_ARGS, rng.randint(0, 3))) + '"']
    for name in ['eth0', 'wlan0', 'br_lan', 'eth_2', 'lo']:
        if rng.random() < 0.4:
            lines.append(f"ARGS_{name}='" + '  '.join(rng.sample(_ARGS + [''], 2)) + "'")
    if rng.random() < 0.2:
        lines.append('# comment')
    names = rng.sample(_NAMES, rng.randint(1, 5))
    return '\n'.join(lines) + '\n', names


def _run_dash(tmp, text, name, action):
    root = tmp / 'root'
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir()
    (root / 'cfg').write_text(text)
    log = root / 'log'
    daemon = root / 'ifplugd'
    daemon.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> {log}\n')
    daemon.chmod(0o755)
    with open(AGENT_SCRIPT) as handle:
        script = handle.read()
    script = (script.replace('DAEMON=/usr/sbin/$DAEMON_NAME', f'DAEMON={daemon}')
              .replace('CFG=/etc/default/$DAEMON_NAME', f'CFG={root}/cfg')
              .replace('/sys/class/net', str(root / 'net'))
              .replace('logger ', ': ')
              .replace('ifplugd_daemon &', 'ifplugd_daemon'))
    (root / 'agent').write_text(script)
    subprocess.run(['dash', str(root / 'agent')], cwd='/', check=True, capture_output=True,
                   env={'PATH': '/usr/bin:/bin', 'INTERFACE': name, 'ACTION': action},
                   timeout=10)
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.skipif(not (AGENT_SCRIPT and shutil.which('dash') and os.geteuid() == 0),
                    reason='needs the shipped udev agent, dash and root')
def test_differential_against_dash_running_the_shipped_udev_agent(tmp_path):
    rng = random.Random(13773)
    compared = started = 0
    for _ in range(300):
        text, names = _random_case(rng)
        result = ih.resolve(_obs(text, names))
        if not result['complete']:
            continue
        by_name = {item['interface']: item for item in result['hotplug']}
        for name in names:
            item = by_name.get(name)
            add = [' '.join(f"-i {name} {item['add']['args']}".split())] if item else []
            remove = [' '.join(item['remove']['argv'])] if item else []
            assert _run_dash(tmp_path, text, name, 'add') == add, (text, name)
            assert _run_dash(tmp_path, text, name, 'remove') == remove, (text, name)
            assert _run_dash(tmp_path, text, name, 'change') == [], (text, name)
            compared += 1
            started += bool(item)
    assert compared > 300 and started > 100
