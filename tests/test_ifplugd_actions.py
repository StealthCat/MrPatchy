import copy
import os
import random
import shutil
import subprocess

import pytest

from app import ifplugd_actions as ia

STOCK = {
    'interface': 'eth0',
    'args': {'state': 'known', 'value': '-q -f -u0 -d10 -w -I'},
    'run_targets': {ia.DEFAULT_RUN: {'state': 'present', 'kind': 'regular', 'executable': True,
                                     'sha256': ia.SHIPPED_SHA256[ia.DEFAULT_RUN]}},
    'action_d': {'state': 'listed', 'entries': [
        {'name': 'ifupdown', 'kind': 'regular', 'executable': True,
         'sha256': ia.SHIPPED_SHA256[ia.IFUPDOWN_ACTION]},
    ]},
}


def obs(**changes):
    value = copy.deepcopy(STOCK)
    value.update(changes)
    return value


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def test_stock_install_runs_ifupdown_via_run_parts():
    result = ia.resolve(obs())
    assert result['covered'] is True and result['gaps'] == []
    daemon = result['daemon']
    assert daemon['argv'] == [ia.DAEMON, '-i', 'eth0', '-q', '-f', '-u0', '-d10', '-w', '-I']
    assert daemon['starts'] and daemon['run_state'] == 'stock_action'
    # Debian's default ARGS contains -q: no action on daemon shutdown.
    assert daemon['runs_on_startup'] == 'up' and daemon['runs_on_shutdown'] is None
    up = result['events']['up']
    assert up['argv'] == [ia.DEFAULT_RUN, 'eth0', 'up'] and up['account'] == 'root'
    [program] = up['run_parts']['programs']
    assert program['argv'] == [ia.IFUPDOWN_ACTION, 'eth0', 'up'] and program['shipped']
    assert program['runs'] == [{'argv': ['/sbin/ifup', 'eth0'], 'account': 'root'}]
    down = result['events']['down']['run_parts']['programs'][0]
    assert down['runs'] == [{'argv': ['/sbin/ifdown', 'eth0'], 'account': 'root'}]


def test_run_parts_selection_and_reverse_order_for_down():
    entries = [
        {'name': 'b-second', 'kind': 'regular', 'executable': True},
        {'name': 'a_first', 'kind': 'regular', 'executable': True},
        {'name': 'c.sh', 'kind': 'regular', 'executable': True},
        {'name': 'd~', 'kind': 'regular', 'executable': True},
        {'name': 'e', 'kind': 'regular', 'executable': False},
        {'name': 'f', 'kind': 'directory', 'executable': True},
        {'name': 'g', 'kind': 'broken_symlink'},
        {'name': 'h', 'kind': 'other', 'executable': True},
    ]
    result = ia.resolve(obs(action_d={'state': 'listed', 'entries': entries}))
    assert result['covered'] is True
    up = result['events']['up']['run_parts']
    assert [p['path'].rsplit('/', 1)[1] for p in up['programs']] == ['a_first', 'b-second']
    assert all(not p['shipped'] for p in up['programs'])
    assert {s['name']: s['reason'] for s in up['skipped']} == {
        'c.sh': 'name_not_matched', 'd~': 'name_not_matched', 'e': 'not_executable',
        'f': 'directory', 'g': 'stat_failed', 'h': 'not_regular_file'}
    down = result['events']['down']['run_parts']['programs']
    assert [p['argv'][1:] for p in down] == [['eth0', 'down'], ['eth0', 'down']]
    assert [p['path'].rsplit('/', 1)[1] for p in down] == ['b-second', 'a_first']


def test_locale_dependent_order_is_a_gap():
    entries = [{'name': 'B', 'kind': 'regular', 'executable': True},
               {'name': 'a', 'kind': 'regular', 'executable': True}]
    result = ia.resolve(obs(action_d={'state': 'listed', 'entries': entries}))
    assert 'order_locale_dependent' in codes(result) and result['covered'] is False
    assert result['events']['up']['run_parts']['order'] == 'unresolved'
    entries = [{'name': 'a-b', 'kind': 'regular', 'executable': True},
               {'name': 'ab', 'kind': 'regular', 'executable': True}]
    assert 'order_locale_dependent' in codes(ia.resolve(obs(action_d={'state': 'listed', 'entries': entries})))


def test_missing_action_d_runs_nothing_and_unknown_is_gap():
    result = ia.resolve(obs(action_d={'state': 'absent'}))
    assert result['covered'] and result['events']['up']['run_parts']['state'] == 'directory_missing'
    result = ia.resolve(obs(action_d={'state': 'unknown'}))
    assert 'action_d_unobserved' in codes(result) and not result['covered']
    result = ia.resolve(obs(action_d={'state': 'listed', 'entries': [], 'complete': False}))
    assert 'action_d_incomplete' in codes(result)
    entry = {'name': 'x', 'kind': 'unknown'}
    result = ia.resolve(obs(action_d={'state': 'listed', 'entries': [entry]}))
    assert 'action_entry_unobserved' in codes(result)
    assert result['events']['up']['run_parts']['programs'] == [{'path': ia.ACTION_D + '/x', 'certain': False}]


def test_args_override_run_target_and_extra_arg():
    custom = '/usr/local/sbin/evil'
    result = ia.resolve(obs(args={'state': 'known', 'value': '-r /tmp/x --run=' + custom + ' -x tail'},
                            run_targets={custom: {'state': 'present', 'kind': 'regular',
                                                  'executable': True, 'sha256': '0' * 64}}))
    assert result['daemon']['run'] == custom and result['daemon']['run_state'] == 'custom_program'
    assert result['events']['up']['argv'] == [custom, 'eth0', 'up', 'tail']
    assert 'run_parts' not in result['events']['up']
    assert codes(result) == ['run_target_not_modelled'] and not result['covered']


def test_modified_stock_path_is_not_stock():
    targets = {ia.DEFAULT_RUN: {'state': 'present', 'kind': 'regular', 'executable': True, 'sha256': 'a' * 64}}
    result = ia.resolve(obs(run_targets=targets))
    assert result['daemon']['run_state'] == 'custom_program'
    assert 'run_target_not_modelled' in codes(result)


def test_run_target_exec_failures_and_unobserved():
    for target in ({'state': 'absent'},
                   {'state': 'present', 'kind': 'regular', 'executable': False},
                   {'state': 'present', 'kind': 'directory', 'executable': True},
                   {'state': 'present', 'kind': 'broken_symlink'}):
        result = ia.resolve(obs(run_targets={ia.DEFAULT_RUN: target}))
        assert result['daemon']['run_state'] == 'exec_fails' and result['covered']
        assert result['events'] == {}
    result = ia.resolve(obs(run_targets={}))
    assert codes(result) == ['run_target_unobserved'] and not result['covered']


def test_interface_override_and_toggles():
    result = ia.resolve(obs(args={'state': 'known', 'value': '-i wlan0 -q -q -p -l'}))
    daemon = result['daemon']
    assert daemon['interface'] == 'wlan0' and daemon['interface_overridden']
    assert daemon['runs_on_shutdown'] == 'down' and daemon['runs_on_startup'] == 'up_or_down'
    assert result['events']['up']['argv'] == [ia.DEFAULT_RUN, 'wlan0', 'up']


@pytest.mark.parametrize('value,reason', [
    ('-k', 'kill'), ('-c', 'check_running'), ('--hel', 'help'), ('-v', 'version'),
    ('-S', 'suspend'), ('-R', 'resume'), ('-z', 'info'), ('-y', 'unknown_option'),
    ('-mx', 'unknown_api_mode'), ('--api-mode=', 'unknown_api_mode'), ('--no-s', 'ambiguous_option'),
    ('--bogus', 'unknown_option'), ('--help=1', 'unexpected_argument'), ('-r', 'missing_argument'),
    ('--run', 'missing_argument'), ('-k -y', 'unknown_option'),
])
def test_modes_that_start_no_daemon(value, reason):
    result = ia.resolve(obs(args={'state': 'known', 'value': value}))
    assert result['daemon']['starts'] is False and result['daemon']['exit_reason'] == reason
    assert result['events'] == {}


def test_end_of_options_and_permuted_operands():
    result = ia.resolve(obs(args={'state': 'known', 'value': 'stray -x one -- -r /tmp/evil'}))
    assert result['daemon']['run'] == ia.DEFAULT_RUN and result['daemon']['extra_arg'] == 'one'
    result = ia.resolve(obs(args={'state': 'known', 'value': '-ma -I'}))
    assert result['daemon']['starts']


def test_glob_words_and_unknown_args_are_gaps():
    result = ia.resolve(obs(args={'state': 'known', 'value': '-r /tmp/*'}))
    assert 'args_pathname_expansion' in codes(result) and not result['covered']
    result = ia.resolve(obs(args={'state': 'unknown'}))
    assert codes(result) == ['args_unobserved'] and result['daemon'] is None


@pytest.mark.parametrize('bad', [
    None, {'interface': 'a/b', 'args': {'state': 'known', 'value': ''}},
    {'interface': 'eth0', 'args': {'state': 'maybe'}},
    {'interface': 'eth0', 'args': {'state': 'known', 'value': 'x' * (ia.MAX_ARGS + 1)}},
    {'interface': 'eth0', 'args': {'state': 'known', 'value': ''}, 'action_d': {'state': 'listed',
     'entries': [{'name': 'a', 'kind': 'regular'}, {'name': 'a', 'kind': 'regular'}]}},
    {'interface': 'eth0', 'args': {'state': 'known', 'value': ''}, 'run_targets': {'rel': {'state': 'absent'}}},
])
def test_invalid_observations_raise(bad):
    with pytest.raises(ia.Invalid):
        ia.resolve(bad)


@pytest.mark.skipif(shutil.which('run-parts') is None, reason='run-parts not installed')
def test_run_parts_selection_matches_real_binary(tmp_path):
    rng = random.Random(1377)
    alphabet = 'abAB09_-.~'
    for trial in range(40):
        directory = tmp_path / f't{trial}'
        directory.mkdir()
        entries = []
        names = {''.join(rng.choice(alphabet) for _ in range(rng.randint(1, 4))) for _ in range(8)}
        for name in sorted(names - {'.', '..'}):
            kind = rng.choice(['exec', 'plain', 'dir', 'broken'])
            path = directory / name
            if kind == 'exec':
                path.write_text('#!/bin/sh\n')
                path.chmod(0o755)
                entries.append({'name': name, 'kind': 'regular', 'executable': True})
            elif kind == 'plain':
                path.write_text('')
                path.chmod(0o644)
                entries.append({'name': name, 'kind': 'regular', 'executable': False})
            elif kind == 'dir':
                path.mkdir()
                entries.append({'name': name, 'kind': 'directory', 'executable': True})
            else:
                path.symlink_to(directory / 'missing-target')
                entries.append({'name': name, 'kind': 'broken_symlink'})
        expected = subprocess.run(['run-parts', '--test', str(directory)], env={'LC_ALL': 'C', 'PATH': os.environ['PATH']},
                                  capture_output=True, text=True, check=False).stdout.split()
        result = ia._run_parts({'state': 'listed', 'entries': entries, 'complete': True}, 'eth0', 'up', [])
        got = [str(directory / program['path'].rsplit('/', 1)[1]) for program in result['programs']]
        assert got == expected, (trial, entries)


GETOPT_C = r'''
#include <getopt.h>
#include <stdio.h>
int main(int argc, char **argv) {
  static struct option o[] = {
    {"no-auto",0,0,'a'},{"no-daemon",0,0,'n'},{"no-syslog",0,0,'s'},{"no-beep",0,0,'b'},
    {"no-beep-up",0,0,'U'},{"no-beep-down",0,0,'D'},{"ignore-fail",0,0,'f'},
    {"ignore-fail-positive",0,0,'F'},{"ignore-retval",0,0,'I'},{"iface",1,0,'i'},{"run",1,0,'r'},
    {"poll-time",1,0,'t'},{"poll-utime",1,0,'T'},{"delay-up",1,0,'u'},{"delay-down",1,0,'d'},
    {"api-mode",1,0,'m'},{"wait-on-fork",0,0,'w'},{"wait-on-kill",0,0,'W'},{"no-startup",0,0,'p'},
    {"no-shutdown",0,0,'q'},{"help",0,0,'h'},{"kill",0,0,'k'},{"check-running",0,0,'c'},
    {"version",0,0,'v'},{"extra-arg",1,0,'x'},{"suspend",0,0,'S'},{"resume",0,0,'R'},{"info",0,0,'z'},
    {"initial-down",0,0,'l'},{"monitor",0,0,'M'},{0,0,0,0}};
  int c, i;
  opterr = 0;
  while ((c = getopt_long(argc, argv, "asni:r:t:T:u:d:hkbUDfFvm:pqwx:cISRzlMW", o, &i)) >= 0) {
    if (c == '?' || c == ':') { printf("ERR\n"); return 0; }
    printf("%c\t%s\n", c, optarg ? optarg : "");
  }
  printf("END\n");
  return 0;
}
'''


@pytest.mark.skipif(shutil.which('cc') is None, reason='no C compiler')
def test_getopt_model_matches_glibc(tmp_path):
    source = tmp_path / 'g.c'
    source.write_text(GETOPT_C)
    binary = tmp_path / 'g'
    subprocess.run(['cc', '-o', str(binary), str(source)], check=True)
    rng = random.Random(1377)
    pool = ['-i', 'wlan0', '-r', '/x', '--run', '--run=/y', '--ru=/z', '--r', '-x', '-xq', '-qp', '-mE',
            '-m', '', '--', 'stray', '-', '--no-s', '--no-sta', '--no-beep', '--no-beep-u', '--help=1',
            '-k', '-y', '--iface=eth9', '-ri', '-qx', '--api', 'w', '-:', '--version', '--kil']
    for _ in range(3000):
        words = [rng.choice(pool) for _ in range(rng.randint(0, 6))]
        lines = subprocess.run([str(binary), *words], capture_output=True, text=True,
                               env={}, check=True).stdout.splitlines()
        model = ia.parse_options(words)
        failed = lines[-1] == 'ERR'
        seen = {line.split('\t', 1)[0]: line.split('\t', 1)[1] for line in lines[:-1]}
        # parse_args exits on an invalid -m before later options are read.
        mode = [line.split('\t', 1)[1] for line in lines[:-1] if line.startswith('m\t')]
        bad_mode = next((m for m in mode if not m or m[0].lower() not in 'emwpai'), None)
        if bad_mode is not None:
            index = next(i for i, line in enumerate(lines) if line == 'm\t' + bad_mode)
            seen = {line.split('\t', 1)[0]: line.split('\t', 1)[1] for line in lines[:index]}
            assert model['exit'] == 'unknown_api_mode', words
            failed = False
        elif failed:
            assert model['exit'] in ('unknown_option', 'ambiguous_option', 'missing_argument',
                                     'unexpected_argument'), words
        else:
            assert model['exit'] in (None, 'help', 'kill', 'resume', 'suspend', 'info', 'version',
                                     'check_running'), words
        if bad_mode is None and not failed:
            assert model['interface'] == seen.get('i', 'eth0'), words
            assert model['run'] == seen.get('r', ia.DEFAULT_RUN), words
            assert model['extra_arg'] == seen.get('x'), words
