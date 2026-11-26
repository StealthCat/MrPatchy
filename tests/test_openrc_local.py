import os
import shutil
import stat
import subprocess

import pytest

from app import openrc_local as ol

SCRIPT = {'type': 'file', 'mode': 0o755, 'noexec': False}


def _listing(*entries, **kw):
    return dict({'state': 'listed', 'entries': list(entries)}, **kw)


def _run(local_d=None, **kw):
    kw.setdefault('family', 'debian')
    kw.setdefault('init_system', 'openrc')
    kw.setdefault('runlevels', ['default'])
    kw.setdefault('conf_d', {'state': 'listed', 'names': []})
    kw.setdefault('shell', 'dash')
    if local_d is None:
        local_d = _listing(dict(SCRIPT, name='firewall.start'))
    return ol.assess(local_d, **kw)


def _outcomes(result, phase):
    return [(s['name'], s['outcome']) for s in result['phases'][phase]['scripts']]


def _codes(result):
    return {g['code'] for g in result['gaps']}


def test_start_and_stop_scripts_run_as_root_through_eval_in_byte_order():
    result = _run(_listing(
        dict(SCRIPT, name='b.start'), dict(SCRIPT, name='A.start'), dict(SCRIPT, name='10-net.start'),
        dict(SCRIPT, name='a.stop'), dict(SCRIPT, name='README'), dict(SCRIPT, name='x.start.bak'),
        dict(SCRIPT, name='y.START'),
    ))
    assert result['complete'] is True and result['gaps'] == []
    assert result['applicability'] == 'applicable'
    assert result['runs_as'] == 'root' and result['command'][0] == 'eval'
    assert result['stops_on_failure'] is False and result['service_fails_on_script_failure'] is False
    assert result['runs_at_boot'] is True and result['enabled_runlevels'] == ['default']
    assert result['order'] == 'byte' and result['origin'] == 'not_assessed'
    assert result['phases']['start']['run_order'] == ['/etc/local.d/10-net.start', '/etc/local.d/A.start',
                                                      '/etc/local.d/b.start']
    assert result['phases']['stop']['run_order'] == ['/etc/local.d/a.stop']
    assert result['phases']['start']['pattern'] == '/etc/local.d/*.start'
    assert result['phases']['stop']['legacy_function'] == 'local_stop'


@pytest.mark.parametrize('entry,outcome', [
    (dict(SCRIPT, name='.hidden.start'), 'hidden_name'),
    (dict(SCRIPT, name='.start'), 'hidden_name'),
    (dict(SCRIPT, name='plain.start', mode=0o644), 'not_executable'),
    (dict(SCRIPT, name='mounted.start', noexec=True), 'noexec_mount'),
    ({'name': 'dir.start', 'type': 'directory', 'mode': 0o755}, 'directory'),
    ({'name': 'fifo.start', 'type': 'other', 'mode': 0o755}, 'not_plain_file'),
    ({'name': 'dangling.start', 'type': 'symlink', 'target': None}, 'stat_failed'),
    ({'name': 'link.start', 'type': 'symlink', 'target': dict(SCRIPT)}, 'runs'),
    ({'name': 'link2.start', 'type': 'symlink', 'target': dict(SCRIPT, mode=0o644)}, 'not_executable'),
])
def test_entry_outcomes(entry, outcome):
    result = _run(_listing(entry))
    assert _outcomes(result, 'start') == [(entry['name'], outcome)]
    assert result['complete'] is True
    assert (result['phases']['start']['run_order'] != []) == (outcome == 'runs')


@pytest.mark.parametrize('name', ['a b.start', 'x;reboot.start', '$(id).start', 'a*.start', 'q?.start',
                                  'br{a,b}.start', 'tick`.start', "quo'te.start", 'nl\n.start'])
def test_shell_special_names_are_reinterpreted_and_block_completeness(name):
    result = _run(_listing(dict(SCRIPT, name=name)))
    assert _outcomes(result, 'start') == [(name, 'runs_as_shell_text')]
    assert 'shell_reinterpreted' in _codes(result) and result['complete'] is False


def test_missing_noexec_flag_runs_with_non_blocking_gap():
    result = _run(_listing({'name': 'a.start', 'type': 'file', 'mode': 0o700}))
    assert _outcomes(result, 'start') == [('a.start', 'runs')]
    assert _codes(result) == {'mount_flags_unobserved'} and result['complete'] is True


def test_missing_metadata_and_unobserved_symlink_are_blocking():
    result = _run(_listing({'name': 'a.start', 'type': 'file'}, {'name': 'b.start', 'type': 'symlink'}))
    assert _outcomes(result, 'start') == [('a.start', 'unresolved'), ('b.start', 'unresolved')]
    assert {'metadata_missing', 'symlink_target_unobserved'} <= _codes(result)
    assert result['complete'] is False


def test_not_enabled_in_any_runlevel_still_lists_scripts_but_not_at_boot():
    result = _run(runlevels=[])
    assert result['runs_at_boot'] is False and result['complete'] is True
    assert result['phases']['start']['run_order'] == ['/etc/local.d/firewall.start']


@pytest.mark.parametrize('kw,code', [
    ({'family': None}, 'family_not_observed'),
    ({'family': 'rpm'}, 'family_unsupported'),
    ({'init_system': None}, 'init_system_not_observed'),
    ({'init_system': 5}, 'input_malformed'),
    ({'runlevels': None}, 'enablement_not_observed'),
    ({'runlevels': ['../x']}, 'input_malformed'),
    ({'runlevels': 'default'}, 'input_malformed'),
    ({'conf_d': None}, 'conf_d_not_observed'),
    ({'conf_d': {'state': 'unreadable'}}, 'conf_d_unreadable'),
    ({'conf_d': {'state': 'listed', 'names': ['a/b']}}, 'input_malformed'),
    ({'conf_d': {'state': 'listed', 'names': [], 'truncated': True}}, 'listing_incomplete'),
    ({'conf_d': 'x'}, 'input_malformed'),
    ({'shell': ''}, 'input_malformed'),
])
def test_unobserved_or_malformed_context_blocks(kw, code):
    result = _run(**kw)
    assert code in _codes(result) and result['complete'] is False


def test_other_init_system_is_not_applicable_but_complete():
    result = _run(init_system='systemd')
    assert result['applicability'] == 'not_applicable' and result['complete'] is True


def test_other_init_system_does_not_run_scripts_at_boot():
    # Review of #1448: an enabled runlevel link must not project boot execution under another init.
    result = _run(init_system='systemd', runlevels=['default'])
    assert result['applicability'] == 'not_applicable'
    assert result['runs_at_boot'] is False and result['enabled_runlevels'] == ['default']
    assert result['phases']['start']['run_order'] == ['/etc/local.d/firewall.start']


@pytest.mark.parametrize('kw', [{'init_system': None}, {'family': None}, {'family': 'rpm'}])
def test_unconfirmed_applicability_leaves_boot_execution_unknown(kw):
    result = _run(**kw)
    assert result['applicability'] == 'unknown' and result['runs_at_boot'] is None
    assert result['complete'] is False


@pytest.mark.parametrize('family', [[], {}, ['debian'], 5, b'debian'])
def test_non_string_family_is_malformed_not_an_exception(family):
    # Review of #1448: captured JSON may hold a list or object here; membership checks used to raise TypeError.
    result = _run(family=family)
    assert 'input_malformed' in _codes(result)
    assert result['applicability'] == 'unknown' and result['complete'] is False


@pytest.mark.parametrize('local_d,code', [
    (None, 'directory_not_observed'),
    ({'state': 'unreadable'}, 'directory_unreadable'),
    ({'state': 'bogus'}, 'input_malformed'),
    ('nope', 'input_malformed'),
    (_listing(dict(SCRIPT, name='a.start'), truncated=True), 'listing_incomplete'),
    ({'state': 'listed', 'entries': 'x'}, 'input_malformed'),
    ({'state': 'listed', 'entries': [dict(SCRIPT, name='a.start')] * (ol.MAX_ENTRIES + 1)}, 'too_many_entries'),
    (_listing(dict(SCRIPT, name='a.start'), dict(SCRIPT, name='a.start')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='a/b.start')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='a\0.start')), 'input_malformed'),
    (_listing('x'), 'input_malformed'),
])
def test_unobserved_or_malformed_listing_blocks(local_d, code):
    result = ol.assess(local_d, family='debian', init_system='openrc', runlevels=['default'],
                       conf_d={'state': 'listed', 'names': []}, shell='dash')
    assert code in _codes(result) and result['complete'] is False
    assert result['phases']['start']['run_order'] == [] or code in ('listing_incomplete', 'input_malformed')


def test_absent_directory_is_complete_and_runs_nothing():
    result = _run({'state': 'absent'})
    assert result['complete'] is True
    assert result['phases']['start']['state'] == 'absent' and result['phases']['start']['run_order'] == []


def test_conf_d_local_and_runlevel_variants_are_sourced_as_root():
    result = _run(conf_d={'state': 'listed', 'names': ['local', 'local.shutdown', 'localhost', 'local.', 'net']})
    sourced = {s['path']: s for s in result['conf_d_sourced']}
    assert set(sourced) == {'/etc/conf.d/local', '/etc/conf.d/local.shutdown'}
    assert sourced['/etc/conf.d/local']['runs_as'] == 'root'
    assert 'shutdown' in sourced['/etc/conf.d/local.shutdown']['when']
    assert result['complete'] is True


def test_absent_conf_d_sources_nothing():
    assert _run(conf_d={'state': 'absent'})['conf_d_sourced'] == []


@pytest.mark.parametrize('shell', ['bash', None])
def test_locale_dependent_order_is_flagged_when_shell_may_collate(shell):
    names = ('B.start', 'a.start')
    result = _run(_listing(*(dict(SCRIPT, name=n) for n in names)), shell=shell)
    assert result['phases']['start']['run_order'] == ['/etc/local.d/B.start', '/etc/local.d/a.start']
    assert 'order_locale_dependent' in _codes(result)
    assert result['order'] == 'byte_assumed' and result['complete'] is True


def test_unambiguous_order_under_bash_has_no_order_gap():
    result = _run(_listing(dict(SCRIPT, name='10.start'), dict(SCRIPT, name='20.start')), shell='bash')
    assert result['gaps'] == [] and result['order'] == 'byte'


def test_gaps_are_bounded():
    entries = [{'name': f'{i:04}.start', 'type': 'file'} for i in range(200)]
    result = _run(_listing(*entries))
    assert len(result['gaps']) == ol.MAX_GAPS and result['gaps'][-1]['code'] == 'gaps_truncated'
    assert result['complete'] is False


def test_contract_is_static_metadata():
    result = _run()
    assert result['contract_version'] == ol.CONTRACT_VERSION
    assert 'local.in' in result['reference']['openrc']
    assert result['not_a_verdict'] and result['unobserved']


# Differential check: the upstream init.d/local.in loop (identical at OpenRC 0.45 and master), run by real shells.
UPSTREAM_LOOP = '''
local_d_dir="$1"; phase="$2"; redirect='> /dev/null 2>&1'
for file in "${local_d_dir}"/*."${phase}"; do
    if [ -x "${file}" ]; then
        eval "${file}" $redirect
    fi
done
'''
DIFF_ENTRIES = ('10-a.start', '2-b.start', 'Z.start', 'z.start', '.hidden.start', 'plain.start', 'dir.start',
                'link.start', 'dangling.start', 'a.stop', 'b.stop', 'x.start.bak', 'UP.START', 'sp ace.start')


def _build(tmp_path):
    root = tmp_path / 'local.d'
    log = tmp_path / 'ran.log'
    root.mkdir()
    entries = []
    for name in DIFF_ENTRIES:
        path = root / name
        if name == 'dir.start':
            path.mkdir(mode=0o755)
            entries.append({'name': name, 'type': 'directory', 'mode': 0o755})
        elif name == 'link.start':
            continue
        elif name == 'dangling.start':
            os.symlink(str(tmp_path / 'missing'), path)
            entries.append({'name': name, 'type': 'symlink', 'target': None})
        else:
            path.write_text(f'#!/bin/sh\nprintf "%s\\n" "{name}" >> "{log}"\n')
            mode = 0o644 if name == 'plain.start' else 0o755
            path.chmod(mode)
            entries.append({'name': name, 'type': 'file', 'mode': mode, 'noexec': False})
    os.symlink(str(root / 'Z.start'), root / 'link.start')
    entries.append({'name': 'link.start', 'type': 'symlink', 'target': dict(SCRIPT)})
    return root, log, entries


@pytest.mark.parametrize('shell', ['dash', 'bash'])
def test_differential_against_upstream_loop_in_real_shell(tmp_path, shell):
    binary = shutil.which(shell)
    if binary is None:
        pytest.skip(f'{shell} is not installed')
    root, log, entries = _build(tmp_path)
    result = _run(_listing(*entries), shell=shell)
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    for phase in ol.PHASES:
        if log.exists():
            log.unlink()
        subprocess.run([binary, '-c', UPSTREAM_LOOP, 'local', str(root), phase], env=env, check=False,
                       timeout=30)
        ran = log.read_text().splitlines() if log.exists() else []
        expected = []
        for script in result['phases'][phase]['scripts']:
            if script['outcome'] == 'runs':
                # link.start runs Z.start's contents, which log Z.start's name.
                expected.append('Z.start' if script['name'] == 'link.start' else script['name'])
        assert ran == expected, (phase, ran, expected)
        assert len(expected) >= 2
    names = [s['name'] for s in result['phases']['start']['scripts']]
    assert 'sp ace.start' in names and 'x.start.bak' not in names and 'UP.START' not in names
    assert stat.S_ISDIR((root / 'dir.start').stat().st_mode)
