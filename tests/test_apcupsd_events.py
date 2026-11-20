import os
import subprocess

import pytest

from app import apcupsd_events as ae

SCRIPT = {'type': 'file', 'mode': 0o755, 'noexec': False}
CONF = 'UPSNAME myups\nUPSCABLE usb\nUPSTYPE usb\nSCRIPTDIR /etc/apcupsd\nPWRFAILDIR /etc/apcupsd\n'


def _listing(*entries, **kw):
    return dict({'state': 'listed', 'entries': list(entries)}, **kw)


def _run(config=None, directory=None, **kw):
    kw.setdefault('family', 'debian')
    kw.setdefault('apcupsd_installed', True)
    kw.setdefault('apccontrol_verified', True)
    kw.setdefault('exec_start', ['/sbin/apcupsd'])
    if config is None:
        config = {'state': 'read', 'text': CONF}
    if directory is None:
        directory = _listing(dict(SCRIPT, name='apccontrol'), dict(SCRIPT, name='onbattery'),
                             dict(SCRIPT, name='apcupsd.conf', mode=0o644))
    return ae.assess(config, directory, **kw)


def _outcomes(result):
    return {s['event']: s['outcome'] for s in result['event_scripts']}


def _codes(result):
    return {g['code'] for g in result['gaps']}


def test_packaged_layout_runs_present_event_scripts_as_root():
    result = _run(directory=_listing(
        dict(SCRIPT, name='apccontrol'), dict(SCRIPT, name='onbattery'), dict(SCRIPT, name='offbattery'),
        dict(SCRIPT, name='changeme', mode=0o644), dict(SCRIPT, name='killpower'),
        dict(SCRIPT, name='doshutdown', type='directory'), dict(SCRIPT, name='unrelated')))
    assert result['complete'] is True and result['gaps'] == []
    assert result['applicability'] == 'applicable' and result['runs_as'] == 'root'
    assert result['scriptdir'] == '/etc/apcupsd' and result['scriptdir_line'] == 4
    assert result['daemon_program']['path'] == '/etc/apcupsd/apccontrol'
    assert result['daemon_program']['argv'] == ('/etc/apcupsd/apccontrol', 'EVENT', 'UPSNAME', 'CONNECTED', 'POWERED')
    assert result['sourced_config']['state'] == 'absent'
    outcomes = _outcomes(result)
    assert [s['event'] for s in result['event_scripts']] == list(ae.DAEMON_EVENTS) + ['killpower']
    assert len(ae.DAEMON_EVENTS) == 19
    assert outcomes['onbattery'] == outcomes['offbattery'] == outcomes['killpower'] == 'runs'
    assert outcomes['changeme'] == 'not_executable'
    assert outcomes['doshutdown'] == 'directory'
    assert outcomes['powerout'] == 'absent'
    assert 'unrelated' not in outcomes
    killpower = [s for s in result['event_scripts'] if s['event'] == 'killpower'][0]
    assert killpower['trigger'] == 'shutdown'
    assert result['shutdown_program']['command'] == ('/etc/apcupsd/apccontrol', 'killpower')


def test_missing_scriptdir_keeps_the_compiled_default():
    result = _run({'state': 'read', 'text': 'UPSNAME x\n'})
    assert result['scriptdir'] == '/etc/apcupsd' and result['scriptdir_line'] is None
    assert result['complete'] is True


def test_nondefault_scriptdir_is_a_blocking_gap_naming_the_program():
    result = _run({'state': 'read', 'text': CONF + 'scriptdir   /opt/ups/bin   # local\n'})
    assert result['scriptdir'] == '/opt/ups/bin' and result['scriptdir_line'] == 6
    assert result['daemon_program']['path'] == '/opt/ups/bin/apccontrol'
    assert 'nondefault_scriptdir' in _codes(result) and result['complete'] is False


def test_last_scriptdir_wins_and_comments_or_other_keys_do_not_set_it():
    text = ('SCRIPTDIR /tmp/a\n# SCRIPTDIR /tmp/b\n  #SCRIPTDIR /tmp/c\nSCRIPTDIRX /tmp/d\n'
            'SCRIPTDIR=/tmp/e\n\tScriptDir\t/etc/apcupsd\t\n')
    result = _run({'state': 'read', 'text': text})
    assert result['scriptdir'] == '/etc/apcupsd' and result['scriptdir_line'] == 6
    assert result['complete'] is True


def test_hash_anywhere_cuts_the_value_and_inner_spaces_are_kept():
    assert ae.scriptdir_from_config('SCRIPTDIR /tmp/x#y\n')[0] == '/tmp/x'
    assert ae.scriptdir_from_config('SCRIPTDIR /tmp/a b  \r\n')[0] == '/tmp/a b'
    assert ae.scriptdir_from_config('SCRIPTDIR\n')[0] == ''
    assert ae.scriptdir_from_config('SCRIPTDIR /tmp/x\0junk\nUPSNAME y\n')[0] == '/tmp/x'


def test_empty_scriptdir_runs_apccontrol_from_the_root_directory():
    result = _run({'state': 'read', 'text': 'SCRIPTDIR   # nothing\n'})
    assert result['scriptdir'] == ''
    assert result['daemon_program']['path'] == '/apccontrol'
    assert 'nondefault_scriptdir' in _codes(result)


def test_relative_scriptdir_resolves_from_root_after_daemonizing():
    result = _run({'state': 'read', 'text': 'SCRIPTDIR etc/apcupsd\n'})
    assert result['daemon_program']['path'] == '/etc/apcupsd/apccontrol'
    assert result['daemon_program']['argv'][0] == 'etc/apcupsd/apccontrol'
    assert 'relative_scriptdir' in _codes(result) and result['complete'] is False


def test_overlong_comment_line_tail_is_parsed_as_its_own_line():
    # fgets(256) returns 255 bytes; the rest of the physical line is read as a new line.
    text = '#' + 'x' * 254 + 'SCRIPTDIR /tmp/evil\n'
    assert len(('#' + 'x' * 254).encode()) == ae.FGETS_CHUNK
    result = _run({'state': 'read', 'text': CONF + text})
    assert result['scriptdir'] == '/tmp/evil'
    assert result['daemon_program']['path'] == '/tmp/evil/apccontrol'
    assert 'nondefault_scriptdir' in _codes(result) and result['complete'] is False


def test_overlong_scriptdir_value_is_cut_at_the_fgets_chunk():
    head = 'SCRIPTDIR /etc/apcupsd'
    text = head + 'y' * (ae.FGETS_CHUNK - len(head)) + 'zzz\n'
    value, line = ae.scriptdir_from_config(text)
    assert value == '/etc/apcupsd' + 'y' * (ae.FGETS_CHUNK - len(head))
    assert line == 1  # The "zzz" tail is parsed as an unknown key, not a SCRIPTDIR.


def test_long_scriptdir_truncates_the_program_path_buffer():
    # "SCRIPTDIR " leaves at most 245 value bytes in one fgets chunk; 245 + "/apccontrol" overflows 255.
    fits = '/' + 'd' * 243
    assert _run({'state': 'read', 'text': f'SCRIPTDIR {fits}\n'})['daemon_program']['path'] == fits + '/apccontrol'
    longdir = '/' + 'd' * 244
    result = _run({'state': 'read', 'text': f'SCRIPTDIR {longdir}\n'})
    assert result['scriptdir'] == longdir
    assert result['daemon_program']['path'] == longdir + '/apccontro'
    assert {'apccontrol_path_truncated', 'nondefault_scriptdir'} <= _codes(result)
    fits_codes = _codes(_run({'state': 'read', 'text': f'SCRIPTDIR {fits}\n'}))
    assert 'apccontrol_path_truncated' not in fits_codes


def test_multibyte_and_non_ascii_keys_are_not_case_folded():
    assert ae.scriptdir_from_config('SCRİPTDIR /tmp/x\n')[0] == '/etc/apcupsd'
    assert ae.scriptdir_from_config('SCRIPTDIR /tmp/é\n')[0] == '/tmp/é'


def test_absent_config_means_the_daemon_does_not_start():
    result = _run({'state': 'absent'})
    assert result['daemon_program']['starts'] is False
    assert result['complete'] is True


def test_sourced_config_file_is_a_blocking_gap():
    result = _run(directory=_listing(dict(SCRIPT, name='apccontrol'), dict(SCRIPT, name='config', mode=0o600)))
    assert result['sourced_config']['state'] == 'sourced'
    assert 'apccontrol_config_sourced' in _codes(result) and result['complete'] is False
    linked = _run(directory=_listing(dict(name='config', type='symlink', target=dict(SCRIPT))))
    assert linked['sourced_config']['state'] == 'sourced'
    dangling = _run(directory=_listing(dict(name='config', type='symlink', target=None)))
    assert dangling['sourced_config']['state'] == 'not_regular' and dangling['complete'] is True
    directory = _run(directory=_listing(dict(name='config', type='directory')))
    assert directory['sourced_config']['state'] == 'not_regular' and directory['complete'] is True


def test_symlinks_noexec_and_special_files():
    result = _run(directory=_listing(
        dict(name='onbattery', type='symlink', target=dict(SCRIPT)),
        dict(name='offbattery', type='symlink', target=None),
        dict(name='commok', type='symlink'),
        dict(SCRIPT, name='commfailure', noexec=True),
        dict(SCRIPT, name='mainsback', mode=0o610),
        dict(name='emergency', type='other'),
        dict(SCRIPT, name='annoyme', noexec=None),
    ))
    outcomes = _outcomes(result)
    assert outcomes['onbattery'] == 'runs'
    assert outcomes['offbattery'] == 'stat_failed'
    assert outcomes['commok'] == 'unresolved'
    assert outcomes['commfailure'] == 'noexec_mount'
    assert outcomes['mainsback'] == 'runs'  # Any execute bit passes for root.
    assert outcomes['emergency'] == 'not_plain_file'
    assert outcomes['annoyme'] == 'runs'
    codes = _codes(result)
    assert {'symlink_target_unobserved', 'mount_flags_unobserved'} <= codes
    assert result['complete'] is False


def test_truncated_listing_leaves_absent_events_unresolved():
    result = _run(directory=_listing(dict(SCRIPT, name='onbattery'), truncated=True))
    outcomes = _outcomes(result)
    assert outcomes['onbattery'] == 'runs' and outcomes['powerout'] == 'unresolved'
    assert {'listing_incomplete', 'config_file_not_observed'} <= _codes(result)
    assert result['complete'] is False


def test_absent_directory_runs_no_event_scripts():
    result = _run(directory={'state': 'absent'})
    assert set(_outcomes(result).values()) == {'absent'}
    assert result['complete'] is True


def test_unverified_apccontrol_and_service_command_are_blocking():
    assert 'apccontrol_unverified' in _codes(_run(apccontrol_verified=None))
    assert 'apccontrol_unverified' in _codes(_run(apccontrol_verified=False))
    assert 'exec_start_not_observed' in _codes(_run(exec_start=None))
    custom = _run(exec_start=['/sbin/apcupsd', '-f', '/tmp/evil.conf'])
    assert 'nondefault_exec_start' in _codes(custom) and custom['complete'] is False
    assert 'input_malformed' in _codes(_run(exec_start='/sbin/apcupsd'))


def test_unobserved_and_malformed_inputs_fail_closed():
    result = ae.assess()
    codes = _codes(result)
    assert {'family_not_observed', 'implementation_not_observed', 'exec_start_not_observed',
            'config_not_observed', 'apccontrol_unverified', 'directory_not_observed'} <= codes
    assert result['complete'] is False and result['applicability'] == 'unknown'
    assert 'family_unsupported' in _codes(_run(family='rpm'))
    assert 'config_unreadable' in _codes(_run({'state': 'unreadable'}))
    assert 'input_malformed' in _codes(_run({'state': 'read'}))
    assert 'input_malformed' in _codes(_run({'state': 'bogus'}))
    assert 'directory_unreadable' in _codes(_run(directory={'state': 'unreadable'}))
    assert 'input_malformed' in _codes(_run(directory=_listing({'name': 'a/b'}, {'name': ''})))
    assert 'too_many_entries' in _codes(_run(directory=_listing(*[dict(SCRIPT, name=f'f{i}')
                                                                  for i in range(ae.MAX_ENTRIES + 1)])))
    assert 'metadata_missing' in _codes(_run(directory=_listing({'name': 'onbattery', 'type': 'file'})))
    assert 'config_too_large' in _codes(_run({'state': 'read', 'text': '#' * (ae.MAX_CONFIG_BYTES + 1)}))
    assert _run(apcupsd_installed=False)['applicability'] == 'not_applicable'


def test_gap_list_is_bounded():
    entries = [dict(name=e, type='symlink') for e in ae.EVENTS]
    entries += [dict(name=f'x{i}', type='file') for i in range(80)]
    result = _run(directory=_listing(*entries), family=None, exec_start=None, apccontrol_verified=None)
    assert len(result['gaps']) <= ae.MAX_GAPS
    assert result['complete'] is False


def test_contract_never_authorizes_actions_or_claims_a_verdict():
    result = _run()
    assert result['origin'] == 'not_assessed'
    assert 'not a safety verdict' in result['not_a_verdict']
    assert not any(k in result for k in ('authorized', 'action', 'response'))


@pytest.mark.skipif(not hasattr(os, 'geteuid') or os.geteuid() != 0 or not os.path.exists('/bin/sh'),
                    reason='apccontrol runs as root; the [ -x ] result differs for other users')
def test_event_outcomes_match_the_packaged_shell_test(tmp_path):
    # The exact test the packaged /etc/apcupsd/apccontrol applies before running an event script.
    cases = {
        'onbattery': ('file', 0o755), 'offbattery': ('file', 0o644), 'mainsback': ('file', 0o610),
        'commok': ('file', 0o001), 'doshutdown': ('directory', 0o755), 'onlink': ('link', 0o755),
        'deadlink': ('dangling', 0), 'dirlink': ('dirlink', 0o755),
    }
    entries = []
    for name, (kind, mode) in cases.items():
        path = tmp_path / name
        if kind == 'file':
            path.write_text('#!/bin/sh\n')
            path.chmod(mode)
            entries.append(dict(name=name, type='file', mode=mode, noexec=False))
        elif kind == 'directory':
            path.mkdir()
            entries.append(dict(name=name, type='directory', mode=mode, noexec=False))
        elif kind == 'link':
            target = tmp_path / 'real-target'
            target.write_text('#!/bin/sh\n')
            target.chmod(mode)
            path.symlink_to(target)
            entries.append(dict(name=name, type='symlink', target=dict(type='file', mode=mode, noexec=False)))
        elif kind == 'dirlink':
            (tmp_path / 'real-dir').mkdir()
            path.symlink_to(tmp_path / 'real-dir')
            entries.append(dict(name=name, type='symlink', target=dict(type='directory', mode=mode, noexec=False)))
        else:
            path.symlink_to(tmp_path / 'missing')
            entries.append(dict(name=name, type='symlink', target=None))
    for name, entry in zip(cases, entries):
        shell = subprocess.run(['/bin/sh', '-c', 'if [ -f "$1" -a -x "$1" ]; then exit 0; fi; exit 1', 'sh',
                                str(tmp_path / name)]).returncode == 0
        assert (ae._event_outcome(entry, name, []) == 'runs') is shell, name
