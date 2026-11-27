import os
import shutil
import signal
import stat
import subprocess
import time

import pytest

from app import runit_services as rs

EXE = {'type': 'file', 'mode': 0o755, 'noexec': False}
ABSENT = {'type': 'absent'}
SUPERVISOR = {'state': 'running', 'directory': '/etc/service', 'uid': 0}


def _files(**kw):
    files = {'run': EXE, 'finish': ABSENT, 'down': ABSENT, 'log': ABSENT}
    files.update(kw)
    return files


def _svc(name, files=None, log=None, control=None, **entry):
    service = {'state': 'listed', 'files': files or _files(),
               'control': control or {'state': 'absent'}}
    if log is not None:
        service['log'] = log
    return dict({'name': name, 'type': 'directory', 'service': service}, **entry)


def _run(*entries, supervisor=SUPERVISOR, **kw):
    scan = dict({'path': '/etc/service', 'state': 'listed', 'entries': list(entries)}, **kw)
    return rs.assess(scan, supervisor=supervisor)


def _service(result, name):
    return next(s for s in result['services'] if s['name'] == name)


def _programs(svc):
    return {p['path']: p['outcome'] for p in svc['programs']}


def _codes(result):
    return {g['code'] for g in result['gaps']}


def test_supervised_service_runs_run_finish_and_log_as_root_with_unknown_final_account():
    log = {'state': 'listed', 'files': {'run': EXE, 'down': ABSENT, 'finish': EXE}}
    result = _run(_svc('sshd', _files(finish=EXE, log={'type': 'directory', 'mode': 0o755}), log=log))
    assert result['complete'] is True and result['gaps'] == []
    assert result['exec_account'] == 'root' and result['origin'] == 'not_assessed'
    assert result['authorizes_response'] is False
    svc = _service(result, 'sshd')
    assert svc['starts_automatically'] is True and svc['wanted_down'] is False and svc['has_log'] is True
    by_role = {p['role']: p for p in svc['programs']}
    assert by_role['run']['argv'] == ('./run',) and by_role['run']['cwd'] == '/etc/service/sshd'
    assert by_role['finish']['argv'] == ('./finish', 'EXITCODE', 'SIGNAL')
    assert by_role['log_run']['cwd'] == '/etc/service/sshd/log'
    assert all(p['exec_account'] == 'root' and p['program_account'] == 'unknown' for p in svc['programs'])
    # Native: runsv never runs log/finish.
    assert '/etc/service/sshd/log/finish' not in _programs(svc)
    assert result['automatic_programs'] == ['/etc/service/sshd/finish', '/etc/service/sshd/log/run',
                                       '/etc/service/sshd/run']


def test_scan_rules_match_native_runsvdir():
    # Native strace: runsv started for a, a symlinked directory and nothing else.
    result = _run(
        _svc('a'), _svc('.hidden'), {'name': 'plainfile', 'type': 'file', 'mode': 0o644},
        {'name': 'linked', 'type': 'symlink', 'target': {'type': 'directory'},
         'service': {'state': 'listed', 'files': _files(), 'control': {'state': 'absent'}}},
        {'name': 'dangling', 'type': 'symlink', 'target': None},
    )
    assert result['complete'] is True
    assert {s['name']: s['outcome'] for s in result['services']} == {
        '.hidden': 'hidden_name', 'a': 'supervised', 'dangling': 'stat_failed', 'linked': 'supervised',
        'plainfile': 'not_directory'}
    assert result['automatic_programs'] == ['/etc/service/a/run', '/etc/service/linked/run']


@pytest.mark.parametrize('down,wanted', [
    ({'type': 'file', 'mode': 0o644}, True),
    ({'type': 'directory', 'mode': 0o755}, True),   # native: a down directory also holds the service down
    (ABSENT, False),                                 # native: a dangling down symlink does not
])
def test_down_file_keeps_run_from_starting_automatically(down, wanted):
    svc = _service(_run(_svc('b', _files(down=down))), 'b')
    assert svc['wanted_down'] is wanted and svc['starts_automatically'] is (not wanted)
    assert _programs(svc)['/etc/service/b/run'] == 'runs' and svc['programs'][0]['automatic'] is (not wanted)


@pytest.mark.parametrize('meta,outcome', [
    ({'type': 'file', 'mode': 0o644, 'noexec': False}, 'not_executable'),   # native EACCES, retried
    ({'type': 'file', 'mode': 0o755, 'noexec': True}, 'noexec_mount'),
    ({'type': 'directory', 'mode': 0o755}, 'not_plain_file'),
])
def test_run_that_cannot_exec_never_starts(meta, outcome):
    svc = _service(_run(_svc('e', _files(run=meta))), 'e')
    assert _programs(svc) == {'/etc/service/e/run': outcome}
    assert svc['starts_automatically'] is False and svc['programs'][0]['exec_account'] is None


def test_missing_run_starts_nothing_and_non_directory_log_is_ignored():
    svc = _service(_run(_svc('g', _files(run=ABSENT, log={'type': 'file', 'mode': 0o644}))), 'g')
    assert svc['programs'] == [] and svc['starts_automatically'] is False and svc['has_log'] is False


def test_log_down_and_log_listing():
    log = {'state': 'listed', 'files': {'run': EXE, 'down': {'type': 'file', 'mode': 0o644}}}
    svc = _service(_run(_svc('h', _files(log={'type': 'directory', 'mode': 0o755}), log=log)), 'h')
    assert svc['log_wanted_down'] is True and '/etc/service/h/log/run' in _programs(svc)
    unobserved = _run(_svc('h', _files(log={'type': 'directory', 'mode': 0o755})))
    assert 'service_not_observed' in _codes(unobserved) and unobserved['complete'] is False


def test_control_scripts_need_owner_execute_and_a_known_letter():
    control = {'state': 'listed', 'entries': [
        {'name': 'u', 'type': 'file', 'mode': 0o100, 'noexec': False},   # native: runs
        {'name': 'h', 'type': 'file', 'mode': 0o654, 'noexec': False},   # native: skipped
        {'name': 'd', 'type': 'file', 'mode': 0o010, 'noexec': False},
        {'name': 't', 'type': 'directory', 'mode': 0o755},               # native: exec fails, SIGTERM sent
        {'name': 'o', 'type': 'file', 'mode': 0o755, 'noexec': False},
        {'name': 'up', 'type': 'file', 'mode': 0o755, 'noexec': False},
    ]}
    svc = _service(_run(_svc('a', control=control)), 'a')
    assert _programs(svc) == {
        '/etc/service/a/run': 'runs', '/etc/service/a/control/u': 'runs',
        '/etc/service/a/control/h': 'no_owner_execute', '/etc/service/a/control/d': 'no_owner_execute',
        '/etc/service/a/control/t': 'not_plain_file', '/etc/service/a/control/o': 'never_consulted',
        '/etc/service/a/control/up': 'never_consulted'}
    u = next(p for p in svc['programs'] if p['path'].endswith('/u'))
    assert u['argv'] == ('control/u',) and 'before every start' in u['event'] and u['automatic'] is True
    assert not any(p['automatic'] for p in svc['programs'] if p.get('letter') not in (None, 'u'))


def test_non_root_supervisor_and_stopped_supervisor():
    result = _run(_svc('a'), supervisor={'state': 'running', 'directory': '/home/u/service', 'uid': 1000})
    assert result['exec_account'] == 'uid 1000' and 'directory_mismatch' in _codes(result)
    stopped = _run(_svc('a'), supervisor={'state': 'not_running'})
    assert stopped['automatic_programs'] == [] and _service(stopped, 'a')['starts_automatically'] is False
    assert stopped['complete'] is True


@pytest.mark.parametrize('kwargs,code', [
    ({'supervisor': None}, 'supervisor_not_observed'),
    ({'supervisor': {'state': 'running', 'directory': 'etc/service', 'uid': 0}}, 'input_malformed'),
    ({'truncated': True}, 'listing_incomplete'),
])
def test_blocking_gaps(kwargs, code):
    result = _run(_svc('a'), **kwargs)
    assert code in _codes(result) and result['complete'] is False


def test_unobserved_and_special_metadata_block():
    fifo = _service(_run(_svc('f', _files(finish={'type': 'other'}))), 'f')
    assert _programs(fifo)['/etc/service/f/finish'] == 'unresolved'
    assert 'special_file' in _codes(_run(_svc('f', _files(finish={'type': 'other'}))))
    assert 'metadata_missing' in _codes(_run(_svc('m', {'run': EXE})))
    assert 'symlink_target_unobserved' in _codes(_run({'name': 's', 'type': 'symlink'}))
    assert 'service_unreadable' in _codes(_run({'name': 'u', 'type': 'directory',
                                                 'service': {'state': 'unreadable'}}))
    assert 'directory_unreadable' in _codes(rs.assess({'path': '/etc/service', 'state': 'unreadable'},
                                                      supervisor=SUPERVISOR))
    assert 'directory_not_observed' in _codes(rs.assess(None, supervisor=SUPERVISOR))
    unobserved_mount = _run(_svc('n', _files(run={'type': 'file', 'mode': 0o755})))
    assert unobserved_mount['complete'] is True and 'mount_flags_unobserved' in _codes(unobserved_mount)


def test_malformed_and_over_limit_input_is_bounded():
    dup = _run(_svc('a'), _svc('a'), {'name': 'x/y', 'type': 'directory'}, 'junk')
    assert [s['name'] for s in dup['services']] == ['a'] and 'input_malformed' in _codes(dup)
    many = _run(*[_svc(f's{i}') for i in range(rs.MAX_SERVICES + 1)])
    assert 'too_many_services' in _codes(many) and many['complete'] is False
    assert len(many['gaps']) <= rs.MAX_GAPS
    assert 'too_many_entries' in _codes(_run(*[{'name': f'f{i}', 'type': 'file'}
                                               for i in range(rs.MAX_ENTRIES + 1)]))
    assert rs.assess('nope', supervisor='nope')['complete'] is False


# --- Optional native differential: runs real runsvdir when installed and running as root. ---

def _capture(path):
    def meta(p):
        try:
            st = os.stat(p)
        except FileNotFoundError:
            return {'type': 'absent'}
        kind = 'file' if stat.S_ISREG(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'other'
        return {'type': kind, 'mode': stat.S_IMODE(st.st_mode), 'noexec': False}

    entries = []
    for name in os.listdir(path):
        full = os.path.join(path, name)
        entry = {'name': name}
        if os.path.islink(full):
            entry['type'] = 'symlink'
            followed = meta(full)
            entry['target'] = None if followed['type'] == 'absent' else followed
        else:
            entry.update(meta(full))
        if os.path.isdir(full):
            files = {n: meta(os.path.join(full, n)) for n in ('run', 'finish', 'down', 'log')}
            service = {'state': 'listed', 'files': files, 'control': {'state': 'absent'}}
            if os.path.isdir(os.path.join(full, 'log')):
                service['log'] = {'state': 'listed',
                                  'files': {n: meta(os.path.join(full, 'log', n)) for n in ('run', 'down')}}
            if os.path.isdir(os.path.join(full, 'control')):
                service['control'] = {'state': 'listed', 'entries': [
                    dict(meta(os.path.join(full, 'control', n)), name=n)
                    for n in os.listdir(os.path.join(full, 'control'))]}
            entry['service'] = service
        entries.append(entry)
    return {'path': path, 'state': 'listed', 'entries': entries}


@pytest.mark.skipif(shutil.which('runsvdir') is None or os.geteuid() != 0,
                    reason='native runit and root are required')
def test_native_runsvdir_runs_exactly_the_reported_programs(tmp_path):
    marker = tmp_path / 'ran.txt'
    svdir = tmp_path / 'service'
    svdir.mkdir()

    def script(path, mode=0o755, body='exec sleep 30'):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'#!/bin/sh\necho "$PWD/${{0#./}}" >> {marker}\n{body}\n')
        path.chmod(mode)

    script(svdir / 'a' / 'run')
    script(svdir / 'a' / 'log' / 'run', body='exec cat >/dev/null')
    script(svdir / 'a' / 'log' / 'finish', body='')
    script(svdir / 'a' / 'control' / 'u', mode=0o100, body='exit 1')
    script(svdir / 'a' / 'control' / 'o', body='')
    script(svdir / 'b' / 'run')
    (svdir / 'b' / 'down').write_text('')
    script(svdir / 'c' / 'run', mode=0o644)
    script(svdir / 'c' / 'finish', body='sleep 30')  # runs even though ./run cannot be executed
    script(svdir / 'f' / 'run', body='exit 3')
    script(svdir / 'f' / 'finish', body='sleep 30')
    script(svdir / '.hidden' / 'run')
    real = tmp_path / 'real'
    script(real / 'run')
    (svdir / 'linked').symlink_to(real)
    (svdir / 'dangling').symlink_to(tmp_path / 'missing')

    result = rs.assess(_capture(str(svdir)), supervisor={'state': 'running', 'directory': str(svdir), 'uid': 0})
    # Without -P every runsv and program stays in this process group, so one killpg cleans up.
    proc = subprocess.Popen(['runsvdir', str(svdir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        time.sleep(3)
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)
    ran = {os.path.realpath(line) for line in marker.read_text().split()}
    expected = {os.path.realpath(p) for p in result['automatic_programs']}
    assert ran == expected
