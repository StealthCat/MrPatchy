"""Pure runit service-directory contract (roadmap F slice, #1628).

Takes captured metadata for the directory a running ``runsvdir`` scans (``/etc/service`` on Debian and Ubuntu) and
says which programs runit runs for each service, on which event, with which argv, under which account at exec,
and where coverage is missing. It never runs anything and never reads a script's contents.

Semantics come from runit 2.1.2 ``src/runsvdir.c`` and ``src/runsv.c`` as Ubuntu 24.04 ships them
(``runit 2.1.2-59ubuntu1``, Debian patches applied), and were traced natively with strace:

* ``runsvdir`` rescans its directory. Every entry whose name does not start with ``.`` and whose ``stat`` (which
  follows symlinks) is a directory gets ``runsv NAME`` with the scan directory as the working directory. A
  dangling symlink or a non-directory is skipped. At most 1000 services are supervised; later new entries are
  refused in ``readdir`` order, which is not observable.
* ``runsv`` changes into the service directory. When ``stat("down")`` succeeds (a file, directory or other
  type; a dangling symlink does not count) the service is wanted down and ``./run`` is not started until an
  administrator runs ``sv up`` or ``sv once``. Otherwise it runs ``execve("./run", ["./run"])`` directly: no
  shell, no ``PATH`` search and no fallback for a file without an interpreter line. A failed start is retried
  about once a second.
* Whenever ``./run`` exits (including a failed exec), ``runsv`` runs ``./finish EXITCODE SIGNAL`` when
  ``open("finish")`` succeeds. ``EXITCODE`` is ``-1`` when ``./run`` was killed by a signal.
* When ``stat("log")`` is a directory, ``runsv`` also runs ``log/run`` (working directory ``log``, standard
  input from the service's standard output), unless ``log/down`` exists. ``log/finish`` and ``log/control`` are
  never run.
* ``control/C`` for C in ``u d x t k p c a h i q 1 2`` replaces or follows the control action when ``stat``
  succeeds and the owner execute bit (``S_IXUSR``) is set; it is run as ``execve("control/C", ["control/C"])``.
  ``control/u`` runs before every start of ``./run`` and its exit status is ignored. ``control/t`` and the
  signal letters skip the default signal when they exit 0.

Every program runs with ``runsvdir``'s account at exec. A run script commonly drops privileges itself (for
example with ``chpst -u``), which is in script contents and is not assessed, so the account a program finally
runs as is reported as unknown. It performs no I/O and never authorizes a response action.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'runit': 'runit 2.1.2 src/runsvdir.c and src/runsv.c with Ubuntu 24.04 runit 2.1.2-59ubuntu1 patches',
}
MAX_SERVICES = 1000
MAX_ENTRIES = 2048
MAX_CONTROL_ENTRIES = 64
MAX_GAPS = 64
LISTING_STATES = ('listed', 'absent', 'unreadable', 'not_directory')
META_TYPES = ('file', 'directory', 'other', 'absent')
CONTROL_EVENTS = {
    'u': ('before every start of ./run: when the service is started automatically, restarted after it exits, or '
          'started by sv up, sv once or sv restart; the exit status is ignored'),
    'd': 'after the stop action for sv down or sv force-stop (as at runit stage 3 shutdown)',
    'x': 'after the stop action for sv exit or when runsv is asked to exit',
    't': ('instead of SIGTERM when it exits 0, whenever runsv stops a running service: sv term, sv down, '
          'sv restart, sv exit and shutdown'),
    'k': 'instead of SIGKILL when it exits 0, for sv kill while the service runs',
    'p': 'instead of SIGSTOP when it exits 0, for sv pause while the service runs',
    'c': 'instead of SIGCONT when it exits 0, for sv cont while the service runs',
    'a': 'instead of SIGALRM when it exits 0, for sv alarm while the service runs',
    'h': 'instead of SIGHUP when it exits 0, for sv hup (or sv reload) while the service runs',
    'i': 'instead of SIGINT when it exits 0, for sv interrupt while the service runs',
    'q': 'instead of SIGQUIT when it exits 0, for sv quit while the service runs',
    '1': 'instead of SIGUSR1 when it exits 0, for sv 1 while the service runs',
    '2': 'instead of SIGUSR2 when it exits 0, for sv 2 while the service runs',
}
EVENTS = {
    'run': ('when runsv starts the service and about once a second after it exits, unless it is wanted down; '
            'also on sv up, sv once and sv restart'),
    'finish': 'every time ./run exits or fails to start, before ./run is started again',
    'log_run': ('when runsv starts the log service and about once a second after it exits, unless log/down '
                'exists; its standard input is the service standard output'),
}
BLOCKING = frozenset({
    'input_malformed', 'supervisor_not_observed', 'directory_mismatch', 'directory_not_observed',
    'directory_unreadable', 'listing_incomplete', 'too_many_entries', 'too_many_services', 'metadata_missing',
    'symlink_target_unobserved', 'service_not_observed', 'service_unreadable', 'control_not_observed',
    'control_unreadable', 'special_file', 'gaps_truncated',
})
UNOBSERVED = (
    ('Script contents are not read, so what a program does, which interpreter it names and whether it drops '
     'privileges (for example with chpst -u) are not assessed.'),
    ('Whether runsvdir starts at boot (runit as init, or the runit.service unit from runit-run) is not modeled; '
     'only the supervisor observed now is.'),
    'The environment runsvdir passes on (Debian /etc/runit/2 clears it to PATH only) is not modeled.',
    'The check script is run by sv as the invoking user, not by runsv, and is not reported.',
    'Which entries beyond the first 1000 services runsvdir refuses depends on readdir order.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'runs': 'runsv executes this file directly with execve; it needs a valid interpreter line or binary format.',
    'missing': 'The file does not exist (or is a dangling symlink), so nothing is executed.',
    'not_executable': 'The file has no execute bit, so execve fails with EACCES and nothing runs.',
    'noexec_mount': 'The file is on a noexec mount, so execve fails and nothing runs.',
    'not_plain_file': 'Not a regular file, so execve fails and nothing runs.',
    'no_owner_execute': 'runsv runs a control script only when the owner execute bit is set.',
    'never_consulted': 'runsv never runs this name: only control/ with one of u d x t k p c a h i q 1 2 is used.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
SERVICE_REASONS = {
    'supervised': 'runsvdir starts runsv for this directory.',
    'hidden_name': 'runsvdir skips names that start with ".".',
    'not_directory': 'runsvdir starts runsv only for entries whose stat is a directory.',
    'stat_failed': 'The entry cannot be followed (for example a dangling symlink), so runsvdir skips it.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code}
    if path is not None:
        gap['path'] = path
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def _meta(meta: Any) -> dict[str, Any] | None:
    """Validate stat-followed metadata: ``{'type': file|directory|other|absent, 'mode', 'noexec'}``."""
    if not isinstance(meta, dict) or meta.get('type') not in META_TYPES:
        return None
    if meta['type'] in ('file', 'directory'):
        mode = meta.get('mode')
        if not (isinstance(mode, int) and not isinstance(mode, bool) and 0 <= mode <= 0o7777):
            return None
    if meta.get('noexec') is not None and not isinstance(meta['noexec'], bool):
        return None
    return meta


def _exec_outcome(meta: dict[str, Any], path: str, gaps: list[dict[str, Any]]) -> str:
    if meta['type'] == 'absent':
        return 'missing'
    if meta['type'] == 'other':
        _gap(gaps, 'special_file', path, 'A FIFO or device can block or misdirect runsv; the outcome is unknown.')
        return 'unresolved'
    if meta['type'] == 'directory':
        return 'not_plain_file'
    if not meta['mode'] & 0o111:
        return 'not_executable'
    if meta.get('noexec'):
        return 'noexec_mount'
    if meta.get('noexec') is None:
        _gap(gaps, 'mount_flags_unobserved', path, 'Reported as running; the noexec flag was not observed.')
    return 'runs'


def _program(role: str, path: str, argv: tuple[str, ...], cwd: str, meta: Any, account: str | None,
             gaps: list[dict[str, Any]], event: str) -> dict[str, Any] | None:
    checked = _meta(meta)
    if checked is None:
        _gap(gaps, 'metadata_missing', path, 'Type, mode or mount flag metadata is missing or malformed.')
        outcome = 'unresolved'
    else:
        outcome = _exec_outcome(checked, path, gaps)
    if outcome == 'missing':
        return None
    return {'role': role, 'path': path, 'argv': argv, 'cwd': cwd, 'event': event, 'outcome': outcome,
            'reason': REASONS[outcome], 'exec_account': account if outcome == 'runs' else None,
            'program_account': 'unknown' if outcome == 'runs' else None}


def _present(meta: Any, path: str, gaps: list[dict[str, Any]]) -> bool | None:
    checked = _meta(meta)
    if checked is None:
        _gap(gaps, 'metadata_missing', path, 'Whether this file exists was not observed.')
        return None
    return checked['type'] != 'absent'


def _control(control: Any, base: str, account: str | None, gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    path = f'{base}/control'
    if control is None:
        _gap(gaps, 'control_not_observed', path)
        return []
    if not isinstance(control, dict) or control.get('state') not in LISTING_STATES:
        _gap(gaps, 'input_malformed', path, 'Malformed control metadata.')
        return []
    if control['state'] == 'unreadable':
        _gap(gaps, 'control_unreadable', path)
    if control['state'] != 'listed':
        return []
    entries = control.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_CONTROL_ENTRIES:
        _gap(gaps, 'too_many_entries' if isinstance(entries, list) else 'input_malformed', path)
        return []
    out = []
    seen: set[str] = set()
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or '/' in name or '\0' in name or name in seen \
                or name in ('.', '..'):
            _gap(gaps, 'input_malformed', path, 'A control entry has a missing, invalid or duplicate name.')
            continue
        seen.add(name)
        entry_path = f'{path}/{name}'
        if name not in CONTROL_EVENTS:
            out.append({'role': 'control', 'path': entry_path, 'letter': None, 'outcome': 'never_consulted',
                        'reason': REASONS['never_consulted'], 'exec_account': None, 'program_account': None})
            continue
        meta = _meta(entry)
        mode = entry.get('mode') if meta is not None else None
        if meta is None or meta['type'] == 'absent' or not isinstance(mode, int) or isinstance(mode, bool):
            _gap(gaps, 'metadata_missing', entry_path, 'Type or mode metadata is missing or malformed.')
            outcome = 'unresolved'
        elif not mode & 0o100:
            outcome = 'no_owner_execute'
        elif meta['type'] != 'file':
            # stat and S_IXUSR pass, but execve fails, so the default action proceeds.
            outcome = 'not_plain_file'
        else:
            outcome = _exec_outcome(meta, entry_path, gaps)
        out.append({'role': 'control', 'path': entry_path, 'letter': name, 'argv': (f'control/{name}',),
                    'cwd': base, 'event': CONTROL_EVENTS[name], 'outcome': outcome, 'reason': REASONS[outcome],
                    'exec_account': account if outcome == 'runs' else None,
                    'program_account': 'unknown' if outcome == 'runs' else None})
    out.sort(key=lambda p: p['path'].encode('utf-8', 'surrogatepass'))
    return out


def _service(entry: dict[str, Any], base: str, account: str | None, supervised_now: bool | None,
             gaps: list[dict[str, Any]]) -> dict[str, Any]:
    svc: dict[str, Any] = {'name': entry['name'], 'path': base, 'outcome': 'supervised',
                           'reason': SERVICE_REASONS['supervised'], 'wanted_down': None,
                           'starts_automatically': None, 'has_log': None, 'programs': []}
    data = entry.get('service')
    if data is None:
        _gap(gaps, 'service_not_observed', base)
        return svc
    if not isinstance(data, dict) or data.get('state') not in ('listed', 'unreadable'):
        _gap(gaps, 'input_malformed', base, 'Malformed service directory metadata.')
        return svc
    if data['state'] == 'unreadable':
        _gap(gaps, 'service_unreadable', base)
        return svc
    files = data.get('files')
    if not isinstance(files, dict):
        _gap(gaps, 'input_malformed', base, 'Malformed service file metadata.')
        return svc
    programs = svc['programs']
    down = _present(files.get('down'), f'{base}/down', gaps)
    svc['wanted_down'] = down
    run = _program('run', f'{base}/run', ('./run',), base, files.get('run'), account, gaps, EVENTS['run'])
    if run is not None:
        programs.append(run)
    finish = _meta(files.get('finish'))
    if finish is None:
        _gap(gaps, 'metadata_missing', f'{base}/finish', 'Whether finish exists was not observed.')
    elif finish['type'] != 'absent':
        programs.append(_program('finish', f'{base}/finish', ('./finish', 'EXITCODE', 'SIGNAL'), base, finish,
                                 account, gaps, EVENTS['finish']))
    if supervised_now is not None and down is not None and (run is None or run['outcome'] != 'unresolved'):
        svc['starts_automatically'] = bool(supervised_now and not down and run is not None
                                           and run['outcome'] == 'runs')
    log_meta = _meta(files.get('log'))
    if log_meta is None:
        _gap(gaps, 'metadata_missing', f'{base}/log', 'Whether log is a directory was not observed.')
    else:
        svc['has_log'] = log_meta['type'] == 'directory'
    if svc['has_log']:
        log = data.get('log')
        log_base = f'{base}/log'
        log_files = log.get('files') if isinstance(log, dict) and log.get('state') == 'listed' else None
        if not isinstance(log_files, dict):
            code = 'service_unreadable' if isinstance(log, dict) and log.get('state') == 'unreadable' \
                else 'service_not_observed' if log is None else 'input_malformed'
            _gap(gaps, code, log_base)
        else:
            log_down = _present(log_files.get('down'), f'{log_base}/down', gaps)
            log_run = _program('log_run', f'{log_base}/run', ('./run',), log_base, log_files.get('run'), account,
                               gaps, EVENTS['log_run'])
            svc['log_wanted_down'] = log_down
            if log_run is not None:
                programs.append(log_run)
    programs.extend(_control(data.get('control'), base, account, gaps))
    # runsv calls control/u and forks ./run (then ./finish after it exits) on every automatic start attempt,
    # even when ./run cannot be executed. Every other control letter needs an sv command or shutdown.
    main_auto = None if supervised_now is None or down is None else bool(supervised_now and not down)
    log_down = svc.get('log_wanted_down')
    log_auto = None if supervised_now is None or log_down is None else bool(supervised_now and not log_down)
    for program in programs:
        if program['role'] in ('run', 'finish') or program.get('letter') == 'u':
            program['automatic'] = main_auto
        elif program['role'] == 'log_run':
            program['automatic'] = log_auto
        else:
            program['automatic'] = False
    return svc


def _service_outcome(entry: dict[str, Any], path: str, gaps: list[dict[str, Any]]) -> str:
    if entry['name'].startswith('.'):
        return 'hidden_name'
    target = entry
    if entry.get('type') == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', path)
            return 'unresolved'
        if entry['target'] is None:
            return 'stat_failed'
        target = entry['target']
    kind = target.get('type') if isinstance(target, dict) else None
    if kind not in ('file', 'directory', 'other'):
        _gap(gaps, 'metadata_missing', path, 'Type metadata is missing or malformed.')
        return 'unresolved'
    return 'supervised' if kind == 'directory' else 'not_directory'


def assess(scan_dir: Any = None, *, supervisor: Any = None) -> dict[str, Any]:
    """Resolve which programs runit runs for each service from captured metadata.

    ``supervisor`` is ``{'state': 'running', 'directory': PATH, 'uid': INT}`` for an observed ``runsvdir``
    process, or ``{'state': 'not_running'}``. ``scan_dir`` is ``{'path': PATH, 'state': 'listed', 'truncated':
    bool, 'entries': [...]}`` (or a ``state`` of ``absent``, ``unreadable`` or ``not_directory``). Each entry has
    ``name`` and ``type`` (``file``, ``directory``, ``other`` or ``symlink`` with ``target`` holding the
    followed type, or ``None`` when it cannot be followed). A supervised entry carries ``service``: ``{'state':
    'listed', 'files': {'run', 'finish', 'down', 'log': META}, 'log': {'state': 'listed', 'files': {'run',
    'down': META}}, 'control': {'state': 'listed', 'entries': [{'name', 'type', 'mode'}]}}``, where ``META`` is
    stat-followed ``{'type': 'file'|'directory'|'other'|'absent', 'mode', 'noexec'}``.
    """
    gaps: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'supervisor': 'not_observed',
        'directory': None, 'exec_account': None, 'services': services, 'gaps': gaps, 'origin': 'not_assessed',
        'authorizes_response': False, 'not_a_verdict': NOT_A_VERDICT, 'unobserved': UNOBSERVED,
    }
    supervised_now: bool | None = None
    account: str | None = None
    if supervisor is None:
        _gap(gaps, 'supervisor_not_observed', None, 'Whether runsvdir runs, and as which account, is unknown.')
    elif not isinstance(supervisor, dict) or supervisor.get('state') not in ('running', 'not_running'):
        _gap(gaps, 'input_malformed', None, 'Malformed supervisor.')
    elif supervisor['state'] == 'not_running':
        result['supervisor'] = 'not_running'
        supervised_now = False
    else:
        uid, directory = supervisor.get('uid'), supervisor.get('directory')
        if not isinstance(uid, int) or isinstance(uid, bool) or uid < 0 \
                or not isinstance(directory, str) or not directory.startswith('/') or '\0' in directory:
            _gap(gaps, 'input_malformed', None, 'Malformed supervisor uid or directory.')
        else:
            result['supervisor'] = 'running'
            result['directory'] = directory
            account = 'root' if uid == 0 else f'uid {uid}'
            result['exec_account'] = account
            supervised_now = True
    if scan_dir is None:
        _gap(gaps, 'directory_not_observed', result['directory'])
    elif not isinstance(scan_dir, dict) or scan_dir.get('state') not in LISTING_STATES \
            or not isinstance(scan_dir.get('path'), str) or not scan_dir['path'].startswith('/'):
        _gap(gaps, 'input_malformed', None, 'Malformed scan directory metadata.')
    else:
        _listing(scan_dir, result, account, supervised_now, gaps)
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    result['automatic_programs'] = sorted(
        p['path'] for s in services for p in s['programs'] if p['outcome'] == 'runs' and p['automatic']
    )
    return result


def _listing(scan_dir: dict[str, Any], result: dict[str, Any], account: str | None, supervised_now: bool | None,
             gaps: list[dict[str, Any]]) -> None:
    path = scan_dir['path'].rstrip('/') or '/'
    if result['directory'] is not None and result['directory'].rstrip('/') != path:
        _gap(gaps, 'directory_mismatch', path, f'runsvdir scans {result["directory"]}, not this directory.')
        # The observed supervisor does not scan this listing, so whether and as whom it runs these is unknown.
        account, supervised_now = None, None
    if result['directory'] is None:
        result['directory'] = path
    if scan_dir['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', path)
    if scan_dir['state'] != 'listed':
        return
    if scan_dir.get('truncated'):
        _gap(gaps, 'listing_incomplete', path)
    entries = scan_dir.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries' if isinstance(entries, list) else 'input_malformed', path)
        return
    seen: set[str] = set()
    supervised = 0
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or '/' in name or '\0' in name or name in seen \
                or name in ('.', '..'):
            _gap(gaps, 'input_malformed', path, 'An entry has a missing, invalid or duplicate name.')
            continue
        seen.add(name)
        base = f'{path.rstrip("/")}/{name}'
        outcome = _service_outcome(entry, base, gaps)
        if outcome != 'supervised':
            result['services'].append({'name': name, 'path': base, 'outcome': outcome,
                                       'reason': SERVICE_REASONS[outcome], 'programs': []})
            continue
        supervised += 1
        result['services'].append(_service(entry, base, account, supervised_now, gaps))
    if supervised > MAX_SERVICES:
        _gap(gaps, 'too_many_services', path,
             f'runsvdir supervises at most {MAX_SERVICES} services; which ones depends on readdir order.')
    result['services'].sort(key=lambda s: s['name'].encode('utf-8', 'surrogatepass'))
