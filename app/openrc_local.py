"""Pure OpenRC ``local.d`` contract (roadmap F slice, #1447).

Takes captured metadata for ``/etc/local.d`` and ``/etc/conf.d`` and says which ``*.start`` and ``*.stop`` files
the OpenRC ``local`` service runs as root, in which order, at which phase, and which ``conf.d`` files it sources,
and where coverage is missing. It never runs anything and never reads a script's contents.

Semantics come from OpenRC ``init.d/local.in`` and ``sh/openrc-run.sh.in``, checked at tag ``0.45`` (the version
Debian 12 ships) and on ``master``. The ``local`` loop is identical in both::

    local_d_dir="${RC_SERVICE%/*/*}/local.d"          # /etc/init.d/local -> /etc/local.d
    yesno $rc_verbose || redirect='> /dev/null 2>&1'
    for file in "${local_d_dir}"/*.start; do           # *.stop in stop()
        if [ -x "${file}" ]; then
            eval "${file}" $redirect
            ...                                        # a failure sets has_errors and the loop continues
    if command -v local_start >/dev/null 2>&1; then local_start   # deprecated, from conf.d
    return 0

* ``depend()`` orders the service ``after *`` with ``keyword -timeout``, so in a runlevel that contains ``local`` it
  starts after every other service, as root, through ``openrc-run``. It runs at boot only when it is enabled in a
  runlevel (``/etc/runlevels/RUNLEVEL/local``); otherwise it runs only when an administrator starts it.
* The shell glob ``*`` does not match a leading ``.``, and the ``.start``/``.stop`` suffix is case-sensitive.
* ``[ -x ]`` follows symlinks. For root, dash and busybox ``test`` accept any execute bit, including on a directory
  or a noexec mount; bash asks the kernel, which refuses noexec. Either way such a file does not run: ``eval``
  fails and the failure is counted. A dangling symlink or a file with no execute bit is skipped.
* ``eval`` re-parses the path as shell text, so a name with characters the shell treats specially may not run
  that file.
* dash sorts glob results with ``strcmp`` and busybox ash on musl does the same. bash sorts with ``strcoll``, so
  the order can depend on the locale.
* ``openrc-run`` sources ``/etc/conf.d/local.RUNLEVEL`` when it exists, otherwise ``/etc/conf.d/local``, as root,
  before running the service. A ``local_start``/``local_stop`` function defined there is called after the scripts.

It performs no I/O and never authorizes a response action. Unobserved family, init system, enablement,
listings or metadata, malformed input, over-limit input and shell-reinterpreted names are blocking gaps.
"""
from __future__ import annotations

import re
from typing import Any

from app.ifupdown_hooks import _stat_ok

CONTRACT_VERSION = 1
REFERENCE = {
    'openrc': 'OpenRC 0.45 and master init.d/local.in and sh/openrc-run.sh.in',
}
RUNS_AS = 'root'
SERVICE = '/etc/init.d/local'
LOCAL_D = '/etc/local.d'
CONF_D = '/etc/conf.d'
PHASES = ('start', 'stop')
SUFFIX = {'start': '.start', 'stop': '.stop'}
COMMAND = ('eval', 'SCRIPT_PATH', '> /dev/null 2>&1 unless rc_verbose is set')
EVENTS = {
    'start': (('when the local service starts: at boot after every other service in a runlevel that enables it '
               '(depend: after *), or when an administrator runs rc-service local start'),),
    'stop': (('when the local service stops: at shutdown or reboot, when leaving a runlevel that enables it, '
              'or when an administrator runs rc-service local stop'),),
}
LEGACY_FUNCTION = {'start': 'local_start', 'stop': 'local_stop'}
APPLICABLE_FAMILIES = frozenset({'debian'})
BYTE_ORDER_SHELLS = frozenset({'dash', 'busybox'})
DIRECTORY_STATES = ('listed', 'absent', 'unreadable', 'not_directory')
MAX_ENTRIES = 1024
MAX_RUNLEVELS = 64
MAX_GAPS = 64
BLOCKING = frozenset({
    'input_malformed', 'family_not_observed', 'family_unsupported', 'init_system_not_observed',
    'enablement_not_observed', 'directory_not_observed', 'directory_unreadable', 'listing_incomplete',
    'too_many_entries', 'metadata_missing', 'symlink_target_unobserved', 'shell_reinterpreted',
    'conf_d_not_observed', 'conf_d_unreadable', 'gaps_truncated',
})
UNOBSERVED = (
    ('Script and conf.d contents are not read, so what a script or a local_start/local_stop function does is '
     'not assessed.'),
    '/etc/rc.conf, which openrc-run sources for every service, is not modeled.',
    'A locally modified /etc/init.d/local, or an OpenRC built with a different sysconfdir, is not detected.',
    'The locale bash would use to order glob results is not observed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'runs': 'The local service runs this file as root through eval with its full path as the command text.',
    'runs_as_shell_text': 'The name contains characters the shell treats specially, so eval parses the path as '
                          'command text and this file may not be what runs.',
    'hidden_name': 'The shell glob * does not match a name that starts with ".", so this file is not run.',
    'directory': 'A directory passes the root [ -x ] test in dash and busybox, but eval cannot run it, so it '
                 'is counted as a failure and nothing runs.',
    'not_executable': 'The file has no execute bit, so [ -x ] skips it.',
    'noexec_mount': 'The file is on a noexec mount, so it cannot be executed: bash skips it and dash or busybox '
                    'count a failure.',
    'stat_failed': 'The entry cannot be followed (for example a dangling symlink), so [ -x ] skips it.',
    'not_plain_file': 'Not a regular file, so it cannot be executed even when [ -x ] accepts it.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
RUNNING = ('runs', 'runs_as_shell_text')
# Characters dash, busybox ash or bash give meaning to inside an unquoted word, including brace expansion in bash.
_SHELL_SPECIAL = re.compile(r'[\s|&;<>()$`\\"\'*?\[{}\x00-\x1f\x7f]')
_RUNLEVEL = re.compile(r'^[A-Za-z0-9._-]{1,64}$')


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


def _outcome(entry: dict[str, Any], path: str, gaps: list[dict[str, Any]]) -> str:
    if entry['name'].startswith('.'):
        return 'hidden_name'
    if entry.get('type') == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', path)
            return 'unresolved'
        if entry['target'] is None:
            return 'stat_failed'
        stat = _stat_ok(entry['target'])
    else:
        stat = _stat_ok(entry)
    if stat is None:
        _gap(gaps, 'metadata_missing', path, 'Type, mode or mount flag metadata is missing or malformed.')
        return 'unresolved'
    if stat['type'] == 'directory':
        return 'directory'
    if stat['type'] == 'other':
        return 'not_plain_file'
    if not stat['mode'] & 0o111:
        return 'not_executable'
    if stat.get('noexec'):
        return 'noexec_mount'
    if stat.get('noexec') is None:
        _gap(gaps, 'mount_flags_unobserved', path, 'Reported as running; the noexec flag was not observed.')
    if _SHELL_SPECIAL.search(entry['name']):
        _gap(gaps, 'shell_reinterpreted', path, 'The local service passes this path to eval as command text.')
        return 'runs_as_shell_text'
    return 'runs'


def _collation_key(name: str) -> tuple[str, str]:
    # An approximation of glibc UTF-8 collation: case and punctuation are ignored first.
    return ''.join(ch for ch in name.casefold() if ch.isalnum()), name


def assess(local_d: Any = None, *, family: Any = None, init_system: Any = None, runlevels: Any = None,
           conf_d: Any = None, shell: Any = None) -> dict[str, Any]:
    """Resolve which /etc/local.d scripts the OpenRC local service runs as root from captured metadata.

    ``local_d`` is ``{'state': 'listed', 'truncated': bool, 'entries': [{'name', 'type':
    'file'|'directory'|'other'|'symlink', 'mode', 'noexec', 'target'}]}`` or a ``state`` of ``absent``,
    ``unreadable`` or ``not_directory``. A symlink entry's ``target`` is the followed metadata, or ``None`` when it
    cannot be followed. ``init_system`` is the observed PID 1 init (``'openrc'`` or another name). ``runlevels``
    lists the runlevels whose ``/etc/runlevels/RUNLEVEL/local`` exists. ``conf_d`` is ``{'state': 'listed',
    'names': [...]}`` for ``/etc/conf.d`` (only names starting with ``local`` matter), or a ``state`` of
    ``absent`` or ``unreadable``. ``shell`` is the shell OpenRC runs service scripts with (``'dash'``,
    ``'busybox'``, ``'bash'`` or another name).
    """
    gaps: list[dict[str, Any]] = []
    phases: dict[str, Any] = {}
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'runs_as': RUNS_AS,
        'service': SERVICE, 'directory': LOCAL_D, 'command': COMMAND, 'stops_on_failure': False,
        'service_fails_on_script_failure': False, 'applicability': 'unknown', 'enabled_runlevels': [],
        'runs_at_boot': None, 'shell': None, 'order': 'unknown', 'phases': phases, 'conf_d_sourced': [],
        'gaps': gaps, 'origin': 'not_assessed', 'not_a_verdict': NOT_A_VERDICT, 'unobserved': UNOBSERVED,
    }
    if family is None:
        _gap(gaps, 'family_not_observed')
    elif family not in APPLICABLE_FAMILIES:
        _gap(gaps, 'family_unsupported')
    if init_system is None:
        _gap(gaps, 'init_system_not_observed', None, 'Whether OpenRC is the init system is unknown.')
    elif not isinstance(init_system, str):
        _gap(gaps, 'input_malformed', None, 'Malformed init system.')
    elif init_system != 'openrc':
        result['applicability'] = 'not_applicable'
    elif family in APPLICABLE_FAMILIES:
        result['applicability'] = 'applicable'
    _enablement(runlevels, result, gaps)
    _shell(shell, result, gaps)
    if local_d is not None and not isinstance(local_d, dict):
        _gap(gaps, 'input_malformed', LOCAL_D, 'Malformed local.d metadata.')
        local_d = {}
    listing = _listing(local_d, gaps)
    for phase in PHASES:
        phases[phase] = _phase(phase, listing, result, gaps)
    result['conf_d_sourced'] = _conf_d(conf_d, gaps)
    if result['shell'] in BYTE_ORDER_SHELLS:
        result['order'] = 'byte'
    elif any(gap['code'] == 'order_locale_dependent' for gap in gaps):
        result['order'] = 'byte_assumed'
    elif listing is not None and listing['state'] == 'listed':
        result['order'] = 'byte'
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result


def _enablement(runlevels: Any, result: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    if runlevels is None:
        _gap(gaps, 'enablement_not_observed', '/etc/runlevels',
             'Whether the local service is in a runlevel, and so whether these scripts run at boot, is unknown.')
        return
    if not isinstance(runlevels, (list, tuple)) or len(runlevels) > MAX_RUNLEVELS \
            or not all(isinstance(r, str) and _RUNLEVEL.match(r) for r in runlevels):
        _gap(gaps, 'input_malformed', '/etc/runlevels', 'Malformed runlevel enablement.')
        return
    result['enabled_runlevels'] = sorted(set(runlevels))
    result['runs_at_boot'] = bool(runlevels)


def _shell(shell: Any, result: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    if shell is None:
        return
    if not isinstance(shell, str) or not shell:
        _gap(gaps, 'input_malformed', None, 'Malformed shell.')
        return
    result['shell'] = shell


def _listing(local_d: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if local_d is None:
        _gap(gaps, 'directory_not_observed', LOCAL_D)
        return None
    if local_d.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', LOCAL_D, 'Malformed local.d metadata.')
        return None
    if local_d['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', LOCAL_D)
    if local_d['state'] != 'listed':
        return local_d
    if local_d.get('truncated'):
        _gap(gaps, 'listing_incomplete', LOCAL_D)
    entries = local_d.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries' if isinstance(entries, list) else 'input_malformed', LOCAL_D)
        return {'state': 'listed', 'entries': []}
    seen: set[str] = set()
    valid = []
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or '/' in name or name in seen or name in ('.', '..') \
                or '\0' in name:
            _gap(gaps, 'input_malformed', LOCAL_D, 'An entry has a missing, invalid or duplicate name.')
            continue
        seen.add(name)
        valid.append(entry)
    return {'state': 'listed', 'entries': valid}


def _phase(phase: str, listing: dict[str, Any] | None, result: dict[str, Any],
           gaps: list[dict[str, Any]]) -> dict[str, Any]:
    suffix = SUFFIX[phase]
    out: dict[str, Any] = {'pattern': f'{LOCAL_D}/*{suffix}', 'state': 'not_observed', 'events': EVENTS[phase],
                           'legacy_function': LEGACY_FUNCTION[phase], 'scripts': [], 'run_order': []}
    if listing is None:
        return out
    out['state'] = listing['state']
    if listing['state'] != 'listed':
        return out
    scripts = []
    for entry in listing['entries']:
        # The glob needs at least the suffix; a name that is only the suffix starts with "." and is hidden.
        if not entry['name'].endswith(suffix):
            continue
        path = f'{LOCAL_D}/{entry["name"]}'
        outcome = _outcome(entry, path, gaps)
        scripts.append({'name': entry['name'], 'path': path, 'outcome': outcome, 'reason': REASONS[outcome]})
    scripts.sort(key=lambda s: s['name'].encode('utf-8', 'surrogatepass'))
    out['scripts'] = scripts
    running = [s for s in scripts if s['outcome'] in RUNNING]
    out['run_order'] = [s['path'] for s in running]
    names = [s['name'] for s in running]
    if result['shell'] not in BYTE_ORDER_SHELLS and len(names) > 1 \
            and (sorted(names, key=_collation_key) != names or not all(n.isascii() for n in names)):
        _gap(gaps, 'order_locale_dependent', out['pattern'],
             'The shell is not observed to be dash or busybox, and a locale-aware sort may order these '
             'scripts differently from the byte order shown.')
    return out


def _conf_d(conf_d: Any, gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if conf_d is None:
        _gap(gaps, 'conf_d_not_observed', CONF_D,
             'Whether /etc/conf.d/local or a runlevel-specific variant is sourced as root is unknown.')
        return []
    if not isinstance(conf_d, dict) or conf_d.get('state') not in ('listed', 'absent', 'unreadable'):
        _gap(gaps, 'input_malformed', CONF_D, 'Malformed conf.d metadata.')
        return []
    if conf_d['state'] == 'unreadable':
        _gap(gaps, 'conf_d_unreadable', CONF_D)
    if conf_d['state'] != 'listed':
        return []
    if conf_d.get('truncated'):
        _gap(gaps, 'listing_incomplete', CONF_D)
    names = conf_d.get('names')
    if not isinstance(names, list) or len(names) > MAX_ENTRIES \
            or not all(isinstance(n, str) and n and '/' not in n and '\0' not in n for n in names):
        _gap(gaps, 'input_malformed', CONF_D, 'Malformed conf.d names.')
        return []
    sourced = []
    for name in sorted(set(names)):
        if name == 'local':
            when = 'for any runlevel without its own conf.d/local.RUNLEVEL file'
        elif name.startswith('local.') and len(name) > len('local.'):
            when = f'when the local service starts or stops in runlevel "{name[len("local."):]}"'
        else:
            continue
        sourced.append({'path': f'{CONF_D}/{name}', 'sourced_by': 'openrc-run', 'runs_as': RUNS_AS,
                        'when': when, 'legacy_functions': ('local_start', 'local_stop'),
                        'reason': 'openrc-run sources this file as root before the service runs; a local_start '
                                  'or local_stop function defined in it is called after the scripts.'})
    return sourced
