"""Pure libvirt hook-script contract (roadmap F slice, #1455).

libvirt runs ``/etc/libvirt/hooks/<driver>`` and the executable entries of
``/etc/libvirt/hooks/<driver>.d/`` synchronously, as the daemon's own user,
whenever the daemon starts, reloads or shuts down and whenever a guest or
virtual network changes state. System-mode daemons (``libvirtd``,
``virtqemud``, ``virtnetworkd`` and the other modular daemons) run as root. Each
script receives the object name, operation, sub-operation and an extra
argument on its command line and the domain or network XML on stdin.

This module turns captured ``stat`` results and directory listings into the
scripts libvirt runs. It performs no I/O, never runs a script and never
authorizes a response action.

The rules follow ``src/util/virhook.c`` and ``src/util/virfile.c`` in libvirt
10.0.0 (Ubuntu 24.04):

- The drivers are ``daemon``, ``qemu``, ``lxc``, ``network``, ``libxl`` and
  ``bhyve`` (``virHookDriver``). No other name in the hooks directory runs.
- ``virFileIsExecutable`` uses ``stat``, so it follows symlinks, and accepts
  only a regular file with at least one of the ``0111`` mode bits. It ignores
  ACLs, ``noexec`` and the owner.
- ``virHookCheck`` decides whether a driver has hooks. It does if ``<driver>``
  is executable. Otherwise it continues only if ``<driver>.d`` is a directory,
  or is an executable regular file. A directory needs at least one executable
  entry. An executable regular ``<driver>.d`` fails ``opendir`` with
  ``ENOTDIR``, so the check returns -1 and ``virHookInitialize`` stops before
  the remaining drivers.
- ``virHookInitialize`` runs at daemon start, and ``virHookCall`` reruns it
  for the ``daemon`` driver's ``reload`` and ``shutdown`` operations. Between
  those points, a driver with no hooks at the last check runs nothing even if
  hooks have been added since.
- ``virHookCall`` runs ``<driver>`` first if it is executable. It then reads
  ``<driver>.d`` with ``readdir``, which skips only ``.`` and ``..``, so hidden
  names are included. It does not recurse. It keeps executable entries, sorts
  them with ``strcmp`` on the full path, and runs every one even if an earlier
  script failed. The call returns the lowest result. A ``<driver>.d`` that
  exists but cannot be opened as a directory makes the call return an error
  after the main script has run.
- Each script runs as ``<script> <id> <op> <subop> <extra>`` with ``-`` for a
  missing sub-operation or extra argument. When the caller wants output, the
  last non-empty successful output is passed as the next script's stdin.

Fail-closed rules: an unobserved ``stat`` result, listing or mode, an
over-limit or malformed listing and a failed hook initialization mark the
result incomplete. Affected drivers are ``unresolved`` and are never reported
as running nothing. ``origin`` is always ``not_assessed`` and no result is a
safety verdict.
"""
from __future__ import annotations

import posixpath
from collections.abc import Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('10.0.0',)
HOOK_DIR = '/etc/libvirt/hooks'
DRIVERS = ('daemon', 'qemu', 'lxc', 'network', 'libxl', 'bhyve')
OPERATIONS = {
    'daemon': ('start', 'shutdown', 'reload'),
    'qemu': ('start', 'stopped', 'prepare', 'release', 'migrate', 'started', 'reconnect', 'attach', 'restore'),
    'lxc': ('start', 'stopped', 'prepare', 'release', 'started', 'reconnect'),
    'network': ('start', 'started', 'stopped', 'port-created', 'port-deleted', 'updated'),
    'libxl': ('start', 'stopped', 'prepare', 'release', 'migrate', 'started', 'reconnect'),
    'bhyve': ('start', 'stopped', 'prepare', 'release', 'started'),
}
SUBOPS = ('-', 'begin', 'end')
TYPES = ('file', 'directory', 'other', 'missing')
MAX_ENTRIES = 1024
MAX_NAME = 255
MAX_GAPS = 64

DRIVER_STATUSES = ('runs', 'no_hooks', 'unresolved')
BLOCKING = frozenset({
    'stat_not_observed', 'mode_not_observed', 'type_not_observed', 'listing_not_observed', 'listing_unreadable',
    'entries_over_limit', 'malformed_entry', 'duplicate_entry', 'hook_dir_relative', 'hook_dir_malformed',
    'listing_truncated', 'listing_unsupported', 'initialize_failed', 'gaps_truncated',
})
LISTING_KEYS = frozenset({'state', 'names', 'truncated'})
LISTING_STATES = (None, 'listed', 'unreadable')
NOT_OBSERVED = (
    'Whether libvirt is installed and which daemons run: the monolithic libvirtd or modular daemons such as '
    'virtqemud and virtnetworkd. Each daemon process runs the daemon hook for its own start, reload and shutdown.',
    'Whether the daemon has started, reloaded or shut down since the files changed. Hook presence is cached '
    'until then.',
    'Session-mode daemons, which read the same directory but run hooks as the session user.',
    'Which operations a failing hook aborts or rewrites (for example qemu prepare/start and migrate/restore XML '
    'output); this contract reports what runs, not each caller\'s reaction to its result.',
    'How the daemon reacts when hook initialization fails.',
    'The contents of the scripts and of any programs they run.',
    'Whether a build uses a sysconfdir other than /etc.',
)


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'path': path, 'detail': detail[:240], 'blocking': code in BLOCKING})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'path': None, 'detail': 'Further gaps were not recorded.',
                     'blocking': True})


def _key(path: str) -> bytes:
    return path.encode('utf-8', 'surrogateescape')


def _encodable(value: str) -> bool:
    """Whether ``value`` maps back to filename bytes.

    Bytes that are not UTF-8 arrive as surrogateescape code points (U+DC80 to U+DCFF) and are valid. Any other
    lone surrogate cannot come from a Linux filename, so the capture is malformed.
    """
    try:
        _key(value)
    except UnicodeEncodeError:
        return False
    return True


def _listing_names(listing: Any) -> tuple[Any, str | None, str]:
    """Return ``(names, gap_code, detail)`` for a captured directory listing.

    A listing is a list of names, or a mapping with ``names`` and optional ``state`` (``listed`` or
    ``unreadable``) and ``truncated`` keys. A truncated, unreadable or unsupported listing yields no names and
    a gap code, because a partial listing can omit executable hooks.
    """
    if isinstance(listing, Mapping):
        if not set(listing) <= LISTING_KEYS or listing.get('state') not in LISTING_STATES:
            return None, 'listing_unsupported', 'The listing has an unsupported shape or state.'
        if listing.get('state') == 'unreadable':
            return None, 'listing_unreadable', 'The directory could not be listed; opendir would fail.'
        truncated = listing.get('truncated', False)
        if truncated is not False and truncated is not None:
            return None, 'listing_truncated', 'The listing is marked truncated, so entries may be missing.'
        names = listing.get('names')
    else:
        names = listing
    if not isinstance(names, (list, tuple)):
        return None, 'listing_not_observed', 'The listing has no list of names.'
    if len(names) > MAX_ENTRIES:
        return None, 'entries_over_limit', f'More than {MAX_ENTRIES} entries.'
    return names, None, ''


def _stat(stats: Mapping[str, Any], path: str, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the followed ``stat`` observation for ``path``, or ``None`` with a blocking gap."""
    observed = stats.get(path)
    if not isinstance(observed, Mapping):
        _gap(gaps, 'stat_not_observed', path, 'No stat result was supplied.')
        return None
    kind = observed.get('type')
    if kind not in TYPES:
        _gap(gaps, 'type_not_observed', path, 'The followed file type was not observed.')
        return None
    mode = observed.get('mode')
    if kind == 'file' and (not isinstance(mode, int) or isinstance(mode, bool) or mode < 0):
        _gap(gaps, 'mode_not_observed', path, 'The mode of a regular file was not observed.')
        return None
    return {'type': kind, 'mode': mode if kind == 'file' else None, 'symlink': bool(observed.get('symlink'))}


def is_executable(observed: Mapping[str, Any] | None) -> bool:
    """Emulate ``virFileIsExecutable`` for a followed ``stat`` observation."""
    return bool(observed and observed.get('type') == 'file' and (observed.get('mode') or 0) & 0o111)


def _skip_reason(observed: Mapping[str, Any]) -> str:
    kind = observed['type']
    if kind == 'missing':
        return 'dangling_symlink' if observed['symlink'] else 'missing'
    if kind == 'file':
        return 'not_executable'
    return kind


def _dropins(driver: str, dir_path: str, stats: Mapping[str, Any], listings: Mapping[str, Any],
             gaps: list[dict[str, Any]]) -> dict[str, Any]:
    """Read ``<driver>.d`` as ``virHookCall`` does."""
    listing = listings.get(dir_path)
    if listing is None:
        _gap(gaps, 'listing_not_observed', dir_path, f'{dir_path[:160]} is a directory, but it was not listed.')
        return {'resolved': False, 'scripts': [], 'skipped': []}
    names, code, detail = _listing_names(listing)
    if code is not None:
        _gap(gaps, code, dir_path, f'{dir_path[:160]}: {detail}')
        return {'resolved': False, 'scripts': [], 'skipped': []}
    resolved = True
    seen: set[str] = set()
    scripts: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for name in names:
        if (not isinstance(name, str) or not name or '/' in name or '\x00' in name
                or not _encodable(name) or len(_key(name)) > MAX_NAME):
            _gap(gaps, 'malformed_entry', dir_path, 'A directory entry has no usable name.')
            resolved = False
            continue
        if name in ('.', '..'):
            continue
        if name in seen:
            _gap(gaps, 'duplicate_entry', dir_path, f'{name[:120]} was listed more than once.')
            resolved = False
            continue
        seen.add(name)
        path = f'{dir_path}/{name}'
        observed = _stat(stats, path, gaps)
        if observed is None:
            resolved = False
            skipped.append({'path': path, 'name': name, 'reason': 'not_observed'})
            continue
        if is_executable(observed):
            scripts.append({'driver': driver, 'path': path, 'name': name, 'kind': 'dropin',
                            'symlink': observed['symlink'], 'hidden': name.startswith('.')})
        else:
            skipped.append({'path': path, 'name': name, 'reason': _skip_reason(observed),
                            'symlink': observed['symlink']})
    # g_slist_sort(entries, strcmp) on the full path; every path shares the directory prefix.
    scripts.sort(key=lambda s: _key(s['path']))
    skipped.sort(key=lambda s: _key(s['path']))
    return {'resolved': resolved, 'scripts': scripts, 'skipped': skipped}


def _driver(driver: str, hook_dir: str, stats: Mapping[str, Any], listings: Mapping[str, Any],
            gaps: list[dict[str, Any]]) -> dict[str, Any]:
    path = posixpath.join(hook_dir, driver)
    dir_path = f'{path}.d'
    record: dict[str, Any] = {
        'driver': driver, 'status': 'unresolved', 'hooks_present': None, 'check_error': False,
        'call_error_after_main': False, 'operations': list(OPERATIONS[driver]), 'scripts': [], 'skipped': [],
        'main': {'path': path, 'state': None}, 'dropin_dir': {'path': dir_path, 'state': None},
        'origin': 'not_assessed',
    }
    local: list[dict[str, Any]] = []
    main = _stat(stats, path, local)
    directory = _stat(stats, dir_path, local)
    for gap in local:
        _gap(gaps, gap['code'], gap['path'], gap['detail'])
    if main is None or directory is None:
        return record
    main_runs = is_executable(main)
    record['main']['state'] = 'runs' if main_runs else _skip_reason(main)
    record['main']['symlink'] = main['symlink']
    if main['type'] != 'missing' and not main_runs:
        record['skipped'].append({'path': path, 'name': driver, 'reason': _skip_reason(main),
                                  'symlink': main['symlink']})
    kind = directory['type']
    dropins: dict[str, Any] = {'resolved': True, 'scripts': [], 'skipped': []}
    if kind == 'directory':
        record['dropin_dir']['state'] = 'directory'
        dropins = _dropins(driver, dir_path, stats, listings, gaps)
    elif kind == 'missing':
        record['dropin_dir']['state'] = 'missing'
    else:
        record['dropin_dir']['state'] = 'executable_file' if is_executable(directory) else f'not_directory_{kind}'
        if main_runs:
            # virHookCall: the main script has already run when opendir fails with ENOTDIR.
            record['call_error_after_main'] = True
            _gap(gaps, 'dropin_not_directory', dir_path, f'{dir_path[:160]} is not a directory, so every '
                 f'{driver} hook call returns an error after the main script runs.')
        elif is_executable(directory):
            record['check_error'] = True
    record['skipped'].extend(dropins['skipped'])
    if not dropins['resolved']:
        return record
    if record['check_error']:
        return record
    scripts = ([{'driver': driver, 'path': path, 'name': driver, 'kind': 'main', 'symlink': main['symlink'],
                 'hidden': False}] if main_runs else []) + dropins['scripts']
    for order, script in enumerate(scripts, 1):
        script.update(order=order, argv=[script['path'], '<id>', '<op>', '<subop>', '<extra>'],
                      stdin='object_xml', runs_as='daemon_user', origin='not_assessed')
    present = bool(scripts)
    record.update(status='runs' if present else 'no_hooks', hooks_present=present, scripts=scripts)
    return record


def evaluate(stats: Any, listings: Any = None, *, hook_dir: str = HOOK_DIR,
             hook_dir_listing: Any = None) -> dict[str, Any]:
    """Resolve which libvirt hook scripts run, for which driver and in which order.

    ``stats`` maps an absolute path to its followed ``stat`` observation:
    ``{'type': 'file' | 'directory' | 'other' | 'missing', 'mode': 0o755, 'symlink': bool}``. A dangling
    symlink is ``{'type': 'missing', 'symlink': True}``. Every ``<driver>`` and ``<driver>.d`` path under
    ``hook_dir`` must be observed, as must every entry of a ``<driver>.d`` directory. ``listings`` maps each
    ``<driver>.d`` directory to its entry names, or to ``{'state': 'unreadable'}``. ``hook_dir_listing``
    optionally lists ``hook_dir`` itself, to report names that never run.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'format': 'libvirt_hooks', 'source_versions': list(SOURCE_VERSIONS),
        'complete': False, 'hook_dir': hook_dir, 'initialize_failed': False, 'drivers': [], 'scripts': [],
        'not_run': [],
        'execution': {
            'argv': ['<script>', '<id>', '<op>', '<subop>', '<extra>'], 'missing_argument': '-',
            'subops': list(SUBOPS), 'stdin': 'domain or network XML', 'synchronous': True,
            'runs_after_failure': True, 'output_chained': True,
            'runs_as': 'the daemon user: root for system-mode daemons',
            'presence_cached_until': 'daemon start, reload or shutdown',
        },
        'origin': 'not_assessed', 'gaps': gaps, 'not_observed': list(NOT_OBSERVED),
    }
    if not isinstance(hook_dir, str) or not hook_dir.startswith('/'):
        _gap(gaps, 'hook_dir_relative', None, 'The hooks directory must be an absolute path.')
        return _finish(result)
    if '\x00' in hook_dir or not _encodable(hook_dir):
        result['hook_dir'] = None
        _gap(gaps, 'hook_dir_malformed', None, 'The hooks directory is not a usable filename.')
        return _finish(result)
    hook_dir = posixpath.normpath(hook_dir)
    result['hook_dir'] = hook_dir
    stats = stats if isinstance(stats, Mapping) else {}
    listings = listings if isinstance(listings, Mapping) else {}
    failed_at: str | None = None
    for driver in DRIVERS:
        if failed_at is not None:
            record = {'driver': driver, 'status': 'unresolved', 'hooks_present': None, 'check_error': False,
                      'call_error_after_main': False, 'operations': list(OPERATIONS[driver]), 'scripts': [],
                      'skipped': [], 'main': {'path': posixpath.join(hook_dir, driver), 'state': None},
                      'dropin_dir': {'path': posixpath.join(hook_dir, driver) + '.d', 'state': None},
                      'not_checked_after': failed_at, 'origin': 'not_assessed'}
        else:
            record = _driver(driver, hook_dir, stats, listings, gaps)
            if record['check_error']:
                failed_at = driver
                result['initialize_failed'] = True
                _gap(gaps, 'initialize_failed', record['dropin_dir']['path'], f'{driver}.d is an executable '
                     'regular file, so virHookCheck fails and hook initialization stops before the later drivers.')
        result['drivers'].append(record)
        result['scripts'].extend(record['scripts'])
    if hook_dir_listing is not None:
        names, code, detail = _listing_names(hook_dir_listing)
        if code is None:
            known = set(DRIVERS) | {f'{d}.d' for d in DRIVERS}
            usable = {n for n in names if isinstance(n, str) and n and '/' not in n and '\x00' not in n
                      and _encodable(n)}
            if len(usable) != len({n for n in names if isinstance(n, str)}) or any(
                    not isinstance(n, str) for n in names):
                _gap(gaps, 'hook_dir_listing_unusable', hook_dir, 'Some hooks directory entries have no usable '
                     'name, so they are not reported. Driver hooks are resolved from their own stat results.')
            for name in sorted(usable, key=_key):
                if name in ('.', '..') or name in known:
                    continue
                result['not_run'].append({'path': posixpath.join(hook_dir, name), 'name': name,
                                          'reason': 'not_a_driver_hook'})
        else:
            _gap(gaps, 'hook_dir_listing_unusable', hook_dir, 'The hooks directory listing could not be used to '
                 f'report names that never run: {detail}')
    return _finish(result)


def _finish(result: dict[str, Any]) -> dict[str, Any]:
    result['complete'] = not any(g['blocking'] for g in result['gaps'])
    return result
