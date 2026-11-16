"""Pure NetworkManager dispatcher script contract (roadmap F slice, #962).

Takes captured, read-only metadata for the files in NetworkManager's
``dispatcher.d`` directories and says which scripts ``nm-dispatcher`` would run
as root, in what order and for which event group, and why the others are not
run. It never reads a script's contents.

Semantics follow ``src/nm-dispatcher/nm-dispatcher.c`` (``check_filename``,
``check_file``, ``check_permissions``, ``find_scripts`` and
``script_must_wait``), read in NetworkManager 1.36.6 and 1.46.0, which agree
except for device handlers:

* The scanned directories are ``/usr/lib/NetworkManager/dispatcher.d`` and
  ``/etc/NetworkManager/dispatcher.d``, plus their ``pre-up.d`` and
  ``pre-down.d`` subdirectories. ``pre-up``/``vpn-pre-up`` events use
  ``pre-up.d``, ``pre-down``/``vpn-pre-down`` use ``pre-down.d`` and every other
  event uses the top directory.
* A name is skipped when it starts with ``.``, ends with ``~``, ``.rpmsave``,
  ``.rpmorig``, ``.rpmnew`` or ``.swp``, or its last ``.dpkg-`` is followed by no
  further dot (``x.dpkg-old``).
* An ``/etc`` name replaces the same name under ``/usr/lib`` before any file
  check, so an unusable ``/etc`` entry masks the ``/usr/lib`` script.
* A symlink whose target text is exactly ``/dev/null``, a path that cannot be
  resolved, a non-regular file and an empty file are skipped silently.
* A script must be owned by uid 0, not writable by group or other, not set-UID
  and executable by its owner. Symlinks are followed for these checks.
* Scripts run in byte order of their names.
* A script that is a symlink whose target's directory resolves to a path ending
  in ``/no-wait.d`` runs without blocking the scripts after it.
* From 1.46, ``device/<name>`` is a device handler run only for a generic
  connection that names it. ``/etc`` is tried first and ``/usr/lib`` is used
  when the ``/etc`` file fails the file check; there is no masking and no name
  filter.

It performs no I/O, never runs a command and never authorizes a response
action. Missing or malformed metadata, an unobserved directory or symlink
target, an unobserved or unsupported NetworkManager version and over-limit input
are explicit blocking gaps and are never reported as covered.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE_VERSIONS = ('1.36.6', '1.46.0')
MIN_VERSION = (1, 36)
DEVICE_HANDLER_VERSION = (1, 46)
MAX_FILES = 1024
MAX_PATH = 4096
MAX_GAPS = 64

ETC_BASE = '/etc/NetworkManager/dispatcher.d'
LIB_BASE = '/usr/lib/NetworkManager/dispatcher.d'
BASES = (LIB_BASE, ETC_BASE)  # nm-dispatcher reads /usr/lib first; /etc then replaces equal names
GROUPS = {'': 'main', 'pre-up.d': 'pre_up', 'pre-down.d': 'pre_down'}
GROUP_EVENTS = {
    'main': 'Every event except pre-up, vpn-pre-up, pre-down, vpn-pre-down and device-handler calls.',
    'pre_up': 'pre-up and vpn-pre-up events.',
    'pre_down': 'pre-down and vpn-pre-down events.',
}
SCANNED_DIRS = tuple(posixpath.join(base, sub) if sub else base for base in BASES for sub in GROUPS)
DEVICE_DIRS = tuple(posixpath.join(base, 'device') for base in BASES)
BAD_SUFFIXES = ('~', '.rpmsave', '.rpmorig', '.rpmnew', '.swp')
FILE_TYPES = ('file', 'symlink', 'directory', 'other')
BLOCKING = frozenset({
    'input_malformed', 'too_many_files', 'duplicate_path', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'version_not_observed', 'version_unsupported',
    'device_handler_version_unverified', 'gaps_truncated',
})
UNOBSERVED = (
    'Script contents, interpreters and anything a script runs are not read.',
    'Whether NetworkManager and NetworkManager-dispatcher.service are installed, enabled and running is not observed.',
    'Which network events occur, and which connections name a device handler, is not observed.',
    'A NetworkManager build with non-default configuration or library directories is not detected.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'runs': 'nm-dispatcher runs this script as root.',
    'name_filtered': 'The name starts with a dot or has a backup or package-manager suffix, so it is not considered.',
    'overridden': 'A script with the same name under /etc/NetworkManager runs instead.',
    'masked': 'An entry with the same name under /etc/NetworkManager replaces this script and does not run itself.',
    'dev_null_link': 'A symlink to /dev/null is skipped.',
    'dangling_symlink': 'The symlink target does not exist, so the entry is skipped.',
    'not_regular': 'Only regular files are run.',
    'empty_file': 'An empty file is skipped.',
    'not_root_owned': 'Rejected: not owned by root.',
    'unsafe_mode': 'Rejected: writable by group or other, or set-UID.',
    'not_owner_executable': 'Rejected: not executable by its owner.',
    'no_wait_target': 'Files in no-wait.d run only through a symlink from a scanned directory.',
    'outside_scanned_directories': 'nm-dispatcher does not scan this location.',
    'outside_dispatcher_directories': 'The path is not under a NetworkManager dispatcher.d directory.',
    'device_handler': 'Device handler: runs as root only for a generic connection that names it.',
    'device_handler_fallback': 'Device handler under /usr/lib, used because the /etc file with this name is '
                               'unusable. Runs as root only for a generic connection that names it.',
    'device_handlers_unsupported': 'This NetworkManager version has no device handlers.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_VERSION = re.compile(r'(\d{1,4})\.(\d{1,4})(?:\.(\d{1,6}))?(?:[-+~.][0-9A-Za-z.+~-]{0,64})?')


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


def name_considered(name: str) -> bool:
    """Return whether ``check_filename`` lets nm-dispatcher consider this directory entry."""
    if not name or name[0] == '.':
        return False
    if name.endswith(BAD_SUFFIXES):
        return False
    index = name.rfind('.dpkg-')
    return index < 0 or '.' in name[index + 1:]


def _int(value: Any, upper: int | None = None) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0 and (upper is None or value <= upper)


def _valid_path(path: Any) -> bool:
    return (isinstance(path, str) and 1 < len(path) <= MAX_PATH and path.startswith('/')
            and not _CONTROL.search(path) and posixpath.normpath(path) == path and not path.startswith('//'))


def _stat(meta: Any) -> dict[str, Any] | None:
    """Validate one stat-like mapping (``type``, ``mode``, ``uid``, ``size``)."""
    if not isinstance(meta, dict) or meta.get('type') not in FILE_TYPES or meta.get('type') == 'symlink':
        return None
    if not (_int(meta.get('mode'), 0o7777) and _int(meta.get('uid')) and _int(meta.get('size'))):
        return None
    return {'type': meta['type'], 'mode': meta['mode'], 'uid': meta['uid'], 'size': meta['size']}


def _check_file(entry: dict[str, Any]) -> tuple[str, str]:
    """Apply ``check_file``. Returns ``(status, reason_code)`` with status ``runs``, ``ignored`` or ``rejected``."""
    if entry['type'] == 'symlink':
        if entry['link_target'] == '/dev/null':
            return 'ignored', 'dev_null_link'
        if entry['target'] is None:
            return 'ignored', 'dangling_symlink'
        stat = entry['target']
    else:
        stat = entry
    if stat['type'] != 'file':
        return 'ignored', 'not_regular'
    if stat['size'] == 0:
        return 'ignored', 'empty_file'
    if stat['uid'] != 0:
        return 'rejected', 'not_root_owned'
    if stat['mode'] & 0o4022:
        return 'rejected', 'unsafe_mode'
    if not stat['mode'] & 0o100:
        return 'rejected', 'not_owner_executable'
    return 'runs', 'runs'


def _wait(entry: dict[str, Any]) -> tuple[bool, str | None]:
    """Apply ``script_must_wait``. Returns ``(wait, basis)``; basis is ``None`` for a non-symlink."""
    if entry['type'] != 'symlink':
        return True, None
    observed = entry.get('link_dir_realpath')
    if observed is not None:
        return not observed.endswith('/no-wait.d'), 'observed'
    link = entry['link_target']
    if not link.startswith('/'):
        link = posixpath.join(posixpath.dirname(entry['path']), link)
    return not posixpath.normpath(posixpath.dirname(link)).endswith('/no-wait.d'), 'lexical'


def _parse_version(version: Any, gaps: list[dict[str, Any]]) -> tuple[int, int] | None:
    if version is None:
        _gap(gaps, 'version_not_observed', detail='The NetworkManager version was not supplied.')
        return None
    match = _VERSION.fullmatch(version) if isinstance(version, str) else None
    if match is None:
        _gap(gaps, 'version_unsupported', detail='The NetworkManager version is not a recognised version string.')
        return None
    parsed = (int(match.group(1)), int(match.group(2)))
    if parsed < MIN_VERSION:
        _gap(gaps, 'version_unsupported',
             detail='The rules were checked from NetworkManager 1.36; older versions are not assessed.')
        return None
    if parsed > DEVICE_HANDLER_VERSION:
        _gap(gaps, 'version_newer_than_reference',
             detail='The rules were checked up to NetworkManager 1.46; a newer version may differ.')
    return parsed


def _directories(directories: Any, gaps: list[dict[str, Any]]) -> dict[str, str]:
    states: dict[str, str] = {}
    known = SCANNED_DIRS + DEVICE_DIRS
    for item in directories if isinstance(directories, (list, tuple)) else ():
        path = item.get('path') if isinstance(item, dict) else None
        state = item.get('state') if isinstance(item, dict) else None
        if path not in known or state not in ('listed', 'absent', 'unreadable') or path in states:
            _gap(gaps, 'input_malformed', detail='A directory observation is malformed, unknown or repeated.')
            continue
        states[path] = state
    if directories is not None and not isinstance(directories, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='Directory observations must be a list.')
    for path in known:
        if path not in states:
            _gap(gaps, 'directory_not_observed', path, 'No listing result was supplied for this directory.')
        elif states[path] == 'unreadable':
            _gap(gaps, 'directory_unreadable', path, 'The directory exists but could not be listed.')
    return states


def _normalize(item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Validate one file observation. Returns ``None`` after recording ``input_malformed``."""
    if not isinstance(item, dict) or not _valid_path(item.get('path')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', detail='A file observation has no valid absolute path or type.')
        return None
    entry: dict[str, Any] = {'path': item['path'], 'type': item['type'], 'resolved': True}
    if item['type'] == 'symlink':
        link = item.get('link_target')
        if not isinstance(link, str) or not link or len(link) > MAX_PATH or '\x00' in link:
            entry['resolved'] = False
            return entry
        entry['link_target'] = link
        realdir = item.get('link_dir_realpath')
        entry['link_dir_realpath'] = realdir if _valid_path(realdir) or realdir == '/' else None
        if link == '/dev/null':
            entry['target'] = None
        elif 'target' not in item:
            entry['resolved'] = False
        elif item['target'] is None:
            entry['target'] = None
        else:
            entry['target'] = _stat(item['target'])
            entry['resolved'] = entry['target'] is not None
        return entry
    stat = _stat(item)
    if stat is None:
        entry['resolved'] = False
    else:
        entry.update(stat)
    return entry


def _place(path: str) -> tuple[str, str, str] | None:
    """Return ``(base, kind, name)``; kind is a group key, ``device``, ``no_wait`` or ``other``."""
    for base in BASES:
        if not path.startswith(base + '/'):
            continue
        parts = path[len(base) + 1:].split('/')
        if len(parts) == 1:
            return base, 'main', parts[0]
        if len(parts) == 2 and parts[0] in GROUPS:
            return base, GROUPS[parts[0]], parts[1]
        if len(parts) == 2 and parts[0] == 'device':
            return base, 'device', parts[1]
        return base, 'no_wait' if parts[0] == 'no-wait.d' else 'other', parts[-1]
    return None


def _record(entry: dict[str, Any], status: str, reason: str, **extra: Any) -> dict[str, Any]:
    record = {'path': entry['path'], 'type': entry['type'], 'status': status, 'reason_code': reason,
              'reason': REASONS[reason]}
    if entry.get('link_target') is not None:
        record['link_target'] = entry['link_target']
    record.update(extra)
    return record


def evaluate(files: Any, *, version: Any = None, directories: Any = None) -> dict[str, Any]:
    """Resolve which dispatcher scripts NetworkManager runs from supplied metadata.

    ``files`` is a list of mappings with ``path`` (absolute, normalized), ``type`` (``file``,
    ``symlink``, ``directory`` or ``other``) and, for anything but a symlink, ``mode`` (permission
    bits including set-UID, 0–0o7777), ``uid`` and ``size``. A symlink carries ``link_target`` (the
    raw link text), ``target`` (the same stat fields for what it resolves to, or ``None`` when it
    resolves to nothing) and optionally ``link_dir_realpath`` (the resolved directory of the link
    target). ``directories`` is a list of ``{'path', 'state'}`` with state ``listed``, ``absent`` or
    ``unreadable`` for each scanned directory. ``version`` is the NetworkManager version string.
    """
    gaps: list[dict[str, Any]] = []
    parsed_version = _parse_version(version, gaps)
    states = _directories(directories, gaps)
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference_versions': list(REFERENCE_VERSIONS),
        'files': [], 'groups': {key: {'events': GROUP_EVENTS[key], 'scripts': []} for key in GROUP_EVENTS},
        'device_handlers': [], 'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed',
        'note': NOT_A_VERDICT,
    }
    if not isinstance(files, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='File observations must be a list.')
        files = ()
    if len(files) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'Only the first {MAX_FILES} file observations are assessed.')
        files = files[:MAX_FILES]

    seen: set[str] = set()
    placed: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}  # (kind, name) -> base -> entry
    records: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for item in files:
        entry = _normalize(item, gaps)
        if entry is None:
            continue
        path = entry['path']
        if path in seen:
            _gap(gaps, 'duplicate_path', path, 'The path was supplied more than once; the first is used.')
            continue
        seen.add(path)
        order.append(path)
        place = _place(path)
        if place is None:
            records[path] = _record(entry, 'ignored', 'outside_dispatcher_directories')
            continue
        base, kind, name = place
        directory = posixpath.dirname(path)
        if kind in ('main', 'pre_up', 'pre_down', 'device') and states.get(directory) == 'absent':
            _gap(gaps, 'input_malformed', path, 'A file was supplied for a directory reported absent.')
        if kind == 'no_wait':
            records[path] = _record(entry, 'ignored', 'no_wait_target')
        elif kind == 'other':
            records[path] = _record(entry, 'ignored', 'outside_scanned_directories')
        elif kind != 'device' and not name_considered(name):
            records[path] = _record(entry, 'ignored', 'name_filtered')
        else:
            placed.setdefault((kind, name), {})[base] = entry

    def unresolved(entry: dict[str, Any]) -> dict[str, Any]:
        code = 'symlink_target_unobserved' if entry['type'] == 'symlink' else 'metadata_missing'
        _gap(gaps, code, entry['path'], 'Required metadata for this entry was not supplied or is malformed.')
        return _record(entry, 'unresolved', 'unresolved')

    lexical_wait = False
    runnable: dict[str, list[tuple[bytes, dict[str, Any]]]] = {key: [] for key in GROUP_EVENTS}
    for (kind, name), by_base in placed.items():
        etc, lib = by_base.get(ETC_BASE), by_base.get(LIB_BASE)
        if kind == 'device':
            if parsed_version is None or parsed_version < DEVICE_HANDLER_VERSION:
                for entry in by_base.values():
                    if parsed_version is not None and parsed_version == MIN_VERSION:
                        records[entry['path']] = _record(entry, 'ignored', 'device_handlers_unsupported')
                    else:
                        if parsed_version is not None:
                            _gap(gaps, 'device_handler_version_unverified', entry['path'],
                                 'Device handlers were checked in NetworkManager 1.46 (present) and 1.36 '
                                 '(absent) only.')
                        records[entry['path']] = _record(entry, 'unresolved', 'unresolved')
                continue
            etc_runs = False
            if etc is not None:
                if not etc['resolved']:
                    records[etc['path']] = unresolved(etc)
                    if lib is not None:
                        records[lib['path']] = _record(lib, 'unresolved', 'unresolved')
                    continue
                status, reason = _check_file(etc)
                etc_runs = status == 'runs'
                records[etc['path']] = _record(etc, status, 'device_handler' if etc_runs else reason)
                if etc_runs:
                    result['device_handlers'].append({'name': name, 'path': etc['path'],
                                                      'conditions': ['connection_names_handler']})
            if lib is not None:
                if etc_runs:
                    records[lib['path']] = _record(lib, 'overridden', 'overridden', overridden_by=etc['path'])
                elif not lib['resolved']:
                    records[lib['path']] = unresolved(lib)
                else:
                    status, reason = _check_file(lib)
                    runs = status == 'runs'
                    code = ('device_handler_fallback' if etc is not None else 'device_handler') if runs else reason
                    records[lib['path']] = _record(lib, status, code)
                    if runs:
                        result['device_handlers'].append({'name': name, 'path': lib['path'],
                                                          'conditions': ['connection_names_handler']})
            continue

        winner = etc if etc is not None else lib
        assert winner is not None
        if not winner['resolved']:
            records[winner['path']] = unresolved(winner)
            if etc is not None and lib is not None:
                records[lib['path']] = _record(lib, 'unresolved', 'unresolved')
            continue
        status, reason = _check_file(winner)
        extra: dict[str, Any] = {}
        if status == 'runs':
            wait, basis = _wait(winner)
            lexical_wait = lexical_wait or basis == 'lexical'
            extra = {'group': kind, 'wait': wait}
            if basis is not None:
                extra['wait_basis'] = basis
            script = {'name': name, 'path': winner['path'], 'wait': wait}
            if winner.get('link_target') is not None:
                script['link_target'] = winner['link_target']
            runnable[kind].append((name.encode('utf-8', 'surrogateescape'), script))
        if etc is not None and lib is not None:
            if status != 'runs':
                extra['masks'] = lib['path']
            records[lib['path']] = _record(lib, 'overridden' if status == 'runs' else 'masked',
                                           'overridden' if status == 'runs' else 'masked',
                                           overridden_by=etc['path'])
        records[winner['path']] = _record(winner, status, reason, **extra)

    for key, scripts in runnable.items():
        for index, (_, script) in enumerate(sorted(scripts, key=lambda pair: pair[0])):
            result['groups'][key]['scripts'].append({'order': index, **script})
    result['device_handlers'].sort(key=lambda handler: handler['name'].encode('utf-8', 'surrogateescape'))
    if lexical_wait:
        _gap(gaps, 'no_wait_lexical',
             detail='Whether a symlinked script blocks later scripts was decided from the link text, not from the '
                    'resolved directory.')
    result['files'] = [records[path] for path in order]
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
