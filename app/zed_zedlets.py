"""Pure ZFS Event Daemon zedlet contract (roadmap F slice, #1235).

Takes the captured ``zed`` command line, the installed OpenZFS version and
read-only metadata for the entries of the zedlet directory, and says which
zedlets ``zed`` registers and runs as root, for which ZFS event classes, and
why every other entry is ignored. It never reads a zedlet's contents.

Semantics were read in OpenZFS ``cmd/zed`` for 2.1.5, 2.2.2 and 2.3.4
(``zed_conf.c``, ``zed_exec.c``, ``zed_event.c``, ``zed_strings.c``). They agree
on every rule below, except that ``-b`` exists only from 2.2:

* ``zed`` scans one directory: ``/etc/zfs/zed.d`` unless ``-d DIR`` is given. A
  relative ``-d`` is joined to the working directory without normalisation.
  The directory is scanned at startup and again only on SIGHUP.
* Only names starting with ``.`` are skipped by name. There is **no** backup
  suffix filter, so ``checksum-notify.sh.dpkg-old`` is registered like any
  other zedlet.
* Each entry is ``stat``-ed with symlinks followed. An entry that cannot be
  resolved, or whose ``<dir>/<name>`` path does not fit in ``PATH_MAX``, is
  skipped.
* A zedlet must be a regular file, owned by uid 0, have the owner execute bit
  and be writable by neither group nor other. ``-f`` waives the owner and
  write checks but not the execute or file-type checks.
* For every event ``zed`` forms up to three strings: the event class (for
  example ``ereport.fs.zfs.checksum``), its subclass (the class after its
  first three dot-separated components, ``checksum``) and ``all``. Registered
  zedlets are walked in ``strcmp`` order. A zedlet runs once for each string
  that its name starts with when the following byte is not an ASCII letter. So
  ``all-syslog.sh``, ``all_x``, ``all1`` and a bare ``all`` run for every
  event, while ``allx`` does not.
* Each run is ``execle(<dir>/<name>, <name>, NULL, env)`` as root, with no
  arguments, ``umask 022``, the zevent file descriptor on fd 3 and an
  environment of ``ZEVENT_*`` event fields, ``ZED_PID``, ``ZED_ZEDLET_DIR``,
  ``IFS``, ``PATH``, ``ZDB``, ``ZED``, ``ZFS``, ``ZINJECT``, ``ZPOOL``,
  ``ZFS_ALIAS``, ``ZFS_VERSION``, ``ZFS_RELEASE`` and a preserved ``TZ``. With
  ``-P PATH`` that ``PATH`` is used and the ZFS tools are named without a
  directory, so they are found through it. At most ``-j`` zedlets (default 16)
  run at once.
* Options are parsed by glibc ``getopt`` with ``:hLVd:p:P:s:vfFMZIj:b:``
  (``:hLVd:p:P:s:vfFMZIj:`` before 2.2). ``-h``, ``-L``, ``-V``, an unknown
  option, a missing argument, ``-j`` of 0 or over 32767 and ``-b`` over
  2147483647 make ``zed`` exit, so nothing runs.

The contract performs no I/O, never runs a command and never authorizes a
response action. Missing or malformed metadata, an unobserved directory, command
line or version, an unsupported version and over-limit input are explicit
blocking gaps. None of them is ever reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE_VERSIONS = ('2.1.5', '2.2.2', '2.3.4')
SUPPORTED = ((2, 1), (2, 2), (2, 3))
RUNS_AS = 'root'
DEFAULT_DIR = '/etc/zfs/zed.d'
DEFAULT_MAX_JOBS = 16
PATH_MAX = 4096
INT16_MAX = 32767
INT32_MAX = 2147483647
ULONG_MAX = 2 ** 64 - 1
OPTSTRING = {(2, 1): ':hLVd:p:P:s:vfFMZIj:'}
OPTSTRING_DEFAULT = ':hLVd:p:P:s:vfFMZIj:b:'
MAX_ARGV = 64
MAX_ARG_LEN = 4096
MAX_ENTRIES = 1024
MAX_EVENT_CLASSES = 64
MAX_NAME_BYTES = 255
MAX_GAPS = 64
TARGET_TYPES = ('file', 'directory', 'char_device', 'block_device', 'fifo', 'socket', 'other')
ENTRY_TYPES = TARGET_TYPES + ('symlink',)
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
ENVIRONMENT = ('ZEVENT_*', 'ZED_PID', 'ZED_ZEDLET_DIR', 'IFS', 'PATH', 'ZDB', 'ZED', 'ZFS', 'ZINJECT', 'ZPOOL',
               'ZFS_ALIAS', 'ZFS_VERSION', 'ZFS_RELEASE', 'TZ')
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'duplicate_name', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'directory_mismatch', 'listing_incomplete',
    'argv_not_observed', 'version_not_observed', 'version_unsupported', 'working_directory_unknown',
    'gaps_truncated',
})
UNOBSERVED = (
    'Zedlet contents, zed.rc settings, interpreters and anything a zedlet runs are not read.',
    'Which ZFS events actually occur on this host is not assessed.',
    'A directory changed after zed started is only rescanned on SIGHUP or restart; the running daemon may still '
    'use an older registration.',
    'Who can write to the zedlet directory, or to the target of a symlinked zedlet, is not assessed.',
    'A POSIXLY_CORRECT environment, which stops option parsing at the first non-option argument, is not modelled.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'registered': 'zed registers this zedlet and runs it as root for every matching event.',
    'hidden': 'zed skips names that start with a dot.',
    'path_too_long': 'The full path does not fit in PATH_MAX, so zed skips it.',
    'unresolvable': 'The entry cannot be resolved (for example a dangling symlink), so zed skips it.',
    'not_regular': 'Only regular files are registered; directories, devices and other file types are skipped.',
    'not_root_owned': 'zed skips a zedlet that is not owned by root (unless started with -f).',
    'not_executable': 'The owner execute bit is not set, so zed skips it.',
    'group_writable': 'zed skips a zedlet that is writable by its group (unless started with -f).',
    'other_writable': 'zed skips a zedlet that is writable by other users (unless started with -f).',
    'daemon_exits': 'zed exits during option parsing with this command line, so nothing is registered.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
OBSERVATIONS = {
    'backup_name_runs': 'The name looks like a package-manager or editor backup, but zed has no backup filter and '
                        'runs it like any other zedlet.',
    'force_waived_owner': 'zed was started with -f, so this zedlet runs as root although it is not owned by root.',
    'force_waived_write': 'zed was started with -f, so this zedlet runs as root although group or other can write '
                          'it.',
    'never_matches': 'The name cannot match all, and matches none of the supplied event classes.',
}
_BACKUP = re.compile(r'(~|\.(rpmnew|rpmsave|rpmorig|dpkg-[a-z]+|ucf-[a-z]+|swp|bak|old|new|orig|save|disabled))$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_VERSION = re.compile(r'(?:zfs-)?(\d{1,3})\.(\d{1,3})(?:$|[^0-9])')
_ASCII_ALPHA = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
_SPACE = b' \t\n\v\f\r'


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


def _bytes(text: str) -> bytes:
    return text.encode('utf-8', 'surrogateescape')


def _text(value: Any, limit: int = MAX_ARG_LEN) -> bool:
    if not isinstance(value, str) or '\x00' in value:
        return False
    try:
        return len(_bytes(value)) <= limit
    except UnicodeEncodeError:
        return False


def _valid_name(name: Any) -> bool:
    return _text(name, MAX_NAME_BYTES) and name not in ('', '.', '..') and '/' not in name


def _int(value: Any, upper: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= upper


def parse_version(value: Any) -> tuple[int, int] | None:
    """Return ``(major, minor)`` from a version such as ``2.2.2-0ubuntu9.1`` or ``zfs-2.1.5-1``."""
    if isinstance(value, str) and len(value) <= 128:
        match = _VERSION.match(value.strip())
        if match:
            return int(match.group(1)), int(match.group(2))
    return None


def strtoul(text: str) -> tuple[int, bool]:
    """Return ``(value, overflowed)`` as glibc ``strtoul(text, NULL, 0)`` does for an ASCII string."""
    raw = _bytes(text)
    i = 0
    while i < len(raw) and raw[i] in _SPACE:
        i += 1
    negative = False
    if i < len(raw) and raw[i] in b'+-':
        negative = raw[i] == ord('-')
        i += 1
    base = 10
    if raw[i:i + 2].lower() == b'0x' and i + 2 < len(raw) and chr(raw[i + 2]) in '0123456789abcdefABCDEF':
        base, i = 16, i + 2
    elif raw[i:i + 1] == b'0':
        base = 8
    digits = '0123456789abcdef'[:base]
    value = 0
    while i < len(raw) and chr(raw[i]).lower() in digits:
        value = value * base + int(chr(raw[i]), base)
        i += 1
    if value > ULONG_MAX:
        return ULONG_MAX, True
    if negative and value:
        value = ULONG_MAX + 1 - value
    return value, False


def parse_argv(argv: list[str], version: tuple[int, int] | None, working_directory: str | None) -> dict[str, Any]:
    """Apply zed's getopt loop (glibc, permuting) to ``argv`` and return the effective settings."""
    optstring = OPTSTRING.get(version, OPTSTRING_DEFAULT) if version else OPTSTRING_DEFAULT
    takes_arg = {optstring[i] for i in range(1, len(optstring)) if optstring[i] != ':'
                 and i + 1 < len(optstring) and optstring[i + 1] == ':'}
    known = {char for char in optstring if char != ':'}
    state: dict[str, Any] = {'starts': True, 'exit_reason': None, 'zedlet_dir': DEFAULT_DIR, 'dir_option': None,
                             'force': False, 'path_override': None, 'max_jobs': DEFAULT_MAX_JOBS,
                             'foreground': False, 'ignored_arguments': []}

    def stop(reason: str) -> dict[str, Any]:
        state.update(starts=False, exit_reason=reason)
        return state

    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == '--':
            state['ignored_arguments'].extend(argv[index + 1:])
            break
        if not arg.startswith('-') or arg == '-':
            state['ignored_arguments'].append(arg)
            index += 1
            continue
        position = 1
        while position < len(arg):
            option = arg[position]
            if option not in known:
                return stop(f'Unknown option -{option}.')
            if option in takes_arg:
                if position + 1 < len(arg):
                    value = arg[position + 1:]
                else:
                    index += 1
                    if index >= len(argv):
                        return stop(f'Option -{option} has no argument.')
                    value = argv[index]
                if option == 'd':
                    state['dir_option'] = value
                    if value.startswith('/'):
                        state['zedlet_dir'] = value
                    elif working_directory is None:
                        state['zedlet_dir'] = None
                    else:
                        state['zedlet_dir'] = f'{working_directory}/{value}'
                elif option == 'P':
                    state['path_override'] = value if value.startswith('/') or working_directory is None \
                        else f'{working_directory}/{value}'
                elif option == 'j':
                    number, overflow = strtoul(value)
                    if overflow or number > INT16_MAX:
                        return stop(f'-j {value} is too many jobs.')
                    if number == 0:
                        return stop(f'-j {value} is zero jobs.')
                    state['max_jobs'] = number
                elif option == 'b':
                    number, overflow = strtoul(value)
                    if overflow or number > INT32_MAX:
                        return stop(f'-b {value} is too large.')
                break
            if option in 'hLV':
                return stop(f'-{option} prints information and exits.')
            if option == 'f':
                state['force'] = True
            elif option == 'F':
                state['foreground'] = True
            position += 1
        index += 1
    return state


def subclass(event_class: str) -> str | None:
    """Return the event subclass: ``event_class`` after its first three dot-separated components."""
    rest = event_class
    for _ in range(3):
        dot = rest.find('.')
        if dot < 0:
            return None
        rest = rest[dot + 1:]
    return rest


def match_strings(event_class: str) -> list[str]:
    """Return the strings zed compares zedlet names against for one event, in its order."""
    strings = [event_class]
    sub = subclass(event_class)
    if sub is not None:
        strings.append(sub)
    strings.append('all')
    return strings


def matches(name: str, string: str) -> bool:
    """Return whether zed's ``strncmp(name, string, n) == 0 && !isalpha(name[n])`` holds."""
    raw, prefix = _bytes(name), _bytes(string)
    if not raw.startswith(prefix):
        return False
    return len(raw) == len(prefix) or raw[len(prefix)] not in _ASCII_ALPHA


def _stat(meta: Any) -> dict[str, Any] | None:
    if not isinstance(meta, dict) or meta.get('type') not in TARGET_TYPES:
        return None
    if meta['type'] == 'file' and not (_int(meta.get('mode'), 0o7777) and _int(meta.get('uid'), 2 ** 32)):
        return None
    return {key: meta.get(key) for key in ('type', 'mode', 'uid')}


def _assess(item: Any, directory: str, force: bool,
            gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_name(item.get('name')) or item.get('type') not in ENTRY_TYPES:
        _gap(gaps, 'input_malformed', directory, 'An entry observation has no valid name or type.')
        return None
    name = item['name']
    path = f'{directory}/{name}'
    record: dict[str, Any] = {'name': name, 'path': path, 'type': item['type'], 'observations': []}
    text = item.get('link_target')
    if item['type'] == 'symlink' and isinstance(text, str) and 0 < len(text) <= MAX_ARG_LEN \
            and not _CONTROL.search(text):
        record['link_target'] = text

    def done(code: str) -> dict[str, Any]:
        status = 'registered' if code == 'registered' else 'unresolved' if code == 'unresolved' else 'ignored'
        record.update(status=status, reason_code=code, reason=REASONS[code])
        return record

    if name.startswith('.'):
        return done('hidden')
    if len(_bytes(path)) >= PATH_MAX:
        return done('path_too_long')
    if item['type'] == 'symlink':
        if 'target' not in item:
            _gap(gaps, 'symlink_target_unobserved', path, 'What the symlink resolves to was not supplied.')
            return done('unresolved')
        if item['target'] is None:
            return done('unresolvable')
        stat = _stat(item['target'])
    else:
        stat = _stat(item)
    if stat is None:
        _gap(gaps, 'metadata_missing', path, 'Required metadata for this entry was not supplied or is malformed.')
        return done('unresolved')
    if stat['type'] != 'file':
        return done('not_regular')
    mode, uid = stat['mode'], stat['uid']
    if uid != 0 and not force:
        return done('not_root_owned')
    if not mode & 0o100:
        return done('not_executable')
    if mode & 0o020 and not force:
        return done('group_writable')
    if mode & 0o002 and not force:
        return done('other_writable')
    if uid != 0:
        record['observations'].append({'code': 'force_waived_owner', 'uid': uid,
                                       'detail': OBSERVATIONS['force_waived_owner']})
    if mode & 0o022:
        record['observations'].append({'code': 'force_waived_write', 'mode': f'{mode:04o}',
                                       'detail': OBSERVATIONS['force_waived_write']})
    if _BACKUP.search(name):
        record['observations'].append({'code': 'backup_name_runs', 'detail': OBSERVATIONS['backup_name_runs']})
    return done('registered')


def _directory(observation: Any, path: str, gaps: list[dict[str, Any]]) -> tuple[str | None, list[Any]]:
    if observation is None:
        _gap(gaps, 'directory_not_observed', path, f'No listing result was supplied for {path}.')
        return None, []
    state = observation.get('state') if isinstance(observation, dict) else None
    complete = observation.get('complete') if isinstance(observation, dict) else None
    entries = observation.get('entries', []) if isinstance(observation, dict) else None
    if state not in DIRECTORY_STATES or not isinstance(entries, (list, tuple)) \
            or (state == 'listed' and not isinstance(complete, bool)) \
            or (complete is not None and not isinstance(complete, bool)):
        _gap(gaps, 'input_malformed', path, 'The directory observation is malformed.')
        return None, []
    if observation.get('path') not in (None, path):
        _gap(gaps, 'directory_mismatch', path,
             f'The listing is for {observation.get("path")!r}, but zed scans {path}.')
        return None, []
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', path, f'{path} exists but could not be listed.')
    elif state == 'listed' and not complete:
        _gap(gaps, 'listing_incomplete', path, f'The listing of {path} did not finish.')
    elif state in ('absent', 'not_directory') and entries:
        _gap(gaps, 'input_malformed', path, 'Entries were supplied for a directory reported absent.')
        return state, []
    return state, list(entries)


def _event_classes(value: Any, gaps: list[dict[str, Any]]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or not all(_text(item, 256) and item and not _CONTROL.search(item)
                                                       for item in value):
        _gap(gaps, 'input_malformed', detail='event_classes must be a list of non-empty event class strings.')
        return []
    if len(value) > MAX_EVENT_CLASSES:
        _gap(gaps, 'event_classes_truncated', detail=f'Only the first {MAX_EVENT_CLASSES} event classes are used.')
    return list(dict.fromkeys(value[:MAX_EVENT_CLASSES]))


def evaluate(*, zfs_version: Any = None, zed_argv: Any = None, working_directory: Any = '/',
             directory: Any = None, event_classes: Any = None) -> dict[str, Any]:
    """Resolve which zedlets zed registers and runs as root from supplied metadata.

    ``zfs_version`` is the installed OpenZFS userland version (``'2.2.2-0ubuntu9.1'``).
    ``zed_argv`` is the daemon's command line including ``argv[0]``, for example the
    ``ExecStart`` of ``zfs-zed.service`` (``['/usr/sbin/zed', '-F']``).
    ``working_directory`` resolves a relative ``-d``; systemd's default for system services is ``/``.
    Pass ``None`` when it is unknown.

    ``directory`` describes the zedlet directory as ``{'state', 'complete', 'entries'}`` with an
    optional ``path`` that must equal the directory zed scans:

    * ``state`` is ``listed``, ``absent``, ``not_directory`` or ``unreadable``.
    * Each entry carries ``name`` and ``type`` as ``lstat`` reports it.
    * A ``file`` carries ``mode`` (0–0o7777) and ``uid``.
    * A ``symlink`` carries ``target``, which is what ``stat`` reports after following it (same
      fields, with a ``type`` other than ``symlink``), or ``None`` when ``stat`` fails.
      ``link_target`` (the raw link text) is optional and informational.

    ``event_classes`` optionally lists event classes such as ``ereport.fs.zfs.checksum`` or
    ``sysevent.fs.zfs.pool_import``; for each one the result lists the zedlet runs, in order.
    """
    gaps: list[dict[str, Any]] = []
    version = None
    if zfs_version is None:
        _gap(gaps, 'version_not_observed', detail='The OpenZFS version was not supplied.')
    else:
        version = parse_version(zfs_version)
        if version is None:
            _gap(gaps, 'input_malformed', detail='The OpenZFS version is malformed.')
        elif version not in SUPPORTED:
            _gap(gaps, 'version_unsupported',
                 detail=f'OpenZFS {version[0]}.{version[1]} is outside the read range 2.1–2.3.')
    if working_directory is not None and not (_text(working_directory) and working_directory.startswith('/')):
        _gap(gaps, 'input_malformed', detail='working_directory must be an absolute path or None.')
        working_directory = None
    daemon = None
    if zed_argv is None:
        _gap(gaps, 'argv_not_observed', detail='The zed command line was not supplied.')
    elif not isinstance(zed_argv, (list, tuple)) or not zed_argv or len(zed_argv) > MAX_ARGV \
            or not all(_text(arg) for arg in zed_argv):
        _gap(gaps, 'input_malformed', detail='zed_argv must be a non-empty list of strings including argv[0].')
    else:
        daemon = parse_argv(list(zed_argv), version, working_directory)
        if daemon['starts'] and daemon['zedlet_dir'] is None:
            _gap(gaps, 'working_directory_unknown',
                 detail=f'-d {daemon["dir_option"]!r} is relative and the working directory is unknown.')
    classes = _event_classes(event_classes, gaps)
    zedlet_dir = daemon['zedlet_dir'] if daemon and daemon['starts'] else None
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference_versions': list(REFERENCE_VERSIONS),
        'zfs_version': f'{version[0]}.{version[1]}' if version else None, 'daemon': daemon,
        'zedlet_dir': zedlet_dir, 'directory_state': None, 'runs_as': RUNS_AS,
        'invocation': {'argv': ['<name>'], 'umask': '0022', 'fd3': 'zevent', 'environment': list(ENVIRONMENT),
                       'max_parallel': daemon['max_jobs'] if daemon else None,
                       'path': daemon['path_override'] if daemon else None},
        'entries': [], 'zedlets': [], 'events': [],
        'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    if daemon is not None and not daemon['starts']:
        result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
        return result
    if zedlet_dir is not None:
        state, entries = _directory(directory, zedlet_dir, gaps)
        result['directory_state'] = state
        if len(entries) > MAX_ENTRIES:
            _gap(gaps, 'too_many_entries', zedlet_dir, f'Only the first {MAX_ENTRIES} entries are assessed.')
            entries = entries[:MAX_ENTRIES]
        seen: set[str] = set()
        records = []
        for item in entries:
            record = _assess(item, zedlet_dir, daemon['force'], gaps)
            if record is None:
                continue
            if record['name'] in seen:
                _gap(gaps, 'duplicate_name', record['path'], 'The name was supplied more than once; the first is used.')
                continue
            seen.add(record['name'])
            records.append(record)
        if state != 'listed':
            for record in records:
                if record['status'] == 'registered':
                    record.update(status='unresolved', reason_code='unresolved', reason=REASONS['unresolved'])
        records.sort(key=lambda rec: _bytes(rec['name']))
        result['entries'] = records
        registered = [record for record in records if record['status'] == 'registered']
        for order, record in enumerate(registered):
            record['order'] = order
            zedlet: dict[str, Any] = {
                'order': order, 'name': record['name'], 'path': record['path'],
                'all_events': matches(record['name'], 'all'),
                'event_classes': [cls for cls in classes if any(matches(record['name'], string)
                                                                for string in match_strings(cls))],
                'observations': [obs['code'] for obs in record['observations']],
            }
            if 'link_target' in record:
                zedlet['link_target'] = record['link_target']
            if classes and not zedlet['all_events'] and not zedlet['event_classes']:
                zedlet['observations'].append('never_matches')
            result['zedlets'].append(zedlet)
        for cls in classes:
            strings = match_strings(cls)
            runs = [{'name': record['name'], 'path': record['path'], 'matched': string}
                    for record in registered for string in strings if matches(record['name'], string)]
            result['events'].append({'event_class': cls, 'subclass': subclass(cls), 'match_strings': strings,
                                     'runs': runs})
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
