"""Pure systemd sleep and shutdown hook contract (roadmap F slice, #1067).

Takes captured, read-only metadata for the entries of systemd's
``system-sleep`` and ``system-shutdown`` hook directories and says which
executables ``systemd-sleep`` and ``systemd-shutdown`` would run as root, with
which arguments, and why every other entry is not run. It never reads a hook's
contents.

Semantics were read in the systemd sources for v249, v252, v255, v256, v257 and
v258 (``src/sleep/sleep.c``, ``src/shutdown/shutdown.c``,
``src/shared/exec-util.c``, ``src/basic/conf-files.c`` and
``hidden_or_backup_file`` in ``src/basic/path-util.c``). They agree on every
rule below:

* Each program scans exactly one compiled-in directory: ``SYSTEM_SLEEP_PATH`` or
  ``SYSTEM_SHUTDOWN_PATH``, which is ``<libexecdir>/system-sleep`` or
  ``<libexecdir>/system-shutdown``. That is ``/usr/lib/systemd/...``, or
  ``/lib/systemd/...`` on a split-usr build. ``/etc/systemd/system-sleep``,
  ``/etc/systemd/system-shutdown`` and ``/usr/local/lib/systemd/...`` are not
  scanned, so a hook placed there never runs.
* Hidden and backup names are skipped. These are names that start with ``.``,
  end with ``~``, are ``lost+found``, ``aquota.user`` or ``aquota.group``, or
  whose last ``.`` suffix is one of ``rpmnew``, ``rpmsave``, ``rpmorig``,
  ``dpkg-old``, ``dpkg-new``, ``dpkg-tmp``, ``dpkg-dist``, ``dpkg-bak``,
  ``dpkg-backup``, ``dpkg-remove``, ``ucf-new``, ``ucf-old``, ``ucf-dist``,
  ``swp``, ``bak``, ``old`` or ``new``.
* Each entry is stat-ed with symlinks followed. An entry that cannot be resolved
  is skipped.
* Directory entries that are not regular files, symlinks or of unknown type
  (for example a character device placed directly in the directory) are
  dropped before any stat.
* An empty regular file, or a symlink to a character device such as
  ``/dev/null``, is a mask and is skipped.
* Anything that is not a regular file is skipped.
* A regular file with no execute bit (``mode & 0111``) is skipped.
* Ownership and write permissions are **not** checked. A hook owned by a
  non-root user, or writable by group or other, still runs as root. It is
  reported as an observation, not skipped.
* Every hook is started in file-name order, and all hooks then run in
  parallel. Exit codes are ignored, and the whole set is killed after the
  build's default timeout (90 s upstream).
  * Sleep hooks are called with ``pre`` and later ``post`` and the requested
    operation (``suspend``, ``hibernate``, ``hybrid-sleep`` or
    ``suspend-then-hibernate``). ``SYSTEMD_SLEEP_ACTION`` names the specific
    step being performed.
  * Shutdown hooks are called with ``halt``, ``poweroff``, ``reboot`` or
    ``kexec``, or with ``exit`` when a system manager running in a container
    exits (``systemctl exit``). They run after services have stopped and most
    file systems have been unmounted.

The contract performs no I/O, never runs a command and never authorizes a
response action. Missing or malformed metadata, an unobserved directory or
systemd version, an unsupported version, an ambiguous split-usr libexec
directory and over-limit input are explicit blocking gaps. None of them is ever
reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE_VERSIONS = (249, 252, 255, 256, 257, 258)
MIN_VERSION = 249
MAX_VERSION = 258
RUNS_AS = 'root'
TIMEOUT_SECONDS = 90
LIBEXEC_DIRS = ('/usr/lib/systemd', '/lib/systemd')
MECHANISMS = {
    'sleep': {
        'subdir': 'system-sleep', 'program': 'systemd-sleep',
        'invocations': tuple((phase, operation) for phase in ('pre', 'post')
                             for operation in ('suspend', 'hibernate', 'hybrid-sleep', 'suspend-then-hibernate')),
        'environment': ('SYSTEMD_SLEEP_ACTION',),
        'when': 'Before entering and after leaving suspend or hibernation. Hooks run with pre before sleep and with '
                'post after resume; the second argument is the requested operation.',
    },
    'shutdown': {
        'subdir': 'system-shutdown', 'program': 'systemd-shutdown',
        'invocations': (('halt',), ('poweroff',), ('reboot',), ('kexec',), ('exit',)),
        'environment': (),
        'when': 'Shortly before the final halt, power-off, reboot or kexec, after services have stopped and most '
                'file systems have been unmounted. The exit argument is used only when a system manager running '
                'in a container exits.',
    },
}
UNSCANNED_DIRS = (
    '/etc/systemd/system-sleep', '/etc/systemd/system-shutdown',
    '/usr/local/lib/systemd/system-sleep', '/usr/local/lib/systemd/system-shutdown',
)
MAX_ENTRIES = 1024
MAX_UNSCANNED = 256
MAX_NAME_BYTES = 255
MAX_PATH = 4096
MAX_GAPS = 64
ENTRY_TYPES = ('file', 'directory', 'symlink', 'char_device', 'other')
TARGET_TYPES = ('file', 'directory', 'char_device', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
BACKUP_SUFFIXES = frozenset({
    'rpmnew', 'rpmsave', 'rpmorig', 'dpkg-old', 'dpkg-new', 'dpkg-tmp', 'dpkg-dist', 'dpkg-bak', 'dpkg-backup',
    'dpkg-remove', 'ucf-new', 'ucf-old', 'ucf-dist', 'swp', 'bak', 'old', 'new',
})
HIDDEN_NAMES = frozenset({'lost+found', 'aquota.user', 'aquota.group'})
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'duplicate_name', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'version_not_observed',
    'version_unsupported', 'libexec_dir_unknown', 'gaps_truncated',
})
UNOBSERVED = (
    'Hook contents, interpreters and anything a hook runs are not read.',
    'Whether suspend, hibernation, kexec or a given shutdown action is ever used on this host is not assessed.',
    'Who can write to the hook directories or to the target of a symlinked hook is not assessed.',
    'A locally rebuilt systemd with a different libexec directory or timeout is not detected.',
    'Hooks run by other sleep or shutdown mechanisms (pm-utils, elogind, sysvinit) are not assessed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'runs': 'systemd runs this executable as root with the listed arguments.',
    'hidden_or_backup': 'systemd skips hidden and backup names (leading dot, trailing ~, or a package-manager or '
                        'editor backup suffix such as .dpkg-old, .rpmnew, .bak or .swp).',
    'unresolvable': 'The entry cannot be resolved (for example a dangling symlink), so systemd skips it.',
    'mask_empty': 'An empty file is a mask, so systemd skips it.',
    'mask_char_device': 'A symlink to a character device such as /dev/null is a mask, so systemd skips it.',
    'not_regular': 'Only regular files are run; directories, device nodes and other file types are skipped.',
    'not_executable': 'The file has no execute bit, so systemd skips it.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
OBSERVATIONS = {
    'not_root_owned': 'The hook runs as root but is owned by a non-root user, who can change what root runs.',
    'group_or_world_writable': 'The hook runs as root but is writable by group or other users.',
}
NOT_SCANNED_REASON = ('systemd {version} does not scan this directory, so this file is never run as a {kind} hook. '
                      'Hooks must be placed in {directory}.')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_VERSION = re.compile(r'(\d{1,4})(?:$|[^0-9])')


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


def hidden_or_backup(name: str) -> bool:
    """Return whether systemd's ``hidden_or_backup_file()`` skips this directory entry name."""
    if name.startswith('.') or name in HIDDEN_NAMES or name.endswith('~'):
        return True
    dot = name.rfind('.')
    return dot >= 0 and name[dot + 1:] in BACKUP_SUFFIXES


def _sort_key(name: str) -> bytes:
    return name.encode('utf-8', 'surrogateescape')


def _valid_name(name: Any) -> bool:
    if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\x00' in name:
        return False
    try:
        return len(_sort_key(name)) <= MAX_NAME_BYTES
    except UnicodeEncodeError:
        return False


def _int(value: Any, upper: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= upper


def _stat(meta: Any) -> dict[str, Any] | None:
    """Validate one followed-stat mapping; a regular file needs ``mode``, ``size`` and ``uid``."""
    if not isinstance(meta, dict) or meta.get('type') not in TARGET_TYPES:
        return None
    if meta['type'] == 'file' and not (_int(meta.get('mode'), 0o7777) and _int(meta.get('size'), 2 ** 63)
                                       and _int(meta.get('uid'), 2 ** 32)):
        return None
    return {key: meta.get(key) for key in ('type', 'mode', 'size', 'uid')}


def parse_version(value: Any) -> int | None:
    """Return the systemd major version from an int or a string such as ``252`` or ``252.39-1~deb12u1``."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value if 0 < value < 10000 else None
    if isinstance(value, str) and len(value) <= 128:
        match = _VERSION.match(value.strip())
        if match:
            return int(match.group(1))
    return None


def _normalize(item: Any, gaps: list[dict[str, Any]], directory: str) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_name(item.get('name')) or item.get('type') not in ENTRY_TYPES:
        _gap(gaps, 'input_malformed', directory, 'An entry observation has no valid name or type.')
        return None
    entry: dict[str, Any] = {'name': item['name'], 'type': item['type'], 'resolved': True}
    if item['type'] == 'symlink':
        text = item.get('link_target')
        if isinstance(text, str) and text and len(text) <= MAX_PATH and not _CONTROL.search(text):
            entry['link_target'] = text
        if 'target' in item:
            if item['target'] is None:
                entry['target'] = None
            else:
                target = _stat(item['target'])
                if target is None:
                    entry['resolved'] = False
                else:
                    entry['target'] = target
    elif item['type'] == 'file':
        stat = _stat(item)
        if stat is None:
            entry['resolved'] = False
        else:
            entry.update(stat)
    return entry


def _assess(entry: dict[str, Any], path: str, gaps: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None]:
    """Return the reason code for one normalized entry whose name systemd considers, and its followed stat."""
    if entry['type'] == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', path, 'What the symlink resolves to was not supplied.')
            return 'unresolved', None
        if entry['target'] is None:
            return 'unresolvable', None
        stat = entry['target']
    elif entry['type'] != 'file':
        # dirent_is_file_with_suffix() drops entries that are not DT_REG, DT_LNK or DT_UNKNOWN
        # before any stat, so a device node placed directly in the directory is never a mask.
        return 'not_regular', entry
    else:
        stat = entry
    if stat['type'] == 'char_device':
        return 'mask_char_device', stat
    if stat['type'] != 'file':
        return 'not_regular', stat
    if stat['size'] == 0:
        return 'mask_empty', stat
    if not stat['mode'] & 0o111:
        return 'not_executable', stat
    return 'runs', stat


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
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', path, f'{path} exists but could not be listed.')
    elif state == 'listed' and not complete:
        _gap(gaps, 'listing_incomplete', path, f'The listing of {path} did not finish.')
    elif state in ('absent', 'not_directory') and entries:
        _gap(gaps, 'input_malformed', path, 'Entries were supplied for a directory reported absent.')
        return state, []
    return state, list(entries)


def _libexec(libexec_dir: Any, merged_usr: Any, gaps: list[dict[str, Any]]) -> str | None:
    if libexec_dir is not None:
        if libexec_dir not in LIBEXEC_DIRS:
            _gap(gaps, 'input_malformed', detail=f'libexec_dir must be one of {", ".join(LIBEXEC_DIRS)}.')
            return None
        return libexec_dir
    if merged_usr is True:
        # /lib is a symlink to usr/lib, so both compiled-in spellings name the same directory.
        return LIBEXEC_DIRS[0]
    if merged_usr is not None and merged_usr is not False:
        _gap(gaps, 'input_malformed', detail='merged_usr must be True, False or None.')
        return None
    _gap(gaps, 'libexec_dir_unknown',
         detail='/lib is not known to be merged with /usr/lib and the compiled-in libexec directory was not '
                'supplied, so which hook directory systemd scans is unknown.')
    return None


def _mechanism(kind: str, libexec: str | None, observation: Any,
               gaps: list[dict[str, Any]]) -> dict[str, Any]:
    spec = MECHANISMS[kind]
    path = f'{libexec}/{spec["subdir"]}' if libexec else None
    result: dict[str, Any] = {
        'program': spec['program'], 'directory': path, 'directory_state': None, 'runs_as': RUNS_AS,
        'execution': 'parallel', 'start_order': 'byte', 'errors': 'ignored', 'timeout_seconds': TIMEOUT_SECONDS,
        'invocations': [list(args) for args in spec['invocations']], 'environment': list(spec['environment']),
        'when': spec['when'], 'entries': [], 'hooks': [],
    }
    if path is None:
        return result
    state, entries = _directory(observation, path, gaps)
    result['directory_state'] = state
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', path, f'Only the first {MAX_ENTRIES} entries are assessed.')
        entries = entries[:MAX_ENTRIES]
    seen: set[str] = set()
    records = []
    for item in entries:
        entry = _normalize(item, gaps, path)
        if entry is None:
            continue
        name = entry['name']
        entry_path = f'{path}/{name}'
        if name in seen:
            _gap(gaps, 'duplicate_name', entry_path, 'The name was supplied more than once; the first is used.')
            continue
        seen.add(name)
        stat = None
        if hidden_or_backup(name):
            code = 'hidden_or_backup'
        elif not entry['resolved']:
            _gap(gaps, 'metadata_missing', entry_path,
                 'Required metadata for this entry was not supplied or is malformed.')
            code = 'unresolved'
        else:
            code, stat = _assess(entry, entry_path, gaps)
        status = 'runs' if code == 'runs' else 'unresolved' if code == 'unresolved' else 'skipped'
        record: dict[str, Any] = {'name': name, 'path': entry_path, 'type': entry['type'], 'status': status,
                                  'reason_code': code, 'reason': REASONS[code], 'observations': []}
        if 'link_target' in entry:
            record['link_target'] = entry['link_target']
        if status == 'runs' and stat is not None:
            if stat['uid'] != 0:
                record['observations'].append({'code': 'not_root_owned', 'uid': stat['uid'],
                                               'detail': OBSERVATIONS['not_root_owned']})
            if stat['mode'] & 0o022:
                record['observations'].append({'code': 'group_or_world_writable', 'mode': f'{stat["mode"]:04o}',
                                               'detail': OBSERVATIONS['group_or_world_writable']})
        records.append(record)
    runnable = [record for record in records if record['status'] == 'runs']
    if state != 'listed':
        for record in runnable:
            record.update(status='unresolved', reason_code='unresolved', reason=REASONS['unresolved'])
        runnable = []
    for index, record in enumerate(sorted(runnable, key=lambda rec: _sort_key(rec['name']))):
        record['start_order'] = index
        hook: dict[str, Any] = {'start_order': index, 'name': record['name'], 'path': record['path'],
                                'observations': [obs['code'] for obs in record['observations']]}
        if 'link_target' in record:
            hook['link_target'] = record['link_target']
        result['hooks'].append(hook)
    result['entries'] = sorted(records, key=lambda rec: _sort_key(rec['name']))
    return result


def _not_scanned(unscanned: Any, version: int | None, libexec: str | None,
                 gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if unscanned is None:
        return []
    if not isinstance(unscanned, dict) or any(key not in UNSCANNED_DIRS for key in unscanned):
        _gap(gaps, 'input_malformed', detail=f'unscanned must map only {", ".join(UNSCANNED_DIRS)} to name lists.')
        return []
    records = []
    for directory in UNSCANNED_DIRS:
        names = unscanned.get(directory)
        if names is None:
            continue
        if not isinstance(names, (list, tuple)) or not all(_valid_name(name) for name in names):
            _gap(gaps, 'input_malformed', directory, 'Unscanned entries must be a list of directory entry names.')
            continue
        kind = 'sleep' if directory.endswith('system-sleep') else 'shutdown'
        target = f'{libexec}/{MECHANISMS[kind]["subdir"]}' if libexec else f'<libexecdir>/{MECHANISMS[kind]["subdir"]}'
        reason = NOT_SCANNED_REASON.format(version=f'v{version}' if version else '(any read version)',
                                           kind=kind, directory=target)
        for name in sorted(set(names[:MAX_UNSCANNED]), key=_sort_key):
            records.append({'name': name, 'path': f'{directory}/{name}', 'mechanism': kind,
                            'status': 'not_scanned', 'reason': reason})
        if len(names) > MAX_UNSCANNED:
            _gap(gaps, 'unscanned_truncated', directory, f'Only the first {MAX_UNSCANNED} names are listed.')
    return records


def evaluate(*, systemd_version: Any = None, merged_usr: Any = None, libexec_dir: Any = None,
             sleep: Any = None, shutdown: Any = None, unscanned: Any = None) -> dict[str, Any]:
    """Resolve which systemd sleep and shutdown hooks run from supplied metadata.

    ``systemd_version`` is the installed systemd version (``252`` or ``'252.39-1~deb12u1'``).
    ``merged_usr`` is ``True`` when ``/lib`` was observed to be a symlink to ``usr/lib``. Otherwise
    pass ``libexec_dir`` (``/usr/lib/systemd`` or ``/lib/systemd``), which is the build's
    compiled-in directory.

    ``sleep`` and ``shutdown`` each describe that mechanism's directory as
    ``{'state', 'complete', 'entries'}``:

    * ``state`` is ``listed``, ``absent``, ``not_directory`` or ``unreadable``.
    * Each entry carries ``name`` and ``type`` as ``lstat`` reports it: ``file``, ``directory``,
      ``symlink``, ``char_device`` or ``other``.
    * A ``file`` carries ``mode`` (0–0o7777), ``size`` and ``uid``.
    * A ``symlink`` carries ``target``, which is what ``stat`` reports after following it (same
      fields, with a ``type`` other than ``symlink``), or ``None`` when ``stat`` fails.
    * ``link_target`` (the raw link text) is optional and informational.

    ``unscanned`` optionally maps any of ``UNSCANNED_DIRS`` to the entry names observed there.
    Those files are reported as ``not_scanned``, because systemd never runs them.

    Each mechanism's ``hooks`` is what that program runs *when* the event happens. Whether the
    host ever suspends, hibernates or uses kexec is not assessed.
    """
    gaps: list[dict[str, Any]] = []
    version = None
    if systemd_version is None:
        _gap(gaps, 'version_not_observed', detail='The systemd version was not supplied.')
    else:
        version = parse_version(systemd_version)
        if version is None:
            _gap(gaps, 'input_malformed', detail='The systemd version is malformed.')
        elif not MIN_VERSION <= version <= MAX_VERSION:
            _gap(gaps, 'version_unsupported',
                 detail=f'systemd v{version} is outside the read range v{MIN_VERSION}–v{MAX_VERSION}.')
    libexec = _libexec(libexec_dir, merged_usr, gaps)
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference_versions': list(REFERENCE_VERSIONS),
        'systemd_version': version, 'libexec_dir': libexec,
        'mechanisms': {'sleep': _mechanism('sleep', libexec, sleep, gaps),
                       'shutdown': _mechanism('shutdown', libexec, shutdown, gaps)},
        'not_scanned': _not_scanned(unscanned, version, libexec, gaps),
        'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
