"""Pure systemd generator contract (roadmap F slice, #1151).

Takes captured, read-only metadata for systemd's generator search directories and
says which generator executables the service manager runs, as whom, with which
arguments and in what order, and why every other entry is not run. It never reads
a generator's contents.

Generators run before any unit is loaded: at every boot, at every user-manager
start and at every ``systemctl daemon-reload`` or ``daemon-reexec`` (which
package installs trigger). A file in ``/etc/systemd`` or ``/run/systemd`` with
the same name as a vendor generator replaces or masks it.

Semantics were read in the systemd sources for v249, v252, v255, v256, v257 and
v258 (``generator_binary_paths()`` and ``env_generator_binary_paths()`` in
``path-lookup.c``, ``files_add()`` in ``conf-files.c``, ``execute_directories()``
in ``exec-util.c``, ``manager_run_generators()`` and
``manager_run_environment_generators()`` in ``manager.c``, ``null_or_empty()`` /
``stat_may_be_dev_null()`` in ``stat-util.c`` and ``hidden_or_backup_file()``).
They agree on every rule below:

* Each of the four generator kinds searches four directories, highest priority
  first: ``/run/systemd/<kind>``, ``/etc/systemd/<kind>``,
  ``/usr/local/lib/systemd/<kind>`` and the compiled-in directory. Only
  ``system-generators`` uses ``<libexecdir>`` (``/lib/systemd`` on a split-usr
  build). The user and environment kinds always use ``/usr/lib/systemd``.
* Hidden and backup names are skipped (the same list as
  :func:`app.systemd_hooks.hidden_or_backup`).
* The first directory that yields a name wins. A same-named entry in a lower
  directory is overridden and never runs.
* Entries are stat-ed with symlinks followed. A mask is an empty regular file or
  anything that resolves to a character device, such as a symlink to
  ``/dev/null`` (a character device placed directly in the directory is also a
  mask). A mask hides that name in every lower directory. v258 also treats a
  dangling symlink whose text is ``/dev/null`` as a mask.
* An entry that cannot be stat-ed, is not a regular file or has no execute bit
  (``mode & 0111``) is skipped **without** claiming the name, so a same-named
  entry in a lower directory still runs.
* Ownership and write permissions are not checked. They are reported as
  observations, never as skips.
* Unit generators are started in byte order of their names and run in
  parallel with three arguments (the normal, early and late output
  directories). Exit codes are ignored and the build default timeout (90 s
  upstream) applies. Environment generators run serially in the same order;
  each receives the environment the earlier ones produced.
* System kinds are run by the system manager as root. User kinds are run by
  every user's ``systemd --user`` manager as that user.

The contract performs no I/O, never runs a command and never authorizes a
response action. Missing or malformed metadata, an unobserved directory or
systemd version, an unsupported version, an ambiguous split-usr libexec
directory and over-limit input are explicit blocking gaps. None of them is ever
reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

from app.systemd_hooks import hidden_or_backup, parse_version

CONTRACT_VERSION = 1
REFERENCE_VERSIONS = (249, 252, 255, 256, 257, 258)
MIN_VERSION = 249
MAX_VERSION = 258
DEV_NULL_SYMLINK_MASK_VERSION = 258
TIMEOUT_SECONDS = 90
LIBEXEC_DIRS = ('/usr/lib/systemd', '/lib/systemd')
UNIT_ARGUMENTS_SYSTEM = ('/run/systemd/generator', '/run/systemd/generator.early', '/run/systemd/generator.late')
UNIT_ARGUMENTS_USER = ('$XDG_RUNTIME_DIR/systemd/generator', '$XDG_RUNTIME_DIR/systemd/generator.early',
                       '$XDG_RUNTIME_DIR/systemd/generator.late')
KINDS = {
    'system': {
        'subdir': 'system-generators', 'manager': 'system', 'runs_as': 'root', 'execution': 'parallel',
        'arguments': UNIT_ARGUMENTS_SYSTEM, 'output': 'unit files, drop-ins and dependency links',
        'when': 'At every boot, before any unit is loaded, and at every systemctl daemon-reload or daemon-reexec, '
                'including the reloads that package installs trigger.',
    },
    'user': {
        'subdir': 'user-generators', 'manager': 'user', 'runs_as': 'each user with a systemd user manager',
        'execution': 'parallel', 'arguments': UNIT_ARGUMENTS_USER,
        'output': 'user unit files, drop-ins and dependency links',
        'when': "Whenever a user's systemd --user manager starts (usually at that user's first login) and at "
                'every systemctl --user daemon-reload.',
    },
    'system_environment': {
        'subdir': 'system-environment-generators', 'manager': 'system', 'runs_as': 'root', 'execution': 'serial',
        'arguments': (), 'output': 'environment variables for every service the system manager starts',
        'when': 'At every boot and at every systemctl daemon-reload or daemon-reexec.',
    },
    'user_environment': {
        'subdir': 'user-environment-generators', 'manager': 'user',
        'runs_as': 'each user with a systemd user manager', 'execution': 'serial', 'arguments': (),
        'output': "environment variables for every unit in that user's manager",
        'when': "Whenever a user's systemd --user manager starts and at every systemctl --user daemon-reload.",
    },
}
HIGHER_PREFIXES = ('/run/systemd', '/etc/systemd', '/usr/local/lib/systemd')
VENDOR_LIB = '/usr/lib/systemd'
MAX_ENTRIES = 1024
MAX_PATH = 4096
MAX_GAPS = 64
ENTRY_TYPES = ('file', 'directory', 'symlink', 'char_device', 'other')
TARGET_TYPES = ('file', 'directory', 'char_device', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'duplicate_name', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'version_not_observed',
    'version_unsupported', 'libexec_dir_unknown', 'gaps_truncated',
})
UNOBSERVED = (
    'Generator contents, interpreters and the units or environment a generator writes are not read.',
    ('SYSTEMD_GENERATOR_PATH and SYSTEMD_ENVIRONMENT_GENERATOR_PATH overrides in the manager environment are '
     'not observed.'),
    'Generators inside the initrd image run from the initrd copy and are not assessed here.',
    'Who can write to the generator directories or to the target of a symlinked generator is not assessed.',
    'A locally rebuilt systemd with a different libexec directory or timeout is not detected.',
    'Which users have a systemd user manager is not assessed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'runs': 'systemd runs this executable as a generator.',
    'hidden_or_backup': 'systemd skips hidden and backup names (leading dot, trailing ~, or a package-manager or '
                        'editor backup suffix such as .dpkg-old, .rpmnew, .bak or .swp).',
    'overridden': 'A same-named generator in a higher-priority directory runs instead of this one.',
    'masked': 'A same-named mask in a higher-priority directory disables this generator.',
    'mask_empty': 'An empty file is a mask. It disables this name here and in every lower-priority directory.',
    'mask_char_device': 'An entry resolving to a character device such as /dev/null is a mask. It disables this '
                        'name here and in every lower-priority directory.',
    'mask_dev_null_symlink': 'On this systemd version a symlink to /dev/null is a mask even when it cannot be '
                             'resolved. It disables this name here and in every lower-priority directory.',
    'unresolvable': 'The entry cannot be resolved (for example a dangling symlink), so systemd skips it. It does '
                    'not hide a same-named generator in a lower-priority directory.',
    'not_regular': 'Only regular files are run. A directory or other file type is skipped and does not hide a '
                   'same-named generator in a lower-priority directory.',
    'not_executable': 'The file has no execute bit, so systemd skips it. It does not hide a same-named generator '
                      'in a lower-priority directory.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
    'shadow_undetermined': 'A same-named entry in a higher-priority directory has an undetermined outcome, so '
                           'whether this one runs is not determined.',
    'higher_directory_unobserved': 'A higher-priority directory was not fully observed and could override or '
                                   'mask this name, so whether this one runs is not determined.',
}
MASK_CODES = frozenset({'mask_empty', 'mask_char_device', 'mask_dev_null_symlink'})
OBSERVATIONS = {
    'not_root_owned': 'The generator is owned by a non-root user, who can change what {runs_as} runs.',
    'group_or_world_writable': 'The generator is writable by group or other users, who can change what '
                               '{runs_as} runs.',
    'runtime_directory': 'The generator is in /run, which is cleared at reboot, so it was placed at runtime.',
    'overrides_lower': 'This generator replaces a same-named entry in a lower-priority directory.',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


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


def _sort_key(name: str) -> bytes:
    return name.encode('utf-8', 'surrogateescape')


def _valid_name(name: Any) -> bool:
    if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\x00' in name:
        return False
    try:
        return len(_sort_key(name)) <= 255
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


def directories_for(kind: str, libexec: str | None) -> list[str | None]:
    """Return the search directories of one generator kind, highest priority first.

    The last element is ``None`` for ``system`` when the compiled-in libexec directory is unknown.
    """
    subdir = KINDS[kind]['subdir']
    if kind == 'system':
        vendor = f'{libexec}/{subdir}' if libexec else None
    else:
        vendor = f'{VENDOR_LIB}/{subdir}'
    return [f'{prefix}/{subdir}' for prefix in HIGHER_PREFIXES] + [vendor]


def _libexec(libexec_dir: Any, merged_usr: Any, gaps: list[dict[str, Any]]) -> str | None:
    if libexec_dir is not None:
        if libexec_dir not in LIBEXEC_DIRS:
            _gap(gaps, 'input_malformed', detail=f'libexec_dir must be one of {", ".join(LIBEXEC_DIRS)}.')
            return None
        return libexec_dir
    if merged_usr is True:
        return LIBEXEC_DIRS[0]
    if merged_usr is not None and merged_usr is not False:
        _gap(gaps, 'input_malformed', detail='merged_usr must be True, False or None.')
        return None
    _gap(gaps, 'libexec_dir_unknown',
         detail='/lib is not known to be merged with /usr/lib and the compiled-in libexec directory was not '
                'supplied, so which vendor system-generators directory systemd scans is unknown.')
    return None


def _directory(observation: Any, path: str, gaps: list[dict[str, Any]]) -> tuple[str | None, bool, list[Any]]:
    """Return ``(state, fully_observed, entries)`` for one directory observation."""
    if observation is None:
        _gap(gaps, 'directory_not_observed', path, f'No listing result was supplied for {path}.')
        return None, False, []
    state = observation.get('state') if isinstance(observation, dict) else None
    complete = observation.get('complete') if isinstance(observation, dict) else None
    entries = observation.get('entries', []) if isinstance(observation, dict) else None
    if state not in DIRECTORY_STATES or not isinstance(entries, (list, tuple)) \
            or (state == 'listed' and not isinstance(complete, bool)) \
            or (complete is not None and not isinstance(complete, bool)):
        _gap(gaps, 'input_malformed', path, 'The directory observation is malformed.')
        return None, False, []
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', path, f'{path} exists but could not be listed.')
        return state, False, []
    if state in ('absent', 'not_directory'):
        if entries:
            _gap(gaps, 'input_malformed', path, 'Entries were supplied for a directory reported absent.')
            return state, False, []
        return state, True, []
    if not complete:
        _gap(gaps, 'listing_incomplete', path, f'The listing of {path} did not finish.')
    entries = list(entries)
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', path, f'Only the first {MAX_ENTRIES} entries are assessed.')
        return state, False, entries[:MAX_ENTRIES]
    return state, bool(complete), entries


def _normalize(item: Any, gaps: list[dict[str, Any]], directory: str) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_name(item.get('name')):
        _gap(gaps, 'input_malformed', directory, 'An entry observation has no valid name or type.')
        return None
    if item.get('type') not in ENTRY_TYPES:
        # The name is known but nothing else is: keep it as an undetermined entry so that it still
        # shadows same-named entries in lower-priority directories instead of silently vanishing.
        _gap(gaps, 'input_malformed', f'{directory}/{item["name"]}', 'An entry observation has no valid type.')
        return {'name': item['name'], 'type': None, 'resolved': False, 'malformed': True}
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


def _assess(entry: dict[str, Any], path: str, version: int | None,
            gaps: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None]:
    """Return the reason code for one normalized, unshadowed entry, and its followed stat."""
    if entry['type'] == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', path, 'What the symlink resolves to was not supplied.')
            return 'unresolved', None
        if entry['target'] is None:
            if entry.get('link_target') == '/dev/null':
                if version is None:
                    _gap(gaps, 'metadata_missing', path,
                         'A dangling symlink to /dev/null is a mask only from systemd v258, and the version is '
                         'unknown.')
                    return 'unresolved', None
                if version >= DEV_NULL_SYMLINK_MASK_VERSION:
                    return 'mask_dev_null_symlink', None
            return 'unresolvable', None
        stat = entry['target']
    elif entry['type'] == 'file':
        stat = entry
    else:
        stat = {'type': entry['type']}
    if stat['type'] == 'char_device':
        return 'mask_char_device', stat
    if stat['type'] != 'file':
        return 'not_regular', stat
    if stat['size'] == 0:
        return 'mask_empty', stat
    if not stat['mode'] & 0o111:
        return 'not_executable', stat
    return 'runs', stat


def _kind(kind: str, libexec: str | None, directories: dict[str, Any], version: int | None,
          gaps: list[dict[str, Any]]) -> dict[str, Any]:
    spec = KINDS[kind]
    paths = directories_for(kind, libexec)
    result: dict[str, Any] = {
        'kind': kind, 'manager': spec['manager'], 'runs_as': spec['runs_as'], 'execution': spec['execution'],
        'start_order': 'byte', 'errors': 'ignored', 'timeout_seconds': TIMEOUT_SECONDS,
        'arguments': list(spec['arguments']), 'output': spec['output'], 'when': spec['when'],
        'directories': [], 'entries': [], 'generators': [],
    }
    winners: dict[str, dict[str, Any]] = {}
    masks: dict[str, dict[str, Any]] = {}
    undetermined: set[str] = set()
    records: list[dict[str, Any]] = []
    uncertain_below: int | None = None
    for priority, path in enumerate(paths):
        if path is None:
            result['directories'].append({'path': None, 'priority': priority, 'state': None})
            uncertain_below = priority if uncertain_below is None else uncertain_below
            continue
        state, fully, entries = _directory(directories.get(path), path, gaps)
        result['directories'].append({'path': path, 'priority': priority, 'state': state})
        seen: set[str] = set()
        for item in entries:
            entry = _normalize(item, gaps, path)
            if entry is None:
                # An entry without a usable name could be any name, so nothing below it is certain.
                fully = False
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
            elif name in winners:
                code = 'overridden'
            elif name in masks:
                code = 'masked'
            elif name in undetermined:
                code = 'shadow_undetermined'
            elif not entry['resolved']:
                if not entry.get('malformed'):
                    _gap(gaps, 'metadata_missing', entry_path,
                         'Required metadata for this entry was not supplied or is malformed.')
                code = 'unresolved'
            else:
                code, stat = _assess(entry, entry_path, version, gaps)
            if uncertain_below is not None and priority > uncertain_below and (code == 'runs' or code in MASK_CODES):
                # Overridden and masked outcomes stay certain: the shadowing entry sits above the gap.
                code = 'higher_directory_unobserved'
            status = ('runs' if code == 'runs' else 'masks' if code in MASK_CODES
                      else 'unresolved' if code in ('unresolved', 'shadow_undetermined', 'higher_directory_unobserved')
                      else 'skipped')
            record: dict[str, Any] = {'name': name, 'path': entry_path, 'directory_priority': priority,
                                      'type': entry['type'], 'status': status, 'reason_code': code,
                                      'reason': REASONS[code], 'observations': []}
            if 'link_target' in entry:
                record['link_target'] = entry['link_target']
            if code in ('overridden', 'masked'):
                record['shadowed_by'] = (winners.get(name) or masks[name])['path']
            if code == 'runs':
                winners[name] = record
                record['overrides'] = []
                if stat is not None:
                    if stat['uid'] != 0:
                        record['observations'].append({'code': 'not_root_owned', 'uid': stat['uid'], 'detail':
                                                       OBSERVATIONS['not_root_owned'].format(runs_as=spec['runs_as'])})
                    if stat['mode'] & 0o022:
                        record['observations'].append({'code': 'group_or_world_writable',
                                                       'mode': f'{stat["mode"]:04o}', 'detail':
                                                       OBSERVATIONS['group_or_world_writable'].format(
                                                           runs_as=spec['runs_as'])})
                if path.startswith('/run/'):
                    record['observations'].append({'code': 'runtime_directory',
                                                   'detail': OBSERVATIONS['runtime_directory']})
            elif code in MASK_CODES:
                masks[name] = record
                record['masks'] = []
            elif code in ('unresolved', 'shadow_undetermined', 'higher_directory_unobserved'):
                undetermined.add(name)
            if code == 'overridden':
                winners[name]['overrides'].append(entry_path)
            elif code == 'masked':
                masks[name]['masks'].append(entry_path)
            records.append(record)
        if not fully and uncertain_below is None:
            uncertain_below = priority
    for record in winners.values():
        if record['overrides'] and not any(obs['code'] == 'overrides_lower' for obs in record['observations']):
            record['observations'].append({'code': 'overrides_lower', 'detail': OBSERVATIONS['overrides_lower']})
    runnable = sorted(winners.values(), key=lambda rec: _sort_key(rec['name']))
    for index, record in enumerate(runnable):
        record['start_order'] = index
        generator: dict[str, Any] = {'start_order': index, 'name': record['name'], 'path': record['path'],
                                     'overrides': list(record['overrides']),
                                     'observations': [obs['code'] for obs in record['observations']]}
        if 'link_target' in record:
            generator['link_target'] = record['link_target']
        result['generators'].append(generator)
    result['entries'] = sorted(records, key=lambda rec: (_sort_key(rec['name']), rec['directory_priority']))
    result['complete'] = uncertain_below is None and not any(
        rec['status'] == 'unresolved' for rec in records)
    return result


def evaluate(*, systemd_version: Any = None, merged_usr: Any = None, libexec_dir: Any = None,
             directories: Any = None, kinds: Any = None) -> dict[str, Any]:
    """Resolve which systemd generators run from supplied directory metadata.

    ``systemd_version`` is the installed systemd version (``252`` or ``'252.39-1~deb12u1'``).
    ``merged_usr`` is ``True`` when ``/lib`` was observed to be a symlink to ``usr/lib``. Otherwise
    pass ``libexec_dir`` (``/usr/lib/systemd`` or ``/lib/systemd``), the build's compiled-in
    directory. Only the vendor ``system-generators`` directory depends on it.

    ``directories`` maps each search directory (see :func:`directories_for`) to
    ``{'state', 'complete', 'entries'}``:

    * ``state`` is ``listed``, ``absent``, ``not_directory`` or ``unreadable``.
    * Each entry carries ``name`` and ``type`` as ``lstat`` reports it: ``file``, ``directory``,
      ``symlink``, ``char_device`` or ``other``.
    * A ``file`` carries ``mode`` (0–0o7777), ``size`` and ``uid``.
    * A ``symlink`` carries ``target``, which is what ``stat`` reports after following it (same
      fields, with a ``type`` other than ``symlink``), or ``None`` when ``stat`` fails.
    * ``link_target`` (the raw link text) is optional, except that it decides whether a dangling
      symlink to ``/dev/null`` is a mask on v258.

    ``kinds`` optionally limits the result to some of ``KINDS``; every directory of each
    requested kind must then be observed.
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
    if kinds is None:
        selected = list(KINDS)
    elif isinstance(kinds, (list, tuple)) and kinds and all(kind in KINDS for kind in kinds):
        selected = [kind for kind in KINDS if kind in kinds]
    else:
        _gap(gaps, 'input_malformed', detail=f'kinds must be a non-empty list of {", ".join(KINDS)}.')
        selected = list(KINDS)
    needs_libexec = 'system' in selected
    libexec = _libexec(libexec_dir, merged_usr, gaps) if needs_libexec else None
    if directories is None:
        directories = {}
    if not isinstance(directories, dict):
        _gap(gaps, 'input_malformed', detail='directories must map search directory paths to observations.')
        directories = {}
    known = {path for kind in selected for path in directories_for(kind, libexec) if path}
    if libexec is None and needs_libexec:
        known.update(f'{candidate}/system-generators' for candidate in LIBEXEC_DIRS)
    unknown = sorted(path for path in directories if path not in known)
    if unknown:
        _gap(gaps, 'input_malformed', detail='Observations were supplied for directories systemd does not '
                                             f'search for the requested kinds: {", ".join(map(str, unknown[:8]))}.')
    results = {kind: _kind(kind, libexec, directories, version, gaps) for kind in selected}
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference_versions': list(REFERENCE_VERSIONS),
        'systemd_version': version, 'libexec_dir': libexec, 'kinds': results,
        'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
