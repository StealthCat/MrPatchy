"""Pure cloud-init script-directory contract (roadmap F slice, #1271).

cloud-init's final-stage modules ``scripts_per_boot``, ``scripts_per_instance``
and ``scripts_per_once`` each run every executable entry of one directory under
the cloud directory (``/var/lib/cloud`` by default) as root:

- ``scripts/per-boot``: frequency ``always``, so at every boot.
- ``scripts/per-instance``: frequency ``instance``, so once per instance ID, and
  again whenever the instance ID changes (for example a cloned image).
- ``scripts/per-once``: frequency ``once``, so once until its semaphore is removed.

This module takes captured, read-only metadata for those directories and says
which entries would run, in what order, and why the others are skipped. It never
reads a script's contents, performs no I/O, never runs a command and never
authorizes a response action.

The rules follow ``cloudinit/subp.py`` (``runparts`` and ``is_exe``) and
``cloudinit/config/cc_scripts_per_{boot,instance,once}.py`` in cloud-init 24.4,
read from the upstream source:

- ``runparts`` returns without running anything when ``os.path.isdir`` of the
  directory is false, so an absent directory, a non-directory or a dangling
  symlink runs nothing. ``isdir`` follows symlinks.
- Entries come from ``sorted(os.listdir(dir))``: Python code-point order of the
  names, with ``.`` and ``..`` excluded. There is **no name filter**: unlike
  ``run-parts``, hidden names, editor backups such as ``x~`` and package leftovers
  such as ``x.dpkg-old`` are run when executable.
- An entry runs when ``os.path.isfile(path) and os.access(path, os.X_OK)``.
  ``isfile`` follows symlinks, so a symlink to a regular file counts and a
  dangling symlink is skipped. cloud-init runs as root, and Linux grants root
  ``X_OK`` on a regular file when any execute bit is set and the file is not on
  a ``noexec`` mount. A non-executable regular file is skipped with a warning;
  anything else (a directory, a device, a FIFO) is skipped silently.
- Each script is executed directly as ``[path]`` with ``shell=False`` and no
  prefix, so a script without a ``#!`` line or a valid binary format fails to
  start. A failing script does not stop later ones; the module reports failure
  after the loop.

Fail-closed rules: an unobserved, unreadable or truncated directory listing,
malformed or missing metadata, an unobserved symlink target and over-limit input
are blocking gaps and are never reported as covered. ``origin`` is always
``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = 'cloud-init 24.4 cloudinit/subp.py runparts/is_exe and cloudinit/config/cc_scripts_per_*.py'
CLOUD_DIR = '/var/lib/cloud'
RUNS_AS = 'root'
# Directory under ``<cloud_dir>/scripts``, its module and its cloud-init frequency.
DIRECTORIES = (
    ('per-boot', 'scripts_per_boot', 'always'),
    ('per-instance', 'scripts_per_instance', 'instance'),
    ('per-once', 'scripts_per_once', 'once'),
)
FREQUENCIES = {
    'always': 'At every boot.',
    'instance': 'Once per instance ID, and again whenever the instance ID changes.',
    'once': 'Once, until the per-once semaphore is removed.',
}
MAX_ENTRIES = 1024
MAX_NAME_BYTES = 255
MAX_LINK = 4096
MAX_GAPS = 64
FILE_TYPES = ('file', 'directory', 'symlink', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'duplicate_name', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'gaps_truncated',
})
NOT_OBSERVED = (
    ('Whether cloud-init is installed and enabled (for example /etc/cloud/cloud-init.disabled, the cloud-init= '
     'kernel argument or ds-identify), and whether its final stage runs at boot.'),
    ('Whether cloud_final_modules lists scripts_per_boot, scripts_per_instance and scripts_per_once; the '
     'distribution default does.'),
    'A non-default system_info paths cloud_dir; the default /var/lib/cloud is assumed.',
    'Semaphore state, so whether a per-instance or per-once script has already run for this instance.',
    'User-data scripts (scripts_user, /var/lib/cloud/instance/scripts) and vendor scripts (scripts_vendor).',
    'Script contents, interpreters, a missing #! line and anything a script runs are not read.',
    'Security modules such as AppArmor or SELinux that could stop a script are not assessed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'runs': 'cloud-init runs this entry as root, executed directly without a shell.',
    'directory': 'Not a regular file after following symlinks, so cloud-init skips it.',
    'not_executable': 'A regular file with no execute bit, so root cannot execute it and cloud-init skips it '
                      'with a warning.',
    'noexec_mount': 'The file is on a noexec mount, so root cannot execute it and cloud-init skips it with a '
                    'warning.',
    'stat_failed': 'The symlink does not resolve, so os.path.isfile is false and cloud-init skips it.',
    'not_plain_file': 'Not a regular file after following symlinks, so cloud-init skips it.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
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


def _valid_name(name: Any) -> bool:
    if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\x00' in name:
        return False
    try:
        return len(name.encode('utf-8', 'surrogateescape')) <= MAX_NAME_BYTES
    except UnicodeEncodeError:
        return False


def _mode(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0o7777


def _optional_bool(value: Any) -> bool:
    return value is None or isinstance(value, bool)


def _stat(meta: Any) -> dict[str, Any] | None:
    """Validate one followed-stat mapping (``type``, and ``mode`` for a regular file)."""
    if not isinstance(meta, dict) or meta.get('type') not in ('file', 'directory', 'other'):
        return None
    if meta['type'] == 'file' and not _mode(meta.get('mode')):
        return None
    if not _optional_bool(meta.get('noexec')):
        return None
    return {'type': meta['type'], 'mode': meta.get('mode'), 'noexec': meta.get('noexec')}


def _normalize(item: Any, base: str, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_name(item.get('name')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', base, 'An entry observation has no valid name or type.')
        return None
    entry: dict[str, Any] = {'name': item['name'], 'type': item['type'], 'resolved': True}
    if item['type'] == 'symlink':
        link = item.get('link_target')
        if isinstance(link, str) and link and len(link) <= MAX_LINK and not _CONTROL.search(link):
            entry['link_target'] = link
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
        if not _mode(item.get('mode')):
            entry['resolved'] = False
        else:
            entry['mode'] = item['mode']
    return entry


def _assess(entry: dict[str, Any], dir_noexec: bool | None, path: str, gaps: list[dict[str, Any]]) -> str:
    """Reason code for one normalized entry under ``is_exe`` as root."""
    if not entry['resolved']:
        _gap(gaps, 'metadata_missing', path, 'The entry metadata is missing or malformed.')
        return 'unresolved'
    if entry['type'] == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', path, 'What the symlink resolves to was not supplied.')
            return 'unresolved'
        if entry['target'] is None:
            return 'stat_failed'
        stat = entry['target']
        noexec = stat['noexec']
    else:
        stat = {'type': entry['type'], 'mode': entry.get('mode')}
        noexec = dir_noexec
    if stat['type'] == 'directory':
        return 'directory'
    if stat['type'] != 'file':
        return 'not_plain_file'
    if not stat['mode'] & 0o111:
        return 'not_executable'
    if noexec:
        return 'noexec_mount'
    if noexec is None:
        entry['mount_unobserved'] = True
    return 'runs'


def _directory(subdir: str, module: str, frequency: str, observed: Any, cloud_dir: str,
               gaps: list[dict[str, Any]]) -> dict[str, Any]:
    base = f'{cloud_dir}/scripts/{subdir}'
    out: dict[str, Any] = {'directory': base, 'module': module, 'frequency': frequency,
                           'frequency_detail': FREQUENCIES[frequency], 'state': None, 'scripts': [],
                           'skipped': [], 'complete': False}
    if observed is None:
        _gap(gaps, 'directory_not_observed', base, 'No listing result was supplied.')
        return out
    state = observed.get('state') if isinstance(observed, dict) else None
    if state not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', base, 'The directory observation has no valid state.')
        return out
    out['state'] = state
    if state in ('absent', 'not_directory'):
        # runparts() returns when os.path.isdir() is false: nothing runs.
        if observed.get('entries'):
            _gap(gaps, 'input_malformed', base, 'Entries were supplied for a directory that is not one.')
            return out
        out['complete'] = True
        return out
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', base, 'The directory could not be listed, so its scripts are unknown.')
        return out
    noexec = observed.get('noexec')
    complete = observed.get('complete')
    entries = observed.get('entries')
    if not _optional_bool(noexec) or not isinstance(complete, bool) or not isinstance(entries, list):
        _gap(gaps, 'input_malformed', base, 'The listing needs a boolean complete flag and an entries list.')
        return out
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', base, f'More than {MAX_ENTRIES} entries were supplied.')
        return out
    ok = complete
    if not complete:
        _gap(gaps, 'listing_incomplete', base, 'The listing was truncated, so later entries are unknown.')
    normalized: dict[str, dict[str, Any]] = {}
    for item in entries:
        entry = _normalize(item, base, gaps)
        if entry is None:
            ok = False
            continue
        if entry['name'] in normalized:
            _gap(gaps, 'duplicate_name', f"{base}/{entry['name']}", 'The same name was listed twice.')
            ok = False
            continue
        normalized[entry['name']] = entry
    # sorted(os.listdir()): Python code-point order of the str names cloud-init sees.
    for name in sorted(normalized):
        entry = normalized[name]
        path = f'{base}/{name}'
        reason = _assess(entry, noexec, path, gaps)
        record: dict[str, Any] = {'name': name, 'path': path, 'type': entry['type'], 'reason': reason,
                                  'reason_detail': REASONS[reason]}
        if 'link_target' in entry:
            record['link_target'] = entry['link_target']
        if reason == 'unresolved':
            ok = False
        if reason == 'runs':
            record.update({'order': len(out['scripts']) + 1, 'argv': [path], 'runs_as': RUNS_AS,
                           'frequency': frequency, 'hidden_name': name.startswith('.'),
                           'mount_unobserved': bool(entry.get('mount_unobserved'))})
            out['scripts'].append(record)
        else:
            out['skipped'].append(record)
    out['complete'] = ok
    return out


def assess(directories: Any) -> dict[str, Any]:
    """Return which cloud-init script-directory entries run as root.

    ``directories`` maps ``per-boot``, ``per-instance`` and ``per-once`` to an
    observation ``{'state': 'listed'|'absent'|'not_directory'|'unreadable',
    'complete': bool, 'noexec': bool|None, 'entries': [...]}``, where the state is
    the result of following any symlink to the directory. Each entry is
    ``{'name', 'type': 'file'|'directory'|'symlink'|'other', 'mode'}``; a symlink
    adds ``link_target`` and ``target``, the followed stat ``{'type', 'mode',
    'noexec'}`` or ``None`` when it does not resolve. A key that is missing means
    the directory was not observed.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'cloud_dir': CLOUD_DIR,
        'runs_as': RUNS_AS, 'directories': [], 'scripts': [], 'complete': False, 'gaps': gaps,
        'not_observed': list(NOT_OBSERVED), 'origin': 'not_assessed', 'verdict': None,
        'note': NOT_A_VERDICT,
    }
    if not isinstance(directories, dict) or any(not isinstance(k, str) for k in directories) \
            or set(directories) - {d[0] for d in DIRECTORIES}:
        _gap(gaps, 'input_malformed', detail='Directory observations must be keyed by per-boot, per-instance '
                                             'and per-once.')
        return result
    for subdir, module, frequency in DIRECTORIES:
        out = _directory(subdir, module, frequency, directories.get(subdir), CLOUD_DIR, gaps)
        result['directories'].append(out)
        result['scripts'].extend(out['scripts'])
    result['complete'] = all(d['complete'] for d in result['directories']) \
        and not any(g['code'] in BLOCKING for g in gaps)
    return result
