"""Pure ISC dhclient hook contract (roadmap F slice, #1063).

Takes captured, read-only metadata for ``/etc/dhcp`` and its two hook
directories and says which hook files Debian's and Ubuntu's ``dhclient-script``
*sources* as root, in which phase and order, and why the other entries are not
used. It never reads hook contents.

Semantics follow ``/sbin/dhclient-script`` from ``isc-dhcp-client``
4.4.3-P1-4ubuntu2 (``run_hook``, ``run_hookdir`` and ``exit_with_hooks``) and
``run-parts --list`` from debianutils 5.17. Both were read and checked by
running them:

* Before handling any ``reason``, the script sources
  ``/etc/dhcp/dhclient-enter-hooks`` and then each entry that
  ``run-parts --list /etc/dhcp/dhclient-enter-hooks.d`` prints.
* ``exit_with_hooks`` sources ``/etc/dhcp/dhclient-exit-hooks`` and then each
  ``run-parts --list /etc/dhcp/dhclient-exit-hooks.d`` entry.
* A hook is sourced with ``.`` when ``[ -f "$script" ]`` holds. That means a
  regular file after following symlinks. The executable bit, owner and mode do
  not matter. The script runs as root, so it can read any regular file.
* A hook directory is used only when ``[ -d "$dir" ]`` holds, following
  symlinks.
* Without ``--lsbsysinit``, ``run-parts --list`` prints only names that fully
  match ``^[A-Za-z0-9_-]+$``, so ``hook.sh``, dotfiles and backup names are not
  sourced. It skips directories, special files and symlinks it cannot ``stat``
  (dangling or looping), and prints the rest in byte order. ``dhclient`` gives
  the script only ``PATH`` and its own DHCP variables, so collation is the C
  locale.

It performs no I/O, never runs a command and never authorizes a response
action. Missing or malformed metadata, an unobserved directory or symlink
target, an unsupported or unobserved client version or distribution family, and
over-limit input are explicit blocking gaps. They are never reported as
covered. No record is labelled safe, and ``origin`` is always ``not_assessed``.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'package': 'isc-dhcp-client',
    'version': '4.4.3-P1-4ubuntu2',
    'script': '/sbin/dhclient-script',
    'script_sha256': '52a321a4c2090abf2e1903fc7e6e3c20524c87c14febb136e6d19735ba2ef264',
    'run_parts': 'debianutils 5.17',
}
MAX_FILES = 1024
MAX_PATH = 4096
MAX_GAPS = 64

CONF_DIR = '/etc/dhcp'
ENTER_FILE = '/etc/dhcp/dhclient-enter-hooks'
EXIT_FILE = '/etc/dhcp/dhclient-exit-hooks'
ENTER_DIR = '/etc/dhcp/dhclient-enter-hooks.d'
EXIT_DIR = '/etc/dhcp/dhclient-exit-hooks.d'
OBSERVED_DIRS = (CONF_DIR, ENTER_DIR, EXIT_DIR)
HOOK_FILES = {ENTER_FILE: 'enter', EXIT_FILE: 'exit'}
HOOK_DIRS = {ENTER_DIR: 'enter', EXIT_DIR: 'exit'}
PHASE_WHEN = {
    'enter': 'Sourced as root at the start of every dhclient-script run, before the DHCP reason is handled.',
    'exit': 'Sourced as root when dhclient-script finishes through exit_with_hooks, after the DHCP reason is '
            'handled.',
}
FILE_TYPES = ('file', 'symlink', 'directory', 'other')
TARGET_TYPES = ('file', 'directory', 'other')
DIR_STATES = ('listed', 'absent', 'unreadable')
BLOCKING = frozenset({
    'input_malformed', 'too_many_files', 'duplicate_path', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'version_not_observed', 'version_unsupported',
    'family_not_observed', 'family_unsupported', 'gaps_truncated',
})
UNOBSERVED = (
    ('Hook contents are not read. A sourced hook runs inside dhclient-script, so it can change variables, '
     'redefine functions or exit and stop the hooks after it.'),
    ('Whether dhclient is installed and used (rather than systemd-networkd, NetworkManager\'s internal client or '
     'dhcpcd) and which DHCP events occur are not observed.'),
    'A replacement script named by a dhclient.conf "script" statement or the -sf option is not observed.',
    'Some dhclient-script error paths exit without running the exit hooks.',
    'RPM-family dhclient-script, which uses different hook locations, is not modelled.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'sourced': 'dhclient-script sources this file as root.',
    'name_filtered': 'run-parts --list prints only names made of letters, digits, "_" and "-", so this entry is '
                     'not sourced.',
    'not_regular': 'Only regular files are sourced; this entry is a directory or special file after following '
                   'symlinks.',
    'unresolvable_symlink': 'The symlink cannot be followed (dangling, looping or otherwise failing stat), so it '
                            'is not sourced.',
    'nested_entry': 'Hook directories are not searched recursively.',
    'not_a_hook_location': 'dhclient-script does not source this path.',
    'directory_not_used': 'The containing hook directory is absent or not a directory, so it is not searched.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_NAME = re.compile(r'[A-Za-z0-9_-]+')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_VERSION = re.compile(r'(?:\d+:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:-P\d{1,3})?(?:[-+~.][0-9A-Za-z.+~-]{0,64})?')
SUPPORTED_SERIES = ((4, 4),)


def run_parts_name(name: str) -> bool:
    """Return whether ``run-parts --list`` (no ``--lsbsysinit``) prints an entry with this name."""
    return isinstance(name, str) and _NAME.fullmatch(name) is not None


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


def _valid_path(path: Any) -> bool:
    return (isinstance(path, str) and 1 < len(path) <= MAX_PATH and path.startswith('/')
            and not _CONTROL.search(path) and posixpath.normpath(path) == path and not path.startswith('//'))


def _check_environment(version: Any, family: Any, script_sha256: Any, gaps: list[dict[str, Any]]) -> bool | None:
    """Validate the client version and family. Returns whether the script matches the reference hash."""
    if family is None:
        _gap(gaps, 'family_not_observed', detail='The distribution family was not supplied.')
    elif family != 'debian':
        _gap(gaps, 'family_unsupported', detail='Only the Debian/Ubuntu dhclient-script is modelled.')
    if version is None:
        _gap(gaps, 'version_not_observed', detail='The isc-dhcp-client package version was not supplied.')
    else:
        match = _VERSION.fullmatch(version) if isinstance(version, str) else None
        if match is None or (int(match.group(1)), int(match.group(2))) not in SUPPORTED_SERIES:
            _gap(gaps, 'version_unsupported',
                 detail='Only the isc-dhcp-client 4.4 series is assessed; the rules were read from 4.4.3-P1-4ubuntu2.')
    if script_sha256 is None:
        verified = None
    elif isinstance(script_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', script_sha256):
        verified = script_sha256 == REFERENCE['script_sha256']
    else:
        _gap(gaps, 'input_malformed', detail='The dhclient-script SHA-256 must be 64 lowercase hex characters.')
        verified = None
    if verified is not True:
        _gap(gaps, 'script_not_reference',
             detail='The hook rules were read from the reference dhclient-script; this host\'s script was not shown '
                    'to be identical.')
    return verified


def _directories(directories: Any, gaps: list[dict[str, Any]]) -> dict[str, str]:
    states: dict[str, str] = {}
    if directories is not None and not isinstance(directories, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='Directory observations must be a list.')
    for item in directories if isinstance(directories, (list, tuple)) else ():
        path = item.get('path') if isinstance(item, dict) else None
        state = item.get('state') if isinstance(item, dict) else None
        if path not in OBSERVED_DIRS or state not in DIR_STATES or path in states:
            _gap(gaps, 'input_malformed', detail='A directory observation is malformed, unknown or repeated.')
            continue
        states[path] = state
    if states.get(CONF_DIR) == 'absent':
        for path in (ENTER_DIR, EXIT_DIR):
            if states.setdefault(path, 'absent') != 'absent':
                _gap(gaps, 'input_malformed', path, 'A hook directory was reported inside an absent /etc/dhcp.')
    for path in OBSERVED_DIRS:
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
    entry: dict[str, Any] = {'path': item['path'], 'type': item['type']}
    if item['type'] != 'symlink':
        entry['effective'] = item['type']
        return entry
    link = item.get('link_target')
    if isinstance(link, str) and link and len(link) <= MAX_PATH and '\x00' not in link:
        entry['link_target'] = link
    if 'target' not in item:
        entry['effective'] = None  # unobserved
    elif item['target'] is None:
        entry['effective'] = 'unresolvable'
    elif isinstance(item['target'], dict) and item['target'].get('type') in TARGET_TYPES:
        entry['effective'] = item['target']['type']
    else:
        entry['effective'] = None
    return entry


def _record(entry: dict[str, Any], status: str, reason: str, **extra: Any) -> dict[str, Any]:
    record = {'path': entry['path'], 'type': entry['type'], 'status': status, 'reason_code': reason,
              'reason': REASONS[reason]}
    if entry.get('link_target') is not None:
        record['link_target'] = entry['link_target']
    record.update(extra)
    return record


def _file_outcome(entry: dict[str, Any], gaps: list[dict[str, Any]]) -> tuple[str, str]:
    effective = entry['effective']
    if effective is None:
        code = 'symlink_target_unobserved' if entry['type'] == 'symlink' else 'metadata_missing'
        _gap(gaps, code, entry['path'], 'Required metadata for this entry was not supplied or is malformed.')
        return 'unresolved', 'unresolved'
    if effective == 'unresolvable':
        return 'ignored', 'unresolvable_symlink'
    if effective != 'file':
        return 'ignored', 'not_regular'
    return 'sourced', 'sourced'


def evaluate(files: Any, *, directories: Any = None, version: Any = None, family: Any = None,
             script_sha256: Any = None) -> dict[str, Any]:
    """Resolve which dhclient hook files dhclient-script sources from supplied metadata.

    ``files`` lists the entries of ``/etc/dhcp`` and of its two hook directories, each a mapping
    with ``path`` (absolute, normalized) and ``type`` (``file``, ``symlink``, ``directory`` or
    ``other``, from ``lstat``). A symlink also carries ``target``: ``{'type': ...}`` with ``file``,
    ``directory`` or ``other`` from ``stat``, or ``None`` when ``stat`` fails (dangling, looping or
    otherwise unresolvable). ``link_target`` (the raw link text) is optional and only echoed.
    ``directories`` gives ``{'path', 'state'}`` for ``/etc/dhcp`` and both hook directories, with
    state ``listed``, ``absent`` (missing, or not a directory after following symlinks) or
    ``unreadable``. ``version`` is the ``isc-dhcp-client`` package version, ``family`` the
    distribution family (only ``debian`` is modelled) and ``script_sha256`` the optional SHA-256 of
    ``/sbin/dhclient-script``.
    """
    gaps: list[dict[str, Any]] = []
    verified = _check_environment(version, family, script_sha256, gaps)
    states = _directories(directories, gaps)
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'script_matches_reference': verified,
        'files': [], 'phases': {phase: {'when': PHASE_WHEN[phase], 'hooks': []} for phase in PHASE_WHEN},
        'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    if not isinstance(files, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='File observations must be a list.')
        files = ()
    if len(files) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'Only the first {MAX_FILES} file observations are assessed.')
        files = files[:MAX_FILES]

    seen: set[str] = set()
    single: dict[str, dict[str, Any]] = {}
    listed: dict[str, list[tuple[bytes, dict[str, Any]]]] = {'enter': [], 'exit': []}
    records: list[dict[str, Any]] = []
    for item in files:
        entry = _normalize(item, gaps)
        if entry is None:
            continue
        path = entry['path']
        if path in seen:
            _gap(gaps, 'duplicate_path', path, 'The path was supplied more than once; the first is used.')
            continue
        seen.add(path)
        parent = posixpath.dirname(path)
        if parent in OBSERVED_DIRS and states.get(parent) == 'absent':
            _gap(gaps, 'input_malformed', path, 'A file was supplied for a directory reported absent.')
        if path in HOOK_FILES:
            status, reason = _file_outcome(entry, gaps)
            record = _record(entry, status, reason, phase=HOOK_FILES[path])
            if status == 'sourced':
                single[HOOK_FILES[path]] = record
        elif parent in HOOK_DIRS:
            phase = HOOK_DIRS[parent]
            name = posixpath.basename(path)
            if states.get(parent) == 'absent':
                record = _record(entry, 'ignored', 'directory_not_used', phase=phase)
            elif not run_parts_name(name):
                record = _record(entry, 'ignored', 'name_filtered', phase=phase)
            else:
                status, reason = _file_outcome(entry, gaps)
                record = _record(entry, status, reason, phase=phase)
                if status == 'sourced':
                    listed[phase].append((name.encode('ascii'), record))
        elif path in HOOK_DIRS:
            effective, state = entry['effective'], states.get(path)
            if (state == 'listed' and effective not in ('directory', None)) or (
                    state == 'absent' and effective == 'directory'):
                _gap(gaps, 'input_malformed', path,
                     'The file metadata for this hook directory contradicts its directory observation.')
            record = _record(entry, 'ignored', 'not_a_hook_location')
        elif any(path.startswith(directory + '/') for directory in HOOK_DIRS):
            record = _record(entry, 'ignored', 'nested_entry')
        else:
            record = _record(entry, 'ignored', 'not_a_hook_location')
        records.append(record)

    for phase in PHASE_WHEN:
        ordered = [('file', single[phase])] if phase in single else []
        ordered += [('directory', record) for _, record in sorted(listed[phase], key=lambda pair: pair[0])]
        for index, (source, record) in enumerate(ordered):
            record['order'] = index
            hook = {'order': index, 'path': record['path'], 'source': source}
            if record.get('link_target') is not None:
                hook['link_target'] = record['link_target']
            result['phases'][phase]['hooks'].append(hook)
    result['files'] = records
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
