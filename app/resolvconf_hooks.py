"""Pure resolvconf hook contract (roadmap F slice, #1199).

Takes entry metadata for ``/etc/resolvconf/update.d`` and
``/etc/resolvconf/update-libc.d`` and says which scripts the Debian
``resolvconf`` package runs as root, in which order, on which triggers, and
where coverage is missing. It never runs anything and never reads a script's
contents.

Semantics come from resolvconf 1.78ubuntu7 (``/sbin/resolvconf`` and
``/etc/resolvconf/update.d/libc``) downloaded from archive.ubuntu.com, and
debianutils ``run-parts``, not from recollection:

* ``resolvconf -a IFACE``, ``-d IFACE`` (when a non-empty record is removed)
  and ``-u`` call ``update_and_exit``, which runs
  ``run-parts ${1:+--arg="$1"} ${2:+--arg="$2"} /etc/resolvconf/update.d`` as
  root. There is no ``--exit-on-error`` and no ``--lsbsysinit``, so a failing
  script does not stop later ones. Interface hooks (ifupdown, dhclient, pppd)
  call these on every DNS change.
* When ``/run/resolvconf/enable-updates`` is absent the update is postponed and
  runs on ``resolvconf --enable-updates`` (the boot service).
* The packaged ``update.d/libc`` script ends with
  ``exec run-parts /etc/resolvconf/update-libc.d`` when that directory exists,
  but only after the generated resolv.conf content changed and only when
  ``/etc/resolv.conf`` is symlinked to the dynamic file.
* run-parts considers names matching ``^[A-Za-z0-9_-]+$`` in byte order (no
  ``setlocale``), follows symlinks, and runs regular files root may execute.
  Directories and dangling symlinks are skipped; other types are skipped with
  an error status.

It performs no I/O and never authorizes a response action. Unobserved
family, implementation, listings or metadata, malformed input and over-limit
input are blocking gaps.
"""
from __future__ import annotations

import re
from typing import Any

from app.ifupdown_hooks import _byte_key, _stat_ok

CONTRACT_VERSION = 1
REFERENCE = {'resolvconf': 'resolvconf 1.78ubuntu7 (Ubuntu package)', 'run_parts': 'debianutils run-parts'}
RUNS_AS = 'root'
UPDATE_D = '/etc/resolvconf/update.d'
UPDATE_LIBC_D = '/etc/resolvconf/update-libc.d'
LIBC_SCRIPT = 'libc'
COMMANDS = {
    UPDATE_D: ('/bin/run-parts', '[--arg=-a|-d|-u]', '[--arg=IFACE]', UPDATE_D),
    UPDATE_LIBC_D: ('/bin/run-parts', UPDATE_LIBC_D),
}
TRIGGERS = {
    UPDATE_D: ('resolvconf -a IFACE (interface DNS record added or changed)',
               'resolvconf -d IFACE (non-empty interface record removed)',
               'resolvconf -u (explicit update)',
               'resolvconf --enable-updates when an update was postponed (boot)'),
    UPDATE_LIBC_D: ('update.d/libc, after the generated resolv.conf content changes and only while '
                    '/etc/resolv.conf is symlinked to the dynamic file',),
}
APPLICABLE_FAMILIES = frozenset({'debian'})
KNOWN_FAMILIES = frozenset({'debian', 'rpm'})
DIRECTORY_STATES = ('listed', 'absent', 'unreadable', 'not_directory')
MAX_ENTRIES = 1024
MAX_GAPS = 64
BLOCKING = frozenset({
    'input_malformed', 'family_not_observed', 'family_unsupported', 'implementation_not_observed',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'too_many_entries',
    'metadata_missing', 'symlink_target_unobserved', 'gaps_truncated',
})
UNOBSERVED = (
    'Script contents, including whether update.d/libc is the packaged script, are not read.',
    'Whether updates are currently enabled (/run/resolvconf/enable-updates) and how often DNS changes occur '
    'are not observed.',
    'Whether /etc/resolv.conf is symlinked to the dynamic file, which gates update-libc.d, is not observed.',
    'openresolv, systemd-resolved resolvconf compatibility and NetworkManager DNS handling are not modeled.',
    'A locally modified /sbin/resolvconf or run-parts with different behavior is not detected.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'runs': 'run-parts runs this script as root on every resolvconf update.',
    'runs_if_libc': 'run-parts runs this script as root when update.d/libc runs and resolv.conf changes.',
    'not_invoked': 'update.d/libc does not run, so this directory is never passed to run-parts.',
    'name_rejected': 'run-parts only considers names made of ASCII letters, digits, "_" and "-".',
    'directory': 'Directories are skipped.',
    'not_executable': 'The file has no execute bit, so run-parts skips it.',
    'noexec_mount': 'The file is on a noexec mount, so root cannot execute it and run-parts skips it.',
    'stat_failed': 'The entry cannot be followed (for example a dangling symlink), so run-parts skips it.',
    'not_plain_file': 'Not a regular file or directory; run-parts skips it and reports an error status.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_NAME = re.compile(r'[A-Za-z0-9_-]+')


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
    name = entry['name']
    if not _NAME.fullmatch(name):
        return 'name_rejected'
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
    return 'runs'


def _run_parts(directory: str, listing: Any, gaps: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {'directory': directory, 'state': 'not_observed', 'command': COMMANDS[directory],
                              'triggers': TRIGGERS[directory], 'scripts': []}
    if listing is None:
        _gap(gaps, 'directory_not_observed', directory)
        return result
    if not isinstance(listing, dict) or listing.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', directory, 'Malformed hook directory metadata.')
        return result
    result['state'] = listing['state']
    if listing['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', directory)
    if listing['state'] != 'listed':
        return result
    if listing.get('truncated'):
        _gap(gaps, 'listing_incomplete', directory)
    entries = listing.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries' if isinstance(entries, list) else 'input_malformed', directory)
        return result
    seen: set[str] = set()
    scripts = []
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or '/' in name or name in seen or name in ('.', '..') \
                or '\0' in name:
            _gap(gaps, 'input_malformed', directory, 'An entry has a missing, invalid or duplicate name.')
            continue
        seen.add(name)
        path = f'{directory}/{name}'
        scripts.append({'name': name, 'path': path, 'outcome': _outcome(entry, path, gaps)})
    scripts.sort(key=lambda s: _byte_key(s['name']))
    result['scripts'] = scripts
    return result


def assess(update_d: Any = None, update_libc_d: Any = None, *, family: Any = None,
           resolvconf_installed: Any = None) -> dict[str, Any]:
    """Resolve which resolvconf hook scripts run as root from captured directory metadata.

    ``update_d`` and ``update_libc_d`` are ``{'state': 'listed', 'truncated': bool, 'entries': [{'name',
    'type': 'file'|'directory'|'other'|'symlink', 'mode', 'noexec', 'target'}]}`` or a ``state`` of
    ``absent``, ``unreadable`` or ``not_directory``. A symlink's ``target`` is the followed metadata, or
    ``None`` when it cannot be followed.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'runs_as': RUNS_AS,
        'applicability': 'unknown', 'run_parts': {}, 'gaps': gaps, 'origin': 'not_assessed',
        'not_a_verdict': NOT_A_VERDICT, 'unobserved': UNOBSERVED,
    }
    if family not in KNOWN_FAMILIES:
        _gap(gaps, 'family_not_observed' if family is None else 'family_unsupported')
    elif family not in APPLICABLE_FAMILIES:
        result['applicability'] = 'not_applicable'
    if resolvconf_installed is False:
        result['applicability'] = 'not_applicable'
    elif resolvconf_installed is not True:
        _gap(gaps, 'implementation_not_observed', None, 'Whether the resolvconf package is installed is unknown.')
    elif family in APPLICABLE_FAMILIES:
        result['applicability'] = 'applicable'
    update = _run_parts(UPDATE_D, update_d, gaps)
    libc = _run_parts(UPDATE_LIBC_D, update_libc_d, gaps)
    libc_outcome = next((s['outcome'] for s in update['scripts'] if s['name'] == LIBC_SCRIPT), None)
    if update['state'] == 'listed' and libc_outcome in ('runs', 'unresolved'):
        libc['invoked_by'] = f'{UPDATE_D}/{LIBC_SCRIPT}'
        libc['invocation'] = 'conditional' if libc_outcome == 'runs' else 'unresolved'
    elif update['state'] in ('listed', 'absent', 'not_directory'):
        libc['invoked_by'] = None
        libc['invocation'] = 'not_invoked'
    else:
        libc['invoked_by'] = None
        libc['invocation'] = 'unresolved'
    for script in update['scripts']:
        script['reason'] = REASONS[script['outcome']]
    for script in libc['scripts']:
        if script['outcome'] == 'runs':
            if libc['invocation'] == 'not_invoked':
                script['outcome'] = 'not_invoked'
            elif libc['invocation'] == 'conditional':
                script['outcome'] = 'runs_if_libc'
            else:
                script['outcome'] = 'unresolved'
        script['reason'] = REASONS[script['outcome']]
    result['run_parts'] = {UPDATE_D: update, UPDATE_LIBC_D: libc}
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
