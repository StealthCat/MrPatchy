"""Pure update-motd.d login script contract (roadmap F slice, #1047).

Takes captured, read-only metadata for the entries of ``/etc/update-motd.d`` and
for the ``pam_motd`` lines of PAM session stacks, and says which scripts the
Debian/Ubuntu ``pam_motd`` runs as root at each login, in what order, why the
others are skipped, and whether any PAM service runs the update at all. It
never reads a script's contents.

Semantics come from the Debian ``pam_motd`` update patch and from debianutils
``run-parts --lsbsysinit``. They were checked against the binaries shipped in
Ubuntu 24.04 (libpam-modules 1.5.3, debianutils 5.17), not recalled:

* Unless a ``pam_motd`` line has the ``noupdate`` argument, opening a session
  runs ``/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new`` as root.
  The directory is fixed in the module. Upstream Linux-PAM ``pam_motd`` (RPM
  families) only displays files and runs no scripts.
* ``--lsbsysinit`` considers a name only when it matches
  ``^_?([a-z0-9_.]+-)+[a-z0-9]+$`` or ``^[a-z0-9][a-z0-9_-]*$`` and does not
  match ``^[a-z0-9-].*\\.dpkg-(old|dist|new|tmp)$``. Upper-case letters, a
  leading dot and most other punctuation exclude a name. The tests pin this
  rule against ``run-parts --list --lsbsysinit`` output for a fuzz corpus.
* A considered entry is ``stat()``-ed, so symlinks are followed. A regular file
  runs when root may execute it, which needs any execute bit and a mount
  without ``noexec``. A directory or non-executable regular file is skipped
  silently. A failed ``stat()`` (such as a dangling symlink) and any other file
  type are reported by run-parts on stderr and skipped; later scripts still run.
* ``env -i`` clears the locale, so scripts run in byte order of their names.

It performs no I/O, never runs a command and never authorizes a response
action. Missing or malformed metadata, an unobserved directory, family or PAM
configuration, a truncated listing and over-limit input are explicit blocking
gaps and are never reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'pam_motd': 'Debian/Ubuntu libpam-modules 1.5.3 update patch', 'run_parts': 'debianutils 5.17'}
MOTD_DIR = '/etc/update-motd.d'
COMMAND = ('/usr/bin/env', '-i', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           'run-parts', '--lsbsysinit', MOTD_DIR)
OUTPUT = '/run/motd.dynamic'
RUNS_AS = 'root'
APPLICABLE_FAMILIES = frozenset({'debian'})
KNOWN_FAMILIES = frozenset({'debian', 'rpm'})
MAX_ENTRIES = 1024
MAX_NAME_BYTES = 255
MAX_INVOCATIONS = 256
MAX_ARGS = 32
MAX_ARG = 1024
MAX_GAPS = 64
FILE_TYPES = ('file', 'directory', 'symlink', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
REACHED = ('yes', 'no', 'unknown')
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'too_many_invocations', 'duplicate_name', 'metadata_missing',
    'symlink_target_unobserved', 'directory_not_observed', 'directory_unreadable', 'listing_incomplete',
    'family_not_observed', 'family_unsupported', 'pam_not_observed', 'gaps_truncated',
})
UNOBSERVED = (
    'Script contents, interpreters and anything a script runs are not read.',
    'Which PAM services open sessions (for example sshd with UsePAM no) and whether a pam_motd line is reached '
    'are taken from the caller, not resolved here.',
    'Security modules such as AppArmor or SELinux that could stop a script are not assessed.',
    'A locally rebuilt pam_motd or run-parts with different behavior is not detected.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'runs': 'pam_motd runs this script as root through run-parts at each login that updates the MOTD.',
    'name_rejected': 'run-parts --lsbsysinit does not consider this name (upper case, a dot without the LSB '
                     'hierarchical form, other punctuation, or a .dpkg-old/-dist/-new/-tmp suffix).',
    'directory': 'Directories are skipped.',
    'not_executable': 'The file has no execute bit, so run-parts skips it.',
    'noexec_mount': 'The file is on a noexec mount, so root cannot execute it and run-parts skips it.',
    'stat_failed': 'run-parts cannot stat this entry (for example a dangling symlink); it reports an error and '
                   'skips it.',
    'not_plain_file': 'Not a regular file or directory; run-parts reports an error and skips it.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_HIERARCHICAL = re.compile(r'_?([a-z0-9_.]+-)+[a-z0-9]+')
_TRADITIONAL = re.compile(r'[a-z0-9][a-z0-9_-]*')
_EXCLUDED = re.compile(r'[a-z0-9-].*\.dpkg-(old|dist|new|tmp)')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


def _gap(gaps: list[dict[str, Any]], code: str, name: str | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code}
    if name is not None:
        gap['path'] = f'{MOTD_DIR}/{name}'
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def name_considered(name: str) -> bool:
    """Return whether ``run-parts --lsbsysinit`` considers this directory entry name."""
    if _EXCLUDED.fullmatch(name):
        return False
    return bool(_HIERARCHICAL.fullmatch(name) or _TRADITIONAL.fullmatch(name))


def _sort_key(name: str) -> bytes:
    return name.encode('utf-8', 'surrogateescape')


def _valid_name(name: Any) -> bool:
    if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\x00' in name:
        return False
    try:
        return len(_sort_key(name)) <= MAX_NAME_BYTES
    except UnicodeEncodeError:
        return False


def _mode(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0o7777


def _stat(meta: Any) -> dict[str, Any] | None:
    """Validate one followed-stat mapping (``type`` and, for a file, ``mode``)."""
    if not isinstance(meta, dict) or meta.get('type') not in ('file', 'directory', 'other'):
        return None
    if meta['type'] == 'file' and not _mode(meta.get('mode')):
        return None
    noexec = meta.get('noexec')
    if noexec is not None and not isinstance(noexec, bool):
        return None
    return {'type': meta['type'], 'mode': meta.get('mode'), 'noexec': noexec}


def _assess(entry: dict[str, Any], dir_noexec: bool | None, gaps: list[dict[str, Any]]) -> str:
    """Return the reason code for one considered, normalized entry."""
    if entry['type'] == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', entry['name'], 'What the symlink resolves to was not supplied.')
            return 'unresolved'
        if entry['target'] is None:
            return 'stat_failed'
        stat = entry['target']
        noexec = stat['noexec']
    else:
        stat = entry
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
        _gap(gaps, 'mount_flags_not_observed', entry['name'],
             'Whether the file is on a noexec mount was not observed; it is reported as running.')
    return 'runs'


def _normalize(item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_name(item.get('name')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', detail='An entry observation has no valid name or type.')
        return None
    entry: dict[str, Any] = {'name': item['name'], 'type': item['type'], 'resolved': True}
    if item['type'] == 'symlink':
        link = item.get('link_target')
        if isinstance(link, str) and link and len(link) <= 4096 and not _CONTROL.search(link):
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
        return entry
    if item['type'] == 'file':
        if not _mode(item.get('mode')):
            entry['resolved'] = False
            return entry
        entry['mode'] = item['mode']
    return entry


def _directory(directory: Any, entries_supplied: bool, gaps: list[dict[str, Any]]) -> tuple[str | None, bool | None]:
    if directory is None:
        _gap(gaps, 'directory_not_observed', detail=f'No listing result was supplied for {MOTD_DIR}.')
        return None, None
    state = directory.get('state') if isinstance(directory, dict) else None
    noexec = directory.get('noexec') if isinstance(directory, dict) else None
    complete = directory.get('complete', True) if isinstance(directory, dict) else None
    if state not in DIRECTORY_STATES or (noexec is not None and not isinstance(noexec, bool)) \
            or not isinstance(complete, bool):
        _gap(gaps, 'input_malformed', detail='The directory observation is malformed.')
        return None, None
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', detail=f'{MOTD_DIR} exists but could not be listed.')
    elif state == 'listed' and not complete:
        _gap(gaps, 'listing_incomplete', detail=f'The listing of {MOTD_DIR} did not finish.')
    elif state in ('absent', 'not_directory') and entries_supplied:
        _gap(gaps, 'input_malformed', detail='Entries were supplied for a directory reported absent.')
    return state, noexec


def _activation(family: Any, invocations: Any, gaps: list[dict[str, Any]]) -> dict[str, Any]:
    if family is None:
        _gap(gaps, 'family_not_observed', detail='The OS family was not supplied, so pam_motd behavior is unknown.')
        return {'state': 'unknown', 'services': []}
    if family not in KNOWN_FAMILIES:
        _gap(gaps, 'family_unsupported', detail='Only Debian-family and RPM-family pam_motd behavior is assessed.')
        return {'state': 'unknown', 'services': []}
    if family not in APPLICABLE_FAMILIES:
        return {'state': 'not_applicable', 'services': [],
                'detail': 'Upstream pam_motd displays message files and runs no update-motd.d scripts.'}
    if invocations is None:
        _gap(gaps, 'pam_not_observed', detail='No pam_motd session lines were supplied.')
        return {'state': 'unknown', 'services': []}
    if not isinstance(invocations, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='pam_motd invocations must be a list.')
        return {'state': 'unknown', 'services': []}
    if len(invocations) > MAX_INVOCATIONS:
        _gap(gaps, 'too_many_invocations', detail=f'Only the first {MAX_INVOCATIONS} invocations are assessed.')
        invocations = invocations[:MAX_INVOCATIONS]
    services = []
    for item in invocations:
        service = item.get('service') if isinstance(item, dict) else None
        args = item.get('args', []) if isinstance(item, dict) else None
        reached = item.get('reached') if isinstance(item, dict) else None
        if not (isinstance(service, str) and 0 < len(service) <= 255 and not _CONTROL.search(service)
                and '/' not in service and isinstance(args, (list, tuple)) and len(args) <= MAX_ARGS
                and all(isinstance(arg, str) and 0 < len(arg) <= MAX_ARG for arg in args) and reached in REACHED):
            _gap(gaps, 'input_malformed', detail='A pam_motd invocation is malformed.')
            continue
        updates = 'noupdate' not in args
        services.append({'service': service, 'args': list(args), 'reached': reached, 'updates': updates})
        if updates and reached == 'unknown':
            _gap(gaps, 'pam_reachability_unknown', detail=f'Whether the {service} pam_motd line is reached is '
                                                          'unknown, so the update may or may not run.')
    if any(s['updates'] and s['reached'] == 'yes' for s in services):
        state = 'active'
    elif any(s['updates'] and s['reached'] == 'unknown' for s in services):
        state = 'possible'
    else:
        state = 'inactive'
    if any(gap['code'] in ('input_malformed', 'too_many_invocations') for gap in gaps) and state == 'inactive':
        state = 'unknown'
    return {'state': state, 'services': services}


def evaluate(entries: Any, *, family: Any = None, directory: Any = None, pam_motd: Any = None) -> dict[str, Any]:
    """Resolve which ``/etc/update-motd.d`` scripts pam_motd runs from supplied metadata.

    ``entries`` is a list of mappings with ``name`` (one directory entry name) and ``type``
    (``file``, ``directory``, ``symlink`` or ``other`` for FIFOs, sockets and devices), as
    ``lstat`` reports it. A ``file`` carries ``mode`` (permission bits, 0–0o7777). A ``symlink``
    carries ``target``: what ``stat`` reports after following it (``type``, ``mode`` for a file,
    and optionally ``noexec`` for the mount holding the target), or ``None`` when ``stat`` fails.
    ``link_target`` (the raw link text) is optional and informational. ``directory`` is
    ``{'state', 'complete', 'noexec'}`` with state ``listed``, ``absent``, ``not_directory`` or
    ``unreadable``; ``noexec`` is the directory's mount flag, or ``None`` when unobserved.
    ``family`` is ``debian`` or ``rpm``. ``pam_motd`` lists ``{'service', 'args', 'reached'}``
    for every ``pam_motd`` session line, with ``reached`` ``yes``, ``no`` or ``unknown`` as
    resolved from the PAM stack by the caller.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'directory': MOTD_DIR,
        'command': list(COMMAND), 'runs_as': RUNS_AS, 'output': OUTPUT, 'order': 'byte',
        'activation': {}, 'entries': [], 'scripts': [], 'gaps': gaps, 'unobserved': list(UNOBSERVED),
        'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    result['activation'] = _activation(family, pam_motd, gaps)
    if not isinstance(entries, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='Entry observations must be a list.')
        entries = ()
    state, dir_noexec = _directory(directory, bool(entries), gaps)
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', detail=f'Only the first {MAX_ENTRIES} entries are assessed.')
        entries = entries[:MAX_ENTRIES]

    seen: set[str] = set()
    records = []
    runnable = []
    for item in entries:
        entry = _normalize(item, gaps)
        if entry is None:
            continue
        name = entry['name']
        if name in seen:
            _gap(gaps, 'duplicate_name', name, 'The name was supplied more than once; the first is used.')
            continue
        seen.add(name)
        if not name_considered(name):
            code = 'name_rejected'
        elif not entry['resolved']:
            _gap(gaps, 'metadata_missing', name, 'Required metadata for this entry was not supplied or is malformed.')
            code = 'unresolved'
        else:
            code = _assess(entry, dir_noexec, gaps)
        status = 'runs' if code == 'runs' else 'unresolved' if code == 'unresolved' else 'skipped'
        record = {'name': name, 'path': f'{MOTD_DIR}/{name}', 'type': entry['type'], 'status': status,
                  'reason_code': code, 'reason': REASONS[code]}
        if entry.get('link_target') is not None:
            record['link_target'] = entry['link_target']
        records.append(record)
        if status == 'runs':
            runnable.append(record)
    if state != 'listed':
        for record in runnable:
            record.update(status='unresolved', reason_code='unresolved', reason=REASONS['unresolved'])
        runnable = []
    for index, record in enumerate(sorted(runnable, key=lambda rec: _sort_key(rec['name']))):
        record['order'] = index
        script = {'order': index, 'name': record['name'], 'path': record['path']}
        if 'link_target' in record:
            script['link_target'] = record['link_target']
        result['scripts'].append(script)
    result['entries'] = sorted(records, key=lambda rec: _sort_key(rec['name']))
    result['directory_state'] = state
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
