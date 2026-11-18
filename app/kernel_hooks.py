"""Pure Debian kernel package hook contract (roadmap F slice, #1072).

Debian-family kernel packages run every eligible script in ``/etc/kernel/*.d`` as
root from their maintainer scripts. Given supplied, read-only directory-entry
metadata, this module says for each hook directory which maintainer-script
actions invoke it, with what arguments and environment, which scripts
``run-parts`` runs and in what order, why other entries are skipped, and where
``--exit-on-error`` stops the run. It never reads a script's contents.

The semantics were checked against shipped artifacts, not recalled:

* Ubuntu 24.04 ``linux-image-6.8.0-71-generic``, ``linux-modules-6.8.0-71-generic``
  and ``linux-headers-6.8.0-71-generic`` maintainer scripts (``set -e``). Each
  hook is guarded by ``[ -d DIR ]``, which follows symlinks, and runs
  ``DEB_MAINT_PARAMS="$*" run-parts --report --exit-on-error --arg=VERSION
  [--arg=IMAGE_PATH] DIR``:

  - ``preinst.d``: every ``linux-image`` preinst call except ``abort-upgrade``.
  - ``postinst.d``: ``linux-image`` and ``linux-modules`` postinst on
    ``configure`` queue the command in ``/usr/lib/linux/triggers/VERSION`` and
    raise the ``linux-update-VERSION`` dpkg trigger, so it runs once when
    ``linux-image`` processes the trigger.
  - ``prerm.d``: ``linux-image`` prerm on ``remove`` only.
  - ``postrm.d``: every ``linux-image`` postrm call, after any queued
    postinst trigger is discarded.
  - ``header_postinst.d``: ``linux-headers`` postinst on ``configure``, with the
    version as the only argument.

* debianutils 5.17 ``run-parts`` without ``--lsbsysinit``: only names matching
  ``^[A-Za-z0-9_-]+$`` are considered, so dots, ``~`` backups and hidden names
  never run. A considered entry is ``stat()``-ed (symlinks followed). A regular
  file runs when root may execute it (any execute bit, mount without
  ``noexec``). Directories and non-executable files are skipped silently. A
  failed ``stat()`` (a dangling symlink) stops the run under
  ``--exit-on-error``, so later scripts never run. Any other file type is
  reported, later scripts still run, and run-parts then exits non-zero. A
  script that exits non-zero also stops the run, which cannot be known from
  metadata, so every script after the first runs only if all earlier ones
  succeed. Order is ``strcoll``; it is reported as byte (C locale) order.

A non-zero run-parts status fails the maintainer script and so the dpkg
operation. RPM-family kernels use ``kernel-install`` plugins instead, so that
family is ``not_applicable``. The module performs no I/O, never runs a command,
makes no safety verdict and never authorizes a response action. Missing or
malformed metadata, an unobserved family or directory, a truncated listing and
over-limit input are blocking gaps and are never reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'maintainer_scripts': 'Ubuntu 24.04 linux-image/linux-modules/linux-headers 6.8.0-71',
             'run_parts': 'debianutils 5.17'}
RUNS_AS = 'root'
ENVIRONMENT = {'DEB_MAINT_PARAMS': 'The arguments dpkg passed to the maintainer script, for example "configure 6.8.0-70".'}
APPLICABLE_FAMILIES = frozenset({'debian'})
KNOWN_FAMILIES = frozenset({'debian', 'rpm'})
_TWO_ARGS = ('<version>', '<image_path>')
HOOKS: dict[str, dict[str, Any]] = {
    'preinst': {
        'directory': '/etc/kernel/preinst.d', 'packages': ('linux-image-*',), 'maintainer_script': 'preinst',
        'actions': ('install', 'upgrade'), 'args': _TWO_ARGS, 'deferred': False,
        'when': 'Before a kernel image is unpacked (install or upgrade); not on abort-upgrade.'},
    'postinst': {
        'directory': '/etc/kernel/postinst.d', 'packages': ('linux-image-*', 'linux-modules-*'),
        'maintainer_script': 'postinst', 'actions': ('configure',), 'args': _TWO_ARGS,
        'deferred': True,
        'when': 'After a kernel image or modules package is configured. The command is queued in '
                '/usr/lib/linux/triggers/<version> and runs once when the linux-update-<version> dpkg '
                'trigger is processed.'},
    'prerm': {
        'directory': '/etc/kernel/prerm.d', 'packages': ('linux-image-*',), 'maintainer_script': 'prerm',
        'actions': ('remove',), 'args': _TWO_ARGS, 'deferred': False,
        'when': 'Before a kernel image is removed; not on upgrade.'},
    'postrm': {
        'directory': '/etc/kernel/postrm.d', 'packages': ('linux-image-*',), 'maintainer_script': 'postrm',
        'actions': ('remove', 'purge', 'upgrade', 'failed-upgrade', 'abort-install', 'abort-upgrade', 'disappear'),
        'args': _TWO_ARGS, 'deferred': False,
        'when': 'On every postrm call of a kernel image, including upgrade and purge. A queued postinst trigger '
                'for the same version is discarded first.'},
    'header_postinst': {
        'directory': '/etc/kernel/header_postinst.d', 'packages': ('linux-headers-*',),
        'maintainer_script': 'postinst', 'actions': ('configure',), 'args': ('<version>',), 'deferred': False,
        'when': 'After a kernel headers package is configured.'},
}
MAX_ENTRIES = 1024
MAX_NAME_BYTES = 255
MAX_GAPS = 64
FILE_TYPES = ('file', 'directory', 'symlink', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'duplicate_name', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'family_not_observed',
    'family_unsupported', 'gaps_truncated',
})
UNOBSERVED = (
    'Script contents, interpreters and anything a script runs are not read.',
    ('Which kernel packages are installed, and whether a locally built kernel package (for example from make '
     'bindeb-pkg or a vendor) uses the same hooks, are not assessed.'),
    'A script that exits non-zero stops the run; exit statuses cannot be known from metadata.',
    ('run-parts orders names with strcoll; a maintainer script running under a non-C locale may order names '
     'differently from the byte order reported here.'),
    'Security modules such as AppArmor or SELinux that could stop a script are not assessed.',
    'A locally rebuilt run-parts or modified kernel maintainer script is not detected.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'runs': 'The kernel package runs this script as root through run-parts when the hook fires.',
    'name_rejected': 'run-parts only considers names made of ASCII letters, digits, "_" and "-", so names with a '
                     'dot, "~" or other punctuation never run.',
    'directory': 'Directories are skipped.',
    'not_executable': 'The file has no execute bit, so run-parts skips it.',
    'noexec_mount': 'The file is on a noexec mount, so root cannot execute it and run-parts skips it.',
    'stat_failed': 'run-parts cannot stat this entry (for example a dangling symlink); with --exit-on-error it '
                   'stops here, so no later script runs and the package operation fails.',
    'not_plain_file': 'Not a regular file or directory; run-parts reports an error, keeps going and then exits '
                      'non-zero, which fails the package operation.',
    'not_reached': 'An earlier entry stops run-parts under --exit-on-error, so this script never runs.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_NAME = re.compile(r'[A-Za-z0-9_-]+')
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


def name_considered(name: str) -> bool:
    """Return whether default (non-``--lsbsysinit``) ``run-parts`` considers this entry name."""
    return bool(_NAME.fullmatch(name))


def command(hook: str) -> list[str]:
    """Return the run-parts command line a kernel package uses for ``hook``."""
    spec = HOOKS[hook]
    return ['run-parts', '--report', '--exit-on-error', *(f'--arg={arg}' for arg in spec['args']),
            spec['directory']]


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


def _normalize(item: Any, gaps: list[dict[str, Any]], directory: str) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_name(item.get('name')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', directory, 'An entry observation has no valid name or type.')
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


def _assess(entry: dict[str, Any], dir_noexec: bool | None, path: str, gaps: list[dict[str, Any]]) -> str:
    """Return the reason code for one considered, normalized entry."""
    if entry['type'] == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', path, 'What the symlink resolves to was not supplied.')
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
        entry['mount_unobserved'] = True
    return 'runs'


def _directory(observed: Any, directory: str, entries_supplied: bool,
               gaps: list[dict[str, Any]]) -> tuple[str | None, bool | None]:
    state = observed.get('state') if isinstance(observed, dict) else None
    noexec = observed.get('noexec') if isinstance(observed, dict) else None
    # A listing must say whether it finished: an omitted flag is malformed, never complete.
    complete = observed.get('complete') if isinstance(observed, dict) else None
    if state not in DIRECTORY_STATES or (noexec is not None and not isinstance(noexec, bool)) \
            or (state == 'listed' and not isinstance(complete, bool)) \
            or (complete is not None and not isinstance(complete, bool)):
        _gap(gaps, 'input_malformed', directory, 'The directory observation is malformed.')
        return None, None
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', directory, 'The directory exists but could not be listed.')
    elif state == 'listed' and not complete:
        _gap(gaps, 'listing_incomplete', directory, 'The directory listing did not finish.')
    elif state in ('absent', 'not_directory') and entries_supplied:
        _gap(gaps, 'input_malformed', directory, 'Entries were supplied for a directory reported absent.')
        return None, None
    return state, noexec


def _hook(hook: str, observed: Any, gaps: list[dict[str, Any]]) -> dict[str, Any]:
    spec = HOOKS[hook]
    directory = spec['directory']
    result: dict[str, Any] = {
        'hook': hook, 'directory': directory, 'packages': list(spec['packages']),
        'maintainer_script': spec['maintainer_script'], 'actions': list(spec['actions']),
        'deferred_by_trigger': spec['deferred'], 'when': spec['when'], 'command': command(hook),
        'directory_state': None, 'run_outcome': 'unknown', 'stops_at': None, 'entries': [], 'scripts': [],
    }
    if observed is None:
        _gap(gaps, 'directory_not_observed', directory, 'No listing result was supplied for this hook directory.')
        return result
    entries = observed.get('entries', []) if isinstance(observed, dict) else None
    if not isinstance(entries, (list, tuple)):
        _gap(gaps, 'input_malformed', directory, 'Entry observations must be a list.')
        entries = ()
    state, dir_noexec = _directory(observed.get('directory') if isinstance(observed, dict) else None,
                                   directory, bool(entries), gaps)
    result['directory_state'] = state
    if state in ('absent', 'not_directory'):
        result['run_outcome'] = 'not_invoked'
        return result
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', directory, f'Only the first {MAX_ENTRIES} entries are assessed.')
        entries = entries[:MAX_ENTRIES]

    seen: set[str] = set()
    records = []
    mount_unobserved: list[str] = []
    for item in entries:
        entry = _normalize(item, gaps, directory)
        if entry is None:
            continue
        name = entry['name']
        path = f'{directory}/{name}'
        if name in seen:
            _gap(gaps, 'duplicate_name', path, 'The name was supplied more than once; the first is used.')
            continue
        seen.add(name)
        if not name_considered(name):
            code = 'name_rejected'
        elif not entry['resolved']:
            _gap(gaps, 'metadata_missing', path, 'Required metadata for this entry was not supplied or is malformed.')
            code = 'unresolved'
        else:
            code = _assess(entry, dir_noexec, path, gaps)
        record = {'name': name, 'path': path, 'type': entry['type'], 'reason_code': code}
        if entry.get('link_target') is not None:
            record['link_target'] = entry['link_target']
        if entry.get('mount_unobserved'):
            record['mount_unobserved'] = True
        records.append(record)

    # run-parts walks considered names in order; a failed stat ends the walk under --exit-on-error.
    records.sort(key=lambda rec: _sort_key(rec['name']))
    stopped = False
    uncertain = False
    reports_error = False
    for record in records:
        code = record['reason_code']
        if code == 'name_rejected':
            pass
        elif stopped:
            code = 'not_reached'
        elif code == 'stat_failed':
            stopped = True
            result['stops_at'] = record['path']
        elif code == 'not_plain_file':
            reports_error = True
        elif code == 'runs' and record.pop('mount_unobserved', False):
            mount_unobserved.append(record['name'])
        record.pop('mount_unobserved', None)
        status = {'runs': 'runs', 'unresolved': 'unresolved', 'not_reached': 'not_reached'}.get(code, 'skipped')
        record.update(status=status, reason_code=code, reason=REASONS[code])
        if status == 'runs':
            # An earlier entry with unknown metadata might be a failed stat that ends the walk.
            record['reached'] = 'unknown' if uncertain else 'yes'
        if code == 'unresolved':
            uncertain = True

    runnable = [rec for rec in records if rec['status'] == 'runs']
    if state != 'listed':
        for record in runnable:
            record.pop('reached', None)
            record.update(status='unresolved', reason_code='unresolved', reason=REASONS['unresolved'])
        runnable = []
        mount_unobserved = []
    if mount_unobserved:
        # One gap per directory, so many scripts cannot exhaust the gap budget on their own.
        shown = ', '.join(mount_unobserved[:5])
        more = f' and {len(mount_unobserved) - 5} more' if len(mount_unobserved) > 5 else ''
        _gap(gaps, 'mount_flags_not_observed', directory,
             f'Whether {len(mount_unobserved)} runnable file(s) ({shown}{more}) are on a noexec mount was not '
             'observed; they are reported as running.')
    for index, record in enumerate(runnable):
        record['order'] = index
        script = {'order': index, 'name': record['name'], 'path': record['path'], 'reached': record['reached'],
                  'requires_earlier_success': index > 0}
        if 'link_target' in record:
            script['link_target'] = record['link_target']
        result['scripts'].append(script)
    result['entries'] = records
    if state == 'listed' and stopped:
        # Entries past a failed stat are never run, even when the listing itself did not finish.
        result['run_outcome'] = 'stops_early'
    elif state == 'listed' and observed['directory'].get('complete'):
        result['run_outcome'] = 'fails_after_run' if reports_error else 'runs'
    return result


def evaluate(observations: Any, *, family: Any = None) -> dict[str, Any]:
    """Resolve which ``/etc/kernel/*.d`` hook scripts kernel packages run, from supplied metadata.

    ``observations`` maps a hook id (``preinst``, ``postinst``, ``prerm``, ``postrm``,
    ``header_postinst``) to ``{'directory': {...}, 'entries': [...]}``. ``directory`` is
    ``{'state', 'complete', 'noexec'}`` with state ``listed``, ``absent``, ``not_directory`` or
    ``unreadable`` as ``[ -d DIR ]`` (following symlinks) and a listing see it; ``noexec`` is the
    directory's mount flag, or ``None`` when unobserved. Each entry has ``name`` and ``type``
    (``file``, ``directory``, ``symlink`` or ``other``) as ``lstat`` reports it; a ``file`` carries
    ``mode`` (0–0o7777) and a ``symlink`` carries ``target`` (the followed ``stat``: ``type``,
    ``mode`` for a file and optional ``noexec``), or ``None`` when ``stat`` fails. ``link_target``
    is optional and informational. ``family`` is ``debian`` or ``rpm``.

    Each hook's ``run_outcome`` is ``runs``, ``stops_early`` (a failed stat ends the walk at
    ``stops_at``), ``fails_after_run`` (an unsupported file type makes run-parts exit non-zero
    after the walk), ``not_invoked`` (no directory) or ``unknown``.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'runs_as': RUNS_AS,
        'environment': dict(ENVIRONMENT), 'order': 'byte', 'applicability': 'unknown', 'hooks': [],
        'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    if family is None:
        _gap(gaps, 'family_not_observed', detail='The OS family was not supplied, so kernel hook behavior is unknown.')
    elif family not in KNOWN_FAMILIES:
        _gap(gaps, 'family_unsupported', detail='Only Debian-family and RPM-family kernel packaging is assessed.')
    elif family not in APPLICABLE_FAMILIES:
        result['applicability'] = 'not_applicable'
        result['applicability_detail'] = ('RPM-family kernels run kernel-install plugins from /etc/kernel/install.d '
                                          'and /usr/lib/kernel/install.d, not these hook directories.')
    else:
        result['applicability'] = 'applicable'
        if not isinstance(observations, dict):
            _gap(gaps, 'input_malformed', detail='Hook observations must be a mapping of hook ids.')
            observations = {}
        unknown = sorted(str(key) for key in observations if key not in HOOKS)
        if unknown:
            _gap(gaps, 'input_malformed', detail='Unknown hook ids were supplied: ' + ', '.join(unknown[:5]) + '.')
        result['hooks'] = [_hook(hook, observations.get(hook), gaps) for hook in HOOKS]
    result['complete'] = result['applicability'] != 'unknown' and not any(gap['code'] in BLOCKING for gap in gaps)
    return result
