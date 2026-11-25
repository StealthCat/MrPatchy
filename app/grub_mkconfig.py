"""Pure grub-mkconfig contract (roadmap F slice, #1136).

``grub-mkconfig`` (``grub2-mkconfig`` on RPM families) runs as root whenever
the GRUB configuration is regenerated: ``update-grub``, the GRUB package's own
maintainer scripts and, on Debian and Ubuntu, every kernel install or removal
through ``/etc/kernel/postinst.d/zz-update-grub``. Each run sources shell files
from ``/etc/default`` and executes scripts from ``/etc/grub.d``; the scripts'
standard output becomes ``grub.cfg``. This module turns captured directory
listings into the files a run sources and the scripts it executes. It performs
no I/O, never runs GRUB or a shell, never reads a script and never authorizes
a response action.

The rules follow ``util/grub-mkconfig.in`` and ``util/grub-mkconfig_lib.in``
in GRUB 2.06 and 2.12, plus Debian's ``/etc/default/grub.d`` patch:

- ``/etc/default/grub`` is sourced (``.``) when ``test -f`` succeeds, so a
  regular file or a symlink to one. On the Debian family, every
  ``/etc/default/grub.d/*.cfg`` whose ``-e`` test succeeds is then sourced in
  glob order. A dot-name never matches the glob. Sourcing a path that exists
  but is not a regular file is a shell error, which can end the run.
- Every ``/etc/grub.d/*`` path, in glob order, is skipped when its name ends in
  ``~`` or is ``#...#``. Otherwise it runs when ``grub_file_is_not_garbage``
  accepts it and ``test -x`` succeeds. ``grub_file_is_not_garbage`` requires
  ``test -f`` (symlinks are followed) and rejects ``*.dpkg-*``,
  ``*.rpmsave``, ``*.rpmnew``, ``README*`` and ``*.sig``. For root,
  ``test -x`` on a regular file succeeds when any execute bit is set. A
  script runs directly, so its ``#!`` line chooses the interpreter, with the
  exported ``GRUB_*`` settings in its environment.
- The glob skips dot-names and is sorted by the shell. dash (``/bin/sh`` on
  the Debian family) compares bytes. bash (``/bin/sh`` on the RPM family)
  uses the locale's collation. grub-mkconfig exports ``LANG=C`` only for some
  ``GRUB_TERMINAL_OUTPUT`` values, and a caller's ``LC_ALL`` or
  ``LC_COLLATE`` still wins. When collation could differ from byte order, the
  order is reported as uncertain.

The rules were checked against ``grub-common`` 2.12-1ubuntu7.3:
``/usr/sbin/grub-mkconfig`` (SHA-256 ``fb2e1207…``) and
``/usr/share/grub/grub-mkconfig_lib`` (SHA-256 ``c8248074…``).

Fail-closed rules: an unobserved listing, entry type, mode or symlink target,
a malformed or over-limit listing and an unknown family mark the result
incomplete. Affected entries are ``unresolved`` and never reported as not
running. ``origin`` is always ``not_assessed`` and no result is a safety
verdict.
"""
from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('2.06', '2.12')
GRUB_D = '/etc/grub.d'
DEFAULT_FILE = '/etc/default/grub'
DEFAULT_D = '/etc/default/grub.d'
FAMILIES = ('debian', 'rpm')
COMMANDS = {'debian': 'grub-mkconfig', 'rpm': 'grub2-mkconfig'}
SHELLS = {'debian': 'dash', 'rpm': 'bash'}
MAX_ENTRIES = 1024
MAX_GAPS = 64

STATUSES = ('runs', 'sourced', 'skipped_backup', 'skipped_garbage', 'skipped_non_file', 'not_executable',
            'not_matched', 'source_error', 'unresolved')
BLOCKING = frozenset({
    'family_unknown', 'directory_not_observed', 'directory_unreadable', 'directory_mismatch',
    'entries_over_limit', 'malformed_entry', 'duplicate_entry', 'type_not_observed', 'target_not_observed',
    'mode_not_observed', 'default_not_observed', 'gaps_truncated',
})
NOT_OBSERVED = (
    'Whether GRUB is installed and which events regenerate its configuration on this host.',
    'The contents of each script or sourced file, and the interpreter named by each script\'s #! line.',
    ('Mount options, ACLs and security modules: noexec or a policy denial makes test -x fail even when an '
     'execute bit is set.'),
    'Whether a wrapper, distribution patch or GRUB_* setting changes the configuration directories.',
    'Whether a sourced file ends the run early, which would stop every later file and script.',
)
_GARBAGE = (
    ('dpkg_leftover', lambda n: '.dpkg-' in n),
    ('rpm_leftover', lambda n: n.endswith(('.rpmsave', '.rpmnew'))),
    ('readme', lambda n: n.startswith('README')),
    ('signature', lambda n: n.endswith('.sig')),
)
_COLLATION_IGNORED = re.compile(r'[^0-9A-Za-z]')


def _gap(gaps: list[dict[str, Any]], code: str, name: str | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'name': name, 'detail': detail[:240], 'blocking': code in BLOCKING})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'name': None, 'detail': 'Further gaps were not recorded.',
                     'blocking': True})


def skip_reason(name: str) -> str | None:
    """Return why grub-mkconfig skips ``name`` by name alone, or ``None``."""
    if name.endswith('~'):
        return 'editor_backup'
    if len(name) >= 2 and name.startswith('#') and name.endswith('#'):
        return 'editor_autosave'
    for reason, test in _GARBAGE:
        if test(name):
            return reason
    return None


def byte_order(names: Iterable[str]) -> list[str]:
    """Sort names as dash's glob does (``strcmp`` on the bytes)."""
    return sorted(names, key=lambda n: n.encode('utf-8', 'surrogatepass'))


def order_certain(names: list[str]) -> bool:
    """Whether a collating locale is unlikely to reorder byte-ordered ``names``.

    glibc locales ignore punctuation at the first level and fold case, so the
    byte order is kept only when the names, with that applied, still sort the
    same way and stay distinct.
    """
    keys = [_COLLATION_IGNORED.sub('', n).casefold() for n in names]
    return len(set(keys)) == len(keys) and keys == sorted(keys) and all(n.isascii() for n in names)


def _followed(entry: Mapping[str, Any], name: str, gaps: list[dict[str, Any]]) -> tuple[str | None, Any]:
    """Return the followed type and mode, or ``(None, reason)`` when unobserved."""
    kind = entry.get('type')
    if kind == 'symlink':
        target = entry.get('target_type')
        if target not in ('file', 'directory', 'other', 'missing'):
            _gap(gaps, 'target_not_observed', name, 'The symlink target type was not observed.')
            return None, 'target_not_observed'
        return target, entry.get('target_mode')
    if kind in ('file', 'directory', 'other'):
        return kind, entry.get('mode')
    _gap(gaps, 'type_not_observed', name, 'The entry type was not observed.')
    return None, 'type_not_observed'


def _names(listing: Any, entries: Any, path: str, gaps: list[dict[str, Any]]
           ) -> tuple[str, dict[str, Mapping[str, Any]]]:
    """Validate a listing; return its state and the entries by name."""
    if not isinstance(listing, Mapping) or listing.get('state') not in ('listed', 'absent', 'unreadable'):
        _gap(gaps, 'directory_not_observed', None, f'No listing result was supplied for {path}.')
        return 'unobserved', {}
    if posixpath.normpath(str(listing.get('path') or '')) != path:
        _gap(gaps, 'directory_mismatch', None, f'The listing is for {str(listing.get("path"))[:120]}, but '
             f'grub-mkconfig reads {path}.')
        return 'unobserved', {}
    if listing['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', None, f'{path} could not be listed.')
        return 'unobserved', {}
    if listing['state'] == 'absent':
        return 'absent', {}
    entries = list(entries) if entries is not None else []
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'entries_over_limit', None, f'More than {MAX_ENTRIES} entries in {path}.')
        return 'unobserved', {}
    by_name: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        name = entry.get('name') if isinstance(entry, Mapping) else None
        if not isinstance(name, str) or not name or '/' in name or '\x00' in name or len(name) > 255:
            _gap(gaps, 'malformed_entry', None, f'An entry in {path} has no usable name.')
            continue
        if name in ('.', '..'):
            continue
        if name in by_name:
            _gap(gaps, 'duplicate_entry', name, f'{name[:120]} was listed more than once in {path}.')
            continue
        by_name[name] = entry
    return 'listed', by_name


def _script(name: str, entry: Mapping[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    record: dict[str, Any] = {'name': name, 'path': posixpath.join(GRUB_D, name), 'type': entry.get('type'),
                              'status': 'unresolved', 'reason': None, 'origin': 'not_assessed'}
    if name.startswith('.'):
        return {**record, 'status': 'not_matched', 'reason': 'dot_name'}
    reason = skip_reason(name)
    if reason in ('editor_backup', 'editor_autosave'):
        return {**record, 'status': 'skipped_backup', 'reason': reason}
    kind, mode = _followed(entry, name, gaps)
    if kind is None:
        return {**record, 'reason': mode}
    if kind != 'file':
        return {**record, 'status': 'skipped_non_file', 'reason': 'dangling_symlink' if kind == 'missing' else kind}
    if reason:
        return {**record, 'status': 'skipped_garbage', 'reason': reason}
    if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o7777:
        _gap(gaps, 'mode_not_observed', name, 'The permission bits were not observed.')
        return {**record, 'reason': 'mode_not_observed'}
    if not mode & 0o111:
        return {**record, 'status': 'not_executable', 'reason': 'no_execute_bit', 'mode': f'{mode:04o}'}
    return {**record, 'status': 'runs', 'mode': f'{mode:04o}'}


def _source(path: str, entry: Mapping[str, Any] | None, test: str, gaps: list[dict[str, Any]]
            ) -> dict[str, Any]:
    name = posixpath.basename(path)
    record: dict[str, Any] = {'path': path, 'test': test, 'type': None, 'status': 'unresolved', 'reason': None,
                              'origin': 'not_assessed'}
    if entry is None:
        return {**record, 'type': 'missing', 'status': 'not_matched', 'reason': 'absent'}
    record['type'] = entry.get('type')
    if entry.get('type') == 'missing':
        return {**record, 'status': 'not_matched', 'reason': 'absent'}
    kind, reason = _followed(entry, name, gaps)
    if kind is None:
        return {**record, 'reason': reason}
    if kind == 'file':
        return {**record, 'status': 'sourced'}
    if kind == 'missing':
        return {**record, 'status': 'not_matched', 'reason': 'dangling_symlink'}
    if test == '-f':
        return {**record, 'status': 'not_matched', 'reason': kind}
    _gap(gaps, 'source_non_file', name, f'{path[:160]} exists but is a {kind}; sourcing it is a shell error that '
         'can end the run.')
    return {**record, 'status': 'source_error', 'reason': kind}


def evaluate(*, family: Any, grub_d: Any, grub_d_entries: Any = None, default_grub: Any = None,
             default_d: Any = None, default_d_entries: Any = None) -> dict[str, Any]:
    """Resolve which files a grub-mkconfig run sources and which scripts it executes.

    ``family`` is ``'debian'`` or ``'rpm'``. ``grub_d`` and ``default_d`` are
    ``{'path': ..., 'state': 'listed' | 'absent' | 'unreadable'}``. Each entry is ``{'name': '10_linux',
    'type': 'file' | 'symlink' | 'directory' | 'other', 'mode': 0o755}``; a symlink carries ``target_type``
    (``'file'``, ``'directory'``, ``'other'`` or ``'missing'``) and ``target_mode`` instead. ``default_grub``
    is one such entry without a name, or ``{'type': 'missing'}``; ``None`` means it was not observed.
    ``default_d`` is only read on the Debian family.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'format': 'grub_mkconfig', 'source_versions': list(SOURCE_VERSIONS),
        'family': family if family in FAMILIES else None, 'command': COMMANDS.get(family), 'complete': False,
        'execution': {'user': 'root', 'scripts': 'executed directly; the #! line chooses the interpreter',
                      'sourced': 'read into the grub-mkconfig shell with "."',
                      'stdout': 'written into the generated grub.cfg', 'environment': 'exported GRUB_* settings'},
        'sourced': [], 'scripts': [], 'runs': [], 'order': None, 'origin': 'not_assessed', 'gaps': gaps,
        'not_observed': list(NOT_OBSERVED),
    }
    if family not in FAMILIES:
        _gap(gaps, 'family_unknown', None, 'The platform family is not debian or rpm, so the command, the shell '
             'that orders the glob and whether /etc/default/grub.d is read are unknown.')
        return _finish(result, gaps)

    if not isinstance(default_grub, Mapping):
        _gap(gaps, 'default_not_observed', 'grub', f'{DEFAULT_FILE} was not observed.')
        result['sourced'].append({'path': DEFAULT_FILE, 'test': '-f', 'type': None, 'status': 'unresolved',
                                  'reason': 'default_not_observed', 'origin': 'not_assessed'})
    else:
        result['sourced'].append(_source(DEFAULT_FILE, default_grub, '-f', gaps))
    if family == 'debian':
        state, entries = _names(default_d, default_d_entries, DEFAULT_D, gaps)
        if state == 'unobserved':
            result['sourced'].append({'path': posixpath.join(DEFAULT_D, '*.cfg'), 'test': '-e', 'type': None,
                                      'status': 'unresolved', 'reason': 'directory_not_observed',
                                      'origin': 'not_assessed'})
        for name in byte_order(n for n in entries if n.endswith('.cfg') and not n.startswith('.')):
            result['sourced'].append(_source(posixpath.join(DEFAULT_D, name), entries[name], '-e', gaps))

    state, entries = _names(grub_d, grub_d_entries, GRUB_D, gaps)
    if state == 'unobserved':
        result['scripts'].append({'name': '*', 'path': posixpath.join(GRUB_D, '*'), 'type': None,
                                  'status': 'unresolved', 'reason': 'directory_not_observed',
                                  'origin': 'not_assessed'})
        return _finish(result, gaps)
    names = byte_order(entries)
    result['scripts'] = [_script(name, entries[name], gaps) for name in names]
    result['runs'] = [{'name': s['name'], 'path': s['path'], 'mode': s['mode'], 'origin': 'not_assessed'}
                      for s in result['scripts'] if s['status'] == 'runs']
    globbed = [n for n in names if not n.startswith('.')]
    shell = SHELLS[family]
    certain = shell == 'dash' or order_certain(globbed)
    result['order'] = {'shell': shell, 'basis': 'byte' if shell == 'dash' else 'locale_collation',
                       'reported': 'byte', 'certain': certain}
    if not certain:
        _gap(gaps, 'order_locale_dependent', None, f'/bin/sh ({shell}) sorts the glob by locale collation, which '
             'could run these scripts in a different order than reported.')
    return _finish(result, gaps)


def _finish(result: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    result['complete'] = not any(g['blocking'] for g in gaps)
    return result
