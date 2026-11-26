"""Pure ca-certificates hook contract (roadmap F slice, #1203).

Takes entry metadata for ``/etc/ca-certificates/update.d`` and says which
scripts Debian's ``update-ca-certificates`` runs as root, in which order, with
which arguments and standard input, on which triggers, and where coverage is
missing. It never runs anything and never reads a script's contents.

Semantics come from the shipped ``/usr/sbin/update-ca-certificates`` and the
``ca-certificates`` postinst and triggers files (Ubuntu 24.04 package
20260816ubuntu0.24.04.1 and .2), and debianutils ``run-parts``, not from recollection:

* The ``ca-certificates`` postinst runs ``update-ca-certificates`` on
  configure, and on its ``update-ca-certificates`` and
  ``update-ca-certificates-fresh`` dpkg triggers (the latter with
  ``--fresh``). Any package that installs CA certificates activates those
  triggers, so the hooks run as root during ordinary package installs and
  upgrades. An administrator may also run it by hand.
* After rebuilding the bundle it runs, only when ``[ -d "$HOOKSDIR" ]``
  (symlinks followed), ``eval run-parts [--verbose] --test -- "$HOOKSDIR" |
  while read -r hook`` and executes each listed path. Hook argv depends on the
  package build: 20260816ubuntu0.24.04.2 runs ``"$hook" $FRESH_ARG``, where the
  argument is ``--fresh`` when ``--fresh``/``--default`` was given or the
  certificates configuration was empty, while 20260816ubuntu0.24.04.1 runs
  ``"$hook"`` with no argument. Other builds are reported as version-dependent. Standard input carries ``+PATH`` lines
  for added ``/etc/ssl/certs`` PEM links followed by ``-PATH`` lines for
  removed ones. Hooks run on every invocation, including when nothing was
  added or removed (empty input). A failing hook prints
  ``E: ... exited with code N.`` and later hooks still run.
* ``run-parts --test`` without ``--lsbsysinit`` considers names matching
  ``^[A-Za-z0-9_-]+$`` in byte order, follows symlinks and lists regular files
  root may execute. Directories and dangling symlinks are skipped; other types
  are skipped with an error status, which the pipeline ignores.

It performs no I/O and never authorizes a response action. Unobserved family,
installation state, listings or metadata, malformed input and over-limit input
are blocking gaps.
"""
from __future__ import annotations

import re
from typing import Any

from app.ifupdown_hooks import _byte_key, _stat_ok

CONTRACT_VERSION = 1
REFERENCE = {
    'update_ca_certificates': 'ca-certificates 20260816ubuntu0.24.04.1 and 20260816ubuntu0.24.04.2 '
                              '/usr/sbin/update-ca-certificates',
    'run_parts': 'debianutils run-parts',
}
RUNS_AS = 'root'
HOOKS_DIR = '/etc/ca-certificates/update.d'
COMMAND = ('run-parts', '--test', '--', HOOKS_DIR)
HOOK_ARGV = ('HOOK', '[--fresh]')
# Observed hook argv per ca-certificates package version. Any other or unknown
# version gets HOOK_ARGV_VERSION_DEPENDENT and a non-blocking gap.
HOOK_ARGV_BY_VERSION = {
    '20260816ubuntu0.24.04.2': HOOK_ARGV,
    '20260816ubuntu0.24.04.1': ('HOOK',),
}
HOOK_ARGV_VERSION_DEPENDENT = ('HOOK', '[--fresh on some package versions]')
HOOK_STDIN = ('+/etc/ssl/certs/NAME.pem (one line per added certificate)',
              '-/etc/ssl/certs/NAME.pem (one line per removed certificate, after all added lines)')
TRIGGERS = (
    'ca-certificates postinst configure (package install or upgrade)',
    'dpkg trigger update-ca-certificates (a package installed or removed CA certificates)',
    'dpkg trigger update-ca-certificates-fresh (passes --fresh to hooks on versions that forward it)',
    'manual update-ca-certificates [--fresh|--default]',
)
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
    'Script contents are not read, so what a hook does with the certificate list is not assessed.',
    'How often packages activate the update-ca-certificates triggers is not observed.',
    'An update-ca-certificates invocation with --hooksdir, or a locally modified update-ca-certificates or '
    'run-parts, is not detected.',
    'RPM update-ca-trust (p11-kit) is a different mechanism and is not modeled.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'runs': 'update-ca-certificates runs this script as root on every invocation, even when nothing changed.',
    'name_rejected': 'run-parts only considers names made of ASCII letters, digits, "_" and "-".',
    'directory': 'Directories are skipped.',
    'not_executable': 'The file has no execute bit, so run-parts does not list it.',
    'noexec_mount': 'The file is on a noexec mount, so root cannot execute it and run-parts does not list it.',
    'stat_failed': 'The entry cannot be followed (for example a dangling symlink), so run-parts skips it.',
    'not_plain_file': 'Not a regular file or directory; run-parts skips it with an error the pipeline ignores.',
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
    if not _NAME.fullmatch(entry['name']):
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


def _hook_argv(version: Any, gaps: list[dict[str, Any]]) -> tuple[str, ...]:
    argv = HOOK_ARGV_BY_VERSION.get(version) if isinstance(version, str) else None
    if argv is not None:
        return argv
    _gap(gaps, 'hook_argv_version_dependent', None,
         'Whether hooks receive --fresh depends on the ca-certificates version, which was '
         + ('not observed.' if version is None else 'not one with observed hook argv.'))
    return HOOK_ARGV_VERSION_DEPENDENT


def assess(hooks_dir: Any = None, *, family: Any = None, ca_certificates_installed: Any = None,
           ca_certificates_version: Any = None) -> dict[str, Any]:
    """Resolve which ``/etc/ca-certificates/update.d`` hooks run as root from captured directory metadata.

    ``hooks_dir`` is ``{'state': 'listed', 'truncated': bool, 'entries': [{'name', 'type':
    'file'|'directory'|'other'|'symlink', 'mode', 'noexec', 'target'}]}`` or a ``state`` of ``absent``,
    ``unreadable`` or ``not_directory`` (the directory test follows symlinks, so ``listed`` covers a symlinked
    directory). A symlink entry's ``target`` is the followed metadata, or ``None`` when it cannot be followed.
    ``ca_certificates_version`` is the installed package version; it selects the reported hook argv.
    """
    gaps: list[dict[str, Any]] = []
    hooks: dict[str, Any] = {
        'directory': HOOKS_DIR, 'state': 'not_observed', 'command': COMMAND,
        'hook_argv': _hook_argv(ca_certificates_version, gaps),
        'hook_stdin': HOOK_STDIN, 'stops_on_failure': False, 'triggers': TRIGGERS, 'scripts': [], 'run_order': [],
    }
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'runs_as': RUNS_AS,
        'applicability': 'unknown', 'hooks': hooks, 'gaps': gaps, 'origin': 'not_assessed',
        'not_a_verdict': NOT_A_VERDICT, 'unobserved': UNOBSERVED,
    }
    if family not in KNOWN_FAMILIES:
        _gap(gaps, 'family_not_observed' if family is None else 'family_unsupported')
    elif family not in APPLICABLE_FAMILIES:
        result['applicability'] = 'not_applicable'
    if ca_certificates_installed is False:
        result['applicability'] = 'not_applicable'
    elif ca_certificates_installed is not True:
        _gap(gaps, 'implementation_not_observed', None, 'Whether the ca-certificates package is installed is unknown.')
    elif family in APPLICABLE_FAMILIES:
        result['applicability'] = 'applicable'
    _listing(hooks, hooks_dir, gaps)
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result


def _listing(hooks: dict[str, Any], listing: Any, gaps: list[dict[str, Any]]) -> None:
    if listing is None:
        _gap(gaps, 'directory_not_observed', HOOKS_DIR)
        return
    if not isinstance(listing, dict) or listing.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', HOOKS_DIR, 'Malformed hook directory metadata.')
        return
    hooks['state'] = listing['state']
    if listing['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', HOOKS_DIR)
    if listing['state'] != 'listed':
        return
    if listing.get('truncated'):
        _gap(gaps, 'listing_incomplete', HOOKS_DIR)
    entries = listing.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries' if isinstance(entries, list) else 'input_malformed', HOOKS_DIR)
        return
    seen: set[str] = set()
    scripts = []
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or '/' in name or name in seen or name in ('.', '..') \
                or '\0' in name:
            _gap(gaps, 'input_malformed', HOOKS_DIR, 'An entry has a missing, invalid or duplicate name.')
            continue
        seen.add(name)
        path = f'{HOOKS_DIR}/{name}'
        outcome = _outcome(entry, path, gaps)
        scripts.append({'name': name, 'path': path, 'outcome': outcome, 'reason': REASONS[outcome]})
    scripts.sort(key=lambda s: _byte_key(s['name']))
    hooks['scripts'] = scripts
    hooks['run_order'] = [s['path'] for s in scripts if s['outcome'] == 'runs']
