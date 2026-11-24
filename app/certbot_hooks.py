"""Pure certbot renewal-hooks contract (roadmap F slice, #1229).

Takes entry metadata for ``/etc/letsencrypt/renewal-hooks/{pre,deploy,post}``
and says which scripts certbot runs, as root, through ``/bin/sh``, in which
order, on which renewal events and with which environment, and where coverage
is missing. It never runs anything and never reads a script's contents.

Semantics come from certbot 2.9.0 source (the version Ubuntu 24.04 ships):
``certbot/_internal/hooks.py``, ``_internal/main.py``, ``_internal/renewal.py``,
``compat/filesystem.py`` and ``compat/misc.py``, not from recollection:

* Distribution packages run ``certbot -q renew`` as root from
  ``certbot.timer`` or ``/etc/cron.d/certbot`` (the snap uses its own timer),
  normally twice a day. Every certbot start first creates the three hook
  directories (mode 0755) when they are missing.
* ``list_hooks`` is ``os.listdir`` of the directory, keeping paths where
  ``os.path.isfile`` (symlinks followed) and ``os.access(path, X_OK)`` hold
  and the path does not end with ``~``, returned by Python ``sorted()`` of the
  full paths. Unlike run-parts there is no name filter: dotfiles,
  ``.dpkg-dist`` copies and ``.sh`` names all run. Directories, special files
  and dangling symlinks are skipped silently. ``access`` refuses execution on a
  noexec mount.
* Each listed path is passed unchanged to ``subprocess.run(path, shell=True)``,
  so ``/bin/sh -c`` parses it as command text. A name containing characters the
  shell treats specially does not simply run that file.
* ``pre``: only for the ``renew`` verb, run once (deduplicated) just before the
  first lineage that is due for renewal, dry runs included; nothing runs when no
  certificate is due. ``post``: only for ``renew``, run once after all renewals
  when at least one renewal was attempted (successful or not), dry runs
  included, with ``RENEWED_DOMAINS`` and ``FAILED_DOMAINS``. ``deploy``: after
  every successful renewal of an existing lineage, for any verb, with
  ``RENEWED_DOMAINS`` and ``RENEWED_LINEAGE``; skipped on ``--dry-run`` unless
  ``--run-deploy-hooks``; not run for a brand-new certificate.
* ``--no-directory-hooks`` disables all three directories. A failing hook only
  logs a warning: later hooks and the renewal continue. When a hook path is not
  a directory, listing it raises and the renewal in progress is reported failed.

It performs no I/O and never authorizes a response action. Unobserved family,
installation state, listings or metadata, malformed input, over-limit input and
shell-reinterpreted names are blocking gaps.
"""
from __future__ import annotations

import re
from typing import Any

from app.ifupdown_hooks import _stat_ok

CONTRACT_VERSION = 1
REFERENCE = {
    'certbot': 'certbot 2.9.0 certbot/_internal/hooks.py, main.py, renewal.py, compat/filesystem.py, compat/misc.py',
}
RUNS_AS = 'root'
HOOKS_ROOT = '/etc/letsencrypt/renewal-hooks'
PHASES = ('pre', 'deploy', 'post')
HOOK_DIRS = {phase: f'{HOOKS_ROOT}/{phase}' for phase in PHASES}
SHELL = ('/bin/sh', '-c', 'HOOK_PATH')
SCHEDULE = ('certbot.timer or /etc/cron.d/certbot running "certbot -q renew" as root (normally twice a day)',
            'snap.certbot.renew.timer for the certbot snap',
            'manual certbot renew, certonly or run by an administrator')
EVENTS = {
    'pre': ('certbot renew, once, just before the first certificate that is due for renewal (dry runs included)',),
    'deploy': ('after each successful renewal of an existing certificate, for any certbot verb',
               'not on --dry-run unless --run-deploy-hooks is given',
               'not when a brand-new certificate is issued'),
    'post': ('certbot renew, once, after all renewals when at least one renewal was attempted, '
             'successful or not (dry runs included)',),
}
ENVIRONMENT = {
    'pre': (),
    'deploy': ('RENEWED_DOMAINS (space-separated names in the certificate)',
               'RENEWED_LINEAGE (/etc/letsencrypt/live/NAME)'),
    'post': ('RENEWED_DOMAINS (space-separated, at most 16000 characters)',
             'FAILED_DOMAINS (space-separated)'),
}
APPLICABLE_FAMILIES = frozenset({'debian', 'rpm'})
DIRECTORY_STATES = ('listed', 'absent', 'unreadable', 'not_directory')
MAX_ENTRIES = 1024
MAX_GAPS = 64
BLOCKING = frozenset({
    'input_malformed', 'family_not_observed', 'family_unsupported', 'implementation_not_observed',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'too_many_entries',
    'metadata_missing', 'symlink_target_unobserved', 'shell_reinterpreted', 'gaps_truncated',
})
UNOBSERVED = (
    'Script contents are not read, so what a hook does is not assessed.',
    'Hook commands in /etc/letsencrypt/renewal/*.conf (pre_hook, post_hook, renew_hook) and cli.ini are not modeled.',
    'A --config-dir override, --no-directory-hooks, or a locally modified certbot is not detected.',
    'Whether any certificate is due, and so whether pre and post hooks fire on a given run, is not observed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'runs': 'certbot runs this file as root through /bin/sh -c with its full path as the command text.',
    'runs_as_shell_text': 'The name contains characters /bin/sh treats specially, so the shell parses the path as '
                          'command text and this file may not be what runs.',
    'backup_name': 'certbot skips paths ending with "~".',
    'directory': 'Directories are skipped.',
    'not_executable': 'The file has no execute bit, so certbot does not list it.',
    'noexec_mount': 'The file is on a noexec mount, so os.access refuses execution and certbot does not list it.',
    'stat_failed': 'The entry cannot be followed (for example a dangling symlink), so certbot skips it.',
    'not_plain_file': 'Not a regular file, so certbot skips it.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
# Characters /bin/sh (dash, or bash as sh) gives meaning to inside an unquoted word,
# including brace expansion in bash. Anything else is passed through literally.
_SHELL_SPECIAL = re.compile(r'[\s|&;<>()$`\\"\'*?\[{}\x00-\x1f\x7f]')


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
    if entry['name'].endswith('~'):
        return 'backup_name'
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
    if _SHELL_SPECIAL.search(entry['name']):
        _gap(gaps, 'shell_reinterpreted', path, 'certbot passes this path to /bin/sh -c as command text.')
        return 'runs_as_shell_text'
    return 'runs'


def assess(directories: Any = None, *, family: Any = None, certbot_installed: Any = None) -> dict[str, Any]:
    """Resolve which certbot renewal-hook scripts run as root from captured directory metadata.

    ``directories`` maps ``pre``, ``deploy`` and ``post`` to ``{'state': 'listed', 'truncated': bool, 'entries':
    [{'name', 'type': 'file'|'directory'|'other'|'symlink', 'mode', 'noexec', 'target'}]}`` or a ``state`` of
    ``absent``, ``unreadable`` or ``not_directory``. A symlink entry's ``target`` is the followed metadata, or
    ``None`` when it cannot be followed. A missing phase key is an unobserved directory.
    """
    gaps: list[dict[str, Any]] = []
    phases: dict[str, Any] = {}
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'runs_as': RUNS_AS,
        'shell': SHELL, 'schedule': SCHEDULE, 'stops_on_failure': False, 'applicability': 'unknown',
        'phases': phases, 'gaps': gaps, 'origin': 'not_assessed', 'not_a_verdict': NOT_A_VERDICT,
        'unobserved': UNOBSERVED,
    }
    if family is None:
        _gap(gaps, 'family_not_observed')
    elif family not in APPLICABLE_FAMILIES:
        _gap(gaps, 'family_unsupported')
    if certbot_installed is False:
        result['applicability'] = 'not_applicable'
    elif certbot_installed is not True:
        _gap(gaps, 'implementation_not_observed', None, 'Whether certbot is installed is unknown.')
    elif family in APPLICABLE_FAMILIES:
        result['applicability'] = 'applicable'
    if directories is not None and not isinstance(directories, dict):
        _gap(gaps, 'input_malformed', HOOKS_ROOT, 'Malformed hook directory map.')
        directories = {}
    for phase in PHASES:
        phases[phase] = _listing(phase, (directories or {}).get(phase), gaps)
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result


def _listing(phase: str, listing: Any, gaps: list[dict[str, Any]]) -> dict[str, Any]:
    directory = HOOK_DIRS[phase]
    out: dict[str, Any] = {'directory': directory, 'state': 'not_observed', 'events': EVENTS[phase],
                           'environment': ENVIRONMENT[phase], 'scripts': [], 'run_order': []}
    if listing is None:
        _gap(gaps, 'directory_not_observed', directory)
        return out
    if not isinstance(listing, dict) or listing.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', directory, 'Malformed hook directory metadata.')
        return out
    out['state'] = listing['state']
    if listing['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', directory)
    if listing['state'] == 'not_directory':
        _gap(gaps, 'directory_breaks_renewal', directory,
             'certbot raises NotADirectoryError listing this path, so the renewal in progress is reported failed.')
    if listing['state'] != 'listed':
        return out
    if listing.get('truncated'):
        _gap(gaps, 'listing_incomplete', directory)
    entries = listing.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries' if isinstance(entries, list) else 'input_malformed', directory)
        return out
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
        outcome = _outcome(entry, path, gaps)
        scripts.append({'name': name, 'path': path, 'outcome': outcome, 'reason': REASONS[outcome]})
    # certbot sorts full paths with Python's sorted(); the shared directory prefix makes that a sort by name.
    scripts.sort(key=lambda s: s['path'])
    out['scripts'] = scripts
    out['run_order'] = [s['path'] for s in scripts if s['outcome'] in ('runs', 'runs_as_shell_text')]
    return out
