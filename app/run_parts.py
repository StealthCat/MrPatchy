"""Pure assessment of whether run-parts would execute a stored cron directory entry.

Covers direct children of ``/etc/cron.hourly``, ``/etc/cron.daily``,
``/etc/cron.weekly`` and ``/etc/cron.monthly`` using only receipt metadata the
agent already collects read-only (path, entry kind, owner uid and permission
bits) plus the host's package family. It performs no I/O and never executes
anything. The rules are the distribution defaults:

* Debian/Ubuntu/Raspberry Pi OS (``debianutils`` run-parts, default namespace
  without ``--lsbsysinit``): names must consist only of ASCII letters, digits,
  ``_`` and ``-``, so a name with a dot (``backup.sh``, ``job.dpkg-old``) never
  runs; non-executable entries are skipped.
* RPM family (cronie ``crontabs`` run-parts script): hidden names and names
  ending in ``~``, ``,``, ``.rpmsave``, ``.rpmorig``, ``.rpmnew``, ``.swp``,
  ``.cfsaved`` or ``,v`` are skipped; non-executable entries are skipped. The
  script expands its file list and each ``$i`` unquoted, so a name containing a
  space is word-split and never runs as itself (skipped), and a name containing
  a glob character (``*``, ``?``, ``[``) is re-expanded with an outcome that
  depends on sibling names (unknown).

Both run-parts implementations run as root, where ``access(X_OK)``/``test -x``
succeeds for a regular file when any execute bit is set. Neither descends into
subdirectories. Both follow symlinks, and the inventory does not record a
symlink target's kind or mode, so symlinks are ``unknown``.

``eligible`` only means no default rule skips the entry. Invocation options,
cronie ``jobs.allow``/``jobs.deny``, whether ``/etc/crontab``, ``0hourly`` or
anacron actually invoke the directory, and script contents are not evaluated.
"""
from __future__ import annotations

import re
from typing import Any

DIRECTORIES = ('/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly')
_DEBIAN_NAME = re.compile(r'[A-Za-z0-9_-]+')
_RPM_SUFFIXES = ('~', ',', '.rpmsave', '.rpmorig', '.rpmnew', '.swp', '.cfsaved', ',v')
_RPM_GLOB = frozenset('*?[')
_MAX_PATH = 4096

REASONS = {
    'unknown_family': 'Package family is not recognised, so no run-parts rules are applied.',
    'symlink_target_not_recorded': 'run-parts follows symlinks, but the target kind and mode are not recorded, so execution cannot be assessed.',
    'not_regular_file': 'Only regular files with recorded owner and mode are assessed.',
    'nested_entry': 'run-parts does not descend into subdirectories, so this entry is never run directly.',
    'debian_name': 'Debian run-parts skips names containing characters other than ASCII letters, digits, _ and - (including dots).',
    'rpm_name': 'cronie run-parts skips hidden names and names ending in "~", ",", ".rpmsave", ".rpmorig", ".rpmnew", ".swp", ".cfsaved" or ",v".',
    'rpm_word_split': 'cronie run-parts expands file names unquoted, so a name containing a space is split into separate words and never runs as itself.',
    'rpm_glob_expansion': 'cronie run-parts expands file names unquoted, so a name containing *, ? or [ is re-expanded as a pattern and whether it runs depends on other file names.',
    'not_executable': 'run-parts skips entries that have no execute permission bit.',
}
LIMITATION = ('Distribution default run-parts rules only: invocation options such as --lsbsysinit, cronie '
              'jobs.allow/jobs.deny, whether /etc/crontab, 0hourly or anacron invoke the directory, and script '
              'contents are not evaluated.')


def family_of(inventory: Any) -> str | None:
    """Map stored host inventory to a run-parts rule family; unknown is never guessed."""
    manager = inventory.get('package_manager') if isinstance(inventory, dict) else None
    return {'apt': 'debian', 'rpm': 'rpm'}.get(manager) if type(manager) is str else None


def _location(path: Any) -> tuple[str, str] | None:
    """Return (directory, remainder) for a path under one run-parts directory."""
    if type(path) is not str or len(path) > _MAX_PATH or any(ord(c) < 32 or ord(c) == 127 for c in path):
        return None
    for directory in DIRECTORIES:
        prefix = directory + '/'
        if path.startswith(prefix) and len(path) > len(prefix):
            remainder = path[len(prefix):]
            parts = remainder.split('/')
            if any(part in ('', '.', '..') for part in parts):
                return None
            return directory, remainder
    return None


def applies(path: Any) -> bool:
    return _location(path) is not None


def _result(state: str, reasons: list[str], family: str | None) -> dict[str, Any]:
    return {'state': state, 'family': family,
            'reasons': [{'code': code, 'detail': REASONS[code]} for code in reasons]}


def assess(entry: Any, family: Any) -> dict[str, Any] | None:
    """Return the run-parts assessment for one stored entry, or None when the
    entry is not under a run-parts cron directory."""
    if type(entry) is not dict:
        return None
    location = _location(entry.get('path'))
    if location is None:
        return None
    if type(family) is not str or family not in ('debian', 'rpm'):
        return _result('unknown', ['unknown_family'], None)
    _, remainder = location
    if '/' in remainder:
        return _result('skipped', ['nested_entry'], family)
    kind = entry.get('kind')
    if kind == 'symlink':
        return _result('unknown', ['symlink_target_not_recorded'], family)
    uid, mode = entry.get('uid'), entry.get('mode')
    if kind != 'regular' or type(uid) is not int or type(mode) is not int or uid < 0 or not 0 <= mode <= 0o7777:
        return _result('unknown', ['not_regular_file'], family)
    if family == 'rpm' and _RPM_GLOB.intersection(remainder):
        return _result('unknown', ['rpm_glob_expansion'], family)
    reasons = []
    if family == 'debian':
        if not _DEBIAN_NAME.fullmatch(remainder):
            reasons.append('debian_name')
    elif remainder.startswith('.') or remainder.endswith(_RPM_SUFFIXES):
        reasons.append('rpm_name')
    if family == 'rpm' and ' ' in remainder:
        reasons.append('rpm_word_split')
    if not mode & 0o111:
        reasons.append('not_executable')
    return _result('skipped' if reasons else 'eligible', reasons, family)
