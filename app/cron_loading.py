"""Pure assessment of whether a cron daemon would load a stored system crontab file.

Uses only receipt metadata already collected read-only by the agent (path, entry
kind, owner uid and permission bits) plus the host's package family. It performs
no I/O and never executes anything. The rules are the distribution defaults:

* Debian/Ubuntu/Raspberry Pi OS cron (``cron(8)``): ``/etc/crontab`` and files in
  ``/etc/cron.d`` must be owned by root and must not be group- or other-writable,
  and ``/etc/cron.d`` file names must consist only of letters, digits, ``_`` and
  ``-`` (the run-parts naming convention, so no dots).
* cronie (RPM family): ``/etc/cron.d`` names starting with ``.``, ending with
  ``~`` or with ``.rpmsave``/``.rpmorig``/``.rpmnew`` are ignored; a system
  crontab must be owned by root ("WRONG FILE OWNER") and satisfy
  ``(mode & 07533) == 0400`` ("BAD FILE MODE").

``eligible`` only means no default rule rejects the file. Daemon options (for
example cronie ``-p``), patched daemons and whether cron runs are not evaluated.
A symlink's target owner/mode is not recorded, so symlinks are ``unknown``.
"""
from __future__ import annotations

import re
from typing import Any

SYSTEM_FILE = '/etc/crontab'
SYSTEM_DIR = '/etc/cron.d'
_DEBIAN_NAME = re.compile(r'[A-Za-z0-9_-]+')
_CRONIE_SUFFIXES = ('~', '.rpmsave', '.rpmorig', '.rpmnew')

REASONS = {
    'unknown_family': 'Package family is not recognised, so no cron loading rules are applied.',
    'symlink_target_not_recorded': 'Symlink target owner and mode are not recorded, so loading cannot be assessed.',
    'not_regular_file': 'Only regular files are assessed.',
    'debian_name': 'Debian cron ignores /etc/cron.d names containing characters other than letters, digits, _ and - (including dots).',
    'cronie_name': 'cronie ignores /etc/cron.d names starting with "." or ending with "~", ".rpmsave", ".rpmorig" or ".rpmnew".',
    'not_root_owned': 'Cron ignores system crontab files that are not owned by root.',
    'group_or_other_writable': 'Debian cron ignores system crontab files that are group- or other-writable.',
    'cronie_mode': 'cronie rejects system crontab files unless the owner can read them and no execute, group/other write, setuid, setgid or sticky bit is set.',
}
LIMITATION = ('Distribution default rules only: daemon options such as cronie -p, patched daemons and '
              'whether the cron daemon runs are not evaluated.')


def family_of(inventory: Any) -> str | None:
    """Map stored host inventory to a cron rule family; unknown is never guessed."""
    manager = inventory.get('package_manager') if isinstance(inventory, dict) else None
    return {'apt': 'debian', 'rpm': 'rpm'}.get(manager)


def applies(path: Any) -> bool:
    return isinstance(path, str) and (path == SYSTEM_FILE or (
        path.startswith(SYSTEM_DIR + '/') and '/' not in path[len(SYSTEM_DIR) + 1:] and len(path) > len(SYSTEM_DIR) + 1))


def _result(state: str, reasons: list[str], family: str | None) -> dict[str, Any]:
    return {'state': state, 'family': family, 'reasons': [{'code': code, 'detail': REASONS[code]} for code in reasons]}


def assess(entry: Any, family: Any) -> dict[str, Any] | None:
    """Return the loading assessment for one stored entry, or None when no system
    crontab rule applies to its path."""
    if not isinstance(entry, dict) or not applies(entry.get('path')):
        return None
    if family not in ('debian', 'rpm'):
        return _result('unknown', ['unknown_family'], None)
    kind = entry.get('kind')
    if kind == 'symlink':
        return _result('unknown', ['symlink_target_not_recorded'], family)
    uid, mode = entry.get('uid'), entry.get('mode')
    if kind != 'regular' or type(uid) is not int or type(mode) is not int or uid < 0 or not 0 <= mode <= 0o7777:
        return _result('unknown', ['not_regular_file'], family)
    name = entry['path'].rsplit('/', 1)[1] if entry['path'] != SYSTEM_FILE else None
    reasons = []
    if family == 'debian':
        if name is not None and not _DEBIAN_NAME.fullmatch(name):
            reasons.append('debian_name')
        if uid != 0:
            reasons.append('not_root_owned')
        if mode & 0o022:
            reasons.append('group_or_other_writable')
    else:
        if name is not None and (name.startswith('.') or name.endswith(_CRONIE_SUFFIXES)):
            reasons.append('cronie_name')
        if uid != 0:
            reasons.append('not_root_owned')
        if mode & 0o7533 != 0o400:
            reasons.append('cronie_mode')
    return _result('skipped' if reasons else 'eligible', reasons, family)
