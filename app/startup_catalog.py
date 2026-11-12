"""Pure startup mechanism catalog and per-mechanism coverage contract (roadmap F slice, #723).

The catalog documents which boot, schedule, login, event and loader mechanisms
can start code on supported platform families, and where each one lives. The
coverage function maps a bounded collection's scope and reported missing roots
onto that catalog so every mechanism is explicitly ``covered``, ``partial``,
``absent_reported`` or ``not_collected``.

It performs no I/O, never reads, sources or executes anything, and never
authorizes a response action. Fail-closed rules:

- A location that was not in the collected scope is ``not_collected``; it is
  never treated as absent or safe.
- ``absent_reported`` means only that the collector reported those exact paths
  missing at collection time. It is not a safety verdict.
- ``entries_parsed`` is true only for mechanisms whose entry parser is
  implemented on main *and* whose locations were collected. Every other
  mechanism is file metadata only, and says so.
- Per-user (home-relative) locations count as collected only when the collector
  states that every account home was enumerated; otherwise they are partial.
- Administrator additional scope is passed separately, labeled ``additional``
  and never credited to a catalog mechanism, even when it overlaps one.
- Roots the collector failed on, or an incomplete inventory, never yield
  ``covered``; entries are reported parsed only when the collection says the
  parser ran and at least one location was fully collected.
- The catalog is not exhaustive and every result says so.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

CONTRACT_VERSION = 1
FAMILIES = ('debian', 'rpm')
TRIGGERS = ('boot', 'schedule', 'login', 'event', 'loader')
SCOPES = ('system', 'per_user')
PARSE_LEVELS = ('entries', 'metadata')
STATES = ('covered', 'partial', 'absent_reported', 'not_collected')
MAX_ADDITIONAL = 16  # matches target/agent.py validate_custom_paths
MAX_ROOTS = 256
MAX_PATH = 4096
PSEUDO_FILESYSTEMS = ('/proc', '/sys', '/dev', '/run')
# Mirrors the agent's SCAN_EXCLUDED Mr Patchy state directories.
EXCLUDED_STATE = ('/var/lib/mrpatchy-quarantine', '/var/lib/mrpatchy-evidence', '/var/lib/mrpatchy-process-response',
                  '/var/lib/mrpatchy-repair-staging')
HOME_PARENTS = ('/home', '/root')
NOT_EXHAUSTIVE = {'code': 'catalog_not_exhaustive',
                  'detail': 'The catalog lists known mechanisms only; other code-execution paths can exist.'}

_BOTH = FAMILIES
_RUNLEVELS = ('0', '1', '2', '3', '4', '5', '6', 'S')


def _loc(path: str, families: tuple[str, ...] = _BOTH) -> dict[str, Any]:
    return {'path': path, 'families': families}


# id, label, trigger, scope, parse level, locations. Home-relative locations start
# with "~/" and apply to every account home. Keep IDs stable: stored coverage and
# later classification records refer to them.
_MECHANISMS: tuple[dict[str, Any], ...] = (
    {'id': 'cron_system', 'label': 'System crontabs', 'trigger': 'schedule', 'scope': 'system', 'parse': 'entries',
     'locations': (_loc('/etc/crontab'), _loc('/etc/cron.d'))},
    {'id': 'cron_runparts', 'label': 'cron run-parts directories', 'trigger': 'schedule', 'scope': 'system',
     'parse': 'metadata',
     'locations': tuple(_loc(f'/etc/cron.{p}') for p in ('hourly', 'daily', 'weekly', 'monthly'))},
    {'id': 'cron_user', 'label': 'User and root crontab spool', 'trigger': 'schedule', 'scope': 'per_user',
     'parse': 'entries',
     'locations': (_loc('/var/spool/cron/crontabs', ('debian',)), _loc('/var/spool/cron', ('rpm',)))},
    {'id': 'anacron', 'label': 'anacron jobs and timestamps', 'trigger': 'schedule', 'scope': 'system',
     'parse': 'metadata', 'locations': (_loc('/etc/anacrontab'), _loc('/var/spool/anacron'))},
    {'id': 'at_queue', 'label': 'Queued at jobs', 'trigger': 'schedule', 'scope': 'per_user', 'parse': 'metadata',
     'locations': (_loc('/var/spool/cron/atjobs', ('debian',)), _loc('/var/spool/at', ('rpm',)))},
    {'id': 'systemd_system', 'label': 'systemd system units, timers and drop-ins', 'trigger': 'boot',
     'scope': 'system', 'parse': 'metadata',
     'locations': (_loc('/etc/systemd/system'), _loc('/etc/systemd/system.control'), _loc('/run/systemd/system'),
                   _loc('/run/systemd/system.control'), _loc('/usr/local/lib/systemd/system'),
                   _loc('/usr/lib/systemd/system'), _loc('/lib/systemd/system', ('debian',)))},
    {'id': 'systemd_generators', 'label': 'systemd generator executables', 'trigger': 'boot', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/etc/systemd/system-generators'), _loc('/usr/local/lib/systemd/system-generators'),
                   _loc('/usr/lib/systemd/system-generators'), _loc('/lib/systemd/system-generators', ('debian',)),
                   _loc('/etc/systemd/user-generators'), _loc('/usr/local/lib/systemd/user-generators'),
                   _loc('/usr/lib/systemd/user-generators'))},
    {'id': 'systemd_hooks', 'label': 'systemd shutdown and sleep hooks', 'trigger': 'event', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/usr/lib/systemd/system-shutdown'), _loc('/usr/lib/systemd/system-sleep'),
                   _loc('/lib/systemd/system-shutdown', ('debian',)), _loc('/lib/systemd/system-sleep', ('debian',)))},
    {'id': 'systemd_generated', 'label': 'systemd generator output', 'trigger': 'boot', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/run/systemd/generator.early'), _loc('/run/systemd/generator'),
                   _loc('/run/systemd/generator.late'))},
    {'id': 'systemd_transient', 'label': 'systemd transient units', 'trigger': 'event', 'scope': 'system',
     'parse': 'metadata', 'locations': (_loc('/run/systemd/transient'),)},
    {'id': 'systemd_user', 'label': 'systemd user units', 'trigger': 'login', 'scope': 'per_user',
     'parse': 'metadata',
     'locations': (_loc('/etc/systemd/user'), _loc('/run/systemd/user'), _loc('/usr/local/lib/systemd/user'),
                   _loc('/usr/lib/systemd/user'), _loc('/lib/systemd/user', ('debian',)),
                   _loc('~/.config/systemd/user'), _loc('~/.local/share/systemd/user'))},
    {'id': 'sysv', 'label': 'SysV init scripts and runlevel links', 'trigger': 'boot', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/etc/init.d'), *(_loc(f'/etc/rc{r}.d', ('debian',)) for r in _RUNLEVELS),
                   _loc('/etc/rc.d/init.d', ('rpm',)),
                   *(_loc(f'/etc/rc.d/rc{r}.d', ('rpm',)) for r in _RUNLEVELS if r != 'S'))},
    {'id': 'rc_local', 'label': 'rc.local boot script', 'trigger': 'boot', 'scope': 'system', 'parse': 'metadata',
     'locations': (_loc('/etc/rc.local'), _loc('/etc/rc.d/rc.local', ('rpm',)))},
    {'id': 'shell_system', 'label': 'System shell startup files', 'trigger': 'login', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/etc/profile'), _loc('/etc/profile.d'), _loc('/etc/environment'),
                   _loc('/etc/bash.bashrc', ('debian',)), _loc('/etc/bashrc', ('rpm',)))},
    {'id': 'shell_user', 'label': 'User shell startup files', 'trigger': 'login', 'scope': 'per_user',
     'parse': 'metadata',
     'locations': tuple(_loc(f'~/{n}') for n in ('.profile', '.bash_profile', '.bash_login', '.bashrc',
                                                   '.bash_logout'))},
    {'id': 'xdg_autostart', 'label': 'XDG desktop autostart', 'trigger': 'login', 'scope': 'per_user',
     'parse': 'metadata', 'locations': (_loc('/etc/xdg/autostart'), _loc('~/.config/autostart'))},
    {'id': 'ssh_rc', 'label': 'SSH login rc hooks', 'trigger': 'login', 'scope': 'per_user', 'parse': 'metadata',
     'locations': (_loc('/etc/ssh/sshrc'), _loc('~/.ssh/rc'))},
    {'id': 'ssh_forced_command', 'label': 'SSH authorized_keys command= options', 'trigger': 'login',
     'scope': 'per_user', 'parse': 'metadata', 'locations': (_loc('~/.ssh/authorized_keys'),)},
    {'id': 'login_hooks', 'label': 'PAM, MOTD and X session login hooks', 'trigger': 'login', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/etc/pam.d'), _loc('/etc/update-motd.d', ('debian',)), _loc('/etc/X11/Xsession.d'))},
    {'id': 'event_hooks', 'label': 'Network dispatcher and log rotation hooks', 'trigger': 'event',
     'scope': 'system', 'parse': 'metadata',
     'locations': (_loc('/etc/NetworkManager/dispatcher.d'), _loc('/etc/network/if-up.d', ('debian',)),
                   _loc('/etc/logrotate.d'))},
    {'id': 'package_manager_hooks', 'label': 'Package manager hooks', 'trigger': 'event', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/etc/apt/apt.conf.d', ('debian',)), _loc('/etc/dnf/plugins', ('rpm',)),
                   _loc('/etc/yum/pluginconf.d', ('rpm',)))},
    {'id': 'udev_rules', 'label': 'udev rules', 'trigger': 'event', 'scope': 'system', 'parse': 'metadata',
     'locations': (_loc('/etc/udev/rules.d'), _loc('/run/udev/rules.d'), _loc('/usr/lib/udev/rules.d'),
                   _loc('/lib/udev/rules.d', ('debian',)))},
    {'id': 'loader_preload', 'label': 'Dynamic loader preload', 'trigger': 'loader', 'scope': 'system',
     'parse': 'metadata', 'locations': (_loc('/etc/ld.so.preload'),)},
    {'id': 'loader_config', 'label': 'Dynamic loader search paths', 'trigger': 'loader', 'scope': 'system',
     'parse': 'metadata', 'locations': (_loc('/etc/ld.so.conf'), _loc('/etc/ld.so.conf.d'))},
    {'id': 'modules_load', 'label': 'Kernel modules loaded at boot', 'trigger': 'boot', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/etc/modules', ('debian',)), _loc('/etc/modules-load.d'), _loc('/run/modules-load.d'),
                   _loc('/usr/lib/modules-load.d'), _loc('/lib/modules-load.d', ('debian',)))},
    {'id': 'modprobe', 'label': 'modprobe install/options configuration', 'trigger': 'event', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/etc/modprobe.d'), _loc('/run/modprobe.d'), _loc('/usr/lib/modprobe.d'),
                   _loc('/lib/modprobe.d', ('debian',)))},
)


def _gap(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {'code': code, 'detail': detail, **extra}


def _absolute_ok(value: Any) -> bool:
    return (isinstance(value, str) and 1 < len(value) <= MAX_PATH and value.startswith('/')
            and not value.startswith('//') and not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts)


def _home_ok(value: Any) -> bool:
    return (isinstance(value, str) and value.startswith('~/') and _absolute_ok('/home/u' + value[1:]))


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip('/') + '/')


def catalog(family: Any) -> dict[str, Any]:
    """Mechanisms and locations that apply to one platform family. An unknown
    family yields no mechanisms and a gap, never a guessed layout."""
    if family not in FAMILIES:
        return {'contract_version': CONTRACT_VERSION, 'family': None, 'mechanisms': [],
                'gaps': [_gap('unknown_family', 'Platform family is not debian or rpm; no catalog applies.')]}
    mechanisms = []
    for item in _MECHANISMS:
        locations = [loc['path'] for loc in item['locations'] if family in loc['families']]
        if locations:
            mechanisms.append({'id': item['id'], 'label': item['label'], 'trigger': item['trigger'],
                               'scope': item['scope'], 'parse': item['parse'], 'locations': locations})
    return {'contract_version': CONTRACT_VERSION, 'family': family, 'mechanisms': mechanisms,
            'gaps': [dict(NOT_EXHAUSTIVE)]}


def _all_locations(family: Any) -> list[str]:
    families = (family,) if family in FAMILIES else FAMILIES
    return [loc for fam in families for m in catalog(fam)['mechanisms'] for loc in m['locations']]


def _overlaps_home_location(path: str, home_relative: list[str]) -> bool:
    """A home parent, an account home, or a path holding a home-relative location."""
    if path in HOME_PARENTS or (_under(path, '/home') and path.count('/') == 2):
        return True
    if _under(path, '/root'):
        tail = path[len('/root'):]
    elif _under(path, '/home'):
        tail = '/' + path.split('/', 3)[3]
    else:
        return False
    return any(_under(tail, rel[1:]) or _under(rel[1:], tail) for rel in home_relative)


def validate_additional_scope(paths: Any, family: Any = None) -> dict[str, Any]:
    """Validate administrator-configured additional scope. Every rejected path gets
    a reason; accepted paths are labeled ``additional`` and never a mechanism.
    An unknown family is checked against every family's locations."""
    if not isinstance(paths, (list, tuple)):
        return {'accepted': [], 'rejected': [], 'gaps': [_gap('malformed_scope', 'Additional scope must be a list.')]}
    if len(paths) > MAX_ADDITIONAL:
        return {'accepted': [], 'rejected': [],
                'gaps': [_gap('over_limit', f'At most {MAX_ADDITIONAL} additional paths are allowed.')]}
    locations = _all_locations(family)
    known = [loc for loc in locations if loc.startswith('/')]
    home_relative = [loc for loc in locations if loc.startswith('~/')]
    accepted: list[dict[str, str]] = []
    rejected: list[dict[str, Any]] = []
    seen: list[str] = []
    for index, path in enumerate(paths):
        if not _absolute_ok(path):
            reason = 'invalid_path'
        elif path in seen:
            reason = 'duplicate'
        elif any(_under(path, p) or _under(p, path) for p in seen):
            reason = 'overlaps_additional'
        elif any(_under(path, p) for p in PSEUDO_FILESYSTEMS):
            reason = 'pseudo_or_root_filesystem'
        elif any(_under(path, p) or _under(p, path) for p in EXCLUDED_STATE):
            reason = 'excluded_state_directory'
        elif any(_under(path, p) or _under(p, path) for p in known) or _overlaps_home_location(path, home_relative):
            reason = 'overlaps_catalog_location'
        else:
            reason = ''
        if reason:
            rejected.append({'index': index, 'reason': reason})
            continue
        seen.append(path)
        accepted.append({'path': path, 'mechanism': 'additional'})
    gaps = [] if family is None or family in FAMILIES else [
        _gap('unknown_family', 'Platform family is unknown; paths were checked against every family.')]
    return {'accepted': accepted, 'rejected': rejected, 'gaps': gaps}


def _roots(value: Any, name: str, gaps: list[dict[str, Any]]) -> list[str] | None:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_ROOTS:
        gaps.append(_gap('malformed_collection', f'{name} must be a list of at most {MAX_ROOTS} paths.'))
        return None
    if not all(_absolute_ok(v) or _home_ok(v) for v in value):
        gaps.append(_gap('malformed_collection', f'{name} contains an invalid path.'))
        return None
    if len(set(value)) != len(value):
        gaps.append(_gap('malformed_collection', f'{name} repeat a path.'))
        return None
    return list(value)


def coverage(family: Any, collected_roots: Any, missing_roots: Any = (), *, failed_roots: Any = (),
             additional_roots: Any = (), complete: Any = False, homes_complete: Any = False,
             entries_reported: Any = False) -> dict[str, Any]:
    """Map a collection's scope onto the catalog.

    - ``collected_roots``: every root in the collection scope (absolute, or
      ``~/``-relative when inspected in each enumerated account home).
    - ``missing_roots``: roots reported absent; a subset of the collected roots.
    - ``failed_roots``: roots with any collection gap (symlinked, unreadable,
      budget, depth or entry limit); a subset of the collected roots.
    - ``additional_roots``: administrator custom scope; a subset of the collected
      roots. They are listed as ``additional`` and never credited to a mechanism.
    - ``complete``: the collection itself finished (inventory ``state`` collected).
    - ``homes_complete``: every account home was enumerated.
    - ``entries_reported``: the collection requested and returned parsed entries.
    """
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'family': None, 'mechanisms': [],
                              'additional': [], 'gaps': [dict(NOT_EXHAUSTIVE)]}
    gaps = result['gaps']
    listing = catalog(family)
    if listing['family'] is None:
        gaps[:] = listing['gaps']
        return result
    collected = _roots(collected_roots, 'Collected roots', gaps)
    missing = _roots(missing_roots, 'Missing roots', gaps)
    failed = _roots(failed_roots, 'Failed roots', gaps)
    additional = _roots(additional_roots, 'Additional roots', gaps)
    if collected is None or missing is None or failed is None or additional is None:
        return result
    if any(r not in collected for r in (*missing, *failed, *additional)):
        gaps.append(_gap('malformed_collection', 'Missing, failed and additional roots must be collected roots.'))
        return result
    if any(_under(r, m) and r != m for r in collected for m in missing):
        gaps.append(_gap('malformed_collection', 'A collected root lies inside a root reported missing.'))
        return result
    if any(type(v) is not bool for v in (complete, homes_complete, entries_reported)):
        gaps.append(_gap('malformed_collection', 'complete, homes_complete and entries_reported must be booleans.'))
        return result
    result['family'] = family
    if not complete:
        gaps.append(_gap('collection_incomplete', 'The collection did not finish; no mechanism is reported covered.'))
    builtin = [r for r in collected if r not in additional]
    present = [r for r in builtin if r not in missing and r not in failed]
    failed_builtin = [r for r in builtin if r in failed]

    def state_of(location: str) -> str:
        if any(_under(location, r) or _under(r, location) for r in failed_builtin):
            return 'collection_failed'
        if location.startswith('~/') and not homes_complete:
            return 'partial_homes' if any(_under(location, r) for r in present) else 'not_collected'
        if any(_under(location, r) for r in missing if r in builtin):
            return 'absent_reported'
        if any(_under(location, r) for r in present):
            return 'collected'
        if any(_under(r, location) for r in present):
            return 'partial_subpath'
        return 'not_collected'

    for mechanism in listing['mechanisms']:
        locations = [{'path': loc, 'state': state_of(loc)} for loc in mechanism['locations']]
        states = {loc['state'] for loc in locations}
        if states == {'absent_reported'}:
            state = 'absent_reported'
        elif states <= {'collected', 'absent_reported'}:
            state = 'covered' if complete else 'partial'
        elif states == {'not_collected'}:
            state = 'not_collected'
        else:
            state = 'partial'
        mechanism_gaps = []

        for code, wanted, detail in (
                ('locations_not_collected', 'not_collected',
                 'These locations were not in the collected scope; nothing is known about them.'),
                ('locations_partly_collected', 'partial_subpath', 'Only some paths inside these locations were collected.'),
                ('collection_failed', 'collection_failed',
                 'Collection of these locations failed or was cut short; nothing is known about them.'),
                ('absence_is_not_safety', 'absent_reported',
                 'The collector reported these paths missing; that is not a safety verdict.')):
            hit = [loc['path'] for loc in locations if loc['state'] == wanted]
            if hit:
                mechanism_gaps.append(_gap(code, detail, paths=hit))
        if 'partial_homes' in states:
            mechanism_gaps.append(_gap('user_homes_incomplete',
                                       'Not every account home was enumerated for home-relative locations.'))
        parsed = mechanism['parse'] == 'entries' and entries_reported and 'collected' in states
        if mechanism['parse'] == 'entries' and not parsed and state != 'not_collected':
            mechanism_gaps.append(_gap('entries_not_parsed', 'No collected location had its entries parsed.'))
        if mechanism['parse'] == 'metadata' and state != 'not_collected':
            mechanism_gaps.append(_gap('metadata_only', 'Only file metadata is collected; individual entries are not parsed.'))
        result['mechanisms'].append({'id': mechanism['id'], 'state': state, 'entries_parsed': parsed,
                                     'locations': locations, 'gaps': mechanism_gaps})

    catalog_paths = [loc for m in listing['mechanisms'] for loc in m['locations']]
    for root in collected:
        overlaps = any(_under(root, loc) or _under(loc, root) for loc in catalog_paths)
        if root in additional or not overlaps:
            result['additional'].append({'path': root, 'mechanism': 'additional', 'missing': root in missing,
                                         'failed': root in failed})
    return result
