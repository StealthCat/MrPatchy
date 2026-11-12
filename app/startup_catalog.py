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
- Administrator additional scope is labeled ``additional`` and is never mapped
  onto a catalog mechanism or used to claim that a mechanism is covered.
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
MAX_ADDITIONAL = 32
MAX_ROOTS = 256
MAX_PATH = 4096
PSEUDO_FILESYSTEMS = ('/proc', '/sys', '/dev')

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
     'locations': (_loc('/etc/systemd/system'), _loc('/run/systemd/system'), _loc('/usr/local/lib/systemd/system'),
                   _loc('/usr/lib/systemd/system'), _loc('/lib/systemd/system', ('debian',)))},
    {'id': 'systemd_generated', 'label': 'systemd generator output', 'trigger': 'boot', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/run/systemd/generator.early'), _loc('/run/systemd/generator'),
                   _loc('/run/systemd/generator.late'))},
    {'id': 'systemd_transient', 'label': 'systemd transient units', 'trigger': 'event', 'scope': 'system',
     'parse': 'metadata', 'locations': (_loc('/run/systemd/transient'),)},
    {'id': 'systemd_user', 'label': 'systemd user units', 'trigger': 'login', 'scope': 'per_user',
     'parse': 'metadata',
     'locations': (_loc('/etc/systemd/user'), _loc('/usr/lib/systemd/user'), _loc('~/.config/systemd/user'))},
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
                   _loc('/usr/lib/modules-load.d'))},
    {'id': 'modprobe', 'label': 'modprobe install/options configuration', 'trigger': 'event', 'scope': 'system',
     'parse': 'metadata',
     'locations': (_loc('/etc/modprobe.d'), _loc('/run/modprobe.d'), _loc('/usr/lib/modprobe.d'))},
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
    return {'contract_version': CONTRACT_VERSION, 'family': family, 'mechanisms': mechanisms, 'gaps': []}


def _catalog_paths(family: str) -> list[str]:
    return [loc for m in catalog(family)['mechanisms'] for loc in m['locations'] if loc.startswith('/')]


def validate_additional_scope(paths: Any, family: Any = None) -> dict[str, Any]:
    """Validate administrator-configured additional scope. Every rejected path gets
    a reason; accepted paths are labeled ``additional`` and never a mechanism."""
    if not isinstance(paths, (list, tuple)):
        return {'accepted': [], 'rejected': [], 'gaps': [_gap('malformed_scope', 'Additional scope must be a list.')]}
    if len(paths) > MAX_ADDITIONAL:
        return {'accepted': [], 'rejected': [],
                'gaps': [_gap('over_limit', f'At most {MAX_ADDITIONAL} additional paths are allowed.')]}
    known = set()
    for fam in (FAMILIES if family is None else (family,) if family in FAMILIES else ()):
        known.update(_catalog_paths(fam))
    accepted: list[dict[str, str]] = []
    rejected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, path in enumerate(paths):
        if not _absolute_ok(path):
            reason = 'invalid_path'
        elif path in seen:
            reason = 'duplicate'
        elif any(_under(path, p) or _under(p, path) for p in seen):
            reason = 'overlaps_additional'
        elif path == '/' or any(_under(path, p) for p in PSEUDO_FILESYSTEMS):
            reason = 'pseudo_or_root_filesystem'
        elif any(_under(path, p) or _under(p, path) for p in known):
            reason = 'overlaps_catalog_location'
        else:
            reason = ''
        if reason:
            rejected.append({'index': index, 'reason': reason})
            continue
        seen.add(path)
        accepted.append({'path': path, 'mechanism': 'additional'})
    gaps = [] if family is None or family in FAMILIES else [
        _gap('unknown_family', 'Catalog locations could not be checked for an unknown platform family.')]
    return {'accepted': accepted, 'rejected': rejected, 'gaps': gaps}


def _roots(value: Any, name: str, gaps: list[dict[str, Any]]) -> list[str] | None:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_ROOTS:
        gaps.append(_gap('malformed_collection', f'{name} must be a list of at most {MAX_ROOTS} paths.'))
        return None
    if not all(_absolute_ok(v) or _home_ok(v) for v in value):
        gaps.append(_gap('malformed_collection', f'{name} contains an invalid path.'))
        return None
    return list(value)


def coverage(family: Any, collected_roots: Any, missing_roots: Any = (), *, homes_complete: bool = False) -> dict[str, Any]:
    """Map a collection's scope onto the catalog.

    ``collected_roots`` are the roots the collector inspected (absolute paths, or
    ``~/``-relative paths it inspected in every enumerated account home).
    ``missing_roots`` must be a subset of them and lists roots reported absent.
    ``homes_complete`` states that every account home was enumerated.
    """
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'family': None, 'mechanisms': [],
                              'additional': [], 'gaps': []}
    gaps = result['gaps']
    listing = catalog(family)
    if listing['family'] is None:
        gaps.extend(listing['gaps'])
        return result
    collected = _roots(collected_roots, 'Collected roots', gaps)
    missing = _roots(missing_roots, 'Missing roots', gaps)
    if collected is None or missing is None:
        return result
    if len(set(collected)) != len(collected) or any(m not in collected for m in missing):
        gaps.append(_gap('malformed_collection', 'Collected roots repeat, or a missing root was not collected.'))
        return result
    if type(homes_complete) is not bool:
        gaps.append(_gap('malformed_collection', 'homes_complete must be a boolean.'))
        return result
    result['family'] = family
    present = [r for r in collected if r not in missing]

    def state_of(location: str) -> str:
        if location.startswith('~/') and not homes_complete:
            return 'partial_homes' if any(_under(location, r) for r in present) else 'not_collected'
        if any(_under(location, r) for r in missing):
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
            state = 'covered'
        elif states == {'not_collected'}:
            state = 'not_collected'
        else:
            state = 'partial'
        mechanism_gaps = []
        uncollected = [loc['path'] for loc in locations if loc['state'] == 'not_collected']
        if uncollected:
            mechanism_gaps.append(_gap('locations_not_collected',
                                       'These locations were not in the collected scope; nothing is known about them.',
                                       paths=uncollected))
        narrowed = [loc['path'] for loc in locations if loc['state'] == 'partial_subpath']
        if narrowed:
            mechanism_gaps.append(_gap('locations_partly_collected',
                                       'Only some paths inside these locations were collected.', paths=narrowed))
        if 'partial_homes' in states:
            mechanism_gaps.append(_gap('user_homes_incomplete',
                                       'Not every account home was enumerated for home-relative locations.'))
        if state == 'absent_reported':
            mechanism_gaps.append(_gap('absence_is_not_safety',
                                       'The collector reported these paths missing; that is not a safety verdict.'))
        parsed = mechanism['parse'] == 'entries' and state in ('covered', 'partial')
        if mechanism['parse'] == 'metadata' and state != 'not_collected':
            mechanism_gaps.append(_gap('metadata_only', 'Only file metadata is collected; individual entries are not parsed.'))
        result['mechanisms'].append({'id': mechanism['id'], 'state': state, 'entries_parsed': parsed,
                                     'locations': locations, 'gaps': mechanism_gaps})

    catalog_paths = [loc for m in listing['mechanisms'] for loc in m['locations']]
    for root in collected:
        if not any(_under(root, loc) or _under(loc, root) for loc in catalog_paths):
            result['additional'].append({'path': root, 'mechanism': 'additional', 'missing': root in missing})
    return result
