"""Pure systemd effective-unit resolution contract (roadmap F slice, #702).

Takes captured, read-only observations of systemd system-unit search
directories (path, entry kind, symlink target, bounded file text) and returns
typed effective-unit records: which fragment wins under search-path precedence,
which fragments it shadows, which drop-ins apply in which order, the resolved
commands/account/schedule, enablement links, masking, timer/socket/path trigger
relationships and the origin of every contributing file.

It performs no I/O, never runs ``systemctl`` or a unit, never sources a script
and never authorizes a response action. Anything it cannot resolve exactly
(an uncollected search directory, unreadable or oversized text, malformed lines,
invalid names, unresolved links, over-cap inputs, runtime state, drop-ins that
apply to no resolved unit) becomes an explicit coverage gap; it is never
silently reported as covered. A drop-in directory naming an instance of an
observed template resolves that instance even without an enablement link,
because on-demand activation needs none. Package
ownership is not inferred: a ``vendor`` origin means only "found in a vendor
search directory", never "verified unchanged package default".

Precedence follows ``systemd.unit(5)`` for the system manager, highest first.
Drop-ins are applied in lexicographic file-name order across every applicable
drop-in directory; for one file name the copy in the highest-precedence search
directory wins, and within one search directory the most specific directory
(unit, then template, then longest dash prefix, then unit type) wins.

A unit's names are its canonical name plus every effective alias (a winning
fragment symlink whose target file has another unit name). systemd reads drop-in
directories for all of those names, so the canonical record and every alias
record apply the same drop-in set. For one file name within one search
directory, a canonical-name directory outranks an alias-name directory of the
same specificity. An alias whose target is not the canonical name's own winning
fragment is reported as an ``alias_target_shadowed`` gap rather than guessed.

Each non-template record carries an ``expanded`` view of ``EXPAND_KEYS`` with
systemd specifiers expanded only where their value is fixed: unit-name
specifiers (with unescaping) and manager specifiers documented for the scope.
Host, boot and environment-dependent specifiers are never guessed; a value
containing one stays raw and the unit gets an ``unexpanded_specifier`` gap.
``$VAR`` environment substitution is not performed.

``resolve_user`` applies the same rules to one account's ``systemd --user``
manager using the user search table (``user_search_paths``). Units from the
account's own configuration/data directories have origin ``user`` and are never
package defaults; the account owning the manager is the effective identity.
An optional ``xdg`` mapping taken from the user manager's environment applies
non-default ``XDG_CONFIG_HOME``/``XDG_DATA_HOME``/``XDG_CACHE_HOME`` and
``XDG_CONFIG_DIRS``/``XDG_DATA_DIRS``; an invalid value is a coverage gap and
is never replaced by a guessed default.

Both resolvers take an optional ``systemd_version`` (the manager's release,
from ``parse_systemd_version``). Specifier meanings changed across releases, so
a supplied version withholds every specifier that release did not support with
its current meaning (``SPECIFIER_MIN_VERSION``); a withheld specifier stays raw
as an ``unexpanded_specifier`` gap. Omitting the version keeps today's table.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from typing import Any, Iterable

CONTRACT_VERSION = 2
MAX_OBSERVATIONS = 4096
MAX_TEXT = 65536
MAX_VALUE = 4096
MAX_NAME = 255
MAX_LINKS_PER_UNIT = 256

# (directory, origin), highest precedence first.
SEARCH_PATHS: tuple[tuple[str, str], ...] = (
    ('/etc/systemd/system.control', 'administrator'),
    ('/run/systemd/system.control', 'runtime'),
    ('/run/systemd/transient', 'transient'),
    ('/run/systemd/generator.early', 'generated'),
    ('/etc/systemd/system', 'administrator'),
    ('/run/systemd/system', 'runtime'),
    ('/run/systemd/generator', 'generated'),
    ('/usr/local/lib/systemd/system', 'local'),
    ('/usr/lib/systemd/system', 'vendor'),
    ('/lib/systemd/system', 'vendor'),
    ('/run/systemd/generator.late', 'generated'),
)
_RANK = {root: i for i, (root, _) in enumerate(SEARCH_PATHS)}
_ORIGIN = dict(SEARCH_PATHS)
# Longest roots first so '/etc/systemd/system.control' is not read as '/etc/systemd/system'.
_ROOTS_BY_LEN = sorted(_RANK, key=len, reverse=True)
# Enablement is only meaningful from administrator/runtime directories.
_ENABLEMENT_ORIGINS = frozenset({'administrator', 'runtime', 'transient', 'generated'})

UNIT_TYPES = ('service', 'socket', 'timer', 'path', 'target', 'mount', 'automount',
              'swap', 'slice', 'scope', 'device')
_NAME_RE = re.compile(r'^([A-Za-z0-9:_.\\-]+?)(@([A-Za-z0-9:_.\\-]*))?\.(' + '|'.join(UNIT_TYPES) + r')$')
_DEP_DIRS = ('wants', 'requires', 'upholds')
LIST_KEYS = frozenset({
    'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecReload',
    'ExecCondition', 'OnCalendar', 'OnBootSec', 'OnStartupSec', 'OnActiveSec',
    'OnUnitActiveSec', 'OnUnitInactiveSec', 'WantedBy', 'RequiredBy', 'Alias',
    'ListenStream', 'ListenDatagram', 'PathExists', 'PathChanged', 'PathModified',
    'Environment', 'EnvironmentFile',
})
SCALAR_KEYS = frozenset({
    'Description', 'Type', 'User', 'Group', 'DynamicUser', 'Unit', 'Persistent',
    'RemainAfterExit', 'WorkingDirectory', 'RootDirectory',
})
LIMITATIONS = (
    'Runtime active/inactive/failed state is not collected by this contract.',
    'Per-user (systemd --user) units are resolved separately by resolve_user().',
    'Package ownership and vendor-default authenticity are not verified here.',
    'Specifiers are expanded only in EXPAND_KEYS and only where their value is fixed; '
    'host/boot/environment specifiers stay raw as gaps. $VAR environment substitution is not performed.',
    'System %u/%U/%h/%s follow current systemd.unit(5) (the manager user, not User=); older '
    'systemd releases resolved them from User=, and the collector does not record the systemd version.',
    'Only the settings named in LIST_KEYS/SCALAR_KEYS are resolved into config.',
)
USER_LIMITATIONS = (
    'Runtime active/inactive/failed state and lingering are not collected by this contract.',
    'XDG_* directories are applied only when the caller supplies the user manager\'s environment as xdg; '
    'otherwise the XDG Base Directory defaults are assumed.',
    'Package ownership and vendor-default authenticity are not verified here.',
    'Specifiers are expanded only in EXPAND_KEYS and only where their value is fixed; %U, %G, %g, %s '
    'and host/boot/environment specifiers stay raw as gaps. $VAR environment substitution is not performed.',
    'Only the settings named in LIST_KEYS/SCALAR_KEYS are resolved into config.',
)
# Settings whose values get an ``expanded`` view. Raw ``config`` is never rewritten.
EXPAND_KEYS = frozenset({
    'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecReload',
    'ExecCondition', 'User', 'Group', 'WorkingDirectory', 'RootDirectory', 'EnvironmentFile',
})
# Manager specifiers whose value systemd.unit(5) fixes for the system manager.
SYSTEM_MANAGER_SPECIFIERS = {
    'u': 'root', 'U': '0', 'g': 'root', 'G': '0', 'h': '/root', 's': '/bin/sh',
    't': '/run', 'S': '/var/lib', 'C': '/var/cache', 'L': '/var/log', 'E': '/etc',
}


# First systemd release giving each manager specifier its current
# systemd.unit(5) meaning (upstream NEWS): 228 made %u/%U/%h/%s always resolve
# to the manager's user instead of User=; 236 added %S/%C/%L; 239 added %E and
# the unit-name %j/%J; 240 added %g/%G. Older releases leave these unexpanded.
SPECIFIER_MIN_VERSION = {
    'u': 228, 'U': 228, 'h': 228, 's': 228,
    'S': 236, 'C': 236, 'L': 236,
    'E': 239, 'j': 239, 'J': 239,
    'g': 240, 'G': 240,
}
MAX_SYSTEMD_VERSION = 9999
MAX_VERSION_TEXT = 4096
_VERSION_RE = re.compile(r'^systemd ([0-9]{1,4})(?: \(([\x21-\x7e][\x20-\x7e]{0,127})\))?$')
VERSION_LIMITATION_APPLIED = ('Version-dependent specifiers follow the supplied systemd version; '
                              'a specifier that release did not support stays raw as a gap.')
VERSION_LIMITATION_INVALID = ('The supplied systemd version was invalid, so every version-dependent '
                              'specifier stays raw as a gap.')


def _gap(code: str, path: str = '', detail: str = '') -> dict[str, str]:
    return {'code': code, 'path': path[:512], 'detail': detail[:256]}


def parse_name(name: Any) -> dict[str, Any] | None:
    """Return name parts or None for an invalid unit name."""
    if not isinstance(name, str) or not name or len(name) > MAX_NAME:
        return None
    m = _NAME_RE.match(name)
    if not m:
        return None
    prefix, at, instance, kind = m.group(1), m.group(2), m.group(3), m.group(4)
    return {
        'name': name, 'prefix': prefix, 'type': kind,
        'template': bool(at) and instance == '',
        'instance': instance if at and instance else None,
        'template_name': f'{prefix}@.{kind}' if at else None,
    }


def _locate(path: str, roots_by_len: Iterable[str] = _ROOTS_BY_LEN) -> tuple[str, str] | None:
    for root in roots_by_len:
        if path.startswith(root + '/'):
            return root, path[len(root) + 1:]
    return None


def parse_unit_text(text: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Parse one fragment/drop-in into ``{section: {key: [assignments]}}``.

    Every assignment is kept in order (including empty resets) so that the
    caller can apply systemd's list-reset semantics across files. Returns the
    parsed sections and a list of problems (malformed or overlong lines).
    """
    sections: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    current: str | None = None
    pending = ''
    for raw in text.splitlines():
        line = pending + raw.strip() if pending else raw.strip()
        pending = ''
        if line.endswith('\\'):
            pending = line[:-1].rstrip() + ' '
            continue
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if '=' not in line or current is None:
            problems.append('malformed_line')
            continue
        key, value = line.split('=', 1)
        key, value = key.strip(), value.strip()
        if not key or len(value) > MAX_VALUE:
            problems.append('overlong_value' if key else 'malformed_line')
            continue
        sections[current].setdefault(key, []).append(value)
    if pending:
        problems.append('dangling_continuation')
    return sections, problems


def _merge(layers: Iterable[dict[str, dict[str, list[str]]]]) -> dict[str, dict[str, Any]]:
    """Apply fragment then drop-ins: lists reset on empty assignment, scalars last-wins."""
    out: dict[str, dict[str, Any]] = {}
    for layer in layers:
        for section, keys in layer.items():
            dest = out.setdefault(section, {})
            for key, values in keys.items():
                if key in LIST_KEYS:
                    cur = dest.get(key, [])
                    for v in values:
                        cur = [] if v == '' else cur + [v]
                    dest[key] = cur
                elif key in SCALAR_KEYS:
                    dest[key] = values[-1] if values else None
    return out


def _dropin_dirs(parts: dict[str, Any]) -> list[str]:
    """Drop-in directory names for a unit, most specific first."""
    name, kind = parts['name'], parts['type']
    dirs = [name + '.d']
    if parts['template_name'] and parts['template_name'] != name:
        dirs.append(parts['template_name'] + '.d')
    pieces = parts['prefix'].split('-')
    for i in range(len(pieces) - 1, 0, -1):
        dirs.append('-'.join(pieces[:i]) + '-.' + kind + '.d')
    dirs.append(kind + '.d')
    return dirs


def parse_systemd_version(text: Any) -> dict[str, Any]:
    """Parse ``systemctl --version`` output into the manager's release number.

    Only the first line is read: ``systemd N`` optionally followed by
    `` (package-version)``. Returns ``{'version', 'package_version', 'gaps'}``;
    anything not matching exactly (missing, oversized, NUL, leading zeros,
    out-of-range or extra text) yields ``version`` None and a gap, never a guess.
    """
    gaps: list[dict[str, str]] = []
    if not isinstance(text, str):
        return {'version': None, 'package_version': None, 'gaps': [_gap('systemd_version_unreadable')]}
    if len(text) > MAX_VERSION_TEXT or '\x00' in text:
        return {'version': None, 'package_version': None,
                'gaps': [_gap('systemd_version_unparsed', detail='oversized or NUL')]}
    first = text.split('\n', 1)[0].rstrip(' \t\r')
    match = _VERSION_RE.match(first)
    version = int(match.group(1)) if match else None
    if match is None or match.group(1).startswith('0') or not 0 < version <= MAX_SYSTEMD_VERSION:
        gaps.append(_gap('systemd_version_unparsed', detail=first[:64]))
        return {'version': None, 'package_version': None, 'gaps': gaps}
    return {'version': version, 'package_version': match.group(2), 'gaps': gaps}


def _version_withheld(systemd_version: Any) -> tuple[str, int | None, frozenset[str]]:
    """Return (state, version, specifiers withheld) for an optional supplied version."""
    if systemd_version is None:
        return 'not_supplied', None, frozenset()
    if isinstance(systemd_version, bool) or not isinstance(systemd_version, int) \
            or not 0 < systemd_version <= MAX_SYSTEMD_VERSION:
        return 'invalid', None, frozenset(SPECIFIER_MIN_VERSION)
    return 'applied', systemd_version, frozenset(
        k for k, minimum in SPECIFIER_MIN_VERSION.items() if systemd_version < minimum)


def resolve(observations: Any, collected_roots: Any = None, systemd_version: Any = None) -> dict[str, Any]:
    """Resolve effective system units from captured observations.

    ``observations`` is a list of dicts with ``path`` and ``kind`` (``file``,
    ``symlink``, ``dir`` or ``unreadable``), plus ``target`` for symlinks and
    ``text`` (and optional ``truncated``) for files. ``collected_roots`` lists
    the search directories the collector actually enumerated; every other
    search directory is reported as an uncollected coverage gap.
    ``systemd_version`` is the manager's release (see ``parse_systemd_version``);
    when supplied, specifiers that release did not support with today's meaning
    stay raw as gaps. Omitting it keeps the current ``systemd.unit(5)`` table.
    """
    return _resolve(observations, collected_roots, SEARCH_PATHS, _ENABLEMENT_ORIGINS, [],
                    manager_specifiers=SYSTEM_MANAGER_SPECIFIERS, systemd_version=systemd_version)


def _valid_dir(value: Any) -> bool:
    return (isinstance(value, str) and value.startswith('/') and value != '/' and '\x00' not in value
            and '\n' not in value and len(value) <= 1024 and posixpath.normpath(value) == value)


# Bounds for caller-supplied XDG_CONFIG_DIRS/XDG_DATA_DIRS entries.
MAX_XDG_DIRS = 32
XDG_KEYS = ('config_home', 'data_home', 'cache_home', 'config_dirs', 'data_dirs')
# XDG Base Directory defaults used when a key is absent or empty.
_XDG_DEFAULT_CONFIG_DIRS = ('/etc/xdg',)
_XDG_DEFAULT_DATA_DIRS = ('/usr/local/share', '/usr/share')
_XDG_DIR_ORIGINS = {'/etc/xdg': 'administrator', '/usr/local/share': 'local', '/usr/share': 'vendor'}


def _xdg_path(value: Any) -> str | None:
    """A trailing ``/`` is tolerated; anything else must already be a valid directory."""
    if isinstance(value, str) and len(value) > 1:
        value = value.rstrip('/') or '/'
    return value if _valid_dir(value) else None


def _xdg_settings(home: str | None, xdg: Any) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Resolve the XDG directories for one user manager.

    Absent, ``None`` or empty values take the XDG Base Directory default (the
    home-relative ones only when ``home`` is valid). A supplied invalid value
    is reported and its directories are left out rather than defaulted.
    """
    gaps: list[dict[str, str]] = []
    if xdg is None:
        xdg = {}
    elif not isinstance(xdg, dict):
        gaps.append(_gap('xdg_invalid'))
        xdg = {}
    unknown = sorted(str(k)[:64] for k in xdg if k not in XDG_KEYS)
    if unknown:
        gaps.append(_gap('xdg_unknown_key', detail=','.join(unknown)[:512]))
    defaults = {'config_home': home and f'{home}/.config', 'data_home': home and f'{home}/.local/share',
                'cache_home': home and f'{home}/.cache'}
    out: dict[str, Any] = {}
    for key, default in defaults.items():
        value = xdg.get(key)
        if value is None or value == '':
            out[key] = default
            continue
        out[key] = _xdg_path(value)
        if out[key] is None:
            gaps.append(_gap('xdg_' + key + '_invalid', value[:512] if isinstance(value, str) else ''))
    for key, default in (('config_dirs', _XDG_DEFAULT_CONFIG_DIRS), ('data_dirs', _XDG_DEFAULT_DATA_DIRS)):
        value = xdg.get(key)
        if isinstance(value, str):
            value = value.split(':')
        if value is None or (isinstance(value, (list, tuple)) and not any(v != '' for v in value)):
            out[key] = list(default)
            continue
        if not isinstance(value, (list, tuple)):
            gaps.append(_gap('xdg_' + key + '_invalid'))
            out[key] = []
            continue
        entries = [v for v in value if v != '']
        if len(entries) > MAX_XDG_DIRS:
            gaps.append(_gap('xdg_' + key + '_cap', detail=f'{len(entries)} > {MAX_XDG_DIRS}'))
            entries = entries[:MAX_XDG_DIRS]
        dirs = []
        for entry in entries:
            path = _xdg_path(entry)
            if path is None:
                gaps.append(_gap('xdg_' + key + '_invalid', entry[:512] if isinstance(entry, str) else ''))
            else:
                dirs.append(path)
        out[key] = dirs
    return out, gaps


def _xdg_dir_origin(path: str, home: str | None, fallback: str) -> str:
    if home and (path == home or path.startswith(home + '/')):
        return 'user'
    return _XDG_DIR_ORIGINS.get(path, fallback)


def user_search_paths(home: Any, runtime_dir: Any,
                      xdg: Any = None) -> tuple[tuple[tuple[str, str], ...], list[dict[str, str]]]:
    """Return the user-manager search table for one account, highest first.

    Follows the ``systemd --user`` table of ``systemd.unit(5)`` with
    ``$XDG_RUNTIME_DIR`` set to ``runtime_dir``. ``xdg`` optionally carries the
    user manager's ``config_home``, ``data_home``, ``cache_home``,
    ``config_dirs`` and ``data_dirs`` (lists or ``:``-separated strings);
    absent or empty values use the XDG Base Directory defaults under ``home``,
    ``/etc/xdg`` and ``/usr/local/share:/usr/share``. An invalid home, runtime
    directory or supplied XDG value omits its directories and returns a gap. A
    directory that would coincide with another one in the table is omitted and
    reported, never merged or guessed.
    """
    gaps: list[dict[str, str]] = []
    h = home if _valid_dir(home) else None
    r = runtime_dir if _valid_dir(runtime_dir) else None
    if h is None:
        gaps.append(_gap('user_home_invalid', home[:512] if isinstance(home, str) else ''))
    if r is None:
        gaps.append(_gap('user_runtime_dir_invalid', runtime_dir[:512] if isinstance(runtime_dir, str) else ''))
    dirs, xdg_gaps = _xdg_settings(h, xdg)
    gaps.extend(xdg_gaps)
    ch, dh = dirs['config_home'], dirs['data_home']
    config_dirs = [(f'{d}/systemd/user', _xdg_dir_origin(d, h, 'administrator')) for d in dirs['config_dirs']]
    data_dirs = [(f'{d}/systemd/user', _xdg_dir_origin(d, h, 'local')) for d in dirs['data_dirs']]
    table: list[tuple[str | None, str]] = [
        (ch and f'{ch}/systemd/user.control', 'user'),
        (r and f'{r}/systemd/user.control', 'runtime'),
        (r and f'{r}/systemd/transient', 'transient'),
        (r and f'{r}/systemd/generator.early', 'generated'),
        (ch and f'{ch}/systemd/user', 'user'),
        *config_dirs,
        ('/etc/systemd/user', 'administrator'),
        (r and f'{r}/systemd/user', 'runtime'),
        ('/run/systemd/user', 'runtime'),
        (r and f'{r}/systemd/generator', 'generated'),
        (dh and f'{dh}/systemd/user', 'user'),
        *data_dirs,
        ('/usr/local/lib/systemd/user', 'local'),
        ('/usr/lib/systemd/user', 'vendor'),
        ('/lib/systemd/user', 'vendor'),
        (r and f'{r}/systemd/generator.late', 'generated'),
    ]
    roots = [root for root, _ in table if root]
    duplicate = {root for root in roots if roots.count(root) > 1}
    result = []
    for root, origin in table:
        if not root:
            continue
        if root in duplicate:
            gaps.append(_gap('user_search_path_conflict', root))
            continue
        result.append((root, origin))
    return tuple(result), gaps


def resolve_user(observations: Any, home: Any, runtime_dir: Any, account: Any,
                 collected_roots: Any = None, xdg: Any = None,
                 systemd_version: Any = None) -> dict[str, Any]:
    """Resolve one account's effective ``systemd --user`` units.

    ``home`` and ``runtime_dir`` (``$XDG_RUNTIME_DIR``, normally
    ``/run/user/<uid>``) locate the per-user directories; ``account`` is the
    login that owns the user manager. A user manager runs every service as
    that account, so ``User=`` never selects another identity: it is kept as
    ``declared_user`` and a different value is reported as a gap. Exec
    prefixes ``+``/``!`` relax sandboxing within the account and do not gain
    root, so ``privileged_exec`` is always false here. Enablement links in the
    account's own configuration directory count as enabled. ``xdg`` is the
    optional user-manager XDG environment described in ``user_search_paths``;
    ``systemd_version`` gates specifiers exactly as in ``resolve``.
    """
    table, gaps = user_search_paths(home, runtime_dir, xdg)
    valid_account = isinstance(account, str) and 0 < len(account) <= 255 and account.isprintable() \
        and '/' not in account and ':' not in account
    if not valid_account:
        gaps.append(_gap('user_account_invalid'))
    manager: dict[str, str] = {}
    if valid_account:
        manager['u'] = account
    if _valid_dir(home):
        manager['h'] = home
    # %E/%C are XDG_CONFIG_HOME/XDG_CACHE_HOME; %S/%L moved between systemd
    # releases, so they stay unexpanded rather than guessed.
    dirs, _ = _xdg_settings(home if _valid_dir(home) else None, xdg)
    if dirs['config_home']:
        manager['E'] = dirs['config_home']
    if dirs['cache_home']:
        manager['C'] = dirs['cache_home']
    if _valid_dir(runtime_dir):
        manager['t'] = runtime_dir
    result = _resolve(observations, collected_roots, table, _ENABLEMENT_ORIGINS | {'user'}, gaps,
                      scope='user', account=account if valid_account else None,
                      manager_specifiers=manager, systemd_version=systemd_version)
    return result


def _resolve(observations: Any, collected_roots: Any, search_paths, enablement_origins,
             initial_gaps, scope: str = 'system', account: Any = None,
             manager_specifiers: dict[str, str] | None = None,
             systemd_version: Any = None) -> dict[str, Any]:
    version_state, version, withheld = _version_withheld(systemd_version)
    rank = {root: i for i, (root, _) in enumerate(search_paths)}
    origins = dict(search_paths)
    roots_by_len = sorted(rank, key=len, reverse=True)
    gaps: list[dict[str, str]] = list(initial_gaps)
    if version_state == 'invalid':
        gaps.append(_gap('systemd_version_invalid', detail=repr(systemd_version)[:64]))
    obs = observations if isinstance(observations, list) else []
    if not isinstance(observations, list):
        gaps.append(_gap('invalid_observations'))
    if len(obs) > MAX_OBSERVATIONS:
        gaps.append(_gap('observation_cap', detail=f'{len(obs)} > {MAX_OBSERVATIONS}'))
        obs = obs[:MAX_OBSERVATIONS]
    collected = set(collected_roots) if isinstance(collected_roots, (list, tuple, set, frozenset)) else set()
    for root, _ in search_paths:
        if root not in collected:
            gaps.append(_gap('search_path_not_collected', root))

    fragments: dict[str, list[dict[str, Any]]] = {}
    dropins: dict[tuple[str, str], list[dict[str, Any]]] = {}  # (dir name, file name)
    links: list[dict[str, Any]] = []
    by_path: dict[str, dict[str, Any]] = {}
    external: dict[str, dict[str, Any]] = {}

    for o in obs:
        if not isinstance(o, dict):
            gaps.append(_gap('invalid_observation'))
            continue
        path = o.get('path')
        if (not isinstance(path, str) or not path.startswith('/') or '\x00' in path
                or posixpath.normpath(path) != path or len(path) > 4096):
            gaps.append(_gap('invalid_path', str(path)[:512] if isinstance(path, str) else ''))
            continue
        loc = _locate(path, roots_by_len)
        if not loc:
            # Possible target of a linked unit (``systemctl link``); kept only as link content.
            if o.get('kind') == 'file' and isinstance(o.get('text'), str):
                external[path] = {'path': path, 'origin': 'linked', 'rank': len(search_paths), 'kind': 'file',
                                  'text': '' if (o.get('truncated') or len(o['text']) > MAX_TEXT) else o['text'],
                                  'incomplete': bool(o.get('truncated') or len(o['text']) > MAX_TEXT)}
            else:
                gaps.append(_gap('outside_search_path', path))
            continue
        root, rel = loc
        kind = o.get('kind')
        if kind == 'dir':
            continue
        if kind == 'unreadable':
            gaps.append(_gap('unreadable', path))
            continue
        if kind not in ('file', 'symlink'):
            gaps.append(_gap('unsupported_entry_kind', path, str(kind)[:32]))
            continue
        rec = {'path': path, 'root': root, 'origin': origins[root], 'rank': rank[root], 'kind': kind}
        if kind == 'symlink':
            target = o.get('target')
            if not isinstance(target, str) or not target or '\x00' in target:
                gaps.append(_gap('unresolved_link', path))
                continue
            if not target.startswith('/'):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
            rec['target'] = target
        else:
            text = o.get('text')
            if not isinstance(text, str):
                gaps.append(_gap('unreadable', path, 'no text'))
                continue
            if o.get('truncated') or len(text) > MAX_TEXT:
                gaps.append(_gap('oversized', path))
                rec['incomplete'] = True
                text = ''
            rec['text'] = text
        by_path[path] = rec
        segs = rel.split('/')
        if len(segs) == 1:
            if parse_name(segs[0]) is None:
                gaps.append(_gap('invalid_unit_name', path))
                continue
            rec['name'] = segs[0]
            fragments.setdefault(segs[0], []).append(rec)
        elif len(segs) == 2 and segs[0].endswith('.d') and kind == 'file':
            if not segs[1].endswith('.conf'):
                continue  # systemd ignores non-.conf files in drop-in dirs
            dropins.setdefault((segs[0], segs[1]), []).append(rec)
        elif len(segs) == 2 and kind == 'symlink' and segs[0].rsplit('.', 1)[-1] in _DEP_DIRS:
            owner, dep = segs[0].rsplit('.', 1)
            if parse_name(owner) is None or parse_name(segs[1]) is None:
                gaps.append(_gap('invalid_unit_name', path))
                continue
            rec.update(owner=owner, dependency=dep, name=segs[1])
            links.append(rec)
        else:
            gaps.append(_gap('unrecognized_entry', path))

    for path, rec in external.items():
        by_path.setdefault(path, rec)
    names = set(fragments)
    for link in links:
        names.add(link['name'])
        names.add(link['owner'])
    # Instances started on demand (logind autovt, sockets, ``systemctl start
    # foo@x``) need no link; a drop-in directory naming an instance of an
    # observed template still configures that instance, so resolve it.
    for dname, _ in dropins:
        dparts = parse_name(dname[:-2])
        if dparts and dparts['instance'] and dparts['template_name'] in fragments:
            names.add(dparts['name'])

    alias_target, aliases = _alias_map(fragments, by_path)

    units: list[dict[str, Any]] = []
    unit_index: dict[str, dict[str, Any]] = {}
    referenced: set[Any] = set()
    for name in sorted(names):
        parts = parse_name(name)
        if parts is None:
            continue
        unit = _resolve_unit(name, parts, fragments, dropins, by_path, links, gaps, alias_target, aliases,
                             enablement_origins)
        if scope == 'user' and unit['account'] is not None:
            declared = unit['account']['user']
            unit['account'] = {'user': account, 'group': unit['account']['group'],
                               'manager': 'user', 'declared_user': declared}
            if declared is not None and declared != account:
                gaps.append(_gap('user_unit_declared_user', unit['fragment'] or name, str(declared)[:256]))
            unit['privileged_exec'] = False
        _expand_unit(unit, alias_target.get(name, name), manager_specifiers or {}, gaps, withheld)
        referenced.add(unit['fragment'])
        units.append(unit)
        unit_index[name] = unit

    for path in sorted(set(external) - referenced):
        gaps.append(_gap('outside_search_path', path))

    # A drop-in that applies to no resolved unit (or alias) name is never
    # silently dropped: report it so the result cannot claim full coverage.
    consumed: set[str] = set()
    for unit in units:
        for n in unit['names'] + [unit['name']]:
            nparts = parse_name(n)
            if nparts is not None:
                consumed.update(_dropin_dirs(nparts))
    for (dname, _), recs in sorted(dropins.items()):
        if dname not in consumed:
            for r in recs:
                gaps.append(_gap('unattached_dropin', r['path'], dname))

    triggers: list[dict[str, Any]] = []
    for unit in units:
        if unit['type'] not in ('timer', 'socket', 'path') or unit['template'] or unit['state'] == 'masked':
            continue
        section = {'timer': 'Timer', 'socket': 'Socket', 'path': 'Path'}[unit['type']]
        explicit = unit['config'].get(section, {}).get('Unit')
        stem = unit['name'].rsplit('.', 1)[0]
        target = explicit or f'{stem}.service'
        tgt = unit_index.get(target)
        if tgt is None and parse_name(target):
            tparts = parse_name(target)
            if tparts and tparts['instance'] and tparts['template_name'] in unit_index:
                tgt = unit_index[tparts['template_name']]
        rel = {
            'trigger': unit['name'], 'type': unit['type'], 'unit': target,
            'explicit': bool(explicit), 'unit_present': bool(tgt and tgt['fragment']),
            'unit_state': tgt['state'] if tgt else 'missing',
        }
        if unit['type'] == 'timer':
            t = unit['config'].get('Timer', {})
            rel['schedule'] = {k: t[k] for k in sorted(t) if k.startswith('On') and t[k]}
        triggers.append(rel)
        if not rel['unit_present'] or rel['unit_state'] == 'masked':
            gaps.append(_gap('trigger_target_missing' if not rel['unit_present'] else 'trigger_target_masked',
                             unit['fragment'] or '', target))
        unit['triggers_unit'] = target

    gaps.sort(key=lambda g: (g['code'], g['path'], g['detail']))
    body = {'contract_version': CONTRACT_VERSION, 'units': units, 'triggers': triggers, 'gaps': gaps}
    if version_state != 'not_supplied':
        # Only present when supplied, so results without a version keep their digest.
        body['systemd_version'] = version
    if scope == 'user':
        body = {**body, 'scope': 'user', 'account': account,
                'search_paths': [{'path': root, 'origin': origin} for root, origin in search_paths]}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {
        **body,
        'complete': not gaps,
        'runtime_state': 'not_collected',
        'limitations': _limitations(scope, version_state),
        'digest': digest,
    }


_HEX = frozenset('0123456789abcdefABCDEF')


def _unescape(value: str) -> str | None:
    """Undo systemd unit-name escaping (``-`` is ``/``, ``\\xNN`` is a byte); None if invalid."""
    out: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == '-':
            out.append('/')
            i += 1
        elif c == '\\':
            hx = value[i + 2:i + 4]
            if value[i + 1:i + 2] != 'x' or len(hx) != 2 or not set(hx) <= _HEX:
                return None
            code = int(hx, 16)
            if code == 0:
                return None
            out.append(chr(code))
            i += 4
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def name_specifiers(name: Any) -> dict[str, str] | None:
    """Return the unit-name specifiers of ``systemd.unit(5)`` for one unit name.

    Covers ``%n %N %p %P %i %I %j %J %f``. A specifier whose escaped text cannot
    be unescaped exactly is omitted, so callers report it rather than guess.
    Returns None for an invalid or template (instance-less) name.
    """
    parts = parse_name(name)
    if parts is None or parts['template']:
        return None
    full = parts['name']
    stem = full[:-(len(parts['type']) + 1)]
    prefix = parts['prefix']
    instance = parts['instance'] or ''
    last = prefix.rsplit('-', 1)[-1] if '-' in prefix else prefix
    spec = {'n': full, 'N': stem, 'p': prefix, 'i': instance, 'j': last}
    for upper, raw in (('P', prefix), ('I', instance), ('J', last)):
        un = _unescape(raw)
        if un is not None:
            spec[upper] = un
    path_source = instance if parts['instance'] else prefix
    if path_source == '-':
        spec['f'] = '/'
    else:
        un = _unescape(path_source)
        if un is not None:
            spec['f'] = un if un.startswith('/') else '/' + un
    return spec


def expand_specifiers(value: str, table: dict[str, str]) -> tuple[str, list[str]]:
    """Expand ``%X`` specifiers from ``table``; ``%%`` is a literal percent.

    Returns ``(expanded, missing)``. When any specifier is not in ``table`` (or a
    trailing ``%`` has no letter), ``missing`` lists them and the raw value is
    returned unchanged: a partially expanded command is never presented.
    """
    out: list[str] = []
    missing: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c != '%':
            out.append(c)
            i += 1
            continue
        letter = value[i + 1:i + 2]
        if letter == '%':
            out.append('%')
        elif letter and letter in table:
            out.append(table[letter])
        else:
            missing.append(letter or '%')
        i += 2
    if missing:
        return value, sorted(set(missing))
    return ''.join(out), []


def _limitations(scope: str, version_state: str) -> list[str]:
    if scope == 'user':
        out = list(USER_LIMITATIONS)
    elif version_state == 'not_supplied':
        out = list(LIMITATIONS)
    else:
        # The User=-versus-manager ambiguity is settled by the supplied version.
        out = [item for item in LIMITATIONS if not item.startswith('System %u/%U/%h/%s')]
    if version_state == 'applied':
        out.append(VERSION_LIMITATION_APPLIED)
    elif version_state == 'invalid':
        out.append(VERSION_LIMITATION_INVALID)
    return out


def _expand_unit(unit: dict[str, Any], id_name: str, manager: dict[str, str],
                 gaps: list[dict[str, str]], withheld: frozenset[str] = frozenset()) -> None:
    """Attach ``expanded`` and ``specifiers`` to one resolved unit record.

    ``withheld`` specifiers are left unexpanded (and reported) because the
    supplied systemd release did not give them their current meaning.
    """
    names = name_specifiers(id_name) if not unit['template'] else None
    if names is None:
        unit['expanded'] = None
        unit['specifiers'] = 'not_applicable'
        return
    table = {k: v for k, v in {**manager, **names}.items() if k not in withheld}
    expanded: dict[str, dict[str, Any]] = {}
    missing: set[str] = set()
    used = False
    for section in sorted(unit['config']):
        for key in sorted(unit['config'][section]):
            if key not in EXPAND_KEYS:
                continue
            raw = unit['config'][section][key]
            values = raw if isinstance(raw, list) else [raw]
            new = []
            for v in values:
                if not isinstance(v, str):
                    new.append(v)
                    continue
                used = used or '%' in v
                e, m = expand_specifiers(v, table)
                missing.update(m)
                new.append(e)
            expanded.setdefault(section, {})[key] = new if isinstance(raw, list) else new[0]
    unit['expanded'] = expanded
    if missing:
        unit['specifiers'] = 'partial'
        unit['incomplete'] = True
        gaps.append(_gap('unexpanded_specifier', unit['fragment'] or unit['name'],
                         ','.join('%' + m for m in sorted(missing))))
    else:
        unit['specifiers'] = 'expanded' if used else 'none'


def _effective_path(rec: dict[str, Any] | None) -> str | None:
    if rec is None:
        return None
    return rec['target'] if rec['kind'] == 'symlink' else rec['path']


def _alias_map(fragments, by_path) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Map each effective alias name to its canonical name, and canonical to aliases.

    An alias is effective only when its winning fragment is a symlink to an
    observed file whose base name is a different valid, non-template unit name.
    """
    alias_target: dict[str, str] = {}
    aliases: dict[str, set[str]] = {}
    for name, recs in fragments.items():
        winner = min(recs, key=lambda r: r['rank'])
        if winner['kind'] != 'symlink' or winner['target'] == '/dev/null':
            continue
        linked = by_path.get(winner['target'])
        if linked is None or linked.get('kind') != 'file':
            continue
        canonical = posixpath.basename(winner['target'])
        parts = parse_name(name)
        cparts = parse_name(canonical)
        if (canonical == name or parts is None or cparts is None or cparts['type'] != parts['type']
                or parts['instance'] or cparts['instance']
                or canonical == parts['template_name']):
            continue
        alias_target[name] = canonical
        aliases.setdefault(canonical, set()).add(name)
    return alias_target, aliases


def _resolve_unit(name, parts, fragments, dropins, by_path, links, gaps,
                  alias_target=None, aliases=None, enablement_origins=_ENABLEMENT_ORIGINS) -> dict[str, Any]:
    alias_target = alias_target or {}
    aliases = aliases or {}
    canonical = alias_target.get(name, name)
    all_names = [canonical] + sorted(aliases.get(canonical, set()) - {canonical})
    cands = sorted(fragments.get(name, []), key=lambda r: r['rank'])
    fragment_parts = parts
    if not cands and parts['instance']:
        cands = sorted(fragments.get(parts['template_name'], []), key=lambda r: r['rank'])
        fragment_parts = parse_name(parts['template_name']) or parts
    winner = cands[0] if cands else None
    shadowed = [{'path': c['path'], 'origin': c['origin']} for c in cands[1:]]
    state = None
    incomplete = False
    alias_of = None
    text = ''
    fragment_path = None
    origin = 'unknown'
    if winner is not None:
        origin = winner['origin']
        fragment_path = winner['path']
        if winner['kind'] == 'symlink':
            target = winner['target']
            if target == '/dev/null':
                state = 'masked'
            else:
                tbase = posixpath.basename(target)
                linked = by_path.get(target)
                if linked is not None and linked.get('kind') == 'file':
                    if tbase != name and tbase != fragment_parts['name']:
                        alias_of = tbase
                    text = linked.get('text', '')
                    incomplete = bool(linked.get('incomplete'))
                    fragment_path = target
                    origin = linked['origin']
                else:
                    gaps.append(_gap('unresolved_link', winner['path'], target))
                    incomplete = True
        else:
            text = winner.get('text', '')
            incomplete = bool(winner.get('incomplete'))
            if text.strip() == '' and not incomplete:
                state = 'masked'

    if canonical != name and state != 'masked':
        canon_cands = fragments.get(canonical, [])
        canon_winner = min(canon_cands, key=lambda r: r['rank']) if canon_cands else None
        if canon_winner is not None and _effective_path(canon_winner) != fragment_path:
            gaps.append(_gap('alias_target_shadowed', winner['path'] if winner else name,
                             _effective_path(canon_winner) or ''))
            incomplete = True

    layers = []
    problems: list[str] = []
    if text and state != 'masked':
        sec, probs = parse_unit_text(text)
        layers.append(sec)
        problems.extend(probs)

    applied: list[dict[str, str]] = []
    if state != 'masked':
        spec: dict[str, tuple[int, int, int]] = {}
        scopes: dict[str, str] = {}
        for ni, n in enumerate(all_names):
            nparts = parse_name(n)
            if nparts is None:
                continue
            for pos, d in enumerate(_dropin_dirs(nparts)):
                scope = _scope(d, nparts)
                if scope == 'unit' and n != name:
                    scope = 'alias'
                key = (_SCOPE_ORDER[scope], ni, pos)
                if d not in spec or key < spec[d]:
                    spec[d] = key
                    scopes[d] = scope
        chosen: dict[str, dict[str, Any]] = {}
        for (dname, fname), recs in dropins.items():
            if dname not in spec:
                continue
            for r in recs:
                key = (r['rank'], spec[dname])
                cur = chosen.get(fname)
                if cur is None or key < cur['_key']:
                    chosen[fname] = {**r, '_key': key, '_dir': dname}
        for fname in sorted(chosen):
            r = chosen[fname]
            if r.get('incomplete'):
                incomplete = True
            sec, probs = parse_unit_text(r.get('text', ''))
            layers.append(sec)
            problems.extend(probs)
            applied.append({'path': r['path'], 'origin': r['origin'], 'scope': scopes[r['_dir']]})
    config = _merge(layers) if state != 'masked' else {}
    if problems:
        incomplete = True
        gaps.append(_gap('malformed_configuration', fragment_path or name,
                         ','.join(sorted(set(problems)))))

    enabled_by: list[dict[str, str]] = []
    static_deps: list[dict[str, str]] = []
    for link in links:
        if link['name'] != name:
            continue
        entry = {'owner': link['owner'], 'dependency': link['dependency'], 'path': link['path'],
                 'origin': link['origin']}
        tbase = posixpath.basename(link['target'])
        if link['target'] == '/dev/null':
            entry['problem'] = 'masked_link'
        elif tbase not in (name, parts['template_name'], canonical):
            entry['problem'] = 'foreign_target'
            gaps.append(_gap('foreign_link_target', link['path'], link['target']))
        (enabled_by if link['origin'] in enablement_origins else static_deps).append(entry)
    if len(enabled_by) > MAX_LINKS_PER_UNIT:
        gaps.append(_gap('link_cap', name, str(len(enabled_by))))
        enabled_by = enabled_by[:MAX_LINKS_PER_UNIT]
    enabled_by.sort(key=lambda e: e['path'])
    static_deps.sort(key=lambda e: e['path'])

    if state is None:
        if winner is None:
            state = 'not_found'
            if enabled_by:
                gaps.append(_gap('dangling_enablement', enabled_by[0]['path'], name))
        elif incomplete:
            state = 'unknown'
        elif origin in ('transient', 'generated'):
            state = origin
        elif any('problem' not in e for e in enabled_by) or alias_of:
            state = 'enabled'
        elif config.get('Install') and any(config['Install'].get(k) for k in ('WantedBy', 'RequiredBy', 'Alias')):
            state = 'disabled'
        else:
            state = 'static'

    vendor_present = any(c['origin'] in ('vendor', 'local') for c in cands)
    override_origins = sorted({a['origin'] for a in applied if a['origin'] not in ('vendor', 'local')})
    if origin in ('generated', 'transient', 'runtime', 'unknown', 'linked'):
        classification = origin if origin != 'linked' else 'custom'
    elif origin in ('vendor', 'local') and not override_origins:
        classification = 'vendor_location'
    elif vendor_present:
        classification = 'vendor_overridden'
    else:
        classification = 'custom'

    svc = config.get('Service', {})
    return {
        'name': name, 'type': parts['type'], 'template': parts['template'],
        'instance': parts['instance'], 'state': state, 'origin': origin,
        'classification': classification, 'package_verified': False,
        'fragment': fragment_path, 'alias_of': alias_of, 'names': sorted(all_names),
        'shadowed': shadowed,
        'dropins': applied, 'override_origins': override_origins,
        'enabled_by': enabled_by, 'static_dependencies': static_deps,
        'exec': {k: svc[k] for k in sorted(svc) if k.startswith('Exec') and svc[k]},
        'account': {'user': svc.get('User') or ('dynamic' if svc.get('DynamicUser') in ('yes', 'true', '1') else None),
                    'group': svc.get('Group')} if parts['type'] == 'service' else None,
        'privileged_exec': any(_privileged(v) for k, vs in svc.items() if k.startswith('Exec') and vs for v in vs),
        'config': config, 'incomplete': incomplete,
    }


def _privileged(value: str) -> bool:
    """True when an Exec line's prefix ('+' or '!'/'!!') bypasses User=/sandboxing."""
    m = re.match(r'^[-@:+!|]*', value)
    prefix = m.group(0) if m else ''
    return '+' in prefix or '!' in prefix


_SCOPE_ORDER = {'unit': 0, 'alias': 0, 'template': 1, 'prefix': 2, 'type': 3}


def _scope(dname: str, parts: dict[str, Any]) -> str:
    if dname == parts['name'] + '.d':
        return 'unit'
    if parts['template_name'] and dname == parts['template_name'] + '.d':
        return 'template'
    if dname == parts['type'] + '.d':
        return 'type'
    return 'prefix'
