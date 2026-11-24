"""Pure networkd-dispatcher script contract (roadmap F slice, #1126).

Takes captured, read-only metadata for networkd-dispatcher's script
directories and the text of ``/etc/default/networkd-dispatcher`` and says which
scripts the daemon runs as root, for which systemd-networkd link state, in what
order, and why the others are not run. It never reads a script's contents.

The rules follow networkd-dispatcher 2.2.4 as packaged by Debian and Ubuntu
(``2.2.4-1.2ubuntu1``): ``scripts_in_path``, ``check_perms``,
``run_hooks_for_state``, ``handle_state`` and ``parse_args`` in
``networkd-dispatcher``, the shipped ``networkd-dispatcher.service`` and the
Debian patches that move its ``EnvironmentFile`` to
``/etc/default/networkd-dispatcher`` and enable ``--run-startup-triggers``:

* The script directories are ``/etc/networkd-dispatcher`` then
  ``/usr/lib/networkd-dispatcher`` unless ``-S``/``--script-dir`` gives another
  colon-separated list. Arguments come from ``networkd_dispatcher_args`` in
  ``/etc/default/networkd-dispatcher`` (``$networkd_dispatcher_args`` in
  ``ExecStart`` is split on whitespace). A missing file means no arguments.
* Scripts run only for the administrative states ``configured``,
  ``configuring``, ``failed``, ``pending``, ``unmanaged``, ``linger`` and
  ``initialized`` and the operational states ``carrier``, ``degraded``,
  ``degraded-carrier``, ``dormant``, ``enslaved``, ``missing``, ``no-carrier``,
  ``off`` and ``routable``, from a subdirectory named ``<state>.d``.
* For one state, the entry names of every script directory's ``<state>.d`` are
  unioned and sorted by code point. There is no name filter: hidden and backup
  names are run too. For each name the directories are tried in order, and the
  first one where all of the following hold is used:

  - the path is a regular file after following symlinks (``os.path.isfile``);
  - the ``<state>.d`` directory itself, not following a symlink, is mode
    exactly ``0755`` and owned by uid 0 and gid 0;
  - the fully resolved file is mode exactly ``0755`` (set-ID and sticky bits
    included in the comparison) and owned by uid 0 and gid 0.

  A failing entry does not mask a later directory's file with the same name.
* A selected script is executed directly with ``argv`` = ``[path]`` (the
  unresolved path, no shell) by the root daemon, with ``IFACE``, ``STATE``,
  ``ADDR``, ``IP_ADDRS``, ``IP6_ADDRS``, ``ESSID``, ``AdministrativeState``,
  ``OperationalState`` and ``json`` added to the daemon's environment. ``ESSID``
  and ``json`` carry the wireless network name, which a nearby transmitter
  chooses.
* With ``--run-startup-triggers`` (the Debian/Ubuntu default file sets it) every
  interface's current states are dispatched once when the service starts.
* The unit starts only when ``/etc/networkd-dispatcher/*/*`` or
  ``/usr/lib/networkd-dispatcher/*/*`` matches (``ConditionPathExistsGlob``).

It performs no I/O, never runs a command and never authorizes a response
action. Unobserved directories, metadata or arguments and over-limit input are
explicit blocking gaps and are never reported as covered.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE_VERSION = '2.2.4 (Debian/Ubuntu 2.2.4-1.2ubuntu1)'
DEFAULTS_PATH = '/etc/default/networkd-dispatcher'
DEFAULT_SCRIPT_DIRS = ('/etc/networkd-dispatcher', '/usr/lib/networkd-dispatcher')
ADMIN_STATES = ('configured', 'configuring', 'failed', 'pending', 'unmanaged', 'linger', 'initialized')
OPER_STATES = ('carrier', 'degraded', 'degraded-carrier', 'dormant', 'enslaved', 'missing', 'no-carrier', 'off',
               'routable')
STATE_KIND = {**{state: 'administrative' for state in ADMIN_STATES}, **{state: 'operational' for state in OPER_STATES}}
ENVIRONMENT = ('ADDR', 'ESSID', 'IP_ADDRS', 'IP6_ADDRS', 'IFACE', 'STATE', 'AdministrativeState',
               'OperationalState', 'json')
RADIO_SUPPLIED = ('ESSID', 'json')
MAX_FILES = 1024
MAX_DIRECTORIES = 16
MAX_PATH = 4096
MAX_DEFAULTS = 65536
MAX_GAPS = 64
FILE_TYPES = ('file', 'symlink', 'directory', 'other')
BLOCKING = frozenset({
    'input_malformed', 'too_many_files', 'duplicate_path', 'metadata_missing', 'directory_not_observed',
    'directory_unreadable', 'defaults_not_observed', 'defaults_unreadable', 'arguments_unparsed',
    'too_many_directories', 'gaps_truncated',
})
UNOBSERVED = (
    'Script contents, interpreters and anything a script runs are not read.',
    'Whether networkd-dispatcher is installed, enabled and running, and whether systemd-networkd manages any link, '
    'is not observed.',
    'Drop-ins or overrides of networkd-dispatcher.service that change ExecStart, EnvironmentFile or the user are '
    'not observed.',
    'Which link states occur, and the daemon\'s own inherited environment, are not observed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'runs': 'networkd-dispatcher runs this script as root when a link enters this state.',
    'overridden': 'A script with the same name in an earlier script directory runs instead.',
    'not_regular': 'Not a regular file after following symlinks, so it is skipped.',
    'dangling_symlink': 'The symlink target does not exist, so the entry is skipped.',
    'directory_permissions': 'Skipped: the state directory is not mode 0755 owned by root:root (a symlinked '
                             'directory always fails this check).',
    'file_permissions': 'Skipped: the resolved file is not exactly mode 0755 owned by root:root.',
    'unknown_state': 'networkd-dispatcher never dispatches a state with this directory name.',
    'outside_script_directories': 'The path is not in a <state>.d directory of a configured script directory.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_ASSIGN = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=(.*)')
_LONG = ('--script-dir', '--run-startup-triggers', '--verbose', '--quiet', '--help')


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


def _int(value: Any, upper: int | None = None) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0 and (upper is None or value <= upper)


def _valid_path(path: Any) -> bool:
    return (isinstance(path, str) and 1 < len(path) <= MAX_PATH and path.startswith('/')
            and not _CONTROL.search(path) and posixpath.normpath(path) == path and not path.startswith('//'))


def _stat(meta: Any, *, allow_symlink: bool = False) -> dict[str, Any] | None:
    """Validate one stat-like mapping (``type``, ``mode``, ``uid``, ``gid``)."""
    types = FILE_TYPES if allow_symlink else ('file', 'directory', 'other')
    if not isinstance(meta, dict) or meta.get('type') not in types:
        return None
    if not (_int(meta.get('mode'), 0o7777) and _int(meta.get('uid')) and _int(meta.get('gid'))):
        return None
    return {'type': meta['type'], 'mode': meta['mode'], 'uid': meta['uid'], 'gid': meta['gid']}


def _root_0755(stat: dict[str, Any]) -> bool:
    """``check_perms(path, 0o755, 0, 0)``: exact permission bits and root:root ownership."""
    return stat['mode'] == 0o755 and stat['uid'] == 0 and stat['gid'] == 0


def _env_value(raw: str) -> str | None:
    """Return the value of one EnvironmentFile assignment, or ``None`` when it is not safely parseable here."""
    value = raw.strip()
    if '\\' in value or '$' in value:
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        inner = value[1:-1]
        return None if '"' in inner or "'" in inner else inner
    return None if '"' in value or "'" in value else value


def parse_defaults(text: str) -> tuple[str | None, bool]:
    """Return ``(networkd_dispatcher_args, parsed)`` from ``/etc/default/networkd-dispatcher`` text.

    Only plain ``NAME=value`` lines with a whole-value quote pair or no quotes, and no backslashes
    or ``$``, in the ``networkd_dispatcher_args`` value are accepted; anything else is reported as
    not parsed instead of guessed. The last assignment wins, as in systemd.
    """
    value: str | None = None
    for line in text.split('\n'):
        stripped = line.strip()
        if not stripped or stripped[0] in '#;':
            continue
        if stripped.endswith('\\'):
            return None, False
        match = _ASSIGN.fullmatch(stripped)
        if match is None:
            return None, False
        if match.group(1) == 'networkd_dispatcher_args':
            value = _env_value(match.group(2))
            if value is None:
                return None, False
    return value, True


def parse_arguments(words: list[str]) -> dict[str, Any] | None:
    """Apply the ``parse_args`` argparse definition. Returns ``None`` for anything argparse would reject or exit on."""
    script_dir: str | None = None
    triggers = False
    index = 0
    while index < len(words):
        word = words[index]
        index += 1
        if word.startswith('--'):
            name, has_value, value = word.partition('=')
            matches = [option for option in _LONG if option.startswith(name)] if len(name) > 2 else []
            if len(matches) != 1 or matches[0] == '--help':
                return None
            option = matches[0]
            if option == '--script-dir':
                if not has_value:
                    if index >= len(words) or words[index].startswith('-'):
                        return None
                    value = words[index]
                    index += 1
                script_dir = value
            elif has_value:
                return None
            elif option == '--run-startup-triggers':
                triggers = True
        elif word.startswith('-') and len(word) > 1:
            cluster = word[1:]
            while cluster:
                flag, cluster = cluster[0], cluster[1:]
                if flag == 'S':
                    if not cluster:
                        if index >= len(words) or words[index].startswith('-'):
                            return None
                        cluster = words[index]
                        index += 1
                    script_dir, cluster = cluster, ''
                elif flag == 'T':
                    triggers = True
                elif flag not in 'vq':
                    return None
        else:
            return None
    return {'script_dir': script_dir, 'startup_triggers': triggers}


def _script_dirs(defaults: Any, gaps: list[dict[str, Any]]) -> tuple[list[str] | None, str, bool | None]:
    """Resolve the script directories and startup-trigger flag from the defaults-file observation."""
    state = defaults.get('state') if isinstance(defaults, dict) else None
    if defaults is None:
        _gap(gaps, 'defaults_not_observed', DEFAULTS_PATH, 'The service arguments file was not observed.')
        return list(DEFAULT_SCRIPT_DIRS), 'default_unconfirmed', None
    if state == 'absent':
        return list(DEFAULT_SCRIPT_DIRS), 'default', False
    if state == 'unreadable':
        _gap(gaps, 'defaults_unreadable', DEFAULTS_PATH, 'The service arguments file could not be read.')
        return list(DEFAULT_SCRIPT_DIRS), 'default_unconfirmed', None
    text = defaults.get('text') if state == 'present' else None
    if not isinstance(text, str) or len(text) > MAX_DEFAULTS or '\x00' in text:
        _gap(gaps, 'input_malformed', DEFAULTS_PATH, 'The service arguments observation is malformed or too large.')
        return list(DEFAULT_SCRIPT_DIRS), 'default_unconfirmed', None
    value, parsed = parse_defaults(text)
    # An unassigned variable expands to no arguments in ExecStart, like an empty assignment.
    options = parse_arguments((value or '').split()) if parsed else None
    if options is None:
        _gap(gaps, 'arguments_unparsed', DEFAULTS_PATH,
             'networkd_dispatcher_args could not be parsed exactly; the script directories are not confirmed.')
        return list(DEFAULT_SCRIPT_DIRS), 'default_unconfirmed', None
    if options['script_dir'] is None:
        return list(DEFAULT_SCRIPT_DIRS), 'default', options['startup_triggers']
    dirs: list[str] = []
    for component in options['script_dir'].split(':'):
        if not _valid_path(component):
            _gap(gaps, 'arguments_unparsed', DEFAULTS_PATH,
                 'A --script-dir component is empty, relative or not a normalized absolute path.')
            return list(DEFAULT_SCRIPT_DIRS), 'default_unconfirmed', None
        if component not in dirs:
            dirs.append(component)
    if len(dirs) > MAX_DIRECTORIES:
        _gap(gaps, 'too_many_directories', DEFAULTS_PATH, f'More than {MAX_DIRECTORIES} script directories.')
        dirs = dirs[:MAX_DIRECTORIES]
    return dirs, 'arguments', options['startup_triggers']


def _normalize(item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_path(item.get('path')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', detail='A file observation has no valid absolute path or type.')
        return None
    entry: dict[str, Any] = {'path': item['path'], 'type': item['type'], 'resolved': True, 'target': None}
    if item['type'] == 'symlink':
        if 'target' not in item:
            entry['resolved'] = False
        elif item['target'] is not None:
            entry['target'] = _stat(item['target'])
            entry['resolved'] = entry['target'] is not None
        if isinstance(item.get('link_target'), str) and 0 < len(item['link_target']) <= MAX_PATH:
            entry['link_target'] = item['link_target']
        return entry
    stat = _stat(item)
    if stat is None:
        entry['resolved'] = False
    else:
        entry['target'] = stat
    return entry


def _directory_states(directories: Any, gaps: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    states: dict[str, dict[str, Any]] = {}
    if directories is not None and not isinstance(directories, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='Directory observations must be a list.')
    for item in directories if isinstance(directories, (list, tuple)) else ():
        path = item.get('path') if isinstance(item, dict) else None
        state = item.get('state') if isinstance(item, dict) else None
        if not _valid_path(path) or state not in ('listed', 'absent', 'unreadable') or path in states:
            _gap(gaps, 'input_malformed', detail='A directory observation is malformed or repeated.')
            continue
        record: dict[str, Any] = {'state': state}
        if state == 'listed':
            record['lstat'] = _stat(item.get('lstat'), allow_symlink=True)
            subdirs = item.get('subdirectories')
            if subdirs is not None and not (isinstance(subdirs, (list, tuple)) and len(subdirs) <= MAX_FILES
                                            and all(isinstance(name, str) and name and '/' not in name
                                                    and name not in ('.', '..') for name in subdirs)):
                _gap(gaps, 'input_malformed', path, 'The subdirectory list is malformed.')
                subdirs = None
            record['subdirectories'] = list(subdirs) if subdirs is not None else None
        states[path] = record
    return states


def _record(entry: dict[str, Any], status: str, reason: str, **extra: Any) -> dict[str, Any]:
    record = {'path': entry['path'], 'type': entry['type'], 'status': status, 'reason_code': reason,
              'reason': REASONS[reason]}
    if entry.get('link_target') is not None:
        record['link_target'] = entry['link_target']
    record.update(extra)
    return record


def _qualifies(entry: dict[str, Any], directory: dict[str, Any] | None) -> tuple[str | None, str]:
    """Apply the per-entry checks of ``scripts_in_path``. Returns ``(status, reason)``; status ``None`` is undetermined."""
    if not entry['resolved']:
        return None, 'unresolved'
    target = entry['target']
    if target is None:
        return 'skipped', 'dangling_symlink'
    if target['type'] != 'file':
        return 'skipped', 'not_regular'
    lstat = directory.get('lstat') if directory else None
    if lstat is None:
        return None, 'unresolved'
    if lstat['type'] != 'directory' or not _root_0755(lstat):
        return 'skipped', 'directory_permissions'
    if not _root_0755(target):
        return 'skipped', 'file_permissions'
    return 'runs', 'runs'


def _service_condition(files: list[dict[str, Any]], dirs: dict[str, dict[str, Any]]) -> str:
    """Evaluate the unit's ``ConditionPathExistsGlob=|<base>/*/*`` triggers for the default bases."""
    for entry in files:
        for base in DEFAULT_SCRIPT_DIRS:
            if entry['path'].startswith(base + '/'):
                parts = entry['path'][len(base) + 1:].split('/')
                if len(parts) == 2 and not parts[0].startswith('.') and not parts[1].startswith('.'):
                    return 'met'
    for base in DEFAULT_SCRIPT_DIRS:
        observed = dirs.get(base)
        if observed is None or observed['state'] == 'unreadable':
            return 'not_determined'
        if observed['state'] == 'listed':
            if observed.get('subdirectories') is None:
                return 'not_determined'
            for name in observed['subdirectories']:
                child = dirs.get(posixpath.join(base, name))
                if not name.startswith('.') and (child is None or child['state'] == 'unreadable'):
                    return 'not_determined'
    return 'not_met'


def evaluate(files: Any, *, directories: Any = None, defaults: Any = None) -> dict[str, Any]:
    """Resolve which networkd-dispatcher scripts run, from supplied metadata.

    ``defaults`` observes ``/etc/default/networkd-dispatcher``: ``{'state': 'absent'}``,
    ``{'state': 'unreadable'}`` or ``{'state': 'present', 'text': str}``.

    ``directories`` is a list of ``{'path', 'state'}`` with state ``listed``, ``absent`` (does
    not exist after following symlinks) or ``unreadable``. It must cover each script directory
    and each of its ``<state>.d`` subdirectories. A listed script directory carries
    ``subdirectories`` (the names of its child directories after following symlinks); a listed
    ``<state>.d`` directory carries ``lstat`` (``type`` of ``directory``, ``symlink`` or ``other``,
    ``mode`` 0–0o7777, ``uid``, ``gid``) of the directory itself, not following a symlink. A
    ``<state>.d`` name missing from its script directory's ``subdirectories`` needs no entry.

    ``files`` lists every entry of the listed ``<state>.d`` directories: ``path`` (absolute,
    normalized), ``type`` (``file``, ``symlink``, ``directory`` or ``other``) and, for a
    non-symlink, ``mode``, ``uid`` and ``gid``. A symlink carries ``target``: the same stat fields
    for the fully resolved path, or ``None`` when it resolves to nothing, plus optional
    ``link_target`` text.
    """
    gaps: list[dict[str, Any]] = []
    script_dirs, dirs_source, triggers = _script_dirs(defaults, gaps)
    observed = _directory_states(directories, gaps)
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference_version': REFERENCE_VERSION,
        'script_directories': script_dirs, 'script_directories_source': dirs_source,
        'startup_triggers': triggers, 'service_condition': 'not_determined',
        'states': {state: {'kind': STATE_KIND[state], 'scripts': []} for state in ADMIN_STATES + OPER_STATES},
        'unknown_state_directories': [], 'files': [], 'user': 'root', 'environment': list(ENVIRONMENT),
        'radio_supplied_environment': list(RADIO_SUPPLIED), 'gaps': gaps, 'unobserved': list(UNOBSERVED),
        'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    if not isinstance(files, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='File observations must be a list.')
        files = ()
    if len(files) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'Only the first {MAX_FILES} file observations are assessed.')
        files = files[:MAX_FILES]

    for base in script_dirs:
        base_obs = observed.get(base)
        if base_obs is None:
            _gap(gaps, 'directory_not_observed', base, 'No listing result was supplied for this script directory.')
        elif base_obs['state'] == 'unreadable':
            _gap(gaps, 'directory_unreadable', base, 'The script directory exists but could not be listed.')
        elif base_obs['state'] == 'listed':
            for name in sorted(base_obs.get('subdirectories') or ()):
                state = name[:-2] if name.endswith('.d') else None
                if state not in STATE_KIND:
                    result['unknown_state_directories'].append(
                        {'path': posixpath.join(base, name), 'reason': REASONS['unknown_state']})
        if base_obs is not None and base_obs['state'] == 'absent':
            continue
        listed = base_obs.get('subdirectories') if base_obs is not None else None
        for state in STATE_KIND:
            path = posixpath.join(base, state + '.d')
            sub = observed.get(path)
            if sub is None and listed is not None and state + '.d' not in listed:
                continue  # the listing shows no such subdirectory
            if sub is None:
                _gap(gaps, 'directory_not_observed', path, 'No listing result was supplied for this state directory.')
            elif sub['state'] == 'unreadable':
                _gap(gaps, 'directory_unreadable', path, 'The state directory exists but could not be listed.')
            elif sub['state'] == 'listed' and sub.get('lstat') is None:
                _gap(gaps, 'metadata_missing', path, 'The state directory\'s own mode and ownership were not supplied.')

    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    by_state: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}  # state -> name -> base -> entry
    records: dict[str, dict[str, Any]] = {}
    for item in files:
        entry = _normalize(item, gaps)
        if entry is None:
            continue
        if entry['path'] in seen:
            _gap(gaps, 'duplicate_path', entry['path'], 'The path was supplied more than once; the first is used.')
            continue
        seen.add(entry['path'])
        entries.append(entry)
        parent, name = posixpath.split(entry['path'])
        base, sub = posixpath.split(parent)
        state = sub[:-2] if sub.endswith('.d') else None
        if base not in script_dirs:
            records[entry['path']] = _record(entry, 'never_run', 'outside_script_directories')
        elif state not in STATE_KIND:
            records[entry['path']] = _record(entry, 'never_run', 'unknown_state')
        else:
            if observed.get(parent, {}).get('state') != 'listed':
                _gap(gaps, 'input_malformed', entry['path'], 'A file was supplied for a directory not reported listed.')
            by_state.setdefault(state, {}).setdefault(name, {})[base] = entry

    def unlisted(base: str, state: str) -> bool:
        """True when this ``<state>.d`` may hold names that were not observed."""
        base_obs = observed.get(base)
        if base_obs is None or base_obs['state'] == 'unreadable':
            return True
        if base_obs['state'] == 'absent':
            return False
        sub = observed.get(posixpath.join(base, state + '.d'))
        if sub is None:
            listed = base_obs.get('subdirectories')
            return listed is None or state + '.d' in listed
        return sub['state'] == 'unreadable'

    result['service_condition'] = _service_condition(entries, observed)
    for state, names in by_state.items():
        order = 0
        for name in sorted(names):
            winner: dict[str, Any] | None = None
            undetermined = False
            for base in script_dirs:
                entry = names[name].get(base)
                if entry is None:
                    # scripts_in_path takes the first directory holding the name,
                    # so an unlisted higher-priority directory may shadow it.
                    if winner is None and unlisted(base, state):
                        undetermined = True
                    continue
                if winner is not None or undetermined:
                    status, reason = ('overridden', 'overridden') if winner is not None else (None, 'unresolved')
                    extra = {'overridden_by': winner['path']} if winner is not None else {}
                    records[entry['path']] = _record(entry, status or 'unresolved', reason, state=state, **extra)
                    continue
                status, reason = _qualifies(entry, observed.get(posixpath.join(base, state + '.d')))
                if status is None:
                    undetermined = True
                    _gap(gaps, 'metadata_missing', entry['path'],
                         'Required metadata for this entry or its state directory was not supplied.')
                    records[entry['path']] = _record(entry, 'unresolved', 'unresolved', state=state)
                    continue
                records[entry['path']] = _record(entry, status, reason, state=state)
                if status == 'runs':
                    winner = entry
                    result['states'][state]['scripts'].append(
                        {'order': order, 'name': name, 'path': entry['path'], 'argv': [entry['path']],
                         'user': 'root', 'shell': False})
                    order += 1
    result['files'] = [records[entry['path']] for entry in entries]
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
