"""Pure wg-quick hook contract (roadmap F slice, #1343).

Takes ``/etc/wireguard`` listing metadata and captured configuration text and
says which ``PreUp``, ``PostUp``, ``PreDown`` and ``PostDown`` commands
``wg-quick`` runs as root through bash ``eval``, for which WireGuard interface,
in which order, and whether an enabled ``wg-quick@NAME.service`` brings the
interface up at boot. It never runs anything.

Semantics come from wireguard-tools v1.0.20210914 (the version Debian 12 and
Ubuntu 24.04 ship) ``src/wg-quick/linux.bash`` and
``src/systemd/wg-quick@.service``, not from recollection:

* ``wg-quick@NAME.service`` is ``Type=oneshot`` with
  ``ExecStart=/usr/bin/wg-quick up %i`` and ``ExecStop=/usr/bin/wg-quick down
  %i``, ``WantedBy=multi-user.target``. It runs as root, so an enabled instance
  runs the up hooks at every boot and the down hooks at every shutdown or stop.
  ``wg-quick`` run by a non-root user re-executes itself through ``sudo``.
* An argument matching ``^[a-zA-Z0-9_=+.-]{1,15}$`` means
  ``/etc/wireguard/ARG.conf``. A file name must match
  ``(^|/)([a-zA-Z0-9_=+.-]{1,15})\\.conf$``, and the interface name is that
  stem. ``readlink -f`` follows symlinks before the file is read.
* ``parse_options`` reads every line with ``read -r`` (a final line without a
  newline included), cuts it at the first ``#`` anywhere on the line, splits the
  key at the first ``=`` (a line with no ``=`` has the whole text as both key and
  value) and trims C-locale whitespace from both. Matching is case-insensitive
  (``shopt -s nocasematch``). A key starting with ``[`` ends the current
  section, and ``[Interface]`` starts one. Repeated ``[Interface]`` sections
  accumulate. Inside one, each ``PreUp``/``PostUp``/``PreDown``/``PostDown``
  value is appended to its list. ``SaveConfig`` other than ``true``/``false``
  makes wg-quick exit before any hook runs.
* ``execute_hooks`` replaces every ``%i`` with the interface name and runs
  ``(eval "$hook")`` in a bash subshell under ``set -e -o pipefail``,
  ``extglob`` and ``LC_ALL=C``. Each value is bash source text, not one
  command. A failing hook makes wg-quick exit: later hooks do not run, and on
  ``up`` the interface is deleted again.
* ``up`` runs ``PreUp`` before the interface is created and ``PostUp`` after
  addresses, MTU, DNS and routes are set. ``down`` runs ``PreDown`` first, then
  (with ``SaveConfig = true``) rewrites the file from the current interface
  state and the parsed hook values, removes the interface and runs ``PostDown``.

It performs no I/O and never authorizes a response action. Unobserved family,
installation state, listing or file text, NUL bytes, malformed or over-limit
input and enabled instances it cannot resolve are blocking gaps.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'wireguard-tools': 'wireguard-tools v1.0.20210914 src/wg-quick/linux.bash, src/systemd/wg-quick@.service',
}
RUNS_AS = 'root'
CONFIG_DIR = '/etc/wireguard'
SHELL = ('/bin/bash', 'eval in a subshell', 'set -e -o pipefail', 'LC_ALL=C')
UNIT = 'wg-quick@NAME.service'
PHASES = ('PreUp', 'PostUp', 'PreDown', 'PostDown')
EVENTS = {
    'PreUp': 'wg-quick up, before the interface is created',
    'PostUp': 'wg-quick up, after addresses, MTU, DNS and routes are set (only if all earlier steps succeed)',
    'PreDown': 'wg-quick down, before the interface is removed',
    'PostDown': 'wg-quick down, after the interface is removed',
}
SCHEDULE = ('an enabled wg-quick@NAME.service runs "wg-quick up NAME" as root at boot and "wg-quick down NAME" '
            'when it stops or the system shuts down',
            'wg-quick up or down run by an administrator, re-executed through sudo when not root')
APPLICABLE_FAMILIES = frozenset({'debian', 'rpm'})
DIRECTORY_STATES = ('listed', 'absent', 'unreadable')
INTERFACE_NAME = re.compile(r'[a-zA-Z0-9_=+.-]{1,15}')
CONF_NAME = re.compile(r'([a-zA-Z0-9_=+.-]{1,15})\.conf')
MAX_ENTRIES = 512
MAX_TEXT = 256 * 1024
MAX_LINES = 8192
MAX_GAPS = 64
BLOCKING = frozenset({
    'input_malformed', 'family_not_observed', 'family_unsupported', 'implementation_not_observed',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'too_many_entries',
    'file_not_read', 'file_unreadable', 'nul_byte', 'file_too_large', 'instance_unresolved', 'gaps_truncated',
})
UNOBSERVED = (
    'What a hook command does is not assessed.',
    'Whether "wg setconf" accepts the rest of the file is not modeled; when it fails, PreUp has already run '
    'and PostUp does not run, so PostUp may be over-reported.',
    'wg-quick run by hand with a configuration path outside /etc/wireguard, a locally modified wg-quick, '
    'a systemd drop-in for wg-quick@.service and the macOS/BSD scripts are not modeled.',
    'File ownership and mode are not assessed, so a hook file writable by a non-root account is not reported.',
)
NOT_A_VERDICT = 'Configuration text only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'interface': 'wg-quick up/down NAME reads this file and runs its [Interface] hooks as root.',
    'name_invalid': 'The name is not an interface name of 1-15 characters [a-zA-Z0-9_=+.-] followed by .conf, so '
                    'wg-quick refuses it.',
    'not_conf': 'Not a .conf file, so wg-quick does not read it as an interface configuration.',
    'directory': 'Directories are not configuration files.',
    'not_plain_file': 'Not a regular file.',
    'config_error': 'A SaveConfig value is neither true nor false, so wg-quick exits before running any hook.',
    'unresolved': 'The file text was not observed, so its hooks are not determined.',
}
_TRIM = ' \t\n\v\f\r'
# nocasematch under LC_ALL=C folds ASCII letters only.
_ASCII_FOLD = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')


def _fold(text: str) -> str:
    return text.translate(_ASCII_FOLD)


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


def _lines(text: str) -> list[str]:
    """``while read -r line || [[ -n $line ]]``: newline-separated, a non-empty final fragment kept."""
    parts = text.split('\n')
    if parts and parts[-1] == '':
        parts.pop()
    return parts


def parse(text: str) -> dict[str, Any]:
    """Reproduce ``parse_options`` for the hook and SaveConfig keys of one configuration text."""
    hooks: dict[str, list[dict[str, Any]]] = {phase: [] for phase in PHASES}
    misplaced: list[dict[str, Any]] = []
    folded = {phase.lower(): phase for phase in PHASES}
    in_interface = False
    save_config = False
    for number, line in enumerate(_lines(text), start=1):
        # read -r with the default IFS strips leading/trailing space, tab and newline; the later trims cover it.
        stripped = line.split('#', 1)[0]
        key, _, value = stripped.partition('=')
        if '=' not in stripped:
            value = stripped
        key = key.strip(_TRIM)
        value = value.strip(_TRIM)
        if key.startswith('['):
            in_interface = False
        if _fold(key) == '[interface]':
            in_interface = True
        lowered = _fold(key)
        if lowered in folded:
            entry = {'line': number, 'value': value}
            if in_interface:
                hooks[folded[lowered]].append(entry)
            else:
                misplaced.append(dict(entry, key=folded[lowered]))
        elif lowered == 'saveconfig' and in_interface:
            if _fold(value) == 'true':
                save_config = True
            elif _fold(value) == 'false':
                save_config = False
            else:
                return {'error': {'line': number, 'value': value}, 'hooks': {p: [] for p in PHASES},
                        'misplaced': misplaced, 'save_config': save_config}
    return {'error': None, 'hooks': hooks, 'misplaced': misplaced, 'save_config': save_config}


def _hook(phase: str, index: int, entry: dict[str, Any], interface: str) -> dict[str, Any]:
    command = entry['value'].replace('%i', interface)
    return {'phase': phase, 'order': index, 'line': entry['line'], 'command': command,
            'sha256': hashlib.sha256(command.encode('utf-8', 'surrogateescape')).hexdigest(),
            'runs_on': EVENTS[phase]}


def _text(entry: dict[str, Any], path: str, gaps: list[dict[str, Any]]) -> str | None:
    text = entry.get('text')
    if 'text' not in entry:
        _gap(gaps, 'file_not_read', path)
        return None
    if text is None:
        _gap(gaps, 'file_unreadable', path)
        return None
    if isinstance(text, bytes):
        text = text.decode('utf-8', 'surrogateescape')
    if not isinstance(text, str):
        _gap(gaps, 'input_malformed', path, 'File text is not a string.')
        return None
    if len(text) > MAX_TEXT or text.count('\n') > MAX_LINES:
        _gap(gaps, 'file_too_large', path)
        return None
    if '\0' in text:
        _gap(gaps, 'nul_byte', path, 'bash read drops NUL bytes, so the text wg-quick parses is not certain.')
        return None
    return text


def _config(entry: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    name = entry['name']
    path = f'{CONFIG_DIR}/{name}'
    out: dict[str, Any] = {'name': name, 'path': path, 'interface': None, 'outcome': None, 'hooks': [],
                           'misplaced_hooks': [], 'save_config': None}
    kind = entry.get('type')
    if kind not in ('file', 'symlink', 'directory', 'other'):
        _gap(gaps, 'input_malformed', path, 'Unknown entry type.')
        out['outcome'] = 'unresolved'
    elif kind == 'directory':
        out['outcome'] = 'directory'
    elif kind == 'other':
        out['outcome'] = 'not_plain_file'
    elif not name.endswith('.conf'):
        out['outcome'] = 'not_conf'
    elif not CONF_NAME.fullmatch(name):
        out['outcome'] = 'name_invalid'
    else:
        out['interface'] = name[:-len('.conf')]
        text = _text(entry, path, gaps)
        if text is None:
            out['outcome'] = 'unresolved'
        else:
            parsed = parse(text)
            out['misplaced_hooks'] = parsed['misplaced']
            if parsed['error'] is not None:
                out['outcome'] = 'config_error'
                out['error_line'] = parsed['error']['line']
            else:
                out['outcome'] = 'interface'
                out['save_config'] = parsed['save_config']
                out['hooks'] = [_hook(phase, i, item, out['interface'])
                                for phase in PHASES for i, item in enumerate(parsed['hooks'][phase], start=1)]
    out['reason'] = REASONS[out['outcome']]
    return out


def assess(directory: Any = None, *, family: Any = None, wireguard_tools_installed: Any = None,
           enabled_instances: Any = None) -> dict[str, Any]:
    """Resolve which wg-quick hook commands run as root from captured ``/etc/wireguard`` metadata and text.

    ``directory`` is ``{'state': 'listed', 'truncated': bool, 'entries': [{'name', 'type':
    'file'|'symlink'|'directory'|'other', 'text'}]}`` or a ``state`` of ``absent`` or ``unreadable``. A
    symlink's ``text`` is the followed target's text. ``text`` is ``None`` when the file could not be read and
    absent when it was not collected. ``enabled_instances`` lists the instance names of enabled
    ``wg-quick@NAME.service`` units, or is ``None`` when enablement was not observed.
    """
    gaps: list[dict[str, Any]] = []
    configs: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'runs_as': RUNS_AS,
        'shell': SHELL, 'unit': UNIT, 'schedule': SCHEDULE, 'stops_on_failure': True,
        'applicability': 'unknown', 'directory': CONFIG_DIR, 'state': 'not_observed', 'configs': configs,
        'boot_hooks': [], 'enabled_instances': None, 'gaps': gaps, 'origin': 'not_assessed',
        'not_a_verdict': NOT_A_VERDICT, 'unobserved': UNOBSERVED,
    }
    if family is None:
        _gap(gaps, 'family_not_observed')
    elif family not in APPLICABLE_FAMILIES:
        _gap(gaps, 'family_unsupported')
    if wireguard_tools_installed is False:
        result['applicability'] = 'not_applicable'
    elif wireguard_tools_installed is not True:
        _gap(gaps, 'implementation_not_observed', None, 'Whether wireguard-tools (wg-quick) is installed is unknown.')
    elif family in APPLICABLE_FAMILIES:
        result['applicability'] = 'applicable'
    _listing(directory, configs, gaps, result)
    _boot(enabled_instances, configs, gaps, result)
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result


def _listing(directory: Any, configs: list[dict[str, Any]], gaps: list[dict[str, Any]],
             result: dict[str, Any]) -> None:
    if directory is None:
        _gap(gaps, 'directory_not_observed', CONFIG_DIR)
        return
    if not isinstance(directory, dict) or directory.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', CONFIG_DIR, 'Malformed configuration directory metadata.')
        return
    result['state'] = directory['state']
    if directory['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', CONFIG_DIR)
    if directory['state'] != 'listed':
        return
    if directory.get('truncated'):
        _gap(gaps, 'listing_incomplete', CONFIG_DIR)
    entries = directory.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries' if isinstance(entries, list) else 'input_malformed', CONFIG_DIR)
        return
    seen: set[str] = set()
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or '/' in name or name in seen or name in ('.', '..') \
                or '\0' in name:
            _gap(gaps, 'input_malformed', CONFIG_DIR, 'An entry has a missing, invalid or duplicate name.')
            continue
        seen.add(name)
        configs.append(_config(entry, gaps))
    configs.sort(key=lambda c: c['name'])


def _boot(enabled: Any, configs: list[dict[str, Any]], gaps: list[dict[str, Any]], result: dict[str, Any]) -> None:
    by_interface = {c['interface']: c for c in configs if c['interface'] is not None}
    if enabled is None:
        _gap(gaps, 'enablement_not_observed', None,
             'Enabled wg-quick@ instances were not observed, so which interfaces come up at boot is unknown.')
        for config in configs:
            if config['interface'] is not None:
                config['at_boot'] = 'unknown'
        return
    if not isinstance(enabled, (list, tuple, set, frozenset)) or not all(isinstance(i, str) for i in enabled):
        _gap(gaps, 'input_malformed', None, 'Malformed enabled-instance list.')
        for config in configs:
            if config['interface'] is not None:
                config['at_boot'] = 'unknown'
        return
    names = sorted(set(enabled))
    result['enabled_instances'] = names
    for config in configs:
        if config['interface'] is not None:
            config['at_boot'] = config['interface'] in names
    for name in names:
        if not INTERFACE_NAME.fullmatch(name):
            _gap(gaps, 'instance_unresolved', None,
                 f'wg-quick@{name}.service names a path, not an interface, and its file is not modeled.')
            continue
        config = by_interface.get(name)
        if config is None:
            if result['state'] == 'listed' and not any(g['code'] == 'listing_incomplete' for g in gaps):
                _gap(gaps, 'instance_without_config', None,
                     f'wg-quick@{name}.service is enabled but {CONFIG_DIR}/{name}.conf does not exist, so it fails.')
            continue
        if config['outcome'] == 'interface':
            result['boot_hooks'].extend(dict(hook, interface=name, path=config['path'])
                                        for hook in config['hooks'] if hook['phase'] in ('PreUp', 'PostUp'))
