"""Pure DNF post-transaction-actions contract (roadmap F slice, #1101).

The dnf-plugins-core ``post-transaction-actions`` plugin makes root run shell
commands after every RPM transaction. This module takes captured, read-only
observations and reports whether the plugin would run, which action lines it
would execute and which lines it rejects.

Behavior follows dnf-plugins-core ``plugins/post-transaction-actions.py`` (DNF 4):

- Action files are ``glob.glob(actiondir + "*.action")``: the directory string is
  concatenated with the pattern, hidden names are skipped and the order is the
  directory's own listing order, which is unspecified. Within a file, lines are
  read in order with ``readlines()`` (universal newlines) and ``strip()``.
- A line is a comment only when its first character (after ``strip()``) is ``#``.
- ``line.split(':', 2)`` must yield three parts; otherwise the line is logged and
  skipped. The state must be exactly ``in``, ``out`` or ``any``; otherwise the
  line is skipped. Parts are not stripped individually.
- Each matched package substitutes ``$name``/``${name}``, ``arch``, ``ver``,
  ``rel``, ``epoch``, ``repoid`` and ``state`` into the command, which then runs
  through ``/bin/sh -c`` as the user running dnf (normally root). Substituted
  values come from package and repository metadata and are not shell-escaped.
- An unreadable, non-regular or undecodable ``*.action`` entry makes the
  plugin's ``open()``/``readlines()`` raise. Every action file is read before
  any command runs, so such a read error means the plugin runs no actions in
  that transaction; the contract reports it as a blocking gap. When the entry
  is known not to be a regular file, actions parsed from other files are kept
  as evidence with ``runs`` false and ``blocked_by`` ``action_file_read_error``.

Plugin enablement follows dnf ``Plugin.read_config`` and ``_check_enabled`` with
the libdnf INI parser: ``/etc/dnf/plugins/post-transaction-actions.conf`` is
optional; the plugin is disabled only when ``[main]`` has an ``enabled`` key
whose OptionBool value is false. Keys and sections are case-sensitive, a later
value wins, matching outer quotes are trimmed and indented lines continue a
value. A parse error or a non-boolean ``enabled`` is a configuration error.
``dnf.conf`` ``[main] plugins`` false disables every plugin.
``Base.init_plugins`` skips loading entirely when plugins are globally off, and
dnf reads plugin-local configuration only for plugin classes it discovered, so a
plugin known to be absent or globally disabled is decided before its local
configuration is read; that configuration cannot then make the result a
configuration error or incomplete. Global ``dnf.conf`` errors stay decisive.

It performs no I/O, never runs dnf or a configured command and never authorizes
a response action. Fail-closed rules:

- Uncollected inputs, unknown plugin installation, a ``pluginconfpath``/
  ``pluginpath``/``actiondir`` override, unreadable or non-regular action
  entries, NUL and over-limit input are blocking gaps: ``complete`` is false.
- Command-line ``--enableplugin``/``--disableplugin``/``--setopt`` and DNF 5's
  separate ``libdnf5-plugins/actions.d`` mechanism are always disclosed as
  unobserved.
- Nothing is labelled safe; ``origin`` is always ``not_assessed``.
"""
from __future__ import annotations

import hashlib
import io
import re
from typing import Any

CONTRACT_VERSION = 1
PLUGIN = 'post-transaction-actions'
PLUGIN_CONF_DIR = '/etc/dnf/plugins'
PLUGIN_CONF = f'{PLUGIN_CONF_DIR}/{PLUGIN}.conf'
DEFAULT_ACTIONDIR = f'{PLUGIN_CONF_DIR}/{PLUGIN}.d/'
DNF_CONF = '/etc/dnf/dnf.conf'
STATES = ('in', 'out', 'any')
VARIABLES = ('name', 'arch', 'ver', 'rel', 'epoch', 'repoid', 'state')
MAX_FILES = 512
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_ACTIONS = 2048
MAX_REJECTED = 256
MAX_NAME = 255
MAX_VALUE = 4096
MAX_GAPS = 256
_TRUE = ('1', 'yes', 'true', 'on')
_FALSE = ('0', 'no', 'false', 'off')
_VAR = re.compile(r'\$(?:\{([A-Za-z0-9_]+)(?=[}:])|([A-Za-z0-9_]+))')
NOT_A_VERDICT = ('Post-transaction actions are reported for review only. They are not a safety verdict, '
                 'and their origin is not assessed.')
UNOBSERVED = (
    {'code': 'cli_options_unobserved',
     'detail': 'A dnf run can pass --enableplugin, --disableplugin or --setopt, which this contract cannot see.'},
    {'code': 'dnf5_actions_not_modelled',
     'detail': 'DNF 5 uses a separate actions plugin (/etc/dnf/libdnf5-plugins/actions.d); it is not evaluated.'},
    {'code': 'execution_order_transaction_dependent',
     'detail': 'Which actions run, how often and in what order depends on the packages in each transaction.'},
)


class _IniError(Exception):
    def __init__(self, line: int, reason: str) -> None:
        super().__init__(reason)
        self.line = line
        self.reason = reason


INACTIVE_STATES = frozenset({'not_installed', 'disabled'})


def _gap(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {'code': code, 'detail': detail, **extra}


def _trim_value(value: str) -> str:
    value = value.rstrip('\n')
    if len(value) > 1 and value[0] == value[-1] and value[0] in '"\'':
        value = value[1:-1]
    return value


def _end_of_section(line: str, pos: int) -> int:
    in_range = False
    for idx in range(pos, len(line)):
        ch = line[idx]
        if ch == ']':
            if in_range:
                in_range = False
            else:
                return idx
        elif ch == '[':
            in_range = True
        elif ch in '\r\n':
            return -1
    return -1


def parse_ini(text: str) -> dict[str, dict[str, str]]:
    """Parse INI text the way libdnf's IniParser and ConfigParser do.

    Raises ``_IniError`` where libdnf throws, so dnf would refuse the file.
    """
    data: dict[str, dict[str, str]] = {}
    section = ''
    key: str | None = None
    value = ''

    def flush() -> None:
        nonlocal key
        if key is not None:
            data.setdefault(section, {})[key] = _trim_value(value)
            key = None

    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    for number, line in enumerate(lines, 1):
        if number == 1 and line.startswith('﻿'):
            line = line[1:]
        if not line or line[0] in '#;':
            flush()
            continue
        stripped = line.lstrip(' \t\r')
        if not stripped:
            if key is not None:
                value += '\n'
            continue
        start = len(line) - len(stripped)
        body = line.rstrip(' \t\r')
        if key is not None and (start == 0 or stripped[0] == '['):
            flush()
        if stripped[0] == '[':
            end = _end_of_section(line, start + 1)
            if end < 0:
                raise _IniError(number, 'missing_bracket')
            if end == start + 1:
                raise _IniError(number, 'empty_section_name')
            # libdnf loops ``idx < end`` where ``end`` is the last non-blank
            # character, so that final character is never inspected.
            for ch in line[end + 1:len(body) - 1]:
                if ch in '#;':
                    break
                if ch not in ' \t\r':
                    raise _IniError(number, 'text_after_section')
            section = line[start + 1:end]
            data.setdefault(section, {})
            continue
        if not section:
            raise _IniError(number, 'missing_section_header')
        if start > 0:
            if key is None:
                raise _IniError(number, 'illegal_continuation_line')
            value += '\n' + body[start:]
            continue
        if stripped[0] == '=':
            raise _IniError(number, 'missing_key')
        if '=' not in line:
            raise _IniError(number, 'missing_equal')
        eq = line.index('=')
        key = line[:eq].rstrip(' \t')
        value = body[eq + 1:].lstrip(' \t') if len(body) > eq + 1 else ''
    flush()
    return data


def parse_bool(value: str) -> bool | None:
    """libdnf OptionBool: case-insensitive fixed words; ``None`` when invalid."""
    lowered = value.lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    return None


def _text(entry: Any) -> tuple[str | None, str | None]:
    content = entry.get('content') if isinstance(entry, dict) else None
    if not isinstance(content, str):
        return None, 'unreadable'
    if len(content.encode('utf-8', 'surrogatepass')) > MAX_FILE_BYTES:
        return None, 'too_large'
    if '\x00' in content:
        return None, 'nul'
    return content, None


def _bounded(value: str) -> dict[str, Any]:
    raw = value.encode('utf-8', 'surrogatepass')
    return {'value': value[:MAX_VALUE], 'truncated': len(value) > MAX_VALUE, 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def substituted_variables(command: str) -> list[str]:
    """Package-metadata variables the plugin substitutes into ``command``."""
    found = []
    for match in _VAR.finditer(command):
        name = match.group(1) or match.group(2)
        if name in VARIABLES and name not in found:
            found.append(name)
    return found


def eligible(name: str) -> bool:
    """Whether ``glob(actiondir + '*.action')`` lists this directory entry."""
    return name.endswith('.action') and not name.startswith('.')


def parse_action_file(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (actions, rejected lines) for one action file's text."""
    actions: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for number, raw in enumerate(io.StringIO(text, newline=None).readlines(), 1):
        line = raw.strip()
        if not line or line[0] == '#':
            continue
        parts = line.split(':', 2)
        if len(parts) != 3:
            rejected.append({'line': number, 'reason': 'bad_action_line', 'text': _bounded(line)})
            continue
        key, state, command = parts
        if state not in STATES:
            rejected.append({'line': number, 'reason': 'bad_transaction_state', 'state': state[:MAX_VALUE],
                             'text': _bounded(line)})
            continue
        variables = substituted_variables(command)
        actions.append({'line': number, 'package_filter': key[:MAX_VALUE], 'state': state,
                        'command': _bounded(command), 'substitutes': variables,
                        'package_metadata_in_shell': bool(variables)})
    return actions, rejected


def _inactive_actiondir(plugin_conf: Any) -> str:
    """Best-effort action directory of a plugin dnf will not load; its local configuration cannot block."""
    if isinstance(plugin_conf, dict) and plugin_conf.get('present') is True:
        text, _ = _text(plugin_conf)
        if text is not None:
            try:
                main = parse_ini(text).get('main') or {}
            except _IniError:
                return DEFAULT_ACTIONDIR
            if 'actiondir' in main:
                return main['actiondir']
    return DEFAULT_ACTIONDIR


def _plugin_state(plugin_conf: Any, dnf_conf: Any, installed: Any, add_gap: Any) -> tuple[str, str, str | None]:
    """Return (state, reason, actiondir)."""
    actiondir: str | None = DEFAULT_ACTIONDIR
    global_enabled: bool | None = True
    if dnf_conf is None:
        add_gap('dnf_conf_not_collected', f'{DNF_CONF} was not collected; plugins may be disabled globally.')
        global_enabled = None
    elif not isinstance(dnf_conf, dict) or not isinstance(dnf_conf.get('present'), bool):
        add_gap('invalid_observation', f'The {DNF_CONF} observation is malformed.')
        global_enabled = None
    elif dnf_conf['present']:
        text, problem = _text(dnf_conf)
        if text is None:
            add_gap(f'dnf_conf_{problem}', f'{DNF_CONF} could not be evaluated.')
            global_enabled = None
        else:
            try:
                main = parse_ini(text).get('main', {})
            except _IniError as error:
                add_gap('dnf_conf_parse_error', f'dnf refuses to run with an unparsable {DNF_CONF}.',
                        line=error.line, reason=error.reason)
                return 'config_error', 'dnf_conf_parse_error', None
            for option in ('pluginconfpath', 'pluginpath'):
                if option in main:
                    add_gap(f'{option}_override', f'{DNF_CONF} sets {option}; other locations are not evaluated.')
            if 'plugins' in main:
                parsed = parse_bool(main['plugins'])
                if parsed is None:
                    add_gap('dnf_conf_invalid_plugins', f'{DNF_CONF} sets plugins to a non-boolean value.')
                    return 'config_error', 'dnf_conf_invalid_plugins', None
                global_enabled = parsed
    if installed is None:
        add_gap('plugin_installation_unknown', 'Whether the post-transaction-actions plugin is installed is unknown.')
    elif not isinstance(installed, bool):
        add_gap('invalid_observation', 'The plugin installation observation is malformed.')
        installed = None
    # dnf skips plugin loading entirely when plugins are globally off, and only reads the local configuration
    # of plugin classes it discovered, so neither case depends on the plugin-local configuration.
    if installed is False:
        return 'not_installed', 'plugin_not_installed', _inactive_actiondir(plugin_conf)
    if global_enabled is False:
        return 'disabled', 'dnf_conf_plugins_disabled', _inactive_actiondir(plugin_conf)
    if plugin_conf is None:
        add_gap('plugin_conf_not_collected', f'{PLUGIN_CONF} was not collected.')
        return 'unknown', 'plugin_conf_not_collected', None
    if not isinstance(plugin_conf, dict) or not isinstance(plugin_conf.get('present'), bool):
        add_gap('invalid_observation', f'The {PLUGIN_CONF} observation is malformed.')
        return 'unknown', 'invalid_observation', None
    enabled = True
    if plugin_conf['present']:
        text, problem = _text(plugin_conf)
        if text is None:
            add_gap(f'plugin_conf_{problem}', f'{PLUGIN_CONF} could not be evaluated.')
            return 'unknown', f'plugin_conf_{problem}', None
        try:
            main = parse_ini(text).get('main')
        except _IniError as error:
            add_gap('plugin_conf_parse_error', f'dnf refuses to load plugins with an unparsable {PLUGIN_CONF}.',
                    line=error.line, reason=error.reason)
            return 'config_error', 'plugin_conf_parse_error', None
        if main is not None and 'enabled' in main:
            parsed = parse_bool(main['enabled'])
            if parsed is None:
                add_gap('plugin_conf_invalid_enabled', f'{PLUGIN_CONF} sets enabled to a non-boolean value.')
                return 'config_error', 'plugin_conf_invalid_enabled', None
            enabled = parsed
        if main is not None and 'actiondir' in main:
            actiondir = main['actiondir']
    if not enabled:
        return 'disabled', 'plugin_conf_disabled', actiondir
    if installed is None or global_enabled is None:
        return 'unknown', 'enablement_inputs_incomplete', actiondir
    return 'enabled', 'enabled', actiondir


def resolve(actions_dir: Any, plugin_conf: Any = None, dnf_conf: Any = None, *,
            plugin_installed: Any = None) -> dict[str, Any]:
    """Resolve post-transaction actions from captured observations.

    ``actions_dir`` lists the entries of the default action directory, each a
    dict with ``name``, ``type`` (``file`` for a regular file or a link to one)
    and ``content`` (text, or ``None`` when unreadable); ``None`` means it was
    not collected. ``plugin_conf`` and ``dnf_conf`` are
    ``{'present': bool, 'content': text|None}`` or ``None`` when not collected.
    ``plugin_installed`` is whether the plugin module is installed, or ``None``.
    """
    gaps: list[dict[str, Any]] = [dict(g) for g in UNOBSERVED]
    complete = True

    def add_gap(code: str, detail: str, **extra: Any) -> None:
        nonlocal complete
        complete = False
        if len(gaps) < MAX_GAPS:
            gaps.append(_gap(code, detail, **extra))
        elif gaps[-1]['code'] != 'gap_limit':
            gaps.append(_gap('gap_limit', 'Further coverage gaps were omitted.'))

    state, reason, actiondir = _plugin_state(plugin_conf, dnf_conf, plugin_installed, add_gap)
    files: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    if actiondir is not None and actiondir != DEFAULT_ACTIONDIR and state in INACTIVE_STATES:
        pass  # Nothing runs from the other location, so the uncollected directory is not a coverage gap.
    elif actiondir is not None and actiondir != DEFAULT_ACTIONDIR:
        add_gap('actiondir_override', 'The plugin reads action files from a different location, which was not '
                'collected.', actiondir=actiondir[:MAX_VALUE],
                glob=(actiondir + '*.action')[:MAX_VALUE])
    elif actions_dir is None:
        add_gap('actions_dir_not_collected', f'{DEFAULT_ACTIONDIR} was not collected.')
    elif not isinstance(actions_dir, list):
        add_gap('invalid_observation', f'The {DEFAULT_ACTIONDIR} observation is malformed.')
    else:
        if len(actions_dir) > MAX_FILES:
            add_gap('file_limit', f'Only the first {MAX_FILES} entries were evaluated.')
        candidates = []
        for entry in actions_dir[:MAX_FILES]:
            name = entry.get('name') if isinstance(entry, dict) else None
            if (not isinstance(name, str) or not name or len(name) > MAX_NAME or '/' in name
                    or name in ('.', '..') or any(ord(c) < 32 or ord(c) == 127 for c in name)):
                add_gap('invalid_entry', 'An entry with an invalid name was not evaluated.')
                continue
            candidates.append((name.encode('utf-8', 'surrogatepass'), name, entry))
        total = 0
        # Sorted for stable output only; the plugin uses the unspecified directory order.
        for _, name, entry in sorted(candidates, key=lambda item: item[0]):
            path = DEFAULT_ACTIONDIR + name
            if not eligible(name):
                files.append({'path': path, 'state': 'ignored',
                              'reason': 'hidden' if name.startswith('.') else 'not_action_suffix'})
                continue
            if entry.get('type') != 'file':
                files.append({'path': path, 'state': 'plugin_read_error', 'reason': 'not_regular_file'})
                add_gap('action_entry_not_regular', 'The plugin fails opening this entry. It reads every action '
                        'file before running any command, so this read error stops it running any action in '
                        'the transaction.', path=path)
                continue
            text, problem = _text(entry)
            if text is not None and total + len(text) > MAX_TOTAL_BYTES:
                text, problem = None, 'total_limit'
            if text is None:
                files.append({'path': path, 'state': problem})
                detail = 'The plugin reads this file, but its contents were not available to the contract.'
                if problem == 'unreadable':
                    detail += (' If the plugin cannot read it either, that read error stops it running any action '
                               'in the transaction.')
                add_gap(f'action_file_{problem}', detail, path=path)
                continue
            total += len(text)
            file_actions, file_rejected = parse_action_file(text)
            files.append({'path': path, 'state': 'parsed', 'actions': len(file_actions),
                          'rejected': len(file_rejected)})
            for item in file_actions:
                if len(actions) >= MAX_ACTIONS:
                    add_gap('action_limit', f'Only the first {MAX_ACTIONS} actions are reported.')
                    break
                actions.append({'path': path, 'runs': state == 'enabled', 'shell': '/bin/sh -c',
                                'runs_as': 'dnf invoking user (normally root)', 'origin': 'not_assessed', **item})
            for item in file_rejected:
                if len(rejected) < MAX_REJECTED:
                    rejected.append({'path': path, **item})
    if any(f['state'] == 'plugin_read_error' for f in files):
        # _parse_actions() raises on this entry before any transaction command is selected, so no action runs.
        for action in actions:
            action['runs'] = False
            action['blocked_by'] = 'action_file_read_error'
    return {
        'contract_version': CONTRACT_VERSION,
        'plugin': {'name': PLUGIN, 'state': state, 'reason': reason, 'installed': plugin_installed
                   if isinstance(plugin_installed, bool) else None,
                   'actiondir': actiondir[:MAX_VALUE] if actiondir is not None else None},
        'complete': complete,
        'file_order': 'directory_order_unspecified',
        'files': files,
        'actions': actions,
        'rejected': rejected,
        'gaps': gaps,
        'not_a_verdict': NOT_A_VERDICT,
    }
