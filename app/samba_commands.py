"""Pure Samba ``smb.conf`` command contract (roadmap F, issue #1580).

Given captured ``smb.conf`` text and captured ``include =`` targets, report which shell
commands ``smbd`` (and, for ``wins hook``, ``nmbd``) is configured to run, for which
share, as which account and on which trigger. Nothing here reads files, runs Samba, a
command or a shell, and nothing here authorizes a response.

Behavior follows Ubuntu 24.04 ``samba 2:4.19.5``: ``lib/util/tini.c`` line handling
and ``source3/param/loadparm.c`` section/parameter handling, checked against
``testparm -s -v`` on native fixtures (see ``tests/test_samba_commands.py``):

* A logical line skips leading whitespace; ``#`` or ``;`` as its first character makes
  it a comment. A backslash (optionally followed by one whitespace run) before the
  newline continues it. Every whitespace run is collapsed to its first character, and
  one leading and one trailing whitespace character is trimmed from names and values.
* ``[name]`` starts a section; text after the first ``]`` is ignored and a missing
  ``]`` makes Samba reject the whole file. A line without ``=`` is ignored; an empty
  parameter name rejects the file.
* Parameter names compare ignoring case and whitespace (``RootPreExec``), but not
  underscores. ``exec`` is a synonym of ``preexec``.
* ``[global]`` (or ``[globals]``) sets global parameters and the defaults for share
  parameters. A share copies the defaults when it is first created; later ``[global]``
  sections do not change it, and a repeated share header (case-insensitive) reopens the
  existing share. A global-only parameter in a share section is ignored.
* ``include =`` is textual: the included file's sections and parameters continue the
  current state, and parameters after the include line apply to the section the
  included file ended in. A missing include file is skipped; more than 100 nested
  includes rejects the file.
* An invalid boolean for a tracked boolean parameter rejects the file.
* After loading, smbd adds ``IPC$`` (and ``ADMIN$`` with ``enable asu support``) from
  the *final* ``[global]`` defaults, so inherited ``root preexec``/``preexec`` run on
  every client connection; an explicit ``[IPC$]`` keeps its own snapshot and is forced
  available.
* ``preexec``/``postexec`` run as the ``force user`` account when one is set (``root``
  or a name resolving to uid 0 in captured ``/etc/passwd`` is root), and as root for
  ``admin users``; an unresolvable ``force user`` is a blocking gap.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SCHEMA = 'samba-commands/1'
DEFAULT_CONFIG_PATH = '/etc/samba/smb.conf'
MAX_TEXT_BYTES = 1024 * 1024
MAX_FILES = 128  # above MAX_INCLUDE_DEPTH, so a recursive include is rejected as Samba does
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_INCLUDE_DEPTH = 100
MAX_COMMANDS = 512

_WS = ' \t\n\v\f\r'

# Share (P_LOCAL) parameters that run commands at connect/disconnect time.
SHARE_COMMANDS: dict[str, tuple[str, str]] = {
    'root preexec': ('root', 'share_connect'),
    'preexec': ('connecting_user', 'share_connect'),
    'root postexec': ('root', 'share_disconnect'),
    'postexec': ('connecting_user', 'share_disconnect'),
}
CLOSE_FLAGS = {'root preexec close': 'root preexec', 'preexec close': 'preexec'}

# Global (P_GLOBAL) parameters whose value is a command. ``root`` only where the Samba
# 4.19 parameter documentation states the command runs as root; otherwise the account
# is reported as not assessed rather than guessed.
GLOBAL_COMMANDS: dict[str, tuple[str, str]] = {
    'add user script': ('root', 'user_management'),
    'delete user script': ('not_assessed', 'user_management'),
    'rename user script': ('root', 'user_management'),
    'add machine script': ('not_assessed', 'user_management'),
    'add group script': ('root', 'group_management'),
    'delete group script': ('root', 'group_management'),
    'add user to group script': ('root', 'group_management'),
    'delete user from group script': ('root', 'group_management'),
    'set primary group script': ('not_assessed', 'group_management'),
    'check password script': ('not_assessed', 'password_change'),
    'passwd program': ('root', 'password_change'),
    'username map script': ('not_assessed', 'authentication'),
    'add share command': ('root', 'share_management'),
    'change share command': ('root', 'share_management'),
    'delete share command': ('root', 'share_management'),
    'addprinter command': ('not_assessed', 'printer_management'),
    'deleteprinter command': ('not_assessed', 'printer_management'),
    'addport command': ('not_assessed', 'printer_management'),
    'enumports command': ('not_assessed', 'printer_management'),
    'shutdown script': ('root', 'remote_shutdown'),
    'abort shutdown script': ('root', 'remote_shutdown'),
    'get quota command': ('not_assessed', 'quota'),
    'set quota command': ('not_assessed', 'quota'),
    'panic action': ('not_assessed', 'daemon_panic'),
    'message command': ('guest', 'winpopup_message'),
    'wins hook': ('not_assessed', 'wins_change'),
    'log nt token command': ('not_assessed', 'logon'),
}

# Command-bearing parameters this increment does not evaluate. Setting one is reported
# as a non-blocking note so the result never implies they were inspected.
NOT_EVALUATED = (
    'print command', 'lpq command', 'lprm command', 'lppause command', 'lpresume command',
    'queuepause command', 'queueresume command', 'dfree command', 'magic script',
    'dns update command', 'nsupdate command', 'samba kcc command', 'spn update command',
    'gpo update command', 'mit kdc command',
)
_LOCAL_NOT_EVALUATED = NOT_EVALUATED[:9]

_BOOLEAN_SHARE = ('available', 'root preexec close', 'preexec close', 'enable asu support')
# Share parameters that change the account ``preexec``/``postexec`` run as.
_ACCOUNT_PARAMS = ('force user', 'admin users')
# Shares smbd adds after loading (``lp_add_ipc``) from the final ``[global]`` defaults.
_IPC_SHARES = ('IPC$', 'ADMIN$')
_TRUE = ('yes', 'true', 'on', '1')
_FALSE = ('no', 'false', 'off', '0')


def _key(name: str) -> str:
    """Samba's ``strwicmp`` comparison key: case- and whitespace-insensitive."""
    return ''.join(ch for ch in name if ch not in _WS).lower()


_SYNONYMS = {'exec': 'preexec'}
_CANONICAL = {_key(n): n for n in (*SHARE_COMMANDS, *CLOSE_FLAGS, *GLOBAL_COMMANDS, *NOT_EVALUATED,
                                   'available', 'include', 'copy', 'config file', 'config backend',
                                   'enable asu support', *_ACCOUNT_PARAMS)}
_CANONICAL.update({_key(k): v for k, v in _SYNONYMS.items()})
_GLOBAL_ONLY = {*GLOBAL_COMMANDS, *NOT_EVALUATED[9:], 'config file', 'config backend', 'enable asu support'}


def _logical_lines(text: str):
    """Yield ``(first_line_number, line)`` exactly as ``tini.c`` ``get_line`` builds it."""
    i, n, lineno = 0, len(text), 1
    while True:
        # next_content: skip whitespace up to and including a newline.
        while i < n and text[i] in _WS and text[i] != '\n':
            i += 1
        if i >= n:
            return
        start_line = lineno
        if text[i] == '\n':
            i += 1
            lineno += 1
            continue
        if text[i] in '#;':
            nl = text.find('\n', i)
            if nl < 0:
                return
            i = nl + 1
            lineno += 1
            continue
        buf: list[str] = []
        while i < n:
            c = text[i]
            i += 1
            if c == '\n':
                lineno += 1
                if buf and buf[-1] == '\\':
                    buf.pop()
                    continue
                if len(buf) > 1 and buf[-2] == '\\' and buf[-1] in _WS:
                    del buf[-2:]
                    continue
                break
            if buf and buf[-1] in _WS and c in _WS:
                continue
            buf.append(c)
        yield start_line, ''.join(buf)


def _trim_one(s: str) -> str:
    if s[:1] and s[0] in _WS:
        s = s[1:]
    if s and s[-1] in _WS:
        s = s[:-1]
    return s


class _Reject(Exception):
    pass


# Agent-reduced files (#1580 increment 3). Agents build logical lines from the hashed bytes with the
# rules above and keep only section headers, the lines this contract tracks and the line Samba rejects
# a file at; commands use best-effort credential redaction. ``error`` is ``nul_byte`` or
# ``invalid_utf8`` for a file the agent did not reduce.
class LogicalLines:
    """Logical lines an agent already built with ``_logical_lines`` (first line number, line)."""

    __slots__ = ('lines', 'error')

    def __init__(self, lines: list[tuple[int, str]], error: str | None = None) -> None:
        self.lines = lines
        self.error = error


TRACKED_NAMES = frozenset(_CANONICAL)


def tracked(name: str) -> bool:
    """Whether a trimmed parameter name is one this contract reads (agents drop every other line)."""
    return _key(name) in TRACKED_NAMES


def command_parameter(name: str) -> bool:
    """Whether a trimmed parameter name holds a command (agents redact these values)."""
    canonical = _CANONICAL.get(_key(name))
    return canonical in SHARE_COMMANDS or canonical in GLOBAL_COMMANDS or canonical in NOT_EVALUATED


def analyze(config_text: str | None, includes: Mapping[str, str | None] | None = None,
            config_path: str = DEFAULT_CONFIG_PATH, passwd_text: str | None = None) -> dict[str, Any]:
    """Report the commands configured by ``config_text``.

    ``includes`` maps absolute include paths to their captured text, or to ``None`` when
    the file was observed to be absent. A path missing from the mapping is unobserved.
    ``passwd_text`` is captured ``/etc/passwd`` text, used only to resolve ``force user``
    accounts other than ``root`` to a uid.
    """
    includes = includes if includes is not None else {}
    gaps: list[dict[str, str]] = []
    notes: list[str] = []

    def gap(code: str, detail: str) -> None:
        if len(gaps) < 64:
            gaps.append({'code': code, 'detail': detail, 'blocking': True})

    defaults: dict[str, tuple[str, str, int]] = {}
    globals_: dict[str, tuple[str, str, int]] = {}
    shares: dict[str, dict[str, Any]] = {}
    state: dict[str, Any] = {'section': None, 'files': 0, 'bytes': 0}

    def check_text(path: str, text: Any) -> str | None:
        if not isinstance(text, str):
            gap('invalid_input', f'{path}: captured text is not a string')
            return None
        size = len(text.encode('utf-8', 'surrogatepass'))
        state['bytes'] += size
        if size > MAX_TEXT_BYTES or state['bytes'] > MAX_TOTAL_BYTES:
            gap('input_too_large', f'{path}: larger than {MAX_TEXT_BYTES} bytes or {MAX_TOTAL_BYTES} in total')
            return None
        if '\x00' in text:
            gap('nul_byte', f'{path}: contains a NUL byte, which Samba truncates lines at')
            return None
        if any('\ud800' <= ch <= '\udfff' for ch in text):
            gap('invalid_utf8', f'{path}: not valid UTF-8')
            return None
        return text

    def set_param(name: str, value: str, path: str, line: int, depth: int) -> None:
        canonical = _CANONICAL.get(_key(name))
        if canonical is None:
            return  # parameters that run nothing are not tracked
        section = state['section']
        if canonical == 'include':
            include(value, path, line, depth)
            return
        if canonical in ('config file', 'config backend'):
            if section is None:
                if canonical == 'config backend' and value.strip().lower() == 'file':
                    return
                gap('alternate_configuration', f'{path}:{line}: {canonical} = {value} is not evaluated')
            return
        if canonical == 'copy':
            if section is not None:
                gap('share_copy', f'{path}:{line}: copy = {value} in [{section["name"]}] is not evaluated')
            return
        if canonical in _BOOLEAN_SHARE or canonical in CLOSE_FLAGS:
            low = value.lower()
            if low not in _TRUE and low not in _FALSE:
                raise _Reject(f'{path}:{line}: {canonical} = {value} is not a boolean')
        if canonical in _GLOBAL_ONLY:
            if section is not None:
                notes.append(f'{path}:{line}: global parameter {canonical} in [{section["name"]}] is ignored by Samba')
                return
            globals_[canonical] = (value, path, line)
            return
        target = defaults if section is None else section['params']
        target[canonical] = (value, path, line)

    def include(value: str, path: str, line: int, depth: int) -> None:
        if value.strip().lower() == 'registry':
            gap('registry_configuration', f'{path}:{line}: include = registry is not evaluated')
            return
        if '%' in value:
            gap('substituted_include', f'{path}:{line}: include path {value} uses % substitution')
            return
        if not value.startswith('/'):
            gap('relative_include', f'{path}:{line}: include path {value} is relative to smbd\'s working directory')
            return
        if depth + 1 > MAX_INCLUDE_DEPTH:
            raise _Reject(f'{path}:{line}: maximum include depth ({MAX_INCLUDE_DEPTH}) exceeded')
        if value not in includes:
            gap('unobserved_include', f'{path}:{line}: include {value} was not captured')
            return
        if includes[value] is None:
            notes.append(f'{path}:{line}: include {value} is absent and is skipped by Samba')
            return
        process(value, includes[value], depth + 1)

    def start_section(raw: str) -> None:
        key = _key(raw)
        if key in ('global', 'globals'):
            state['section'] = None
            return
        existing = shares.get(raw.lower())
        if existing is None:
            if len(shares) >= 1024:
                raise _Reject('more than 1024 shares')
            existing = {'name': raw, 'params': dict(defaults), 'implicit': False}
            shares[raw.lower()] = existing
        state['section'] = existing

    def process(path: str, text: Any, depth: int) -> None:
        state['files'] += 1
        if state['files'] > MAX_FILES:
            gap('too_many_files', f'more than {MAX_FILES} configuration files')
            return
        if isinstance(text, LogicalLines):
            if text.error is not None:
                gap(text.error, f'{path}: ' + ('contains a NUL byte, which Samba truncates lines at'
                                               if text.error == 'nul_byte' else 'not valid UTF-8'))
                return
            lines = iter(text.lines)
        else:
            checked = check_text(path, text)
            if checked is None:
                return
            lines = _logical_lines(checked)
        for lineno, line in lines:
            if line.startswith('['):
                end = line.find(']', 1)
                if end < 0:
                    raise _Reject(f'{path}:{lineno}: section header without ]')
                start_section(line[1:end])
                continue
            if '=' not in line:
                continue
            name, value = line.split('=', 1)
            name = _trim_one(name)
            if not name:
                raise _Reject(f'{path}:{lineno}: empty parameter name')
            set_param(name, _trim_one(value), path, lineno, depth)

    loads = True
    reject_reason = None
    if config_text is None:
        gap('unobserved_config', f'{config_path} was not captured')
    else:
        try:
            process(config_path, config_text, 0)
        except _Reject as exc:
            loads = False
            reject_reason = str(exc)

    commands: list[dict[str, Any]] = []
    configured_not_evaluated: set[str] = set()
    uids = _passwd_uids(passwd_text)
    if loads:
        # lp_add_ipc: IPC$ (and ADMIN$ with ``enable asu support``) are added after the
        # whole file is read, so they take the final [global] defaults. An explicit
        # section with the same name keeps its own creation-time snapshot. Both are
        # forced available.
        added = ['IPC$'] + (['ADMIN$'] if _bool(globals_.get('enable asu support'), False) else [])
        for name in added:
            share = shares.get(name.lower())
            if share is None:
                shares[name.lower()] = {'name': name, 'params': dict(defaults), 'implicit': True}
            else:
                share['params']['available'] = ('yes', '', 0)
        for name, (value, path, line) in sorted(globals_.items()):
            if name in NOT_EVALUATED:
                if value:
                    configured_not_evaluated.add(name)
                continue
            if value and name in GLOBAL_COMMANDS:
                account, trigger = GLOBAL_COMMANDS[name]
                commands.append({'parameter': name, 'share': None, 'template': None, 'command': value,
                                 'account': account, 'trigger': trigger, 'file': path, 'line': line,
                                 'share_available': None, 'refuses_connection_on_failure': None})
        for share in shares.values():
            params = share['params']
            available = _bool(params.get('available'), True)
            template = share['name'].lower() if share['name'].lower() in ('homes', 'printers') else None
            for name in _LOCAL_NOT_EVALUATED:
                if params.get(name, ('',))[0]:
                    configured_not_evaluated.add(name)
            forced = params.get('force user', ('', '', 0))
            admins = params.get('admin users', ('', '', 0))[0] or None
            user_account = 'connecting_user'
            if forced[0]:
                user_account = _forced_account(forced[0], uids)
            for name, (account, trigger) in SHARE_COMMANDS.items():
                value, path, line = params.get(name, ('', '', 0))
                if not value:
                    continue
                runs_as_user = account == 'connecting_user'
                if runs_as_user and user_account not in ('connecting_user', 'root', 'forced_user'):
                    gap('unresolved_force_user', f'[{share["name"]}] force user = {forced[0]} ({forced[1]}:{forced[2]}) '
                        f'could not be resolved to a uid, so the account of {name} is not known')
                close_flag = next((f for f, target in CLOSE_FLAGS.items() if target == name), None)
                commands.append({
                    'parameter': name, 'share': share['name'], 'template': template, 'command': value,
                    'implicit_share': share['implicit'],
                    'account': user_account if runs_as_user else account, 'trigger': trigger,
                    'file': path, 'line': line,
                    'forced_user': forced[0] if runs_as_user and forced[0] else None,
                    'root_for_admin_users': admins if runs_as_user else None,
                    'share_available': available,
                    'refuses_connection_on_failure': _bool(params.get(close_flag), False) if close_flag else False,
                })
    if len(commands) > MAX_COMMANDS:
        gap('too_many_commands', f'more than {MAX_COMMANDS} commands')
        commands = commands[:MAX_COMMANDS]
    for name in sorted(configured_not_evaluated):
        notes.append(f'{name} is configured but not evaluated in this increment')

    return {
        'schema': SCHEMA,
        'config_path': config_path,
        'loads': loads,
        'reject_reason': reject_reason,
        'commands': commands,
        'root_commands': [c for c in commands if (c['account'] == 'root' or c.get('root_for_admin_users'))
                          and c['share_available'] is not False],
        'shares': sorted(s['name'] for s in shares.values()) if loads else [],
        'configured_not_evaluated': sorted(configured_not_evaluated),
        'notes': notes[:64],
        'gaps': gaps,
        'complete': not gaps,
        'origin': 'not_assessed',
        'authorizes_response': False,
    }


def _bool(entry: tuple[str, str, int] | None, default: bool) -> bool:
    if entry is None:
        return default
    return entry[0].lower() in _TRUE


def _passwd_uids(text: str | None) -> dict[str, int] | None:
    if not isinstance(text, str):
        return None
    uids: dict[str, int] = {}
    for line in text.splitlines()[:100000]:
        fields = line.split(':')
        if len(fields) >= 3 and fields[0] and fields[2].isdigit():
            uids.setdefault(fields[0], int(fields[2]))
    return uids


def _forced_account(name: str, uids: dict[str, int] | None) -> str:
    """Account for ``preexec``/``postexec`` under ``force user``.

    ``root`` (or any name resolving to uid 0) is ``root``; another resolved name is
    ``forced_user``. A ``%`` macro, an unknown name or a missing ``/etc/passwd`` is
    ``not_assessed`` and the caller records a blocking gap.
    """
    if '%' in name:
        return 'not_assessed'
    if name == 'root':
        return 'root'
    if uids is None:
        return 'not_assessed'
    uid = uids.get(name, uids.get(name.lower()))
    if uid is None:
        return 'not_assessed'
    return 'root' if uid == 0 else 'forced_user'
