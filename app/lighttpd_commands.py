"""Pure lighttpd command contract (roadmap F slice, #1603).

lighttpd runs commands named in its configuration:

- ``include_shell "cmd"`` runs ``$SHELL -c cmd`` (``/bin/sh`` when ``SHELL`` is
  unset, as it is for a systemd service) while the configuration is parsed,
  as the invoking user (root when the service starts), and parses the
  command's standard output as more configuration. Every start, ``-t`` and
  ``-tt`` test and ``-p`` print runs it again.
- Piped loggers, ``server.errorlog``, ``server.breakagelog`` and
  ``accesslog.filename`` values starting with ``|``, run ``$SHELL -c cmd``
  after the daemon has dropped to ``server.username``/``server.groupname``.
  Loggers assigned inside a ``$HTTP[...]`` conditional start at daemon start
  too, not per request.
- FastCGI and SCGI ``bin-path`` backends are executed directly, with the value
  split on blanks into argv, as ``server.username``.

A command made only of path characters (``[A-Za-z0-9_./+,:@-]``) is executed
directly instead, with argv ``[command]``; a blank, tab or ``;`` selects the
shell. Other characters are reported as using the shell, with a
non-blocking ``shell_choice_not_verified`` note.

Debian and Ubuntu's stock ``lighttpd.conf`` already runs two ``include_shell``
Perl helpers and includes ``conf-enabled/*.conf``, so a new drop-in or helper
makes root run a new command on the next start.

This module turns captured configuration text, captured ``include`` glob
matches, optionally captured ``include_shell`` output and captured
``/etc/passwd`` and ``/etc/group`` text into those commands with their argv,
account, timing, source file/line and enclosing conditional. It performs no
I/O, never runs lighttpd or a command and never authorizes a response action.

The rules follow lighttpd 1.4.74, checked against native runs of Ubuntu 24.04
``lighttpd 1.4.74-1ubuntu3`` traced with
``strace -f -e trace=execve,setuid,setgid``:

- ``#`` starts a comment outside strings; strings are double quoted and
  ``\\"`` is a literal quote. Values are strings, integers, ``( ... )`` arrays
  with optional ``key => value`` entries and references to earlier keys,
  ``var.*`` variables or ``env.*`` environment values, joined with ``+``.
  ``var.CWD`` and ``var.PID`` are predefined.
- ``=`` on a key already set in the same block is a "Duplicate config
  variable" error that rejects the configuration; ``:=`` replaces and ``+=``
  appends.
- ``include`` paths are relative to the including file's directory. A glob
  that matches nothing is silently skipped; a missing plain file rejects the
  configuration.
- ``include_shell`` output is parsed as if it came from a file named after
  the command; its relative includes use the including file's directory.

Unobserved files or glob listings, ``include_shell`` output that was not
captured, unresolved references, unknown accounts and parse errors are
blocking gaps, and ``complete`` is false whenever one is present. Request-time
``cgi.assign`` interpreters, ``mod_magnet`` Lua scripts and module load
success are not assessed. ``origin`` is always ``not_assessed`` and
``authorizes_response`` is always false.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from collections.abc import Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSION = 'lighttpd 1.4.74 (Ubuntu 24.04 lighttpd 1.4.74-1ubuntu3)'

DEFAULT_CONFIG = '/etc/lighttpd/lighttpd.conf'
DEFAULT_SHELL = '/bin/sh'
MAX_TEXT = 1024 * 1024
MAX_FILES = 256
MAX_DEPTH = 16
MAX_COMMANDS = 1000
LOGGER_KEYS = ('server.errorlog', 'server.breakagelog', 'accesslog.filename')
BACKEND_KEYS = ('fastcgi.server', 'scgi.server')
_GLOB = re.compile(r'[*?\[]')
_KEY = re.compile(r'[A-Za-z_][A-Za-z0-9_.\-]*')
# Commands made only of these characters were executed directly, without the shell, in the
# native traces; a blank, tab or ';' made lighttpd use ``$SHELL -c``.
_DIRECT = re.compile(r'[A-Za-z0-9_./+,:@-]+')
_SHELL = re.compile(r'[ \t;]')


class ConfigError(ValueError):
    def __init__(self, message: str, line: int):
        super().__init__(message)
        self.line = line


def tokenize(text: str) -> list[tuple[str, Any, int]]:
    """Return ``(kind, value, line)`` tokens; raise ConfigError on bad input."""
    tokens: list[tuple[str, Any, int]] = []
    i, line, n = 0, 1, len(text)
    while i < n:
        c = text[i]
        if c == '\n':
            line += 1
            i += 1
        elif c in ' \t\r':
            i += 1
        elif c == '#':
            while i < n and text[i] != '\n':
                i += 1
        elif c == '"':
            j, out = i + 1, []
            while j < n and text[j] != '"':
                if text[j] == '\\' and j + 1 < n and text[j + 1] == '"':
                    out.append('"')
                    j += 2
                    continue
                if text[j] == '\n':
                    line += 1
                out.append(text[j])
                j += 1
            if j >= n:
                raise ConfigError('unterminated string', line)
            tokens.append(('str', ''.join(out), line))
            i = j + 1
        elif c.isdigit():
            j = i
            while j < n and text[j].isdigit():
                j += 1
            tokens.append(('int', int(text[i:j]), line))
            i = j
        elif c == '$':
            m = re.compile(r'\$[A-Z_]+').match(text, i)
            if not m:
                raise ConfigError('bad conditional', line)
            tokens.append(('cond', m.group(0), line))
            i = m.end()
        else:
            for op in ('=>', '+=', ':=', '==', '!=', '=~', '!~', '=^', '=$'):
                if text.startswith(op, i):
                    tokens.append(('op', op, line))
                    i += len(op)
                    break
            else:
                if c in '=+(){}[],':
                    tokens.append(('op', c, line))
                    i += 1
                    continue
                m = _KEY.match(text, i)
                if not m:
                    raise ConfigError(f'unexpected character {c!r}', line)
                tokens.append(('word', m.group(0), line))
                i = m.end()
    return tokens


class _Unresolved(Exception):
    def __init__(self, name: str):
        super().__init__(name)
        self.name = name


def _concat(left: Any, right: Any, line: int) -> Any:
    if isinstance(left, list) and isinstance(right, list):
        return left + right
    if isinstance(left, (str, int)) and isinstance(right, (str, int)):
        if isinstance(left, int) and isinstance(right, int):
            return left + right
        return f'{left}{right}'
    raise ConfigError('cannot concatenate these values', line)


class _Reader:
    def __init__(self, files: Mapping[str, str | bytes | None], globs: Mapping[str, Sequence[str] | None],
                 shell_output: Mapping[str, str | bytes | None], env: Mapping[str, str], cwd: str | None):
        self.files, self.globs, self.shell_output, self.env = files, globs, shell_output, env
        self.values: dict[str, Any] = {'var.PID': 0}
        if cwd:
            self.values['var.CWD'] = cwd
        self.gaps: list[dict[str, Any]] = []
        self.notes: list[dict[str, Any]] = []
        self.read: list[dict[str, Any]] = []
        self.commands: list[dict[str, Any]] = []
        self.rejected = False
        self.count = 0

    def gap(self, code: str, *, blocking: bool = True, **detail: Any) -> None:
        entry = {'code': code, 'blocking': blocking, **detail}
        if entry not in self.gaps:
            self.gaps.append(entry)

    def reject(self, code: str, **detail: Any) -> None:
        self.rejected = True
        self.gap(code, **detail)

    # -- sources --------------------------------------------------------
    def source(self, name: str, text: str | bytes, directory: str, depth: int, scope: dict[str, Any]) -> None:
        if isinstance(text, bytes):
            text = text.decode('utf-8', 'replace')
        if len(text) > MAX_TEXT:
            self.reject('input_over_limit', source=name, limit=MAX_TEXT)
            return
        self.count += 1
        if self.count > MAX_FILES or depth > MAX_DEPTH:
            self.reject('input_over_limit', source=name, limit=MAX_FILES if depth <= MAX_DEPTH else MAX_DEPTH)
            return
        try:
            tokens = tokenize(text)
            _Parser(self, name, directory, depth, tokens, scope).statements(top=True)
        except ConfigError as error:
            self.reject('parse_error', source=name, line=error.line, message=str(error))

    def include(self, pattern: str, directory: str, depth: int, line: int, origin: str,
                scope: dict[str, Any]) -> None:
        path = posixpath.normpath(posixpath.join(directory, pattern))
        if _GLOB.search(pattern):
            matches = self.globs.get(path)
            if matches is None:
                self.gap('unobserved_glob', pattern=path, source=origin, line=line)
                return
            targets = sorted(posixpath.normpath(m) for m in matches)
        else:
            targets = [path]
        for target in targets:
            text = self.files.get(target)
            if text is None:
                if target not in self.files:
                    self.gap('unobserved_file', path=target, source=origin, line=line)
                elif not _GLOB.search(pattern):
                    self.reject('include_not_found', path=target, source=origin, line=line)
                continue
            self.read.append({'path': target, 'included_from': origin, 'line': line})
            self.source(target, text, posixpath.dirname(target), depth + 1, scope)

    def include_shell(self, command: str, directory: str, depth: int, line: int, origin: str,
                      scope: dict[str, Any]) -> None:
        self.add({'kind': 'include_shell', 'command': command, 'argv': self.argv(command, origin, line),
                  'runs': 'config_parse', 'account': 'invoking_user', 'uid': None, 'gid': None,
                  'privileged_at_service_start': True, 'source': origin, 'line': line, 'condition': None})
        output = self.shell_output.get(command)
        if output is None:
            self.gap('include_shell_output_not_captured', command=command, source=origin, line=line)
            return
        self.source(command, output, directory, depth + 1, scope)

    def shell(self) -> str:
        return self.env.get('SHELL') or DEFAULT_SHELL

    def argv(self, command: str, origin: str, line: int) -> list[str]:
        if _DIRECT.fullmatch(command):
            return [command]
        if not _SHELL.search(command):
            self.gap('shell_choice_not_verified', blocking=False, command=command, source=origin, line=line,
                     detail='reported as run through the shell; lighttpd may execute it directly')
        return [self.shell(), '-c', command]

    def add(self, row: dict[str, Any]) -> None:
        if len(self.commands) >= MAX_COMMANDS:
            self.reject('input_over_limit', limit=MAX_COMMANDS)
            return
        self.commands.append(row)


class _Parser:
    def __init__(self, reader: _Reader, name: str, directory: str, depth: int,
                 tokens: list[tuple[str, Any, int]], scope: dict[str, Any]):
        self.r, self.name, self.directory, self.depth = reader, name, directory, depth
        self.tokens, self.pos, self.scope = tokens, 0, scope

    def peek(self, offset: int = 0) -> tuple[str, Any, int] | None:
        index = self.pos + offset
        return self.tokens[index] if index < len(self.tokens) else None

    def line(self) -> int:
        token = self.peek() or (self.tokens[-1] if self.tokens else None)
        return token[2] if token else 1

    def take(self, kind: str | None = None, value: Any = None) -> tuple[str, Any, int]:
        token = self.peek()
        if token is None or (kind and token[0] != kind) or (value is not None and token[1] != value):
            raise ConfigError('parser failed near here', self.line())
        self.pos += 1
        return token

    def statements(self, *, top: bool) -> None:
        while True:
            token = self.peek()
            if token is None:
                if not top:
                    raise ConfigError('missing }', self.line())
                return
            if token == ('op', '}', token[2]):
                if top:
                    raise ConfigError('unexpected }', token[2])
                return
            self.statement()

    def block(self, condition: str | None) -> None:
        self.take('op', '{')
        outer = self.scope
        self.scope = {'condition': condition, 'keys': set()}
        self.statements(top=False)
        self.take('op', '}')
        self.scope = outer

    def statement(self) -> None:
        kind, value, line = self.take()
        if kind == 'word' and value in ('include', 'include_shell'):
            target = self.expression()
            if target is _UNRESOLVED:
                self.r.gap('unresolved_value', directive=value, source=self.name, line=line)
            elif not isinstance(target, str):
                raise ConfigError(f'{value} needs a string', line)
            elif value == 'include':
                self.r.include(target, self.directory, self.depth, line, self.name, self.scope)
            else:
                self.r.include_shell(target, self.directory, self.depth, line, self.name, self.scope)
            return
        if kind == 'word' and value == 'global':
            self.block(None)
            return
        if kind == 'cond':
            condition = self.condition(value, line)
            self.block(condition)
            while self.peek() and self.peek()[:2] == ('word', 'else'):
                self.take()
                if self.peek() and self.peek()[0] == 'cond':
                    cond_token = self.take()
                    self.block('else ' + self.condition(cond_token[1], cond_token[2]))
                else:
                    self.block(f'else of {condition}')
            return
        if kind != 'word':
            raise ConfigError('parser failed near here', line)
        operator = self.take('op')[1]
        if operator not in ('=', '+=', ':='):
            raise ConfigError('parser failed near here', line)
        result = self.expression()
        self.assign(value, operator, result, line)

    def condition(self, name: str, line: int) -> str:
        self.take('op', '[')
        field = self.take('str')[1]
        self.take('op', ']')
        operator = self.take('op')[1]
        if operator not in ('==', '!=', '=~', '!~', '=^', '=$'):
            raise ConfigError('bad conditional operator', line)
        pattern = self.expression()
        if pattern is _UNRESOLVED:
            pattern = '?'
        text = f'{name}["{field}"] {operator} "{pattern}"'
        outer = self.scope.get('condition')
        return f'{outer} / {text}' if outer else text

    def assign(self, key: str, operator: str, result: Any, line: int) -> None:
        keys = self.scope['keys']
        if operator == '=' and key in keys:
            raise ConfigError(f'Duplicate config variable: {key}', line)
        keys.add(key)
        values = self.r.values
        if result is _UNRESOLVED:
            values.pop(key, None)
            self.r.gap('unresolved_value', key=key, source=self.name, line=line)
            return
        if operator == '+=' and key in values:
            result = _concat(values[key], result, line)
        if self.scope.get('condition') is None or key.startswith('var.'):
            values[key] = result
        self.record(key, result, line)

    def record(self, key: str, result: Any, line: int) -> None:
        condition = self.scope.get('condition')
        row = {'key': key, 'value': result, 'source': self.name, 'line': line, 'condition': condition}
        if key in LOGGER_KEYS + BACKEND_KEYS:
            self.r.notes.append({'code': 'assignment', **row})

    def expression(self) -> Any:
        result = self.value()
        while self.peek() and self.peek()[:2] == ('op', '+'):
            line = self.take()[2]
            right = self.value()
            result = _UNRESOLVED if _UNRESOLVED in (result, right) else _concat(result, right, line)
        return result

    def value(self) -> Any:
        kind, value, line = self.take()
        if kind in ('str', 'int'):
            return value
        if kind == 'word':
            if value.startswith('env.'):
                found = self.r.env.get(value[4:])
                if found is None:
                    self.r.gap('unresolved_reference', name=value, source=self.name, line=line)
                    return _UNRESOLVED
                return found
            if value in self.r.values:
                return self.r.values[value]
            self.r.gap('unresolved_reference', name=value, source=self.name, line=line)
            return _UNRESOLVED
        if (kind, value) == ('op', '('):
            items: list[Any] = []
            while self.peek() and self.peek()[:2] != ('op', ')'):
                item = self.expression()
                if self.peek() and self.peek()[:2] == ('op', '=>'):
                    self.take()
                    item = (item, self.expression())
                items.append(item)
                if self.peek() and self.peek()[:2] == ('op', ','):
                    self.take()
                elif self.peek() and self.peek()[:2] != ('op', ')'):
                    raise ConfigError('expected , or )', self.line())
            self.take('op', ')')
            return items
        raise ConfigError('parser failed near here', line)


_UNRESOLVED = object()


def _accounts(text: str | None, *, users: bool) -> dict[str, tuple[int, int]] | None:
    if text is None:
        return None
    table: dict[str, tuple[int, int]] = {}
    for raw in text.splitlines():
        parts = raw.split(':')
        if len(parts) >= (7 if users else 4) and parts[2].isdigit() and parts[0] not in table:
                table[parts[0]] = (int(parts[2]), int(parts[3]) if users and parts[3].isdigit() else int(parts[2]))
    return table


def _pairs(value: Any) -> list[tuple[Any, Any]]:
    return [item for item in value if isinstance(item, tuple)] if isinstance(value, list) else []


def _fingerprint(rows: list[dict[str, Any]]) -> str:
    material = [{k: row[k] for k in ('kind', 'argv', 'account', 'condition', 'extension')} for row in rows]
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def evaluate(*, files: Mapping[str, str | bytes | None], globs: Mapping[str, Sequence[str] | None] | None = None,
             include_shell_output: Mapping[str, str | bytes | None] | None = None,
             passwd_text: str | None = None, group_text: str | None = None,
             environment: Mapping[str, str] | None = None, config_path: str = DEFAULT_CONFIG,
             cwd: str | None = '/') -> dict[str, Any]:
    """Report the commands lighttpd runs for ``config_path``.

    ``files`` maps absolute paths to captured text, or None for a path observed
    to be absent. ``globs`` maps an absolute include glob to the paths it
    matched. ``include_shell_output`` maps a command to its captured stdout.
    ``environment`` is the service environment (``SHELL`` and ``env.*``).
    """
    config_path = posixpath.normpath(config_path)
    reader = _Reader(files, globs or {}, include_shell_output or {}, dict(environment or {}), cwd)
    text = files.get(config_path)
    if text is None:
        reader.reject('unobserved_file' if config_path not in files else 'include_not_found', path=config_path)
    else:
        reader.read.append({'path': config_path, 'included_from': None, 'line': None})
        reader.source(config_path, text, posixpath.dirname(config_path), 0, {'condition': None, 'keys': set()})
    passwd = _accounts(passwd_text, users=True)
    groups = _accounts(group_text, users=False)
    username = reader.values.get('server.username')
    groupname = reader.values.get('server.groupname')
    uid = gid = None
    if username is None:
        account, uid, gid = 'invoking_user', None, None
        reader.gap('no_privilege_drop', blocking=False,
                   detail='server.username is unset, so the daemon keeps the invoking account (root at service start)')
    else:
        account = str(username)
        if passwd is None:
            reader.gap('passwd_not_captured')
        elif account not in passwd:
            reader.reject('unknown_user', user=account)
        else:
            uid, gid = passwd[account]
        if groupname is not None and groups is None:
            reader.gap('group_not_captured')
        elif groupname is not None and str(groupname) not in groups:
            reader.reject('unknown_group', group=str(groupname))
        elif groupname is not None:
            gid = groups[str(groupname)][0]
    for note in [n for n in reader.notes if n['code'] == 'assignment']:
        key, value = note['key'], note['value']
        common = {'source': note['source'], 'line': note['line'], 'condition': note['condition'],
                  'account': account, 'uid': uid, 'gid': gid, 'runs': 'daemon_start',
                  'privileged_at_service_start': uid in (None, 0)}
        if key in LOGGER_KEYS and isinstance(value, str) and value.startswith('|'):
            command = value[1:]
            reader.add({'kind': 'piped_logger', 'key': key, 'command': command,
                        'argv': reader.argv(command, note['source'], note['line']), **common})
        elif key in BACKEND_KEYS:
            for extension, hosts in _pairs(value):
                for host in hosts if isinstance(hosts, list) else []:
                    options = dict(_pairs(host) if isinstance(host, list) else [])
                    bin_path = options.get('bin-path')
                    if isinstance(bin_path, str) and bin_path.strip():
                        reader.add({'kind': key.split('.')[0], 'key': key, 'extension': extension,
                                    'command': bin_path, 'argv': bin_path.split(),
                                    'max_procs': options.get('max-procs', 4), **common})
    for row in reader.commands:
        row.setdefault('extension', None)
        row['starts'] = not reader.rejected
    reader.notes = [n for n in reader.notes if n['code'] != 'assignment']
    blocking = [gap for gap in reader.gaps if gap['blocking']]
    return {
        'command_sha256': _fingerprint(reader.commands),
        'contract': 'lighttpd_commands',
        'contract_version': CONTRACT_VERSION,
        'source_version': SOURCE_VERSION,
        'complete': not blocking,
        'config_path': config_path,
        'config_accepted': not reader.rejected,
        'server_user': account,
        'server_uid': uid,
        'server_gid': gid,
        'files': reader.read,
        'commands': reader.commands,
        'root_commands': [i for i, row in enumerate(reader.commands)
                          if row['starts'] and row['privileged_at_service_start']],
        'gaps': reader.gaps,
        'notes': reader.notes,
        'origin': 'not_assessed',
        'authorizes_response': False,
    }
