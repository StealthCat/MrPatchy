"""Pure rsyslog program-action contract (roadmap F slice, #1227).

rsyslogd starts external programs from its configuration: ``omprog`` and
``mmexternal`` actions run their ``binary`` and feed it messages, and the
legacy ``^program`` shell-execute action runs a program once per message. They
run as rsyslogd's user, which is root unless the configuration drops
privileges. This module turns captured configuration text and captured include
directory listings into the program actions rsyslogd creates, the argv each
starts with and the account it runs as. It performs no I/O, never runs
rsyslogd, a program or a shell, and never authorizes a response action.

The rules were observed by running the real rsyslogd 8.2312.0 (Ubuntu 24.04
``rsyslog_8.2312.0-3ubuntu9.4``) on generated configurations with a probe
program that recorded its argv, uid and gid:

- A ``binary`` value is split at its first space into the program and the
  rest. The rest is split at single spaces outside double quotes; quotes stay
  in the argument, single quotes and backslashes are ordinary characters, an
  unbalanced quote runs to the end, two spaces make an empty argument and a
  trailing empty argument is dropped. A tab is not a separator. A value that
  starts with a space has an empty program, and nothing runs.
- ``action(type="omprog"|"mmexternal")`` needs ``module(load=...)`` or
  ``$ModLoad`` of that module earlier in configuration order, including
  include order; otherwise it is a configuration error and no action is
  created.
- ``$ActionOMProgBinary`` takes one word (more words are ignored with an error)
  and is only a known directive after omprog is loaded. A legacy ``:omprog:``
  action uses the most recent value; without one it is not created.
- ``^program`` (up to ``;``) runs the program with the formatted message as
  its only argument and needs no module.
- ``$PrivDropToUser``/``$PrivDropToUserID`` and ``$PrivDropToGroup``/
  ``$PrivDropToGroupID`` are global: their position does not matter and the
  last one wins. Every program child runs as the dropped user; without a group
  directive the group stays root. An unknown user name makes rsyslogd exit at
  startup. ``global(privilege.dropToUser=...)`` is an unknown parameter in
  8.2312.0 and drops nothing; later releases accept it.
- ``include(file=...)`` and ``$IncludeConfig`` expand a glob in sorted order;
  a glob without matches includes nothing and is not an error.

Fail-closed rules: an unobserved file or listing, a glob outside the last path
component, a directory include, unterminated strings or comments, malformed
objects, backtick values, invalid UTF-8, NUL bytes and over-limit input mark
the result incomplete, and affected actions are ``unresolved``. ``origin`` is
always ``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import hashlib
import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('8.2312.0',)
DEFAULT_CONFIG = '/etc/rsyslog.conf'
PROGRAM_MODULES = ('omprog', 'mmexternal')
MAX_TEXT = 262144
MAX_FILES = 256
MAX_DEPTH = 16
MAX_GAPS = 64
MAX_ACTIONS = 256

STATUSES = ('runs', 'module_not_loaded', 'rejected', 'unresolved')
BLOCKING = frozenset({
    'file_not_observed', 'listing_not_observed', 'over_limit', 'invalid_utf8', 'binary', 'syntax',
    'glob_in_directory', 'directory_include', 'relative_include', 'include_depth', 'backtick_value',
    'files_over_limit', 'actions_over_limit', 'gaps_truncated', 'include_text_unsupported',
})
NOT_OBSERVED = (
    'Whether rsyslogd is installed, enabled and running, and which configuration file and module directory its '
    'command line selects.',
    'Which messages reach each action: filters, if-conditions, rulesets and their input bindings are not evaluated.',
    'Whether each program exists and is executable, and what it does.',
    'Whether the dropped user and group names exist on the host; an unknown user name makes rsyslogd exit.',
    'Releases other than 8.2312.0, some of which accept global(privilege.dropToUser=...).',
    'Whether rsyslogd\'s own grammar accepts every statement; a syntax error it cannot recover from stops it from '
    'starting, and no program runs.',
    'Whether rsyslogd stops on configuration errors elsewhere in the files; it normally keeps running with the '
    'actions that loaded.',
)

_PRI_FILTER = re.compile(
    r'[*a-zA-Z0-9]+(?:,[*a-zA-Z0-9]+)*\.[!=<>]*[*a-zA-Z0-9]+'
    r'(?:;[*a-zA-Z0-9]+(?:,[*a-zA-Z0-9]+)*\.[!=<>]*[*a-zA-Z0-9]+)*[ \t]+')
_PROP_FILTER = re.compile(r':[!$a-zA-Z0-9_.-]+[ \t]*,[ \t]*!?[a-zA-Z_-]+[ \t]*,[ \t]*"(?:[^"\\\n]|\\.)*"[ \t]+')
_IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]*')
_PARAM = re.compile(r'[A-Za-z0-9_.-]+')
_ESCAPES = {'\\': '\\', '"': '"', "'": "'", '$': '$', 'b': '\b', 'n': '\n', 't': '\t', 'r': '\r'}
_GLOB = re.compile(r'[*?\[]')


class _Syntax(Exception):
    pass


def split_binary(value: str) -> tuple[str, list[str]]:
    """Return the program and argument list rsyslog builds from a ``binary`` value."""
    program, sep, rest = value.partition(' ')
    if not sep:
        return program, []
    args: list[str] = []
    current = ''
    quoted = False
    for char in rest:
        if char == '"':
            quoted = not quoted
            current += char
        elif char == ' ' and not quoted:
            args.append(current)
            current = ''
        else:
            current += char
    if current:
        args.append(current)
    return program, args


def _glob_match(pattern: str, name: str) -> bool:
    if name.startswith('.') and not pattern.startswith('.'):
        return False
    regex = ''
    index = 0
    while index < len(pattern):
        char = pattern[index]
        index += 1
        if char == '*':
            regex += '.*'
        elif char == '?':
            regex += '.'
        elif char == '[':
            end = pattern.find(']', index + 1 if index < len(pattern) and pattern[index] in '!^' else index)
            if end < 0:
                regex += re.escape(char)
                continue
            body = pattern[index:end]
            index = end + 1
            if body[:1] in ('!', '^'):
                body = '^' + body[1:]
            regex += '[' + body.replace('\\', '\\\\') + ']'
        else:
            regex += re.escape(char)
    return re.fullmatch(regex, name, re.DOTALL) is not None


class _State:
    def __init__(self, files: Mapping[str, str | None], listings: Mapping[str, Iterable[str] | None]):
        self.files = files
        self.listings = listings
        self.gaps: list[dict[str, Any]] = []
        self.loaded: set[str] = set()
        self.legacy_binary: str | None = None
        self.privilege: dict[str, Any] = {'user': None, 'user_source': None, 'group': None, 'group_source': None}
        self.actions: list[dict[str, Any]] = []
        self.read: list[dict[str, Any]] = []
        self.legacy_ruleset: str | None = None
        self.notes: list[str] = []

    def gap(self, code: str, path: str | None, detail: str = '') -> None:
        if len(self.gaps) < MAX_GAPS:
            self.gaps.append({'code': code, 'path': path, 'detail': detail[:240], 'blocking': code in BLOCKING})
        elif self.gaps[-1]['code'] != 'gaps_truncated':
            self.gaps.append({'code': 'gaps_truncated', 'path': None, 'detail': 'Further gaps were not recorded.',
                              'blocking': True})


def _string(text: str, index: int, path: str, line: int) -> tuple[str, int]:
    quote = text[index]
    index += 1
    out = ''
    while index < len(text):
        char = text[index]
        if char == quote:
            return out, index + 1
        if char == '\n' and quote == '`':
            break
        if char == '\\' and quote != '`' and index + 1 < len(text):
            nxt = text[index + 1]
            if nxt in _ESCAPES:
                out += _ESCAPES[nxt]
                index += 2
                continue
            if nxt == 'x' and re.fullmatch(r'[0-9a-fA-F]{2}', text[index + 2:index + 4]):
                out += chr(int(text[index + 2:index + 4], 16))
                index += 4
                continue
            if re.fullmatch(r'[0-7]{3}', text[index + 1:index + 4]):
                out += chr(int(text[index + 1:index + 4], 8))
                index += 4
                continue
        out += char
        index += 1
    raise _Syntax(f'{path}:{line}: unterminated {quote} string')


def _skip_space(text: str, index: int, path: str) -> int:
    while index < len(text):
        if text[index] in ' \t\r\n':
            index += 1
        elif text[index] == '#':
            end = text.find('\n', index)
            index = len(text) if end < 0 else end
        elif text.startswith('/*', index):
            end = text.find('*/', index + 2)
            if end < 0:
                raise _Syntax(f'{path}: unterminated /* comment')
            index = end + 2
        else:
            break
    return index


def _object(text: str, index: int, path: str, line: int) -> tuple[dict[str, Any], int]:
    """Parse ``(name="value" ...)`` starting at the opening parenthesis."""
    params: dict[str, Any] = {}
    index += 1
    while True:
        index = _skip_space(text, index, path)
        if index >= len(text):
            raise _Syntax(f'{path}:{line}: unterminated object')
        if text[index] == ')':
            return params, index + 1
        match = _PARAM.match(text, index)
        if not match:
            raise _Syntax(f'{path}:{line}: unexpected {text[index]!r} in object')
        name = match.group(0).lower()
        index = _skip_space(text, match.end(), path)
        if index >= len(text) or text[index] != '=':
            raise _Syntax(f'{path}:{line}: parameter {name!r} has no value')
        index = _skip_space(text, index + 1, path)
        if index >= len(text):
            raise _Syntax(f'{path}:{line}: parameter {name!r} has no value')
        char = text[index]
        if char in '"\'`':
            value, index = _string(text, index, path, line)
            params[name] = {'backtick': True, 'value': value} if char == '`' else value
        elif char == '[':
            items: list[str] = []
            index += 1
            while True:
                index = _skip_space(text, index, path)
                if index < len(text) and text[index] == ']':
                    index += 1
                    break
                if index >= len(text) or text[index] not in '"\'':
                    raise _Syntax(f'{path}:{line}: malformed array for {name!r}')
                item, index = _string(text, index, path, line)
                items.append(item)
                index = _skip_space(text, index, path)
                if index < len(text) and text[index] == ',':
                    index += 1
            params[name] = items
        else:
            end = index
            while end < len(text) and text[end] not in ' \t\r\n)':
                end += 1
            params[name] = text[index:end]
            index = end


def _module_name(value: str) -> str:
    name = posixpath.basename(value.strip())
    return name[:-3] if name.endswith('.so') else name


def _add_action(state: _State, entry: dict[str, Any]) -> None:
    if len(state.actions) >= MAX_ACTIONS:
        state.gap('actions_over_limit', entry['file'])
        return
    state.actions.append(entry)


def _program_action(state: _State, kind: str, path: str, line: int, ruleset: str | None, binary: Any,
                    module: str | None) -> None:
    entry: dict[str, Any] = {'kind': kind, 'file': path, 'line': line, 'ruleset': ruleset, 'binary': None,
                             'program': None, 'argv': None, 'reason': None}
    if isinstance(binary, dict):
        entry.update(status='unresolved', reason='The binary value is a backtick expression rsyslogd evaluates '
                                                 'when it loads the configuration.')
        state.gap('backtick_value', path, f'line {line}')
    elif module and module not in state.loaded:
        entry.update(status='module_not_loaded', reason=f'{module} is not loaded before this action, so '
                                                         'rsyslogd reports an error and creates no action.')
    elif not isinstance(binary, str):
        entry.update(status='rejected', reason='No binary is set, so rsyslogd creates no action.')
    else:
        program, args = split_binary(binary)
        entry['binary'] = binary
        if not program:
            entry.update(status='rejected', reason='The binary value starts with a space, so the program is empty.')
        else:
            entry.update(status='runs', program=program,
                         argv=[program, *args] if kind != 'shell_execute' else [program, '<formatted message>'],
                         binary_sha256=hashlib.sha256(binary.encode()).hexdigest())
    _add_action(state, entry)


def _include(state: _State, pattern: str, source: str, depth: int, line: int) -> None:
    if not pattern.startswith('/'):
        state.gap('relative_include', source, f'line {line}: {pattern[:200]}')
        return
    if pattern.endswith('/'):
        state.gap('directory_include', source, f'line {line}: {pattern[:200]}')
        return
    directory, base = posixpath.split(pattern)
    if _GLOB.search(directory):
        state.gap('glob_in_directory', source, f'line {line}: {pattern[:200]}')
        return
    if not _GLOB.search(base):
        if pattern in state.files:
            _file(state, pattern, depth + 1, source)
        else:
            state.gap('file_not_observed', pattern, f'included from {source}:{line}')
        return
    listing = state.listings.get(directory)
    if listing is None:
        state.gap('listing_not_observed', directory, f'included from {source}:{line}')
        return
    names = sorted({name for name in listing if isinstance(name, str) and '/' not in name},
                   key=lambda name: name.encode('utf-8', 'surrogateescape'))
    for name in names:
        if _glob_match(base, name):
            _file(state, posixpath.join(directory, name), depth + 1, source)


def _legacy(state: _State, text: str, path: str, line: int, depth: int) -> None:
    directive, _, rest = text[1:].partition(' ')
    directive = directive.strip().lower()
    words = rest.split()
    word = words[0] if words else ''
    if directive == 'modload' and word:
        state.loaded.add(_module_name(word))
    elif directive == 'includeconfig' and word:
        _include(state, word, path, depth, line)
    elif directive in ('privdroptouser', 'privdroptouserid') and word:
        state.privilege.update(user=word, user_source=f'{path}:{line}', user_is_id=directive.endswith('id'))
    elif directive in ('privdroptogroup', 'privdroptogroupid') and word:
        state.privilege.update(group=word, group_source=f'{path}:{line}', group_is_id=directive.endswith('id'))
    elif directive == 'actionomprogbinary' and 'omprog' in state.loaded:
        state.legacy_binary = word or None
    elif directive == 'ruleset' and word:
        state.legacy_ruleset = word


def _legacy_action(state: _State, text: str, index: int, path: str, line: int,
                   ruleset: str | None = None) -> int | None:
    """Handle a legacy action at ``index``; return the end of line, or None for a RainerScript action."""
    end = text.find('\n', index)
    end = len(text) if end < 0 else end
    action = text[index:end]
    ruleset = state.legacy_ruleset if ruleset is None else ruleset
    if action.startswith(':omprog:'):
        _program_action(state, 'legacy_omprog', path, line, ruleset, state.legacy_binary, 'omprog')
        return end
    if action.startswith('^'):
        program = action[1:].split(';', 1)[0].rstrip(' \t\r')
        _program_action(state, 'shell_execute', path, line, ruleset, program, None)
        return end
    if action.startswith('action') or action.startswith('{') or action.startswith('call'):
        return None
    return end


def _scan(state: _State, text: str, path: str, depth: int) -> None:
    index = 0
    line = 1
    line_start = True
    in_expr = False
    rulesets: list[str | None] = []
    pending_ruleset: str | None = None
    while index < len(text):
        char = text[index]
        if char == '\n':
            line += 1
            line_start = True
            index += 1
            continue
        if char in ' \t\r':
            index += 1
            continue
        if line_start and not in_expr:
            line_start = False
            if char == '$':
                end = text.find('\n', index)
                end = len(text) if end < 0 else end
                _legacy(state, text[index:end].rstrip('\r'), path, line, depth)
                index = end
                continue
            match = _PRI_FILTER.match(text, index) or _PROP_FILTER.match(text, index)
            if char == '&':
                match = re.compile(r'&[ \t]*').match(text, index)
            if match:
                # A selector or ``&`` line inside ``ruleset(){}`` binds its action to that ruleset, exactly like
                # a RainerScript ``action()`` on the same line.
                end = _legacy_action(state, text, match.end(), path, line, rulesets[-1] if rulesets else None)
                index = match.end() if end is None else end
                continue
        line_start = False
        if char == '#':
            end = text.find('\n', index)
            index = len(text) if end < 0 else end
            continue
        if text.startswith('/*', index):
            end = text.find('*/', index + 2)
            if end < 0:
                raise _Syntax(f'{path}:{line}: unterminated /* comment')
            line += text.count('\n', index, end)
            index = end + 2
            continue
        if char in '"\'`':
            value_end = _string(text, index, path, line)[1]
            line += text.count('\n', index, value_end)
            index = value_end
            continue
        if not in_expr and (char == '^' or text.startswith(':omprog:', index)):
            # rsyslog's lexer accepts a legacy action wherever a statement may start: at top level, after
            # ``else``, inside ``{ ... }`` blocks and after ``&``, not only after a selector or ``then``.
            index = _legacy_action(state, text, index, path, line, rulesets[-1] if rulesets else None)
            continue
        if char == '{':
            rulesets.append(pending_ruleset if pending_ruleset is not None else (rulesets[-1] if rulesets else None))
            pending_ruleset = None
            index += 1
            continue
        if char == '}':
            if rulesets:
                rulesets.pop()
            index += 1
            continue
        match = _IDENT.match(text, index)
        if not match:
            index += 1
            continue
        word = match.group(0).lower()
        index = match.end()
        if word == 'if':
            in_expr = True
            continue
        if word == 'then':
            in_expr = False
            after = _skip_space(text, index, path)
            if text.startswith(':omprog:', after) or text.startswith('^', after):
                line += text.count('\n', index, after)
                index = _legacy_action(state, text, after, path, line,
                                       rulesets[-1] if rulesets else None) or after
            continue
        after = _skip_space(text, index, path)
        if word not in ('action', 'module', 'global', 'include', 'ruleset') or after >= len(text) \
                or text[after] != '(':
            continue
        params, end = _object(text, after, path, line)
        object_line = line
        line += text.count('\n', index, end)
        index = end
        current = rulesets[-1] if rulesets else state.legacy_ruleset
        if word == 'module':
            load = params.get('load')
            if isinstance(load, str):
                state.loaded.add(_module_name(load))
        elif word == 'ruleset':
            name = params.get('name')
            pending_ruleset = name if isinstance(name, str) else None
        elif word == 'global':
            if any(key.startswith('privilege.') for key in params):
                state.notes.append(f'{path}:{object_line}: global(privilege.*) is an unknown parameter in '
                                   '8.2312.0 and drops nothing.')
        elif word == 'include':
            if 'text' in params:
                state.gap('include_text_unsupported', path, f'line {object_line}')
            target = params.get('file')
            if isinstance(target, dict):
                state.gap('backtick_value', path, f'line {object_line}')
            elif isinstance(target, str):
                _include(state, target, path, depth, object_line)
        elif word == 'action':
            kind = params.get('type')
            if isinstance(kind, str) and kind.lower() in PROGRAM_MODULES:
                _program_action(state, kind.lower(), path, object_line, current, params.get('binary'), kind.lower())


def _file(state: _State, path: str, depth: int, included_from: str | None) -> None:
    if depth > MAX_DEPTH:
        state.gap('include_depth', path, f'included from {included_from}')
        return
    if len(state.read) >= MAX_FILES:
        state.gap('files_over_limit', path)
        return
    raw = state.files.get(path)
    record: dict[str, Any] = {'path': path, 'included_from': included_from, 'status': 'read'}
    state.read.append(record)
    if raw is None:
        record['status'] = 'not_observed'
        state.gap('file_not_observed', path, f'included from {included_from}' if included_from else '')
        return
    if isinstance(raw, bytes):
        try:
            raw = raw.decode('utf-8')
        except UnicodeDecodeError:
            record['status'] = 'invalid'
            state.gap('invalid_utf8', path)
            return
    if '\0' in raw:
        record['status'] = 'invalid'
        state.gap('binary', path)
        return
    if len(raw.encode('utf-8', 'surrogatepass')) > MAX_TEXT:
        record['status'] = 'invalid'
        state.gap('over_limit', path)
        return
    record['sha256'] = hashlib.sha256(raw.encode('utf-8', 'surrogatepass')).hexdigest()
    first_action = len(state.actions)
    try:
        _scan(state, raw, path, depth)
    except _Syntax as exc:
        record['status'] = 'syntax_error'
        state.gap('syntax', path, str(exc))
        for action in state.actions[first_action:]:
            action.update(status='unresolved', reason='A later syntax error in this file was not resolved.')


def _account(value: str | None, is_id: bool, default: str) -> dict[str, Any]:
    if value is None:
        return {'name': default, 'id': 0, 'source': 'default'}
    if is_id:
        return {'name': None, 'id': int(value) if value.isdigit() else None, 'source': 'configured'}
    return {'name': value, 'id': 0 if value == default else None, 'source': 'configured'}


def resolve(files: Mapping[str, str | bytes | None], listings: Mapping[str, Iterable[str] | None] | None = None,
            config: str = DEFAULT_CONFIG) -> dict[str, Any]:
    """Resolve the program actions rsyslogd creates from captured configuration."""
    state = _State(files, listings or {})
    _file(state, config, 0, None)
    privilege = state.privilege
    user = _account(privilege['user'], bool(privilege.get('user_is_id')), 'root')
    group = _account(privilege['group'], bool(privilege.get('group_is_id')), 'root')
    user['source_location'] = privilege['user_source']
    group['source_location'] = privilege['group_source']
    for action in state.actions:
        if action['status'] == 'runs':
            action['runs_as'] = {'user': user, 'group': group}
    complete = not any(gap['blocking'] for gap in state.gaps)
    if not complete:
        for action in state.actions:
            if action['status'] == 'runs':
                action['complete'] = False
    return {
        'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS),
        'config': config,
        'complete': complete,
        'privilege': {'user': user, 'group': group,
                      'drops_root': user['id'] != 0},
        'loaded_modules': sorted(state.loaded),
        'actions': state.actions,
        'files': state.read,
        'gaps': state.gaps,
        'notes': state.notes,
        'not_observed': list(NOT_OBSERVED),
        'origin': 'not_assessed',
    }
