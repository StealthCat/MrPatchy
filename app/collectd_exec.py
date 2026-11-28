"""Pure collectd exec-plugin contract (roadmap F slice, #1551).

collectd's ``exec`` plugin starts programs named in ``<Plugin exec>`` blocks:
each ``Exec`` program at every read interval while it is not already running,
and each ``NotificationExec`` program once per dispatched notification. The
packaged ``collectd.service`` runs the daemon as root, and a new ``Exec`` line
in ``collectd.conf`` or an included drop-in makes it start a new program on
the next start, as the account written on that line.

This module turns captured configuration text, captured directory listings
for ``Include`` targets and captured ``/etc/passwd`` and ``/etc/group`` text
into the programs the exec plugin starts, with their argv, uid, gid and
supplementary groups. It performs no I/O, never runs collectd or a program and
never authorizes a response action.

The rules follow upstream collectd 5.12.0, checked against native runs of
Ubuntu 24.04 ``collectd-core 5.12.0-17.1build2`` traced with
``strace -f -e trace=execve,setgroups,setgid,setuid``:

- liboconfig's flex scanner picks the longest match, the earlier rule on a
  tie. ``true``/``yes``/``on`` and ``false``/``no``/``off`` are booleans only
  in lower case; numbers (decimal, float, ``0x`` hex and ``0``-led "octal",
  all read by ``strtod`` so ``0755`` is 755) become ``%lf`` strings in argv;
  unquoted strings are ``[0-9A-Za-z_]+`` (IPv4/IPv6 literals too); ``#``
  starts a comment; backslash-newline joins lines; a quoted string ending in
  backslash-newline continues on the next line with its leading blanks
  removed. Any other byte (``-``, ``.``, ``+`` outside a number...) is echoed
  and ignored, so ``foo-bar`` is two arguments.
- Every statement ends with a newline, so a last line without one is a parse
  error. Block names must close with the same case (``</plugin>`` does not
  close ``<Plugin>``). A parse error rejects that file.
- ``Include`` (simple or ``<Include path>`` with ``Filter``) is expanded only
  at the top level of a file, through ``wordexp(WRDE_NOCMD)`` and ``stat``.
  Missing targets are skipped. A directory's entries (not starting with
  ``.``) are read in ``strcmp`` order, recursively, with ``Filter`` applied
  to file basenames; an entry that fails to parse or does not match is
  skipped. A directly included file that fails to parse, or does not match
  its ``Filter``, rejects the including file, and collectd exits when the
  main file is rejected. Nesting is limited to 8 levels.
- Top-level items dispatch in order. A ``<Plugin exec>`` block before
  ``LoadPlugin exec`` is ignored unless ``AutoLoadPlugin`` was set true
  earlier; names compare case-insensitively.
- ``Exec``/``NotificationExec`` (case-insensitive) need at least two string
  arguments and no block; the first is ``user[:group]``, the second the
  program, which ``execvpe`` searches on collectd's ``PATH`` when it has no
  ``/``. argv[0] is the program's basename. Unknown users and uid 0 are
  refused at every start ("Cowardly refusing to exec program as root");
  the uid comes from ``getpwnam`` (a numeric user is a name). The child calls
  ``setgroups([pw_gid, group])``, ``setgid(pw_gid)``, ``setegid(group)`` and
  ``setuid(pw_uid)``. An empty group means the primary group; an unknown
  group is logged and the program still starts with only the primary group.
  A configured group of ``root`` therefore gives the program gid 0.

Unobserved files or listings, unsupported ``wordexp`` input, a relocated
``PluginDir``, unknown accounts databases and a non-root daemon are blocking
gaps, and ``complete`` is false whenever one is present. Other plugins'
configuration and load success are not assessed; a failure there would stop
collectd before any program starts. ``origin`` is always ``not_assessed``
and ``authorizes_response`` is always false.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

CONTRACT_VERSION = 1
SOURCE_VERSION = 'collectd 5.12.0 (Ubuntu 24.04 collectd-core 5.12.0-17.1build2)'

DEFAULT_CONFIG = '/etc/collectd/collectd.conf'
DEFAULT_PLUGIN_DIR = '/usr/lib/collectd'
MAX_DEPTH = 8                 # configfile.c CF_MAX_DEPTH
NAME_BUFFER = 1024            # cf_read_dir: char name[1024]
ARG_BUFFER = 128              # exec_config_exec: char buffer[128]
MAX_TEXT = 1024 * 1024
MAX_FILES = 512
MAX_PROGRAMS = 2000
UID_MAX = 0xFFFFFFFF

# --- scanner -------------------------------------------------------------

_IP_BYTE = r'(?:2(?:5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])'
_PORT = (r'(?:6(?:5(?:5(?:3[0-5]|[0-2][0-9])|[0-4][0-9][0-9])|[0-4][0-9][0-9][0-9])'
         r'|[1-5][0-9][0-9][0-9][0-9]|[1-9][0-9]?[0-9]?[0-9]?)')
_IPV4 = rf'{_IP_BYTE}\.{_IP_BYTE}\.{_IP_BYTE}\.{_IP_BYTE}(?::{_PORT})?'
_H = r'[0-9A-Fa-f]{1,4}'
_V6P = rf'(?:{_H}:{_H}|{_IPV4})'
_IPV6_BASE = (rf'(?:(?:{_H}:){{6}}{_V6P}|::(?:{_H}:){{5}}{_V6P}|(?:{_H})?::(?:{_H}:){{4}}{_V6P}'
              rf'|(?:(?:{_H}:){{0,1}}{_H})?::(?:{_H}:){{3}}{_V6P}'
              rf'|(?:(?:{_H}:){{0,2}}{_H})?::(?:{_H}:){{2}}{_V6P}'
              rf'|(?:(?:{_H}:){{0,3}}{_H})?::{_H}:{_V6P}|(?:(?:{_H}:){{0,4}}{_H})?::{_V6P}'
              rf'|(?:(?:{_H}:){{0,5}}{_H})?::{_H}|(?:(?:{_H}:){{0,6}}{_H})?::)')
_IP_RULES = [re.compile(_IPV4), re.compile(rf'{_IPV6_BASE}|\[{_IPV6_BASE}\](?::{_PORT})?')]
_IP_CHARS = re.compile(r'[0-9A-Fa-f:.\[\]]{1,80}')
_NUMBERS = [re.compile(r'[+-]?[0-9]*\.[0-9]+(?:[eE][+-][0-9]+)?'), re.compile(r'0[xX][0-9a-fA-F]+'),
            re.compile(r'0[0-7]+'), re.compile(r'[+-]?[0-9]+')]
_UNQUOTED = re.compile(r'[0-9A-Za-z_]+')
_BOOLS = (('true', True), ('yes', True), ('on', True), ('false', False), ('no', False), ('off', False))
_BLANK = ' \t\b'

# token kinds (priority order of the flex rules that produce them)
EOL, SLASH, OPEN, CLOSE, BOOL, NUMBER, QUOTED, UNQUOTED = (
    'EOL', 'SLASH', 'OPEN', 'CLOSE', 'BOOL', 'NUMBER', 'QUOTED', 'UNQUOTED')


def _quoted_scan(text: str, start: int) -> tuple[int | None, int | None]:
    """Scan ``([^\\\\"]+|\\\\.)*`` from ``start``.

    Returns ``(close, continuation)``: the index just past a closing ``"``
    and the end of the longest ``\\\\{EOL}`` continuation, either ``None``.
    """
    i, n, cont = start, len(text), None
    while i < n:
        ch = text[i]
        if ch == '"':
            return i + 1, cont
        if ch == '\\':
            if text.startswith('\n', i + 1):
                return None, i + 2
            if text.startswith('\r\n', i + 1):
                cont = i + 3          # `\\.` can still take the CR
            if i + 1 >= n:
                return None, cont
            i += 2
            continue
        i += 1
    return None, cont


def _word_candidates(text: str, pos: int) -> list[tuple[int, int, str, Any]]:
    """Longest-match candidates for rules starting with a letter, digit or sign."""
    found: list[tuple[int, int, str, Any]] = []
    for word, value in _BOOLS:
        if text.startswith(word, pos):
            found.append((len(word), 7, BOOL, value))
            break
    run = _IP_CHARS.match(text, pos)
    # IPv4 literals need a '.', IPv6 literals a ':'; skip the prefix search otherwise.
    if run and ('.' in run.group() or ':' in run.group()):
        for rule_priority, rule in enumerate(_IP_RULES):
            for end in range(run.end(), pos, -1):
                if rule.fullmatch(text, pos, end):
                    found.append((end - pos, 9 + rule_priority, UNQUOTED, text[pos:end]))
                    break
    longest = None
    for rule in _NUMBERS:
        m = rule.match(text, pos)
        if m and (longest is None or m.end() > longest.end()):
            longest = m
    if longest:
        found.append((longest.end() - pos, 11, NUMBER, _strtod(longest.group())))
    m = _UNQUOTED.match(text, pos)
    if m:
        found.append((m.end() - pos, 13, UNQUOTED, m.group()))
    return found


def _strtod(literal: str) -> float:
    if literal.lower().startswith('0x'):
        return float(int(literal, 16))
    return float(literal)


def tokenize(text: str) -> list[tuple[str, Any, int]]:
    """Return ``(kind, value, line)`` tokens as liboconfig's scanner yields them."""
    tokens: list[tuple[str, Any, int]] = []
    pos, n, line = 0, len(text), 1
    multiline: list[str] | None = None
    ml_line = 0

    def advance(end: int) -> None:
        nonlocal pos, line
        line += text.count('\n', pos, end)
        pos = end

    while pos < n:
        if multiline is not None:
            best: tuple[int, int, str] | None = None
            if pos == 0 or text[pos - 1] == '\n':
                end = pos
                while end < n and text[end] in _BLANK:
                    end += 1
                if end > pos:
                    best = (end, 0, 'blank')
            if text[pos] not in _BLANK:
                close, cont = _quoted_scan(text, pos + 1)
                for end, priority, kind in ((cont, 1, 'more'), (close, 2, 'close')):
                    if end is not None and (best is None or end > best[0]):
                        best = (end, priority, kind)
            if best is None:
                advance(pos + 1)          # default rule: ECHO
                continue
            end, _priority, kind = best
            piece = text[pos:end]
            if kind == 'more':
                multiline.append(piece[:-3] if piece.endswith('\r\n') else piece[:-2])
            elif kind == 'close':
                multiline.append(piece)
                tokens.append((QUOTED, _unquote(''.join(multiline)), ml_line))
                multiline = None
            advance(end)
            continue
        ch = text[pos]
        if ch in _BLANK:
            advance(pos + 1)
        elif ch == '#':
            end = text.find('\n', pos)
            advance(n if end < 0 else end)
        elif ch == '\\' and (text.startswith('\n', pos + 1) or text.startswith('\r\n', pos + 1)):
            advance(pos + (2 if text[pos + 1] == '\n' else 3))
        elif ch == '\n' or text.startswith('\r\n', pos):
            tokens.append((EOL, None, line))
            advance(pos + (1 if ch == '\n' else 2))
        elif ch in '/<>':
            tokens.append(({'/': SLASH, '<': OPEN, '>': CLOSE}[ch], ch, line))
            advance(pos + 1)
        elif ch == '"':
            close, cont = _quoted_scan(text, pos + 1)
            if close is not None and (cont is None or close >= cont):
                tokens.append((QUOTED, _unquote(text[pos:close]), line))
                advance(close)
            elif cont is not None:
                piece = text[pos:cont]
                multiline = [piece[:-3] if piece.endswith('\r\n') else piece[:-2]]
                ml_line = line
                advance(cont)
            else:
                advance(pos + 1)
        else:
            candidates = _word_candidates(text, pos)
            if not candidates:
                advance(pos + 1)          # default rule: ECHO
                continue
            length, _priority, kind, value = max(candidates, key=lambda c: (c[0], -c[1]))
            tokens.append((kind, value, line))
            advance(pos + length)
    return tokens


def _unquote(raw: str) -> str:
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return raw
    body, out, i = raw[1:-1], [], 0
    while i < len(body):
        if body[i] == '\\':
            i += 1
            if i >= len(body):
                break
        out.append(body[i])
        i += 1
    return ''.join(out)


# --- parser --------------------------------------------------------------

class ParseError(Exception):
    def __init__(self, line: int, reason: str) -> None:
        super().__init__(reason)
        self.line = line
        self.reason = reason


def _item(key: str, values: list[tuple[str, Any]], line: int,
          children: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {'key': key, 'values': values, 'children': children or [], 'line': line}


def parse(text: str) -> list[dict[str, Any]]:
    """Parse one file into top-level items; raise :class:`ParseError` like yyparse."""
    tokens = tokenize(text)
    last_line = text.count('\n') + 1
    pos = 0

    def peek(offset: int = 0) -> tuple[str, Any, int] | None:
        return tokens[pos + offset] if pos + offset < len(tokens) else None

    def expect(kind: str, reason: str) -> tuple[str, Any, int]:
        nonlocal pos
        tok = peek()
        if tok is None or tok[0] != kind:
            raise ParseError(tok[2] if tok else last_line, reason)
        pos += 1
        return tok

    def arguments() -> list[tuple[str, Any]]:
        nonlocal pos
        values: list[tuple[str, Any]] = []
        while (tok := peek()) is not None and tok[0] in (NUMBER, BOOL, QUOTED, UNQUOTED):
            values.append(('number' if tok[0] == NUMBER else 'boolean' if tok[0] == BOOL else 'string',
                           tok[1]))
            pos += 1
        return values

    def statements(inside: bool) -> list[dict[str, Any]]:
        nonlocal pos
        items: list[dict[str, Any]] = []
        while (tok := peek()) is not None:
            kind = tok[0]
            if kind == EOL:
                pos += 1
            elif kind == UNQUOTED:
                pos += 1
                values = arguments()
                if not values:
                    raise ParseError(tok[2], 'option_without_value')
                expect(EOL, 'expecting_eol')
                items.append(_item(tok[1], values, tok[2]))
            elif kind == OPEN:
                following = peek(1)
                if following is not None and following[0] == SLASH:
                    if inside:
                        return items
                    raise ParseError(tok[2], 'unexpected_block_end')
                pos += 1
                name = expect(UNQUOTED, 'block_name_expected')
                values = arguments()
                expect(CLOSE, 'expecting_close_bracket')
                expect(EOL, 'expecting_eol')
                children = statements(True)
                expect(OPEN, 'block_not_closed')
                expect(SLASH, 'block_not_closed')
                end_name = expect(UNQUOTED, 'block_not_closed')
                expect(CLOSE, 'block_not_closed')
                expect(EOL, 'expecting_eol')
                if end_name[1] != name[1]:
                    raise ParseError(end_name[2], 'block_not_closed')
                if values or children:
                    items.append(_item(name[1], values, tok[2], children))
            else:
                raise ParseError(tok[2], 'unexpected_token')
        if inside:
            raise ParseError(last_line, 'block_not_closed')
        return items

    return statements(False)


# --- include expansion ---------------------------------------------------

_WORDEXP_FAIL = set('|&;<>(){}\n')
_WORDEXP_GAP = set('$`\'"\\~ \t')
_GLOB = set('*?[')


def _norm(path: str) -> str:
    collapsed = re.sub(r'/+', '/', path)
    return collapsed[:-1] if len(collapsed) > 1 and collapsed.endswith('/') else collapsed


def _fnmatch(pattern: str, name: str, *, period: bool) -> bool | None:
    """glibc ``fnmatch`` in the C locale; ``None`` for unsupported classes."""
    if '[:' in pattern or '[=' in pattern or '[.' in pattern:
        return None
    if period and name.startswith('.') and not pattern.startswith('.'):
        return False
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == '\\' and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if ch == '*':
            out.append('.*')
        elif ch == '?':
            out.append('.')
        elif ch == '[':
            j = i + 1
            if j < len(pattern) and pattern[j] in '!^':
                j += 1
            if j < len(pattern) and pattern[j] == ']':
                j += 1
            while j < len(pattern) and pattern[j] != ']':
                j += 1
            if j >= len(pattern):
                out.append(re.escape('['))
            else:
                body = pattern[i + 1:j]
                negate = body[:1] in ('!', '^')
                body = body[1:] if negate else body
                body = body.replace('\\', '\\\\').replace('^', r'\^')
                out.append(('[^' if negate else '[') + body + ']')
                i = j + 1
                continue
        else:
            out.append(re.escape(ch))
        i += 1
    return re.fullmatch(''.join(out), name, re.DOTALL) is not None


def _tag(items: list[dict[str, Any]], path: str) -> None:
    for item in items:
        item['file'] = path
        _tag(item['children'], path)


class _Reader:
    def __init__(self, files: Mapping[str, Any], directories: Mapping[str, Any],
                 parsed: Mapping[str, Any] | None = None) -> None:
        self.files = {_norm(k): v for k, v in files.items()}
        self.directories = {_norm(k): v for k, v in directories.items()}
        self.parsed = {_norm(k): v for k, v in (parsed or {}).items()}
        self.gaps: list[dict[str, Any]] = []
        self.notes: list[dict[str, Any]] = []
        self.read: list[dict[str, Any]] = []

    def gap(self, code: str, *, blocking: bool = True, **detail: Any) -> None:
        entry = {'code': code, 'blocking': blocking, **detail}
        if entry not in self.gaps:
            self.gaps.append(entry)

    def note(self, code: str, **detail: Any) -> None:
        self.notes.append({'code': code, **detail})

    def stat(self, path: str) -> str | None:
        key = _norm(path)
        if key in self.files:
            return 'file' if self.files[key] is not None else None
        if key in self.directories:
            return 'dir' if self.directories[key] is not None else None
        self.gap('path_unobserved', path=key)
        return None

    def wordexp(self, path: str) -> list[str] | None:
        """``wordexp(WRDE_NOCMD)``; ``None`` means it failed."""
        if any(ch in _WORDEXP_FAIL for ch in path):
            self.note('include_wordexp_failed', path=path)
            return None
        if any(ch in _WORDEXP_GAP for ch in path):
            self.gap('include_path_unsupported', path=path)
            return []
        if not path.startswith('/'):
            # Relative to collectd's working directory at configuration time.
            self.gap('include_path_relative', path=path)
            return []
        if not any(ch in _GLOB for ch in path):
            return [path]
        parent, _, last = path.rpartition('/')
        if any(ch in _GLOB for ch in parent):
            self.gap('include_glob_unsupported', path=path)
            return []
        listing = self.directories.get(_norm(parent or '/'), ...)
        if listing is ...:
            self.gap('listing_unobserved', path=_norm(parent or '/'))
            return []
        matches = []
        for name in listing or ():
            hit = _fnmatch(last, name, period=True)
            if hit is None:
                self.gap('include_glob_unsupported', path=path)
                return []
            if hit:
                matches.append(f'{parent}/{name}')
        return sorted(matches) or [path]

    def generic(self, path: str, pattern: str | None, depth: int) -> list[dict[str, Any]] | None:
        if depth >= MAX_DEPTH:
            self.note('include_depth_exceeded', path=path)
            return None
        words = self.wordexp(path)
        if words is None:
            return None
        items: list[dict[str, Any]] = []
        for word in sorted(words):
            kind = self.stat(word)
            if kind is None:
                continue
            got = self.file(word, pattern, depth) if kind == 'file' else self.directory(word, pattern, depth)
            if got is None:
                return None
            items.extend(got)
        return items

    def file(self, path: str, pattern: str | None, depth: int) -> list[dict[str, Any]] | None:
        key = _norm(path)
        if pattern is not None:
            hit = _fnmatch(pattern, key.rpartition('/')[2], period=False)
            if hit is None:
                self.gap('filter_unsupported', pattern=pattern)
                return None
            if not hit:
                self.read.append({'path': key, 'status': 'filtered_out'})
                return None
        if len(self.read) >= MAX_FILES:
            self.gap('too_many_files', limit=MAX_FILES)
            return None
        try:
            if key in self.parsed:
                # Items an agent already parsed from the exact file bytes (#1551 increment 3).
                supplied = self.parsed[key]
                if isinstance(supplied, ParseError):
                    raise supplied
                items = copy.deepcopy(list(supplied))
            else:
                text = self.files[key]
                if isinstance(text, bytes):
                    text = text.decode('utf-8', 'surrogateescape')
                if not isinstance(text, str) or len(text) > MAX_TEXT or '\0' in text:
                    self.gap('file_invalid', path=key)
                    self.read.append({'path': key, 'status': 'not_assessed'})
                    return None
                items = parse(text)
        except ParseError as exc:
            self.read.append({'path': key, 'status': 'parse_error', 'line': exc.line, 'reason': exc.reason})
            return None
        record = {'path': key, 'status': 'parsed'}
        self.read.append(record)
        _tag(items, key)
        result: list[dict[str, Any]] = []
        for item in items:
            if item['key'].lower() != 'include':
                result.append(item)
                continue
            values = item['values']
            if len(values) != 1 or values[0][0] != 'string':
                self.note('include_invalid', file=key, line=item['line'])
                result.append(item)
                continue
            filter_pattern = None
            for child in item['children']:
                if child['key'].lower() == 'filter' and len(child['values']) == 1 \
                        and child['values'][0][0] == 'string':
                    filter_pattern = child['values'][0][1]
                else:
                    self.note('include_option_ignored', file=key, line=child['line'], option=child['key'])
            included = self.generic(values[0][1], filter_pattern, depth + 1)
            if included is None:
                record['status'] = 'rejected'
                record['include_line'] = item['line']
                return None
            result.extend(included)
        return result

    def directory(self, path: str, pattern: str | None, depth: int) -> list[dict[str, Any]] | None:
        listing = self.directories[_norm(path)]
        items: list[dict[str, Any]] = []
        names = [f'{path}/{name}' for name in listing if name and not name.startswith('.')]
        if any(len(name.encode('utf-8', 'surrogateescape')) >= NAME_BUFFER for name in names):
            self.note('include_name_too_long', path=path)
            return None
        for name in sorted(names):
            got = self.generic(name, pattern, depth)
            if got is not None:
                items.extend(got)
        return items


# --- dispatch and the exec plugin ----------------------------------------

def _accounts(text: str | None, *, users: bool) -> dict[str, tuple[int, int]] | None:
    if text is None:
        return None
    rows: dict[str, tuple[int, int]] = {}
    for raw in str(text).splitlines():
        fields = raw.split(':')
        if len(fields) < (7 if users else 3) or not fields[0] or fields[0] in rows:
            continue
        try:
            ident = int(fields[2])
            gid = int(fields[3]) if users else ident
        except ValueError:
            continue
        rows[fields[0]] = (ident, gid)
    return rows


def _argv_text(value: tuple[str, Any]) -> str:
    kind, raw = value
    if kind == 'string':
        return raw
    text = f'{raw:f}' if kind == 'number' else ('true' if raw else 'false')
    return text.encode('utf-8', 'surrogateescape')[:ARG_BUFFER - 1].decode('utf-8', 'surrogateescape')


def _program(child: dict[str, Any], passwd: Mapping[str, tuple[int, int]] | None,
             groups: Mapping[str, tuple[int, int]] | None, reader: _Reader) -> dict[str, Any] | None:
    where = {'file': child.get('file'), 'line': child['line'], 'option': child['key']}
    values = child['values']
    if child['children']:
        reader.note('exec_option_is_block', **where)
        return None
    if len(values) < 2 or values[0][0] != 'string' or values[1][0] != 'string':
        reader.note('exec_option_invalid', **where)
        return None
    user, sep, group = values[0][1].partition(':')
    group_name = group if sep else None
    executable = values[1][1]
    base = executable.rpartition('/')[2]
    argv0 = base.encode('utf-8', 'surrogateescape')[:ARG_BUFFER - 1].decode('utf-8', 'surrogateescape')
    row: dict[str, Any] = {
        'kind': 'notification_exec' if child['key'].lower() == 'notificationexec' else 'exec',
        **where,
        'user': user,
        'group': group_name,
        'executable': executable,
        'path_search': '/' not in executable,
        'argv': [argv0] + [_argv_text(value) for value in values[2:]],
        'uid': None, 'gid': None, 'effective_gid': None, 'supplementary_gids': None,
        'refused': None, 'group_status': None, 'runs_with_root_group': None,
    }
    if passwd is None:
        row['refused'] = 'not_assessed'
        return row
    if user not in passwd:
        row['refused'] = 'unknown_user'
        return row
    uid, gid = passwd[user]
    if uid == 0:
        row['refused'] = 'root_user'
        return row
    egid: int | None
    if group_name is None:
        egid, row['group_status'] = None, 'primary'
    elif group_name == '':
        egid, row['group_status'] = gid, 'primary'
    elif groups is None:
        egid, row['group_status'] = None, 'not_assessed'
    elif group_name in groups:
        egid, row['group_status'] = groups[group_name][0], 'configured'
    else:
        egid, row['group_status'] = None, 'unknown_group_ignored'
    supplementary = [gid] if egid is None or egid == gid else [gid, egid]
    row.update(uid=uid, gid=gid, effective_gid=gid if egid is None else egid,
               supplementary_gids=supplementary,
               runs_with_root_group=0 in supplementary)
    return row


def _is_true(value: tuple[str, Any]) -> bool:
    kind, raw = value
    if kind == 'boolean':
        return bool(raw)
    return kind == 'string' and raw.lower() in ('true', 'yes', 'on')


def _fingerprint(rows: list[dict[str, Any]]) -> str:
    canonical = json.dumps([[r['kind'], r['user'], r['group'], r['executable'], r['argv'], r['uid'],
                             r['effective_gid'], r['refused']] for r in rows],
                           ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8', 'surrogateescape')).hexdigest()


def evaluate(*, files: Mapping[str, str | bytes | None], directories: Mapping[str, Sequence[str] | None]
             | None = None, passwd_text: str | None = None, group_text: str | None = None,
             config_path: str = DEFAULT_CONFIG, collectd_uid: int = 0,
             parsed: Mapping[str, Sequence[dict[str, Any]] | ParseError] | None = None) -> dict[str, Any]:
    """Return the programs collectd's exec plugin starts and the accounts they run as.

    ``files`` maps absolute paths to captured text, or ``None`` when the path
    does not exist; ``directories`` maps absolute paths to their entry names,
    or ``None`` when absent. A path in neither mapping is unobserved.
    ``collectd_uid`` is the daemon's real uid (0 for the packaged service).
    ``parsed`` optionally maps a path in ``files`` to the items :func:`parse`
    returned for it, or the :class:`ParseError` it raised, instead of text.
    """
    reader = _Reader(files or {}, directories or {}, parsed)
    if not isinstance(collectd_uid, int) or isinstance(collectd_uid, bool) \
            or not 0 <= collectd_uid <= UID_MAX:
        reader.gap('collectd_uid_invalid')
    elif collectd_uid != 0:
        # Without root, setgroups is skipped and setuid needs CAP_SETUID.
        reader.gap('collectd_not_root', uid=collectd_uid)
    passwd = _accounts(passwd_text, users=True)
    groups = _accounts(group_text, users=False)
    if passwd is None:
        reader.gap('passwd_not_supplied')
    if group_text is None:
        reader.gap('group_not_supplied')

    items = reader.generic(config_path, None, 0)
    accepted: bool | None = items is not None and bool(items)
    if items is not None and not items:
        reader.note('config_empty', path=config_path)
    loaded, autoload, plugin_dir = False, False, DEFAULT_PLUGIN_DIR
    programs: list[dict[str, Any]] = []
    other_plugins: list[str] = []
    for item in items or []:
        key = item['key'].lower()
        values = item['values']
        name = values[0][1] if values and values[0][0] == 'string' else None
        if key == 'autoloadplugin' and len(values) == 1:
            autoload = _is_true(values[0])
        elif key == 'plugindir' and len(values) == 1 and values[0][0] == 'string':
            plugin_dir = values[0][1]
        elif key == 'loadplugin' and len(values) == 1 and name is not None:
            if name.lower() == 'exec':
                if not loaded and _norm(plugin_dir) != DEFAULT_PLUGIN_DIR:
                    reader.gap('plugin_dir_relocated', plugin_dir=plugin_dir)
                loaded = True
            elif name.lower() not in other_plugins:
                other_plugins.append(name.lower())
        elif key == 'plugin' and name is not None and name.lower() == 'exec':
            if not loaded and autoload:
                if _norm(plugin_dir) != DEFAULT_PLUGIN_DIR:
                    reader.gap('plugin_dir_relocated', plugin_dir=plugin_dir)
                loaded = True
            if not loaded:
                reader.note('exec_block_before_load', file=item.get('file'), line=item['line'])
                continue
            for child in item['children']:
                if child['key'].lower() not in ('exec', 'notificationexec'):
                    reader.note('exec_option_unknown', file=item.get('file'), line=child['line'],
                                option=child['key'])
                    continue
                row = _program(child, passwd, groups, reader)
                if row is not None:
                    if len(programs) >= MAX_PROGRAMS:
                        reader.gap('too_many_programs', limit=MAX_PROGRAMS)
                        break
                    programs.append(row)
    if other_plugins:
        reader.note('other_plugins_not_assessed', plugins=other_plugins)
    if not accepted:
        for row in programs:
            row['starts'] = False
    for row in programs:
        if row['refused'] == 'not_assessed':
            row.setdefault('starts', None)
        row.setdefault('starts', bool(accepted) and row['refused'] is None)
    blocking = [gap for gap in reader.gaps if gap['blocking']]
    return {
        'program_sha256': _fingerprint(programs),
        'contract': 'collectd_exec',
        'contract_version': CONTRACT_VERSION,
        'source_version': SOURCE_VERSION,
        'complete': not blocking,
        'config_path': _norm(config_path),
        'config_accepted': accepted,
        'exec_plugin_loaded': loaded,
        'collectd_uid': collectd_uid,
        'files': reader.read,
        'programs': programs,
        'root_group_programs': [i for i, row in enumerate(programs)
                                if row['starts'] and row['runs_with_root_group']],
        'path_search_note': 'execvpe searches the PATH collectd itself was started with',
        'gaps': reader.gaps,
        'notes': reader.notes,
        'origin': 'not_assessed',
        'authorizes_response': False,
    }
