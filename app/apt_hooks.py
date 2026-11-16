"""Pure APT configuration hook contract (roadmap F slice, #950).

Takes captured, read-only observations of ``/etc/apt/apt.conf.d`` entries and
``/etc/apt/apt.conf`` and returns the effective APT options that make root run
commands or replace the programs APT runs:

- ``command``: ``APT::Update::{Pre,Post}-Invoke``, ``APT::Update::Post-Invoke-Success``,
  ``DPkg::{Pre,Post}-Invoke`` and ``DPkg::Pre-Install-Pkgs`` list items. APT runs
  each non-empty item through ``sh -c`` as the invoking user (normally root).
- ``proxy_command``: ``Acquire::<method>::Proxy-Auto-Detect`` (and the older
  ``ProxyAutoDetect`` spelling), a program APT executes to find a proxy.
- ``binary_override``: ``Dir::Bin::<name>``, which replaces a program APT runs.
- ``path_override``: ``DPkg::Path``, the ``PATH`` dpkg and its hooks run with.
- ``dpkg_options``: ``DPkg::Options`` list items passed to every dpkg call.

``Binary::<program>::`` scoped copies of these options are reported with that
program as their ``scope``; they apply only when that APT front end runs.

File eligibility and order follow apt.conf(5) and APT's ``Dir::Etc::Parts``
listing: hidden and non-regular entries are skipped, a name must have no
extension or the ``conf`` extension and consist of ``[A-Za-z0-9_.:-]``, the
default ``Dir::Ignore-Files-Silently`` patterns are skipped silently, eligible
files are read in byte order, and the main ``apt.conf`` is read last.

Syntax follows APT's configuration parser: ``//``, ``/* */`` and ``#`` comments,
``A::B "value";`` and unquoted values, nested ``A { B "v"; };`` blocks, list
items (``A { "x"; };`` and ``A:: "x";``), ``#clear`` and ``#include``. Keys are
case-insensitive. A later scalar or tagged child overrides an earlier one, an
untagged item appends, and ``#clear`` removes the subtree. Hook lists execute
only their child items; a scalar set on the list node itself is reported as
inert, because APT never runs it.

It performs no I/O, never sources, includes or runs anything and never
authorizes a response action. Fail-closed rules:

- A syntax error (including a quoted value left open at the end of a line or
  a quoted string touching other text, which this contract does not interpret) makes APT's behavior
  ``undetermined``: APT refuses to run with an unparsable file. Statements
  before the error are still applied so their hooks stay visible.
- ``#include`` targets are never followed and become gaps, as do unreadable
  or oversized files, a ``Dir``/``Dir::Etc``/parts/main directory override,
  over-cap input, an uncollected main file and the unobservable ``APT_CONFIG``
  environment. Any gap that can hide or change effective options makes the
  result ``undetermined``.
- Recognized options are a fixed list; other options are not evaluated and the
  result is never a safety verdict.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
PARTS_DIR = '/etc/apt/apt.conf.d'
MAIN_FILE = '/etc/apt/apt.conf'
MAX_FILES = 512
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_STATEMENTS = 20000
MAX_DEPTH = 32
MAX_NAME = 255
MAX_VALUE = 4096
MAX_HOOKS = 512
MAX_GAPS = 256

# APT's default Dir::Ignore-Files-Silently list.
SILENT_IGNORE = tuple(re.compile(p) for p in (
    r'~$', r'\.disabled$', r'\.bak$', r'\.dpkg-[a-z]+$', r'\.ucf-[a-z]+$', r'\.save$', r'\.orig$',
    r'\.distUpgrade$'))
_NAME_CHARS = re.compile(r'[A-Za-z0-9_.:-]+')

COMMAND_LISTS = {
    ('apt', 'update', 'pre-invoke'): 'APT::Update::Pre-Invoke',
    ('apt', 'update', 'post-invoke'): 'APT::Update::Post-Invoke',
    ('apt', 'update', 'post-invoke-success'): 'APT::Update::Post-Invoke-Success',
    ('dpkg', 'pre-invoke'): 'DPkg::Pre-Invoke',
    ('dpkg', 'post-invoke'): 'DPkg::Post-Invoke',
    ('dpkg', 'pre-install-pkgs'): 'DPkg::Pre-Install-Pkgs',
}
DIRECTORY_KEYS = {('dir',), ('dir', 'etc'), ('dir', 'etc', 'parts'), ('dir', 'etc', 'main')}
KINDS = ('command', 'proxy_command', 'binary_override', 'path_override', 'dpkg_options')
NOT_A_VERDICT = ('Effective APT hook options are reported for review only. They are not a safety verdict, '
                 'and unrecognized options are not evaluated.')


class _Syntax(Exception):
    def __init__(self, line: int, detail: str):
        super().__init__(detail)
        self.line = line
        self.detail = detail


class _Node:
    __slots__ = ('tag', 'value', 'source', 'children')

    def __init__(self, tag: str | None):
        self.tag = tag  # original spelling; None for an untagged list item
        self.value: str | None = None
        self.source: tuple[str, int] | None = None
        self.children: list[_Node] = []

    def child(self, tag: str, create: bool) -> _Node | None:
        folded = tag.lower()
        for node in self.children:
            if node.tag is not None and node.tag.lower() == folded:
                return node
        if not create:
            return None
        node = _Node(tag)
        self.children.append(node)
        return node


def _gap(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {'code': code, 'detail': detail, **extra}


def eligibility(name: str) -> dict[str, Any]:
    """Return whether APT reads a regular file named ``name`` from the parts directory."""
    if name.startswith('.'):
        return {'read': False, 'reason': 'hidden', 'notice': False}
    silent = any(p.search(name) for p in SILENT_IGNORE)
    if '.' in name and name.rsplit('.', 1)[1] != 'conf':
        return {'read': False, 'reason': 'extension', 'notice': not silent}
    if not _NAME_CHARS.fullmatch(name):
        return {'read': False, 'reason': 'invalid_character', 'notice': not silent}
    return {'read': True, 'reason': None, 'notice': False}


def _strip_comments(text: str) -> tuple[list[tuple[int, str]], _Syntax | None]:
    """Remove comments; return (line number, remaining text) pairs before any error, and the error."""
    out: list[tuple[int, str]] = []
    in_block = False
    for number, raw in enumerate(text.split('\n'), 1):
        kept: list[str] = []
        quote = False
        i = 0
        while i < len(raw):
            c = raw[i]
            if in_block:
                if raw.startswith('*/', i):
                    in_block = False
                    i += 2
                    if raw.startswith('/', i):
                        # APT 2.8.3 drops or rejects the rest of the line when ``*/`` is
                        # directly followed by ``/`` (``a/*c*//*d*/b``); not interpreted here.
                        return out, _Syntax(number, 'A /* */ comment is directly followed by a slash.')
                else:
                    i += 1
                continue
            if c == '"':
                quote = not quote
            elif not quote:
                if raw.startswith('//', i):
                    break
                if raw.startswith('/*', i):
                    # APT deletes the comment without leaving a separator, so text on both
                    # sides of a same-line comment joins into one word (``ev/*x*/il`` is ``evil``).
                    in_block = True
                    i += 2
                    continue
                if c == '#' and not (raw.startswith('#clear', i) or raw.startswith('#include', i)):
                    break
            kept.append(c)
            i += 1
        if quote:
            return out, _Syntax(number, 'A quoted value is not closed on its line.')
        out.append((number, ''.join(kept)))
    if in_block:
        return out, _Syntax(len(out), 'A /* comment is never closed.')
    return out, None


_TOKEN = re.compile(r'\s*(?:(")([^"]*)"|([{};])|([^\s{};"]+))')


def _tokens(text: str) -> tuple[list[tuple[int, str, str]], _Syntax | None]:
    """Return (line, kind, text) tokens before any error, and the error.

    ``kind`` is ``str``, ``word`` or the punctuation itself.
    """
    tokens: list[tuple[int, str, str]] = []
    lines, error = _strip_comments(text)
    for number, line in lines:
        pos = 0
        while pos < len(line):
            match = _TOKEN.match(line, pos)
            if not match or match.end() == pos:
                if line[pos:].strip():
                    return tokens, _Syntax(number, 'Unexpected text.')
                break
            pos = match.end()
            quoted = bool(match.group(1))
            if (quoted or match.group(4)) and pos < len(line) and (
                    line[pos] == '"' or (quoted and line[pos] not in ' \t\r\f\v{};')):
                # APT joins a word and an adjacent quoted string into one word (``x"a"`` is
                # ``xa``, ``#clear"A"`` is not a directive). This contract does not interpret that.
                return tokens, _Syntax(number, 'A quoted string touches other text.')
            if match.group(1):
                tokens.append((number, 'str', match.group(2)))
            elif match.group(3):
                tokens.append((number, match.group(3), match.group(3)))
            elif match.group(4):
                tokens.append((number, 'word', match.group(4)))
    return tokens, error


def _statements(text: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Parse ``text`` into flat statements; returns (statements, syntax error or None)."""
    statements: list[dict[str, Any]] = []
    stack: list[list[str]] = []
    # Tokens before a lexical error are still parsed so their statements stay visible.
    tokens, lexical = _tokens(text)
    i = 0

    def key_path(word: str, line: int) -> list[str]:
        parts = word.split('::')
        if any(p == '' for p in parts[:-1]):
            raise _Syntax(line, 'An option name has an empty component.')
        return parts

    try:
        while i < len(tokens):
            if len(statements) >= MAX_STATEMENTS:
                raise _Syntax(tokens[i][0], 'Too many statements.')
            line, kind, value = tokens[i]
            prefix = [p for frame in stack for p in frame]
            if kind == ';':
                i += 1
                continue
            if kind == '}':
                if not stack:
                    raise _Syntax(line, 'A closing brace has no matching block.')
                stack.pop()
                i += 1
                continue
            if kind == 'word' and value in ('#clear', '#include'):
                # APT accepts directives only at the top level and with exactly one argument
                # ("Directives can only be done at the top level", "Extra junk after value").
                if stack:
                    raise _Syntax(line, value + ' is only valid at the top level.')
                args: list[str] = []
                i += 1
                while i < len(tokens) and tokens[i][1] in ('word', 'str'):
                    args.append(tokens[i][2])
                    i += 1
                if i >= len(tokens) or tokens[i][1] != ';' or len(args) != 1:
                    raise _Syntax(line, value + ' needs exactly one argument and a terminating semicolon.')
                i += 1
                op = 'clear' if value == '#clear' else 'include'
                arg = args[0]
                if op == 'include':
                    statements.append({'op': 'include', 'target': arg, 'line': line})
                    continue
                path = key_path(arg, line)
                if not any(path):
                    raise _Syntax(line, '#clear needs an option name.')
                if path[-1] == '':
                    # ``#clear A::;`` names an empty child of A, so APT clears nothing.
                    continue
                statements.append({'op': 'clear', 'path': path, 'line': line})
                continue
            if kind == 'str':
                # An untagged item inside a block: ``{ "value"; }``.
                if not stack:
                    raise _Syntax(line, 'A value has no option name.')
                if i + 1 >= len(tokens) or tokens[i + 1][1] not in (';', '}'):
                    raise _Syntax(line, 'A list item must end with a semicolon.')
                statements.append({'op': 'set', 'path': prefix + [''], 'value': value, 'line': line})
                i += 2 if tokens[i + 1][1] == ';' else 1
                continue
            if kind != 'word' or value.startswith('#'):
                raise _Syntax(line, 'Expected an option name.')
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            if nxt and nxt[1] in (';', '}'):
                # APT reads a bare word as an untagged item of the enclosing block, or of the
                # root at the top level (``DPkg::Post-Invoke::T;`` adds an item whose value is
                # the text; it creates no ``T`` option). The word is never split on ``::``.
                statements.append({'op': 'set', 'path': prefix + [''], 'value': value, 'line': line})
                i += 2 if nxt[1] == ';' else 1
                continue
            path = key_path(value, line)
            if nxt and nxt[1] == '{':
                if path[-1] == '' or len(stack) >= MAX_DEPTH:
                    raise _Syntax(line, 'Unsupported block name or nesting.')
                stack.append(path)
                i += 2
                continue
            if nxt and nxt[1] in ('str', 'word'):
                after = tokens[i + 2] if i + 2 < len(tokens) else None
                if not after or after[1] not in (';', '}'):
                    raise _Syntax(line, 'An option value must end with a semicolon.')
                statements.append({'op': 'set', 'path': prefix + path, 'value': nxt[2], 'line': line})
                i += 3 if after[1] == ';' else 2
                continue
            raise _Syntax(line, 'An option must end with a semicolon.')
        if lexical:
            raise lexical
        if stack:
            raise _Syntax(tokens[-1][0] if tokens else 1, 'A block is never closed.')
    except _Syntax as error:
        # A lexical error truncates the token stream, so it explains any statement it cut short.
        error = lexical or error
        return statements, {'line': error.line, 'detail': error.detail}
    return statements, None


def _apply(root: _Node, statement: dict[str, Any], source: tuple[str, int]) -> None:
    path = statement['path']
    if statement['op'] == 'clear':
        node = root
        for tag in path[:-1]:
            node = node.child(tag, False)
            if node is None:
                return
        folded = path[-1].lower()
        node.children = [c for c in node.children if c.tag is None or c.tag.lower() != folded]
        return
    node = root
    for tag in path[:-1]:
        node = node.child(tag, True)
    if path[-1] == '':
        target = _Node(None)
        node.children.append(target)
    else:
        target = node.child(path[-1], True)
    target.value = statement['value']
    target.source = source


def _lookup(node: _Node, path: tuple[str, ...]) -> _Node | None:
    for tag in path:
        found = node.child(tag, False)
        if found is None:
            return None
        node = found
    return node


def _entry(option: str, kind: str, node: _Node, scope: str | None, executed: bool) -> dict[str, Any]:
    value = node.value or ''
    return {'option': option, 'kind': kind, 'scope': scope, 'tag': node.tag,
            'value': value[:MAX_VALUE], 'truncated': len(value) > MAX_VALUE, 'executed': executed,
            'shell': executed and kind == 'command',
            'source': {'path': node.source[0], 'line': node.source[1]} if node.source else None}


def _hooks(base: _Node, scope: str | None) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    prefix = f'Binary::{scope}::' if scope else ''
    for path, option in COMMAND_LISTS.items():
        node = _lookup(base, path)
        if node is None:
            continue
        if node.value:
            found.append(_entry(prefix + option, 'command', node, scope, False))
        found.extend(_entry(prefix + option, 'command', c, scope, True) for c in node.children if c.value)
    acquire = _lookup(base, ('acquire',))
    for method in acquire.children if acquire else ():
        if method.tag is None:
            continue
        for spelling in ('Proxy-Auto-Detect', 'ProxyAutoDetect'):
            node = method.child(spelling, False)
            if node is not None and node.value:
                found.append(_entry(f'{prefix}Acquire::{method.tag}::{spelling}', 'proxy_command', node, scope, True))
    binaries = _lookup(base, ('dir', 'bin'))
    for node in binaries.children if binaries else ():
        if node.tag is not None and node.value:
            found.append(_entry(f'{prefix}Dir::Bin::{node.tag}', 'binary_override', node, scope, True))
    node = _lookup(base, ('dpkg', 'path'))
    if node is not None and node.value:
        found.append(_entry(prefix + 'DPkg::Path', 'path_override', node, scope, True))
    node = _lookup(base, ('dpkg', 'options'))
    if node is not None:
        found.extend(_entry(prefix + 'DPkg::Options', 'dpkg_options', c, scope, True) for c in node.children if c.value)
    return found


def _content(entry: Any) -> tuple[str | None, str | None]:
    """Return (text, problem) for a captured file observation."""
    content = entry.get('content') if isinstance(entry, dict) else None
    if not isinstance(content, str):
        return None, 'unreadable'
    if len(content.encode('utf-8', 'surrogatepass')) > MAX_FILE_BYTES:
        return None, 'too_large'
    return content, None


def resolve(parts: Any, main: Any = None) -> dict[str, Any]:
    """Resolve effective APT hook options from captured observations.

    ``parts`` is the list of ``/etc/apt/apt.conf.d`` entries, each a dict with
    ``name``, ``type`` (``file`` for a regular file or a link to one, otherwise
    anything else) and ``content`` (text, or ``None`` when unreadable). ``None``
    means the directory was not collected. ``main`` describes
    ``/etc/apt/apt.conf`` as ``{'present': bool, 'content': text|None}``;
    ``None`` means it was not collected.
    """
    gaps: list[dict[str, Any]] = [_gap(
        'apt_config_env_unobserved',
        'A file named by the APT_CONFIG environment of a particular APT run is read first and cannot be observed.')]
    undetermined = False
    files: list[dict[str, Any]] = []
    root = _Node('')
    total = 0

    def add_gap(code: str, detail: str, **extra: Any) -> None:
        nonlocal undetermined
        undetermined = True
        if len(gaps) < MAX_GAPS:
            gaps.append(_gap(code, detail, **extra))
        elif gaps[-1]['code'] != 'gap_limit':
            gaps.append(_gap('gap_limit', 'Further coverage gaps were omitted.'))

    def read(path: str, text: str) -> str:
        statements, error = _statements(text)
        for statement in statements:
            if statement['op'] == 'include':
                add_gap('include_not_followed', 'An #include target is not followed by this contract.',
                        path=path, line=statement['line'], target=statement['target'][:MAX_VALUE])
                continue
            if statement['op'] == 'set' and tuple(p.lower() for p in statement['path']) in DIRECTORY_KEYS:
                add_gap('directory_override', 'The configuration changes where APT reads its configuration.',
                        path=path, line=statement['line'])
            _apply(root, statement, (path, statement['line']))
        if error:
            add_gap('syntax_error', 'This contract could not parse the file; APT may reject it or read it differently.',
                    path=path, line=error['line'], reason=error['detail'])
            return 'syntax_error'
        return 'parsed'

    if parts is None:
        add_gap('parts_not_collected', f'{PARTS_DIR} was not collected.')
    elif not isinstance(parts, list):
        add_gap('invalid_observation', f'The {PARTS_DIR} observation is malformed.')
    else:
        if len(parts) > MAX_FILES:
            add_gap('file_limit', f'Only the first {MAX_FILES} entries were evaluated.')
        candidates = []
        for entry in parts[:MAX_FILES]:
            name = entry.get('name') if isinstance(entry, dict) else None
            if (not isinstance(name, str) or not name or len(name) > MAX_NAME or '/' in name
                    or name in ('.', '..') or any(ord(c) < 32 or ord(c) == 127 for c in name)):
                add_gap('invalid_entry', 'An entry with an invalid name was not evaluated.')
                continue
            candidates.append((name.encode('utf-8', 'surrogatepass'), name, entry))
        for _, name, entry in sorted(candidates, key=lambda item: item[0]):
            path = f'{PARTS_DIR}/{name}'
            verdict = eligibility(name)
            if not verdict['read']:
                files.append({'path': path, 'state': 'ignored', 'reason': verdict['reason'],
                              'notice': verdict['notice']})
                continue
            if entry.get('type') != 'file':
                files.append({'path': path, 'state': 'ignored', 'reason': 'not_regular_file', 'notice': False})
                continue
            text, problem = _content(entry)
            if text is not None and total + len(text) > MAX_TOTAL_BYTES:
                text, problem = None, 'total_limit'
            if text is None:
                files.append({'path': path, 'state': problem})
                add_gap('file_' + problem if problem != 'unreadable' else 'file_unreadable',
                        'APT reads this file, but its contents were not available to the contract.', path=path)
                continue
            total += len(text)
            files.append({'path': path, 'state': read(path, text)})
    if main is None:
        add_gap('main_not_collected', f'{MAIN_FILE} was not collected.')
    elif not isinstance(main, dict) or not isinstance(main.get('present'), bool):
        add_gap('invalid_observation', f'The {MAIN_FILE} observation is malformed.')
    elif main['present']:
        text, problem = _content(main)
        if text is None:
            files.append({'path': MAIN_FILE, 'state': problem})
            add_gap('file_' + problem, 'APT reads this file, but its contents were not available to the contract.',
                    path=MAIN_FILE)
        else:
            files.append({'path': MAIN_FILE, 'state': read(MAIN_FILE, text)})

    hooks = _hooks(root, None)
    binary = root.child('binary', False)
    for program in binary.children if binary else ():
        if program.tag is not None:
            hooks.extend(_hooks(program, program.tag))
    if len(hooks) > MAX_HOOKS:
        add_gap('hook_limit', f'Only the first {MAX_HOOKS} hook options are reported.')
        hooks = hooks[:MAX_HOOKS]
    return {
        'contract_version': CONTRACT_VERSION,
        # The APT_CONFIG gap is disclosed but does not affect the default-environment result.
        'apt_behavior': 'undetermined' if undetermined else 'determined',
        'files': files,
        'hooks': hooks,
        'gaps': gaps,
        'not_a_verdict': NOT_A_VERDICT,
    }
