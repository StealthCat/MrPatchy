"""Pure udev rules parsing and effective-file contract (roadmap F slice, #844).

Turns the captured, read-only text of one ``*.rules`` file and a captured
listing of the udev rules directories into typed, bounded records. It performs
no I/O, never runs ``udevadm``, never executes a rule or a command and never
authorizes a response action.

Syntax follows udev(7) and the token validation in systemd's
``udev-rules.c``:

- Lines are ``KEY[{attr}]OP"value"`` pairs separated by commas. Leading
  whitespace is stripped from every physical line. Lines starting with ``#``
  are ignored even inside a line continuation, and a trailing backslash joins
  the next physical line.
- A physical line of ``UDEV_LINE_SIZE`` bytes or more stops udev reading the
  file; a joined logical line of that size is ignored. Both are gaps here.
- Values are double-quoted. In a plain string only ``\\"`` is an escape; any
  other backslash, including ``\\\\``, is kept literally. An ``e"..."`` string
  uses C-style escapes.
- A rule with an unknown key, a missing attribute, an operator the key does
  not accept or a syntax error is skipped by udev. It is skipped here too and
  reported as a line-numbered gap, never guessed at.
- ``PROGRAM``, ``IMPORT`` and ``TEST`` written with an assignment operator
  (the common ``PROGRAM="..."`` idiom) are treated by udev as ``==``, so the
  command still runs. They are recorded as ``==`` matches with the operator
  as written kept in ``written_operator``; ``-=`` is still invalid.

Executions: ``RUN`` (``{program}`` by default), ``PROGRAM`` and
``IMPORT{program}`` become external program records with a bounded command,
the full-command SHA-256, the program token, the library directories udev
searches for a relative name and whether the command uses ``$``/``%``
substitutions. ``RUN{builtin}`` and ``IMPORT{builtin}`` are recorded as
builtins with no external program. ``IMPORT{file|db|cmdline|parent}`` are not
executions.

Fail-closed rules: over-limit text, invalid UTF-8 and NUL bytes produce no
partial records. No record is labelled safe or a package default; ``origin`` is
always ``not_assessed`` because provenance needs authenticated package evidence.
"""
from __future__ import annotations

import hashlib
import posixpath
import re
from collections.abc import Iterable
from typing import Any

CONTRACT_VERSION = 1
MAX_TEXT = 262144
MAX_LINES = 8192
MAX_RULES = 4096
MAX_PAIRS = 64
MAX_ENTRIES = 2048
MAX_COMMAND = 4096
MAX_FIELD = 512
MAX_GAPS = 64
# systemd udev-rules.c UDEV_LINE_SIZE.
UDEV_LINE_SIZE = 16384

# Highest precedence first. A file name in an earlier directory overrides the
# same name in every later one (udev(7) "Rules Files").
RULES_DIRS = ('/etc/udev/rules.d', '/run/udev/rules.d', '/usr/local/lib/udev/rules.d',
              '/usr/lib/udev/rules.d', '/lib/udev/rules.d')
# udev resolves a relative RUN/PROGRAM/IMPORT{program} name inside its library
# directory: /usr/lib/udev, or /lib/udev on pre-usrmerge Debian layouts.
PROGRAM_DIRS = ('/usr/lib/udev', '/lib/udev')

MATCH = frozenset({'==', '!='})
ASSIGN = frozenset({'=', '+=', ':='})
ASSIGN_ALL = ASSIGN | {'-='}
# key: (attribute 'required' | 'optional' | 'none', accepted operators,
#       udev treats an assignment operator as '==' for this key)
KEYS: dict[str, tuple[str, frozenset[str], bool]] = {
    'ACTION': ('none', MATCH, False), 'DEVPATH': ('none', MATCH, False),
    'KERNEL': ('none', MATCH, False), 'KERNELS': ('none', MATCH, False),
    'SUBSYSTEM': ('none', MATCH, False), 'SUBSYSTEMS': ('none', MATCH, False),
    'DRIVER': ('none', MATCH, False), 'DRIVERS': ('none', MATCH, False),
    'TAGS': ('none', MATCH, False), 'RESULT': ('none', MATCH, False),
    'ATTRS': ('required', MATCH, False), 'CONST': ('required', MATCH, False),
    'TEST': ('optional', MATCH, True), 'PROGRAM': ('none', MATCH, True),
    'IMPORT': ('required', MATCH, True),
    'NAME': ('none', MATCH | ASSIGN, False), 'SYMLINK': ('none', MATCH | ASSIGN_ALL, False),
    'TAG': ('none', MATCH | ASSIGN_ALL, False), 'ENV': ('required', MATCH | ASSIGN, False),
    'ATTR': ('required', MATCH | ASSIGN, False), 'SYSCTL': ('required', MATCH | ASSIGN, False),
    'OWNER': ('none', ASSIGN, False), 'GROUP': ('none', ASSIGN, False), 'MODE': ('none', ASSIGN, False),
    'SECLABEL': ('required', ASSIGN, False), 'OPTIONS': ('none', ASSIGN, False),
    'RUN': ('optional', ASSIGN, False), 'LABEL': ('none', frozenset({'='}), False),
    'GOTO': ('none', frozenset({'='}), False),
}
RUN_TYPES = frozenset({'program', 'builtin'})
IMPORT_TYPES = frozenset({'program', 'builtin', 'file', 'db', 'cmdline', 'parent'})

_KEY = re.compile(r'([A-Za-z_]+)(?:\{([^{}]*)\})?')
_OP = re.compile(r'==|!=|\+=|-=|:=|=')
_SUBSTITUTION = re.compile(r'[$%]')
_C_ESCAPES = {'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v',
              '\\': '\\', '"': '"', "'": "'"}


class _Malformed(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _gap(gaps: list[dict[str, Any]], code: str, line: int | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'line': line, 'detail': detail[:200]})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'line': None, 'detail': 'Further gaps were not recorded.'})


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _decode(text: str | bytes, gaps: list[dict[str, Any]]) -> str | None:
    if isinstance(text, bytes):
        if len(text) > MAX_TEXT:
            _gap(gaps, 'over_limit', None, f'More than {MAX_TEXT} bytes.')
            return None
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            _gap(gaps, 'invalid_utf8', None, 'Text is not valid UTF-8.')
            return None
    if not isinstance(text, str):
        _gap(gaps, 'unreadable', None, 'No text was captured.')
        return None
    try:
        size = len(text.encode('utf-8'))
    except UnicodeEncodeError:
        _gap(gaps, 'invalid_utf8', None, 'Text is not valid UTF-8.')
        return None
    if size > MAX_TEXT:
        _gap(gaps, 'over_limit', None, f'More than {MAX_TEXT} bytes.')
        return None
    if '\x00' in text:
        _gap(gaps, 'binary', None, 'Text contains NUL bytes.')
        return None
    return text


def _c_unescape(raw: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char != '\\':
            out.append(char)
            index += 1
            continue
        if index + 1 >= len(raw):
            raise _Malformed('invalid_escape', 'An e"" string ends with a lone backslash.')
        code = raw[index + 1]
        if code in _C_ESCAPES:
            out.append(_C_ESCAPES[code])
            index += 2
        elif code == 'x' and re.fullmatch(r'[0-9A-Fa-f]{2}', raw[index + 2:index + 4]):
            out.append(chr(int(raw[index + 2:index + 4], 16)))
            index += 4
        elif re.fullmatch(r'[0-7]{3}', raw[index + 1:index + 4]):
            out.append(chr(int(raw[index + 1:index + 4], 8)))
            index += 4
        else:
            raise _Malformed('invalid_escape', f'Unsupported escape "\\{code}" in an e"" string.')
    value = ''.join(out)
    if '\x00' in value:
        raise _Malformed('invalid_escape', 'An e"" string decodes to a NUL byte.')
    return value


def _value(line: str, index: int) -> tuple[str, int]:
    """Parse a quoted value starting at ``index``; return it and the next index."""
    escaped = line.startswith('e"', index)
    if escaped:
        index += 1
    if index >= len(line) or line[index] != '"':
        raise _Malformed('unquoted_value', 'A value must be enclosed in double quotes.')
    index += 1
    raw: list[str] = []
    while True:
        if index >= len(line):
            raise _Malformed('unterminated_value', 'A quoted value has no closing quote.')
        char = line[index]
        if char == '"':
            break
        if char == '\\' and index + 1 < len(line):
            following = line[index + 1]
            if escaped:
                raw.append(char + following)
                index += 2
                continue
            if following == '"':
                raw.append(following)
                index += 2
                continue
        raw.append(char)
        index += 1
    text = ''.join(raw)
    return (_c_unescape(text) if escaped else text), index + 1


def _pairs(line: str) -> list[tuple[str, str | None, str, str]]:
    pairs: list[tuple[str, str | None, str, str]] = []
    index = 0
    while True:
        while index < len(line) and line[index] in ' \t,':
            index += 1
        if index >= len(line):
            return pairs
        key = _KEY.match(line, index)
        if not key:
            raise _Malformed('malformed_key', f'Expected a key at column {index + 1}.')
        index = key.end()
        while index < len(line) and line[index] in ' \t':
            index += 1
        op = _OP.match(line, index)
        if not op:
            raise _Malformed('missing_operator', f'{key.group(1)[:32]} has no operator.')
        index = op.end()
        while index < len(line) and line[index] in ' \t':
            index += 1
        value, index = _value(line, index)
        if index < len(line) and line[index] not in ' \t,':
            raise _Malformed('missing_separator', f'Unexpected text after the {key.group(1)[:32]} value.')
        pairs.append((key.group(1), key.group(2), op.group(0), value))
        if len(pairs) > MAX_PAIRS:
            raise _Malformed('over_limit', f'More than {MAX_PAIRS} key/value pairs in one rule.')


def _program_token(command: str) -> str | None:
    command = command.lstrip()
    if not command:
        return None
    if command[0] in ('"', "'"):
        end = command.find(command[0], 1)
        return command[1:end] if end > 0 else None
    return command.split(None, 1)[0]


def _execution(kind: str, kind_type: str, op: str, command: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        'kind': kind, 'type': kind_type, 'external': kind_type == 'program', 'operator': op,
        'command': command[:MAX_COMMAND], 'command_truncated': len(command) > MAX_COMMAND,
        'command_sha256': _sha(command), 'program': None, 'candidate_paths': [],
        'uses_substitutions': bool(_SUBSTITUTION.search(command)), 'origin': 'not_assessed',
    }
    token = _program_token(command)
    if token is not None:
        record['program'] = token[:MAX_FIELD]
        if kind_type == 'program':
            record['candidate_paths'] = ([posixpath.normpath(token)] if token.startswith('/') else
                                         [posixpath.join(d, token) for d in PROGRAM_DIRS])
    return record


def _rule(path: str, line_no: int, line: str, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    try:
        pairs = _pairs(line)
    except _Malformed as error:
        _gap(gaps, error.code, line_no, f'{error.detail} The rule is skipped, as udev skips it.')
        return None
    if not pairs:
        return None
    rule: dict[str, Any] = {'file': path, 'line': line_no, 'matches': [], 'assignments': [], 'label': None,
                            'goto': None, 'executions': [], 'origin': 'not_assessed'}
    for key, attr, op, value in pairs:
        spec = KEYS.get(key)
        if spec is None:
            _gap(gaps, 'unknown_key', line_no, f'{key[:32]} is not a udev key. The rule is skipped, as udev skips it.')
            return None
        attr_rule, ops, coerce = spec
        if attr_rule == 'required' and not attr:
            _gap(gaps, 'missing_attribute', line_no, f'{key} requires a {{attribute}}. The rule is skipped.')
            return None
        if attr_rule == 'none' and attr is not None:
            _gap(gaps, 'unexpected_attribute', line_no, f'{key} takes no {{attribute}}. The rule is skipped.')
            return None
        written = op
        if op not in ops:
            if coerce and op in ASSIGN:
                op = '=='
            else:
                _gap(gaps, 'invalid_operator', line_no, f'{key} does not accept "{written}". The rule is skipped, '
                     'as udev skips it.')
                return None
        if key == 'RUN':
            kind_type = attr or 'program'
            if kind_type not in RUN_TYPES:
                _gap(gaps, 'invalid_attribute', line_no, f'RUN{{{kind_type[:32]}}} is not a RUN type. The rule is skipped.')
                return None
        if key == 'IMPORT' and attr not in IMPORT_TYPES:
            _gap(gaps, 'invalid_attribute', line_no, f'IMPORT{{{(attr or "")[:32]}}} is not an IMPORT type. '
                 'The rule is skipped.')
            return None
        if key in ('LABEL', 'GOTO'):
            rule[key.lower()] = value[:MAX_FIELD]
            continue
        record = {'key': key, 'attr': None if attr is None else attr[:MAX_FIELD], 'operator': op,
                  'value': value[:MAX_FIELD], 'value_truncated': len(value) > MAX_FIELD}
        if written != op:
            record['written_operator'] = written
        rule['matches' if op in MATCH else 'assignments'].append(record)
        if key == 'RUN':
            rule['executions'].append(_execution('run', attr or 'program', op, value))
        elif key == 'PROGRAM':
            rule['executions'].append(_execution('program', 'program', op, value))
        elif key == 'IMPORT' and attr in ('program', 'builtin'):
            rule['executions'].append(_execution('import', attr, op, value))
    return rule


def parse_rules_file(path: str, text: str | bytes) -> dict[str, Any]:
    """Parse one captured udev ``*.rules`` file into rules and executed programs."""
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'format': 'udev_rules', 'state': 'parsed',
                              'path': str(path)[:4096], 'sha256': None, 'size': None, 'rules': [],
                              'labels': [], 'origin': 'not_assessed', 'gaps': gaps}
    decoded = _decode(text, gaps)
    if decoded is None:
        result['state'] = 'unavailable'
        return result
    lines = decoded.split('\n')
    if len(lines) > MAX_LINES:
        _gap(gaps, 'over_limit', None, f'More than {MAX_LINES} lines.')
        result['state'] = 'unavailable'
        return result
    result['sha256'] = _sha(decoded)
    result['size'] = len(decoded.encode('utf-8'))
    rules: list[dict[str, Any]] = []
    # Mirrors udev_rules_parse_file() in systemd's udev-rules.c.
    pending: str | None = None
    ignore = False
    start = 0
    for number, raw in enumerate(lines, 1):
        physical = raw.rstrip('\r')
        if len(physical.encode('utf-8')) >= UDEV_LINE_SIZE:
            _gap(gaps, 'line_too_long', number, f'A line of {UDEV_LINE_SIZE} bytes or more stops udev reading this '
                 'file; later lines are not loaded.')
            pending = None
            break
        line = physical.lstrip(' \t\r\n')
        if line.startswith('#'):
            continue
        if pending is None:
            start = number
        elif not ignore:
            if len(pending.encode('utf-8')) + len(line.encode('utf-8')) >= UDEV_LINE_SIZE:
                ignore = True
            else:
                pending += line
                line = pending
        if line.endswith('\\'):
            if not ignore:
                pending = line[:-1]
            continue
        if ignore:
            _gap(gaps, 'line_too_long', start, f'The joined line reaches {UDEV_LINE_SIZE} bytes; udev ignores it.')
        elif line:
            rule = _rule(result['path'], start, line.strip(), gaps)
            if rule is not None:
                if len(rules) >= MAX_RULES:
                    _gap(gaps, 'over_limit', start, f'More than {MAX_RULES} rules.')
                    result.update(state='unavailable', rules=[], labels=[])
                    return result
                rules.append(rule)
        pending = None
        ignore = False
    if pending is not None:
        _gap(gaps, 'unterminated_continuation', start, 'The file ends inside a "\\" line continuation; '
             'the unfinished rule is skipped.')
    labels = [r['label'] for r in rules if r['label'] is not None]
    for rule in rules:
        if rule['goto'] is not None and rule['goto'] not in labels:
            _gap(gaps, 'goto_without_label', rule['line'], f'GOTO "{rule["goto"][:64]}" names no LABEL in this file.')
    result['rules'] = rules
    result['labels'] = labels
    if gaps:
        result['state'] = 'partial'
    return result


def effective_files(entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Apply udev rules-directory precedence to a captured directory listing.

    Each entry is ``{'dir': '/etc/udev/rules.d', 'name': '70-x.rules', 'target': None}``;
    ``target`` is the symbolic link target, or ``None`` for a regular file.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'format': 'udev_rules_files',
                              'state': 'parsed', 'files': [], 'masked': [], 'ignored': [], 'gaps': gaps}
    entries = list(entries) if entries is not None else []
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'over_limit', None, f'More than {MAX_ENTRIES} rules directory entries.')
        result['state'] = 'unavailable'
        return result
    by_name: dict[str, list[dict[str, Any]]] = {}
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            _gap(gaps, 'malformed_entry', None, 'A directory entry is not a mapping.')
            continue
        directory = str(entry.get('dir') or '').rstrip('/')
        name = entry.get('name')
        target = entry.get('target')
        if directory not in RULES_DIRS:
            _gap(gaps, 'unrecognized_directory', None, f'{directory[:120]} is not a udev rules directory.')
            continue
        if (not isinstance(name, str) or not name or '/' in name or '\x00' in name or name in ('.', '..')
                or len(name) > 255):
            _gap(gaps, 'malformed_entry', None, f'An entry in {directory} has an unusable name.')
            continue
        if target is not None and (not isinstance(target, str) or not target or '\x00' in target
                                   or len(target) > 4096):
            _gap(gaps, 'invalid_target', None, f'{directory}/{name[:120]} has an unreadable link target.')
            continue
        if (directory, name) in seen:
            _gap(gaps, 'duplicate_entry', None, f'{directory}/{name[:120]} was listed more than once.')
            continue
        seen.add((directory, name))
        path = f'{directory}/{name}'
        # udev's dirent_is_file_with_suffix() skips hidden names.
        if name.startswith('.') or not name.endswith('.rules'):
            result['ignored'].append(path)
            continue
        by_name.setdefault(name, []).append({'dir': directory, 'path': path, 'target': target})
    for name in sorted(by_name):
        candidates = sorted(by_name[name], key=lambda c: RULES_DIRS.index(c['dir']))
        winner, shadowed = candidates[0], [c['path'] for c in candidates[1:]]
        masked = winner['target'] is not None and posixpath.normpath(winner['target']) == '/dev/null'
        record = {'name': name, 'path': winner['path'], 'dir': winner['dir'], 'target': winner['target'],
                  'symlink': winner['target'] is not None, 'overridden': shadowed, 'origin': 'not_assessed'}
        (result['masked'] if masked else result['files']).append(record)
    result['ignored'].sort()
    if gaps:
        result['state'] = 'partial'
    return result
