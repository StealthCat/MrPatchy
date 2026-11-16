"""Pure PAM service-stack contract (roadmap F slice, #967).

Turns captured, read-only text of PAM service files into typed, bounded
records and resolves which modules each service loads, in order, including the
commands ``pam_exec.so`` runs. It performs no I/O, never calls PAM, never runs a
configured command and never authorizes a response action.

Rules this module follows were read from ``libpam/pam_handlers.c`` and
``libpam/pam_misc.c`` in Linux-PAM 1.4.0 and 1.5.3 (identical apart from
compiler annotations), Debian's ``031_pam_include`` patch for 1.5.3 and
``modules/pam_exec/pam_exec.c`` in 1.5.3:

- A service is the lower-cased name the application passes to ``pam_start``.
  Its file is the first of ``/etc/pam.d/<service>``, ``/usr/lib/pam.d/<service>``
  and, when the build has one, ``<vendor_dir>/pam.d/<service>``.
- Blank lines and lines whose first non-blank character is ``#`` are skipped,
  also inside a continued line. Otherwise the first ``#`` ends the line, even
  inside brackets. A backslash as the last non-blank character joins the next
  line.
- Fields are separated by spaces and tabs. A field starting with ``[`` runs to
  the first ``]`` (``\\]`` is a literal ``]``) and may contain spaces. Without
  a closing ``]`` it runs to the end of the line and keeps the line's newline.
- The line is ``type control module [arguments]``. Type and control keywords
  are case-insensitive, and a leading ``-`` on the type only silences load
  errors. A missing or unknown type, a missing control or a missing module
  becomes an entry that always fails when its type is used (``must_fail``);
  an unknown type is filed under ``auth``, or under the including line's type.
- ``include`` and ``substack`` read another file in place, keeping only lines
  of the including line's type. A name without ``/`` is looked up like a
  service, in the same directory order (compiled Ubuntu libpam 1.5.3 does this
  too). Debian's ``@include <name>`` takes the place of the type and keeps
  every type the current file was read for. A name starting with ``/`` is used
  as a path. libpam also accepts a relative name containing ``/``; the
  contract reports it as a missing target.
- Types for which the service file yields no entry use the ``other`` service.
  A ``substack`` line counts as an entry of its type even when the file it
  names yields nothing. libpam reads ``other`` for every service.
- ``pam_exec.so`` reads options until the first argument that starts with
  ``/`` or is not an option; the rest is the command, run as root unless
  ``seteuid`` changes the effective user.

Fail-closed rules:

- An include target that was not captured, an include loop, nesting deeper
  than libpam allows, a continued line that never ends, a line near libpam's
  1024-byte buffer and control characters (including a carriage return) are
  blocking gaps for every service that reaches them. A blocking gap in
  ``other`` is a gap for every service. The contract never
  returns a silently shorter stack.
- Unreadable files, invalid UTF-8, NUL bytes and over-limit input are blocking
  gaps. An unreadable file still shadows the same name in a lower-priority
  directory.
- Linux-PAM versions other than 1.4.x and 1.5.x are reported with the blocking
  ``version_unverified`` gap: 1.7.0 rewrote the line reader and it was not
  compared.
- Arguments and commands are returned bounded with the SHA-256 of the full
  value. Nothing is labelled a package default or safe; ``origin`` is always
  ``not_assessed``.
- ``unobserved`` names what this contract cannot see.
"""
from __future__ import annotations

import hashlib
import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
MAX_FILES = 512
MAX_TEXT = 262144
MAX_LINE = 1000          # libpam's buffer is 1024 bytes; stay clearly inside it
MAX_ENTRIES = 2048
MAX_ARGS = 64
MAX_FIELD = 256
MAX_GAPS = 64
MAX_SUBSTACK = 16        # PAM_SUBSTACK_MAX_LEVEL
MAX_INCLUDE_DEPTH = 32

CONFIG_DIR = '/etc/pam.d'
DIST_DIR = '/usr/lib/pam.d'
DEFAULT_SERVICE = 'other'
TYPES = ('auth', 'account', 'password', 'session')
FAMILIES = ('debian', 'upstream')
SIMPLE_CONTROLS = ('required', 'requisite', 'optional', 'sufficient')
EXEC_FLAGS = ('debug', 'stdout', 'seteuid', 'quiet', 'quiet_log', 'expose_authtok')
EXEC_TYPES = {'auth': ('auth',), 'account': ('account',), 'password': ('password',),
              'session': ('open_session', 'close_session')}
UNOBSERVED = (
    '/etc/pam.conf, which libpam reads only when no pam.d directory exists',
    'module binaries and the default module directory they are loaded from',
    'the files and commands that modules such as pam_exec, pam_script or pam_mount run',
    'the service name and any alternative configuration directory each application passes to PAM',
    'distribution patches other than Debian\'s include handling',
)
NOT_A_VERDICT = 'Parsed configuration only. This is not a safety verdict and origin is not assessed.'

_VERSION = re.compile(r'1\.[45]\.\d+(?:\D.*)?\Z')
_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')


class _Unusable(Exception):
    def __init__(self, code: str, line: int | None = None):
        super().__init__(code)
        self.code, self.line = code, line


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _bound(value: str) -> str:
    return value if len(value) <= MAX_FIELD else value[:MAX_FIELD]


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, line: int | None = None) -> None:
    item = {'code': code, 'path': _bound(path) if isinstance(path, str) else None, 'line': line, 'blocking': True}
    if item in gaps:
        return
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'path': None, 'line': None, 'blocking': True}
        return
    gaps.append(item)


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Return ``(first physical line number, assembled text)`` as ``_pam_assemble_line`` builds them."""
    out: list[tuple[int, str]] = []
    pending, start = '', None
    physical = text.split('\n')
    for number, raw in enumerate(physical, 1):
        if len(raw.encode('utf-8')) > MAX_LINE:
            raise _Unusable('line_too_long', number)
        body = raw.lstrip(' \t')
        if not body or body[0] == '#':
            continue
        first = start or number
        if '#' in raw:
            pending, done = pending + raw[:raw.index('#')], True
        else:
            stripped = raw.rstrip(' \t')
            if stripped.endswith('\\'):
                pending, done = pending + stripped[:-1] + ' ', False
            else:
                # fgets keeps the newline, and a ``[`` field with no closing ``]``
                # runs to the end of the buffer, so the module receives it.
                pending, done = pending + raw + ('\n' if number < len(physical) else ''), True
        if len(pending.encode('utf-8')) > MAX_LINE:
            raise _Unusable('line_too_long', first)
        if done:
            out.append((first, pending))
            pending, start = '', None
        else:
            start = first
    if start is not None:
        raise _Unusable('continuation_at_eof', start)
    return out


def tokenize(line: str) -> list[str]:
    """Split one assembled line the way ``_pam_StrTok`` does with space, tab and newline."""
    tokens: list[str] = []
    pos, size = 0, len(line)
    while True:
        while pos < size and line[pos] in ' \t\n':
            pos += 1
        if pos >= size:
            return tokens
        if line[pos] == '[':
            pos += 1
            chars: list[str] = []
            while pos < size and line[pos] != ']':
                if line[pos] == '\\' and pos + 1 < size and line[pos + 1] == ']':
                    pos += 1
                chars.append(line[pos])
                pos += 1
            pos += 1
            tokens.append(''.join(chars))
        else:
            end = pos
            while end < size and line[end] not in ' \t\n':
                end += 1
            tokens.append(line[pos:end])
            pos = end + 1


def _parse_file(record: dict[str, Any]) -> list[tuple[int, list[str]]]:
    text = record.get('text')
    if isinstance(text, bytes):
        if len(text) > MAX_TEXT:
            raise _Unusable('file_too_large')
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            raise _Unusable('invalid_utf8') from None
    if not isinstance(text, str):
        raise _Unusable('file_unreadable')
    if len(text) > MAX_TEXT:
        raise _Unusable('file_too_large')
    match = _CONTROL.search(text)
    if match:
        raise _Unusable('control_character', text.count('\n', 0, match.start()) + 1)
    return [(number, tokenize(line)) for number, line in logical_lines(text)]


def _exec(entry_type: str, args: list[str]) -> dict[str, Any]:
    options: list[str] = []
    type_filter = None
    index = 0
    while index < len(args):
        arg = args[index]
        lower = arg.lower()
        if arg.startswith('/'):
            break
        if lower in EXEC_FLAGS or lower.startswith('log='):
            options.append(_bound(arg))
        elif lower.startswith('type='):
            type_filter = arg[5:]
            options.append(_bound(arg))
        else:
            break
        index += 1
    command = args[index:]
    flags = {option.lower() for option in options}
    return {
        'options': options,
        'type_filter': _bound(type_filter) if type_filter is not None else None,
        # pam_exec compares type= case-sensitively with the PAM call it serves.
        'applies': type_filter is None or type_filter in EXEC_TYPES[entry_type],
        'seteuid': 'seteuid' in flags,
        'expose_authtok': 'expose_authtok' in flags,
        'command': [_bound(part) for part in command],
        'command_sha256': _sha('\0'.join(command)) if command else None,
        'command_missing': not command,
        'runs_as': 'root unless seteuid changes the effective user; not observed',
    }


def _entry(entry_type: str, silent: bool, control: str | None, module: str | None, args: list[str],
           must_fail: str | None, path: str, line: int, via: list[dict[str, Any]], level: int) -> dict[str, Any]:
    lower = control.lower() if control is not None else None
    entry: dict[str, Any] = {
        'type': entry_type,
        'status': 'must_fail' if must_fail else 'module',
        'reason': must_fail,
        'silent': silent,
        'control': _bound(control) if control is not None else None,
        'control_kind': 'simple' if lower in SIMPLE_CONTROLS else 'bracket_or_unknown' if control is not None else None,
        'module': _bound(module) if module is not None else None,
        'module_sha256': _sha(module) if module is not None else None,
        'module_absolute': bool(module) and module.startswith('/'),
        'args': [_bound(arg) for arg in args[:MAX_ARGS]],
        'args_truncated': len(args) > MAX_ARGS or any(len(arg) > MAX_FIELD for arg in args),
        'args_sha256': _sha('\0'.join(args)),
        'source': {'path': path, 'line': line},
        'via': list(via),
        'substack_level': level,
        'exec': None,
        'origin': 'not_assessed',
    }
    if not must_fail and module is not None and posixpath.basename(module) == 'pam_exec.so':
        entry['exec'] = _exec(entry_type, args)
    return entry


class _Resolver:
    def __init__(self, records: dict[str, dict[str, Any]], family: str, dirs: tuple[str, ...]):
        self.records, self.family, self.dirs = records, family, dirs
        self.parsed: dict[str, Any] = {}

    def lines(self, path: str) -> list[tuple[int, list[str]]]:
        if path not in self.parsed:
            try:
                self.parsed[path] = _parse_file(self.records[path])
            except _Unusable as error:
                self.parsed[path] = error
        if isinstance(self.parsed[path], _Unusable):
            raise self.parsed[path]
        return self.parsed[path]

    def service_file(self, name: str) -> str | None:
        for directory in self.dirs:
            path = f'{directory}/{name}'
            if path in self.records:
                return path
        return None

    def include_target(self, name: str) -> str | None:
        if name.startswith('/'):
            path = posixpath.normpath(name)
            return path if path in self.records else None
        return self.service_file(name) if '/' not in name else None

    def walk(self, path: str, requested: str | None, level: int, chain: list[dict[str, Any]],
             entries: list[dict[str, Any]], gaps: list[dict[str, Any]], held: set[str]) -> None:
        try:
            lines = self.lines(path)
        except _Unusable as error:
            _gap(gaps, error.code, path, error.line)
            return
        for number, tokens in lines:
            if len(entries) >= MAX_ENTRIES:
                _gap(gaps, 'too_many_entries', path, number)
                return
            first = tokens[0] if tokens else ''
            silent = first.startswith('-')
            keyword = (first[1:] if silent else first).lower()
            must_fail = None
            include = None
            index = 1
            if keyword in TYPES:
                entry_type: str | None = keyword
            elif keyword == '@include' and self.family == 'debian':
                include, entry_type = '@include', requested
            else:
                entry_type, must_fail = requested or 'auth', 'type_invalid' if keyword else 'type_missing'
            control = None
            if include is None:
                if requested is not None and entry_type != requested:
                    continue
                if len(tokens) > 1:
                    control = tokens[1]
                    if control.lower() in ('include', 'substack'):
                        include = control.lower()
                else:
                    must_fail = must_fail or 'control_missing'
                index = 2
            if include is not None:
                name = tokens[index] if len(tokens) > index else None
                deeper = level + (include == 'substack')
                if include == 'substack':
                    # libpam installs a substack marker for this type before it reads
                    # the file, so the type no longer falls back to ``other``.
                    held.add(entry_type or 'auth')
                if name is None:
                    _gap(gaps, 'include_name_missing', path, number)
                    continue
                target = self.include_target(name)
                if target is None:
                    _gap(gaps, 'include_target_missing', path, number)
                elif deeper >= MAX_SUBSTACK or len(chain) >= MAX_INCLUDE_DEPTH:
                    _gap(gaps, 'include_too_deep', path, number)
                elif target == path or any(step['target'] == target for step in chain):
                    _gap(gaps, 'include_loop', path, number)
                else:
                    step = {'path': path, 'line': number, 'kind': include, 'target': target}
                    self.walk(target, entry_type, deeper, chain + [step], entries, gaps, held)
                continue
            module = tokens[index] if len(tokens) > index else None
            if module is None:
                must_fail = must_fail or 'module_missing'
            entries.append(_entry(entry_type or 'auth', silent, control, module, tokens[index + 1:], must_fail,
                                  path, number, chain, level))


def evaluate(files: Any, family: str, version: str, vendor_dir: str | None = None) -> dict[str, Any]:
    """Resolve every captured PAM service.

    ``files`` is a list of ``{'path': absolute path, 'text': str | bytes}``
    records; a record without ``text`` is a file the collector saw but could
    not read. ``family`` is ``debian`` (Debian, Ubuntu, Raspberry Pi OS) or
    ``upstream``. ``version`` is the installed Linux-PAM version.
    ``vendor_dir`` is the build's vendor directory, when it has one.
    """
    if family not in FAMILIES:
        raise ValueError('family must be debian or upstream')
    gaps: list[dict[str, Any]] = []
    dirs = (CONFIG_DIR, DIST_DIR)
    if vendor_dir is not None:
        if (not isinstance(vendor_dir, str) or not vendor_dir.startswith('/')
                or posixpath.normpath(vendor_dir) != vendor_dir or _CONTROL.search(vendor_dir)):
            raise ValueError('vendor_dir must be a normalized absolute path')
        dirs += (f'{vendor_dir}/pam.d',)
    if not isinstance(version, str) or not _VERSION.match(version):
        _gap(gaps, 'version_unverified')
    records: dict[str, dict[str, Any]] = {}
    if not isinstance(files, (list, tuple)):
        _gap(gaps, 'input_malformed')
        files = ()
    if len(files) > MAX_FILES:
        _gap(gaps, 'too_many_files')
        files = files[:MAX_FILES]
    for record in files:
        path = record.get('path') if isinstance(record, dict) else None
        if (not isinstance(path, str) or not path.startswith('/') or len(path) > MAX_FIELD
                or posixpath.normpath(path) != path or _CONTROL.search(path)):
            _gap(gaps, 'input_malformed')
        elif path in records:
            _gap(gaps, 'duplicate_path', path)
        else:
            records[path] = record
    resolver = _Resolver(records, family, dirs)
    names = sorted({posixpath.basename(path) for path in records if posixpath.dirname(path) in dirs})

    def stack(name: str) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], set[str]]:
        path = resolver.service_file(name)
        entries: list[dict[str, Any]] = []
        found: list[dict[str, Any]] = []
        held: set[str] = set()
        resolver.walk(path, None, 0, [], entries, found, held)
        return path, entries, found, held

    other = stack(DEFAULT_SERVICE) if DEFAULT_SERVICE in names else None
    services = []
    for name in names:
        path, entries, found, held = stack(name)
        present = {entry['type'] for entry in entries} | held
        fallback = [kind for kind in TYPES if kind not in present] if name != DEFAULT_SERVICE else []
        # libpam reads ``other`` for every service, and a file it cannot parse
        # fails pam_start even when no type falls back to it.
        if name != DEFAULT_SERVICE and other is not None:
            for item in other[2]:
                _gap(found, item['code'], item['path'], item['line'])
        services.append({
            'service': _bound(name),
            # pam_start lower-cases the requested name, so other names are reachable only through an include.
            'selectable': name == name.lower(),
            'file': path,
            'shadowed_files': [f'{directory}/{name}' for directory in dirs
                               if f'{directory}/{name}' in records and f'{directory}/{name}' != path],
            'entries': entries,
            'uses_other_for': fallback,
            'other_available': other is not None,
            'exec_commands': sum(1 for entry in entries if entry['exec'] is not None),
            'absolute_modules': sum(1 for entry in entries if entry['module_absolute']),
            'must_fail': sum(1 for entry in entries if entry['status'] == 'must_fail'),
            'gaps': found,
            'complete': not found and not gaps,
        })
    return {
        'contract_version': CONTRACT_VERSION,
        'family': family,
        'version': _bound(version) if isinstance(version, str) else None,
        'directories': list(dirs),
        'services': services,
        'gaps': gaps,
        'complete': not gaps and all(service['complete'] for service in services),
        'unobserved': list(UNOBSERVED),
        'note': NOT_A_VERDICT,
    }
