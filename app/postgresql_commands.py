"""Pure PostgreSQL server command contract (roadmap F slice, #1597).

Takes captured, read-only observations of a PostgreSQL 16 server's main configuration
file, the files and directories it includes and the data directory's
``postgresql.auto.conf`` (which ``ALTER SYSTEM`` writes, so a database superuser can
change it without shell access). It reports which shell commands the server runs and
which shared libraries it loads, as the server's operating-system account, and from
which file and line each effective value comes.

Commands: ``archive_command`` (per completed WAL segment), ``restore_command``,
``recovery_end_command`` and ``archive_cleanup_command`` (archive recovery or standby
only), and ``ssl_passphrase_command`` (startup, and reload only when
``ssl_passphrase_command_supports_reload`` is on). Loaded code: ``archive_library``,
``shared_preload_libraries`` (postmaster start), ``session_preload_libraries`` and
``local_preload_libraries`` (each new session).

Semantics follow PostgreSQL 16 (``guc-file.l``, ``guc.c``, ``conffiles.c``,
``percentrepl.c``, ``pgarch.c``, ``varlena.c``), checked against Ubuntu 24.04
``postgresql-16`` with ``postgres -C``. The rules are:

* The lexer is ``guc-file.l``. Newline ends a line; space, tab and CR separate tokens;
  ``#`` starts a comment. Bytes 0x80-0xFF are letters. A name is an ID
  (``[A-Za-z_\\x80-\\xff][A-Za-z0-9_\\x80-\\xff]*``) or ``ID.ID``. A value is an ID, a
  quoted string, an integer (with optional unit letters), a real or an unquoted string
  (a letter followed by letters, digits and ``-._:/``). Flex takes the longest match and
  the earlier rule on a tie, so ``foo.conf`` is a qualified ID, which is not a valid
  value. ``=`` between name and value is optional. Anything else on the line is a syntax
  error.
* Quoted strings drop their quotes. ``''`` is ``'``; ``\\b \\f \\n \\r \\t``, a backslash
  followed by one to three octal digits, and a backslash followed by any other
  character are decoded as in ``DeescapeQuotedString``.
* A syntax error does not stop parsing: the parser skips to the next line, up to 100
  errors per file. Any error marks the configuration as containing errors.
* Names compare case-insensitively. ``include`` (strict), ``include_if_exists`` (an
  unopenable file is skipped) and ``include_dir`` are processed in place. A relative
  path is resolved against the including file's directory. An all-blank name, direct
  self-inclusion and nesting deeper than 10 are errors. ``include_dir`` reads entries
  whose name is at least 6 bytes, does not start with ``.`` and ends in ``.conf``, skips
  directories, and parses them in ``strcmp`` order.
* The server reads the main file once to find ``data_directory``, then rereads it with
  ``postgresql.auto.conf`` from the data directory appended. The last assignment of a
  name wins.
* At postmaster start any error is fatal, including an unknown parameter name (not
  modelled here except for the settings below) and a bad value for a modelled setting.
  An invalid library list is only logged: the server starts and loads none of that
  list. ``archive_mode`` other than ``off`` with ``wal_level =
  minimal`` also stops the server. On reload, a configuration with errors leaves the
  running values in place.
* ``archive_command`` runs only when ``archive_mode`` is ``on`` or ``always`` and
  ``archive_library`` is empty. When both are set the archiver fails and neither runs.
* Commands run through ``system()``, which is ``/bin/sh -c``, after ``%`` placeholders
  are replaced (``replace_percent_placeholders``). An unknown placeholder or a trailing
  ``%`` makes the process raise an error instead of running the command.
* Library lists are split with ``SplitDirectoriesString``: comma separated, optional
  double quotes with ``""`` for ``"``, no empty items. An unknown placeholder, a
  trailing ``%``, an invalid list, ``archive_mode``/``wal_level = minimal`` and setting
  both ``archive_command`` and ``archive_library`` were each confirmed on a running
  PostgreSQL 16.15 server.

The contract reports what the observed files make the server run at its next start or
reload. It does not observe a running server, which keeps values that need a restart
until it restarts, and it does not observe ``recovery.signal`` or ``standby.signal``.
Other parameters' names and values are not validated, so a configuration this
contract accepts could still be rejected on the host; the contract never under-reports.
It performs no I/O, runs no command and never authorizes a response action. Unobserved
or unmodelled file states, NUL bytes, invalid UTF-8 and over-limit input become explicit
gaps, and a result with any gap is not ``complete``.
"""
from __future__ import annotations

import posixpath
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('PostgreSQL 16 (Ubuntu 24.04 postgresql-16)',)
MAX_TEXT = 1 << 20
MAX_GAPS = 256
MAX_FILES = 256
MAX_DEPTH = 10
MAX_SYNTAX_ERRORS = 100
AUTO_CONF = 'postgresql.auto.conf'
FILE_STATES = ('absent', 'regular', 'unreadable', 'not_regular', 'unknown')
DIR_STATES = ('present', 'absent', 'unreadable', 'unknown')
RUN_AS = 'server_os_user'
SHELL = ('/bin/sh', '-c')

# setting: (placeholders, when it runs)
COMMANDS = {
    'archive_command': ('fp', 'each_completed_wal_segment'),
    'restore_command': ('fpr', 'archive_recovery_or_standby'),
    'recovery_end_command': ('r', 'end_of_archive_recovery'),
    'archive_cleanup_command': ('r', 'standby_restartpoint'),
    'ssl_passphrase_command': ('p', 'server_start_when_ssl_key_has_passphrase'),
}
LIBRARIES = {
    'shared_preload_libraries': 'postmaster_start',
    'session_preload_libraries': 'each_session_start',
    'local_preload_libraries': 'each_session_start',
}
ENUMS = {
    'archive_mode': {'always': 'always', 'on': 'on', 'off': 'off', 'true': 'on',
                     'false': 'off', 'yes': 'on', 'no': 'off', '1': 'on', '0': 'off'},
    'wal_level': {'minimal': 'minimal', 'replica': 'replica', 'archive': 'replica',
                  'hot_standby': 'replica', 'logical': 'logical'},
}
BOOLS = ('ssl', 'ssl_passphrase_command_supports_reload')
DEFAULTS = {'archive_mode': 'off', 'wal_level': 'replica', 'archive_library': '',
            'ssl': 'off', 'ssl_passphrase_command_supports_reload': 'off'}
MODELLED = frozenset(set(COMMANDS) | set(LIBRARIES) | set(ENUMS) | set(BOOLS)
                     | {'archive_library', 'data_directory', 'dynamic_library_path'})
NOT_MODELLED = (
    'running_server_values_and_pending_restart',
    'recovery_and_standby_signal_files',
    'other_parameter_names_and_values',
    'command_line_and_environment_settings',
    'library_file_resolution_and_contents',
    'ssl_key_passphrase_presence',
    'contents_of_the_commands_run',
)

_EOL, _ID, _QID, _STRING, _USTRING, _INT, _REAL, _EQ, _ERR = range(9)
_VALUE_TOKENS = (_ID, _STRING, _INT, _REAL, _USTRING)
_DIGITS = frozenset(b'0123456789')
_HEX = frozenset(b'0123456789abcdefABCDEF')
_ALPHA = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
_LETTER = frozenset(_ALPHA | {ord('_')} | set(range(0x80, 0x100)))
_LETTER_DIGIT = frozenset(_LETTER | _DIGITS)
_USTRING_REST = frozenset(_LETTER_DIGIT | set(b'-._:/'))
_BOOL_TRUE = ('on', 'true', 'yes', '1')
_BOOL_FALSE = ('off', 'false', 'no', '0')


def _run(buf: bytes, i: int, allowed: frozenset) -> int:
    while i < len(buf) and buf[i] in allowed:
        i += 1
    return i


def _id_end(buf: bytes, i: int) -> int:
    return _run(buf, i + 1, _LETTER_DIGIT) if i < len(buf) and buf[i] in _LETTER else i


def _int_end(buf: bytes, i: int) -> int:
    j = i + 1 if i < len(buf) and buf[i] in b'+-' else i
    if buf[j:j + 2] == b'0x' and j + 2 < len(buf) and buf[j + 2] in _HEX:
        k = _run(buf, j + 2, _HEX)
    else:
        k = _run(buf, j, _DIGITS)
        if k == j:
            return i
    return _run(buf, k, _ALPHA)


def _real_end(buf: bytes, i: int) -> int:
    j = i + 1 if i < len(buf) and buf[i] in b'+-' else i
    k = _run(buf, j, _DIGITS)
    if k >= len(buf) or buf[k] != ord('.'):
        return i
    k = _run(buf, k + 1, _DIGITS)
    if k < len(buf) and buf[k] in b'Ee':
        m = k + 1 + (1 if k + 1 < len(buf) and buf[k + 1] in b'+-' else 0)
        n = _run(buf, m, _DIGITS)
        if n > m:
            k = n
    return k


def _string_end(buf: bytes, i: int) -> int:
    if i >= len(buf) or buf[i] != 0x27:
        return i
    j = i + 1
    while j < len(buf):
        c = buf[j]
        if c == 0x27:
            if buf[j + 1:j + 2] == b"'":
                j += 2
                continue
            return j + 1
        if c == 0x0A:
            return i
        if c == 0x5C:
            if j + 1 >= len(buf) or buf[j + 1] == 0x0A:
                return i
            j += 2
            continue
        j += 1
    return i


def _tokens(buf: bytes):
    """Yield ``(token, text, line)`` like the ``guc-file.l`` scanner, then ``(None, '', line)``."""
    i, line = 0, 1
    while i < len(buf):
        c = buf[i]
        if c == 0x0A:
            yield _EOL, b'\n', line
            line += 1
            i += 1
            continue
        if c in b' \t\r':
            i += 1
            continue
        if c == 0x23:
            nl = buf.find(b'\n', i)
            i = len(buf) if nl < 0 else nl
            continue
        ident = _id_end(buf, i)
        qual = ident
        if ident > i and buf[ident:ident + 1] == b'.':
            second = _id_end(buf, ident + 1)
            qual = second if second > ident + 1 else ident
        candidates = [
            (ident - i, _ID),
            (qual - i if qual > ident else 0, _QID),
            (_string_end(buf, i) - i, _STRING),
            (_run(buf, i + 1, _USTRING_REST) - i if c in _LETTER else 0, _USTRING),
            (_int_end(buf, i) - i, _INT),
            (_real_end(buf, i) - i, _REAL),
            (1 if c == 0x3D else 0, _EQ),
        ]
        length, kind = 0, _ERR
        for size, token in candidates:  # flex: longest match, earlier rule on ties
            if size > length:
                length, kind = size, token
        if length == 0:
            length = 1
        yield kind, buf[i:i + length], line
        i += length
    yield None, b'', line


def _deescape(raw: bytes) -> bytes:
    body, out, i = raw[1:-1], bytearray(), 0
    simple = {ord('b'): 8, ord('f'): 12, ord('n'): 10, ord('r'): 13, ord('t'): 9}
    while i < len(body):
        c = body[i]
        if c == 0x5C and i + 1 < len(body):
            n = body[i + 1]
            if n in simple:
                out.append(simple[n])
                i += 2
            elif 0x30 <= n <= 0x37:
                j, value = i + 1, 0
                while j < len(body) and j < i + 4 and 0x30 <= body[j] <= 0x37:
                    value = value * 8 + body[j] - 0x30
                    j += 1
                out.append(value & 0xFF)
                i = j
            else:
                out.append(n)
                i += 2
        elif c == 0x27 and body[i + 1:i + 2] == b"'":
            out.append(0x27)
            i += 2
        else:
            out.append(c)
            i += 1
    return bytes(out)


def _text(raw: bytes) -> str:
    return raw.decode('utf-8', errors='backslashreplace')


def split_library_list(value: str) -> list[str] | None:
    """``SplitDirectoriesString``: the items, or ``None`` for invalid list syntax."""
    items: list[str] = []
    i, n = 0, len(value)
    while i < n and value[i].isspace():
        i += 1
    if i == n:
        return items
    while True:
        if value[i] == '"':
            out, i = [], i + 1
            while True:
                end = value.find('"', i)
                if end < 0:
                    return None
                out.append(value[i:end])
                if value[end + 1:end + 2] == '"':
                    out.append('"')
                    i = end + 2
                    continue
                i = end + 1
                break
            name = ''.join(out)
        else:
            start = i
            while i < n and value[i] != ',' and not value[i].isspace():
                i += 1
            if i == start:
                return None
            name = value[start:i]
        while i < n and value[i].isspace():
            i += 1
        items.append(name)
        if i == n:
            return items
        if value[i] != ',':
            return None
        i += 1
        while i < n and value[i].isspace():
            i += 1
        if i == n:
            return None


def placeholder_problem(command: str, allowed: str) -> str | None:
    """Why ``replace_percent_placeholders`` would raise an error, or ``None``."""
    i = 0
    while i < len(command):
        if command[i] == '%':
            if i + 1 >= len(command):
                return 'string_ends_after_percent'
            nxt = command[i + 1]
            if nxt != '%' and nxt not in allowed:
                return 'unexpected_placeholder_%' + nxt
            i += 2
            continue
        i += 1
    return None


def _parse_bool(value: str) -> bool | None:
    """``parse_bool``: case-insensitive prefixes of true/false/yes/no, ``on``, ``of(f)``,
    ``1`` and ``0``. No whitespace is trimmed."""
    low, n = value.lower(), len(value)
    if not n:
        return None
    if low[0] == 'o':
        if low == 'on':
            return True
        if n >= 2 and 'off'.startswith(low):
            return False
        return None
    if low in ('1', '0'):
        return low == '1'
    for word, result in (('true', True), ('false', False), ('yes', True), ('no', False)):
        if word.startswith(low):
            return result
    return None


def assess(files: dict[str, dict[str, Any]] | None, *, config_file: str,
           data_dir: str | None = None,
           directories: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return the commands and libraries one PostgreSQL 16 configuration makes it run.

    ``files`` maps absolute paths to ``{'state', 'text'}`` (``state`` in
    ``FILE_STATES``; ``text`` required for ``regular``). ``directories`` maps absolute
    ``include_dir`` paths to ``{'state', 'entries': [{'name', 'kind'}]}`` with ``state``
    in ``DIR_STATES`` and ``kind`` ``file``, ``dir``, ``other`` or ``unstatable``, as
    ``stat`` (which follows symlinks) sees the entry.
    ``data_dir`` is the ``-D`` directory, used when ``data_directory`` is not set.
    """
    files = files or {}
    directories = directories or {}
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
        'config_file': config_file, 'data_directory': None, 'auto_conf': None,
        'run_as': RUN_AS, 'has_errors': False, 'server_starts': None, 'errors': [],
        'files_read': [], 'settings': {}, 'commands': [], 'libraries': [], 'gaps': [],
        'not_modelled': list(NOT_MODELLED), 'complete': True, 'origin': 'not_assessed',
        'authorizes_response': False,
    }
    gaps: list[dict[str, Any]] = result['gaps']

    def gap(reason: str, **detail: Any) -> None:
        result['complete'] = False
        if len(gaps) < MAX_GAPS:
            gaps.append({'reason': reason, **detail})
        elif len(gaps) == MAX_GAPS:
            gaps.append({'reason': 'gap_limit_reached', 'limit': MAX_GAPS})

    def error(reason: str, file: str | None, line: int | None, **detail: Any) -> None:
        result['has_errors'] = True
        if len(result['errors']) < MAX_GAPS:
            result['errors'].append({'reason': reason, 'file': file, 'line': line, **detail})

    if not isinstance(config_file, str) or not config_file.startswith('/'):
        gap('config_file_not_absolute')
        result['server_starts'] = None
        return result

    def parse_file(path: str, strict: bool, calling: str | None, calling_line: int | None,
                   depth: int, items: list[dict[str, Any]], record: bool) -> bool:
        if depth > MAX_DEPTH:
            error('maximum_nesting_depth_exceeded', calling, calling_line, path=path)
            return False
        if not path.strip(' \t\r\n'):
            error('empty_configuration_file_name', calling, calling_line)
            return False
        if path.startswith('/'):
            absolute = path
        elif calling is None:
            if not result['data_directory']:
                gap('relative_path_without_directory', path=path)
                return True
            absolute = posixpath.join(result['data_directory'], path)
        else:
            absolute = posixpath.join(posixpath.dirname(calling), path)
        if calling is not None and absolute == calling:
            error('configuration_file_recursion', calling, calling_line, path=absolute)
            return False
        if len(result['files_read']) >= MAX_FILES:
            gap('file_limit_reached', limit=MAX_FILES, path=absolute)
            return True
        observed = files.get(absolute)
        state = observed.get('state') if isinstance(observed, dict) else None
        if state not in FILE_STATES:
            state = 'unknown'
        if state in ('absent', 'unreadable'):
            if strict:
                error('could_not_open_file', calling, calling_line, path=absolute, state=state)
                return False
            return True
        if state != 'regular':
            gap('file_' + state, path=absolute)
            return True
        text = observed.get('text')
        if not isinstance(text, str):
            gap('file_text_missing', path=absolute)
            return True
        try:
            buf = text.encode('utf-8')
        except UnicodeEncodeError:
            gap('file_not_utf8', path=absolute)
            return True
        if len(buf) > MAX_TEXT:
            gap('file_too_large', path=absolute, limit=MAX_TEXT)
            return True
        if b'\0' in buf:
            gap('file_contains_nul', path=absolute)
            return True
        if record:
            result['files_read'].append(absolute)
        return parse_buffer(buf, absolute, depth, items, record)

    def parse_dir(path: str, calling: str, calling_line: int, depth: int,
                  items: list[dict[str, Any]], record: bool) -> bool:
        if not path.strip(' \t\r\n'):
            error('empty_configuration_directory_name', calling, calling_line)
            return False
        absolute = path if path.startswith('/') else posixpath.join(posixpath.dirname(calling), path)
        observed = directories.get(absolute)
        state = observed.get('state') if isinstance(observed, dict) else None
        if state in ('absent', 'unreadable'):
            error('could_not_open_directory', calling, calling_line, path=absolute, state=state)
            return False
        entries = observed.get('entries') if state == 'present' else None
        if not isinstance(entries, list):
            gap('directory_not_observed', path=absolute)
            return True
        names = []
        for entry in entries:
            name = entry.get('name') if isinstance(entry, dict) else None
            kind = entry.get('kind') if isinstance(entry, dict) else None
            if not isinstance(name, str) or '/' in name or not name:
                gap('directory_entry_invalid', path=absolute)
                continue
            if len(name.encode('utf-8', 'surrogatepass')) < 6 or name.startswith('.') \
                    or not name.endswith('.conf'):
                continue
            if kind == 'dir':
                continue
            if kind == 'unstatable':
                error('could_not_stat_file', calling, calling_line,
                      path=posixpath.join(absolute, name))
                return False
            if kind not in ('file', 'other'):
                gap('directory_entry_kind_unknown', path=posixpath.join(absolute, name))
                continue
            names.append(posixpath.join(absolute, name))
        ok = True
        for name in sorted(names, key=lambda n: n.encode('utf-8', 'surrogatepass')):
            if not parse_file(name, True, calling, calling_line, depth, items, record):
                ok = False
        return ok

    def parse_buffer(buf: bytes, path: str, depth: int, items: list[dict[str, Any]],
                     record: bool) -> bool:
        ok, errors = True, 0
        stream = _tokens(buf)
        while True:
            token, raw, line = next(stream)
            if token is None:
                return ok
            if token == _EOL:
                continue
            failed = token not in (_ID, _QID)
            if not failed:
                name = _text(raw)
                token, raw, _ = next(stream)
                if token == _EQ:
                    token, raw, _ = next(stream)
                if token not in _VALUE_TOKENS:
                    failed = True
            if not failed:
                value = _text(_deescape(raw) if token == _STRING else raw)
                token, raw, _ = next(stream)
                if token not in (_EOL, None):
                    failed = True
            if failed:
                near = 'end of line' if token in (_EOL, None) else _text(raw)
                error('syntax_error', path, line, near=near[:64])
                ok = False
                errors += 1
                if errors >= MAX_SYNTAX_ERRORS:
                    return ok
                while token not in (_EOL, None):
                    token, raw, _ = next(stream)
                if token is None:
                    return ok
                continue
            low = name.lower()
            if low == 'include_dir':
                if not parse_dir(value, path, line, depth + 1, items, record):
                    ok = False
            elif low == 'include_if_exists':
                if not parse_file(value, False, path, line, depth + 1, items, record):
                    ok = False
            elif low == 'include':
                if not parse_file(value, True, path, line, depth + 1, items, record):
                    ok = False
            else:
                items.append({'name': low, 'value': value, 'file': path, 'line': line})
            if token is None:
                return ok

    # First pass: the main file only, to find data_directory (errors are reported by the
    # second pass, which rereads the same files).
    first: list[dict[str, Any]] = []
    errors_before = list(result['errors'])
    gaps_before = list(gaps)
    first_ok = parse_file(config_file, True, None, None, 0, first, False)
    result['errors'][:] = errors_before
    result['has_errors'] = False
    gaps[:] = gaps_before
    result['complete'] = not gaps
    data_directory = None
    for item in first:
        if item['name'] == 'data_directory':
            data_directory = item['value']
    if not first_ok:
        data_directory = None
    if data_directory == '':
        gap('data_directory_empty')
        data_directory = None
    elif data_directory is not None:
        if not data_directory.startswith('/'):
            gap('data_directory_relative', value=data_directory)
            data_directory = None
    else:
        data_directory = data_dir if isinstance(data_dir, str) and data_dir.startswith('/') else None
        if data_directory is None:
            gap('data_directory_unknown')
    result['data_directory'] = data_directory

    items: list[dict[str, Any]] = []
    main_ok = parse_file(config_file, True, None, None, 0, items, True)
    if main_ok and data_directory:
        auto = posixpath.join(data_directory, AUTO_CONF)
        result['auto_conf'] = auto
        if auto not in files:
            gap('auto_conf_not_observed', path=auto)
        elif not parse_file(auto, False, None, None, 0, items, True):
            pass

    winners: dict[str, dict[str, Any]] = {}
    history: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        winners[item['name']] = item
        if item['name'] in MODELLED:
            history.setdefault(item['name'], []).append(item)
    settings: dict[str, Any] = result['settings']
    for name, rows in history.items():
        last = rows[-1]
        settings[name] = {'value': last['value'], 'file': last['file'], 'line': last['line'],
                          'superseded': [{k: r[k] for k in ('value', 'file', 'line')}
                                         for r in rows[:-1]]}

    def value(name: str) -> str:
        row = winners.get(name)
        return row['value'] if row else DEFAULTS.get(name, '')

    def where(name: str) -> dict[str, Any]:
        row = winners.get(name)
        return {'file': row['file'], 'line': row['line']} if row else {'file': None, 'line': None}

    enums: dict[str, str | None] = {}
    for name, table in ENUMS.items():
        enums[name] = table.get(value(name).lower())
        if enums[name] is None:
            error('invalid_value', where(name)['file'], where(name)['line'], setting=name,
                  value=value(name)[:64])
    bools: dict[str, bool | None] = {}
    for name in BOOLS:
        bools[name] = _parse_bool(value(name))
        if bools[name] is None:
            error('invalid_value', where(name)['file'], where(name)['line'], setting=name,
                  value=value(name)[:64])
    lib_lists: dict[str, list[str] | None] = {}
    for name in LIBRARIES:
        lib_lists[name] = split_library_list(value(name))

    if result['has_errors']:
        result['server_starts'] = False
        result['start_blocker'] = 'configuration_file_contains_errors'
    elif enums['archive_mode'] != 'off' and enums['wal_level'] == 'minimal':
        result['server_starts'] = False
        result['start_blocker'] = 'archive_mode_requires_wal_level_above_minimal'
    else:
        result['server_starts'] = True
        result['start_blocker'] = None
    starts = result['server_starts']

    archive_library = value('archive_library')
    for name, (allowed, when) in COMMANDS.items():
        command = value(name)
        if not command:
            continue
        problem = placeholder_problem(command, allowed)
        active = bool(starts) and problem is None
        reason = None if starts else result['start_blocker']
        conditions: list[str] = []
        if name == 'archive_command':
            if enums['archive_mode'] == 'off':
                active, reason = False, reason or 'archive_mode_off'
            elif archive_library:
                active, reason = False, reason or 'archive_library_also_set'
            else:
                conditions.append('archive_mode_' + str(enums['archive_mode']))
                if enums['archive_mode'] == 'on':
                    conditions.append('not_while_standby')
        elif name in ('restore_command', 'recovery_end_command', 'archive_cleanup_command'):
            conditions.append('recovery_or_standby_signal_file_present')
        elif name == 'ssl_passphrase_command':
            if bools['ssl'] is False:
                active, reason = False, reason or 'ssl_off'
            conditions.append('ssl_key_file_has_passphrase')
            conditions.append('reload_runs_it' if bools['ssl_passphrase_command_supports_reload']
                              else 'start_only')
        if problem and reason is None:
            reason = problem
        result['commands'].append({
            'setting': name, 'command': command, **where(name), 'when': when,
            'conditions': conditions, 'active': active, 'inactive_reason': None if active else reason,
            'placeholders': sorted(set(allowed)), 'placeholder_error': problem,
            'invocation': [*SHELL, command], 'run_as': RUN_AS,
        })
    if archive_library:
        active = bool(starts) and enums['archive_mode'] != 'off' and not value('archive_command')
        reason = None if active else (result['start_blocker'] or (
            'archive_mode_off' if enums['archive_mode'] == 'off' else 'archive_command_also_set'))
        result['libraries'].append({
            'setting': 'archive_library', 'library': archive_library, **where('archive_library'),
            'when': 'archiver_start', 'active': active, 'inactive_reason': reason,
            'run_as': RUN_AS})
    for name, when in LIBRARIES.items():
        if lib_lists[name] is None:
            # load_libraries() logs "invalid list syntax" and loads nothing; the server starts.
            result['libraries'].append({
                'setting': name, 'library': None, 'raw_value': value(name), **where(name),
                'when': when, 'active': False,
                'inactive_reason': 'invalid_list_syntax_nothing_loaded', 'run_as': RUN_AS})
            continue
        for library in lib_lists[name]:
            result['libraries'].append({
                'setting': name, 'library': library, **where(name), 'when': when,
                'active': bool(starts), 'inactive_reason': None if starts else result['start_blocker'],
                'run_as': RUN_AS})
    if any(row['library'] and '/' not in row['library'] for row in result['libraries']):
        result['dynamic_library_path'] = value('dynamic_library_path') or '$libdir'
    return result
