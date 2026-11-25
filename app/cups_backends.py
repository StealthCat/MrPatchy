"""Pure CUPS backend contract (roadmap F slice, #1532).

cupsd sends every print job's final output to a backend program,
``<ServerBin>/backend/<scheme>``, where ``<scheme>`` is the part of the
queue's ``DeviceURI`` before the first ``:``. cupsd runs that backend as root
whenever the file has no world-execute bit (for example mode 0700 or 0744),
and as the unprivileged ``User`` from ``cups-files.conf`` (``lp`` on Debian
and Ubuntu) otherwise. A changed ``DeviceURI`` line or a new backend file
therefore makes cupsd run a new program, possibly as root, on the next job.

This module turns captured ``printers.conf`` and ``cups-files.conf`` text,
captured ``stat()`` metadata for the backend files and their directory, and
captured ``/etc/passwd`` and ``/etc/group`` text into the backend each queue
runs, its argv[0] and the account it runs as. It performs no I/O, never runs
cupsd or a backend and never authorizes a response action.

The rules follow upstream CUPS 2.4.7, checked against a native run of
Ubuntu 24.04 ``cups-daemon 2.4.7-1.2ubuntu7.14``:

- ``cupsFileGets`` ends a line at CR, LF or CR LF and reads at most the
  buffer size less one byte (4095 for ``printers.conf``, 2047 for
  ``cups-files.conf``); a longer line would be split, which is a blocking gap.
- ``cupsFileGetConf`` looks only at the first ``#``. ``\\#`` drops the
  backslash and keeps the ``#`` (later ``#`` bytes then stay too); otherwise
  the ``#`` and the whitespace before it end the line. Leading whitespace is
  skipped (``_cups_isspace``: space, tab, LF, VT, FF, CR), the first word is
  the directive and the rest, with trailing whitespace removed, is the value.
  A line starting with ``<`` needs a value ending in ``>``, which is removed;
  otherwise the value is dropped.
- ``cupsdLoadAllPrinters`` matches directives case-insensitively.
  ``<Printer name>`` and ``<DefaultPrinter name>`` open a queue (idle and
  accepting, with ``DeviceURI file:///dev/null``) only outside another queue;
  ``</Printer>``/``</DefaultPrinter>`` close it. The last ``DeviceURI`` wins
  and ``State Idle``/``State Stopped`` set the queue state. On close, a queue
  that is not stopped and whose backend does not exist is stopped.
- ``cupsdSetDeviceURI`` keeps the full URI for ``DEVICE_URI`` and passes a
  copy without the ``user:password@`` part as argv[0]. This contract reports
  only the sanitized copy and whether credentials were present.
- ``cupsdContinueJob`` starts no backend for ``file:`` URIs. Otherwise it
  reads the scheme with ``sscanf("%254[^:]")``, builds
  ``<ServerBin>/backend/<scheme>`` and sets ``backroot`` when cupsd runs as
  root, ``stat`` succeeds and the mode has none of group-write, other-write
  and other-execute.
- ``cupsdStartProcess`` first runs ``_cupsFileCheck`` (with root checks only
  when cupsd runs as root): no ``../`` in the path, the file exists and is a
  regular file (``stat`` follows symlinks), is owned by root, is not
  group- or other-writable and is not setuid, and its directory passes the
  same ownership and write checks. A failure stops the job. The child runs as
  root for ``backroot`` and as ``User`` otherwise, always with group
  ``Group``. When cupsd itself is not root, everything runs as cupsd's uid.
- ``read_cups_files_conf`` sets ``User`` (a leading digit means a numeric
  uid; 0 and unknown names are refused), ``Group`` (unknown names are fatal)
  and ``ServerBin`` (relative to ``ServerRoot``, applied only when it
  exists). The same directives in ``cupsd.conf`` are ignored by cupsd, so
  that file is not an input.

Unobserved metadata or accounts, over-long or NUL-containing lines,
unterminated or duplicate queues, schemes cupsd cannot map to a flat backend
name, refused ``User``/``Group`` values and ``ServerRoot`` relocation are
blocking gaps, and ``complete`` is false whenever one is present. ``origin``
is always ``not_assessed`` and ``authorizes_response`` is always false.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

CONTRACT_VERSION = 1
SOURCE_VERSION = 'cups 2.4.7 (Ubuntu 24.04 cups-daemon 2.4.7-1.2ubuntu7.14)'

DEFAULT_SERVER_ROOT = '/etc/cups'
DEFAULT_SERVER_BIN = '/usr/lib/cups'
DEFAULT_USER = 'lp'
DEFAULT_GROUP = 'lp'
NOBODY_ID = 65534

PRINTERS_LINE_BUFFER = 4096          # printers.c: char line[4096]
CUPS_FILES_LINE_BUFFER = 2048        # conf.c: char line[HTTP_MAX_BUFFER]
COMMAND_BUFFER = 1024                # job.c: char command[1024]
URI_BUFFER = 1024                    # printers.c cupsdSetDeviceURI: char buffer[1024]
SCHEME_MAX = 254                     # job.c: sscanf("%254[^:]")
MAX_TEXT = 4 * 1024 * 1024
MAX_PRINTERS = 2000
UID_MAX = 0xFFFFFFFF

S_IFMT = 0o170000
S_IFREG = 0o100000
S_IFDIR = 0o040000
S_ISUID = 0o4000
S_IWGRP = 0o020
S_IWOTH = 0o002
S_IXOTH = 0o001

_WHITESPACE = ' \t\n\v\f\r'
_LINE_BREAK = re.compile(r'\r\n|\r|\n')


def _ascii_lower(text: str) -> str:
    """``_cups_strcasecmp`` folds ASCII letters only."""
    return ''.join(chr(ord(ch) + 32) if 'A' <= ch <= 'Z' else ch for ch in text)


def _byte_length(text: str) -> int:
    return len(text.encode('utf-8', 'surrogateescape'))


class _State:
    def __init__(self) -> None:
        self.gaps: list[dict[str, Any]] = []
        self.notes: list[dict[str, Any]] = []

    def gap(self, code: str, *, blocking: bool = True, **detail: Any) -> None:
        entry = {'code': code, 'blocking': blocking}
        entry.update(detail)
        if entry not in self.gaps:
            self.gaps.append(entry)

    def note(self, code: str, **detail: Any) -> None:
        entry = {'code': code}
        entry.update(detail)
        self.notes.append(entry)


def _checked_text(name: str, text: Any, state: _State) -> str | None:
    if text is None:
        return None
    if isinstance(text, bytes):
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            text = text.decode('utf-8', 'surrogateescape')
    if not isinstance(text, str):
        state.gap('file_invalid', file=name, reason='not_text')
        return None
    if len(text) > MAX_TEXT:
        state.gap('file_invalid', file=name, reason='oversized')
        return None
    if '\0' in text:
        # C string functions would stop at the NUL; the rest of that line is
        # invisible to cupsd and the line split is not modelled.
        state.gap('file_invalid', file=name, reason='nul_byte')
        return None
    return text


def read_conf_lines(text: str, buffer_size: int, name: str,
                    state: _State) -> list[tuple[int, str, str | None]]:
    """Return ``(line_number, directive, value)`` as ``cupsFileGetConf`` yields them."""
    rows: list[tuple[int, str, str | None]] = []
    physical = _LINE_BREAK.split(text)
    if physical and physical[-1] == '':
        physical.pop()
    for number, raw in enumerate(physical, start=1):
        if _byte_length(raw) > buffer_size - 1:
            state.gap('line_too_long', file=name, line=number, limit=buffer_size - 1)
            continue
        parsed = parse_conf_line(raw)
        if parsed is not None:
            rows.append((number, parsed[0], parsed[1]))
    return rows


def parse_conf_line(raw: str) -> tuple[str, str | None] | None:
    """Apply ``cupsFileGetConf`` to one line; ``None`` when nothing is left."""
    buf = raw
    hash_at = buf.find('#')
    if hash_at >= 0:
        if hash_at > 0 and buf[hash_at - 1] == '\\':
            buf = buf[:hash_at - 1] + buf[hash_at:]
        else:
            end = hash_at
            while end > 0 and buf[end - 1] in _WHITESPACE:
                end -= 1
            buf = buf[:end]
    buf = buf.lstrip(_WHITESPACE)
    if not buf:
        return None
    split = 0
    while split < len(buf) and buf[split] not in _WHITESPACE:
        split += 1
    directive = buf[:split]
    value = buf[split:].lstrip(_WHITESPACE)
    if not value:
        return directive, None
    if directive.startswith('<'):
        if not value.endswith('>'):
            return directive, None
        value = value[:-1]
    # The C loop stops at the value's first byte, which is never whitespace,
    # so stripping trailing whitespace can leave an empty (non-NULL) value.
    return directive, value.rstrip(_WHITESPACE)


def sanitize_device_uri(uri: str) -> str:
    """Return argv[0] as ``cupsdSetDeviceURI`` builds it (credentials removed)."""
    encoded = uri.encode('utf-8', 'surrogateescape')[:URI_BUFFER - 1]
    buffer = encoded.decode('utf-8', 'surrogateescape')
    colon = buffer.find(':')
    if colon < 0:
        return buffer
    start = colon + 1
    while start < len(buffer) and buffer[start] == '/':
        start += 1
    slash = buffer.find('/', start)
    if slash < 0:
        slash = len(buffer)
    at = buffer.find('@', start)
    if 0 <= at < slash:
        buffer = buffer[:start] + buffer[at + 1:]
    return buffer


def _uri_has_credentials(uri: str) -> bool:
    return sanitize_device_uri(uri) != uri.encode('utf-8', 'surrogateescape')[:URI_BUFFER - 1].decode(
        'utf-8', 'surrogateescape')


def _parse_accounts(text: str | None) -> dict[str, int] | None:
    if text is None:
        return None
    accounts: dict[str, int] = {}
    for line in text.splitlines():
        fields = line.split(':')
        if len(fields) < 3 or not fields[0] or fields[0] in accounts:
            continue
        if fields[2].isascii() and fields[2].isdigit():
            accounts[fields[0]] = int(fields[2])
    return accounts


def _names_by_id(accounts: Mapping[str, int] | None) -> dict[int, str]:
    names: dict[int, str] = {}
    for name, number in (accounts or {}).items():
        names.setdefault(number, name)
    return names


def _numeric_id(value: str) -> int | None:
    """``strtoul`` of a value that starts with a digit; ``None`` when not modelled exactly."""
    if not (value.isascii() and value.isdigit()):
        return None
    number = int(value)
    return number if number <= UID_MAX else None


def _normal_path(path: str) -> str:
    return re.sub('/+', '/', path) if path != '/' else path


def _meta(file_meta: Mapping[str, Any], path: str) -> tuple[bool, Mapping[str, Any] | None]:
    """Return ``(observed, stat)`` for ``path``; ``stat`` is ``None`` when it does not exist."""
    for key in (path, _normal_path(path)):
        if key in file_meta:
            entry = file_meta[key]
            if entry is None:
                return True, None
            if isinstance(entry, Mapping) and isinstance(entry.get('mode'), int) \
                    and isinstance(entry.get('uid'), int):
                return True, entry
            return False, None
    return False, None


def _read_cups_files(text: str | None, file_meta: Mapping[str, Any], passwd: Mapping[str, int] | None,
                     groups: Mapping[str, int] | None, state: _State) -> dict[str, Any]:
    settings: dict[str, Any] = {
        'server_root': DEFAULT_SERVER_ROOT,
        'server_bin': DEFAULT_SERVER_BIN,
        'user': None, 'uid': None, 'user_source': 'default',
        'group': None, 'gid': None, 'group_source': 'default',
    }
    # Compiled-in defaults: getpwnam("lp") else 65534; getgrnam("lp") else
    # getgrnam("nobody") else 65534.
    if passwd is None:
        state.gap('accounts_not_supplied', blocking=False, database='passwd')
        settings['user'] = DEFAULT_USER
    elif DEFAULT_USER in passwd:
        settings['user'], settings['uid'] = DEFAULT_USER, passwd[DEFAULT_USER]
    else:
        settings['uid'] = NOBODY_ID
    if groups is None:
        state.gap('accounts_not_supplied', blocking=False, database='group')
        settings['group'] = DEFAULT_GROUP
    elif DEFAULT_GROUP in groups:
        settings['group'], settings['gid'] = DEFAULT_GROUP, groups[DEFAULT_GROUP]
    elif 'nobody' in groups:
        settings['group'], settings['gid'] = 'nobody', groups['nobody']
    else:
        settings['gid'] = NOBODY_ID
    text = _checked_text('cups-files.conf', text, state)
    if text is None:
        return settings
    for number, directive, value in read_conf_lines(text, CUPS_FILES_LINE_BUFFER, 'cups-files.conf', state):
        name = _ascii_lower(directive)
        if name == 'user':
            if value is None:
                state.gap('cups_files_value_missing', directive=directive, line=number)
                continue
            if value[:1].isascii() and value[:1].isdigit():
                uid = _numeric_id(value)
                if uid is None:
                    state.gap('user_value_not_modelled', line=number)
                elif uid == 0:
                    state.gap('user_root_refused', line=number)
                else:
                    settings.update(user=_names_by_id(passwd).get(uid), uid=uid, user_source='cups-files.conf')
            elif passwd is None:
                settings.update(user=value, uid=None, user_source='cups-files.conf')
            elif value not in passwd:
                state.gap('user_unknown', line=number)
            elif passwd[value] == 0:
                state.gap('user_root_refused', line=number)
            else:
                settings.update(user=value, uid=passwd[value], user_source='cups-files.conf')
        elif name == 'group':
            if value is None:
                state.gap('cups_files_value_missing', directive=directive, line=number)
                continue
            if value[:1].isascii() and value[:1].isdigit():
                gid = _numeric_id(value)
                if gid is None:
                    state.gap('group_value_not_modelled', line=number)
                else:
                    settings.update(group=_names_by_id(groups).get(gid), gid=gid, group_source='cups-files.conf')
            elif groups is None:
                settings.update(group=value, gid=None, group_source='cups-files.conf')
            elif value not in groups:
                state.gap('group_unknown', line=number)
            else:
                settings.update(group=value, gid=groups[value], group_source='cups-files.conf')
        elif name == 'serverroot':
            state.gap('server_root_relocated', line=number)
        elif name == 'serverbin':
            if value is None:
                state.gap('cups_files_value_missing', directive=directive, line=number)
                continue
            candidate = value if value.startswith('/') else f"{settings['server_root']}/{value}"
            if _byte_length(candidate) > COMMAND_BUFFER - 1:
                state.gap('server_bin_not_modelled', line=number, reason='too_long')
                continue
            observed, entry = _meta(file_meta, candidate)
            if not observed:
                state.gap('metadata_unobserved', path=candidate, role='server_bin')
            elif entry is None:
                state.gap('server_bin_missing', line=number, path=candidate)
            else:
                settings['server_bin'] = candidate
    return settings


def _scheme(uri: str) -> tuple[str | None, str | None]:
    """Return ``(scheme, problem)`` as ``sscanf("%254[^:]")`` reads it."""
    if not uri or uri.startswith(':'):
        return None, 'scheme_empty'
    colon = uri.find(':')
    prefix = uri if colon < 0 else uri[:colon]
    if _byte_length(prefix) > SCHEME_MAX:
        return None, 'scheme_too_long'
    if '/' in prefix:
        return None, 'scheme_contains_slash'
    return prefix, None


def _file_check(command: str, file_meta: Mapping[str, Any], root_checks: bool,
                state: _State) -> tuple[str | None, Mapping[str, Any] | None]:
    """Return ``(_cupsFileCheck result, backend stat)``; result ``None`` when unobserved."""
    if '../' in command:
        return 'relative_path', None
    observed, entry = _meta(file_meta, command)
    if not observed:
        state.gap('metadata_unobserved', path=command, role='backend')
        return None, None
    if entry is None:
        return 'missing', None
    mode = int(entry['mode'])
    if mode & S_IFMT != S_IFREG:
        return 'wrong_type', entry
    if not root_checks:
        return 'ok', entry
    if int(entry['uid']) != 0 or mode & (S_IWGRP | S_ISUID | S_IWOTH):
        return 'insecure_permissions', entry
    slash = command.rfind('/')
    directory = '/' if slash == 0 else command[:slash]
    observed, parent = _meta(file_meta, directory)
    if not observed:
        state.gap('metadata_unobserved', path=directory, role='backend_directory')
        return None, entry
    if parent is None:
        return 'directory_missing', entry
    parent_mode = int(parent['mode'])
    if int(parent['uid']) != 0 or parent_mode & (S_IWGRP | S_ISUID | S_IWOTH):
        return 'directory_insecure_permissions', entry
    return 'ok', entry


def _backend_row(printer: dict[str, Any], settings: Mapping[str, Any], file_meta: Mapping[str, Any],
                 cupsd_uid: int, state: _State) -> dict[str, Any]:
    uri = printer.pop('_uri')
    row: dict[str, Any] = {
        'printer': printer['name'],
        'default': printer['default'],
        'line': printer['line'],
        'device_uri_line': printer['device_uri_line'],
        'argv0': sanitize_device_uri(uri),
        'uri_has_credentials': _uri_has_credentials(uri),
        'state': printer['state'],
        'runs_backend': False,
        'executable': None,
        'file_check': None,
        'runs_as_root': False,
        'run_user': None, 'run_uid': None, 'run_group': None, 'run_gid': None,
    }
    if uri.startswith('file:'):
        row['file_check'] = 'file_device_no_backend'
        return row
    scheme, problem = _scheme(uri)
    if scheme is None:
        state.gap(problem or 'scheme_empty', printer=printer['name'])
        row['file_check'] = None
        return row
    command = f"{settings['server_bin']}/backend/{scheme}"
    if _byte_length(command) > COMMAND_BUFFER - 1:
        state.gap('backend_path_too_long', printer=printer['name'])
        return row
    row['executable'] = command
    result, entry = _file_check(command, file_meta, cupsd_uid == 0, state)
    row['file_check'] = result
    if result is None:
        return row
    if row['state'] != 'stopped' and result == 'missing':
        # cupsdLoadAllPrinters: access() fails, so the queue is stopped with
        # "Backend ... does not exist!".
        row['state'] = 'stopped'
        row['stopped_reason'] = 'backend_missing'
    if result != 'ok':
        return row
    row['runs_backend'] = True
    if cupsd_uid != 0:
        row.update(run_uid=cupsd_uid, run_user=None)
        return row
    mode = int(entry['mode']) if entry else 0
    if not mode & (S_IWGRP | S_IWOTH | S_IXOTH):
        row.update(runs_as_root=True, run_user='root', run_uid=0)
    else:
        row.update(run_user=settings['user'], run_uid=settings['uid'])
        if settings['uid'] is None:
            state.gap('run_account_unresolved', printer=printer['name'])
    row.update(run_group=settings['group'], run_gid=settings['gid'])
    if settings['gid'] is None:
        state.gap('run_account_unresolved', printer=printer['name'], database='group')
    return row


def _read_printers(text: str | None, state: _State) -> list[dict[str, Any]]:
    printers: list[dict[str, Any]] = []
    text = _checked_text('printers.conf', text, state)
    if text is None:
        return printers
    current: dict[str, Any] | None = None
    seen: set[str] = set()
    for number, directive, value in read_conf_lines(text, PRINTERS_LINE_BUFFER, 'printers.conf', state):
        name = _ascii_lower(directive)
        if name == 'nextprinterid':
            continue
        if name in ('<printer', '<defaultprinter'):
            if current is None and value is not None:
                if len(printers) >= MAX_PRINTERS:
                    state.gap('too_many_printers', limit=MAX_PRINTERS)
                    break
                if value == '':
                    state.gap('printer_name_empty', line=number)
                if value in seen:
                    state.gap('duplicate_printer_name', printer=value, line=number)
                seen.add(value)
                current = {'name': value, 'default': name == '<defaultprinter', 'line': number,
                           '_uri': 'file:///dev/null', 'device_uri_line': None, 'state': 'idle'}
            else:
                state.note('syntax_error', file='printers.conf', line=number)
        elif name in ('</printer>', '</defaultprinter>'):
            if current is None:
                state.note('syntax_error', file='printers.conf', line=number)
            else:
                printers.append(current)
                current = None
        elif current is None:
            state.note('syntax_error', file='printers.conf', line=number)
        elif name == 'deviceuri':
            if value is None:
                state.note('syntax_error', file='printers.conf', line=number)
            else:
                current['_uri'] = value
                current['device_uri_line'] = number
        elif name == 'state':
            lowered = _ascii_lower(value) if value is not None else None
            if lowered == 'idle':
                current['state'] = 'idle'
            elif lowered == 'stopped':
                current['state'] = 'stopped'
            else:
                state.note('syntax_error', file='printers.conf', line=number)
    if current is not None:
        # The queue exists but is never closed, so cupsd skips the close-time
        # attribute setup and backend check; its behaviour is not modelled.
        state.gap('printer_unterminated', printer=current['name'], line=current['line'])
        current.pop('_uri', None)
    return printers


def evaluate(*, printers_conf: str | bytes | None, cups_files_conf: str | bytes | None = None,
             file_meta: Mapping[str, Any] | None = None, passwd_text: str | None = None,
             group_text: str | None = None, cupsd_uid: int = 0) -> dict[str, Any]:
    """Return the backend each captured queue runs and the account it runs as.

    ``file_meta`` maps absolute paths to ``stat()`` (symlinks followed)
    results, ``{'mode': st_mode, 'uid': st_uid}``, or ``None`` when the path
    does not exist. A path missing from the mapping is unobserved. It must
    cover each ``<ServerBin>/backend/<scheme>`` file, its directory and any
    ``ServerBin`` set in ``cups-files.conf``. ``cupsd_uid`` is cupsd's real
    uid (0 for the packaged ``cupsd -l`` service).
    """
    state = _State()
    file_meta = file_meta or {}
    digest = hashlib.sha256()
    for part in (printers_conf, cups_files_conf, passwd_text, group_text):
        raw = part.encode('utf-8', 'surrogateescape') if isinstance(part, str) else (part or b'')
        digest.update(len(raw).to_bytes(8, 'big') + raw)
    if not isinstance(cupsd_uid, int) or isinstance(cupsd_uid, bool) or not 0 <= cupsd_uid <= UID_MAX:
        state.gap('cupsd_uid_invalid')
        cupsd_uid = 0
    passwd = _parse_accounts(passwd_text)
    groups = _parse_accounts(group_text)
    settings = _read_cups_files(cups_files_conf, file_meta, passwd, groups, state)
    if printers_conf is None:
        state.gap('printers_conf_not_supplied')
    backends = [_backend_row(printer, settings, file_meta, cupsd_uid, state)
                for printer in _read_printers(printers_conf, state)]
    blocking = [gap for gap in state.gaps if gap['blocking']]
    return {
        'contract': 'cups_backends',
        'contract_version': CONTRACT_VERSION,
        'source_version': SOURCE_VERSION,
        'input_sha256': digest.hexdigest(),
        'complete': not blocking,
        'server_root': settings['server_root'],
        'server_bin': settings['server_bin'],
        'cupsd_uid': cupsd_uid,
        'user': {'name': settings['user'], 'uid': settings['uid'], 'source': settings['user_source']},
        'group': {'name': settings['group'], 'gid': settings['gid'], 'source': settings['group_source']},
        'backends': backends,
        'root_backends': [row['printer'] for row in backends if row['runs_as_root']],
        'gaps': state.gaps,
        'notes': state.notes,
        'origin': 'not_assessed',
        'authorizes_response': False,
    }
