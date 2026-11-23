"""Pure snmptrapd traphandle contract (roadmap F slice, #1431).

``snmptrapd`` receives SNMP notifications. A ``traphandle`` line in
``snmptrapd.conf`` makes the daemon run a shell command for every matching
trap, with the trap details on standard input. The packaged Debian/Ubuntu
service (``ExecStart=/usr/sbin/snmptrapd -LOw -f udp:162 udp6:162``) runs as
root, and the remote sender decides when a trap arrives. This module turns
captured configuration text into the handlers the daemon would register and
whether any configured authorization lets a trap execute them. It performs no
I/O, never runs snmptrapd and never authorizes a response action.

The rules follow ``snmptrapd_handlers.c``, ``snmptrapd_auth.c`` and
``read_config.c`` in net-snmp 5.9.4 (Ubuntu 24.04
``snmptrapd 5.9.4+dfsg-1.1ubuntu3.3``). The behaviours below were also checked
against that real daemon:

- Configuration files are read in the order the caller captured them (on
  Ubuntu: ``/etc/snmp/snmptrapd.conf``, then the persistent
  ``/var/lib/snmp/snmptrapd.conf``). Lines are not continued with a
  backslash. After leading blanks, an empty line or one starting with ``#`` is
  ignored. The first word is the directive, matched ASCII case-insensitively.
- ``traphandle [-F FORMAT] OID|default COMMAND`` registers ``COMMAND``: the
  rest of the line, unchanged, run through ``/bin/sh -c``. A trailing ``*``
  makes the OID a subtree match and ``.*`` a strict subtree match. ``default``
  is case-sensitive. Every
  ``default`` handler runs when no OID handler matches. A line without a
  command is rejected.
- A handler runs only for a trap with ``execute`` access. That needs an
  ``authCommunity``, ``authUser``, ``authGroup`` or ``authAccess`` line whose
  comma-separated types include ``execute`` (case-sensitive: ``Execute`` grants
  nothing), or ``disableAuthorization yes``
  (the last ``disableAuthorization`` line wins). ``log`` or ``net`` access
  alone does not run handlers.

Which handler a given trap OID selects depends on net-snmp's lookup order and
the MIBs loaded, so this contract reports each handler's match specification
rather than the traps that select it. Whether a sender can satisfy a
community, user, source or view restriction is not visible from the text.

Fail-closed rules: an unchecked file, invalid UTF-8, NUL bytes, over-limit
input, an overlong line, an unknown service user, ``includeFile`` /
``includeDir`` / ``includeSearch``, ``[section]`` context switches, embedded
``perl`` handlers and an unparseable ``disableAuthorization`` value mark the
result incomplete. ``origin`` is always ``not_assessed`` and no result is a
safety verdict.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 1
MAX_FILES = 16
MAX_TEXT_BYTES = 256 * 1024
MAX_HANDLERS = 256
# read_config() reads each line into a fixed STRINGMAX (1024) buffer; a longer
# line is split by fgets() into pieces that are parsed as separate lines.
MAX_LINE_CHARS = 1023
DEFAULT_FILES = ('/etc/snmp/snmptrapd.conf', '/var/lib/snmp/snmptrapd.conf')
AUTH_DIRECTIVES = ('authcommunity', 'authuser', 'authgroup', 'authaccess')
INCLUDE_DIRECTIVES = ('includefile', 'includedir', 'includesearch')
NOT_OBSERVED = (
    'which trap OIDs select each handler',
    'whether a sender can satisfy the community, user, source or view restriction',
    'whether each command exists or succeeds',
    'command-line -c/-C options and SNMPCONFPATH overrides of the read files',
)
_LOWER = {c: c + 32 for c in range(ord('A'), ord('Z') + 1)}
_BLANKS = ' \t'
_TRUE = ('yes', 'true', '1')
_FALSE = ('no', 'false', '0')


def _lower(value: str) -> str:
    return value.translate(_LOWER)


def _gap(gaps: list, code: str, where: str, detail: str = '', *, blocking: bool = True) -> None:
    gaps.append({'code': code, 'where': where, 'detail': detail, 'blocking': blocking})


def _next_word(rest: str) -> tuple[str, str]:
    """Return the next blank-separated word and the remainder after its trailing blanks."""
    rest = rest.lstrip(_BLANKS)
    if rest[:1] in ('"', "'"):
        # copy_nword(): a quoted word ends at the matching quote; a backslash
        # copies the next character literally.
        quote, out, i = rest[0], [], 1
        while i < len(rest) and rest[i] != quote:
            if rest[i] == '\\' and i + 1 < len(rest):
                i += 1
            out.append(rest[i])
            i += 1
        return ''.join(out), rest[i + 1:].lstrip(_BLANKS)
    i = 0
    while i < len(rest) and rest[i] not in _BLANKS:
        i += 1
    return rest[:i], rest[i:].lstrip(_BLANKS)


def _decode(text: Any, path: str, gaps: list) -> str | None:
    if isinstance(text, str):
        raw = text.encode('utf-8', 'surrogatepass')
    elif isinstance(text, (bytes, bytearray)):
        raw = bytes(text)
    else:
        _gap(gaps, 'text_not_captured', path)
        return None
    if len(raw) > MAX_TEXT_BYTES:
        _gap(gaps, 'text_over_limit', path, f'{len(raw)} bytes')
        return None
    if b'\x00' in raw:
        _gap(gaps, 'nul_byte', path)
        return None
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', path)
        return None


def _parse_traphandle(rest: str, where: str, gaps: list) -> dict[str, Any] | None:
    word, rest = _next_word(rest)
    fmt = None
    if word.startswith('-F'):
        fmt, rest = _next_word(rest)
        word, rest = _next_word(rest)
    command = rest.rstrip(_BLANKS + '\r')
    if not word or not command:
        _gap(gaps, 'traphandle_without_command', where, 'snmptrapd rejects this line', blocking=False)
        return None
    if word == 'default':  # upstream compares with strcmp()
        return {'match': 'default', 'oid': None, 'subtree': False, 'strict_subtree': False,
                'format': fmt, 'command': command}
    oid, subtree, strict = word, False, False
    if oid.endswith('*'):
        subtree, oid = True, oid[:-1]
        if oid.endswith('.'):
            strict, oid = True, oid[:-1]
    numeric = oid.lstrip('.')
    if not numeric or not all(part.isdigit() and part.isascii() for part in numeric.split('.')):
        # Symbolic OIDs resolve through the MIBs loaded at runtime; a name that
        # does not resolve makes snmptrapd drop the line.
        _gap(gaps, 'symbolic_oid', where, word)
    return {'match': 'oid', 'oid': oid, 'subtree': subtree, 'strict_subtree': strict,
            'format': fmt, 'command': command}


def evaluate(*, files: Sequence[Mapping[str, Any]] | None, service_user: str | None = 'root') -> dict[str, Any]:
    """Evaluate captured snmptrapd configuration files in read order.

    Each file mapping has ``path``, ``exists`` (``True``, ``False`` or ``None``
    when unchecked) and ``text`` (str or bytes) when it exists.
    """
    gaps: list[dict[str, Any]] = []
    handlers: list[dict[str, Any]] = []
    grants: list[dict[str, Any]] = []
    disable: dict[str, Any] | None = None
    read: list[dict[str, Any]] = []
    if service_user is None:
        _gap(gaps, 'service_user_unknown', 'snmptrapd.service')
    if files is None:
        _gap(gaps, 'files_not_captured', 'snmptrapd')
        files = ()
    elif len(files) > MAX_FILES:
        _gap(gaps, 'too_many_files', 'snmptrapd', str(len(files)))
        files = files[:MAX_FILES]
    for entry in files:
        path = str(entry.get('path') or '')
        exists = entry.get('exists')
        if exists is None:
            _gap(gaps, 'file_not_checked', path)
            read.append({'path': path, 'state': 'not_checked', 'sha256': None})
            continue
        if not exists:
            read.append({'path': path, 'state': 'absent', 'sha256': None})
            continue
        text = _decode(entry.get('text'), path, gaps)
        if text is None:
            read.append({'path': path, 'state': 'unreadable', 'sha256': None})
            continue
        read.append({'path': path, 'state': 'read',
                     'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()})
        for number, raw in enumerate(text.split('\n'), 1):
            where = f'{path}:{number}'
            if len(raw) > MAX_LINE_CHARS:
                _gap(gaps, 'line_over_limit', where, f'{len(raw)} characters')
                continue
            line = raw.lstrip(_BLANKS).rstrip('\r')
            if not line or line.startswith('#'):
                continue
            if line.startswith('['):
                _gap(gaps, 'section_context', where, line.split(']', 1)[0] + ']')
                continue
            directive, rest = _next_word(line)
            name = _lower(directive)
            if name == 'traphandle':
                handler = _parse_traphandle(rest, where, gaps)
                if handler is None:
                    continue
                if len(handlers) >= MAX_HANDLERS:
                    _gap(gaps, 'too_many_handlers', where)
                    break
                handler.update({'source': where, 'shell': '/bin/sh -c', 'runs_as': service_user})
                handlers.append(handler)
            elif name in AUTH_DIRECTIVES:
                types, remainder = _next_word(rest)
                kinds = [t for t in types.split(',') if t]  # case-sensitive upstream
                arguments = remainder.rstrip(_BLANKS + '\r')
                # Observed on 5.9.4: a later authCommunity line for the same
                # community and source does not change the access the first set.
                shadowed = name == 'authcommunity' and any(
                    _lower(g['directive']) == name and g['arguments'] == arguments for g in grants)
                grants.append({'source': where, 'directive': directive, 'types': kinds,
                               'execute': 'execute' in kinds and not shadowed,
                               'shadowed': shadowed, 'arguments': arguments})
            elif name == 'disableauthorization':
                value, _ = _next_word(rest)
                low = _lower(value)
                if low in _TRUE or low in _FALSE:
                    disable = {'source': where, 'value': low in _TRUE}
                else:
                    _gap(gaps, 'unparsed_disable_authorization', where, value)
            elif name in INCLUDE_DIRECTIVES:
                _gap(gaps, 'include_not_resolved', where, line)
            elif name == 'perl':
                _gap(gaps, 'embedded_perl_handler', where, 'runs Perl inside the daemon')
    execute_grants = [g['source'] for g in grants if g['execute']]
    if disable and disable['value']:
        authorization = 'disabled'
    elif execute_grants:
        authorization = 'execute_granted'
    else:
        authorization = 'none'
    can_run = bool(handlers) and authorization != 'none'
    for handler in handlers:
        handler['code_runs'] = 'on_matching_trap' if can_run else 'not_authorized'
    if not any(r['state'] in ('read', 'not_checked', 'unreadable') for r in read) and not any(
            g['code'] == 'files_not_captured' for g in gaps):
        status = 'absent'
    elif can_run:
        status = 'runs'
    elif handlers:
        status = 'handlers_not_authorized'
    else:
        status = 'no_handlers'
    if any(g['blocking'] for g in gaps):
        status = 'unresolved' if status != 'runs' else status
    return {
        'contract_version': CONTRACT_VERSION,
        'origin': 'not_assessed',
        'status': status,
        'complete': not any(g['blocking'] for g in gaps),
        'files': read,
        'handlers': handlers,
        'authorization': {'state': authorization, 'execute_grants': execute_grants,
                          'disable_authorization': disable, 'grants': grants},
        'gaps': gaps,
        'not_observed': list(NOT_OBSERVED),
    }
