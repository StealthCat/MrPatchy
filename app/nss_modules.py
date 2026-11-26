"""Pure nsswitch.conf module-load contract (roadmap F slice, #1399).

Turns the captured, read-only content of ``/etc/nsswitch.conf`` into the NSS
service modules glibc loads into a process when it looks up a database. An NSS
module is a shared object (``libnss_<service>.so.2``) that runs inside every
process doing a user, group, host or similar lookup, including root daemons
such as sshd, cron and login. A new name in this file therefore makes those
processes run new code, without any change to the program or its unit.

This module performs no I/O, never loads a library or runs a lookup, and never
authorizes a response action.

Behavior this module follows (glibc 2.39 ``nss/nss_database.c``,
``nss/nss_action_parse.c``, ``nss/nss_module.c`` and ``nss/databases.def``,
checked against the real glibc 2.39 loader):

- The file is read line by line with ``getline``. A final line that does not
  end in a newline is never processed, because ``getline`` reports end of file
  for it.
- There are no comments. A line whose first word is not a database name
  (including ``#passwd:``) is ignored, but a ``#`` after the colon is just
  another service: ``passwd: files # note`` loads ``libnss_#.so.2`` and
  ``libnss_note.so.2``.
- Database names are matched exactly and case-sensitively against the 17
  glibc databases. Any other name (``sudoers``, ``automount``, ``PASSWD``) is
  ignored. A line with no space or colon after the name is ignored. The last
  line for a database replaces earlier ones.
- After the name, any run of spaces and colons is skipped. Each service is a
  run of characters up to white space or ``[``. A ``[`` with no service before
  it ends the list, and the rest of the line is ignored.
- ``[STATUS=ACTION ...]`` criteria take ``SUCCESS``, ``NOTFOUND``, ``UNAVAIL``
  or ``TRYAGAIN`` and ``RETURN``, ``CONTINUE`` or ``MERGE``, matched ignoring
  case, with ``!`` meaning every other status. Anything else is a syntax
  error, and one syntax error makes glibc reject the whole file: lookups fail
  and no module is loaded.
- Defaults: ``shadow`` takes the ``passwd`` line, ``gshadow`` takes the
  ``group`` line and ``shadow_compat`` takes the ``passwd_compat`` line when
  only the latter is given. Otherwise ``hosts`` and ``networks`` default to
  ``files dns``, ``publickey`` to ``nis nisplus``, the ``*_compat`` databases to
  ``nis``, ``initgroups`` to no list (lookups then use ``group``) and every
  other database to ``files``. A missing file, or one glibc cannot open because
  of permissions, a directory or a symlink loop, gives every database its
  default.
- ``files`` and ``dns`` are built into glibc 2.39 and load no shared object.
  Every other service, including ``compat``, makes glibc ``dlopen``
  ``libnss_<service>.so.2``. A service name holding ``/`` makes that a path,
  relative to the process's working directory.

Fail-closed rules:

- An unsupplied or unreadable file, invalid UTF-8, NUL bytes and over-limit
  input become explicit gaps and mark the result incomplete.
- Nothing is labelled a package default or safe. ``origin`` is always
  ``not_assessed`` and every result says it is not a safety verdict.
- ``unobserved`` always names what this contract cannot see.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

CONTRACT_VERSION = 1
MAX_TEXT = 262144
MAX_SERVICES = 4096
MAX_FIELD = 1024
MAX_GAPS = 64

PATH = '/etc/nsswitch.conf'
# nss/databases.def, glibc 2.39, in its sorted order.
DATABASES = ('aliases', 'ethers', 'group', 'group_compat', 'gshadow', 'hosts', 'initgroups', 'netgroup', 'networks',
             'passwd', 'passwd_compat', 'protocols', 'publickey', 'rpc', 'services', 'shadow', 'shadow_compat')
BUILTIN = frozenset({'files', 'dns'})
STATUSES = ('SUCCESS', 'NOTFOUND', 'UNAVAIL', 'TRYAGAIN')
ACTIONS = ('RETURN', 'CONTINUE', 'MERGE')
# nss_database.c per_database_defaults without LINK_OBSOLETE_NSL.
DEFAULTS = {'hosts': 'files dns', 'networks': 'files dns', 'publickey': 'nis nisplus', 'group_compat': 'nis',
            'passwd_compat': 'nis', 'shadow_compat': 'nis', 'initgroups': None}
# Databases that take another database's line when only that one is given.
INHERITS = (('shadow_compat', 'passwd_compat'), ('shadow', 'passwd'), ('gshadow', 'group'))
BLOCKING = frozenset({'file_not_supplied', 'file_unreadable', 'symlink_not_followed', 'invalid_utf8', 'nul_byte',
                      'text_over_limit', 'too_many_services'})
UNOBSERVED = (
    {'code': 'library_resolution', 'detail': 'Where each libnss library is found (ld.so.cache, the library search '
                                             'path, LD_LIBRARY_PATH), whether it exists and what it contains are not '
                                             'observed. A module that cannot be loaded is treated as unavailable.'},
    {'code': 'lookups_performed', 'detail': 'Which processes look up which database, and how far each lookup walks '
                                            'the list before a service answers, are not observed. A listed module is '
                                            'loaded only when a lookup reaches it.'},
    {'code': 'compat_and_caches', 'detail': 'Modules the compat module loads through the *_compat databases, '
                                            'nscd, sssd and systemd-userdbd caches, and per-program '
                                            '__nss_configure_lookup overrides are not observed.'},
    {'code': 'other_c_libraries', 'detail': 'Statically linked programs, containers with their own root, glibc '
                                            'builds with obsolete NSL defaults and C libraries other than glibc '
                                            'are not modelled.'},
)
NOT_A_VERDICT = 'Parsed configuration only. This is not a safety verdict and origin is not assessed.'

_C_SPACE = b' \t\n\v\f\r'
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


def _gap(gaps: list[dict[str, Any]], code: str, line: int | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code, 'path': PATH}
    if line is not None:
        gap['line'] = line
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _SyntaxError(Exception):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _default_actions() -> dict[str, str]:
    actions = dict.fromkeys(STATUSES, 'CONTINUE')
    actions['SUCCESS'] = 'RETURN'
    return actions


def _word(line: bytes, pos: int, stops: bytes) -> int:
    while pos < len(line) and line[pos] not in _C_SPACE and line[pos] not in stops:
        pos += 1
    return pos


def _skip_ws(line: bytes, pos: int) -> int:
    while pos < len(line) and line[pos] in _C_SPACE:
        pos += 1
    return pos


def _parse_actions(line: bytes) -> list[tuple[bytes, dict[str, str]]]:
    """Repeat ``nss_action_parse``; raise ``_SyntaxError`` where glibc returns an error."""
    services: list[tuple[bytes, dict[str, str]]] = []
    pos = 0
    while True:
        pos = _skip_ws(line, pos)
        if pos >= len(line):
            return services
        start = pos
        pos = _word(line, pos, b'[')
        if pos == start:
            return services  # a '[' with no service ends the list
        name = line[start:pos]
        actions = _default_actions()
        pos = _skip_ws(line, pos)
        if pos < len(line) and line[pos] == ord('['):
            pos = _skip_ws(line, pos + 1)
            while True:
                negate = pos < len(line) and line[pos] == ord('!')
                if negate:
                    pos += 1
                start = pos
                pos = _word(line, pos, b'=]')
                status = line[start:pos].upper().decode('utf-8', 'replace')  # ASCII-only, like strncasecmp
                if status not in STATUSES:
                    raise _SyntaxError(f'Unknown status {line[start:pos]!r} in criteria.')
                pos = _skip_ws(line, pos)
                if pos >= len(line) or line[pos] != ord('='):
                    raise _SyntaxError('Criteria status is not followed by "=".')
                pos = _skip_ws(line, pos + 1)
                start = pos
                pos = _word(line, pos, b'=]')
                action = line[start:pos].upper().decode('utf-8', 'replace')
                if action not in ACTIONS:
                    raise _SyntaxError(f'Unknown action {line[start:pos]!r} in criteria.')
                if negate:
                    saved = actions[status]
                    actions = dict.fromkeys(STATUSES, action)
                    actions[status] = saved
                else:
                    actions[status] = action
                pos = _skip_ws(line, pos)
                if pos < len(line) and line[pos] == ord(']'):
                    pos += 1
                    break
        services.append((name, actions))


def _service_record(name: bytes, actions: dict[str, str], order: int) -> dict[str, Any]:
    text = name.decode('utf-8', 'replace')
    builtin = text in BUILTIN
    library = None if builtin else f'libnss_{text}.so.2'
    return {'service': text[:MAX_FIELD], 'service_truncated': len(text) > MAX_FIELD, 'service_sha256': _sha(name),
            'order': order, 'builtin': builtin, 'loads_shared_object': not builtin,
            'library': library[:MAX_FIELD] if library else None,
            'library_is_path': bool(library and '/' in library),
            'control_characters': bool(_CONTROL.search(text)),
            'actions': dict(actions),
            'default_actions': actions == _default_actions()}


def _result(gaps: list[dict[str, Any]], **fields: Any) -> dict[str, Any]:
    complete = not any(g['code'] in BLOCKING or g['code'] == 'gaps_truncated' for g in gaps)
    return {'contract_version': CONTRACT_VERSION, 'kind': 'nsswitch_modules', **fields, 'gaps': gaps,
            'complete': complete, 'unobserved': [dict(item) for item in UNOBSERVED], 'origin': 'not_assessed',
            'note': NOT_A_VERDICT}


def _read(file: Any, gaps: list[dict[str, Any]]) -> tuple[bytes | None, str]:
    if not isinstance(file, dict) or file.get('path', PATH) != PATH:
        _gap(gaps, 'file_not_supplied', detail='Supply the file, or type "absent" when it does not exist.')
        return None, 'not_supplied'
    kind = file.get('type', 'file')
    text = file.get('text')
    if kind == 'absent':
        return None, 'absent'
    if kind in ('directory', 'unopenable'):
        # glibc ignores EACCES, EISDIR, ELOOP, ENOTDIR and EPERM and uses the defaults.
        return None, kind
    if kind not in ('file', 'symlink'):
        _gap(gaps, 'file_unreadable', detail='Not a regular file; its content was not captured.')
        return None, 'unreadable'
    if text is None and kind == 'symlink':
        _gap(gaps, 'symlink_not_followed', detail='glibc follows this link; its target was not read.')
        return None, 'unreadable'
    if isinstance(text, str):
        try:
            text = text.encode('utf-8')
        except UnicodeEncodeError:
            _gap(gaps, 'invalid_utf8')
            return None, 'unreadable'
    if not isinstance(text, bytes):
        _gap(gaps, 'file_unreadable')
        return None, 'unreadable'
    if len(text) > MAX_TEXT:
        _gap(gaps, 'text_over_limit')
        return None, 'unreadable'
    if b'\x00' in text:
        _gap(gaps, 'nul_byte')
        return None, 'unreadable'
    try:
        text.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8')
        return None, 'unreadable'
    return text, 'parsed'


def resolve_nss_modules(file: Any) -> dict[str, Any]:
    """Resolve which NSS modules glibc loads, for which database, in which order.

    ``file`` is a mapping with ``type`` (``file``, ``symlink``, ``absent``, ``directory`` or ``unopenable`` for a
    path glibc cannot open because of permissions or a symlink loop) and ``text`` (``str`` or ``bytes``).
    """
    gaps: list[dict[str, Any]] = []
    data, status = _read(file, gaps)
    record: dict[str, Any] = {'path': PATH, 'status': status}
    if status in ('not_supplied', 'unreadable'):
        record['reason'] = gaps[-1]['code']
        return _result(gaps, file=record, databases=[], modules=[])
    explicit: dict[str, tuple[int, list[tuple[bytes, dict[str, str]]]]] = {}
    ignored: list[dict[str, Any]] = []
    if data is not None:
        record['sha256'] = _sha(data)
        lines = data.split(b'\n')
        unterminated = lines.pop()  # empty when the file ends in a newline
        if unterminated.strip(_C_SPACE):
            ignored.append({'line': len(lines) + 1, 'reason': 'no_final_newline'})
        for number, raw in enumerate(lines, 1):
            line = raw + b'\n'
            pos = _skip_ws(line, 0)
            start = pos
            pos = _word(line, pos, b':')
            if pos >= len(line) or pos == start:
                continue
            name = line[start:pos]
            while pos < len(line) and (line[pos] in _C_SPACE or line[pos] == ord(':')):
                pos += 1
            database = name.decode('utf-8', 'replace')
            if database not in DATABASES:
                if not name.startswith(b'#'):
                    ignored.append({'line': number, 'reason': 'not_a_database', 'name': database[:MAX_FIELD]})
                continue
            try:
                explicit[database] = (number, _parse_actions(line[pos:]))
            except _SyntaxError as exc:
                # nss_database_reload fails: every lookup fails and no module is loaded.
                record['status'] = 'rejected'
                record['rejected_line'] = number
                record['reason'] = exc.detail
                return _result(gaps, file=record, databases=[], modules=[], ignored_lines=ignored)
    databases: list[dict[str, Any]] = []
    sources: dict[str, dict[str, Any]] = {}
    count = 0
    for database in DATABASES:
        source: dict[str, Any]
        if database in explicit:
            number, services = explicit[database]
            source = {'source': 'file', 'line': number}
        else:
            parent = dict(INHERITS).get(database)
            if parent in explicit:
                number, services = explicit[parent]
                source = {'source': 'inherited', 'inherited_from': parent, 'line': number}
            elif database == 'initgroups':
                group = sources['group']
                services = [(s['service'].encode(), s['actions']) for s in group['services']]
                source = {'source': 'uses_group', 'line': group.get('line')}
            else:
                services = _parse_actions(DEFAULTS.get(database, 'files').encode())
                source = {'source': 'default'}
        rows = []
        for order, (name, actions) in enumerate(services):
            if count >= MAX_SERVICES:
                if not any(g['code'] == 'too_many_services' for g in gaps):
                    _gap(gaps, 'too_many_services', detail=f'Only the first {MAX_SERVICES} services are listed.')
                break
            count += 1
            rows.append(_service_record(name, actions, order))
        entry = {'database': database, **source, 'services': rows, 'empty': not services}
        sources[database] = entry
        databases.append(entry)
    modules: dict[str, dict[str, Any]] = {}
    for entry in databases:
        for row in entry['services']:
            if row['loads_shared_object']:
                module = modules.setdefault(row['library'], {'library': row['library'], 'service': row['service'],
                                                             'library_is_path': row['library_is_path'],
                                                             'databases': []})
                module['databases'].append(entry['database'])
    return _result(gaps, file=record, databases=databases, modules=list(modules.values()), ignored_lines=ignored)
