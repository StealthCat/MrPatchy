"""Pure D-Bus bus-activation contract (roadmap F slice, #1211).

A message bus starts the ``Exec`` of a ``[D-BUS Service]`` file in one of its
service directories the first time a client sends to, or asks to start, the
bus name that file provides. On the system bus the start runs through
``dbus-daemon-launch-helper`` as the file's ``User``, or through systemd when
the bus is configured for systemd activation and the file names a
``SystemdService``. This module turns a captured, ordered list of service
directories and the text of their ``*.service`` files into the names the bus
makes activatable and the file that wins each name. It performs no I/O, never
runs a bus, a helper or a command, and never authorizes a response action.

The rules were established by a differential against the real
``dbus-daemon`` 1.14.10 (Ubuntu ``1.14.10-4ubuntu4.1``): a private bus was
started with chosen ``<servicedir>`` lists and queried with
``ListActivatableNames`` and ``StartServiceByName``. They match on both
``<type>session</type>`` and ``<type>system</type>`` buses.

- Only directory entries whose name ends in the case-sensitive suffix
  ``.service`` are read; ``.service`` itself and hidden files are read too.
  Subdirectories, dangling links and other non-files are skipped. A symlink
  to a regular file is read.
- Text must be valid UTF-8 without NUL; otherwise the whole file is rejected.
  Lines end at ``\\n``, ``\\r\\n`` or ``\\r``. A blank line, or one of only
  spaces and tabs, is ignored. A line starting with ``#`` is a comment; a
  comment after leading whitespace rejects the file.
- A group line is exactly ``[`` name ``]`` with no ``[`` or ``]`` inside and
  nothing after it. A repeated group rejects the file.
- A key line needs a current group. The key is ``[A-Za-z0-9-]+``, optionally
  followed by a ``[locale]`` part, then spaces, ``=``, spaces and the value.
  Leading whitespace, a tab before ``=``, an empty key or another character
  rejects the file. Trailing spaces stay part of the value. ``\\s``, ``\\t``,
  ``\\n``, ``\\r`` and ``\\\\`` are unescaped; any other escape, or a trailing
  backslash, rejects the file. The first value of a repeated key wins.
- ``Name`` and ``Exec`` without a locale part are required in the
  ``[D-BUS Service]`` group (exact case); a file missing either is not
  loaded. ``SystemdService`` does not replace ``Exec``. Empty values and
  names that are not valid bus names still load.
- The first directory that provides a name wins. Within one directory a file
  named exactly ``<Name>.service`` wins; between other files of one
  directory the winner follows ``readdir`` order, which is unspecified, so the
  contract reports that name as ambiguous rather than guessing.

Not modeled: the launch-helper checks the system bus applies when it starts a
service (file name and ``User``), AppArmor/SELinux mediation and the bus
configuration that chooses the directories; the caller supplies them in bus
order.

Fail-closed rules: an unobserved directory or file text, and over-limit
input, make the result incomplete. A name whose winner could be displaced by
an unobserved directory or file at or before it is ``unresolved`` and never
reported as not activatable. ``origin`` is always ``not_assessed`` and no
result is a safety verdict.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('1.14.10',)
SERVICE_GROUP = 'D-BUS Service'
SUFFIX = '.service'
MAX_TEXT = 65536
MAX_DIRECTORIES = 32
MAX_ENTRIES = 2048

_KEY = re.compile(r'[A-Za-z0-9-]+')
_ESCAPES = {'s': ' ', 't': '\t', 'n': '\n', 'r': '\r', '\\': '\\'}
_RECORDED_KEYS = ('Name', 'Exec', 'User', 'SystemdService', 'AssumedAppArmorLabel')
FILE_STATUSES = ('wins', 'shadowed', 'ambiguous', 'not_service', 'skipped_non_file',
                 'skipped_incomplete', 'rejected', 'unresolved')
NAME_STATUSES = ('activatable', 'ambiguous', 'unresolved')


class ParseError(ValueError):
    pass


def _unescape(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch != '\\':
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(value) or value[i + 1] not in _ESCAPES:
            raise ParseError('invalid_escape')
        out.append(_ESCAPES[value[i + 1]])
        i += 2
    return ''.join(out)


def _lines(text: str) -> list[str]:
    return text.replace('\r\n', '\n').replace('\r', '\n').split('\n')


def parse_service_file(data: bytes | str) -> dict[str, dict[str, str]]:
    """Return ``{group: {key: value}}`` or raise :class:`ParseError`.

    Locale-qualified keys are kept with their ``[locale]`` suffix so they never
    satisfy the plain ``Name``/``Exec`` requirement.
    """
    if isinstance(data, str):
        data = data.encode('utf-8', 'surrogatepass')
    if b'\x00' in data:
        raise ParseError('nul_byte')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise ParseError('invalid_utf8') from None
    groups: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in _lines(text):
        if not line.strip(' \t'):
            continue
        if line.startswith('#'):
            continue
        if line.startswith('['):
            if not line.endswith(']') or len(line) < 3:
                raise ParseError('invalid_group')
            name = line[1:-1]
            if '[' in name or ']' in name:
                raise ParseError('invalid_group')
            if name in groups:
                raise ParseError('duplicate_group')
            current = groups[name] = {}
            continue
        if current is None:
            raise ParseError('key_outside_group')
        match = _KEY.match(line)
        if match is None:
            raise ParseError('invalid_key')
        pos = match.end()
        key = line[:pos]
        if pos < len(line) and line[pos] == '[':
            close = line.find(']', pos)
            stop = line.find('=', pos)
            if stop < 0:
                raise ParseError('invalid_key')
            # dbus accepts an unclosed locale part up to '=' (``Foo[en=1``).
            end = close + 1 if 0 <= close < stop else stop
            key = line[:end]
            pos = end
        while pos < len(line) and line[pos] == ' ':
            pos += 1
        if pos >= len(line) or line[pos] != '=':
            raise ParseError('invalid_key')
        pos += 1
        while pos < len(line) and line[pos] == ' ':
            pos += 1
        value = _unescape(line[pos:])
        current.setdefault(key, value)
    return groups


def _digest(data: bytes | str | None) -> str | None:
    if data is None:
        return None
    raw = data.encode('utf-8', 'surrogatepass') if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def resolve(directories: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Resolve activatable names from captured service directories in bus order.

    Each directory is ``{'path': str, 'observed': bool, 'entries': {filename:
    {'kind': 'file' | 'dir' | 'dangling' | 'other', 'text': bytes | str | None}}}``
    where ``kind`` already follows symlinks.
    """
    dirs = list(directories)
    gaps: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    if len(dirs) > MAX_DIRECTORIES:
        gaps.append({'reason': 'too_many_directories', 'limit': MAX_DIRECTORIES})
        dirs = dirs[:MAX_DIRECTORIES]
    # blocked_from: first directory index at which an unobserved input could
    # provide any name; winners at or after it are unresolved.
    blocked_from: int | None = None
    candidates: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, directory in enumerate(dirs):
        path = str(directory.get('path') or '')
        if not directory.get('observed'):
            gaps.append({'reason': 'directory_not_observed', 'directory': path})
            blocked_from = index if blocked_from is None else blocked_from
            continue
        entries = directory.get('entries') or {}
        if len(entries) > MAX_ENTRIES:
            gaps.append({'reason': 'too_many_entries', 'directory': path, 'limit': MAX_ENTRIES})
            blocked_from = index if blocked_from is None else blocked_from
            continue
        for filename in sorted(entries):
            entry = entries[filename] or {}
            record: dict[str, Any] = {'directory': path, 'file': filename, 'directory_index': index,
                                      'origin': 'not_assessed'}
            files.append(record)
            if '/' in filename or not filename.endswith(SUFFIX):
                record['status'] = 'not_service'
                continue
            kind = entry.get('kind')
            if kind in ('dir', 'dangling', 'other'):
                record['status'] = 'skipped_non_file'
                continue
            text = entry.get('text')
            if kind != 'file' or text is None:
                record.update(status='unresolved', reason='text_not_observed')
                gaps.append({'reason': 'file_not_observed', 'directory': path, 'file': filename})
                blocked_from = index if blocked_from is None else blocked_from
                continue
            raw = text.encode('utf-8', 'surrogatepass') if isinstance(text, str) else bytes(text)
            if len(raw) > MAX_TEXT:
                record.update(status='unresolved', reason='text_over_limit')
                gaps.append({'reason': 'file_over_limit', 'directory': path, 'file': filename, 'limit': MAX_TEXT})
                blocked_from = index if blocked_from is None else blocked_from
                continue
            record['sha256'] = _digest(raw)
            try:
                groups = parse_service_file(raw)
            except ParseError as exc:
                record.update(status='rejected', reason=str(exc))
                continue
            section = groups.get(SERVICE_GROUP, {})
            if 'Name' not in section or 'Exec' not in section:
                missing = [key for key in ('Name', 'Exec') if key not in section]
                record.update(status='skipped_incomplete', missing=missing)
                continue
            record['declared'] = {key: section[key] for key in _RECORDED_KEYS if key in section}
            candidates.setdefault(section['Name'], []).append((index, record))
    names: list[dict[str, Any]] = []
    for name in sorted(candidates):
        providers = candidates[name]
        first = min(index for index, _ in providers)
        in_first = [record for index, record in providers if index == first]
        exact = [record for record in in_first if record['file'] == name + SUFFIX]
        winner = exact[0] if exact else (in_first[0] if len(in_first) == 1 else None)
        unresolved = blocked_from is not None and blocked_from <= first
        for index, record in providers:
            if record is winner:
                record['status'] = 'unresolved' if unresolved else 'wins'
                if unresolved:
                    record['reason'] = 'earlier_input_not_observed'
            elif index == first and winner is None:
                record['status'] = 'ambiguous'
                record['reason'] = 'readdir_order_unspecified'
            else:
                record['status'] = 'shadowed'
                if winner is not None:
                    record['shadowed_by'] = {'directory': winner['directory'], 'file': winner['file']}
        if unresolved:
            status = 'unresolved'
        elif winner is None:
            status = 'ambiguous'
        else:
            status = 'activatable'
        entry: dict[str, Any] = {'name': name, 'status': status, 'origin': 'not_assessed'}
        if winner is not None and not unresolved:
            entry.update(directory=winner['directory'], file=winner['file'], declared=winner['declared'])
        else:
            entry['candidates'] = [{'directory': r['directory'], 'file': r['file']}
                                   for index, r in providers if index == first]
        names.append(entry)
    return {
        'contract': 'dbus_activation',
        'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS),
        'complete': not gaps,
        'gaps': gaps,
        'names': names,
        'files': files,
        'origin': 'not_assessed',
        'verdict': None,
    }
