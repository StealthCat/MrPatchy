"""Pure dynamic-loader configuration contract (roadmap F slice, #960).

Turns captured, read-only content of ``/etc/ld.so.preload`` and of
``/etc/ld.so.conf`` with its included files into typed, bounded records. It
performs no I/O, never runs ``ldconfig`` or loads a library, and never
authorizes a response action.

Behavior this module follows (glibc ``elf/rtld.c`` and ``elf/ldconfig.c``,
compared with glibc 2.39):

- ``ld.so.preload``: every entry is loaded into each dynamically linked
  process, including set-user-ID programs. Entries are separated by a space,
  tab, newline or colon and by nothing else, so a carriage return, comma or
  semicolon is part of an entry.
- ``ld.so.preload`` comments: glibc blanks a ``#`` comment up to the end of its
  line, but it searches for the next ``#`` from the start of the file inside a
  window that shrinks by the offset of each comment it finds. A ``#`` beyond
  that window is not treated as a comment, and the words after it are loaded as
  libraries. This contract repeats that search exactly and marks every entry
  that follows a ``#`` on its own line as ``after_comment_marker``.
- ``ld.so.conf``: ``#`` ends a line anywhere. ``include`` followed by a space
  or tab takes glob patterns, relative to the including file's directory, and
  reads the matches in sorted order. ``hwcap`` lines are ignored. Any other
  line names one directory: the whole line, with trailing whitespace removed
  and then trailing slashes removed, once each and in that order. ``/lib /``
  is therefore the directory ``/lib`` followed by a space, not ``/lib``.
  Spaces, colons and commas do not separate directories.
- An ``include`` wildcard pattern that ends in a slash selects directories
  only, so no file is read through it.
- ``include`` is lower-case only; ``INCLUDE /x`` is a directory named
  ``INCLUDE /x``. A missing file or a pattern with no match is skipped
  silently.

Fail-closed rules:

- Unreadable files, symlinks that were not followed, invalid UTF-8, NUL bytes
  and over-limit input become explicit gaps and mark the result incomplete.
- An ``include`` pattern this contract does not interpret (``[``, a backslash,
  ``.``/``..`` components, control characters or a wildcard before the last
  component), or one that points into a directory whose listing was not
  supplied, is a gap. It is never treated as "no match".
- A directory line holding ``=`` is version dependent: glibc releases that
  still knew library types cut the line at the ``=``. Both readings are
  reported and the result is incomplete.
- Nothing is labelled a package default or safe. ``origin`` is always
  ``not_assessed`` and every result says it is not a safety verdict.
- ``unobserved`` always names what this contract cannot see.
"""
from __future__ import annotations

import hashlib
import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
MAX_FILES = 512
MAX_TEXT = 262144
MAX_ENTRIES = 4096
MAX_FIELD = 4096
MAX_GAPS = 64
MAX_DEPTH = 16
MAX_PARSES = 1024

PRELOAD_PATH = '/etc/ld.so.preload'
CONF_PATH = '/etc/ld.so.conf'
DEFAULT_LISTED = ('/etc/ld.so.conf.d',)
DYNAMIC_TOKENS = ('ORIGIN', 'LIB', 'PLATFORM')
# Gaps that can hide an entry the real tools would read.
BLOCKING = frozenset({'input_malformed', 'too_many_files', 'too_many_entries', 'duplicate_path', 'file_unreadable',
                      'file_not_supplied', 'symlink_not_followed', 'invalid_utf8', 'nul_byte', 'text_over_limit',
                      'field_over_limit', 'include_pattern_not_interpreted', 'include_directory_not_listed',
                      'include_target_not_supplied', 'include_depth_exceeded', 'resolution_budget_exceeded',
                      'equals_sign_version_dependent'})
UNOBSERVED_PRELOAD = (
    {'code': 'environment_and_options', 'detail': 'LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH and the loader\'s --preload '
                                                  'and --audit options are not observed.'},
    {'code': 'library_files', 'detail': 'Whether each entry exists, what it resolves to and what it contains are not '
                                        'observed. The loader ignores an entry it cannot load.'},
    {'code': 'other_loaders', 'detail': 'Statically linked programs and C libraries other than glibc do not read '
                                        'this file.'},
    {'code': 'loader_version', 'detail': 'Tokenization was compared with glibc 2.39; the installed loader version is '
                                         'not observed.'},
)
UNOBSERVED_CONF = (
    {'code': 'built_cache', 'detail': '/etc/ld.so.cache is what the loader reads. It reflects this configuration only '
                                      'as of the last ldconfig run and is not observed.'},
    {'code': 'built_in_directories', 'detail': 'ldconfig also scans its built-in system directories (such as /lib, '
                                               '/usr/lib and the multiarch directories), which are not listed here.'},
    {'code': 'directory_state', 'detail': 'Whether each directory exists, is a symlink or is the same directory as '
                                          'another entry is not observed. ldconfig drops missing directories and '
                                          'entries with the same device and inode.'},
    {'code': 'match_order_locale', 'detail': 'Included files are ordered by byte value. ldconfig sorts matches with '
                                             'the collation of its locale, which is not observed.'},
    {'code': 'per_binary_and_environment_paths', 'detail': 'RPATH, RUNPATH, LD_LIBRARY_PATH, glibc-hwcaps '
                                                           'subdirectories and ldconfig command-line directories are '
                                                           'not observed.'},
)
NOT_A_VERDICT = 'Parsed configuration only. This is not a safety verdict and origin is not assessed.'

_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_PRELOAD_SEPARATORS = re.compile(rb'[^: \t\n]+')
_DST = re.compile(r'\$(?:\{(' + '|'.join(DYNAMIC_TOKENS) + r')\}|(' + '|'.join(DYNAMIC_TOKENS) + r')(?![A-Za-z0-9_]))')
_C_SPACE = ' \t\n\v\f\r'


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, line: int | None = None,
         detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code}
    if path is not None:
        gap['path'] = path
    if line is not None:
        gap['line'] = line
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def _complete(gaps: list[dict[str, Any]]) -> bool:
    # A truncated gap list may have dropped a blocking gap.
    return not any(g['code'] in BLOCKING or g['code'] == 'gaps_truncated' for g in gaps)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _raw(path: str, item: Any, gaps: list[dict[str, Any]]) -> tuple[bytes | None, str]:
    """Return ``(content, status)`` for one supplied file mapping; content is ``None`` unless it is readable."""
    kind = item.get('type', 'file')
    text = item.get('text')
    if kind == 'absent':
        return None, 'absent'
    if kind == 'directory':
        return None, 'directory'
    if kind not in ('file', 'symlink'):
        _gap(gaps, 'file_unreadable', path, detail='Not a regular file; its content was not captured.')
        return None, 'unreadable'
    if text is None and kind == 'symlink':
        _gap(gaps, 'symlink_not_followed', path, detail='The tools follow this link; its target was not read.')
        return None, 'unreadable'
    if isinstance(text, str):
        try:
            text = text.encode('utf-8')
        except UnicodeEncodeError:
            _gap(gaps, 'invalid_utf8', path)
            return None, 'unreadable'
    if not isinstance(text, bytes):
        _gap(gaps, 'file_unreadable', path)
        return None, 'unreadable'
    if len(text) > MAX_TEXT:
        _gap(gaps, 'text_over_limit', path)
        return None, 'unreadable'
    if b'\x00' in text:
        _gap(gaps, 'nul_byte', path)
        return None, 'unreadable'
    try:
        text.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', path)
        return None, 'unreadable'
    return text, 'parsed'


def _result(kind: str, gaps: list[dict[str, Any]], unobserved: tuple[dict[str, str], ...],
            **fields: Any) -> dict[str, Any]:
    return {'contract_version': CONTRACT_VERSION, 'kind': kind, **fields, 'gaps': gaps,
            'complete': _complete(gaps), 'unobserved': [dict(item) for item in unobserved],
            'origin': 'not_assessed', 'note': NOT_A_VERDICT}


def _blank_preload_comments(data: bytes) -> bytearray:
    """Repeat glibc's comment removal, including its shrinking search window."""
    buf = bytearray(data)
    rest = len(buf)
    while rest > 0:
        index = buf.find(b'#', 0, rest)  # glibc never advances the search start
        if index < 0:
            break
        rest -= index
        while True:
            buf[index] = 0x20
            rest -= 1
            if rest <= 0:
                break
            index += 1
            if buf[index] == 0x0a:
                break
    return buf


def resolve_preload(file: Any) -> dict[str, Any]:
    """Resolve the libraries ``/etc/ld.so.preload`` makes the loader preload.

    ``file`` is a mapping with ``type`` (``file``, ``symlink`` or ``absent``) and ``text`` (``str`` or ``bytes``).
    """
    gaps: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    record: dict[str, Any] = {'path': PRELOAD_PATH}
    if not isinstance(file, dict) or file.get('path', PRELOAD_PATH) != PRELOAD_PATH:
        _gap(gaps, 'file_not_supplied', PRELOAD_PATH, detail='Supply the file, or type "absent" when it does not exist.')
        record['status'] = 'not_supplied'
        return _result('ld_so_preload', gaps, UNOBSERVED_PRELOAD, file=record, entries=entries)
    data, status = _raw(PRELOAD_PATH, file, gaps)
    if status == 'directory':
        _gap(gaps, 'file_unreadable', PRELOAD_PATH, detail='A directory is at this path.')
        status = 'unreadable'
    record['status'] = status
    if data is None:
        if status == 'unreadable':
            record['reason'] = gaps[-1]['code']
        return _result('ld_so_preload', gaps, UNOBSERVED_PRELOAD, file=record, entries=entries)
    record['sha256'] = _sha(data)
    blanked = _blank_preload_comments(data)
    first: dict[str, int] = {}
    for match in _PRELOAD_SEPARATORS.finditer(blanked):
        if len(entries) >= MAX_ENTRIES:
            _gap(gaps, 'too_many_entries', PRELOAD_PATH, detail=f'Only the first {MAX_ENTRIES} entries are listed.')
            break
        raw = bytes(match.group())
        start = match.start()
        line_start = data.rfind(b'\n', 0, start) + 1
        name = raw.decode('utf-8', 'replace')
        order = len(entries)
        entry: dict[str, Any] = {
            'entry': name[:MAX_FIELD], 'entry_truncated': len(name) > MAX_FIELD, 'entry_sha256': _sha(raw),
            'line': data.count(b'\n', 0, start) + 1, 'order': order,
            'kind': 'path' if '/' in name else 'library_name', 'absolute': name.startswith('/'),
            'dynamic_tokens': sorted({a or b for a, b in _DST.findall(name)}),
            # The words a reader would take for a comment, but which the loader loads.
            'after_comment_marker': b'#' in data[line_start:match.end()],
            'control_characters': bool(_CONTROL.search(name)),
            'duplicate_of': first.get(name)}
        first.setdefault(name, order)
        entries.append(entry)
    return _result('ld_so_preload', gaps, UNOBSERVED_PRELOAD, file=record, entries=entries)


def _component_regex(component: str) -> re.Pattern[str]:
    parts = ['[^/]*' if char == '*' else '[^/]' if char == '?' else re.escape(char) for char in component]
    return re.compile(''.join(parts), re.S)


def resolve_search_paths(files: Any, listed_directories: Any = DEFAULT_LISTED) -> dict[str, Any]:
    """Resolve the directories ``/etc/ld.so.conf`` and its includes hand to ``ldconfig``.

    ``files`` is an iterable of mappings with ``path``, ``type`` (``file``, ``symlink``, ``directory`` or ``absent``)
    and ``text``. ``listed_directories`` names the directories whose complete listing is among ``files``; an
    ``include`` pattern is only matched inside those.
    """
    gaps: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    includes: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []

    def done() -> dict[str, Any]:
        for record in records:
            record.setdefault('status', 'not_included')
        return _result('ld_so_conf', gaps, UNOBSERVED_CONF, files=records, directories=directories,
                       includes=includes, ignored_lines=ignored)

    try:
        supplied = list(files)
        listed = {posixpath.normpath(d) for d in listed_directories if isinstance(d, str) and d.startswith('/')}
    except TypeError:
        _gap(gaps, 'input_malformed', detail='files must be an iterable of mappings.')
        return done()
    if len(supplied) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'More than {MAX_FILES} files were supplied; none were parsed.')
        return done()
    by_path: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for item in supplied:
        path = item.get('path') if isinstance(item, dict) else None
        if (not isinstance(path, str) or not path.startswith('/') or len(path) > MAX_FIELD or _CONTROL.search(path)
                or posixpath.normpath(path) != path or path.startswith('//')):
            _gap(gaps, 'input_malformed', detail='A file entry has no normalized absolute path.')
            continue
        if path in by_path:
            _gap(gaps, 'duplicate_path', path)
            continue
        record: dict[str, Any] = {'path': path}
        records.append(record)
        by_path[path] = (record, item)
    budget = {'parses': 0}
    first: dict[str, int] = {}

    def matches(pattern: str, path: str, line: int) -> list[str] | None:
        """Return the supplied paths a glob pattern selects, or ``None`` when it is a gap."""
        if not pattern.startswith('/'):
            pattern = posixpath.dirname(path) + '/' + pattern
        parts = [part for part in pattern.split('/') if part]
        if (_CONTROL.search(pattern) or '[' in pattern or '\\' in pattern or '.' in parts or '..' in parts
                or any('*' in part or '?' in part for part in parts[:-1])):
            _gap(gaps, 'include_pattern_not_interpreted', path, line,
                 'This include pattern is not interpreted; the files it selects are unknown.')
            return None
        target = '/' + '/'.join(parts)
        parent = posixpath.dirname(target)
        if not parts or not ('*' in parts[-1] or '?' in parts[-1]):
            if target in by_path:
                return [target]
            if parent in listed or target in listed:
                return []  # absent, or a directory: ldconfig reads nothing from it
            _gap(gaps, 'include_target_not_supplied', path, line, f'{target[:256]} was not supplied.')
            return None
        if parent not in listed:
            _gap(gaps, 'include_directory_not_listed', path, line, f'The listing of {parent[:256]} was not supplied.')
            return None
        only_directories = pattern.endswith('/')  # glob: a wildcard pattern ending in "/" selects directories only
        regex = _component_regex(parts[-1])
        hidden_ok = parts[-1].startswith('.')
        found = []
        for candidate, (_, item) in by_path.items():
            name = posixpath.basename(candidate)
            if (posixpath.dirname(candidate) != parent or item.get('type', 'file') == 'absent'
                    or (name.startswith('.') and not hidden_ok)
                    or (only_directories and item.get('type', 'file') != 'directory')):
                continue
            by_character = bool(regex.fullmatch(name))
            by_byte = bool(regex.fullmatch(name.encode('utf-8', 'surrogatepass').decode('latin-1')))
            if by_character != by_byte:
                # "?" matches one character or one byte depending on ldconfig's locale.
                _gap(gaps, 'include_pattern_not_interpreted', path, line,
                     'Whether this pattern selects a non-ASCII file name depends on the locale of ldconfig.')
                return None
            if by_character:
                found.append(candidate)
        return sorted(found, key=lambda candidate: candidate.encode('utf-8', 'surrogatepass'))

    def parse(path: str, depth: int, parent: str | None) -> None:
        record, item = by_path[path]
        if parent is not None and parent not in record.setdefault('included_from', []):
            record['included_from'].append(parent)
        if depth > MAX_DEPTH:
            _gap(gaps, 'include_depth_exceeded', path, detail=f'Includes nest deeper than {MAX_DEPTH} files.')
            return
        budget['parses'] += 1
        if budget['parses'] > MAX_PARSES:
            if budget['parses'] == MAX_PARSES + 1:
                _gap(gaps, 'resolution_budget_exceeded', path, detail=f'More than {MAX_PARSES} files were read.')
            return
        if record.get('status') == 'parsed':
            data: bytes | None = record['_data']
        elif 'status' in record:
            return  # absent, a directory, or already reported unreadable
        else:
            data, status = _raw(path, item, gaps)
            record['status'] = status
            if data is None:
                if status == 'unreadable':
                    record['reason'] = gaps[-1]['code']
                return
            record.update(sha256=_sha(data), _data=data)
        lines = data.decode('utf-8').split('\n')
        if lines and lines[-1] == '':
            lines.pop()
        for number, line in enumerate(lines, 1):
            line = line.split('#', 1)[0].lstrip(_C_SPACE)
            if not line:
                continue
            if line.startswith('include') and line[7:8] in (' ', '\t'):
                for pattern in re.split(r'[ \t]', line[8:]):
                    if not pattern:
                        continue
                    include: dict[str, Any] = {'pattern': pattern[:MAX_FIELD], 'file': path, 'line': number,
                                               'matches': []}
                    includes.append(include)
                    if len(pattern) > MAX_FIELD:
                        _gap(gaps, 'field_over_limit', path, number, 'An include pattern is too long.')
                        continue
                    found = matches(pattern, path, number)
                    if found is None:
                        include['status'] = 'not_resolved'
                        continue
                    include.update(status='resolved', matches=found)
                    for target in found:
                        parse(target, depth + 1, path)
                continue
            if line[:5].lower() == 'hwcap' and line[5:6] in (' ', '\t'):
                ignored.append({'file': path, 'line': number, 'reason': 'hwcap_directive'})
                continue
            # ldconfig removes trailing whitespace and then trailing slashes, once each: "/lib /" stays "/lib ".
            directory = line.rstrip(_C_SPACE).rstrip('/')
            if not directory:
                ignored.append({'file': path, 'line': number, 'reason': 'empty_after_trimming'})
                continue
            if len(directory) > MAX_FIELD:
                _gap(gaps, 'field_over_limit', path, number, 'A directory line is too long.')
                continue
            if len(directories) >= MAX_ENTRIES:
                if not any(g['code'] == 'too_many_entries' for g in gaps):
                    _gap(gaps, 'too_many_entries', path, number, f'Only the first {MAX_ENTRIES} directories are listed.')
                return
            order = len(directories)
            entry: dict[str, Any] = {'path': directory, 'absolute': directory.startswith('/'), 'file': path,
                                     'line': number, 'order': order,
                                     'control_characters': bool(_CONTROL.search(directory)),
                                     'duplicate_of': first.get(directory), 'legacy_path': None}
            if '=' in directory:
                # Older glibc cut the line at "=" and read the rest as a library type.
                entry['legacy_path'] = directory.split('=', 1)[0].rstrip(_C_SPACE).rstrip('/')
                _gap(gaps, 'equals_sign_version_dependent', path, number,
                     'Older glibc releases read the text before "=" as the directory.')
            first.setdefault(directory, order)
            directories.append(entry)

    if CONF_PATH not in by_path:
        _gap(gaps, 'file_not_supplied', CONF_PATH, detail='Supply the file, or type "absent" when it does not exist.')
    else:
        parse(CONF_PATH, 0, None)
    for record in records:
        record.pop('_data', None)
    return done()
