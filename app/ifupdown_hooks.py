"""Pure ifupdown hook contract (roadmap F slice, #1052).

Takes captured, read-only text of ``/etc/network/interfaces`` and the files it
includes, directory listings needed to expand ``source``/``source-directory``,
and entry metadata for the ``/etc/network/if-*.d`` directories. It says which
hook commands each ``iface`` stanza runs through ``/bin/sh -c`` as root, in
which phase and order, which ``run-parts`` scripts run for every stanza, which
``mapping`` scripts run, and where coverage is missing. It never runs anything
and never reads a hook script's contents.

Semantics come from the ifupdown 0.8.35 (``config.c``, ``execute.c``,
``main.c``) and debianutils 5.24 (``run-parts.c``) sources downloaded from
archive.ubuntu.com, not from recollection:

* Lines: leading whitespace is stripped; a line whose first character is then
  ``#`` is a comment. A logical line ending in ``\\`` (before trailing
  whitespace is removed) continues with the next physical line appended
  verbatim, even if that line starts with ``#``. Trailing whitespace is
  removed. Words split on whitespace and are truncated to 79 bytes.
* ``post-up`` is an alias for ``up`` and ``pre-down`` for ``down``. Each hook
  line is kept separately in file order. A hook with an empty value, an option
  outside an ``iface`` stanza, or a bad ``iface`` line aborts parsing of that
  file. In the top-level file this makes ifup refuse to run at all; in an
  included file the definitions read so far are kept and the parent continues.
* ``auto``, ``allow-*``, ``no-auto-down`` and ``no-scripts`` with arguments,
  ``rename``, ``source`` and ``source-dir*`` end the current stanza, so later
  options are misplaced. Without arguments inside a stanza, they apply to it.
* ``source`` expands ``<dir of current file>/<rest>`` (or an absolute
  ``rest``) with ``wordexp(WRDE_NOCMD)``; missing results are skipped.
  ``source-dir`` (any word starting with it, e.g. ``source-directory``) reads
  names made only of ASCII letters, digits, ``_`` and ``-``, in byte order.
  A file already parsed (same path string) is skipped.
* ``iface NAME FAMILY METHOD [inherits OTHER]``: the Linux families and
  methods are fixed tables below. ``inherits`` copies the options and hooks of
  the first earlier stanza with that name (and family, when given) before the
  stanza's own lines.
* Unless ``ifup --no-loopback`` is used, ifupdown puts ``lo`` first in the
  ``auto`` class before reading any file, whether or not ``lo`` has a stanza.
  If no stanza uses the ``loopback`` method, it also adds an ``lo inet
  loopback`` stanza with no hooks.
* ``ifup`` runs, per stanza: ``pre-up`` hooks, ``run-parts
  /etc/network/if-pre-up.d``, the method, ``up`` hooks, ``run-parts
  /etc/network/if-up.d``. ``ifdown`` runs ``if-down.d``, ``down`` hooks, the
  method, ``if-post-down.d``, ``post-down`` hooks. ``no-scripts`` patterns
  (``fnmatch`` on the logical name) suppress only the run-parts directories,
  not the hooks. A hook starting with ``-`` has its exit status ignored.
* ``run-parts --exit-on-error`` (no ``--lsbsysinit``) considers names matching
  ``^[a-zA-Z0-9_-]+$`` in byte order (no ``setlocale``), follows symlinks, and
  runs regular files root may execute. Directories are skipped; a dangling
  symlink is skipped; any other type is skipped with an error status.

It performs no I/O and never authorizes a response action. Unobserved files,
directories, implementation or family, unmodeled shell expansion in include
patterns, include depth and over-limit input are blocking gaps.
"""
from __future__ import annotations

import fnmatch
import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'ifupdown': 'ifupdown 0.8.35 (Ubuntu source)', 'run_parts': 'debianutils 5.24'}
INTERFACES = '/etc/network/interfaces'
SHELL = ('/bin/sh', '-c')
RUNS_AS = 'root'
PHASES = ('pre-up', 'up', 'down', 'post-down')
PHASE_ALIASES = {'post-up': 'up', 'pre-down': 'down'}
HOOK_DIRS = {phase: f'/etc/network/if-{phase}.d' for phase in PHASES}
UP_SEQUENCE = ('hooks:pre-up', 'run-parts:pre-up', 'method:up', 'hooks:up', 'run-parts:up')
DOWN_SEQUENCE = ('run-parts:down', 'hooks:down', 'method:down', 'run-parts:post-down', 'hooks:post-down')
FAMILY_METHODS = {
    'inet': frozenset({'loopback', 'static', 'manual', 'dhcp', 'bootp', 'tunnel', 'ppp', 'wvdial', 'ipv4ll'}),
    'inet6': frozenset({'auto', 'loopback', 'static', 'manual', 'dhcp', 'v4tunnel', '6to4'}),
    'ipx': frozenset({'static', 'dynamic'}),
    'can': frozenset({'static'}),
    'meta': frozenset({'none'}),
}
APPLICABLE_FAMILIES = frozenset({'debian'})
KNOWN_FAMILIES = frozenset({'debian', 'rpm'})
MAX_FILES = 256
MAX_FILE_BYTES = 1 << 20
MAX_DEPTH = 32
MAX_HOOKS = 2048
MAX_ENTRIES = 1024
MAX_GAPS = 64
WORD_MAX = 79
FILE_STATES = ('read', 'absent', 'unreadable', 'directory')
DIRECTORY_STATES = ('listed', 'absent', 'unreadable', 'not_directory')
BLOCKING = frozenset({
    'input_malformed', 'family_not_observed', 'family_unsupported', 'implementation_not_observed',
    'file_not_observed', 'file_unreadable', 'file_truncated', 'directory_not_observed', 'directory_unreadable',
    'listing_incomplete', 'include_pattern_unmodeled', 'include_depth_exceeded', 'too_many_files',
    'too_many_hooks', 'too_many_entries', 'metadata_missing', 'symlink_target_unobserved', 'gaps_truncated',
})
UNOBSERVED = (
    'Hook command text is reported as written; what the shell, scripts or programs then do is not read.',
    'Whether a stanza is actually brought up (auto/allow classes, hotplug, mapping results, ifup arguments '
    'such as --no-scripts, --force or --allow) is not resolved; activation lists only literal class lines.',
    'Method-specific required options and runtime failures that stop later steps are not evaluated.',
    'ifupdown2, ifupdown-ng, netplan and NetworkManager use other configuration and are not modeled.',
    'A locally rebuilt ifupdown or run-parts with different behavior is not detected.',
)
NOT_A_VERDICT = 'Configuration and file metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'runs': 'run-parts runs this script as root for every interface stanza in this phase.',
    'name_rejected': 'run-parts only considers names made of ASCII letters, digits, "_" and "-".',
    'directory': 'Directories are skipped.',
    'not_executable': 'The file has no execute bit, so run-parts skips it.',
    'noexec_mount': 'The file is on a noexec mount, so root cannot execute it and run-parts skips it.',
    'stat_failed': 'The entry cannot be followed (for example a dangling symlink), so run-parts skips it.',
    'not_plain_file': 'Not a regular file or directory; run-parts skips it and exits with an error status.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_RUN_PARTS_NAME = re.compile(r'[A-Za-z0-9_-]+')
_SOURCE_DIR_NAME = re.compile(r'[A-Za-z0-9_-]+')
_C_SPACE = ' \t\n\v\f\r'
_WORDEXP_BADCHARS = frozenset('|&;<>(){}\n')
_UNMODELED_CHARS = frozenset('$`\'"\\')
_GLOB_CHARS = frozenset('*?[')


class _Rejected(Exception):
    """A parse error that makes ifupdown stop reading the current file."""

    def __init__(self, line: int, message: str):
        super().__init__(message)
        self.line = line
        self.message = message


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code}
    if path is not None:
        gap['path'] = path
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def _byte_key(name: str) -> bytes:
    return name.encode('utf-8', 'surrogateescape')


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Return ``(first physical line number, logical line)`` pairs as ifupdown's ``get_line`` reads them."""
    physical = text.split('\n')
    if physical and physical[-1] == '':
        physical.pop()
    out: list[tuple[int, str]] = []
    i = 0
    while i < len(physical):
        start = i + 1
        current = physical[i].lstrip(_C_SPACE)
        i += 1
        if current.startswith('#'):
            continue
        while current.endswith('\\'):
            current = current[:-1]
            if i >= len(physical):
                break
            current += physical[i]
            i += 1
        out.append((start, current.rstrip(_C_SPACE)))
    return out


def _next_word(rest: str) -> tuple[str, str] | None:
    """Mirror ``next_word``: ``None`` at end of input, else (truncated word, remainder without leading space)."""
    if not rest:
        return None
    j = 0
    while j < len(rest) and rest[j] not in _C_SPACE:
        j += 1
    word = rest[:j]
    if len(_byte_key(word)) > WORD_MAX:
        word = _byte_key(word)[:WORD_MAX].decode('utf-8', 'surrogateescape')
    return word, rest[j:].lstrip(_C_SPACE)


def _words(rest: str) -> list[str]:
    words = []
    item = _next_word(rest)
    while item is not None:
        words.append(item[0])
        item = _next_word(item[1])
    return words


def env_name(option: str) -> str:
    """Return the ``IF_*`` variable name ifupdown exports for a stanza option."""
    out = []
    for ch in f'IF_{option}':
        ch = '_' if ch == '-' else ch
        if ch.isascii() and ch.isalpha():
            ch = ch.upper()
        if ch.isascii() and (ch.isalnum() or ch == '_'):
            out.append(ch)
    return ''.join(out)


class _State:
    def __init__(self, files: dict[str, Any], directories: dict[str, Any], gaps: list[dict[str, Any]]):
        self.files = files
        self.directories = directories
        self.gaps = gaps
        self.seen: set[str] = set()
        self.stanzas: list[dict[str, Any]] = []
        self.mappings: list[dict[str, Any]] = []
        self.classes: dict[str, list[str]] = {}
        self.no_scripts: list[str] = []
        self.no_auto_down: list[str] = []
        self.parsed: list[dict[str, Any]] = []
        self.include_errors: list[dict[str, Any]] = []
        self.hooks = 0
        self.loopback = False

    def file(self, path: str) -> dict[str, Any] | None:
        return self.files.get(posixpath.normpath(path))

    def directory(self, path: str) -> dict[str, Any] | None:
        return self.directories.get(posixpath.normpath(path))


def _expand(state: _State, current: str, rest: str, line: int) -> list[str] | None:
    """Expand a ``source``/``source-dir`` argument like ``wordexp``; ``None`` when not modeled."""
    pattern = rest if rest.startswith('/') else f'{posixpath.dirname(current)}/{rest}'
    if any(ch in _WORDEXP_BADCHARS for ch in pattern):
        return []  # wordexp rejects the pattern (WRDE_BADCHAR), so nothing is read.
    if any(ch in _UNMODELED_CHARS for ch in pattern) or any(ch in _C_SPACE for ch in pattern):
        _gap(state.gaps, 'include_pattern_unmodeled', current,
             f'Line {line}: shell expansion, quoting or several words in {rest!r} are not modeled.')
        return None
    head, tail = posixpath.split(pattern)
    if any(ch in _GLOB_CHARS for ch in head):
        _gap(state.gaps, 'include_pattern_unmodeled', current,
             f'Line {line}: a wildcard before the last path component in {rest!r} is not modeled.')
        return None
    if not any(ch in _GLOB_CHARS for ch in tail):
        return [pattern]
    listing = state.directory(head)
    if listing is None:
        _gap(state.gaps, 'directory_not_observed', head or '/', f'Needed to expand {rest!r} (line {line}).')
        return None
    if listing['state'] == 'unreadable':
        _gap(state.gaps, 'directory_unreadable', head or '/', f'Needed to expand {rest!r} (line {line}).')
        return None
    if listing['state'] != 'listed':
        return []
    if listing['truncated']:
        _gap(state.gaps, 'listing_incomplete', head or '/')
    names = [name for name in listing['names']
             if (tail.startswith('.') or not name.startswith('.')) and fnmatch.fnmatchcase(name, tail)]
    return [f'{head}/{name}' for name in sorted(names, key=_byte_key)]


def _read(state: _State, path: str, depth: int, top: bool) -> bool:
    """Parse one file. Return False only when the top-level file is rejected or missing."""
    if path in state.seen:
        return True
    state.seen.add(path)
    if depth > MAX_DEPTH:
        _gap(state.gaps, 'include_depth_exceeded', path, f'Includes nest deeper than {MAX_DEPTH} files.')
        return True
    if len(state.parsed) >= MAX_FILES:
        _gap(state.gaps, 'too_many_files', path, f'Only {MAX_FILES} files are parsed.')
        return True
    meta = state.file(path)
    if meta is None:
        _gap(state.gaps, 'file_not_observed', path)
        return True
    if meta['state'] == 'unreadable':
        _gap(state.gaps, 'file_unreadable', path)
        return True
    if meta['state'] in ('absent', 'directory'):
        # fopen() of a missing file only warns; reading a directory fails with EISDIR and rejects the file.
        state.parsed.append({'path': path, 'state': meta['state']})
        return not (top and meta['state'] == 'directory')
    if meta['truncated']:
        _gap(state.gaps, 'file_truncated', path, 'Only part of the file was captured.')
    record: dict[str, Any] = {'path': path, 'state': 'parsed'}
    state.parsed.append(record)
    try:
        _parse(state, path, meta['text'], depth)
    except _Rejected as exc:
        record['state'] = 'rejected'
        record['error'] = {'line': exc.line, 'message': exc.message}
        if top:
            return False
        state.include_errors.append({'path': path, 'line': exc.line, 'message': exc.message})
    return True


def _parse(state: _State, path: str, text: str, depth: int) -> None:
    current: dict[str, Any] | None = None
    mapping: dict[str, Any] | None = None
    processing = 'none'
    for line, buf in logical_lines(text):
        first = _next_word(buf)
        if first is None:
            continue
        word, rest = first
        if word == 'mapping':
            mapping = {'matches': _words(rest), 'script': None, 'maps': [], 'file': path, 'line': line}
            state.mappings.append(mapping)
            processing = 'mapping'
        elif word == 'source' or word.startswith('source-dir'):
            targets = _expand(state, path, rest, line)
            for target in targets or ():
                if word == 'source':
                    if (state.file(target) or {}).get('state') == 'absent':
                        continue
                    _read(state, target, depth + 1, False)
                    continue
                listing = state.directory(target)
                if listing is None:
                    _gap(state.gaps, 'directory_not_observed', target, f'Named by source-directory in {path}:{line}.')
                    continue
                if listing['state'] == 'unreadable':
                    _gap(state.gaps, 'directory_unreadable', target)
                    continue
                if listing['state'] != 'listed':
                    continue
                if listing['truncated']:
                    _gap(state.gaps, 'listing_incomplete', target)
                for name in sorted((n for n in listing['names'] if _SOURCE_DIR_NAME.fullmatch(n)), key=_byte_key):
                    _read(state, f'{target}/{name}', depth + 1, False)
            processing = 'none'
        elif word == 'iface':
            current = _iface(state, path, line, rest)
            processing = 'iface'
        elif word in ('auto', 'no-auto-down', 'no-scripts') or (word.startswith('allow-') and len(word) > 6):
            if not rest and processing == 'iface' and current is not None:
                names = [current['logical']]
            else:
                names = _words(rest)
                processing = 'none'
            for name in names:
                if word == 'no-scripts':
                    state.no_scripts.append(name)
                elif word == 'no-auto-down':
                    state.no_auto_down.append(name)
                else:
                    cls = 'auto' if word == 'auto' else word[6:]
                    members = state.classes.setdefault(cls, [])
                    if name not in members:
                        members.append(name)
        elif word == 'rename':
            processing = 'none'
        elif processing == 'iface' and current is not None:
            option = PHASE_ALIASES.get(word, word)
            if not rest:
                raise _Rejected(line, 'option with empty value')
            if option in PHASES:
                if state.hooks >= MAX_HOOKS:
                    _gap(state.gaps, 'too_many_hooks', path, f'Only {MAX_HOOKS} hook lines are listed.')
                    continue
                state.hooks += 1
                current['hooks'][option].append(_hook(rest, path, line, word))
            elif option not in current['options']:
                current['options'].append(option)
        elif processing == 'mapping' and mapping is not None:
            if word == 'script':
                if mapping['script'] is not None:
                    raise _Rejected(line, 'duplicate script in mapping')
                mapping['script'] = {'command': rest, 'file': path, 'line': line}
            elif word == 'map':
                mapping['maps'].append(rest)
            else:
                raise _Rejected(line, 'misplaced option')
        else:
            raise _Rejected(line, 'misplaced option')


def _hook(command: str, path: str, line: int, written_as: str) -> dict[str, Any]:
    ignore = command.startswith('-')
    return {'command': command[1:] if ignore else command, 'ignore_status': ignore,
            'file': path, 'line': line, 'written_as': written_as}


def _iface(state: _State, path: str, line: int, rest: str) -> dict[str, Any]:
    words = _words(rest)
    if len(words) < 2:
        raise _Rejected(line, 'too few parameters for iface line')
    name, family, method, inherits = words[0], None, None, None
    tail = words[1:]
    if tail[0] in FAMILY_METHODS:
        family = tail.pop(0)
        if tail and tail[0] in FAMILY_METHODS[family]:
            method = tail.pop(0)
    if family is None and tail[0] != 'inherits':
        raise _Rejected(line, 'unknown or no address type and no inherits keyword specified')
    if method is None and (not tail or tail[0] != 'inherits'):
        raise _Rejected(line, 'unknown or no method and no inherits keyword specified')
    if tail and tail[0] != 'inherits':
        tail = []  # ifupdown warns that the extra parameter is ignored and reads nothing further
    stanza: dict[str, Any] = {
        'logical': name, 'family': family, 'method': method, 'file': path, 'line': line, 'inherits': None,
        'implicit': False, 'options': [], 'hooks': {phase: [] for phase in PHASES},
    }
    if tail and tail[0] == 'inherits':
        if len(tail) < 2:
            raise _Rejected(line, "'inherits' keyword is missing a parameter")
        inherits = tail[1]
        parent = next((s for s in state.stanzas
                       if s['logical'] == inherits and (family is None or s['family'] == family)), None)
        if parent is None:
            raise _Rejected(line, f'unknown iface to inherit from: {inherits}')
        stanza['inherits'] = {'logical': inherits, 'file': parent['file'], 'line': parent['line']}
        stanza['options'] = list(parent['options'])
        for phase in PHASES:
            stanza['hooks'][phase] = [dict(hook, inherited=True) for hook in parent['hooks'][phase]]
        stanza['family'] = stanza['family'] or parent['family']
        stanza['method'] = stanza['method'] or parent['method']
    if family in ('inet', 'inet6') and method == 'loopback':
        state.loopback = True
    state.stanzas.append(stanza)
    return stanza


def _normalize_files(files: Any, gaps: list[dict[str, Any]]) -> dict[str, dict[str, Any]] | None:
    if not isinstance(files, dict):
        return None
    out: dict[str, dict[str, Any]] = {}
    for path, meta in files.items():
        if not isinstance(path, str) or not path.startswith('/') or not isinstance(meta, dict):
            _gap(gaps, 'input_malformed', None, 'A file entry is not an absolute path with metadata.')
            continue
        st = meta.get('state')
        if st not in FILE_STATES:
            _gap(gaps, 'input_malformed', path, 'Unknown file state.')
            continue
        entry = {'state': st, 'text': '', 'truncated': bool(meta.get('truncated'))}
        if st == 'read':
            text = meta.get('text')
            if not isinstance(text, str) or len(_byte_key(text)) > MAX_FILE_BYTES:
                _gap(gaps, 'input_malformed', path, f'Text is missing or larger than {MAX_FILE_BYTES} bytes.')
                continue
            entry['text'] = text
        out[posixpath.normpath(path)] = entry
    return out


def _normalize_dirs(directories: Any, gaps: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if directories is None:
        return out
    if not isinstance(directories, dict):
        _gap(gaps, 'input_malformed', None, 'Directory listings are not a mapping.')
        return out
    for path, meta in directories.items():
        if not isinstance(path, str) or not path.startswith('/') or not isinstance(meta, dict) \
                or meta.get('state') not in DIRECTORY_STATES:
            _gap(gaps, 'input_malformed', path if isinstance(path, str) else None, 'Malformed directory listing.')
            continue
        names = meta.get('names', [])
        if meta['state'] == 'listed' and (not isinstance(names, list) or len(names) > MAX_ENTRIES or not all(
                isinstance(n, str) and n and '/' not in n and n not in ('.', '..') for n in names)):
            _gap(gaps, 'input_malformed', path, 'Directory names are malformed or over the limit.')
            continue
        out[posixpath.normpath(path)] = {'state': meta['state'], 'names': list(names) if meta['state'] == 'listed'
                                         else [], 'truncated': bool(meta.get('truncated'))}
    return out


def _stat_ok(meta: Any) -> dict[str, Any] | None:
    if not isinstance(meta, dict) or meta.get('type') not in ('file', 'directory', 'other'):
        return None
    mode = meta.get('mode')
    if meta['type'] == 'file' and not (isinstance(mode, int) and not isinstance(mode, bool) and 0 <= mode <= 0o7777):
        return None
    if meta.get('noexec') is not None and not isinstance(meta.get('noexec'), bool):
        return None
    return meta


def _run_parts(phase: str, listing: Any, gaps: list[dict[str, Any]]) -> dict[str, Any]:
    directory = HOOK_DIRS[phase]
    result: dict[str, Any] = {'directory': directory, 'state': 'not_observed', 'scripts': [],
                              'command': ('/bin/run-parts', '--exit-on-error', directory)}
    if listing is None:
        _gap(gaps, 'directory_not_observed', directory)
        return result
    if not isinstance(listing, dict) or listing.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', directory, 'Malformed hook directory metadata.')
        return result
    result['state'] = listing['state']
    if listing['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', directory)
    if listing['state'] != 'listed':
        return result
    if listing.get('truncated'):
        _gap(gaps, 'listing_incomplete', directory)
    entries = listing.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries' if isinstance(entries, list) else 'input_malformed', directory)
        return result
    seen: set[str] = set()
    scripts = []
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or '/' in name or name in seen or name in ('.', '..'):
            _gap(gaps, 'input_malformed', directory, 'An entry has a missing, invalid or duplicate name.')
            continue
        seen.add(name)
        path = f'{directory}/{name}'
        if not _RUN_PARTS_NAME.fullmatch(name):
            scripts.append({'name': name, 'path': path, 'outcome': 'name_rejected'})
            continue
        if entry.get('type') == 'symlink':
            if 'target' not in entry:
                _gap(gaps, 'symlink_target_unobserved', path)
                scripts.append({'name': name, 'path': path, 'outcome': 'unresolved'})
                continue
            if entry['target'] is None:
                scripts.append({'name': name, 'path': path, 'outcome': 'stat_failed'})
                continue
            stat = _stat_ok(entry['target'])
        else:
            stat = _stat_ok(entry)
        if stat is None:
            _gap(gaps, 'metadata_missing', path, 'Type, mode or mount flag metadata is missing or malformed.')
            scripts.append({'name': name, 'path': path, 'outcome': 'unresolved'})
            continue
        if stat['type'] == 'directory':
            outcome = 'directory'
        elif stat['type'] == 'other':
            outcome = 'not_plain_file'
        elif not stat['mode'] & 0o111:
            outcome = 'not_executable'
        elif stat.get('noexec'):
            outcome = 'noexec_mount'
        else:
            outcome = 'runs'
            if stat.get('noexec') is None:
                _gap(gaps, 'mount_flags_unobserved', path, 'Reported as running; the noexec flag was not observed.')
        scripts.append({'name': name, 'path': path, 'outcome': outcome})
    scripts.sort(key=lambda s: _byte_key(s['name']))
    for script in scripts:
        script['reason'] = REASONS[script['outcome']]
    result['scripts'] = scripts
    return result


def assess(files: Any, directories: Any = None, hook_dirs: Any = None, *, family: Any = None,
           ifupdown_installed: Any = None, interfaces: str = INTERFACES) -> dict[str, Any]:
    """Resolve what ifupdown runs from captured configuration and metadata.

    ``files`` maps absolute paths to ``{'state': 'read', 'text': str, 'truncated': bool}`` or a
    ``state`` of ``absent``, ``unreadable`` or ``directory``. ``directories`` maps directories that
    ``source`` globs or ``source-directory`` need to ``{'state': 'listed', 'names': [...]}`` (or another
    state). ``hook_dirs`` maps each phase to ``{'state': 'listed', 'entries': [{'name', 'type',
    'mode', 'noexec', 'target'}]}`` for ``/etc/network/if-<phase>.d``.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'interfaces': interfaces,
        'runs_as': RUNS_AS, 'shell': SHELL, 'up_sequence': UP_SEQUENCE, 'down_sequence': DOWN_SEQUENCE,
        'applicability': 'unknown', 'config_state': 'not_observed', 'stanzas': [], 'mappings': [],
        'classes': {}, 'files': [], 'include_errors': [], 'run_parts': {}, 'gaps': gaps,
        'origin': 'not_assessed', 'not_a_verdict': NOT_A_VERDICT, 'unobserved': UNOBSERVED,
    }
    if family not in KNOWN_FAMILIES:
        _gap(gaps, 'family_not_observed' if family is None else 'family_unsupported')
    elif family not in APPLICABLE_FAMILIES:
        result['applicability'] = 'not_applicable'
    if ifupdown_installed is False:
        result['applicability'] = 'not_applicable'
    elif ifupdown_installed is not True:
        _gap(gaps, 'implementation_not_observed', None, 'Whether the ifupdown package is installed is unknown.')
    elif family in APPLICABLE_FAMILIES:
        result['applicability'] = 'applicable'
    normalized = _normalize_files(files, gaps)
    if normalized is None:
        _gap(gaps, 'input_malformed', None, 'Files are not a mapping.')
        result['complete'] = False
        return result
    state = _State(normalized, _normalize_dirs(directories, gaps), gaps)
    if not isinstance(interfaces, str) or not interfaces.startswith('/'):
        _gap(gaps, 'input_malformed', None, 'The interfaces path is not absolute.')
        result['complete'] = False
        return result
    state.classes['auto'] = ['lo']
    accepted = _read(state, interfaces, 0, True)
    top = state.file(interfaces)
    if top is not None and top['state'] in ('read', 'absent', 'directory'):
        result['config_state'] = 'rejected' if not accepted else ('absent' if top['state'] == 'absent' else 'accepted')
    result['files'] = state.parsed
    result['include_errors'] = state.include_errors
    if result['config_state'] in ('accepted', 'absent'):
        if not state.loopback:
            state.stanzas.insert(0, {'logical': 'lo', 'family': 'inet', 'method': 'loopback', 'file': None,
                                     'line': None, 'inherits': None, 'implicit': True, 'options': [],
                                     'hooks': {phase: [] for phase in PHASES}})
        for stanza in state.stanzas:
            stanza['activation'] = sorted(cls for cls, members in state.classes.items()
                                          if stanza['logical'] in members)
            stanza['no_scripts'] = any(fnmatch.fnmatchcase(stanza['logical'], p) for p in state.no_scripts)
            stanza['no_auto_down'] = any(fnmatch.fnmatchcase(stanza['logical'], p) for p in state.no_auto_down)
            stanza['environment'] = sorted({env_name(o) for o in stanza.pop('options')})
        result['stanzas'] = state.stanzas
        result['mappings'] = [m for m in state.mappings if m['script'] is not None]
        result['classes'] = {cls: list(members) for cls, members in sorted(state.classes.items())}
    if not isinstance(hook_dirs, dict):
        hook_dirs = {}
    result['run_parts'] = {phase: _run_parts(phase, hook_dirs.get(phase), gaps) for phase in PHASES}
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
