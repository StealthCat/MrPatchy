"""Pure strongSwan swanctl updown contract (roadmap F slice, #1624).

charon's ``updown`` plugin runs the ``updown`` command of a CHILD_SA's
configuration each time that CHILD_SA comes up or goes down (and on related
events such as rekeying of a virtual IP). ``swanctl --load-conns``, which the
packaged ``strongswan.service`` runs after the daemon starts, reads
``/etc/swanctl/swanctl.conf`` and every file it includes, so a new ``updown``
line in a drop-in makes the daemon run a new shell command as root on the
next tunnel event.

This module turns captured ``swanctl.conf`` text and captured directory
listings for ``include`` patterns into the commands the updown plugin runs,
for which connection and child, as which account. It performs no I/O, never
runs charon, swanctl or a script and never authorizes a response action.

The rules follow strongSwan 5.9.13, checked against native runs of Ubuntu
24.04 ``charon-systemd``/``strongswan-swanctl 5.9.13-2ubuntu4.24.04.5``: two
daemons in separate network namespaces with the ``kernel-libipsec`` plugin
established each CHILD_SA, and the updown script recorded its uid, its parent
process command line and its arguments:

- The command runs as ``/bin/sh -c "2>&1 <command>"`` with charon's uid
  (0 for the packaged service), so shell syntax applies: ``;`` ran a second
  command and ``$VAR`` was expanded.
- A value is a sequence of unquoted words and double-quoted strings joined by
  single spaces: ``a"b c"d  e`` became ``a b c d e``. Quotes are consumed, so
  quoting inside the value does not reach the shell; a fully quoted value
  keeps single quotes and ``\\"`` escapes for the shell. ``#`` starts a
  comment, ``,`` is literal, and the value ends at a newline or ``}``.
- A later ``updown`` for the same child replaces an earlier one, including
  one from an ``include``d file processed later. Sections with the same name
  merge.
- A value containing a newline (a multi-line quoted string) makes swanctl
  discard the whole connection ("invalid value for: updown, config
  discarded"), so none of its children run anything.
- ``include`` patterns are relative to the including file's directory; the
  default ``swanctl.conf`` includes ``conf.d/*.conf``. A pattern with no
  match includes nothing. An empty pattern (``include ""``) is ignored
  ("no include pattern specified, ignored") and the rest of the file loads.

Unobserved files or listings, unsupported include patterns, unknown escapes,
unbalanced quotes or braces, NUL bytes, over-limit input and a non-root or
invalid daemon uid are blocking gaps, and ``complete`` is false whenever one
is present. Whether a connection's other settings load, whether its tunnels
ever come up and whether ``strongswan.conf`` disables the updown plugin are
not assessed. ``origin`` is always ``not_assessed`` and
``authorizes_response`` is always false.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import posixpath
from collections.abc import Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 2
SOURCE_VERSION = 'strongSwan 5.9.13 (Ubuntu 24.04 strongswan-swanctl 5.9.13-2ubuntu4.24.04.5)'

DEFAULT_CONFIG = '/etc/swanctl/swanctl.conf'
MAX_DEPTH = 10
MAX_TEXT = 1024 * 1024
MAX_FILES = 512
MAX_COMMANDS = 2000
UID_MAX = 0xFFFFFFFF
ESCAPES = {'"': '"', '\\': '\\', 'n': '\n', 't': '\t', 'r': '\r'}
SHELL_META = set(';&|<>`$()*?[]{}~\'"\\\n')
_SPACE = ' \t\r'


class _Gaps:
    def __init__(self) -> None:
        self.gaps: list[dict[str, Any]] = []
        self.notes: list[dict[str, Any]] = []

    def gap(self, code: str, **detail: Any) -> None:
        entry = {'code': code, 'blocking': True, **detail}
        if entry not in self.gaps:
            self.gaps.append(entry)

    def note(self, code: str, **detail: Any) -> None:
        entry = {'code': code, **detail}
        if entry not in self.notes:
            self.notes.append(entry)


def tokenize(text: str, path: str, log: _Gaps) -> list[tuple[str, Any, int]] | None:
    """Return ('word'|'string'|'{'|'}'|'='|'nl', value, line) tokens, or None on a lexing gap."""
    out: list[tuple[str, Any, int]] = []
    i, line, n = 0, 1, len(text)
    while i < n:
        ch = text[i]
        if ch == '\n':
            out.append(('nl', None, line))
            line += 1
            i += 1
        elif ch in _SPACE:
            i += 1
        elif ch == '#':
            while i < n and text[i] != '\n':
                i += 1
        elif ch in '{}=':
            out.append((ch, None, line))
            i += 1
        elif ch == '"':
            start_line = line
            i += 1
            buf: list[str] = []
            while True:
                if i >= n:
                    log.gap('unterminated_quote', file=path, line=start_line)
                    return None
                ch = text[i]
                if ch == '"':
                    i += 1
                    break
                if ch == '\\':
                    if i + 1 >= n or text[i + 1] not in ESCAPES:
                        log.gap('escape_sequence', file=path, line=line)
                        return None
                    buf.append(ESCAPES[text[i + 1]])
                    i += 2
                    continue
                if ch == '\n':
                    line += 1
                buf.append(ch)
                i += 1
            out.append(('string', ''.join(buf), start_line))
        else:
            start = i
            while i < n and text[i] not in '\n#{}="' and text[i] not in _SPACE:
                i += 1
            out.append(('word', text[start:i], line))
    return out


class _Reader:
    def __init__(self, files: Mapping[str, Any], directories: Mapping[str, Any], log: _Gaps) -> None:
        self.files = files
        self.directories = directories
        self.log = log
        self.read: list[str] = []

    def load(self, path: str, section: dict[str, Any], depth: int) -> None:
        if depth > MAX_DEPTH:
            self.log.gap('include_depth', file=path, limit=MAX_DEPTH)
            return
        if path not in self.files:
            self.log.gap('file_not_observed', file=path)
            return
        raw = self.files[path]
        if raw is None:
            self.log.note('file_absent', file=path)
            return
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', 'surrogateescape')
        if len(self.read) >= MAX_FILES:
            self.log.gap('too_many_files', limit=MAX_FILES)
            return
        if len(raw) > MAX_TEXT:
            self.log.gap('text_too_large', file=path, limit=MAX_TEXT)
            return
        if '\x00' in raw:
            self.log.gap('nul_byte', file=path)
            return
        self.read.append(path)
        tokens = tokenize(raw, path, self.log)
        if tokens is not None:
            self._parse(tokens, path, section, depth)

    def _include(self, pattern: str, path: str, line: int, section: dict[str, Any], depth: int) -> None:
        if not pattern:
            # Native 5.9.13: "no include pattern specified, ignored"; the rest of the file still loads (#1680).
            self.log.note('include_pattern_empty', file=path, line=line)
            return
        if not pattern.startswith('/'):
            pattern = posixpath.join(posixpath.dirname(path), pattern)
        pattern = posixpath.normpath(pattern)
        directory, base = posixpath.split(pattern)
        if any(c in directory for c in '*?[') or '\\' in pattern or not base:
            self.log.gap('include_pattern_unsupported', file=path, line=line, pattern=pattern)
            return
        if not any(c in base for c in '*?['):
            # A literal path is included only when it exists.
            if pattern in self.files and self.files[pattern] is None:
                return
            self.load(pattern, section, depth + 1)
            return
        if directory not in self.directories:
            self.log.gap('directory_not_observed', directory=directory, file=path, line=line)
            return
        names = self.directories[directory]
        if names is None:
            return
        # glob(3) sorts matches and skips names starting with '.' unless the pattern does.
        for name in sorted(names):
            if name.startswith('.') and not base.startswith('.'):
                continue
            if fnmatch.fnmatchcase(name, base):
                self.load(posixpath.join(directory, name), section, depth + 1)

    def _parse(self, tokens: list[tuple[str, Any, int]], path: str, root: dict[str, Any], depth: int) -> None:
        stack = [root]
        i, n = 0, len(tokens)
        while i < n:
            kind, value, line = tokens[i]
            if kind == 'nl':
                i += 1
                continue
            if kind == '}':
                if len(stack) == 1:
                    self.log.gap('unbalanced_braces', file=path, line=line)
                    return
                stack.pop()
                i += 1
                continue
            if kind not in ('word', 'string'):
                self.log.gap('syntax', file=path, line=line)
                return
            nxt = tokens[i + 1][0] if i + 1 < n else None
            if kind == 'word' and value == 'include' and nxt in ('word', 'string'):
                j = i + 1
                parts = []
                while j < n and tokens[j][0] in ('word', 'string'):
                    parts.append(tokens[j][1])
                    j += 1
                self._include(' '.join(parts), path, line, stack[-1], depth)
                i = j
                continue
            if nxt == '{':
                child = stack[-1]['sections'].setdefault(value, {'sections': {}, 'keys': {}})
                stack.append(child)
                i += 2
                continue
            if nxt == '=':
                j = i + 2
                parts = []
                while j < n and tokens[j][0] in ('word', 'string'):
                    parts.append(tokens[j][1])
                    j += 1
                if j < n and tokens[j][0] in ('=', '{'):
                    self.log.gap('syntax', file=path, line=tokens[j][2])
                    return
                stack[-1]['keys'][value] = {'value': ' '.join(parts), 'file': path, 'line': line}
                i = j
                continue
            self.log.gap('syntax', file=path, line=line)
            return
        if len(stack) != 1:
            self.log.gap('unbalanced_braces', file=path, line=tokens[-1][2] if tokens else 1)


def _command_row(conn: str, child: str, entry: Mapping[str, Any], uid: int | None) -> dict[str, Any]:
    command = entry['value']
    words = command.split()
    meta = sorted({c for c in command if c in SHELL_META})
    discarded = '\n' in command
    return {
        'connection': conn,
        'child': child,
        'command': command,
        'argv': ['/bin/sh', '-c', '2>&1 ' + command],
        'program': words[0] if words and not meta else None,
        'shell_metacharacters': meta,
        'uid': uid,
        'file': entry['file'],
        'line': entry['line'],
        'connection_discarded': discarded,
        'runs': not discarded and bool(words),
    }


def _fingerprint(rows: list[dict[str, Any]]) -> str:
    canonical = json.dumps([[r['connection'], r['child'], r['command'], r['uid'], r['runs']] for r in rows],
                           ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8', 'surrogateescape')).hexdigest()


def evaluate(*, files: Mapping[str, str | bytes | None], directories: Mapping[str, Sequence[str] | None]
             | None = None, config_path: str = DEFAULT_CONFIG, charon_uid: int = 0) -> dict[str, Any]:
    """Return the updown commands charon runs for swanctl connections, and as which account.

    ``files`` maps absolute paths to captured text, or ``None`` when the path
    does not exist; ``directories`` maps absolute directories to their entry
    names, or ``None`` when absent. A path in neither mapping is unobserved.
    ``charon_uid`` is the daemon's uid (0 for the packaged service).
    """
    log = _Gaps()
    uid: int | None = charon_uid
    if not isinstance(charon_uid, int) or isinstance(charon_uid, bool) or not 0 <= charon_uid <= UID_MAX:
        log.gap('charon_uid_invalid')
        uid = None
    elif charon_uid != 0:
        log.gap('charon_not_root', uid=charon_uid)
    root: dict[str, Any] = {'sections': {}, 'keys': {}}
    reader = _Reader(files or {}, directories or {}, log)
    reader.load(posixpath.normpath(config_path), root, 0)

    rows: list[dict[str, Any]] = []
    connections = root['sections'].get('connections', {'sections': {}})['sections']
    for conn_name, conn in connections.items():
        children = conn['sections'].get('children', {'sections': {}})['sections']
        conn_rows = []
        for child_name, child in children.items():
            entry = child['keys'].get('updown')
            if entry is None:
                continue
            if len(rows) + len(conn_rows) >= MAX_COMMANDS:
                log.gap('too_many_commands', limit=MAX_COMMANDS)
                break
            row = _command_row(conn_name, child_name, entry, uid)
            if not row['command'].strip():
                log.note('updown_empty', connection=conn_name, child=child_name, file=entry['file'],
                         line=entry['line'])
            conn_rows.append(row)
        if any(r['connection_discarded'] for r in conn_rows):
            log.note('connection_discarded', connection=conn_name, reason='updown_contains_newline')
            for r in conn_rows:
                r['connection_discarded'] = True
                r['runs'] = False
        rows.extend(conn_rows)
    if connections:
        log.note('connection_load_not_assessed')
    log.note('updown_plugin_load_not_assessed')
    blocking = [gap for gap in log.gaps if gap['blocking']]
    return {
        'command_sha256': _fingerprint(rows),
        'contract': 'strongswan_updown',
        'contract_version': CONTRACT_VERSION,
        'source_version': SOURCE_VERSION,
        'complete': not blocking,
        'config_path': posixpath.normpath(config_path),
        'charon_uid': uid,
        'files': reader.read,
        'commands': rows,
        'root_commands': [i for i, r in enumerate(rows) if r['runs'] and r['uid'] == 0],
        'shell_note': 'charon runs each command through /bin/sh -c, so shell syntax and variables apply',
        'gaps': log.gaps,
        'notes': log.notes,
        'origin': 'not_assessed',
        'authorizes_response': False,
    }
