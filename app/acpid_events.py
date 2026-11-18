"""Pure acpid event-rule contract (roadmap F slice, #1079).

acpid runs the ``action`` of every rule file in its configuration directory
(``/etc/acpi/events`` by default) as root through ``/bin/sh -c`` whenever an
ACPI event matches the rule's ``event`` regular expression. This module turns a
captured directory listing, captured rule-file text and the ``OPTIONS`` value
from ``/etc/default/acpid`` into the rules acpid loads. It performs no I/O,
never runs acpid or a shell, never evaluates an action and never authorizes a
response action.

The rules follow ``event.c`` and ``acpid.c`` in acpid 2.0.28, 2.0.32, 2.0.33
and 2.0.34 (Ubuntu 26.04 ``acpid_2.0.34-1ubuntu3``). Their rule-loading,
rule-matching and command code is identical apart from a renamed debug
variable:

- ``acpid_read_conf`` loads every entry whose name matches
  ``^[a-zA-Z0-9_-]+$``. A name with a dot, such as ``power.conf``, is skipped.
  An entry whose ``d_type`` is not a regular file is followed with
  ``fstatat``; only a regular file, or a symlink to one, loads. A dangling link
  is skipped. Directory order is ``readdir`` order, which is unspecified.
- ``parse_file`` reads with ``fgets`` into a 512-byte buffer limited to 511,
  so a line of more than 510 bytes is processed in 510-byte pieces and each
  piece is parsed as its own line. Leading whitespace is skipped, and blank
  lines and lines starting with ``#`` are ignored. Each remaining line is split
  with ``sscanf("%63[^=\\n]=%255[^\\n]")``: the key is whitespace-significant
  and compared case-insensitively with ``event`` and ``action``, and a value
  longer than 255 bytes is silently truncated. The acpid(8) page says 511;
  the code keeps 255. A line that does not split is skipped, as is an unknown
  key. A later ``event`` or ``action`` replaces an earlier one.
- Every ``event`` value is compiled with ``REG_EXTENDED | REG_ICASE |
  REG_NOSUB | REG_NEWLINE``; a value that does not compile rejects the whole
  file. Every ``action`` value passes ``check_escapes``: a ``%`` escape other
  than ``%e`` and ``%%`` rejects the whole file, even if a later ``action``
  line replaces it. A file without both keys is skipped as incomplete.
- An action equal to the drop action (``<drop>``, or ``-r``/``--dropaction``)
  makes a drop rule. Drop rules are checked first, and a matching one stops
  every later rule and client notification for that event.
- A matching command rule forks, replaces ``%e`` with the event text and
  ``%%`` with ``%``, sets umask 0077 and runs ``/bin/sh -c`` as acpid's user,
  root. acpid waits for it before handling the next rule.
- ``-c``/``--confdir`` and ``-r``/``--dropaction`` come from the ``OPTIONS``
  words, which systemd splits at whitespace for ``$OPTIONS``. Long options
  follow ``getopt_long``: a unique prefix is accepted and an ambiguous or
  unknown option makes acpid print its usage and exit. A configuration
  directory that cannot be opened makes acpid exit at startup.

Fail-closed rules: an unobserved directory, options value, symlink target or
rule-file text, invalid UTF-8, NUL bytes and over-limit input mark the result
incomplete; affected files are ``unresolved`` and never reported as not
running. ``origin`` is always ``not_assessed`` and no result is a safety
verdict.
"""
from __future__ import annotations

import hashlib
import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('2.0.28', '2.0.32', '2.0.33', '2.0.34')
DEFAULT_CONFDIR = '/etc/acpi/events'
DEFAULT_DROPACTION = '<drop>'
DEFAULT_LOCKFILE = '/var/lock/acpid'
SHELL = '/bin/sh'
REGEX_FLAGS = ('REG_EXTENDED', 'REG_ICASE', 'REG_NOSUB', 'REG_NEWLINE')
# event.c: fgets(buf, sizeof(buf)-1, fp) with char buf[512].
FGETS_CHUNK = 510
KEY_MAX = 63
VALUE_MAX = 255
MAX_TEXT = 65536
MAX_ENTRIES = 1024
MAX_OPTIONS = 256
MAX_GAPS = 64
MAX_LINE_NOTES = 256

STATUSES = ('loads', 'drop', 'ignored', 'skipped_non_file', 'skipped_incomplete', 'rejected', 'unresolved')
BLOCKING = frozenset({
    'directory_not_observed', 'directory_unreadable', 'directory_mismatch', 'options_not_observed',
    'options_over_limit', 'confdir_relative', 'entries_over_limit', 'malformed_entry', 'duplicate_entry',
    'target_not_observed', 'type_not_observed', 'text_not_observed', 'over_limit', 'invalid_utf8', 'binary',
    'gaps_truncated',
})
NOT_OBSERVED = (
    ('Whether each event regular expression compiles under the host C library; a file whose regex does not '
     'compile is not loaded, but is reported here as loaded.'),
    ('Whether acpid is installed, enabled and running, and whether a systemd drop-in or init script changes its '
     'command line beyond OPTIONS.'),
    'Which ACPI events the hardware produces, so which rules ever match.',
    (f'Whether the lock file ({DEFAULT_LOCKFILE} unless -L/--lockfile is set) exists; acpid ignores every event '
     'while it does.'),
    'The contents of programs or scripts an action runs.',
    'The order acpid loads rule files in, which follows readdir and is unspecified.',
)

# acpid.c handle_cmdline(): getopt_long(argc, argv, "c:C:de:flg:m:s:Sp:L:nr:tvh", opts).
_SHORT_WITH_ARG = frozenset('cCegmspLr')
_SHORT_NO_ARG = frozenset('dflSntvh')
_LONG = {
    'confdir': 'c', 'clientmax': 'C', 'debug': 'd', 'eventfile': 'e', 'foreground': 'f', 'logevents': 'l',
    'socketgroup': 'g', 'socketmode': 'm', 'socketfile': 's', 'nosocket': 'S', 'pidfile': 'p',
    'lockfile': 'L', 'netlink': 'n', 'dropaction': 'r', 'tpmutefix': 't', 'version': 'v', 'help': 'h',
}
_NAME = re.compile(r'[a-zA-Z0-9_-]+')
# C-locale isspace().
_SPACE = b' \t\n\v\f\r'


def _gap(gaps: list[dict[str, Any]], code: str, name: str | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'name': name, 'detail': detail[:240], 'blocking': code in BLOCKING})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'name': None, 'detail': 'Further gaps were not recorded.',
                     'blocking': True})


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def name_loads(name: str) -> bool:
    """Return whether acpid's file-name filter accepts ``name``."""
    return bool(_NAME.fullmatch(name))


def parse_options(options: str) -> dict[str, Any]:
    """Apply acpid's ``getopt_long`` handling to the whitespace-split ``OPTIONS`` value."""
    result: dict[str, Any] = {'confdir': DEFAULT_CONFDIR, 'dropaction': DEFAULT_DROPACTION,
                              'lockfile': DEFAULT_LOCKFILE, 'starts': True, 'error': None}
    words = options.split()

    def fail(message: str) -> dict[str, Any]:
        result.update(starts=False, error=message[:240])
        return result

    def assign(letter: str, value: str) -> None:
        key = {'c': 'confdir', 'r': 'dropaction', 'L': 'lockfile'}.get(letter)
        if key:
            result[key] = value

    index = 0
    while index < len(words):
        word = words[index]
        index += 1
        if word == '--':
            break
        if word.startswith('--'):
            name, has_value, value = word[2:].partition('=')
            if name in _LONG:
                letter = _LONG[name]
            else:
                matches = [long for long in _LONG if long.startswith(name)]
                if len(matches) != 1:
                    return fail(f'"--{name[:40]}" is {"ambiguous" if matches else "not an option"}; '
                                'acpid prints its usage and exits.')
                letter = _LONG[matches[0]]
            if letter in _SHORT_WITH_ARG:
                if not has_value:
                    if index >= len(words):
                        return fail(f'"--{name[:40]}" needs an argument; acpid prints its usage and exits.')
                    value = words[index]
                    index += 1
                assign(letter, value)
            elif has_value:
                return fail(f'"--{name[:40]}" takes no argument; acpid prints its usage and exits.')
            elif letter in 'vh':
                return fail(f'"--{name[:40]}" makes acpid print and exit.')
            continue
        if not word.startswith('-') or word == '-':
            # getopt_long permutes non-options to the end; acpid ignores them.
            continue
        position = 1
        while position < len(word):
            letter = word[position]
            position += 1
            if letter in _SHORT_WITH_ARG:
                value = word[position:]
                if not value:
                    if index >= len(words):
                        return fail(f'"-{letter}" needs an argument; acpid prints its usage and exits.')
                    value = words[index]
                    index += 1
                assign(letter, value)
                break
            if letter not in _SHORT_NO_ARG:
                return fail(f'"-{letter}" is not an option; acpid prints its usage and exits.')
            if letter in 'vh':
                return fail(f'"-{letter}" makes acpid print and exit.')
    return result


def _chunks(data: bytes) -> Iterable[bytes]:
    """Yield what successive ``fgets(buf, 511, fp)`` calls return."""
    start = 0
    while start < len(data):
        newline = data.find(b'\n', start, start + FGETS_CHUNK)
        end = newline + 1 if newline >= 0 else min(start + FGETS_CHUNK, len(data))
        yield data[start:end]
        start = end


def _split(line: bytes) -> tuple[bytes, bytes, bool] | None:
    """Emulate ``sscanf(p, "%63[^=\\n]=%255[^\\n]", key, val)``; ``None`` unless it returns 2."""
    end = 0
    while end < len(line) and end < KEY_MAX and line[end:end + 1] not in (b'=', b'\n'):
        end += 1
    if end == 0 or line[end:end + 1] != b'=':
        return None
    rest = line[end + 1:]
    stop = rest.find(b'\n')
    raw = rest if stop < 0 else rest[:stop]
    if not raw:
        return None
    return line[:end], raw[:VALUE_MAX], len(raw) > VALUE_MAX


def _escapes_valid(value: bytes) -> bool:
    """Emulate ``check_escapes()``."""
    index = 0
    while index < len(value):
        if value[index:index + 1] == b'%':
            index += 1
            if index >= len(value) or value[index:index + 1] not in (b'%', b'e'):
                return False
        index += 1
    return True


def _first_word(command: str) -> str | None:
    words = command.split()
    return words[0][:256] if words else None


def parse_rule(name: str, text: str | bytes | None, *, dropaction: str = DEFAULT_DROPACTION) -> dict[str, Any]:
    """Parse one captured rule file as acpid's ``parse_file()`` does."""
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'name': name, 'status': 'unresolved', 'reason': None, 'sha256': None, 'size': None,
                              'event': None, 'action': None, 'lines': [], 'lines_truncated': False, 'origin': 'not_assessed', 'gaps': gaps}
    if text is None:
        _gap(gaps, 'text_not_observed', name, 'The rule file text was not captured.')
        result['reason'] = 'text_not_observed'
        return result
    data = text.encode('utf-8', 'surrogatepass') if isinstance(text, str) else text
    if not isinstance(data, bytes) or len(data) > MAX_TEXT:
        _gap(gaps, 'over_limit', name, f'More than {MAX_TEXT} bytes.')
        result['reason'] = 'over_limit'
        return result
    if b'\x00' in data:
        _gap(gaps, 'binary', name, 'The file contains NUL bytes.')
        result['reason'] = 'binary'
        return result
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', name, 'The file is not valid UTF-8.')
        result['reason'] = 'invalid_utf8'
        return result
    result['sha256'] = _sha(data)
    result['size'] = len(data)
    event: dict[str, Any] | None = None
    action: dict[str, Any] | None = None
    offset = 0
    for number, chunk in enumerate(_chunks(data), 1):
        split_line = offset > 0 and data[offset - 1:offset] != b'\n'
        offset += len(chunk)
        stripped = chunk.lstrip(_SPACE)
        if not stripped or stripped.startswith(b'#'):
            continue
        parsed = _split(stripped)
        note: dict[str, Any] = {'line': number, 'continues_long_line': split_line}
        if len(result['lines']) >= MAX_LINE_NOTES:
            result['lines_truncated'] = True
            note = {}
        if parsed is None:
            if note:
                result['lines'].append({**note, 'outcome': 'unparsed'})
            continue
        raw_key, raw_value, truncated = parsed
        try:
            key = raw_key.decode('utf-8')
            value = raw_value.decode('utf-8')
        except UnicodeDecodeError:
            _gap(gaps, 'invalid_utf8', name, f'Line {number} splits a multi-byte character at acpid\'s limit.')
            result.update(status='unresolved', reason='invalid_utf8', event=None, action=None)
            return result
        lowered = key.lower() if key.isascii() else key
        if lowered not in ('event', 'action'):
            if note:
                result['lines'].append({**note, 'outcome': 'unknown_key', 'key': key[:KEY_MAX]})
            continue
        record = {'value': value, 'line': number, 'truncated': truncated, 'continues_long_line': split_line}
        if note:
            result['lines'].append({**note, 'outcome': lowered, 'truncated': truncated})
        if lowered == 'event':
            event = {**record, 'flags': list(REGEX_FLAGS)}
            continue
        if not _escapes_valid(raw_value):
            result.update(status='rejected', reason='invalid_escape', event=None, action=None)
            return result
        action = {**record, 'sha256': _sha(raw_value), 'drop': value == dropaction,
                  'event_substitution': _uses_event(value), 'first_word': _first_word(value)}
    if event is None or action is None:
        result.update(status='skipped_incomplete', reason='missing_event' if event is None else 'missing_action')
        return result
    result.update(event=event, action=action, status='drop' if action['drop'] else 'loads', reason=None)
    return result


def _uses_event(value: str) -> bool:
    index = 0
    while index < len(value):
        if value[index] == '%':
            if value[index + 1:index + 2] == 'e':
                return True
            index += 2
            continue
        index += 1
    return False


def evaluate(entries: Any, *, directory: Any = None, options: Any = None,
             texts: Mapping[str, str | bytes | None] | None = None) -> dict[str, Any]:
    """Resolve which acpid rule files load and what they run.

    ``directory`` is ``{'path': '/etc/acpi/events', 'state': 'listed' | 'absent' | 'unreadable'}`` for the
    effective configuration directory. ``options`` is the ``OPTIONS`` value from ``/etc/default/acpid``
    (``''`` when it is unset or commented out; ``None`` when it was not observed). Each entry is
    ``{'name': 'powerbtn', 'type': 'file' | 'symlink' | 'directory' | 'other', 'target_type': ...}``, where
    ``target_type`` is the followed type of a symlink (``'file'``, ``'directory'``, ``'other'`` or
    ``'missing'``). ``texts`` maps an entry name to its captured text.
    """
    gaps: list[dict[str, Any]] = []
    texts = texts or {}
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'format': 'acpid_events', 'source_versions': list(SOURCE_VERSIONS),
        'complete': False, 'acpid_starts': None, 'confdir': None, 'dropaction': None, 'lockfile': None,
        'execution': {'shell': SHELL, 'argv': [SHELL, '-c', '<action>'], 'user': 'root', 'umask': '0077',
                      'waits_for_completion': True, 'event_substitution': '%e', 'percent_escape': '%%'},
        'files': [], 'rules': [], 'drop_rules': [], 'origin': 'not_assessed', 'gaps': gaps,
        'not_observed': list(NOT_OBSERVED),
    }
    if options is None:
        _gap(gaps, 'options_not_observed', None, 'OPTIONS from /etc/default/acpid was not supplied; '
             '-c/--confdir or -r/--dropaction may change the directory or drop action.')
        parsed = parse_options('')
    elif not isinstance(options, str) or len(options) > 4096 or len(options.split()) > MAX_OPTIONS:
        _gap(gaps, 'options_over_limit', None, 'OPTIONS is not text or is over the limit.')
        parsed = parse_options('')
    else:
        parsed = parse_options(options)
    result.update(confdir=parsed['confdir'], dropaction=parsed['dropaction'], lockfile=parsed['lockfile'])
    if not parsed['starts']:
        _gap(gaps, 'option_exits', None, parsed['error'])
        result.update(acpid_starts=False, complete=not any(g['blocking'] for g in gaps))
        return result
    confdir = parsed['confdir']
    if not confdir.startswith('/'):
        _gap(gaps, 'confdir_relative', None, f'--confdir "{confdir[:120]}" is relative to acpid\'s working '
             'directory, which was not observed.')
        return _finish(result, gaps)
    if not isinstance(directory, Mapping) or directory.get('state') not in ('listed', 'absent', 'unreadable'):
        _gap(gaps, 'directory_not_observed', None, f'No listing result was supplied for {confdir[:200]}.')
        return _finish(result, gaps)
    if posixpath.normpath(str(directory.get('path') or '')) != posixpath.normpath(confdir):
        _gap(gaps, 'directory_mismatch', None, f'The listing is for {str(directory.get("path"))[:120]}, but acpid '
             f'reads {confdir[:120]}.')
        return _finish(result, gaps)
    if directory['state'] == 'absent':
        result['acpid_starts'] = False
        _gap(gaps, 'directory_absent', None, f'opendir({confdir[:120]}) fails, so acpid exits at startup and runs '
             'no rules.')
        return _finish(result, gaps)
    if directory['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', None, f'{confdir[:200]} could not be listed.')
        return _finish(result, gaps)
    result['acpid_starts'] = True
    entries = list(entries) if entries is not None else []
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'entries_over_limit', None, f'More than {MAX_ENTRIES} directory entries.')
        return _finish(result, gaps)
    seen: set[str] = set()
    files: list[dict[str, Any]] = []
    for entry in entries:
        name = entry.get('name') if isinstance(entry, Mapping) else None
        if not isinstance(name, str) or not name or '/' in name or '\x00' in name or len(name) > 255:
            _gap(gaps, 'malformed_entry', None, 'A directory entry has no usable name.')
            continue
        if name in ('.', '..'):
            continue
        if name in seen:
            _gap(gaps, 'duplicate_entry', name, f'{name[:120]} was listed more than once.')
            continue
        seen.add(name)
        files.append(_entry(name, entry, parsed['dropaction'], texts, gaps))
    files.sort(key=lambda f: f['name'].encode('utf-8', 'surrogatepass'))
    path = confdir.rstrip('/') or '/'
    for record in files:
        record['path'] = posixpath.join(path, record['name'])
        if record['status'] in ('loads', 'drop'):
            rule = {'name': record['name'], 'path': record['path'], 'event': record['event']['value'],
                    'event_flags': list(REGEX_FLAGS), 'action': record['action']['value'],
                    'action_sha256': record['action']['sha256'],
                    'action_truncated': record['action']['truncated'],
                    'event_truncated': record['event']['truncated'],
                    'event_substitution': record['action']['event_substitution'],
                    'first_word': record['action']['first_word'], 'origin': 'not_assessed'}
            (result['drop_rules'] if record['status'] == 'drop' else result['rules']).append(rule)
    result['files'] = files
    return _finish(result, gaps)


def _finish(result: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    result['complete'] = not any(g['blocking'] for g in gaps)
    return result


def _entry(name: str, entry: Mapping[str, Any], dropaction: str, texts: Mapping[str, Any],
           gaps: list[dict[str, Any]]) -> dict[str, Any]:
    base = {'name': name, 'type': entry.get('type'), 'status': 'unresolved', 'reason': None, 'event': None,
            'action': None, 'sha256': None, 'origin': 'not_assessed'}
    if not name_loads(name):
        return {**base, 'status': 'ignored', 'reason': 'name_filter'}
    kind = entry.get('type')
    if kind == 'symlink':
        target = entry.get('target_type')
        if target is None:
            _gap(gaps, 'target_not_observed', name, 'The symlink target type was not observed.')
            return {**base, 'reason': 'target_not_observed'}
        if target == 'missing':
            return {**base, 'status': 'skipped_non_file', 'reason': 'dangling_symlink'}
        if target != 'file':
            return {**base, 'status': 'skipped_non_file', 'reason': f'symlink_to_{target}'[:40]}
    elif kind in ('directory', 'other'):
        return {**base, 'status': 'skipped_non_file', 'reason': kind}
    elif kind != 'file':
        _gap(gaps, 'type_not_observed', name, 'The entry type was not observed.')
        return {**base, 'reason': 'type_not_observed'}
    parsed = parse_rule(name, texts.get(name), dropaction=dropaction)
    for gap in parsed.pop('gaps'):
        _gap(gaps, gap['code'], gap['name'], gap['detail'])
    parsed.pop('name')
    return {**base, **parsed}
