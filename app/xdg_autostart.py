"""Pure XDG desktop autostart contract (roadmap F slice, #889).

Takes captured, read-only observations of XDG autostart directories (bounded
``.desktop`` file text, in precedence order) and returns typed records saying
which entry is effective for each file name, which less important files it
shadows, whether the effective entry would start at login, and which program
and argv it would run.

Semantics follow the freedesktop *Desktop Application Autostart Specification*
and *Desktop Entry Specification*:

* Directories are searched most important first: ``$XDG_CONFIG_HOME/autostart``
  (normally ``~/.config/autostart``) and then each ``$XDG_CONFIG_DIRS``
  ``autostart`` directory (normally ``/etc/xdg/autostart``). For one file name
  only the most important file is used; the others are ``overridden_by`` it.
* ``Hidden=true`` in the effective file means "deleted": nothing with that
  name autostarts, including the shadowed system file.
* ``OnlyShowIn``/``NotShowIn`` and ``TryExec`` depend on the login session's
  desktop and ``PATH``, which are not observed here, so such entries are
  ``conditional`` rather than guessed as enabled or disabled.
* ``X-GNOME-Autostart-enabled=false`` is reported as ``disabled``. It is a
  GNOME session-manager extension, recorded with that provenance.

It performs no I/O, never executes an entry and never authorizes a response
action. Anything it cannot resolve exactly (an uncollected directory above a
found file, unreadable or oversized text, malformed lines, unbalanced ``Exec``
quoting, unknown field codes, over-cap inputs) is an explicit coverage gap and
is never reported as covered. A ``system`` origin means only "found in a
system configuration directory", never "verified unchanged package default".
"""
from __future__ import annotations

import re
from typing import Any, Iterable

CONTRACT_VERSION = 1
MAX_FILE_BYTES = 64 * 1024
MAX_ENTRIES = 512
MAX_VALUE_CHARS = 4096
MAX_ARGS = 256

GROUP = 'Desktop Entry'
_NAME_RE = re.compile(r'^[A-Za-z0-9._@+-]{1,251}\.desktop$')
_KEY_RE = re.compile(r'^[A-Za-z0-9-]+$')
_LOCALIZED_RE = re.compile(r'^[A-Za-z0-9-]+\[[^\]]+\]$')
_VALUE_ESCAPES = {'s': ' ', 'n': '\n', 't': '\t', 'r': '\r', '\\': '\\'}
# Field codes with no value at login autostart (no files/URLs are passed) and
# deprecated codes the spec says to ignore.
_DROPPED_CODES = set('fFuUdDnNvm')


def _gap(kind: str, detail: str, **extra: Any) -> dict[str, Any]:
    gap = {'kind': kind, 'detail': detail}
    gap.update({k: v for k, v in extra.items() if v is not None})
    return gap


def _unescape(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == '\\' and i + 1 < len(value) and value[i + 1] in _VALUE_ESCAPES:
            out.append(_VALUE_ESCAPES[value[i + 1]])
            i += 2
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _split_list(value: str) -> list[str]:
    """Split a ``;``-separated string list, honouring ``\\;`` escapes."""
    items: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == '\\' and i + 1 < len(value) and value[i + 1] == ';':
            cur.append(';')
            i += 2
            continue
        if ch == ';':
            items.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        items.append(''.join(cur))
    return [_unescape(item) for item in items if item]


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered == 'true':
        return True
    if lowered == 'false':
        return False
    return None


def parse_desktop_entry(text: str) -> dict[str, Any]:
    """Parse the ``[Desktop Entry]`` group of one ``.desktop`` file.

    Returns ``{'has_group', 'keys', 'gaps'}``. The first occurrence of a key
    wins and later duplicates are gaps; localized keys are ignored.
    """
    keys: dict[str, str] = {}
    gaps: list[dict[str, Any]] = []
    group: str | None = None
    has_group = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            group = line[1:-1]
            if group == GROUP:
                if has_group:
                    gaps.append(_gap('duplicate_group', 'Repeated [Desktop Entry] group ignored.', line=number))
                    group = None
                has_group = True
            continue
        if group != GROUP:
            continue
        key, sep, value = raw.partition('=')
        key = key.strip()
        if not sep or not key:
            gaps.append(_gap('malformed_line', 'Line is not a key=value pair.', line=number))
            continue
        if _LOCALIZED_RE.match(key):
            continue
        if not _KEY_RE.match(key):
            gaps.append(_gap('malformed_line', 'Key contains characters the specification does not allow.', line=number))
            continue
        if key in keys:
            gaps.append(_gap('duplicate_key', f'Duplicate {key} ignored; the first value is used.', line=number))
            continue
        value = value.strip()
        if len(value) > MAX_VALUE_CHARS:
            gaps.append(_gap('value_too_long', f'{key} exceeds {MAX_VALUE_CHARS} characters and was not used.', line=number))
            continue
        keys[key] = value
    return {'has_group': has_group, 'keys': keys, 'gaps': gaps}


def split_exec(value: str, *, icon: str | None = None, name: str | None = None,
               location: str | None = None) -> dict[str, Any]:
    """Tokenize an ``Exec`` value into argv as a login autostart would.

    General string escapes are applied first, then the ``Exec`` quoting rules:
    whitespace separates arguments, double quotes group them and, inside
    quotes, a backslash escapes ``"``, `````, ``$`` and ``\\``. Field codes are
    expanded for autostart (no files or URLs): ``%f %F %u %U`` and deprecated
    codes are dropped, ``%i`` becomes ``--icon <Icon>``, ``%c`` the name,
    ``%k`` the file location and ``%%`` a literal ``%``.
    Returns ``{'argv', 'program', 'gaps'}``; ``argv`` is ``None`` when the
    value cannot be tokenized exactly.
    """
    gaps: list[dict[str, Any]] = []
    text = _unescape(value)
    tokens: list[tuple[str, bool]] = []  # (text, was_quoted)
    cur: list[str] = []
    in_token = False
    quoted = False
    in_quotes = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_quotes:
            if ch == '\\' and i + 1 < len(text) and text[i + 1] in '"`$\\':
                cur.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quotes = False
            else:
                cur.append(ch)
            i += 1
            continue
        if ch == '"':
            in_quotes = True
            in_token = True
            quoted = True
        elif ch in ' \t\n':
            if in_token:
                tokens.append((''.join(cur), quoted))
                cur, in_token, quoted = [], False, False
        else:
            cur.append(ch)
            in_token = True
        i += 1
    if in_quotes:
        gaps.append(_gap('exec_unbalanced_quote', 'Exec has an unterminated double quote; argv was not guessed.'))
        return {'argv': None, 'program': None, 'gaps': gaps}
    if in_token:
        tokens.append((''.join(cur), quoted))

    argv: list[str] = []
    for token, was_quoted in tokens:
        if was_quoted:
            # Field codes are not expanded inside quoted arguments.
            argv.append(token)
            continue
        if len(token) == 2 and token[0] == '%' and token[1] != '%':
            code = token[1]
            if code in _DROPPED_CODES:
                continue
            if code == 'i':
                if icon:
                    argv.extend(['--icon', icon])
                continue
            if code == 'c':
                if name:
                    argv.append(name)
                continue
            if code == 'k':
                if location:
                    argv.append(location)
                continue
            gaps.append(_gap('exec_invalid_field_code', f'Unknown field code %{code} was removed.'))
            continue
        out: list[str] = []
        j = 0
        while j < len(token):
            if token[j] == '%' and j + 1 < len(token):
                nxt = token[j + 1]
                if nxt == '%':
                    out.append('%')
                else:
                    gaps.append(_gap('exec_embedded_field_code',
                                     f'Field code %{nxt} inside an argument was removed.'))
                j += 2
                continue
            if token[j] == '%':
                gaps.append(_gap('exec_invalid_field_code', 'A trailing % was removed.'))
                j += 1
                continue
            out.append(token[j])
            j += 1
        argv.append(''.join(out))
    if len(argv) > MAX_ARGS:
        gaps.append(_gap('exec_too_many_args', f'Exec has more than {MAX_ARGS} arguments; argv was not reported.'))
        return {'argv': None, 'program': None, 'gaps': gaps}
    if not argv:
        gaps.append(_gap('exec_empty', 'Exec expands to no program.'))
        return {'argv': None, 'program': None, 'gaps': gaps}
    return {'argv': argv, 'program': argv[0], 'gaps': gaps}


def _classify(path: str, keys: dict[str, str], has_group: bool) -> tuple[str, list[str], dict[str, Any]]:
    """Return ``(status, reasons, details)`` for one effective file."""
    reasons: list[str] = []
    details: dict[str, Any] = {
        'type': keys.get('Type'),
        'name': _unescape(keys['Name']) if 'Name' in keys else None,
        'exec': keys.get('Exec'),
        'try_exec': _unescape(keys['TryExec']) if 'TryExec' in keys else None,
        'only_show_in': _split_list(keys['OnlyShowIn']) if 'OnlyShowIn' in keys else [],
        'not_show_in': _split_list(keys['NotShowIn']) if 'NotShowIn' in keys else [],
        'argv': None,
        'program': None,
        'exec_gaps': [],
    }
    if not has_group:
        return 'invalid', ['No [Desktop Entry] group.'], details
    if _bool(keys.get('Hidden')):
        return 'hidden', ['Hidden=true: treated as deleted, including same-named lower-precedence files.'], details
    if 'Exec' in keys:
        parsed = split_exec(keys['Exec'], icon=keys.get('Icon'), name=details['name'], location=path)
        details['argv'] = parsed['argv']
        details['program'] = parsed['program']
        details['exec_gaps'] = parsed['gaps']
    if details['type'] != 'Application':
        return 'invalid', [f"Type is {details['type']!r}, not 'Application'."], details
    if 'Exec' not in keys:
        return 'invalid', ['No Exec key.'], details
    if _bool(keys.get('X-GNOME-Autostart-enabled')) is False:
        return 'disabled', ['X-GNOME-Autostart-enabled=false (GNOME session manager extension).'], details
    if details['only_show_in']:
        reasons.append('OnlyShowIn limits it to: ' + ', '.join(details['only_show_in']) + '.')
    if details['not_show_in']:
        reasons.append('NotShowIn excludes: ' + ', '.join(details['not_show_in']) + '.')
    if details['try_exec']:
        reasons.append(f"TryExec requires {details['try_exec']} to be executable at login.")
    if reasons:
        return 'conditional', reasons, details
    return 'enabled', ['Starts at login for any desktop session that implements XDG autostart.'], details


def resolve_autostart(directories: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Resolve effective autostart entries from directory observations.

    ``directories`` is in precedence order, most important first. Each item is
    ``{'path', 'scope' ('user'|'system'), 'collected': bool, 'files': [...]}``
    where each file is ``{'name', 'text': str|None, 'size': int|None,
    'error': str|None}``.
    """
    gaps: list[dict[str, Any]] = []
    seen: dict[str, list[dict[str, Any]]] = {}
    uncollected_before: dict[str, list[str]] = {}
    uncollected: list[str] = []
    total = 0
    truncated = False
    for rank, directory in enumerate(directories):
        dpath = str(directory.get('path') or '')
        scope = directory.get('scope') if directory.get('scope') in ('user', 'system') else 'system'
        if not directory.get('collected', False):
            uncollected.append(dpath)
            gaps.append(_gap('directory_not_collected', 'Autostart directory was not observed.', path=dpath))
            continue
        for item in directory.get('files') or ():
            name = str(item.get('name') or '')
            if not name.endswith('.desktop'):
                continue
            fpath = f'{dpath.rstrip("/")}/{name}'
            if not _NAME_RE.match(name):
                gaps.append(_gap('invalid_name', 'File name is not a usable desktop-file ID.', path=fpath))
                continue
            if total >= MAX_ENTRIES:
                truncated = True
                continue
            total += 1
            candidate = {'path': fpath, 'scope': scope, 'rank': rank, 'item': item}
            if name not in seen:
                uncollected_before[name] = list(uncollected)
            seen.setdefault(name, []).append(candidate)
    if truncated:
        gaps.append(_gap('entries_truncated', f'More than {MAX_ENTRIES} autostart files; the rest were not resolved.'))

    entries: list[dict[str, Any]] = []
    for name in sorted(seen):
        candidates = seen[name]
        winner = candidates[0]
        item = winner['item']
        entry_gaps: list[dict[str, Any]] = []
        for dpath in uncollected_before.get(name, []):
            entry_gaps.append(_gap('precedence_uncertain',
                                   'A more important autostart directory was not observed and could override this file.',
                                   path=dpath))
        text = item.get('text')
        size = item.get('size')
        record: dict[str, Any] = {
            'id': name,
            'path': winner['path'],
            'scope': winner['scope'],
            'overridden_by': None,
            'overrides': [c['path'] for c in candidates[1:]],
        }
        if item.get('error') or text is None:
            record.update({'status': 'unknown', 'reasons': ['File text was not readable.'], 'argv': None, 'program': None})
            entry_gaps.append(_gap('unreadable', str(item.get('error') or 'No text captured.'), path=winner['path']))
        elif (isinstance(size, int) and size > MAX_FILE_BYTES) or len(text.encode('utf-8', 'surrogatepass')) > MAX_FILE_BYTES:
            record.update({'status': 'unknown', 'reasons': ['File exceeds the size limit.'], 'argv': None, 'program': None})
            entry_gaps.append(_gap('file_too_large', f'File exceeds {MAX_FILE_BYTES} bytes and was not parsed.', path=winner['path']))
        else:
            parsed = parse_desktop_entry(text)
            status, reasons, details = _classify(winner['path'], parsed['keys'], parsed['has_group'])
            entry_gaps.extend(dict(g, path=winner['path']) for g in parsed['gaps'])
            entry_gaps.extend(dict(g, path=winner['path']) for g in details.pop('exec_gaps'))
            record.update({'status': status, 'reasons': reasons, **details})
        record['gaps'] = entry_gaps
        entries.append(record)
        for shadowed in candidates[1:]:
            entries.append({
                'id': name, 'path': shadowed['path'], 'scope': shadowed['scope'],
                'overridden_by': winner['path'], 'overrides': [], 'status': 'overridden',
                'reasons': [f"Shadowed by more important {winner['path']}."], 'argv': None, 'program': None,
                'gaps': [],
            })
    return {'contract_version': CONTRACT_VERSION, 'entries': entries, 'gaps': gaps}
