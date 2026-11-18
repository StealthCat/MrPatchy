"""Pure incron table contract (roadmap F slice, #1132).

incrond runs a command whenever an inotify event fires on a path named in an
incron table. System tables run as root; per-user tables run as their user.
This module turns captured ``incron.conf`` text, table-directory listings,
table text, allow/deny list text and the set of known account names into the
entries incrond loads. It performs no I/O, never runs incrond, a shell or a
command, never expands a wildcard and never authorizes a response action.

The rules follow incron 0.5.12 (``incrontab.cpp``, ``strtok.cpp``,
``incroncfg.cpp``, ``icd-main.cpp``, ``usertable.cpp`` and ``usertable.h``):

- ``IncronCfg::Load`` reads ``/etc/incron.conf`` with ``getline(s, 1023)``. A
  line of 1023 bytes or more sets ``failbit`` and stops reading, so later
  lines are ignored. ``IsComment`` treats a line as a comment only when ``#``
  is preceded by nothing but spaces and tabs. ``ParseLine`` splits at the
  first ``=``, trims spaces and tabs from the key and spaces, tabs and ``=``
  from the start of the value. ``std::map::insert`` keeps the *first* value
  for a repeated key. Missing keys use the built-in defaults.
- ``load_tables`` reads ``system_table_dir`` and then ``user_table_dir``.
  An entry loads when ``d_type`` is ``DT_REG``; on ``DT_UNKNOWN`` it falls
  back to ``stat`` and loads a regular file, following symlinks. A
  ``DT_LNK`` entry is skipped. System tables whose names begin with ``.`` are
  skipped; user tables are not. An unopenable system directory is ignored;
  an unopenable user directory stops incrond at startup.
- A user table loads only when ``getpwnam`` finds the name and
  ``IncronTab::CheckUser`` allows it. If the allow file exists, only listed
  users are allowed. If it is missing (``ENOENT``), the deny file is
  consulted: a missing deny file allows everyone, otherwise listed users are
  refused. Any other ``fopen`` failure refuses. Lists are read in 99-byte
  ``fgets`` pieces and the first ``%s`` word of each piece is compared.
- ``IncronTab::Load`` reads tables in 999-byte ``fgets`` pieces, and each
  piece is parsed as its own line. There is no comment syntax: a line is an
  entry when ``IncronTabEntry::Parse`` finds three fields. Fields are split
  by ``StringTokenizer(" \\t", '\\\\')``. With two delimiters its escape
  tracking toggles twice per character, so ``\\ `` does not protect a space.
  The path has single backslashes removed (``\\\\`` becomes ``\\``); the
  command is the raw remainder with one trailing newline removed.
- A mask field starting with a decimal number (``%lu``) is used as the raw
  mask with default flags. Otherwise its comma-separated words are
  ``IN_*`` names, ``IN_NO_LOOP``, ``loopable=true``, ``recursive=false`` and
  ``dotdirs=true``; an unknown word contributes nothing.
- On an event, ``$$`` becomes ``$``, ``$@`` the watched path, ``$#`` the
  file name, ``$%`` the event names and ``$&`` the numeric mask; any other
  ``$x`` drops the ``$``. A system-table command runs through ``system()``,
  that is ``/bin/sh -c``, as root. A user-table command runs as the user via
  ``/bin/bash -c`` after ``setgid``, ``initgroups`` and ``setuid``; for a
  non-root user the environment is cleared and ``LOGNAME``, ``USER``,
  ``USERNAME``, ``HOME``, ``SHELL`` and ``PATH`` are set.
- Loop suppression is compiled only with ``LOOPER``, which 0.5.12 does not
  define, so ``loopable`` and ``IN_NO_LOOP`` have no runtime effect.

Fail-closed rules: an unobserved configuration, listing, stat type, table,
allow/deny state or account list, invalid UTF-8, NUL bytes and over-limit
input mark the result incomplete; affected tables are ``unresolved`` and are
never reported as not running. ``origin`` is always ``not_assessed`` and no
result is a safety verdict.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSION = '0.5.12'
CONFIG_PATH = '/etc/incron.conf'
DEFAULTS = {
    'system_table_dir': '/etc/incron.d', 'user_table_dir': '/var/spool/incron',
    'allowed_users': '/etc/incron.allow', 'denied_users': '/etc/incron.deny',
}
SYSTEM_SHELL = '/bin/sh'
USER_SHELL = '/bin/bash'
DEFAULT_PATH = '/usr/local/bin:/usr/bin:/bin:/usr/X11R6/bin'
CONFIG_LINE_MAX = 1022  # getline(s, 1023) stores at most 1022 bytes.
TABLE_CHUNK = 999       # fgets(s, 1000, f)
LIST_CHUNK = 99         # fgets(s, 100, f)
MAX_TEXT = 65536
MAX_ENTRIES = 1024
MAX_TABLE_ENTRIES = 512
MAX_GAPS = 64

MASKS = {
    'IN_ACCESS': 0x1, 'IN_MODIFY': 0x2, 'IN_ATTRIB': 0x4, 'IN_CLOSE_WRITE': 0x8, 'IN_CLOSE_NOWRITE': 0x10,
    'IN_OPEN': 0x20, 'IN_MOVED_FROM': 0x40, 'IN_MOVED_TO': 0x80, 'IN_CREATE': 0x100, 'IN_DELETE': 0x200,
    'IN_DELETE_SELF': 0x400, 'IN_UNMOUNT': 0x2000, 'IN_Q_OVERFLOW': 0x4000, 'IN_IGNORED': 0x8000,
    'IN_CLOSE': 0x18, 'IN_MOVE': 0xC0, 'IN_ISDIR': 0x40000000, 'IN_ONESHOT': 0x80000000,
    'IN_ALL_EVENTS': 0xFFF, 'IN_DONT_FOLLOW': 0x02000000, 'IN_ONLYDIR': 0x01000000, 'IN_MOVE_SELF': 0x800,
}
_EVENT_BITS = (
    ('IN_ACCESS', 0x1), ('IN_MODIFY', 0x2), ('IN_ATTRIB', 0x4), ('IN_CLOSE_WRITE', 0x8),
    ('IN_CLOSE_NOWRITE', 0x10), ('IN_OPEN', 0x20), ('IN_MOVED_FROM', 0x40), ('IN_MOVED_TO', 0x80),
    ('IN_CREATE', 0x100), ('IN_DELETE', 0x200), ('IN_DELETE_SELF', 0x400), ('IN_MOVE_SELF', 0x800),
)
# Kernel inotify_add_watch(): EINVAL unless the mask has at least one valid bit.
_VALID_BITS = 0xFFF | 0x2000 | 0x4000 | 0x8000 | 0x01000000 | 0x02000000 | 0x04000000 | 0x10000000 \
    | 0x20000000 | 0x40000000 | 0x80000000
_FLAG_WORDS = {'IN_NO_LOOP', 'loopable=true', 'recursive=false', 'dotdirs=true'}
_NUMBER = re.compile(r'[ \t\n\v\f\r]*([+-]?)([0-9]+)')
_LIST_WORD = re.compile(r'[ \t\n\v\f\r]*([^ \t\n\v\f\r]+)')

STATUSES = ('loads', 'rejected_mask', 'skipped_non_file', 'skipped_dotfile', 'user_unknown', 'user_refused',
            'unresolved')
BLOCKING = frozenset({
    'config_not_observed', 'config_over_limit', 'directory_not_observed', 'malformed_entry', 'entries_over_limit',
    'duplicate_entry', 'type_not_observed', 'text_not_observed', 'over_limit', 'invalid_utf8', 'binary',
    'accounts_not_observed', 'list_not_observed', 'table_entries_over_limit', 'gaps_truncated',
})
NOT_OBSERVED = (
    'Whether incron is installed, enabled and running, and whether incrond was started with -f to read a '
    'different configuration file.',
    'Which inotify events occur on watched paths, so which commands ever run.',
    'Which files a wildcard path or recursive watch expands to; incrond resolves both when it loads a table.',
    'Whether a user can access a watched path; incrond silently discards events on paths the user cannot reach.',
    'The contents of programs or scripts a command runs.',
)


def _gap(gaps: list[dict[str, Any]], code: str, name: str | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'name': name, 'detail': detail[:240], 'blocking': code in BLOCKING})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'name': None, 'detail': 'Further gaps were not recorded.',
                     'blocking': True})


def _text(value: Any, gaps: list[dict[str, Any]], name: str) -> str | None:
    """Return validated captured text, or ``None`` with a gap."""
    if value is None:
        _gap(gaps, 'text_not_observed', name, 'The text was not captured.')
        return None
    data = value.encode('utf-8', 'surrogateescape') if isinstance(value, str) else bytes(value)
    if len(data) > MAX_TEXT:
        _gap(gaps, 'over_limit', name, f'More than {MAX_TEXT} bytes.')
        return None
    if b'\0' in data:
        _gap(gaps, 'binary', name, 'The text contains NUL bytes.')
        return None
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', name, 'The text is not valid UTF-8.')
        return None


def _pieces(text: str, size: int) -> Iterable[str]:
    """Yield what successive ``fgets(buf, size + 1, fp)`` calls return (byte-accurate)."""
    data = text.encode('utf-8')
    start = 0
    while start < len(data):
        newline = data.find(b'\n', start, start + size)
        end = newline + 1 if newline >= 0 else min(start + size, len(data))
        yield data[start:end].decode('utf-8', 'surrogateescape')
        start = end


def parse_config(text: str) -> dict[str, Any]:
    """Apply ``IncronCfg::Load`` and ``ParseLine`` to ``incron.conf`` text."""
    values: dict[str, str] = {}
    notes: list[str] = []
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    for number, line in enumerate(lines, 1):
        if len(line.encode('utf-8')) > CONFIG_LINE_MAX:
            notes.append(f'Line {number} is longer than {CONFIG_LINE_MAX} bytes; incrond stops reading there.')
            break
        hash_at = line.find('#')
        if hash_at >= 0 and not line[:hash_at].strip(' \t'):
            continue
        if not line or line.startswith('='):
            continue
        key, sep, rest = line.partition('=')
        if not sep:
            continue
        key = key.strip(' \t')
        if not key:
            continue
        value = rest.lstrip(' \t=').rstrip(' \t')
        if key in values:
            notes.append(f'Line {number} repeats "{key[:40]}"; incrond keeps the first value.')
            continue
        values[key] = value
    effective = {key: values.get(key, default) for key, default in DEFAULTS.items()}
    return {'values': effective, 'notes': notes}


def build_path(directory: str, name: str) -> str:
    """``IncronCfg::BuildPath``: join without doubling a trailing slash."""
    return directory + name if directory.endswith('/') else directory + '/' + name


def _tokenize(line: str) -> tuple[str, str, str] | None:
    """Port of ``IncronTabEntry::Parse`` field splitting, including tokenizer quirks."""
    delims = ' \t'
    prefix = '\\'
    length = len(line)
    pos = 0

    def raw_token() -> str:
        nonlocal pos
        pref = 0
        for index in range(pos, length):
            char = line[index]
            # The C loop runs once per delimiter, so the prefix toggle runs twice per character.
            for delim in delims:
                if char == delim:
                    if pref == 0:
                        token = line[pos:index]
                        pos = index + 1
                        return token
                    pref = 0
                elif char == prefix:
                    pref = 0 if pref == 1 else 1
                else:
                    pref = 0
        token = line[pos:]
        pos = length
        return token

    def strip_prefix(value: str) -> str:
        out = []
        index = 0
        while index < len(value):
            if value[index] == prefix:
                if index < len(value) - 1 and value[index + 1] == prefix:
                    out.append(prefix)
                    index += 1
            else:
                out.append(value[index])
            index += 1
        return ''.join(out)

    def next_token() -> str:
        token = strip_prefix(raw_token())
        while not token and pos < length:
            token = strip_prefix(raw_token())
        return token

    if pos >= length:
        return None
    path = next_token()
    if pos >= length:
        return None
    mask = next_token()
    if pos >= length:
        return None
    command = line[pos:]
    if command.endswith('\n'):
        command = command[:-1]
    return path, mask, command


def parse_mask(field: str) -> dict[str, Any]:
    """Return the mask and flags ``IncronTabEntry::Parse`` derives from the mask field."""
    result: dict[str, Any] = {'mask': 0, 'recursive': True, 'dotdirs': False, 'loopable': False,
                              'numeric': False, 'unknown_words': []}
    match = _NUMBER.match(field)
    if match:
        value = int(match.group(2))
        value = min(value, 2 ** 64 - 1)
        if match.group(1) == '-':
            value = (-value) % 2 ** 64
        result.update(mask=value & 0xFFFFFFFF, numeric=True)
        return result
    for word in field.split(','):
        if word == 'IN_NO_LOOP':
            result['loopable'] = False
        elif word == 'loopable=true':
            result['loopable'] = True
        elif word == 'recursive=false':
            result['recursive'] = False
        elif word == 'dotdirs=true':
            result['dotdirs'] = True
        elif word in MASKS:
            result['mask'] |= MASKS[word]
        else:
            result['unknown_words'].append(word[:64])
    return result


def event_names(mask: int) -> list[str]:
    return [name for name, bit in _EVENT_BITS if mask & bit]


def parse_table(text: str) -> list[dict[str, Any]]:
    """Return every entry ``IncronTab::Load`` keeps from table text, in order."""
    entries = []
    for number, piece in enumerate(_pieces(text, TABLE_CHUNK), 1):
        fields = _tokenize(piece)
        if fields is None:
            continue
        path, mask_field, command = fields
        mask = parse_mask(mask_field)
        notes = []
        if mask['unknown_words']:
            notes.append('Unknown mask words contribute nothing: ' + ', '.join(mask['unknown_words'][:8]))
        if not path.startswith('/'):
            notes.append("A relative path is resolved against incrond's working directory, which is not observed.")
        if '*' in path:
            notes.append('A wildcard path is expanded to matching files when the table loads; it is not watched '
                         'itself.')
        if not command.strip():
            notes.append('The command is empty.')
        status = 'loads' if mask['mask'] & _VALID_BITS else 'rejected_mask'
        if status == 'rejected_mask':
            notes.append('inotify_add_watch rejects a mask with no valid bits, so this entry never runs.')
        elif not mask['mask'] & 0xFFF:
            notes.append('The mask selects no file events, so this entry never runs a command.')
        entries.append({
            'piece': number, 'path': path, 'mask_field': mask_field[:200], 'mask': mask['mask'],
            'events': event_names(mask['mask']), 'oneshot': bool(mask['mask'] & 0x80000000),
            'dont_follow': bool(mask['mask'] & 0x02000000), 'recursive': mask['recursive'],
            'dotdirs': mask['dotdirs'], 'loopable': mask['loopable'], 'loop_suppression_compiled': False,
            'command': command, 'command_sha256': hashlib.sha256(command.encode('utf-8', 'surrogateescape'))
            .hexdigest(), 'status': status, 'notes': notes,
        })
    return entries


def _list_words(text: str) -> list[str]:
    words = []
    for piece in _pieces(text, LIST_CHUNK):
        match = _LIST_WORD.match(piece)
        if match:
            words.append(match.group(1))
    return words


def check_user(user: str, allow: Mapping[str, Any] | None, deny: Mapping[str, Any] | None,
               gaps: list[dict[str, Any]]) -> bool | None:
    """Apply ``IncronTab::CheckUser``. Return ``None`` when an input is unobserved.

    ``allow`` and ``deny`` are ``{'state': 'present'|'missing'|'unreadable', 'text': str}``.
    """
    def state(value: Mapping[str, Any] | None, name: str) -> tuple[str | None, str | None]:
        if not isinstance(value, Mapping) or value.get('state') not in ('present', 'missing', 'unreadable'):
            _gap(gaps, 'list_not_observed', name, 'Whether the list exists was not captured.')
            return None, None
        if value['state'] != 'present':
            return value['state'], None
        text = _text(value.get('text'), gaps, name)
        return ('present', text) if text is not None else (None, None)

    allow_state, allow_text = state(allow, 'allowed_users')
    if allow_state is None:
        return None
    if allow_state == 'present':
        return user in _list_words(allow_text or '')
    if allow_state == 'unreadable':
        return False
    deny_state, deny_text = state(deny, 'denied_users')
    if deny_state is None:
        return None
    if deny_state == 'missing':
        return True
    if deny_state == 'unreadable':
        return False
    return user not in _list_words(deny_text or '')


def _listing(listing: Any, gaps: list[dict[str, Any]], name: str) -> list[dict[str, Any]] | None:
    if listing is None:
        _gap(gaps, 'directory_not_observed', name, 'The directory listing was not captured.')
        return None
    if not isinstance(listing, (list, tuple)):
        _gap(gaps, 'malformed_entry', name, 'The listing is not a list.')
        return None
    if len(listing) > MAX_ENTRIES:
        _gap(gaps, 'entries_over_limit', name, f'More than {MAX_ENTRIES} entries.')
        return None
    seen: set[str] = set()
    result = []
    for item in listing:
        entry_name = item.get('name') if isinstance(item, Mapping) else None
        if not isinstance(entry_name, str) or not entry_name or '/' in entry_name:
            _gap(gaps, 'malformed_entry', name, 'A listing entry has no valid name.')
            return None
        if entry_name in seen:
            _gap(gaps, 'duplicate_entry', entry_name, 'The name is listed twice.')
            return None
        seen.add(entry_name)
        result.append(item)
    return result


def _is_regular(item: Mapping[str, Any], gaps: list[dict[str, Any]]) -> bool | None:
    """``d_type == DT_REG``, or ``stat`` (following links) when ``d_type`` is ``DT_UNKNOWN``."""
    d_type = item.get('d_type')
    if d_type == 'unknown':
        stat_type = item.get('stat_type')
        if stat_type not in ('file', 'directory', 'other', 'missing'):
            _gap(gaps, 'type_not_observed', item['name'], 'd_type is DT_UNKNOWN and the stat type was not captured.')
            return None
        return stat_type == 'file'
    if d_type not in ('file', 'symlink', 'directory', 'other'):
        _gap(gaps, 'type_not_observed', item['name'], 'The directory entry type was not captured.')
        return None
    return d_type == 'file'


def resolve(config_text: str | None, system_listing: Any, user_listing: Any,
            tables: Mapping[str, Any] | None = None, accounts: Mapping[str, Mapping[str, Any]] | None = None,
            allow: Mapping[str, Any] | None = None, deny: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Resolve the tables incrond loads and the commands each one runs.

    ``config_text`` is ``incron.conf`` text, ``''`` when the file is missing, or ``None`` when not observed.
    Listings are ``None`` (not observed), ``'unopenable'`` or lists of ``{'name', 'd_type', 'stat_type'}``
    where ``d_type`` is ``file``, ``symlink``, ``directory``, ``other`` or ``unknown``. ``tables`` maps the
    full table path to its text. ``accounts`` maps user names to ``{'uid': int}``.
    """
    gaps: list[dict[str, Any]] = []
    tables = tables or {}
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_version': SOURCE_VERSION, 'config_path': CONFIG_PATH,
        'config': None, 'starts': None, 'tables': [], 'commands': [], 'gaps': gaps, 'complete': False,
        'origin': 'not_assessed', 'not_observed': list(NOT_OBSERVED), 'notes': [],
    }
    config_value = _text(config_text, gaps, CONFIG_PATH) if config_text is not None else None
    if config_text is None:
        _gap(gaps, 'config_not_observed', CONFIG_PATH, 'The configuration was not captured.')
    if config_value is None:
        return result
    config = parse_config(config_value)
    result['config'] = config['values']
    result['notes'].extend(config['notes'])
    values = config['values']

    def load(kind: str, listing: Any) -> None:
        directory = values[f'{kind}_table_dir']
        if listing == 'unopenable':
            if kind == 'system':
                result['notes'].append('The system table directory cannot be opened; incrond ignores it.')
            else:
                result['starts'] = False
                result['notes'].append('The user table directory cannot be opened; incrond exits at startup.')
            return
        items = _listing(listing, gaps, directory)
        if items is None:
            return
        for item in items:
            name = item['name']
            path = build_path(directory, name)
            record: dict[str, Any] = {'kind': kind, 'name': name, 'path': path, 'user': None,
                                      'runs_as': None, 'shell': None, 'status': 'unresolved', 'entries': []}
            regular = _is_regular(item, gaps)
            if regular is None:
                result['tables'].append(record)
                continue
            if not regular:
                if name not in ('.', '..'):
                    record['status'] = 'skipped_non_file'
                    result['tables'].append(record)
                continue
            if kind == 'system':
                if name.startswith('.'):
                    record['status'] = 'skipped_dotfile'
                    result['tables'].append(record)
                    continue
                record.update(user='root', runs_as='root', shell=SYSTEM_SHELL)
            else:
                record['user'] = name
                if accounts is None:
                    _gap(gaps, 'accounts_not_observed', name, 'The account list was not captured.')
                    result['tables'].append(record)
                    continue
                if name not in accounts:
                    record['status'] = 'user_unknown'
                    result['tables'].append(record)
                    continue
                allowed = check_user(name, allow, deny, gaps)
                if allowed is None:
                    result['tables'].append(record)
                    continue
                if not allowed:
                    record['status'] = 'user_refused'
                    result['tables'].append(record)
                    continue
                uid = accounts[name].get('uid') if isinstance(accounts[name], Mapping) else None
                record.update(runs_as=name, shell=USER_SHELL, uid=uid,
                              environment='inherited' if uid == 0 else 'reset')
            text = _text(tables.get(path), gaps, path)
            if text is None:
                result['tables'].append(record)
                continue
            entries = parse_table(text)
            if len(entries) > MAX_TABLE_ENTRIES:
                _gap(gaps, 'table_entries_over_limit', path, f'More than {MAX_TABLE_ENTRIES} entries.')
                result['tables'].append(record)
                continue
            record.update(status='loads', entries=entries,
                          sha256=hashlib.sha256(text.encode('utf-8')).hexdigest())
            result['tables'].append(record)
            for entry in entries:
                if entry['status'] == 'loads' and entry['events']:
                    result['commands'].append({
                        'table': path, 'kind': kind, 'runs_as': record['runs_as'], 'shell': record['shell'],
                        'path': entry['path'], 'events': entry['events'], 'command': entry['command'],
                        'command_sha256': entry['command_sha256'],
                    })

    load('system', system_listing)
    load('user', user_listing)
    if result['starts'] is None and user_listing is not None and not any(
            gap['blocking'] and gap['name'] == values['user_table_dir'] for gap in gaps):
        result['starts'] = True
    result['complete'] = not any(gap['blocking'] for gap in gaps)
    return result
