"""Pure Postfix ``~/.forward`` command contract (roadmap F slice, #1489).

Takes the Postfix installation state, ``postconf`` values, passwd entries and
metadata plus text for each user's ``.forward*`` home entries. It says which
``|command`` destinations Postfix ``local(8)`` runs on mail to that user, for
which recipient address, as which account, and where coverage is missing. It
never runs anything, never reads a command's program and never authorizes a
response action.

Semantics come from the Postfix source (``src/local/dotforward.c``,
``token.c``, ``command.c``, ``local.c``, ``local_expand.c`` and
``src/global/mail_params.h``), not from recollection:

* ``forward_path`` defaults to
  ``$home/.forward${recipient_delimiter}${extension}, $home/.forward``. An entry
  whose expansion uses an undefined macro is skipped, and ``${extension}`` is
  undefined without an address extension. ``${recipient_delimiter}`` expands to
  the delimiter character actually used in the address. The first entry that
  ``lstat_as`` finds, as the recipient, is chosen and the search stops there,
  even when the chosen file is then refused.
* The chosen file is used only when ``S_ISREG`` holds for that ``lstat`` (a
  symlink is refused), it is owned by root or the recipient, and it is not
  world-writable. Otherwise it is ignored with a warning, and no other
  ``forward_path`` entry is tried.
* ``deliver_token_stream`` skips lines beginning with ``#`` and parses each
  other line with the RFC 822 tokenizer. A destination beginning with ``|`` is
  a command. It is refused unless ``allow_mail_to_commands`` contains
  ``forward`` (the default is ``alias, forward``). Commands in ``:include:``
  files need ``include``.
* ``deliver_dotforward`` sets the recipient's rights. ``deliver_command`` then
  replaces uid 0 or gid 0 with ``default_privs`` (default ``nobody``), so a
  root ``.forward`` command runs unprivileged. ``local_command_shell``, when
  set, is the shell used to run the command.
* ``deliver_recipient`` (``recipient.c``) case-folds the recipient before
  ``split_addr`` separates the user from the extension at the first
  ``recipient_delimiter`` character. A passwd name with ASCII upper case is
  never looked up, a username containing a delimiter character is always
  split, and an extension file name with ASCII upper case is never chosen.
  Non-ASCII names and extensions (SMTPUTF8 Unicode folding) and delimiters
  with upper case are blocking gaps.

A conservative tokenizer handles quoted strings, bare atoms, dots and commas.
Comments, route addresses, group syntax, backslashes and unbalanced quotes are
reported as blocking gaps instead of guessed. A non-default ``forward_path``,
``line_length_limit`` or ``local_transport``, unobserved inputs, missing
metadata or text, an unresolved default account, ``:include:`` files whose
commands would be allowed and over-limit input are blocking gaps too.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'postfix': 'Postfix src/local/dotforward.c, token.c, command.c, local.c, local_expand.c and '
               'src/global/mail_params.h',
}
DEFAULT_FORWARD_PATH = ('$home/.forward${recipient_delimiter}${extension}', '$home/.forward')
PLAIN_FORWARD_PATH = ('$home/.forward',)
DEFAULT_ALLOW_COMMANDS = 'alias, forward'
COMMAND_CLASSES = frozenset({'alias', 'forward', 'include'})
DEFAULT_LINE_LIMIT = 2048
DEFAULT_DEFAULT_PRIVS = 'nobody'
REQUIRED_PARAMETERS = ('forward_path', 'allow_mail_to_commands', 'recipient_delimiter', 'default_privs',
                       'local_command_shell', 'local_transport', 'line_length_limit')
FILE_PREFIX = '.forward'
MAX_USERS = 4096
MAX_ENTRIES = 64
MAX_FILE_BYTES = 1 << 20
MAX_GAPS = 64
_SPECIALS = set('()<>;:\\[]@')
_SPLIT = re.compile(r'[,\s]+')
BLOCKING = frozenset({
    'input_malformed', 'postfix_not_observed', 'config_not_observed', 'nondefault_forward_path',
    'nondefault_line_limit', 'nondefault_local_transport', 'unknown_command_class', 'default_privs_unresolved',
    'users_not_observed', 'too_many_users', 'home_not_observed', 'home_unreadable', 'too_many_entries',
    'metadata_missing', 'content_not_observed', 'content_malformed', 'file_too_large', 'line_too_long', 'line_unparsed',
    'include_not_resolved', 'casefold_not_modeled', 'gaps_truncated',
})
UNOBSERVED = (
    'Command programs and scripts are not read, so what a command does is not assessed.',
    ('Whether mail actually reaches a user through local(8) (aliases, virtual maps, mailbox_transport, '
     'fallback_transport and relay rules) is not predicted; commands are reported as they would run if it does.'),
    'lstat and open are done as the recipient; home directory search permissions are assumed to allow it.',
    'Address destinations other than commands are counted but not followed to other users.',
)
NOT_A_VERDICT = 'Configuration and file metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'read': 'local(8) reads this file as the recipient and delivers to each destination in it.',
    'not_regular': 'Not a regular file (lstat, so symlinks too); local(8) ignores it and tries no other '
                   'forward_path entry.',
    'bad_owner': 'Owned by neither root nor the recipient; local(8) ignores it and tries no other entry.',
    'world_writable': 'World-writable; local(8) ignores it and tries no other entry.',
    'unresolved': 'Required metadata or text was not supplied, so the outcome is not determined.',
}


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


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def parse_line(line: str) -> list[str] | None:
    """Return the destinations on one ``.forward`` line, or None when unsupported.

    Supports comma-separated destinations that are either one bare atom (dots
    and ``@`` included) or one whole double-quoted string, which covers ``"|command args"``,
    ``|/path/prog``, ``/file``, ``~/file``, ``user`` and ``user@domain``
    forms. Words joined only by whitespace, and anything else needing the
    full RFC 822 grammar, return None.
    """
    if line.startswith(':include:'):
        rest = line[len(':include:'):].strip()
        if not rest or any(c in rest for c in '",\\()<>') or any(c.isspace() for c in rest):
            return None
        return [':include:' + rest]
    dests: list[str] = []
    current: list[str] = []
    joined_by_space = False
    index = 0
    pending_space = False

    quoted = False

    def finish() -> bool:
        nonlocal current, joined_by_space, quoted
        if current:
            # Adjacent words, or a quoted string glued to other tokens, need tok822 internalization.
            if joined_by_space or (quoted and len(current) > 1):
                return False
            dests.append(''.join(current))
        current = []
        joined_by_space = quoted = False
        return True

    while index < len(line):
        char = line[index]
        if char == ',':
            if not finish():
                return None
            pending_space = False
            index += 1
        elif char.isspace():
            pending_space = bool(current)
            index += 1
        elif char == '"':
            end = line.find('"', index + 1)
            if end < 0 or '\\' in line[index + 1:end]:
                return None
            if pending_space:
                joined_by_space = True
            current.append(line[index + 1:end])
            quoted = True
            pending_space = False
            index = end + 1
        elif char in _SPECIALS and char != '@':
            return None
        else:
            end = index
            while end < len(line) and not line[end].isspace() and line[end] not in ',"' and \
                    (line[end] not in _SPECIALS or line[end] == '@'):
                end += 1
            if end < len(line) and line[end] in _SPECIALS and line[end] != '@':
                return None
            if pending_space:
                joined_by_space = True
            current.append(line[index:end])
            pending_space = False
            index = end
    if not finish():
        return None
    return dests


def _forward_path(value: str) -> tuple[str, ...] | None:
    items = tuple(item for item in _SPLIT.split(value.strip()) if item)
    if items in (DEFAULT_FORWARD_PATH, PLAIN_FORWARD_PATH):
        return items
    return None


def _command_classes(value: str, gaps: list[dict[str, Any]]) -> set[str] | None:
    names = {item for item in _SPLIT.split(value.strip()) if item}
    unknown = sorted(names - COMMAND_CLASSES)
    if unknown:
        _gap(gaps, 'unknown_command_class', detail='allow_mail_to_commands has ' + ', '.join(unknown))
        return None
    return names


def _users(users: Any, gaps: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    if users is None:
        _gap(gaps, 'users_not_observed')
        return None
    if not isinstance(users, list):
        _gap(gaps, 'input_malformed', detail='users must be a list')
        return None
    if len(users) > MAX_USERS:
        _gap(gaps, 'too_many_users', detail=f'More than {MAX_USERS} passwd entries.')
        return None
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for user in users:
        if not isinstance(user, dict) or not isinstance(user.get('name'), str) or not user['name'] or \
                _int(user.get('uid')) is None or _int(user.get('gid')) is None or \
                not isinstance(user.get('home'), str) or not user['home'].startswith('/'):
            _gap(gaps, 'input_malformed', detail='each user needs name, uid, gid and an absolute home')
            return None
        if user['name'] in seen:  # getpwnam returns the first entry with a name
            continue
        seen.add(user['name'])
        out.append(user)
    return out


def _home_join(home: str, name: str) -> str:
    return home.rstrip('/') + '/' + name


def _file_outcome(entry: dict[str, Any], uid: int) -> str:
    kind, owner, mode = entry.get('type'), _int(entry.get('uid')), _int(entry.get('mode'))
    if not isinstance(kind, str) or owner is None or mode is None:
        return 'unresolved'
    if kind != 'file':
        return 'not_regular'
    if owner not in (0, uid):
        return 'bad_owner'
    if mode & 0o002:
        return 'world_writable'
    return 'read'


def _destinations(entry: dict[str, Any], path: str, run_as: dict[str, Any] | None, classes: set[str],
                  line_limit: int, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    text = entry.get('content')
    if not isinstance(text, str):
        _gap(gaps, 'content_not_observed', path)
        return None
    try:
        data = text.encode('utf-8', 'surrogateescape')
    except UnicodeEncodeError:  # A lone surrogate that is not a surrogateescape byte.
        _gap(gaps, 'content_malformed', path, 'The captured text is not valid UTF-8 or surrogateescape bytes.')
        return None
    if len(data) > MAX_FILE_BYTES:
        _gap(gaps, 'file_too_large', path)
        return None
    found: dict[str, Any] = {'commands': [], 'files': [], 'includes': [], 'addresses': 0, 'complete': True}
    for number, raw in enumerate(data.split(b'\n'), start=1):
        if len(raw) + 1 > line_limit:
            _gap(gaps, 'line_too_long', path, f'Line {number} exceeds line_length_limit, so Postfix splits it.')
            found['complete'] = False
            continue
        if raw.startswith(b'#'):
            continue
        line = raw.decode('utf-8', 'surrogateescape').strip()
        if not line:
            continue
        dests = parse_line(line)
        if dests is None:
            _gap(gaps, 'line_unparsed', path, f'Line {number} needs the full RFC 822 tokenizer.')
            found['complete'] = False
            continue
        for dest in dests:
            if dest.startswith('|'):
                found['commands'].append({'line': number, 'command': dest[1:], 'allowed': 'forward' in classes,
                                          'run_as': run_as})
            elif dest.startswith(('/', '~')):
                found['files'].append({'line': number, 'path': dest})
            elif dest[:9].lower() == ':include:':
                found['includes'].append({'line': number, 'path': dest[9:],
                                          'commands_allowed': 'include' in classes})
                if 'include' in classes:
                    _gap(gaps, 'include_not_resolved', path, f'Line {number} includes {dest[9:]}.')
                    found['complete'] = False
            else:
                found['addresses'] += 1
    return found


def assess(postfix_installed: Any = None, postconf: Any = None, users: Any = None, homes: Any = None) -> dict[str, Any]:
    """Resolve which ``.forward`` commands local(8) runs, as whom, for which recipient."""
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'postfix': 'not_observed',
        'commands_allowed': None, 'include_commands_allowed': None, 'default_privs': None,
        'command_shell': None, 'recipient_delimiter': None, 'users': [], 'unreachable_users': [], 'commands': [],
        'gaps': gaps, 'unobserved': list(UNOBSERVED), 'not_a_verdict': NOT_A_VERDICT,
    }
    if postfix_installed is False:
        result['postfix'] = 'absent'
        return _finish(result)
    if postfix_installed is not True:
        _gap(gaps, 'postfix_not_observed')
        return _finish(result)
    result['postfix'] = 'installed'
    if not isinstance(postconf, dict) or any(not isinstance(postconf.get(k), str) for k in REQUIRED_PARAMETERS):
        missing = [k for k in REQUIRED_PARAMETERS if not isinstance(postconf, dict) or
                   not isinstance(postconf.get(k), str)]
        _gap(gaps, 'config_not_observed', detail='Missing postconf values: ' + ', '.join(missing))
        return _finish(result)
    forward_path = _forward_path(postconf['forward_path'])
    if forward_path is None:
        _gap(gaps, 'nondefault_forward_path', detail=postconf['forward_path'][:200])
    if postconf['line_length_limit'].strip() != str(DEFAULT_LINE_LIMIT):
        _gap(gaps, 'nondefault_line_limit', detail=postconf['line_length_limit'][:40])
    transport = postconf['local_transport'].strip()
    if transport.split(':', 1)[0] != 'local':
        _gap(gaps, 'nondefault_local_transport', detail=transport[:200])
    classes = _command_classes(postconf['allow_mail_to_commands'], gaps)
    delimiter = postconf['recipient_delimiter'].strip()
    shell = postconf['local_command_shell'].strip()
    result.update(recipient_delimiter=delimiter, command_shell=shell or None)
    if not delimiter.isascii() or delimiter != delimiter.lower():
        _gap(gaps, 'casefold_not_modeled', detail='recipient_delimiter has upper-case or non-ASCII characters')
    if classes is not None:
        result.update(commands_allowed='forward' in classes, include_commands_allowed='include' in classes)
    passwd = _users(users, gaps)
    if forward_path is None or classes is None or passwd is None:
        return _finish(result)
    privs_name = postconf['default_privs'].strip()
    privs = next((u for u in passwd if u['name'] == privs_name), None)
    if privs is None or privs['uid'] == 0 or privs['gid'] == 0:
        _gap(gaps, 'default_privs_unresolved', detail=f'default_privs = {privs_name[:64]}')
        privs = None
    else:
        result['default_privs'] = {'user': privs['name'], 'uid': privs['uid'], 'gid': privs['gid']}
    if not isinstance(homes, dict):
        _gap(gaps, 'home_not_observed', detail='No home listings were supplied.')
        return _finish(result)
    for user in passwd:
        _user(user, homes.get(user['name']), forward_path, delimiter, privs, classes, gaps, result)
    return _finish(result)


def _run_as(user: dict[str, Any], privs: dict[str, Any] | None) -> dict[str, Any] | None:
    uid, gid = user['uid'], user['gid']
    if uid == 0 or gid == 0:
        if privs is None:
            return None
        return {'user': privs['name'] if uid == 0 else user['name'], 'uid': privs['uid'] if uid == 0 else uid,
                'gid': privs['gid'] if gid == 0 else gid, 'default_privs': True}
    return {'user': user['name'], 'uid': uid, 'gid': gid, 'default_privs': False}


def _user(user: dict[str, Any], listing: Any, forward_path: tuple[str, ...], delimiter: str,
          privs: dict[str, Any] | None, classes: set[str], gaps: list[dict[str, Any]],
          result: dict[str, Any]) -> None:
    home = user['home']
    name = user['name']
    if not name.isascii():
        _gap(gaps, 'casefold_not_modeled', home, 'Non-ASCII username; SMTPUTF8 case folding is not modelled.')
        return
    if name != name.lower():
        result['unreachable_users'].append({'user': name, 'reason': 'local(8) case-folds the recipient, so this '
                                            'upper-case passwd name is never looked up and its .forward is unused.'})
        return
    if delimiter and any(c in delimiter for c in name):
        result['unreachable_users'].append({'user': name, 'reason': 'local(8) splits the recipient at the first '
                                            'recipient_delimiter character, so this username is never looked up.'})
        return
    if listing is None:
        _gap(gaps, 'home_not_observed', home, f'No .forward listing for {user["name"]}.')
        return
    if not isinstance(listing, dict) or listing.get('state') not in ('listed', 'absent', 'unreadable'):
        _gap(gaps, 'input_malformed', home, 'home listing state must be listed, absent or unreadable')
        return
    if listing['state'] == 'absent':
        return
    if listing['state'] == 'unreadable':
        _gap(gaps, 'home_unreadable', home)
        return
    entries = listing.get('entries')
    if not isinstance(entries, list):
        _gap(gaps, 'input_malformed', home, 'listed home needs entries')
        return
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', home)
        return
    by_name: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or \
                not entry['name'].startswith(FILE_PREFIX) or '/' in entry['name']:
            _gap(gaps, 'input_malformed', home, 'entries need a .forward* name')
            return
        by_name[entry['name']] = entry
    run_as = _run_as(user, privs)
    selections: list[dict[str, Any]] = []
    # Recipient "user" (no extension): the extension entry is undefined, so $home/.forward is used.
    if FILE_PREFIX in by_name:
        selections.append(_select(user, 'user', by_name[FILE_PREFIX], run_as, classes, gaps))
    # Recipient "user<d>ext": with the default path, .forward<d>ext is chosen first when it exists.
    if len(forward_path) == 2 and delimiter:
        for entry_name in sorted(by_name):
            suffix = entry_name[len(FILE_PREFIX):]
            if len(suffix) < 2 or suffix[0] not in delimiter:
                continue
            if not suffix.isascii():
                _gap(gaps, 'casefold_not_modeled', _home_join(home, entry_name),
                     'Non-ASCII extension; SMTPUTF8 case folding is not modelled.')
            elif suffix == suffix.lower():
                selections.append(_select(user, 'extension', by_name[entry_name], run_as, classes, gaps,
                                          extension=suffix[1:], delim=suffix[0]))
    if selections:
        result['users'].append({'user': user['name'], 'uid': user['uid'], 'home': home,
                                'run_as': run_as, 'selections': selections})
        for selection in selections:
            for command in selection.get('commands', []):
                result['commands'].append(dict(command, user=user['name'], recipient=selection['recipient'],
                                               path=selection['path'], shell=result['command_shell']))


def _select(user: dict[str, Any], kind: str, entry: dict[str, Any], run_as: dict[str, Any] | None,
            classes: set[str], gaps: list[dict[str, Any]], extension: str = '', delim: str = '') -> dict[str, Any]:
    path = _home_join(user['home'], entry['name'])
    recipient = user['name'] if kind == 'user' else f'{user["name"]}{delim}{extension}'
    outcome = _file_outcome(entry, user['uid'])
    selection: dict[str, Any] = {'recipient': recipient, 'path': path, 'outcome': outcome}
    if kind == 'extension':
        selection['extension'] = extension
        selection['fallback'] = ('Chosen before $home/.forward because it exists; if it is refused, '
                                 '$home/.forward is not tried for this recipient.')
    if outcome == 'unresolved':
        _gap(gaps, 'metadata_missing', path)
    elif outcome == 'read':
        if run_as is None:
            _gap(gaps, 'default_privs_unresolved', path, 'Commands for a root recipient run as default_privs.')
        found = _destinations(entry, path, run_as, classes, int(DEFAULT_LINE_LIMIT), gaps)
        if found is None:
            selection['outcome'] = 'unresolved'
        else:
            selection.update(found)
    selection['reason'] = REASONS[selection['outcome']]
    return selection


def _finish(result: dict[str, Any]) -> dict[str, Any]:
    codes = {gap['code'] for gap in result['gaps']}
    result['blocking'] = sorted(codes & BLOCKING)
    result['complete'] = not result['blocking']
    return result
