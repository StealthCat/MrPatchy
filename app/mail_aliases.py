"""Pure Postfix aliases(5) delivery contract (roadmap F slice, #1215).

When mail arrives for a local name, Postfix ``local(8)`` looks the name up in
``alias_maps`` and delivers to each target of the matching entry. A target of
the form ``"|command"`` runs a command and ``/path`` appends to a file. Both
happen without any login, so an alias entry is an event-driven execution
trigger. This module turns the captured text of one Postfix aliases source
file (normally ``/etc/aliases``) plus the database owner and the relevant
``main.cf`` values into the aliases, their targets, the user that command and
file deliveries run as, and whether ``local(8)`` permits them. It performs no
I/O, never runs ``postalias``, ``newaliases`` or a command and never
authorizes a response action.

The rules follow the Postfix 3.8.6 sources: ``util/readlline.c``,
``postalias/postalias.c``, ``global/tok822_parse.c``, ``local/alias.c`` and
``local/token.c``. The downloaded binaries could not be run in the authoring
sandbox, so there is no live differential.

- Logical lines (``readllines``): physical lines end at ``\\n``. A line that
  is empty, all whitespace, or whose first non-whitespace character is ``#``
  is dropped, including inside a continuation. A line starting with
  whitespace continues the previous logical line; one with no previous text
  is dropped with a warning.
- Each logical line is tokenized as RFC 822: ``(comments)`` nest,
  ``"quoted strings"`` and ``[domain literals]`` keep backslash escapes
  unescaped, ``|``, ``%``, ``!`` and the RFC 822 specials are single tokens and
  everything else forms atoms.
- The key is everything before the first ``:`` token. A line with no key, no
  value, a ``,`` before the colon or an ``@``/``%`` before the colon is
  skipped. Keys are folded to lowercase. With default ``postalias`` flags a
  duplicate key is ignored and the first value wins.
- ``local(8)`` classifies each comma-separated target by its unquoted form:
  ``/`` is a file, ``~`` a home-relative file, ``|`` a command,
  ``:include:`` (any case) an include file, anything else an address.
- Delivery rights (``local/alias.c``): when the alias database is owned by a
  trusted owner (root), commands and files run as ``default_privs``
  (default ``nobody``). Otherwise they run as the database owner. With an
  unknown owner, delivery is deferred.
- ``allow_mail_to_commands`` and ``allow_mail_to_files`` (default
  ``alias, forward``) must include ``alias`` or the delivery bounces as
  restricted.

Fail-closed rules: input that was not observed or is over the limits makes the
result incomplete. A target whose tokens fall outside the modeled subset (a
multi-word unquoted target, comments, group syntax or a complex key) is
``unresolved`` rather than guessed. ``:include:`` files are not followed and
are reported as gaps, because commands inside them run with
``allow_mail_to_commands`` ``include`` rights. ``origin`` is always
``not_assessed`` and no result is a safety verdict.

Not modeled: ``postalias -r``/``-w`` duplicate modes, other ``alias_maps``
tables, ``.forward`` files, ``owner-`` aliases, ``virtual(5)``, Exim and
Sendmail semantics, and collection, inventory, UI or AI wiring.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from itertools import pairwise
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('postfix-3.8.6',)
MAX_TEXT = 262144
MAX_ENTRIES = 4096
DEFAULT_PRIVS = 'nobody'
DEFAULT_ALLOW = 'alias, forward'

_SPECIALS = '()<>@,;:\\".[]'
_OPCHARS = '|%!' + _SPECIALS
_SPACE = ' \t\r\n'
_WORD = ('atom', 'qstring')
TARGET_KINDS = ('command', 'file', 'home_file', 'include', 'address')
ENTRY_STATUSES = ('active', 'duplicate_ignored', 'skipped', 'unresolved')


def logical_lines(text: str) -> list[str]:
    """Join physical lines the way ``readllines`` does."""
    out: list[str] = []
    current: str | None = None
    for line in text.split('\n'):
        stripped = line.lstrip(' \t\r\n\v\f')
        if not stripped or stripped.startswith('#'):
            continue
        if line[0] in ' \t\r\n\v\f':
            if current is None:
                continue  # continuation without preceding text: warned and dropped
            current += line
            continue
        if current is not None:
            out.append(current)
        current = line
    if current is not None:
        out.append(current)
    return out


def _collect(text: str, i: int, stop: str | None) -> tuple[str, int]:
    """``COLLECT``: unescape backslashes, map whitespace to space."""
    out: list[str] = []
    while i < len(text):
        ch = text[i]
        if ch == '\\':
            i += 1
            if i >= len(text):
                break
            ch = text[i]
        elif stop is not None and ch == stop or stop is None and (ch in _SPACE or ch in _OPCHARS):
            break
        out.append(' ' if ch in _SPACE else ch)
        i += 1
    return ''.join(out), i


def tokenize(text: str) -> list[tuple[str, str]]:
    """Return ``(type, value)`` tokens following ``tok822_scan``."""
    tokens: list[tuple[str, str]] = []
    i = 0
    while i < len(text):
        ch = text[i]
        i += 1
        if ch in _SPACE:
            continue
        if ch == '(':
            level, start = 1, i - 1
            while i < len(text):
                c = text[i]
                i += 1
                if c == '(':
                    level += 1
                elif c == ')':
                    level -= 1
                    if level == 0:
                        break
                elif c == '\\' and i < len(text):
                    i += 1
            tokens.append(('comment', text[start:i]))
        elif ch in '["':
            value, i = _collect(text, i, ']' if ch == '[' else '"')
            if i < len(text):
                i += 1
            tokens.append(('domlit' if ch == '[' else 'qstring', value))
        elif ch != '\\' and ch in _OPCHARS:
            tokens.append(('op', ch))
        else:
            value, i = _collect(text, i - 1, None)
            tokens.append(('atom', value))
    return tokens


def _classify(value: str) -> tuple[str, str]:
    if value.startswith('/'):
        return 'file', value
    if value.startswith('~'):
        return 'home_file', value
    if value.startswith('|'):
        return 'command', value[1:]
    if value[:9].lower() == ':include:':
        return 'include', value[9:]
    return 'address', value


def _target(tokens: list[tuple[str, str]]) -> dict[str, Any]:
    if not tokens:
        return {'status': 'unresolved', 'reason': 'empty_target'}
    if any(kind in ('comment', 'domlit') for kind, _ in tokens):
        return {'status': 'unresolved', 'reason': 'tokens_not_modeled'}
    for left, right in pairwise(tokens):
        if left[0] in _WORD and right[0] in _WORD:
            # tok822_parse may resynchronize adjacent words into several
            # addresses ("missing comma"); not modeled, so never guessed.
            return {'status': 'unresolved', 'reason': 'adjacent_words_not_modeled'}
    if any(kind == 'op' and value in '<>;' for kind, value in tokens):
        return {'status': 'unresolved', 'reason': 'tokens_not_modeled'}
    kind, value = _classify(''.join(value for _, value in tokens))
    return {'status': 'parsed', 'kind': kind, 'value': value}


def _allowed(setting: str) -> bool:
    words = {word.lower() for word in setting.replace(',', ' ').split()}
    return 'alias' in words


def resolve(source: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve aliases from ``{'path', 'observed', 'text', 'owner',
    'default_privs', 'allow_mail_to_commands', 'allow_mail_to_files'}``.

    ``owner`` is ``{'trusted': bool, 'user': str}`` for the database file, or
    ``None`` when unknown. Unset ``main.cf`` values take Postfix defaults.
    """
    path = str(source.get('path') or '/etc/aliases')
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract': 'mail_aliases', 'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS), 'path': path,
        'origin': 'not_assessed', 'verdict': None,
    }
    text = source.get('text')
    if not source.get('observed') or text is None:
        gaps.append({'reason': 'source_not_observed', 'path': path})
        return {**result, 'complete': False, 'gaps': gaps, 'entries': [], 'executions': []}
    raw = text.encode('utf-8', 'surrogatepass') if isinstance(text, str) else bytes(text)
    if len(raw) > MAX_TEXT:
        gaps.append({'reason': 'source_over_limit', 'path': path, 'limit': MAX_TEXT})
        return {**result, 'complete': False, 'gaps': gaps, 'entries': [], 'executions': []}
    result['sha256'] = hashlib.sha256(raw).hexdigest()
    decoded = raw.decode('utf-8', 'surrogateescape')
    owner = source.get('owner')
    privs = str(source.get('default_privs') or DEFAULT_PRIVS)
    if owner is None:
        run_as, delivery = None, 'deferred_owner_unknown'
    elif owner.get('trusted'):
        run_as, delivery = privs, 'default_privs'
    else:
        run_as, delivery = str(owner.get('user') or ''), 'database_owner'
        if not run_as:
            run_as, delivery = None, 'deferred_owner_unknown'
    allow = {
        'command': str(source.get('allow_mail_to_commands') or DEFAULT_ALLOW),
        'file': str(source.get('allow_mail_to_files') or DEFAULT_ALLOW),
    }
    entries: list[dict[str, Any]] = []
    executions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for number, line in enumerate(logical_lines(decoded), 1):
        if len(entries) >= MAX_ENTRIES:
            gaps.append({'reason': 'too_many_entries', 'limit': MAX_ENTRIES})
            break
        entry: dict[str, Any] = {'logical_line': number, 'origin': 'not_assessed'}
        entries.append(entry)
        tokens = tokenize(line)
        colon = next((i for i, (kind, value) in enumerate(tokens) if kind == 'op' and value == ':'), None)
        if colon is None or colon == 0 or colon == len(tokens) - 1:
            entry.update(status='skipped', reason='need_name_value_pair')
            continue
        key_tokens, value_tokens = tokens[:colon], tokens[colon + 1:]
        if any(kind == 'op' and value == ',' for kind, value in key_tokens):
            entry.update(status='skipped', reason='need_name_value_pair')
            continue
        if any(kind == 'op' and value in '@%' for kind, value in key_tokens):
            entry.update(status='skipped', reason='name_must_be_local')
            continue
        if len(key_tokens) != 1 or key_tokens[0][0] not in _WORD:
            entry.update(status='unresolved', reason='complex_key_not_modeled')
            gaps.append({'reason': 'complex_key_not_modeled', 'logical_line': number})
            continue
        name = key_tokens[0][1].lower()
        entry['name'] = name
        if name in seen:
            entry['status'] = 'duplicate_ignored'
            continue
        seen.add(name)
        groups: list[list[tuple[str, str]]] = [[]]
        for token in value_tokens:
            if token == ('op', ','):
                groups.append([])
            else:
                groups[-1].append(token)
        targets = [_target(group) for group in groups if group]
        entry['targets'] = targets
        entry['status'] = 'active'
        for target in targets:
            if target['status'] != 'parsed':
                entry['status'] = 'unresolved'
                gaps.append({'reason': target['reason'], 'name': name})
                continue
            kind = target['kind']
            if kind == 'include':
                target['followed'] = False
                gaps.append({'reason': 'include_not_followed', 'name': name, 'include': target['value']})
                continue
            if kind == 'address':
                continue
            rights_kind = 'command' if kind == 'command' else 'file'
            allowed = _allowed(allow[rights_kind])
            target.update(
                allowed=allowed,
                delivery_rights=delivery if allowed else 'restricted',
                run_as=run_as if allowed else None,
            )
            if allowed and run_as is not None:
                executions.append({'name': name, 'kind': kind, 'value': target['value'],
                                   'run_as': run_as, 'delivery_rights': delivery,
                                   'origin': 'not_assessed'})
    return {**result, 'complete': not gaps, 'gaps': gaps, 'entries': entries, 'executions': executions}
