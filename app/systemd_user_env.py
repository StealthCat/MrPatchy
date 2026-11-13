"""Pure parsers for per-user systemd manager inputs (roadmap F slice, #702).

``systemd_units.resolve_user`` needs, for one account, the user manager's home,
``$XDG_RUNTIME_DIR`` and any non-default XDG base directories. This module turns
two captured, read-only observations into exactly those inputs:

* ``parse_manager_environment(text)`` parses the output of
  ``systemctl --user show-environment`` (plain ``KEY=value`` lines and the
  ``KEY=$'...'`` C-style quoting systemd uses for values that need it);
* ``parse_linger(names)`` validates a ``/var/lib/systemd/linger`` directory
  listing into the accounts whose user manager starts at boot.

It performs no I/O, never runs ``systemctl`` and never authorizes a response
action. Only the documented keys are kept; every other variable is dropped
without being echoed, because a user environment can carry secrets. Nothing
is guessed: a malformed line, invalid name, unsupported escape, duplicate key,
NUL/newline in a value or over-cap input becomes an explicit coverage gap and
the affected key is omitted, so ``resolve_user`` applies its own validation or
documented defaults and reports the result as incomplete.

Limitation: systemd releases that predate quoting print values raw. A raw value
that itself begins with ``$'`` is indistinguishable from a quoted one and is
decoded as quoted (or reported as a gap when it does not decode).
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

CONTRACT_VERSION = 1
MAX_ENV_BYTES = 64 * 1024
MAX_ENV_LINES = 1024
MAX_LINGER_ENTRIES = 4096

# Environment variable -> resolve_user()/user_search_paths() input name.
ENV_KEYS = {
    'HOME': 'home',
    'XDG_RUNTIME_DIR': 'runtime_dir',
    'XDG_CONFIG_HOME': 'config_home',
    'XDG_DATA_HOME': 'data_home',
    'XDG_CACHE_HOME': 'cache_home',
    'XDG_CONFIG_DIRS': 'config_dirs',
    'XDG_DATA_DIRS': 'data_dirs',
}
_XDG_OUTPUTS = ('config_home', 'data_home', 'cache_home', 'config_dirs', 'data_dirs')

_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
_ACCOUNT_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}\Z')
_SIMPLE_ESCAPES = {
    'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v',
    '\\': '\\', "'": "'", '"': '"', '?': '?',
}


def _gap(code: str, detail: str = '') -> dict[str, str]:
    return {'code': code, 'detail': detail}


def _decode_quoted(body: str) -> str | None:
    """Decode the inside of ``$'...'``; None when anything is unsupported."""
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "'":
            return None  # unescaped quote inside the quoted body
        if ch != '\\':
            out += ch.encode('utf-8', 'surrogatepass')
            i += 1
            continue
        nxt = body[i + 1:i + 2]
        if nxt and nxt in _SIMPLE_ESCAPES:
            out += _SIMPLE_ESCAPES[nxt].encode()
            i += 2
        elif nxt == 'x' and re.fullmatch(r'[0-9A-Fa-f]{2}', body[i + 2:i + 4]):
            out.append(int(body[i + 2:i + 4], 16))
            i += 4
        elif re.fullmatch(r'[0-3][0-7]{2}', body[i + 1:i + 4]):
            out.append(int(body[i + 1:i + 4], 8))
            i += 4
        else:
            return None
    try:  # escaped bytes may form UTF-8 sequences; reject anything that does not decode
        return out.decode('utf-8')
    except UnicodeDecodeError:
        return None


def _decode_value(raw: str) -> str | None:
    if raw.startswith("$'"):
        if len(raw) < 3 or not raw.endswith("'"):
            return None
        return _decode_quoted(raw[2:-1])
    return raw


def parse_manager_environment(text: Any) -> dict[str, Any]:
    """Parse ``systemctl --user show-environment`` output for ``resolve_user``.

    Returns ``{'contract_version', 'home', 'runtime_dir', 'xdg', 'gaps',
    'complete'}``. ``home``/``runtime_dir`` are None when absent or rejected;
    ``xdg`` holds only the keys that were present, non-empty and decoded
    exactly (an empty XDG value means "unset" in the XDG Base Directory spec).
    Values are not path-validated here; ``resolve_user`` does that and reports
    invalid paths as its own gaps.
    """
    gaps: list[dict[str, str]] = []
    found: dict[str, str] = {}
    rejected: set[str] = set()
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'home': None,
                              'runtime_dir': None, 'xdg': {}, 'gaps': gaps}
    if not isinstance(text, str):
        gaps.append(_gap('env_not_collected'))
        result['complete'] = False
        return result
    if len(text.encode('utf-8', 'surrogatepass')) > MAX_ENV_BYTES:
        gaps.append(_gap('env_too_large', str(MAX_ENV_BYTES)))
        result['complete'] = False
        return result
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    if len(lines) > MAX_ENV_LINES:
        gaps.append(_gap('env_too_many_lines', str(MAX_ENV_LINES)))
        result['complete'] = False
        return result
    for number, line in enumerate(lines, 1):
        name, sep, raw = line.partition('=')
        if not sep or not _NAME_RE.match(name):
            # Never echo the line: it may hold another variable's secret value.
            gaps.append(_gap('env_line_malformed', f'line {number}'))
            continue
        if '\x00' in line:
            gaps.append(_gap('env_value_invalid', name))
            rejected.add(name)
            continue
        if name not in ENV_KEYS:
            continue
        if name in found or name in rejected:
            gaps.append(_gap('env_duplicate_key', name))
            found.pop(name, None)
            rejected.add(name)
            continue
        value = _decode_value(raw)
        if value is None:
            gaps.append(_gap('env_value_undecodable', name))
            rejected.add(name)
            continue
        if '\x00' in value or '\n' in value or '\r' in value:
            gaps.append(_gap('env_value_invalid', name))
            rejected.add(name)
            continue
        found[name] = value
    for name, value in found.items():
        key = ENV_KEYS[name]
        if key in ('home', 'runtime_dir'):
            result[key] = value or None
        elif value:
            result['xdg'][key] = value
    if result['home'] is None:
        gaps.append(_gap('env_home_missing'))
    if result['runtime_dir'] is None:
        gaps.append(_gap('env_runtime_dir_missing'))
    result['xdg'] = {k: result['xdg'][k] for k in _XDG_OUTPUTS if k in result['xdg']}
    result['complete'] = not gaps
    return result


def _valid_account(name: str) -> bool:
    return bool(_ACCOUNT_RE.match(name)) and not name.isdigit()


def parse_linger(names: Any) -> dict[str, Any]:
    """Validate a ``/var/lib/systemd/linger`` listing.

    ``names`` is the captured list of directory entry names (``None`` when the
    directory was not collected). An absent directory should be passed as an
    empty list, which means "no lingering accounts". Invalid or over-cap entries
    are gaps and are never accepted as accounts.
    """
    gaps: list[dict[str, str]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'accounts': [], 'gaps': gaps}
    if names is None or isinstance(names, (str, bytes)) or not isinstance(names, Iterable):
        gaps.append(_gap('linger_not_collected'))
        result['complete'] = False
        return result
    accounts: set[str] = set()
    for index, entry in enumerate(names):
        if index >= MAX_LINGER_ENTRIES:
            gaps.append(_gap('linger_too_many_entries', str(MAX_LINGER_ENTRIES)))
            break
        if not isinstance(entry, str) or not _valid_account(entry):
            gaps.append(_gap('linger_entry_invalid', f'entry {index + 1}'))
            continue
        accounts.add(entry)
    result['accounts'] = sorted(accounts)
    result['complete'] = not gaps
    return result
