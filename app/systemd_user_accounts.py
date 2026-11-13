"""Pure account enumeration for per-user systemd managers (roadmap F slice, #702).

``systemd_units.resolve_user`` resolves one account's ``systemd --user`` units.
This module decides which accounts to resolve, from three captured read-only
observations:

* ``parse_login_defs(text)`` reads ``UID_MIN``/``UID_MAX`` from
  ``/etc/login.defs``;
* ``parse_passwd(text)`` reads ``getent passwd`` output;
* ``candidate_accounts(passwd, login_defs, linger)`` combines them with the
  validated ``/var/lib/systemd/linger`` account list (``parse_linger`` in
  ``systemd_user_env``) into the accounts whose user manager may run.

A user manager (``user@<uid>.service``) starts for any account that opens a
logind session and stays up at boot for lingering accounts, so the candidates
are root, regular accounts in the login.defs UID range and every lingering
account. Accounts with a non-interactive shell are kept and flagged, because
lingering or ``su -s``/``systemd-run`` sessions still start their manager.

It performs no I/O, runs no command and never authorizes a response action.
The password and GECOS fields are never carried forward. Nothing is guessed:
malformed, duplicate or over-cap input becomes an explicit coverage gap and
the affected entry or value is not accepted. A rejected login.defs value falls
back to the documented ``login.defs(5)`` default and marks the result
incomplete.

Limitations: only plain decimal login.defs values are accepted (shadow-utils
also reads octal and hexadecimal, which are reported as gaps); a vendor
``/usr/etc/login.defs`` is not merged; ``default_runtime_dir`` is the logind
``/run/user/<uid>`` convention, not an observed runtime directory.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
DEFAULT_UID_MIN = 1000
DEFAULT_UID_MAX = 60000
MAX_UID = 4294967294  # (uid_t)-1 is reserved
MAX_LOGIN_DEFS_BYTES = 256 * 1024
MAX_PASSWD_BYTES = 4 * 1024 * 1024
MAX_PASSWD_LINES = 50000
NON_INTERACTIVE_SHELLS = frozenset({
    '/usr/sbin/nologin', '/sbin/nologin', '/usr/bin/nologin', '/bin/nologin',
    '/bin/false', '/usr/bin/false', '/bin/true', '/usr/bin/true',
})

_ACCOUNT_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}\$?\Z')
_DECIMAL_RE = re.compile(r'(0|[1-9][0-9]{0,9})\Z')
_KEY_RE = re.compile(r'[A-Z_][A-Z0-9_]*\Z')


def _gap(code: str, detail: str = '') -> dict[str, str]:
    return {'code': code, 'detail': detail}


def _valid_account(name: Any) -> bool:
    return isinstance(name, str) and bool(_ACCOUNT_RE.match(name)) and not name.rstrip('$').isdigit()


def _valid_path(value: str) -> bool:
    return (value.startswith('/') and '\x00' not in value and len(value) <= 1024
            and posixpath.normpath(value) == value)


def _decimal(value: str) -> int | None:
    if not _DECIMAL_RE.match(value):
        return None
    number = int(value)
    return number if number <= MAX_UID else None


def parse_login_defs(text: Any) -> dict[str, Any]:
    """Return ``UID_MIN``/``UID_MAX`` from captured ``/etc/login.defs`` text.

    ``None`` means the file was not collected (a gap; defaults apply). An empty
    string is a collected file without the keys, so the documented defaults
    apply without a gap. Duplicate keys follow shadow-utils (last value wins)
    and are reported. ``defaulted`` lists keys that fell back to the default.
    """
    gaps: list[dict[str, str]] = []
    values: dict[str, int] = {}
    defaulted: list[str] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'gaps': gaps}
    if not isinstance(text, str):
        gaps.append(_gap('login_defs_not_collected'))
    elif len(text.encode('utf-8', 'surrogatepass')) > MAX_LOGIN_DEFS_BYTES:
        gaps.append(_gap('login_defs_too_large', str(MAX_LOGIN_DEFS_BYTES)))
    else:
        seen: set[str] = set()
        for number, line in enumerate(text.split('\n'), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            parts = stripped.split(None, 1)
            key = parts[0]
            if not _KEY_RE.match(key) or key not in ('UID_MIN', 'UID_MAX'):
                continue
            if key in seen:
                gaps.append(_gap('login_defs_duplicate_key', key))
            seen.add(key)
            raw = parts[1].strip() if len(parts) > 1 else ''
            value = _decimal(raw)
            if value is None:
                gaps.append(_gap('login_defs_value_invalid', f'{key} line {number}'))
                values.pop(key, None)
                continue
            values[key] = value
    if 'UID_MIN' in values and 'UID_MAX' in values and values['UID_MIN'] > values['UID_MAX']:
        gaps.append(_gap('login_defs_range_invalid', f"{values['UID_MIN']}>{values['UID_MAX']}"))
        values.clear()
    for key, default in (('UID_MIN', DEFAULT_UID_MIN), ('UID_MAX', DEFAULT_UID_MAX)):
        if key not in values:
            values[key] = default
            defaulted.append(key)
    if values['UID_MIN'] > values['UID_MAX']:  # one side defaulted past the other
        gaps.append(_gap('login_defs_range_invalid', f"{values['UID_MIN']}>{values['UID_MAX']}"))
        values = {'UID_MIN': DEFAULT_UID_MIN, 'UID_MAX': DEFAULT_UID_MAX}
        defaulted = ['UID_MIN', 'UID_MAX']
    result.update(uid_min=values['UID_MIN'], uid_max=values['UID_MAX'],
                  defaulted=defaulted, complete=not gaps)
    return result


def parse_passwd(text: Any) -> dict[str, Any]:
    """Parse captured ``getent passwd`` output.

    Returns ``{'contract_version', 'accounts', 'gaps', 'complete'}`` where each
    account is ``{name, uid, gid, home, shell}``. ``home`` is None when it is
    not an absolute, normalised path (``candidate_accounts`` reports that only
    for candidates). A duplicated name is ambiguous across NSS sources, so every
    entry for it is dropped and reported. Lines are identified by number only,
    because a malformed line may hold a password hash.
    """
    gaps: list[dict[str, str]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'accounts': [], 'gaps': gaps}
    if not isinstance(text, str):
        gaps.append(_gap('passwd_not_collected'))
        result['complete'] = False
        return result
    if len(text.encode('utf-8', 'surrogatepass')) > MAX_PASSWD_BYTES:
        gaps.append(_gap('passwd_too_large', str(MAX_PASSWD_BYTES)))
        result['complete'] = False
        return result
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    if len(lines) > MAX_PASSWD_LINES:
        gaps.append(_gap('passwd_too_many_lines', str(MAX_PASSWD_LINES)))
        result['complete'] = False
        return result
    accounts: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for number, line in enumerate(lines, 1):
        fields = line.split(':')
        if len(fields) != 7 or '\x00' in line or '\r' in line:
            gaps.append(_gap('passwd_line_malformed', f'line {number}'))
            continue
        name, _password, uid_raw, gid_raw, _gecos, home, shell = fields
        if not _valid_account(name):
            gaps.append(_gap('passwd_name_invalid', f'line {number}'))
            continue
        uid, gid = _decimal(uid_raw), _decimal(gid_raw)
        if uid is None or gid is None:
            gaps.append(_gap('passwd_id_invalid', name))
            continue
        if name in accounts or name in duplicates:
            if name not in duplicates:
                gaps.append(_gap('passwd_duplicate_name', name))
            duplicates.add(name)
            accounts.pop(name, None)
            continue
        accounts[name] = {
            'name': name, 'uid': uid, 'gid': gid,
            'home': home if _valid_path(home) else None,
            # An empty shell field means /bin/sh (passwd(5)).
            'shell': shell if shell == '' or _valid_path(shell) else None,
        }
    result['accounts'] = [accounts[n] for n in sorted(accounts)]
    result['complete'] = not gaps
    return result


def candidate_accounts(passwd: Any, login_defs: Any, linger: Any) -> dict[str, Any]:
    """Return the accounts whose ``systemd --user`` manager may run.

    ``passwd`` and ``login_defs`` are results of the parsers above; ``linger``
    is a ``parse_linger`` result (``{'accounts': [...], 'complete': ...}``) or
    None when lingering was not collected. Upstream incompleteness is carried
    forward so a partial passwd or linger observation never reads as complete.
    """
    gaps: list[dict[str, str]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'accounts': [], 'gaps': gaps}
    if not isinstance(passwd, dict) or not isinstance(passwd.get('accounts'), list):
        gaps.append(_gap('passwd_not_collected'))
        result['complete'] = False
        return result
    if not passwd.get('complete'):
        gaps.append(_gap('passwd_incomplete'))
    if not isinstance(login_defs, dict) or not isinstance(login_defs.get('uid_min'), int) \
            or not isinstance(login_defs.get('uid_max'), int):
        login_defs = parse_login_defs(None)
    if not login_defs.get('complete'):
        gaps.append(_gap('login_defs_incomplete'))
    uid_min, uid_max = login_defs['uid_min'], login_defs['uid_max']
    lingering: set[str] = set()
    if not isinstance(linger, dict) or not isinstance(linger.get('accounts'), list):
        gaps.append(_gap('linger_not_collected'))
    else:
        if not linger.get('complete'):
            gaps.append(_gap('linger_incomplete'))
        lingering = {a for a in linger['accounts'] if _valid_account(a)}
    by_name = {a['name']: a for a in passwd['accounts'] if isinstance(a, dict) and _valid_account(a.get('name'))}
    for name in sorted(lingering - by_name.keys()):
        gaps.append(_gap('linger_account_unknown', name))
    accounts: list[dict[str, Any]] = []
    for name in sorted(by_name):
        entry = by_name[name]
        uid = entry.get('uid')
        if not isinstance(uid, int):
            continue
        reasons = []
        if uid == 0:
            reasons.append('root')
        if uid_min <= uid <= uid_max:
            reasons.append('regular_uid')
        if name in lingering:
            reasons.append('lingering')
        if not reasons:
            continue
        home = entry.get('home')
        if home is None or home == '/':
            gaps.append(_gap('account_home_invalid', name))
        shell = entry.get('shell')
        accounts.append({
            'account': name,
            'uid': uid,
            'home': home if home not in (None, '/') else None,
            'lingering': name in lingering,
            'interactive_shell': None if shell is None else (shell or '/bin/sh') not in NON_INTERACTIVE_SHELLS,
            'default_runtime_dir': f'/run/user/{uid}',
            'reasons': reasons,
        })
    result['accounts'] = accounts
    result['uid_range'] = [uid_min, uid_max]
    result['complete'] = not gaps
    return result

