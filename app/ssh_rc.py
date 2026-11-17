"""Pure OpenSSH login rc-hook contract (roadmap F slice, #1045).

Takes captured, read-only observations of ``/etc/ssh/sshrc``, each account's
``~/.ssh/rc`` and the effective sshd settings, and says which rc hook sshd runs
for that account's sessions. It also gives the command sshd uses to run it.

Semantics follow OpenSSH ``session.c`` ``do_rc_files()``:

* sshd runs ``~/.ssh/rc`` (``<pw_dir>/.ssh/rc``) when all of these hold: the
  session is not a subsystem, there is no ``ForceCommand``, the authentication's
  options permit user rc (``no-user-rc`` and ``restrict`` clear it, ``user-rc``
  sets it again, and password and other methods keep the default), ``PermitUserRC``
  is yes and ``stat()`` on the file succeeds. It runs
  ``<login shell> -c '/bin/sh <pw_dir>/.ssh/rc'``. The login shell is ``/bin/sh``
  when it is empty.
* Otherwise, if ``stat()`` on ``/etc/ssh/sshrc`` succeeds, sshd runs
  ``/bin/sh /etc/ssh/sshrc``. That includes subsystem (for example sftp)
  sessions and ``ForceCommand`` sessions.
* Otherwise no rc hook runs, and sshd itself runs xauth only when X11
  forwarding was requested. When either rc hook runs, sshd leaves xauth to it.

The branches are exclusive. Once the user rc branch is taken, the system rc is
not a fallback, even when the user rc cannot actually run its script. That
happens when it is a directory, or when the login shell is ``nologin`` or
``false``. Both scripts run through ``/bin/sh``, so their mode does not matter.
``stat()`` follows symlinks, so a dangling symlink counts as absent.

``key_user_rc`` must reflect every way the account can authenticate: the
``authorized_keys`` options and, for certificate logins, the certificate's
``permit-user-rc`` extension, which sets the same flag.

Both hooks run as the logged-in user in their home directory. The observation is
assumed to be collected with at least the user's view of these paths.

It performs no I/O, never runs a command and never authorizes a response
action. Every input that is unknown, malformed or over a cap, or that cannot be
resolved exactly (``ChrootDirectory``, or a home or login shell path that a
shell would expand, glob, quote or split, because only paths made of
``[A-Za-z0-9_./+,:@%=-]`` are taken literally) becomes an explicit coverage gap and never yields a covered result.
"""
from __future__ import annotations

import itertools
import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
MAX_ACCOUNTS = 4096
MAX_PATH = 4096
MAX_GAPS = 256

SYSTEM_RC = '/etc/ssh/sshrc'
USER_RC = '.ssh/rc'
BSHELL = '/bin/sh'
SESSION_KINDS = ('session', 'subsystem')
FILE_STATES = ('present', 'absent', 'unknown')
FILE_KINDS = ('regular', 'directory', 'other')
KEY_USER_RC = ('permitted', 'denied', 'mixed', 'unknown')
_NON_EXECUTING_SHELLS = ('nologin', 'false')
_USER = re.compile(r'[A-Za-z0-9_.][A-Za-z0-9_.@-]{0,255}\$?')
_SHA256 = re.compile(r'[0-9a-f]{64}')
# sshd builds the user rc command with popen(), so /bin/sh parses the login
# shell path, and the login shell then parses '/bin/sh <pw_dir>/.ssh/rc' as
# shell code. Only paths made entirely of characters that no POSIX shell
# expands, globs, quotes or splits are taken literally; anything else is a gap.
_SHELL_LITERAL = re.compile(r'[A-Za-z0-9_./+,:@%=-]+')


class Invalid(ValueError):
    """An observation that cannot be interpreted safely."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})
    elif not gaps or gaps[-1]['code'] != 'gaps_truncated':
        gaps[-1] = {'code': 'gaps_truncated'}


def _path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith('/') or len(value) > MAX_PATH or '\0' in value:
        raise Invalid('invalid absolute path')
    return value


def _file(value: Any) -> dict[str, Any]:
    if value is None:
        return {'state': 'unknown', 'kind': None, 'sha256': None}
    if not isinstance(value, dict) or not set(value) <= {'state', 'kind', 'sha256'} or 'state' not in value:
        raise Invalid('invalid file observation')
    state = value['state']
    if state not in FILE_STATES:
        raise Invalid('invalid file state')
    kind = value.get('kind')
    sha = value.get('sha256')
    if state != 'present' and (kind is not None or sha is not None):
        raise Invalid('kind or hash supplied for a file that is not present')
    if kind is not None and kind not in FILE_KINDS:
        raise Invalid('invalid file kind')
    if sha is not None and (not isinstance(sha, str) or not _SHA256.fullmatch(sha) or kind != 'regular'):
        raise Invalid('invalid file hash')
    return {'state': state, 'kind': kind, 'sha256': sha}


def _tristate(value: Any, name: str) -> bool | None:
    if value is None or type(value) is bool:
        return value
    raise Invalid(f'invalid {name}')


def _sshd(value: Any, base: dict[str, Any] | None = None) -> dict[str, Any]:
    keys = ('permit_user_rc', 'force_command', 'chroot_directory')
    if value is None:
        return dict(base) if base is not None else dict.fromkeys(keys)
    if not isinstance(value, dict) or not set(value) <= set(keys):
        raise Invalid('invalid sshd settings')
    out = dict(base) if base is not None else dict.fromkeys(keys)
    for key in keys:
        if key in value:
            out[key] = _tristate(value[key], key)
    return out


def _user_rc_command(shell: str, home: str) -> str:
    return f"{shell} -c '{BSHELL} {posixpath.join(home, USER_RC)}'"


def _decide(kind: str, sshd: dict[str, Any], key_permits: bool, user_rc_present: bool, system_present: bool,
            account: dict[str, Any], system_rc: dict[str, Any]) -> dict[str, Any]:
    reasons = []
    user_allowed = True
    if kind == 'subsystem':
        reasons.append('subsystem_ignores_user_rc')
        user_allowed = False
    if sshd['force_command']:
        reasons.append('force_command_ignores_user_rc')
        user_allowed = False
    if not key_permits:
        reasons.append('authentication_options_deny_user_rc')
        user_allowed = False
    if not sshd['permit_user_rc']:
        reasons.append('permit_user_rc_no')
        user_allowed = False
    if user_allowed and not user_rc_present:
        reasons.append('user_rc_absent')
    if user_allowed and user_rc_present:
        shell = account['shell'] or BSHELL
        path = posixpath.join(account['home'], USER_RC)
        script_runs: bool | None = True
        if posixpath.basename(shell) in _NON_EXECUTING_SHELLS:
            script_runs = False
            reasons.append('login_shell_does_not_run_commands')
        if account['user_rc']['kind'] == 'directory':
            script_runs = False
            reasons.append('user_rc_is_directory')
        elif account['user_rc']['kind'] != 'regular':
            script_runs = None if script_runs else script_runs
            reasons.append('user_rc_kind_not_regular_or_unknown')
        if not _SHELL_LITERAL.fullmatch(shell):
            script_runs = None
            reasons.append('login_shell_path_parsed_by_shell')
        if not _SHELL_LITERAL.fullmatch(account['home']):
            script_runs = None if script_runs else script_runs
            reasons.append('home_path_resplit_by_shell')
        return {'outcome': 'user_rc', 'path': path, 'command': _user_rc_command(shell, account['home']),
                'sha256': account['user_rc']['sha256'], 'script_runs': script_runs,
                'system_rc_skipped': True, 'xauth_left_to_rc': True, 'reasons': reasons}
    if system_present:
        script_runs = True
        if system_rc['kind'] == 'directory':
            script_runs = False
            reasons.append('system_rc_is_directory')
        elif system_rc['kind'] != 'regular':
            script_runs = None
            reasons.append('system_rc_kind_not_regular_or_unknown')
        return {'outcome': 'system_rc', 'path': SYSTEM_RC, 'command': f'{BSHELL} {SYSTEM_RC}',
                'sha256': system_rc['sha256'], 'script_runs': script_runs,
                'system_rc_skipped': False, 'xauth_left_to_rc': True, 'reasons': reasons}
    reasons.append('system_rc_absent')
    return {'outcome': 'none', 'path': None, 'command': None, 'sha256': None, 'script_runs': None,
            'system_rc_skipped': False, 'xauth_left_to_rc': False, 'reasons': reasons}


def _signature(decision: dict[str, Any]) -> tuple:
    return (decision['outcome'], decision['path'], decision['command'], decision['script_runs'])


def _choices(value: bool | None) -> tuple[bool, ...]:
    return (True, False) if value is None else (value,)


def _present(state: str) -> tuple[bool, ...]:
    return (True, False) if state == 'unknown' else (state == 'present',)


def _resolve_kind(kind: str, sshd: dict[str, Any], account: dict[str, Any], system_rc: dict[str, Any],
                  gaps: list[dict[str, Any]]) -> dict[str, Any]:
    if sshd['chroot_directory'] is not False:
        code = 'chroot_paths_not_observed' if sshd['chroot_directory'] else 'chroot_directory_unknown'
        _gap(gaps, code, session=kind)
        return {'outcome': 'uncertain', 'possible': [], 'reasons': [code]}
    key = account['key_user_rc']
    key_options = {'permitted': (True,), 'denied': (False,), 'mixed': (True, False), 'unknown': (True, False)}[key]
    decisions: dict[bool, list[dict[str, Any]]] = {True: [], False: []}
    for permit, force, key_permits, user_present, system_present in itertools.product(
            _choices(sshd['permit_user_rc']), _choices(sshd['force_command']), key_options,
            _present(account['user_rc']['state']), _present(system_rc['state'])):
        decision = _decide(kind, {'permit_user_rc': permit, 'force_command': force}, key_permits, user_present,
                           system_present, account, system_rc)
        decisions[key_permits].append(decision)
    flat = decisions[True] + decisions[False]
    distinct = {_signature(d): d for d in flat}
    if len(distinct) == 1:
        return next(iter(distinct.values()))
    if key == 'mixed':
        per_key = {k: {_signature(d): d for d in v} for k, v in decisions.items() if v}
        if all(len(v) == 1 for v in per_key.values()):
            return {'outcome': 'depends_on_key', 'possible': sorted({d['outcome'] for d in flat}),
                    'by_key': {('permitted' if k else 'denied'): next(iter(v.values())) for k, v in per_key.items()},
                    'reasons': ['authentication_options_differ_between_keys']}
    unknown = [name for name, value in (('permit_user_rc', sshd['permit_user_rc']),
                                        ('force_command', sshd['force_command'])) if value is None]
    if key == 'unknown':
        unknown.append('key_user_rc')
    if account['user_rc']['state'] == 'unknown':
        unknown.append('user_rc')
    if system_rc['state'] == 'unknown':
        unknown.append('system_rc')
    for name in unknown:
        _gap(gaps, 'input_unknown', session=kind, input=name)
    return {'outcome': 'uncertain', 'possible': sorted({d['outcome'] for d in flat}),
            'reasons': ['inputs_unknown'] + [f'{n}_unknown' for n in unknown]}


def _account(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not {'user', 'home', 'shell', 'user_rc'} <= set(value) \
            or not set(value) <= {'user', 'home', 'shell', 'user_rc', 'key_user_rc', 'sshd'}:
        raise Invalid('invalid account observation')
    if not isinstance(value['user'], str) or not _USER.fullmatch(value['user']):
        raise Invalid('invalid user name')
    shell = value['shell']
    if not isinstance(shell, str) or (shell and not shell.startswith('/')) or len(shell) > MAX_PATH or '\0' in shell:
        raise Invalid('invalid login shell')
    key = value.get('key_user_rc', 'unknown')
    if key not in KEY_USER_RC:
        raise Invalid('invalid key user-rc permission')
    return {'user': value['user'], 'home': _path(value['home']), 'shell': shell, 'user_rc': _file(value['user_rc']),
            'key_user_rc': key}


def resolve(observation: Any) -> dict[str, Any]:
    """Resolve which SSH rc hook runs for each observed account.

    ``observation`` is ``{'system_rc': file, 'sshd': settings, 'accounts': [...]}``.
    A file is ``{'state': 'present'|'absent'|'unknown', 'kind': 'regular'|'directory'|'other',
    'sha256': hex}``. Settings hold ``permit_user_rc``, ``force_command`` and ``chroot_directory``,
    each true, false or None for unknown. An account is ``{'user', 'home', 'shell', 'user_rc',
    'key_user_rc', 'sshd'}``, where ``sshd`` holds Match-block overrides for that account.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'complete': False, 'system_rc': None,
                              'accounts': [], 'gaps': gaps}
    try:
        if not isinstance(observation, dict) or not set(observation) <= {'system_rc', 'sshd', 'accounts'}:
            raise Invalid('invalid observation')
        system_rc = _file(observation.get('system_rc'))
        sshd = _sshd(observation.get('sshd'))
        accounts = observation.get('accounts', [])
        if not isinstance(accounts, list):
            raise Invalid('accounts must be a list')
    except Invalid as exc:
        _gap(gaps, 'invalid_observation', detail=str(exc))
        return result
    if len(accounts) > MAX_ACCOUNTS:
        _gap(gaps, 'accounts_over_cap', limit=MAX_ACCOUNTS)
        accounts = accounts[:MAX_ACCOUNTS]
    if system_rc['state'] == 'unknown':
        _gap(gaps, 'system_rc_not_observed', path=SYSTEM_RC)
    result['system_rc'] = {'path': SYSTEM_RC, **system_rc}
    seen: set[str] = set()
    for index, raw in enumerate(accounts):
        try:
            account = _account(raw)
            account_sshd = _sshd(raw.get('sshd'), sshd)
            if account['user'] in seen:
                raise Invalid('duplicate user')
        except Invalid as exc:
            _gap(gaps, 'invalid_account', index=index, detail=str(exc))
            continue
        seen.add(account['user'])
        account_gaps: list[dict[str, Any]] = []
        sessions = {kind: _resolve_kind(kind, account_sshd, account, system_rc, account_gaps) for kind in SESSION_KINDS}
        if account['user_rc']['state'] == 'unknown':
            _gap(account_gaps, 'user_rc_not_observed', path=posixpath.join(account['home'], USER_RC))
        for decision in sessions.values():
            if decision.get('script_runs') is None and decision['outcome'] in ('user_rc', 'system_rc'):
                _gap(account_gaps, 'script_execution_unresolved', reasons=decision['reasons'])
        result['accounts'].append({'user': account['user'], 'home': account['home'], 'sessions': sessions,
                                   'gaps': account_gaps})
        for gap in account_gaps:
            _gap(gaps, gap['code'], user=account['user'], **{k: v for k, v in gap.items() if k != 'code'})
    result['complete'] = not gaps
    return result
