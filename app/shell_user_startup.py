"""Pure per-user shell startup contract (roadmap F slice, #1057).

Takes one account's passwd shell, uid/gid and supplied metadata for its home
dotfiles and says which file each kind of session runs. This covers the catalog's
``shell_user`` mechanism (``~/.bash_profile``, ``~/.bash_login``, ``~/.profile``,
``~/.bashrc`` and ``~/.bash_logout``). It never reads a file's contents.

Semantics were checked against Ubuntu 24.04 (bash 5.2.21 and dash 0.5.12), as
root and as ``nobody``, not recalled:

* A login bash tries ``~/.bash_profile``, ``~/.bash_login`` and ``~/.profile``
  in that order. Only a missing name (or a dangling symlink, ENOENT) falls
  through to the next. An unreadable file ("Permission denied") or a directory
  ("is a directory") prints an error and stops the chain, so later files are
  not read. A symlink that cannot be followed for another reason also stops
  the chain with an error: a loop (ELOOP, "Too many levels of symbolic
  links"), a target behind a directory the account cannot search (EACCES,
  "Permission denied") or a path through a non-directory (ENOTDIR, "Not a
  directory"). Root reads a mode 0000 file and searches a mode 0000
  directory. A FIFO blocks the login.
* An interactive non-login bash reads ``~/.bashrc``.
* Debian builds bash with ``SSH_SOURCE_BASHRC``. A non-interactive bash that
  sshd starts for ``ssh host command`` (``SSH_CLIENT`` set, ``SHLVL`` below 2)
  also reads ``~/.bashrc``.
* A login bash runs ``~/.bash_logout`` when it exits through ``exit``/``logout``
  or end of input.
* A login ``sh`` (dash, or bash invoked as ``sh``) reads only ``~/.profile``.
  dash silently skips an unreadable, directory or unfollowable-symlink
  ``~/.profile``.
* ``nologin`` and ``false`` start no shell. Other shells are not modelled.

It performs no I/O, never runs a command and never authorizes a response
action. Unobserved or malformed metadata, unmodelled shells or families,
undetermined group membership and over-limit input are explicit blocking gaps
and are never reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'shells': 'bash 5.2.21 and dash 0.5.12 (Ubuntu 24.04)'}
KNOWN_FAMILIES = frozenset({'debian', 'rpm'})
BASH_LOGIN_CHAIN = ('.bash_profile', '.bash_login', '.profile')
DOTFILES = ('.bash_profile', '.bash_login', '.profile', '.bashrc', '.bash_logout')
SESSIONS = ('login', 'interactive', 'ssh_command', 'logout')
FILE_TYPES = ('absent', 'file', 'directory', 'symlink', 'other')
# Errors from following a symlink (stat/open as the account) other than ENOENT. ENOENT is
# ``target: None`` (dangling). Anything else must be reported as ``other``.
LINK_ERRORS = ('ELOOP', 'EACCES', 'ENOTDIR', 'other')
HOME_STATES = ('listed', 'absent', 'unreadable')
BASH_SHELLS = frozenset({'/bin/bash', '/usr/bin/bash', '/bin/rbash', '/usr/bin/rbash'})
POSIX_SHELLS = frozenset({'/bin/sh', '/usr/bin/sh', '/bin/dash', '/usr/bin/dash'})
NO_LOGIN_SHELLS = frozenset({'/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/usr/bin/false'})
MAX_ID = 2 ** 32 - 1
MAX_GROUPS = 1024
MAX_PATH = 4096
MAX_GAPS = 32
BLOCKING = frozenset({
    'input_malformed', 'account_not_observed', 'family_not_observed', 'family_unsupported',
    'family_not_modelled', 'shell_not_modelled', 'home_not_observed', 'home_unreadable',
    'file_not_observed', 'metadata_missing', 'symlink_target_unobserved', 'symlink_error_unrecognized',
    'groups_not_observed', 'special_file', 'gaps_truncated',
})
UNOBSERVED = (
    ('File contents are not read, so a file that sources another (Debian\'s ~/.profile sources ~/.bashrc for '
     'bash) or exits early is not followed.'),
    '/etc/profile, /etc/profile.d, /etc/bash.bashrc and other system files are not interpreted here.',
    'Search permission on the home directory, POSIX ACLs and security modules are not assessed.',
    ('Shell invocation flags (--noprofile, --norc, --rcfile), BASH_ENV, ENV and a non-default HOME are not '
     'observed.'),
    'Whether /bin/sh is dash or bash is not observed; both read only ~/.profile at login.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'reads': 'This file runs in this kind of session.',
    'absent': 'No file by this name exists (or the symlink is dangling).',
    'not_reached': 'An earlier file in the login chain ran or failed, so this one is not tried.',
    'chain_stopped_unreadable': 'bash cannot read this file and stops the login chain with "Permission denied"; '
                                'later files are not read.',
    'chain_stopped_directory': 'bash reports "is a directory" and stops the login chain; later files are not '
                               'read.',
    'error_unreadable': 'bash cannot read this file and reports "Permission denied".',
    'error_directory': 'bash reports "is a directory" for this name.',
    'chain_stopped_link_error': 'bash cannot follow this symlink (loop, unsearchable directory or path through '
                                'a non-directory), reports an error and stops the login chain; later files are '
                                'not read.',
    'error_link_error': 'bash cannot follow this symlink (loop, unsearchable directory or path through a '
                        'non-directory) and reports an error.',
    'skipped_link_error': 'dash cannot follow this symlink and silently skips it.',
    'link_error_unrecognized': 'Following this symlink failed with an error whose shell behavior is not '
                               'modelled, so the outcome is not determined.',
    'skipped_unreadable': 'dash cannot read this file and silently skips it.',
    'skipped_directory': 'dash silently skips a directory with this name.',
    'not_used_by_shell': 'This shell does not read this file in this kind of session.',
    'no_login_shell': 'The account\'s shell refuses logins, so no shell startup file runs.',
    'special_file': 'Not a regular file or directory; reading a FIFO blocks and a device or socket reads '
                    'untracked input.',
    'depends_on_groups': 'Readability depends on supplementary group membership, which was not supplied.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
SESSION_LABELS = {
    'login': 'Login shell (console, su -, ssh without a command)',
    'interactive': 'Interactive non-login shell',
    'ssh_command': 'Non-interactive ssh host command',
    'logout': 'Login shell exit',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


def _gap(gaps: list[dict[str, Any]], code: str, name: str | None = None, detail: str = '') -> None:
    if any(g['code'] == code and g.get('path') == (f'~/{name}' if name else None) for g in gaps):
        return
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code}
    if name is not None:
        gap['path'] = f'~/{name}'
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def _int(value: Any, upper: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= upper


def classify_shell(shell: Any) -> str:
    """Return ``bash``, ``posix``, ``no_login`` or ``other`` for a passwd shell field.

    An empty field means ``/bin/sh`` (passwd(5)). Only canonical absolute paths are
    recognized; anything else, including a relative path, is ``other``.
    """
    if shell == '':
        return 'posix'
    if shell in BASH_SHELLS:
        return 'bash'
    if shell in POSIX_SHELLS:
        return 'posix'
    if shell in NO_LOGIN_SHELLS:
        return 'no_login'
    return 'other'


def account_can_read(mode: int, file_uid: int, file_gid: int, uid: int, gid: int,
                     groups: Any = None) -> bool | None:
    """Whether ``access(R_OK)`` succeeds for an account, or ``None`` when it depends on unknown groups.

    Root always reads. Otherwise exactly one class applies: owner when the account owns the
    file, group when the file's group is the primary group or a supplied supplementary
    group, and other otherwise.
    """
    if uid == 0:
        return True
    if file_uid == uid:
        return bool(mode & 0o400)
    if file_gid == gid or (groups is not None and file_gid in groups):
        return bool(mode & 0o040)
    if groups is None and bool(mode & 0o040) != bool(mode & 0o004):
        return None
    return bool(mode & 0o004)


def _stat(meta: Any) -> dict[str, Any] | None:
    if not isinstance(meta, dict) or meta.get('type') not in ('file', 'directory', 'other'):
        return None
    if meta['type'] == 'file' and not (_int(meta.get('mode'), 0o7777) and _int(meta.get('uid'), MAX_ID)
                                       and _int(meta.get('gid'), MAX_ID)):
        return None
    return {'type': meta['type'], 'mode': meta.get('mode'), 'uid': meta.get('uid'), 'gid': meta.get('gid')}


def _observe(name: str, item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any]:
    """Normalize one dotfile observation to ``{'kind', ...}`` with kind absent/file/directory/other/unresolved."""
    if item is None:
        _gap(gaps, 'file_not_observed', name, 'No observation was supplied for this dotfile.')
        return {'kind': 'unresolved', 'type': None}
    if not isinstance(item, dict) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', name, 'The dotfile observation has no valid type.')
        return {'kind': 'unresolved', 'type': None}
    kind = item['type']
    out: dict[str, Any] = {'type': kind}
    if kind == 'absent':
        out['kind'] = 'absent'
        return out
    if kind == 'symlink':
        link = item.get('link_target')
        if isinstance(link, str) and link and len(link) <= MAX_PATH and not _CONTROL.search(link):
            out['link_target'] = link
        if 'target_error' in item:
            error = item['target_error']
            if error not in LINK_ERRORS or item.get('target') is not None:
                _gap(gaps, 'input_malformed', name, 'A symlink error must be ELOOP, EACCES, ENOTDIR or other, '
                                                    'with no followed target.')
                out['kind'] = 'unresolved'
                return out
            out['target_error'] = error
            if error == 'other':
                _gap(gaps, 'symlink_error_unrecognized', name,
                     'Following the symlink failed with an error whose shell behavior is not modelled.')
                out['kind'] = 'unresolved_link'
                return out
            out['kind'] = 'link_error'
            return out
        if 'target' not in item:
            _gap(gaps, 'symlink_target_unobserved', name, 'What the symlink resolves to was not supplied.')
            out['kind'] = 'unresolved'
            return out
        if item['target'] is None:
            out['kind'] = 'absent'
            out['dangling'] = True
            return out
        stat = _stat(item['target'])
    else:
        stat = _stat(item)
    if stat is None:
        _gap(gaps, 'metadata_missing', name, 'Required metadata for this dotfile was not supplied or is malformed.')
        out['kind'] = 'unresolved'
        return out
    out.update(kind=stat['type'], mode=stat['mode'], uid=stat['uid'], gid=stat['gid'])
    return out


def _readable(obs: dict[str, Any], account: dict[str, Any]) -> bool | None:
    return account_can_read(obs['mode'], obs['uid'], obs['gid'], account['uid'], account['gid'],
                            account.get('groups'))


def _single(name: str, obs: dict[str, Any], account: dict[str, Any], shell: str,
            gaps: list[dict[str, Any]]) -> tuple[str, str]:
    """Return ``(state, reason_code)`` for one file the shell opens once (no chain)."""
    kind = obs['kind']
    if kind == 'unresolved':
        return 'unknown', 'unresolved'
    if kind == 'unresolved_link':
        return 'unknown', 'link_error_unrecognized'
    if kind == 'link_error':
        return ('skipped', 'skipped_link_error') if shell == 'posix' else ('error', 'error_link_error')
    if kind == 'absent':
        return 'none', 'absent'
    if kind == 'other':
        _gap(gaps, 'special_file', name, 'Reading a FIFO, socket or device can block or read untracked input.')
        return 'unknown', 'special_file'
    if kind == 'directory':
        return ('skipped', 'skipped_directory') if shell == 'posix' else ('error', 'error_directory')
    readable = _readable(obs, account)
    if readable is None:
        _gap(gaps, 'groups_not_observed', name, 'Supplementary groups decide readability and were not supplied.')
        return 'unknown', 'depends_on_groups'
    if readable:
        return 'reads', 'reads'
    return ('skipped', 'skipped_unreadable') if shell == 'posix' else ('error', 'error_unreadable')


def _bash_login(obs: dict[str, dict[str, Any]], account: dict[str, Any],
                gaps: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, str]]:
    """Walk the bash login chain. Returns the session result and a per-file reason map."""
    reasons: dict[str, str] = {}
    session: dict[str, Any] | None = None
    for name in BASH_LOGIN_CHAIN:
        if session is not None:
            reasons[name] = 'unresolved' if session['state'] == 'unknown' else 'not_reached'
            continue
        state, code = _single(name, obs[name], account, 'bash', gaps)
        if state == 'none':
            reasons[name] = 'absent'
            continue
        if state == 'error':
            code = {'error_directory': 'chain_stopped_directory',
                    'error_link_error': 'chain_stopped_link_error'}.get(code, 'chain_stopped_unreadable')
        reasons[name] = code
        session = {'state': state, 'file': f'~/{name}', 'reason_code': code}
    if session is None:
        session = {'state': 'none', 'file': None, 'reason_code': 'absent'}
    return session, reasons


def _account(account: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if account is None:
        _gap(gaps, 'account_not_observed', detail='No account (shell, uid and gid) was supplied.')
        return None
    if not isinstance(account, dict) or not _int(account.get('uid'), MAX_ID) or not _int(account.get('gid'), MAX_ID) \
            or not isinstance(account.get('shell'), str) or len(account['shell']) > MAX_PATH \
            or _CONTROL.search(account['shell']):
        _gap(gaps, 'input_malformed', detail='The account observation needs a shell string and integer uid and gid.')
        return None
    groups = account.get('groups')
    if groups is not None:
        if not isinstance(groups, (list, tuple, set, frozenset)) or len(groups) > MAX_GROUPS \
                or not all(_int(g, MAX_ID) for g in groups):
            _gap(gaps, 'input_malformed', detail='Supplementary groups must be a bounded list of integer gids.')
            return None
        groups = frozenset(groups)
    return {'uid': account['uid'], 'gid': account['gid'], 'shell': account['shell'], 'groups': groups}


def _family(family: Any, gaps: list[dict[str, Any]]) -> bool:
    if family is None:
        _gap(gaps, 'family_not_observed', detail='The OS family was not supplied, so the bash build is unknown.')
        return False
    if family not in KNOWN_FAMILIES:
        _gap(gaps, 'family_unsupported', detail='Only Debian-family and RPM-family systems are recognized.')
        return False
    if family != 'debian':
        _gap(gaps, 'family_not_modelled', detail='RPM-family bash build options (SSH_SOURCE_BASHRC and the '
                                                 'system bashrc) are not modelled yet.')
        return False
    return True


def _session(state: str, file: str | None, code: str) -> dict[str, Any]:
    return {'state': state, 'file': file, 'reason_code': code, 'reason': REASONS[code]}


def evaluate(files: Any, *, account: Any = None, family: Any = None, home: Any = None) -> dict[str, Any]:
    """Resolve which per-user shell startup files run for one account from supplied metadata.

    ``account`` is ``{'shell', 'uid', 'gid'}`` from passwd, plus optional ``groups`` (supplementary
    gids). ``home`` is ``{'state'}`` with ``listed``, ``absent`` or ``unreadable``. ``files`` maps each
    name in ``DOTFILES`` to an observation: ``{'type': 'absent'}``; ``{'type': 'file', 'mode', 'uid',
    'gid'}``; ``{'type': 'directory'}``; ``{'type': 'other'}`` for a FIFO, socket or device; or
    ``{'type': 'symlink', 'target': <followed stat or None>, 'link_target'?}``. ``target: None``
    means following the link failed with ENOENT (dangling) and nothing else. Any other failure
    is ``{'type': 'symlink', 'target_error': 'ELOOP' | 'EACCES' | 'ENOTDIR' | 'other'}``. Resolve
    symlinks with the account's own credentials: EACCES on a directory along the path applies to
    other accounts but not to root. ``family`` is ``debian`` or ``rpm``.

    ``sessions`` maps ``login``, ``interactive``, ``ssh_command`` and ``logout`` to ``{'state',
    'file', 'reason_code', 'reason'}``. ``state`` is ``reads``, ``none``, ``error`` (bash reports an
    error), ``skipped`` (dash ignores the file), or ``unknown``.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'shell': None, 'shell_kind': None,
        'login_chain': [f'~/{n}' for n in BASH_LOGIN_CHAIN], 'runs_as': 'the account itself',
        'sessions': {}, 'files': [], 'gaps': gaps, 'unobserved': list(UNOBSERVED),
        'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    family_ok = _family(family, gaps)
    acct = _account(account, gaps)
    shell_kind = classify_shell(acct['shell']) if acct else None
    if acct:
        result['shell'] = acct['shell']
        result['shell_kind'] = shell_kind
        if shell_kind == 'other':
            _gap(gaps, 'shell_not_modelled', detail='Only bash, sh/dash and nologin/false shells are modelled.')

    home_state = home.get('state') if isinstance(home, dict) else None
    if home is None:
        _gap(gaps, 'home_not_observed', detail='No home directory observation was supplied.')
    elif home_state not in HOME_STATES:
        _gap(gaps, 'input_malformed', detail='The home directory observation is malformed.')
        home_state = None
    elif home_state == 'unreadable':
        _gap(gaps, 'home_unreadable', detail='The home directory exists but could not be listed.')

    if not isinstance(files, dict):
        if files is not None:
            _gap(gaps, 'input_malformed', detail='Dotfile observations must be a mapping of name to metadata.')
        files = {}
    extra = [k for k in files if k not in DOTFILES]
    if extra:
        _gap(gaps, 'input_malformed', detail='Observations were supplied for names outside the modelled dotfiles.')

    if home_state == 'absent':
        if any(isinstance(v, dict) and v.get('type') != 'absent' for k, v in files.items() if k in DOTFILES):
            _gap(gaps, 'input_malformed', detail='Dotfiles were supplied for a home directory reported absent.')
        obs = {name: {'kind': 'absent', 'type': 'absent'} for name in DOTFILES}
    elif home_state == 'listed':
        obs = {name: _observe(name, files.get(name), gaps) for name in DOTFILES}
    else:
        obs = {name: {'kind': 'unresolved', 'type': None} for name in DOTFILES}

    reasons: dict[str, dict[str, str]] = {name: {} for name in DOTFILES}
    sessions: dict[str, dict[str, Any]] = {}
    determinable = acct is not None and family_ok and shell_kind in ('bash', 'posix', 'no_login') \
        and home_state in ('listed', 'absent')
    if not determinable:
        for kind in SESSIONS:
            sessions[kind] = _session('unknown', None, 'unresolved')
    elif shell_kind == 'no_login':
        for kind in SESSIONS:
            sessions[kind] = _session('none', None, 'no_login_shell')
        for name in DOTFILES:
            for kind in SESSIONS:
                reasons[name][kind] = 'no_login_shell'
    elif shell_kind == 'posix':
        state, code = _single('.profile', obs['.profile'], acct, 'posix', gaps)
        sessions['login'] = _session(state, '~/.profile' if state != 'none' else None, code)
        for kind in ('interactive', 'ssh_command', 'logout'):
            sessions[kind] = _session('none', None, 'not_used_by_shell')
        reasons['.profile']['login'] = code
    else:
        login, chain = _bash_login(obs, acct, gaps)
        sessions['login'] = _session(login['state'], login['file'], login['reason_code'])
        for name, code in chain.items():
            reasons[name]['login'] = code
        for kind in ('interactive', 'ssh_command'):
            state, code = _single('.bashrc', obs['.bashrc'], acct, 'bash', gaps)
            sessions[kind] = _session(state, '~/.bashrc' if state != 'none' else None, code)
            reasons['.bashrc'][kind] = code
        state, code = _single('.bash_logout', obs['.bash_logout'], acct, 'bash', gaps)
        sessions['logout'] = _session(state, '~/.bash_logout' if state != 'none' else None, code)
        reasons['.bash_logout']['logout'] = code

    result['sessions'] = sessions
    for name in DOTFILES:
        record: dict[str, Any] = {'name': name, 'path': f'~/{name}', 'type': obs[name]['type'],
                                  'runs_in': sorted(k for k, c in reasons[name].items() if c == 'reads'),
                                  'reasons': {k: {'code': c, 'reason': REASONS[c]} for k, c in
                                              sorted(reasons[name].items())}}
        if obs[name].get('dangling'):
            record['dangling'] = True
        if 'link_target' in obs[name]:
            record['link_target'] = obs[name]['link_target']
        if 'target_error' in obs[name]:
            record['target_error'] = obs[name]['target_error']
        result['files'].append(record)
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
