"""Pure zsh startup-file contract (roadmap F slice, #1371).

Takes one zsh invocation (invoked name, options, session kind, real/effective ids),
the ``HOME``/``ZDOTDIR`` it starts with and supplied followed-``stat`` metadata for
each candidate file. It says which system and per-user startup files the shell
sources, in which order, and when a compiled ``.zwc`` file may be loaded instead.
It never reads a file's contents.

Semantics were checked against Ubuntu 24.04 zsh 5.9 (run as root), not recalled:

* zsh always sources the global ``zshenv`` first. It then sources
  ``$ZDOTDIR/.zshenv``; for a login shell the global ``zprofile`` and
  ``$ZDOTDIR/.zprofile``; for an interactive shell the global ``zshrc`` and
  ``$ZDOTDIR/.zshrc``; and for a login shell the global ``zlogin`` and
  ``$ZDOTDIR/.zlogin``. When a login shell exits it sources ``$ZDOTDIR/.zlogout``
  and then the global ``zlogout`` (on ``exit``/``logout`` or end of input; a
  ``-c`` command that finishes, or an ``exec``, runs no logout files). Debian builds keep the global files in
  ``/etc/zsh``; RPM builds keep them directly in ``/etc``.
* ``-f``/``--no-rcs`` unsets RCS, so only the global ``zshenv`` runs.
  ``-d``/``--no-globalrcs`` unsets GLOBAL_RCS, which skips every later global file
  but not the user files. ``-p``/``--privileged``, or a real id that differs from
  the effective id, skips every user file.
* ``ZDOTDIR`` replaces ``HOME`` for user files. An empty ``ZDOTDIR`` is still set,
  so the files resolve under ``/``. A relative value resolves against the working
  directory, which is not observed.
* For every file, zsh first stats ``<file>.zwc``. When it exists and either the
  source is missing or the ``.zwc`` is at least as new (same mtime counts), zsh
  loads the compiled wordcode instead, provided the dump is valid; an invalid dump
  falls back to the source.
* A missing, unreadable or directory file is skipped silently. Root reads a mode
  0000 file.
* In an interactive zsh-emulation shell with RCS set and not privileged, zsh loads
  the ``zsh/newuser`` module right after the global ``zshenv`` (``-d`` does not stop
  it). When none of ``.zshenv``, ``.zprofile``, ``.zshrc`` and ``.zlogin`` exists in
  ``$ZDOTDIR`` (``access(F_OK)``, which follows symlinks, so a directory or an
  unreadable file exists and a dangling symlink does not; ``.zlogout`` is not
  checked), it sources ``<SITESCRIPT_DIR>/newuser`` and, only if that is not found,
  ``<SCRIPT_DIR>/newuser``. Not found means no usable ``.zwc`` and ``open`` fails, so
  an absent or unreadable file moves on to the next directory and a directory stops
  the search. The build's script directories and whether the module loads are
  supplied, not assumed (checked against the zsh 5.9 ``init.c``, ``newuser.c`` and
  ``parse.c`` sources).
* The invoked name selects emulation: after an optional leading ``-`` and one
  leading ``r``, a name starting with ``s`` or ``b`` emulates sh and ``k`` emulates
  ksh (``sh``, ``bzsh``, ``rsh`` and ``ksh`` read ``~/.profile``; ``rzsh`` and
  ``csh`` stay zsh). Emulation is reported as not modelled.

It performs no I/O, never runs a command and never authorizes a response action.
Unobserved or malformed metadata, unknown options or families, relative
``ZDOTDIR``, possible compiled substitutes and over-limit input are explicit
blocking gaps, and the result is never reported complete with any of them.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'shell': 'zsh 5.9 (Ubuntu 24.04)'}
GLOBAL_DIRS = {'debian': '/etc/zsh', 'rpm': '/etc'}
FILE_TYPES = ('absent', 'file', 'directory', 'other')
ZWC_SUFFIX = '.zwc'
PATH_MAX = 4096
MAX_ID = 2 ** 32 - 1
MAX_OPTIONS = 64
MAX_GAPS = 32
MAX_MTIME = 2 ** 63 - 1
SESSIONS = ('noninteractive', 'interactive', 'login', 'interactive_login')
# Options modelled here. ``-c``/``-s``/``-i``/``-l`` and their long forms only select the
# session kind or the command source.
FLAG_OPTIONS = {
    '-f': 'no_rcs', '--no-rcs': 'no_rcs', '--norcs': 'no_rcs',
    '-d': 'no_global_rcs', '--no-globalrcs': 'no_global_rcs', '--noglobalrcs': 'no_global_rcs',
    '-p': 'privileged', '--privileged': 'privileged',
    '-l': 'login', '--login': 'login',
    '-i': 'interactive', '--interactive': 'interactive',
    '-c': 'command', '-s': 'stdin', '--shinstdin': 'stdin',
}
# Order of sourcing. ``scope`` is ``global`` (GLOBAL_RCS applies) or ``user``.
STEPS = (
    ('env', 'global', 'zshenv'), ('env', 'user', '.zshenv'),
    ('login', 'global', 'zprofile'), ('login', 'user', '.zprofile'),
    ('interactive', 'global', 'zshrc'), ('interactive', 'user', '.zshrc'),
    ('login', 'global', 'zlogin'), ('login', 'user', '.zlogin'),
    ('logout', 'user', '.zlogout'), ('logout', 'global', 'zlogout'),
)
BLOCKING = frozenset({
    'input_malformed', 'family_not_observed', 'family_unsupported', 'invocation_not_observed',
    'options_unverified', 'ids_not_observed', 'emulation_not_modelled', 'home_not_observed',
    'zdotdir_not_observed', 'zdotdir_relative', 'file_not_observed', 'compiled_file_unverified',
    'special_file', 'gaps_truncated', 'newuser_not_observed',
})
NEWUSER_CHECKED = ('.zshenv', '.zprofile', '.zshrc', '.zlogin')
MAX_SCRIPT_DIRS = 2
UNOBSERVED = (
    ('File contents are not read. A startup file can change RCS, GLOBAL_RCS or ZDOTDIR, source other files, '
     'exec or exit, which changes which later files run; that is not followed here.'),
    'Search permission on parent directories, POSIX ACLs and security modules are not assessed.',
    'Whether a compiled .zwc dump is valid for its file name is not checked; see compiled_file_unverified.',
    ('A newuser script that runs can autoload zsh-newuser-install or other functions from $fpath; those '
     'are not followed. Files the global zshenv creates before the newuser check are not followed either.'),
    'The passwd shell, chsh history and which programs start zsh are not observed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'reads': 'zsh sources this file.',
    'reads_compiled': 'A .zwc file exists that is at least as new as this file, or this file is missing; zsh '
                      'loads the compiled wordcode instead when the dump is valid, and this file otherwise.',
    'absent': 'No file by this name exists; zsh skips it silently.',
    'skipped_unreadable': 'zsh cannot open this file and skips it silently.',
    'skipped_directory': 'zsh silently skips a directory with this name.',
    'special_file': 'Not a regular file or directory; zsh opens it and reads untracked input (a FIFO blocks).',
    'not_in_session': 'This kind of session does not source this file.',
    'skipped_no_rcs': 'RCS is unset (-f), so only the global zshenv runs.',
    'skipped_no_global_rcs': 'GLOBAL_RCS is unset (-d), so later global files are skipped.',
    'skipped_privileged': 'The shell is privileged (-p, or real and effective ids differ), so user files are '
                          'skipped.',
    'path_too_long': 'The ZDOTDIR path plus the file name reaches PATH_MAX; zsh reports "path too long" and '
                     'skips the file.',
    'skipped_user_files_exist': 'At least one of .zshenv, .zprofile, .zshrc and .zlogin exists, so the zsh/newuser '
                                'module sources no script.',
    'module_unavailable': 'The zsh/newuser module is not installed or cannot load, so no newuser script runs.',
    'not_reached': 'An earlier newuser script directory was found, so this one is not tried.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, detail: str = '') -> None:
    if any(g['code'] == code and g.get('path') == path for g in gaps):
        return
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


def _int(value: Any, upper: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= upper


def _path(value: Any) -> bool:
    return isinstance(value, str) and len(value) < PATH_MAX and not _CONTROL.search(value)


def emulation_for(argv0: str) -> str:
    """Return ``zsh``, ``sh`` or ``ksh`` for an invoked name, as zsh 5.9 does.

    Only the basename counts. A leading ``-`` (login) and then one leading ``r``
    (restricted) are ignored before the first character is checked.
    """
    name = argv0.rsplit('/', 1)[-1]
    if name.startswith('-'):
        name = name[1:]
    if name.startswith('r'):
        name = name[1:]
    if name[:1] in ('s', 'b'):
        return 'sh'
    if name[:1] == 'k':
        return 'ksh'
    return 'zsh'


def _invocation(item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        _gap(gaps, 'invocation_not_observed', detail='No invocation was supplied.')
        return None
    argv0, options, interactive = item.get('argv0'), item.get('options', []), item.get('interactive')
    if not (_path(argv0) and argv0) or not isinstance(interactive, bool) or not isinstance(options, list) \
            or len(options) > MAX_OPTIONS or not all(isinstance(o, str) and _path(o) for o in options):
        _gap(gaps, 'input_malformed', detail='The invocation needs an argv0, an options list and an interactive '
                                             'flag.')
        return None
    flags = set()
    for option in options:
        if option in FLAG_OPTIONS:
            flags.add(FLAG_OPTIONS[option])
        else:
            _gap(gaps, 'options_unverified', detail=f'Option {option!r} is not modelled; it may set or unset '
                                                    'RCS, GLOBAL_RCS or other startup options.')
    if 'interactive' in flags and not interactive:
        _gap(gaps, 'input_malformed', detail='-i makes the shell interactive, but interactive is false.')
        return None
    return {'argv0': argv0, 'flags': flags, 'interactive': interactive,
            'login': argv0.startswith('-') or 'login' in flags}


def _observe(path: str, files: dict[str, Any], gaps: list[dict[str, Any]], *, zwc: bool = False) -> dict[str, Any]:
    item = files.get(path)
    if item is None:
        _gap(gaps, 'file_not_observed', path, 'No followed stat observation was supplied for this path.')
        return {'type': None}
    if not isinstance(item, dict) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', path, 'The observation has no valid type.')
        return {'type': None}
    out: dict[str, Any] = {'type': item['type']}
    if item['type'] == 'absent':
        return out
    if not _int(item.get('mtime'), MAX_MTIME) or (not zwc and item['type'] == 'file'
                                                     and not isinstance(item.get('readable'), bool)):
        _gap(gaps, 'input_malformed', path, 'A present path needs an integer mtime, and a file needs readable '
                                            '(open as the effective user).')
        return {'type': None}
    out['mtime'] = item['mtime']
    out['readable'] = item.get('readable')
    return out


def evaluate(payload: Any) -> dict[str, Any]:
    """Resolve which zsh startup files run, in order, for one invocation.

    ``payload`` keys: ``family`` (``debian``/``rpm``), ``invocation`` (``argv0``,
    ``options``, ``interactive``), ``ids`` (``uid``, ``euid``, ``gid``, ``egid``),
    ``newuser`` (``module``: whether ``zsh/newuser`` loads; ``script_dirs``: the
    build's SITESCRIPT_DIR then SCRIPT_DIR, at most two absolute paths; needed only
    when an interactive session may source the newuser script),
    ``environment`` (``HOME`` and ``ZDOTDIR``, each a string or ``None`` for unset;
    an absent key is unobserved) and ``files``: followed-stat observations keyed by
    absolute path, each ``{'type': absent|file|directory|other, 'mtime', 'readable'}``.
    Observations are needed for every candidate path and its ``.zwc``.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'shell': 'zsh',
                              'emulation': None, 'session': None, 'privileged': None, 'user_dir': None,
                              'sequence': [], 'runs': [], 'gaps': gaps, 'complete': False,
                              'unobserved': list(UNOBSERVED), 'note': NOT_A_VERDICT}
    if not isinstance(payload, dict):
        _gap(gaps, 'input_malformed', detail='The payload must be an object.')
        return result
    family = payload.get('family')
    if family is None:
        _gap(gaps, 'family_not_observed', detail='The distribution family decides where global files live.')
    elif family not in GLOBAL_DIRS:
        _gap(gaps, 'family_unsupported', detail='Only debian and rpm zsh builds are modelled.')
    invocation = _invocation(payload.get('invocation'), gaps)
    ids = payload.get('ids')
    privileged = None
    if isinstance(ids, dict) and all(_int(ids.get(k), MAX_ID) for k in ('uid', 'euid', 'gid', 'egid')):
        privileged = ids['uid'] != ids['euid'] or ids['gid'] != ids['egid']
    else:
        _gap(gaps, 'ids_not_observed', detail='Real and effective uid/gid decide whether user files run.')
    if invocation is not None and 'privileged' in invocation['flags']:
        privileged = True
    result['privileged'] = privileged
    if invocation is not None:
        emulation = emulation_for(invocation['argv0'])
        result['emulation'] = emulation
        result['session'] = ('interactive_login' if invocation['interactive'] else 'login') if invocation['login'] \
            else ('interactive' if invocation['interactive'] else 'noninteractive')
        if emulation != 'zsh':
            _gap(gaps, 'emulation_not_modelled', detail=f'Invoked as {emulation}, zsh reads /etc/profile, '
                                                         '~/.profile and $ENV like that shell; not modelled.')
    user_dir = _user_dir(payload.get('environment'), gaps)
    result['user_dir'] = user_dir
    files = payload.get('files')
    if not isinstance(files, dict):
        _gap(gaps, 'input_malformed', detail='files must be an object keyed by path.')
        files = {}
    if family not in GLOBAL_DIRS or invocation is None or result['emulation'] != 'zsh':
        return _finish(result)
    _sequence(result, invocation, GLOBAL_DIRS[family], user_dir, privileged, files, gaps,
              payload.get('newuser'))
    return _finish(result)


def _user_dir(env: Any, gaps: list[dict[str, Any]]) -> str | None:
    if not isinstance(env, dict) or 'ZDOTDIR' not in env:
        _gap(gaps, 'zdotdir_not_observed', detail='Whether ZDOTDIR is set decides where user files live.')
        return None
    zdotdir = env['ZDOTDIR']
    if zdotdir is None:
        if 'HOME' not in env or env['HOME'] is None:
            _gap(gaps, 'home_not_observed', detail='ZDOTDIR is unset and HOME was not supplied.')
            return None
        zdotdir = env['HOME']
    if not _path(zdotdir):
        _gap(gaps, 'input_malformed', detail='ZDOTDIR or HOME is not a usable path string.')
        return None
    if zdotdir and not zdotdir.startswith('/'):
        _gap(gaps, 'zdotdir_relative', detail='A relative directory resolves against the unobserved working '
                                              'directory.')
        return None
    return zdotdir


def _sequence(result: dict[str, Any], invocation: dict[str, Any], global_dir: str, user_dir: str | None,
              privileged: bool | None, files: dict[str, Any], gaps: list[dict[str, Any]],
              newuser: Any = None) -> None:
    flags, login, interactive = invocation['flags'], invocation['login'], invocation['interactive']
    rcs, global_rcs = 'no_rcs' not in flags, 'no_global_rcs' not in flags
    phases = {'env': True, 'login': login, 'interactive': interactive, 'logout': login}
    first = True
    for phase, scope, name in STEPS:
        path = f'{global_dir}/{name}' if scope == 'global' else (f'{user_dir}/{name}' if user_dir is not None
                                                                   else f'$ZDOTDIR/{name}')
        entry: dict[str, Any] = {'phase': phase, 'scope': scope, 'path': path}
        result['sequence'].append(entry)
        always = first
        first = False
        if not phases[phase]:
            entry['decision'] = 'not_in_session'
        elif not always and not rcs:
            entry['decision'] = 'skipped_no_rcs'
        elif scope == 'global' and not always and not global_rcs:
            entry['decision'] = 'skipped_no_global_rcs'
        elif scope == 'user' and privileged is None:
            entry['decision'] = 'unresolved'
        elif scope == 'user' and privileged:
            entry['decision'] = 'skipped_privileged'
        elif scope == 'user' and user_dir is None:
            entry['decision'] = 'unresolved'
        elif scope == 'user' and len(user_dir) + len(name) + 1 >= PATH_MAX:
            entry['decision'] = 'path_too_long'
        else:
            _decide(entry, files, gaps)
        entry['reason'] = REASONS[entry['decision']]
        if entry['decision'] in ('reads', 'reads_compiled'):
            result['runs'].append({'phase': phase, 'path': path, 'compiled': entry.get('compiled')})
        if always and interactive:
            for item in _newuser(rcs, privileged, user_dir, files, gaps, newuser):
                item['reason'] = REASONS[item['decision']]
                result['sequence'].append(item)
                if item['decision'] in ('reads', 'reads_compiled'):
                    result['runs'].append({'phase': 'newuser', 'path': item['path'],
                                           'compiled': item.get('compiled')})


def _newuser(rcs: bool, privileged: bool | None, user_dir: str | None, files: dict[str, Any],
             gaps: list[dict[str, Any]], newuser: Any) -> list[dict[str, Any]]:
    """Entries for the zsh/newuser step of an interactive zsh-emulation shell."""
    entry: dict[str, Any] = {'phase': 'newuser', 'scope': 'script', 'path': '$SCRIPT_DIR/newuser'}
    if not rcs:
        return [{**entry, 'decision': 'skipped_no_rcs'}]
    if privileged is None or user_dir is None:
        return [{**entry, 'decision': 'unresolved'}]
    if privileged:
        return [{**entry, 'decision': 'skipped_privileged'}]
    exists: list[bool | None] = []
    for name in NEWUSER_CHECKED:
        if len(user_dir) + len(name) + 1 >= PATH_MAX:
            exists.append(False)  # access() fails with ENAMETOOLONG
            continue
        observed = _observe(f'{user_dir}/{name}', files, gaps, zwc=True)['type']
        exists.append(None if observed is None else observed != 'absent')
    if any(exists):
        return [{**entry, 'decision': 'skipped_user_files_exist'}]
    if None in exists:
        return [{**entry, 'decision': 'unresolved'}]
    dirs = newuser.get('script_dirs') if isinstance(newuser, dict) else None
    if not isinstance(newuser, dict) or not isinstance(newuser.get('module'), bool) or not isinstance(dirs, list) \
            or len(dirs) > MAX_SCRIPT_DIRS or not all(isinstance(d, str) and _path(d) and d.startswith('/')
                                                      for d in dirs):
        _gap(gaps, 'newuser_not_observed', detail='No user startup file exists, so zsh/newuser may source a '
                                                  'newuser script; whether the module loads and the build\'s '
                                                  'script directories were not supplied.')
        return [{**entry, 'decision': 'unresolved'}]
    if not newuser['module']:
        return [{**entry, 'decision': 'module_unavailable'}]
    out: list[dict[str, Any]] = []
    found = False
    for directory in dirs:
        item: dict[str, Any] = {'phase': 'newuser', 'scope': 'script', 'path': f'{directory.rstrip("/")}/newuser'}
        out.append(item)
        if found:
            item['decision'] = 'not_reached'
            continue
        _decide(item, files, gaps)
        # source() reports "not found" only when no compiled dump loads and open() fails.
        found = item['decision'] not in ('absent', 'skipped_unreadable')
        if item['decision'] == 'unresolved':
            for rest in dirs[len(out):]:
                out.append({'phase': 'newuser', 'scope': 'script', 'path': f'{rest.rstrip("/")}/newuser',
                            'decision': 'unresolved'})
            break
    return out


def _decide(entry: dict[str, Any], files: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    path = entry['path']
    zwc_path = path + ZWC_SUFFIX
    source = _observe(path, files, gaps)
    zwc = _observe(zwc_path, files, gaps, zwc=True)
    if source['type'] is None or zwc['type'] is None:
        entry['decision'] = 'unresolved'
        return
    if zwc['type'] != 'absent' and (source['type'] == 'absent' or zwc['mtime'] >= source['mtime']):
        entry['decision'] = 'reads_compiled'
        entry['compiled'] = zwc_path
        _gap(gaps, 'compiled_file_unverified', zwc_path,
             'zsh loads this compiled file instead when it is a valid dump for this name; its validity and '
             'contents are not checked.')
        return
    if source['type'] == 'other':
        entry['decision'] = 'special_file'
        _gap(gaps, 'special_file', path, REASONS['special_file'])
        return
    entry['decision'] = {'absent': 'absent', 'directory': 'skipped_directory'}.get(source['type']) or (
        'reads' if source['readable'] else 'skipped_unreadable')


def _finish(result: dict[str, Any]) -> dict[str, Any]:
    result['complete'] = not any(g['code'] in BLOCKING for g in result['gaps']) and bool(result['sequence']) \
        and all(e['decision'] != 'unresolved' for e in result['sequence'])
    return result
