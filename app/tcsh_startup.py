"""Pure tcsh/csh startup-file contract (roadmap F slice, #1463).

Takes one tcsh invocation (invoked name and arguments), the build's ``$version``
option words, the ``HOME`` it starts with and supplied followed-``stat`` metadata
for each candidate file. It says which system and per-user startup files the shell
sources, in which order, and which run only when a login shell logs out. It never
reads a file's contents.

Semantics were checked against Ubuntu 24.04 tcsh 6.24.10 (``csh`` is the same
binary through alternatives), run as root and as an unprivileged user, not recalled:

* Every shell, including a non-interactive ``-c`` shell or a script, sources
  ``/etc/csh.cshrc``; a login shell then sources ``/etc/csh.login``. Every shell
  then sources ``~/.tcshrc`` or, only when ``~/.tcshrc`` cannot be opened (absent,
  dangling or unreadable), ``~/.cshrc``. A login shell then sources ``~/.login``
  and ``~/.cshdirs``; ``-d`` makes a non-login shell source ``~/.cshdirs`` too.
  ``~/.cshdirs`` is executed (it normally holds ``pushd`` commands) whether or not
  ``savedirs`` is set. ``~/.history`` is loaded into the history list and is not
  executed.
* A directory named ``~/.tcshrc`` (readable or not) stops the ``~/.cshrc``
  fallback and runs nothing. Any other absent, unreadable or directory file is
  skipped silently. File ownership, ``-m`` and differing real and effective ids do
  not change which files run. An error inside a file (an undefined variable or a
  syntax error, but not a command that is not found) stops every later startup
  file, ``~/.cshdirs`` included; contents are not read, so that is disclosed, not
  modelled.
* When a login shell logs out it sources ``/etc/csh.logout`` and then
  ``~/.logout``: on ``logout``, and on ``exit``, end of input or hangup when the
  shell reads a terminal. ``exec`` ends it without them. A startup error does not
  stop them.
* A login shell is one whose invoked name starts with ``-``, or whose only
  argument is ``-l``; an option word containing ``l`` alongside any other argument
  is rejected and the shell does not start. ``-f``, or an unset ``HOME``, skips
  every startup file, the system files included; the logout files still run, except
  ``~/.logout`` when ``HOME`` is unset. An empty ``HOME`` makes the user files
  resolve under ``/``. A relative ``HOME`` resolves against the working directory,
  which is not observed. Wildcards in ``HOME`` are not expanded.
* Options are parsed until the first word that does not start with ``-`` (a lone
  ``-`` included), which is the script or its arguments. A word with ``c`` takes
  the next word as the command, and option parsing continues after it.
* A build whose ``$version`` lists ``lf`` (LOGINFIRST) reads the login files
  earlier; that order is not modelled. Only the Debian/Ubuntu build is verified.

It performs no I/O, never runs a command and never authorizes a response action.
Unobserved or malformed metadata, unknown options, unsupported builds, relative
``HOME``, special files and over-limit input are explicit blocking gaps, and the
result is never reported complete with any of them.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'shell': 'tcsh 6.24.10 (Ubuntu 24.04)'}
FAMILIES = ('debian',)
SYSTEM = {'cshrc': '/etc/csh.cshrc', 'login': '/etc/csh.login', 'logout': '/etc/csh.logout'}
FILE_TYPES = ('absent', 'file', 'directory', 'other')
PATH_MAX = 4096
MAX_ARGUMENTS = 64
MAX_BUILD_OPTIONS = 64
MAX_GAPS = 32
# Option letters with no effect on which startup files run. ``c`` takes the next argument as the command.
NEUTRAL_FLAGS = frozenset('ceimqstvxVXF')
LOGIN_FIRST = 'lf'
BLOCKING = frozenset({
    'input_malformed', 'family_not_observed', 'family_unsupported', 'invocation_not_observed',
    'options_unverified', 'build_not_observed', 'build_order_unsupported', 'home_not_observed', 'home_relative',
    'file_not_observed', 'special_file', 'gaps_truncated',
})
UNOBSERVED = (
    ('File contents are not read. A startup file can set home, dirsfile or histfile, source other files, exec or '
     'exit, which changes which later files run; that is not followed here.'),
    ('An error inside a startup file, such as an undefined variable or a syntax error, stops every later startup '
     'file; the runs listed assume none occurs.'),
    'Whether a script operand opens is not observed; when it does not, tcsh exits before any startup file.',
    ('Whether a login shell reads a terminal, which decides if exit or end of input runs the logout files, is not '
     'observed.'),
    'Search permission on parent directories, POSIX ACLs and security modules are not assessed.',
    'The passwd shell, chsh history and which programs start tcsh are not observed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'reads': 'tcsh sources this file.',
    'absent': 'No file by this name exists; tcsh skips it silently.',
    'skipped_unreadable': 'tcsh cannot open this file and skips it silently.',
    'skipped_directory': 'tcsh silently skips a directory with this name.',
    'opened_directory': 'A directory with this name counts as found, so tcsh runs nothing from it and does not fall '
                        'back to ~/.cshrc.',
    'special_file': 'Not a regular file or directory; tcsh opens it and reads untracked input (a FIFO blocks).',
    'fallback_not_used': '~/.tcshrc opened, so ~/.cshrc is not read.',
    'not_in_session': 'This kind of session does not source this file.',
    'skipped_fast': 'The -f option skips every startup file.',
    'skipped_no_home': 'HOME is unset, so tcsh skips every startup file and ~/.logout.',
    'not_started': 'tcsh rejects -l with other arguments and does not start.',
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


def _text(value: Any) -> bool:
    return isinstance(value, str) and len(value) < PATH_MAX and not _CONTROL.search(value)


def parse_arguments(arguments: list[str]) -> dict[str, Any]:
    """Classify tcsh arguments the way tcsh 6.24.10 reads its options.

    Options are leading ``-`` words whose letters may be combined (``-fc``). A word
    with ``c`` takes the next word as the command and parsing continues after it;
    the first other word without a leading ``-``, or a lone ``-``, ends parsing. Returns the
    login/fast/dirs flags, whether ``-l`` is rejected and any unmodelled letters.
    """
    out: dict[str, Any] = {'login': False, 'fast': False, 'dirs': False, 'rejected': False, 'unmodelled': []}
    if arguments == ['-l']:
        out['login'] = True
        return out
    index = 0
    while index < len(arguments):
        word = arguments[index]
        if not word.startswith('-') or word == '-':
            break
        letters = word[1:]
        for letter in letters:
            if letter == 'l':
                out['rejected'] = True
            elif letter == 'f':
                out['fast'] = True
            elif letter == 'd':
                out['dirs'] = True
            elif letter not in NEUTRAL_FLAGS:
                out['unmodelled'].append(f'-{letter}')
        index += 1
        if 'c' in letters:
            if index >= len(arguments):
                out['unmodelled'].append('-c without a command')
            index += 1
    return out


def _invocation(item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        _gap(gaps, 'invocation_not_observed', detail='No invocation was supplied.')
        return None
    argv0, arguments = item.get('argv0'), item.get('arguments', [])
    if not (_text(argv0) and argv0) or not isinstance(arguments, list) or len(arguments) > MAX_ARGUMENTS \
            or not all(_text(a) for a in arguments):
        _gap(gaps, 'input_malformed', detail='The invocation needs an argv0 and an arguments list.')
        return None
    parsed = parse_arguments(arguments)
    for option in parsed['unmodelled']:
        _gap(gaps, 'options_unverified', detail=f'Option {option!r} is not modelled; it may change how tcsh '
                                                'starts or which files it reads.')
    parsed['login'] = parsed['login'] or argv0.startswith('-')
    return parsed


def _build(options: Any, gaps: list[dict[str, Any]]) -> None:
    if not isinstance(options, list) or len(options) > MAX_BUILD_OPTIONS or not all(_text(o) for o in options):
        _gap(gaps, 'build_not_observed', detail='The option words of the build\'s $version (from tcsh -f) decide '
                                                'whether login files are read first.')
    elif LOGIN_FIRST in options:
        _gap(gaps, 'build_order_unsupported', detail='This build reads login files first (lf); that order is not '
                                                     'modelled.')


def _home(env: Any, gaps: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """Return (observed, home). ``home`` is ``None`` when HOME is unset."""
    if not isinstance(env, dict) or 'HOME' not in env:
        _gap(gaps, 'home_not_observed', detail='Whether HOME is set decides whether any startup file runs.')
        return False, None
    home = env['HOME']
    if home is None:
        return True, None
    if not _text(home):
        _gap(gaps, 'input_malformed', detail='HOME is not a usable path string.')
        return False, None
    if home and not home.startswith('/'):
        _gap(gaps, 'home_relative', detail='A relative HOME resolves against the unobserved working directory.')
        return False, None
    return True, home


def _observe(path: str, files: dict[str, Any], gaps: list[dict[str, Any]]) -> str | None:
    """Return ``absent``, ``file``, ``unreadable``, ``directory`` or ``other``; ``None`` when unknown."""
    item = files.get(path)
    if item is None:
        _gap(gaps, 'file_not_observed', path, 'No followed stat observation was supplied for this path.')
        return None
    if not isinstance(item, dict) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', path, 'The observation has no valid type.')
        return None
    if item['type'] == 'file':
        if not isinstance(item.get('readable'), bool):
            _gap(gaps, 'input_malformed', path, 'A file needs readable (open as the effective user).')
            return None
        return 'file' if item['readable'] else 'unreadable'
    if item['type'] == 'other':
        _gap(gaps, 'special_file', path, REASONS['special_file'])
    return item['type']


DECISIONS = {'file': 'reads', 'absent': 'absent', 'unreadable': 'skipped_unreadable',
             'directory': 'skipped_directory', 'other': 'special_file', None: 'unresolved'}


def evaluate(payload: Any) -> dict[str, Any]:
    """Resolve which tcsh startup files run, in order, for one invocation.

    ``payload`` keys: ``family`` (``debian``), ``build_options`` (the option words
    of the build's ``$version``, read with ``tcsh -f``), ``invocation`` (``argv0``
    and ``arguments``, the words after argv0), ``environment`` (``HOME``: a string,
    or ``None`` for unset; an absent key is unobserved) and ``files``: followed-stat
    observations keyed by absolute path, each ``{'type': absent|file|directory|other,
    'readable'}`` (``readable`` is required for a file).
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'shell': 'tcsh',
                              'session': None, 'home': None, 'sequence': [], 'runs': [], 'gaps': gaps,
                              'complete': False, 'unobserved': list(UNOBSERVED), 'note': NOT_A_VERDICT}
    if not isinstance(payload, dict):
        _gap(gaps, 'input_malformed', detail='The payload must be an object.')
        return result
    family = payload.get('family')
    if family is None:
        _gap(gaps, 'family_not_observed', detail='The distribution family decides the system file paths.')
    elif family not in FAMILIES:
        _gap(gaps, 'family_unsupported', detail='Only the Debian/Ubuntu tcsh build is modelled.')
    _build(payload.get('build_options'), gaps)
    invocation = _invocation(payload.get('invocation'), gaps)
    observed, home = _home(payload.get('environment'), gaps)
    result['home'] = home
    files = payload.get('files')
    if not isinstance(files, dict):
        _gap(gaps, 'input_malformed', detail='files must be an object keyed by path.')
        files = {}
    if invocation is not None:
        result['session'] = 'login' if invocation['login'] else 'nonlogin'
    if family in FAMILIES and invocation is not None:
        _sequence(result, invocation, observed, home, files, gaps)
    return _finish(result)


def _sequence(result: dict[str, Any], invocation: dict[str, Any], observed: bool, home: str | None,
              files: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    login = invocation['login']
    user = (home.rstrip('/') if home is not None else '$HOME') + '/'
    steps = (
        ('startup', 'system', SYSTEM['cshrc'], True),
        ('startup', 'system', SYSTEM['login'], login),
        ('startup', 'user', user + '.tcshrc', True),
        ('startup', 'user', user + '.cshrc', True),
        ('startup', 'user', user + '.login', login),
        ('startup', 'user', user + '.cshdirs', login or invocation['dirs']),
        ('logout', 'system', SYSTEM['logout'], login),
        ('logout', 'user', user + '.logout', login),
    )
    fallback: str | None = None  # decision for ~/.tcshrc, which decides the ~/.cshrc fallback
    for phase, scope, path, in_session in steps:
        entry: dict[str, Any] = {'phase': phase, 'scope': scope, 'path': path}
        result['sequence'].append(entry)
        if invocation['rejected']:
            entry['decision'] = 'not_started'
        elif not in_session:
            entry['decision'] = 'not_in_session'
        elif phase == 'startup' and invocation['fast']:
            entry['decision'] = 'skipped_fast'
        elif not observed:
            entry['decision'] = 'unresolved'
        elif home is None and (phase == 'startup' or scope == 'user'):
            entry['decision'] = 'skipped_no_home'
        elif scope == 'user' and len(path) >= PATH_MAX:
            entry['decision'] = 'unresolved'
            _gap(gaps, 'input_malformed', path, 'The path reaches PATH_MAX.')
        elif path.endswith('/.cshrc') and fallback not in ('absent', 'skipped_unreadable'):
            entry['decision'] = 'unresolved' if fallback in ('unresolved', 'special_file') else 'fallback_not_used'
        else:
            kind = _observe(path, files, gaps)
            entry['decision'] = DECISIONS[kind]
            if path.endswith('/.tcshrc') and kind == 'directory':
                entry['decision'] = 'opened_directory'
        if path.endswith('/.tcshrc'):
            fallback = entry['decision']
        entry['reason'] = REASONS[entry['decision']]
        if entry['decision'] == 'reads':
            result['runs'].append({'phase': phase, 'path': path})


def _finish(result: dict[str, Any]) -> dict[str, Any]:
    result['complete'] = not any(g['code'] in BLOCKING for g in result['gaps']) and bool(result['sequence']) \
        and all(e['decision'] != 'unresolved' for e in result['sequence'])
    return result
