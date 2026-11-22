"""Pure ifplugd action contract (roadmap F slice, #1377).

Debian's ``ifplugd`` package runs one root daemon per interface. The init
script ``/etc/init.d/ifplugd`` sources ``/etc/default/ifplugd`` and, for each
interface ``IF`` it starts, runs ``/usr/sbin/ifplugd -i $IF $A``. ``$A`` is
``ARGS_<IF with the first '-' made '_'>`` when that is non-empty and ``ARGS``
otherwise. Both expansions are unquoted.

Whenever the link goes up or down, the daemon forks and calls
``execl(run, run, interface, "up"|"down", extra_arg, NULL)`` as root, with
umask 0022 and ``IFPLUGD_PREVIOUS``/``IFPLUGD_CURRENT`` set. ``run`` defaults to
``/etc/ifplugd/ifplugd.action``. The shipped script runs
``run-parts --arg=IF --arg=up /etc/ifplugd/action.d/`` for ``up`` and the same
with ``--reverse`` for ``down``. It does not pass the extra argument on.

This module takes captured, read-only observations and says which root
programs those events run, with which argv and in which order. The rules are
pinned to:

* ifplugd ``0.28`` with the Debian ``0.28-19.7`` patch series:
  ``src/ifplugd.c`` (``parse_args`` and ``action``), ``debian/ifplugd.init``,
  ``debian/ifplugd.action`` and ``debian/ifupdown.action``.
* debianutils ``5.21`` ``run-parts.c``: without ``--lsbsysinit`` or
  ``--regex``, names must match ``^[a-zA-Z0-9_-]+$``. Names are sorted with
  ``strcoll``. A name whose ``stat`` fails (a broken symlink) is dropped. A
  directory is skipped. A regular file runs when ``access(X_OK)`` succeeds.
  Anything else that is not a directory is reported as an error and skipped. A
  missing directory makes ``run-parts`` exit 1 before anything runs.

``getopt_long`` is modelled as glibc does it with ``POSIXLY_CORRECT`` unset:
arguments are permuted, ``--`` ends options, long options accept unambiguous
prefixes and ``--name=value``. Within ``parse_args``, ``-i``, ``-r`` and ``-x``
keep their last value and ``-p``, ``-q`` and ``-l`` toggle. An unknown option
or an invalid ``-m`` mode exits before the daemon starts. ``-h``, ``-k``,
``-S``, ``-R``, ``-z``, ``-v`` and ``-c`` exit without starting a daemon.

Shell is never evaluated. ``ARGS`` is accepted as an already-expanded value and
split on the default IFS. A word with a pathname-expansion character is a gap.
The run target and an ``action.d`` entry are understood only when their SHA-256
matches the shipped file. Every other run target is still reported as the root
program it is, with a gap for what it does. Unknown, malformed or over-cap
input becomes an explicit coverage gap and never yields a covered result.

It performs no I/O, never runs a command and never authorizes a response action.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
MAX_ENTRIES = 1024
MAX_ARGS = 4096
MAX_WORDS = 256
MAX_GAPS = 256

DAEMON = '/usr/sbin/ifplugd'
DEFAULT_RUN = '/etc/ifplugd/ifplugd.action'
ACTION_D = '/etc/ifplugd/action.d'
IFUPDOWN_ACTION = ACTION_D + '/ifupdown'

# SHA-256 of the files shipped by ifplugd 0.28-19.7 (debian/ifplugd.action and
# debian/ifupdown.action, installed by debian/rules).
SHIPPED_SHA256 = {
    DEFAULT_RUN: '8a8c53c4b7daeaa6f386d073d57572bcc24c8064c593c32dfad2832f0f1d26a4',
    IFUPDOWN_ACTION: 'b17df7e987213cbe9af555e4db35d9746812be119e83b7a70fbdca07fa37a8cf',
}

# getopt_long short-option string from ifplugd 0.28-19.7.
SHORT_OPTIONS = 'asni:r:t:T:u:d:hkbUDfFvm:pqwx:cISRzlMW'
LONG_OPTIONS = {
    'no-auto': 'a', 'no-daemon': 'n', 'no-syslog': 's', 'no-beep': 'b',
    'no-beep-up': 'U', 'no-beep-down': 'D', 'ignore-fail': 'f',
    'ignore-fail-positive': 'F', 'ignore-retval': 'I', 'iface': 'i', 'run': 'r',
    'poll-time': 't', 'poll-utime': 'T', 'delay-up': 'u', 'delay-down': 'd',
    'api-mode': 'm', 'wait-on-fork': 'w', 'wait-on-kill': 'W', 'no-startup': 'p',
    'no-shutdown': 'q', 'help': 'h', 'kill': 'k', 'check-running': 'c',
    'version': 'v', 'extra-arg': 'x', 'suspend': 'S', 'resume': 'R', 'info': 'z',
    'initial-down': 'l', 'monitor': 'M',
}
_TAKES_ARGUMENT = frozenset('irtTudmx')
# parse_args checks these in this order once parsing finishes.
_NO_DAEMON = (('h', 'help'), ('k', 'kill'), ('R', 'resume'), ('S', 'suspend'),
              ('z', 'info'), ('v', 'version'), ('c', 'check_running'))
_API_MODES = frozenset('emwpaiEMWPAI')

FILE_STATES = ('present', 'absent', 'unknown')
DIR_STATES = ('listed', 'absent', 'unknown')
KINDS = ('regular', 'directory', 'broken_symlink', 'other', 'unknown')

_SHA256 = re.compile(r'[0-9a-f]{64}')
_IFNAME = re.compile(r'[^\x00-\x20/\x7f]{1,15}')
_ENTRY_NAME = re.compile(r'[^\x00/]{1,255}')
_RUN_PARTS_NAME = re.compile(r'[a-zA-Z0-9_-]+')
_IFS = re.compile(r'[ \t\n]+')
_GLOB = re.compile(r'[*?\[]')
_PATH = re.compile(r'/[^\x00]{0,4095}')


class Invalid(ValueError):
    """The observation does not have the documented shape."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps[-1] = {'code': 'gaps_truncated'}


def _file(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Invalid(f'{name} must be an object')
    state = value.get('state')
    if state not in FILE_STATES:
        raise Invalid(f'{name}.state is invalid')
    kind = value.get('kind', 'unknown')
    if kind not in KINDS:
        raise Invalid(f'{name}.kind is invalid')
    executable = value.get('executable')
    if executable is not None and not isinstance(executable, bool):
        raise Invalid(f'{name}.executable is invalid')
    digest = value.get('sha256')
    if digest is not None and (not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
        raise Invalid(f'{name}.sha256 is invalid')
    present = state == 'present'
    return {'state': state, 'kind': kind if present else None,
            'executable': executable if present else None,
            'sha256': digest if present else None}


def _directory(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Invalid(f'{name} must be an object')
    state = value.get('state')
    if state not in DIR_STATES:
        raise Invalid(f'{name}.state is invalid')
    if state != 'listed':
        return {'state': state, 'entries': [], 'complete': False}
    raw = value.get('entries', [])
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
        raise Invalid(f'{name}.entries is invalid')
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise Invalid(f'{name} entry must be an object')
        entry_name = item.get('name')
        if not isinstance(entry_name, str) or not _ENTRY_NAME.fullmatch(entry_name) or entry_name in ('.', '..'):
            raise Invalid(f'{name} entry name is invalid')
        if entry_name in seen:
            raise Invalid(f'{name} entry {entry_name!r} is duplicated')
        seen.add(entry_name)
        entry = _file({**item, 'state': 'present'}, f'{name} entry {entry_name!r}')
        entries.append({'name': entry_name, 'kind': entry['kind'],
                        'executable': entry['executable'], 'sha256': entry['sha256']})
    complete = value.get('complete', True)
    if not isinstance(complete, bool):
        raise Invalid(f'{name}.complete is invalid')
    return {'state': state, 'entries': entries, 'complete': complete}


def daemon_words(interface: str, args: str) -> tuple[list[str], list[dict[str, Any]]]:
    """Return the argv words after the program name for ``ifplugd -i $IF $A``."""
    gaps: list[dict[str, Any]] = []
    words = ['-i', interface]
    for word in _IFS.split(args):
        if not word:
            continue
        if _GLOB.search(word):
            # The unquoted expansion is also subject to pathname expansion in
            # the init script's working directory, which is not observed.
            _gap(gaps, 'args_pathname_expansion', word=word)
        words.append(word)
    if len(words) > MAX_WORDS:
        raise Invalid('ARGS has too many words')
    return words, gaps


def parse_options(words: list[str]) -> dict[str, Any]:
    """Model ifplugd 0.28-19.7 ``parse_args`` over ``words`` (argv[1:])."""
    state: dict[str, Any] = {
        'interface': None, 'run': DEFAULT_RUN, 'extra_arg': None,
        'no_startup_script': False, 'no_shutdown_script': False,
        'initial_down': False, 'flags': set(), 'exit': None,
    }

    def apply(letter: str, value: str | None) -> bool:
        if letter == 'i':
            state['interface'] = value
        elif letter == 'r':
            state['run'] = value
        elif letter == 'x':
            state['extra_arg'] = value
        elif letter == 'p':
            state['no_startup_script'] = not state['no_startup_script']
        elif letter == 'q':
            state['no_shutdown_script'] = not state['no_shutdown_script']
        elif letter == 'l':
            state['initial_down'] = not state['initial_down']
        elif letter == 'm' and (not value or value[0] not in _API_MODES):
            # tolower(optarg[0]) in the C locale; an empty argument reads the
            # terminating NUL and is refused too.
            state['exit'] = 'unknown_api_mode'
            return False
        state['flags'].add(letter)
        return True

    index = 0
    while index < len(words):
        word = words[index]
        index += 1
        if word == '--':
            break
        if not word.startswith('-') or word == '-':
            continue  # permuted non-option; parse_args never reads it
        if word.startswith('--'):
            body = word[2:]
            name, has_value, value = body.partition('=')
            if name in LONG_OPTIONS:
                matches = [name]
            else:
                matches = [option for option in LONG_OPTIONS if option.startswith(name)]
            if len(matches) != 1:
                state['exit'] = 'ambiguous_option' if matches else 'unknown_option'
                break
            letter = LONG_OPTIONS[matches[0]]
            if letter in _TAKES_ARGUMENT:
                if not has_value:
                    if index >= len(words):
                        state['exit'] = 'missing_argument'
                        break
                    value = words[index]
                    index += 1
            elif has_value:
                state['exit'] = 'unexpected_argument'
                break
            if not apply(letter, value if letter in _TAKES_ARGUMENT else None):
                break
            continue
        position = 1
        stop = False
        while position < len(word):
            letter = word[position]
            position += 1
            if letter == ':' or letter not in SHORT_OPTIONS:
                state['exit'] = 'unknown_option'
                stop = True
                break
            value = None
            if letter in _TAKES_ARGUMENT:
                if position < len(word):
                    value = word[position:]
                elif index < len(words):
                    value = words[index]
                    index += 1
                else:
                    state['exit'] = 'missing_argument'
                    stop = True
                    break
                position = len(word)
            if not apply(letter, value):
                stop = True
                break
        if stop:
            break

    if state['exit'] is None:
        for letter, reason in _NO_DAEMON:
            if letter in state['flags']:
                state['exit'] = reason
                break
    if state['interface'] is None:
        state['interface'] = 'eth0'
    state['flags'] = sorted(state['flags'])
    return state


def _collation_safe(names: list[str]) -> bool:
    """True when common ``strcoll`` orders agree with byte order for ``names``.

    Names here match ``[a-zA-Z0-9_-]+``. glibc locales such as ``en_US``
    ignore ``-`` and ``_`` and fold case at the first level, while ``C``
    compares bytes. The order is stated only when both rules give the same
    strict order.
    """
    keys = [name.replace('-', '').replace('_', '').lower() for name in names]
    if len(set(keys)) != len(keys):
        return False
    return sorted(names) == [name for _, name in sorted(zip(keys, names))]


def _run_parts(directory: dict[str, Any], interface: str, event: str,
               gaps: list[dict[str, Any]]) -> dict[str, Any]:
    if directory['state'] == 'absent':
        return {'state': 'directory_missing', 'programs': [], 'skipped': []}
    if directory['state'] != 'listed':
        _gap(gaps, 'action_d_unobserved', path=ACTION_D)
        return {'state': 'unknown', 'programs': [], 'skipped': []}
    if not directory['complete']:
        _gap(gaps, 'action_d_incomplete', path=ACTION_D)
    selected = [entry for entry in directory['entries'] if _RUN_PARTS_NAME.fullmatch(entry['name'])]
    skipped = [{'name': entry['name'], 'reason': 'name_not_matched'}
               for entry in directory['entries'] if not _RUN_PARTS_NAME.fullmatch(entry['name'])]
    selected.sort(key=lambda entry: entry['name'].encode())
    names = [entry['name'] for entry in selected]
    order_known = _collation_safe(names)
    programs: list[dict[str, Any]] = []
    for entry in selected:
        path = f"{ACTION_D}/{entry['name']}"
        kind = entry['kind']
        if kind == 'broken_symlink':
            skipped.append({'name': entry['name'], 'reason': 'stat_failed'})
            continue
        if kind == 'directory':
            skipped.append({'name': entry['name'], 'reason': 'directory'})
            continue
        if kind == 'other':
            skipped.append({'name': entry['name'], 'reason': 'not_regular_file'})
            continue
        if kind != 'regular' or entry['executable'] is None:
            _gap(gaps, 'action_entry_unobserved', path=path)
            programs.append({'path': path, 'certain': False})
            continue
        if not entry['executable']:
            skipped.append({'name': entry['name'], 'reason': 'not_executable'})
            continue
        program: dict[str, Any] = {'path': path, 'certain': True,
                                   'argv': [path, interface, event], 'account': 'root'}
        shipped = SHIPPED_SHA256.get(path)
        if shipped is not None and entry['sha256'] == shipped:
            program['shipped'] = True
            program['runs'] = [{'argv': ['/sbin/ifup' if event == 'up' else '/sbin/ifdown', interface],
                                'account': 'root'}]
        else:
            program['shipped'] = False
        programs.append(program)
    if not order_known and len(programs) > 1:
        _gap(gaps, 'order_locale_dependent', path=ACTION_D, names=names)
    if event == 'down':
        programs.reverse()
    return {'state': 'listed', 'programs': programs, 'skipped': skipped,
            'order': 'byte' if order_known else 'unresolved'}


def resolve(observation: Any) -> dict[str, Any]:
    """Return which root programs ifplugd runs for one init-script interface.

    ``observation`` keys:

    * ``interface``: the interface name the init script loop starts.
    * ``args``: ``{'state': 'known'|'unknown', 'value': str}``, the expanded
      value of ``$A`` (``ARGS_<IF>`` or ``ARGS``) after sourcing
      ``/etc/default/ifplugd``.
    * ``run_targets``: ``{path: file}`` for any path the argv can name; each
      file is ``{'state', 'kind', 'executable', 'sha256'}``.
    * ``action_d``: ``{'state': 'listed'|'absent'|'unknown', 'entries': [...],
      'complete': bool}``; each entry has ``name``, ``kind``, ``executable``
      and optional ``sha256``, with ``kind`` describing the ``stat`` target.
    """
    if not isinstance(observation, dict):
        raise Invalid('observation must be an object')
    interface = observation.get('interface')
    if not isinstance(interface, str) or not _IFNAME.fullmatch(interface):
        raise Invalid('interface is invalid')
    args = observation.get('args')
    if not isinstance(args, dict) or args.get('state') not in ('known', 'unknown'):
        raise Invalid('args is invalid')
    targets_raw = observation.get('run_targets', {})
    if not isinstance(targets_raw, dict) or len(targets_raw) > 16:
        raise Invalid('run_targets is invalid')
    targets: dict[str, dict[str, Any]] = {}
    for path, value in targets_raw.items():
        if not isinstance(path, str) or not _PATH.fullmatch(path):
            raise Invalid('run_targets path is invalid')
        targets[path] = _file(value, f'run_targets[{path!r}]')
    action_d = _directory(observation.get('action_d', {'state': 'unknown'}), 'action_d')

    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'interface': interface,
        'daemon': None, 'events': {}, 'gaps': gaps, 'covered': False,
        'unobserved': ['init_script_selection', 'running_instance_check', 'daemon_locale',
                       'run_parts_path_lookup'],
    }
    if args['state'] != 'known':
        _gap(gaps, 'args_unobserved')
        return result
    value = args.get('value')
    if not isinstance(value, str) or len(value) > MAX_ARGS or '\x00' in value:
        raise Invalid('args.value is invalid')
    words, split_gaps = daemon_words(interface, value)
    for gap in split_gaps:
        _gap(gaps, **gap)
    options = parse_options(words)
    daemon = {
        'argv': [DAEMON, *words], 'account': 'root',
        'interface': options['interface'], 'run': options['run'],
        'extra_arg': options['extra_arg'],
        'starts': options['exit'] is None, 'exit_reason': options['exit'],
        'runs_on_startup': 'up' if not options['no_startup_script'] else None,
        'runs_on_shutdown': None if options['no_shutdown_script'] else 'down',
    }
    if options['initial_down']:
        daemon['runs_on_startup'] = 'up_or_down'
    result['daemon'] = daemon
    # A later -i in ARGS makes this daemon watch a different interface.
    daemon['interface_overridden'] = options['interface'] != interface
    if not daemon['starts']:
        result['covered'] = not gaps
        return result

    run = options['run']
    target = targets.get(run)
    if target is None or target['state'] == 'unknown':
        _gap(gaps, 'run_target_unobserved', path=run)
        result['covered'] = False
        return result
    if target['state'] == 'absent' or target['kind'] in ('broken_symlink', 'directory', 'other'):
        daemon['run_state'] = 'exec_fails'
        result['covered'] = not gaps
        return result
    if target['kind'] != 'regular' or target['executable'] is None:
        _gap(gaps, 'run_target_unobserved', path=run)
        return result
    if not target['executable']:
        daemon['run_state'] = 'exec_fails'
        result['covered'] = not gaps
        return result

    tail = [options['extra_arg']] if options['extra_arg'] is not None else []
    stock = run == DEFAULT_RUN and target['sha256'] == SHIPPED_SHA256[DEFAULT_RUN]
    daemon['run_state'] = 'stock_action' if stock else 'custom_program'
    for event in ('up', 'down'):
        invocation: dict[str, Any] = {'argv': [run, options['interface'], event, *tail], 'account': 'root'}
        if stock:
            invocation['run_parts'] = _run_parts(action_d, options['interface'], event, gaps)
        result['events'][event] = invocation
    if not stock:
        _gap(gaps, 'run_target_not_modelled', path=run, sha256=target['sha256'])
    result['covered'] = not gaps
    return result
