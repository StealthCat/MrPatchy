"""Pure pppd hook contract (roadmap F slice, #1091).

Takes the captured text of ``/etc/ppp/options`` and ``/etc/ppp/peers/*`` plus
read-only file and directory metadata, and says which programs pppd runs **as
root** on each link event, and why other entries do not run. It never reads
script contents.

The rules were read from ``ppp_2.5.2.orig.tar.gz`` (sha256 ``47da358d...33cb2``)
and ``ppp_2.5.2-1+2build1.debian.tar.xz`` (sha256 ``ef4ad7b7...0d873``) from
archive.ubuntu.com:

* Default script paths come from ``pppd/pathnames.h``. Debian's ``zzz_config``
  patch does not change them.
* ``net-init-script``, ``net-pre-up-script``, ``net-down-script``,
  ``ip-up-script``, ``ip-down-script``, ``ip-pre-up-script``, ``ipv6-up-script``
  and ``ipv6-down-script`` replace those defaults. They are ``OPT_PRIV|OPT_STATIC``
  and have no ``OPT_PRIO``, so ``process_option`` copies each new value over the
  old one: the last privileged occurrence wins. ``main.c`` reads
  ``/etc/ppp/options`` first, then ``~/.ppprc`` and then the command line, where
  ``call <peer>`` reads ``/etc/ppp/peers/<peer>`` at its position. A tty
  options file is read later. ``auth-up`` and ``auth-down`` cannot be
  overridden.
* ``run_program`` calls ``stat`` (following symlinks) and runs the path only
  when it is a regular file with any execute bit. A missing path is skipped
  silently. The child calls ``setuid(0)``, changes to ``/`` and calls
  ``execve`` with a cleared environment, so the program runs as root.
* The Debian package ships the ``ip-up``, ``ip-down``, ``ip-pre-up``,
  ``ipv6-up`` and ``ipv6-down`` wrappers, but no ``auth-*`` or ``net-*`` files.
  Each wrapper ``exec``s ``/etc/ppp/<name>.local`` when ``[ -x ]`` holds for
  it, which replaces the next step. Otherwise it runs
  ``run-parts /etc/ppp/<name>.d`` without ``--lsbsysinit``.
  Those directory rules are only applied when the caller says the wrapper is
  package-verified and unchanged. Package ownership alone is not enough.

It performs no I/O, never runs a command and never authorizes a response
action. Unobserved or malformed input, unsupported versions or families,
unverified wrappers, option syntax this parser does not model and over-limit
input are explicit blocking gaps. No record is labelled safe, and ``origin`` is
always ``not_assessed``.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

from app.dhclient_hooks import run_parts_name

CONTRACT_VERSION = 1
REFERENCE = {
    'package': 'ppp',
    'version': '2.5.2-1+2build1',
    'upstream_sha256': '47da358de54a10cb10bf6ff2cf9b1c03c0d3555518f6182e8f701b8e55733cb2',
    'debian_sha256': 'ef4ad7b76fac9246ca5fbb8002adae035acbe8939797791e8e994543c6d0d873',
    'run_parts': 'debianutils run-parts without --lsbsysinit',
}
MAX_FILES = 1024
MAX_PEERS = 256
MAX_TEXT = 65536
MAX_WORD = 1024  # pppd MAXWORDLEN; longer words are truncated
MAX_PATH = 4096
MAX_GAPS = 64

CONF_DIR = '/etc/ppp'
OPTIONS_FILE = '/etc/ppp/options'
PEERS_DIR = '/etc/ppp/peers'
# event -> (default path, override option or None, shipped Debian wrapper, when it runs)
EVENTS = {
    'net-init': ('/etc/ppp/net-init', 'net-init-script', False,
                 'Once, when pppd starts, before the link is established (main.c).'),
    'net-pre-up': ('/etc/ppp/net-pre-up', 'net-pre-up-script', False,
                   'Before the network phase starts; pppd waits for it (main.c).'),
    'net-down': ('/etc/ppp/net-down', 'net-down-script', False,
                 'When the network phase ends (main.c).'),
    'auth-up': ('/etc/ppp/auth-up', None, False,
                'After the peer authenticates successfully (auth.c).'),
    'auth-down': ('/etc/ppp/auth-down', None, False,
                  'When an authenticated link goes down (auth.c).'),
    'ip-pre-up': ('/etc/ppp/ip-pre-up', 'ip-pre-up-script', True,
                  'Before the IPv4 interface is brought up; pppd waits for it (ipcp.c).'),
    'ip-up': ('/etc/ppp/ip-up', 'ip-up-script', True,
              'When IPCP brings IPv4 up (ipcp.c).'),
    'ip-down': ('/etc/ppp/ip-down', 'ip-down-script', True,
                'When IPv4 goes down (ipcp.c).'),
    'ipv6-up': ('/etc/ppp/ipv6-up', 'ipv6-up-script', True,
                'When IPV6CP brings IPv6 up (ipv6cp.c).'),
    'ipv6-down': ('/etc/ppp/ipv6-down', 'ipv6-down-script', True,
                  'When IPv6 goes down (ipv6cp.c).'),
}
OPTION_EVENTS = {option: event for event, (_, option, _, _) in EVENTS.items() if option}
SHIPPED_WRAPPERS = frozenset(spec[0] for spec in EVENTS.values() if spec[2])
WRAPPER_DIR_PATHS = frozenset(path + '.d' for path in SHIPPED_WRAPPERS)
OBSERVED_DIRS = (CONF_DIR, PEERS_DIR) + tuple(sorted(WRAPPER_DIR_PATHS))
FILE_TYPES = ('file', 'symlink', 'directory', 'other')
TARGET_TYPES = ('file', 'directory', 'other')
DIR_STATES = ('listed', 'absent', 'unreadable')
WRAPPER_STATES = ('unchanged', 'modified', 'unverified')
BLOCKING = frozenset({
    'input_malformed', 'too_many_files', 'too_many_peers', 'text_too_large', 'duplicate_path', 'metadata_missing',
    'symlink_target_unobserved', 'directory_not_observed', 'directory_unreadable', 'options_not_observed',
    'option_syntax_unsupported', 'option_missing_argument', 'include_not_followed', 'override_path_relative',
    'wrapper_not_verified', 'version_not_observed', 'version_unsupported', 'family_not_observed',
    'family_unsupported', 'gaps_truncated',
})
UNOBSERVED = (
    'Script contents are not read. A wrapper or hook can run anything as root.',
    ('The pppd command line, ~/.ppprc of the invoking user, /etc/ppp/options.<tty> files and peer files named by '
     'the "file" or "call" options are not observed. Any of them can override a script path.'),
    'Options that run other commands (connect, disconnect, init, pty, welcome, plugin) are not assessed here.',
    ('Option words are matched by name. An option that takes an argument equal to a script option name would be '
     'misread; pppd itself does not allow this to set a script path.'),
    'Whether pppd is installed, which peers are used and which link events occur are not observed.',
)
NOT_A_VERDICT = 'File metadata and option text only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'runs_as_root': 'pppd runs this regular executable file as root for the event.',
    'missing': 'The path does not exist, so pppd skips it silently.',
    'not_regular': 'pppd only runs a regular file after following symlinks.',
    'not_executable': 'pppd only runs a file with at least one execute bit set.',
    'unresolvable_symlink': 'The symlink cannot be followed (dangling or looping), so pppd treats it as missing.',
    'local_replaces': 'The wrapper execs its executable .local file instead of running run-parts.',
    'local_exec_fails': ('[ -x ] holds for the .local entry but it is not a regular file, so the wrapper\'s exec '
                         'fails and nothing after it runs.'),
    'run_parts': 'The wrapper runs this entry as root through run-parts.',
    'skipped_by_local': 'An executable .local file replaces run-parts, so this directory entry does not run.',
    'name_filtered': 'run-parts without --lsbsysinit runs only names made of letters, digits, "_" and "-".',
    'nested_entry': 'run-parts does not descend into subdirectories.',
    'directory_not_used': 'The containing run-parts directory is absent, so it is not searched.',
    'wrapper_not_run': 'The wrapper that would run this entry is not run by pppd.',
    'wrapper_not_verified': 'The wrapper was not verified as the unchanged package file, so its behaviour is unknown.',
    'not_a_hook_location': 'pppd and its package wrappers do not run this path.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_VERSION = re.compile(r'(?:\d+:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:[-+~.][0-9A-Za-z.+~-]{0,64})?')
_PEER_NAME = re.compile(r'[^/\x00]{1,255}')
SUPPORTED_SERIES = ((2, 5),)
_UNSUPPORTED_CHARS = frozenset('"\'\\')


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


def _valid_path(path: Any) -> bool:
    return (isinstance(path, str) and 1 < len(path) <= MAX_PATH and path.startswith('/')
            and not _CONTROL.search(path) and posixpath.normpath(path) == path and not path.startswith('//'))


def _mode(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 0o7777 else None


def parse_options(text: Any, source: str, gaps: list[dict[str, Any]]) -> dict[str, str] | None:
    """Return the last script override per event in one options file.

    Returns ``None`` when the file cannot be modelled; the reason is recorded as a gap. Words are
    split on whitespace, and a word starting with ``#`` starts a comment to the end of the line.
    Quoting, escapes and ``#`` inside a word are not modelled, so they are gaps.
    """
    if not isinstance(text, str):
        _gap(gaps, 'input_malformed', source, 'Options text must be a string.')
        return None
    if len(text) > MAX_TEXT:
        _gap(gaps, 'text_too_large', source, f'Options text over {MAX_TEXT} characters is not assessed.')
        return None
    words: list[str] = []
    for line in text.splitlines():
        for word in line.split():
            if word.startswith('#'):
                break
            if _UNSUPPORTED_CHARS.intersection(word) or '#' in word or len(word) >= MAX_WORD:
                _gap(gaps, 'option_syntax_unsupported', source,
                     'Quotes, backslashes, "#" inside a word and words pppd would truncate are not modelled.')
                return None
            words.append(word)
    overrides: dict[str, str] = {}
    complete = True
    index = 0
    while index < len(words):
        word = words[index]
        if word in ('file', 'call'):
            _gap(gaps, 'include_not_followed', source,
                 f'The "{word}" option reads another options file, which is not followed.')
            complete = False
        elif word.split('=', 1)[0] in OPTION_EVENTS and word not in OPTION_EVENTS:
            _gap(gaps, 'option_syntax_unsupported', source, f'"{word}" is not a form this parser models.')
            complete = False
        elif word in OPTION_EVENTS:
            if index + 1 >= len(words):
                _gap(gaps, 'option_missing_argument', source, f'"{word}" has no argument, so pppd rejects the file.')
                return None
            index += 1
            overrides[OPTION_EVENTS[word]] = words[index]
        index += 1
    return overrides if complete else None


def _check_environment(version: Any, family: Any, gaps: list[dict[str, Any]]) -> None:
    if family is None:
        _gap(gaps, 'family_not_observed', detail='The distribution family was not supplied.')
    elif family != 'debian':
        _gap(gaps, 'family_unsupported', detail='Only the Debian/Ubuntu ppp package is modelled.')
    if version is None:
        _gap(gaps, 'version_not_observed', detail='The ppp package version was not supplied.')
    else:
        match = _VERSION.fullmatch(version) if isinstance(version, str) else None
        if match is None or (int(match.group(1)), int(match.group(2))) not in SUPPORTED_SERIES:
            _gap(gaps, 'version_unsupported', detail='Only the ppp 2.5 series is assessed; rules read from 2.5.2.')


def _directories(directories: Any, gaps: list[dict[str, Any]]) -> dict[str, str]:
    states: dict[str, str] = {}
    if directories is not None and not isinstance(directories, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='Directory observations must be a list.')
    for item in directories if isinstance(directories, (list, tuple)) else ():
        path = item.get('path') if isinstance(item, dict) else None
        state = item.get('state') if isinstance(item, dict) else None
        if path not in OBSERVED_DIRS or state not in DIR_STATES or path in states:
            _gap(gaps, 'input_malformed', detail='A directory observation is malformed, unknown or repeated.')
            continue
        states[path] = state
    if states.get(CONF_DIR) == 'absent':
        for path in OBSERVED_DIRS[1:]:
            if states.setdefault(path, 'absent') != 'absent':
                _gap(gaps, 'input_malformed', path, 'A directory was reported inside an absent /etc/ppp.')
    for path in OBSERVED_DIRS:
        if path not in states:
            _gap(gaps, 'directory_not_observed', path, 'No listing result was supplied for this directory.')
        elif states[path] == 'unreadable':
            _gap(gaps, 'directory_unreadable', path, 'The directory exists but could not be listed.')
    return states


def _normalize(item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_path(item.get('path')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', detail='A file observation has no valid absolute path or type.')
        return None
    entry: dict[str, Any] = {'path': item['path'], 'type': item['type']}
    if item['type'] != 'symlink':
        entry['effective'], entry['mode'] = item['type'], _mode(item.get('mode'))
        return entry
    link = item.get('link_target')
    if isinstance(link, str) and link and len(link) <= MAX_PATH and '\x00' not in link:
        entry['link_target'] = link
    target = item.get('target', ...)
    if target is ...:
        entry['effective'], entry['mode'] = None, None
    elif target is None:
        entry['effective'], entry['mode'] = 'unresolvable', None
    elif isinstance(target, dict) and target.get('type') in TARGET_TYPES:
        entry['effective'], entry['mode'] = target['type'], _mode(target.get('mode'))
    else:
        entry['effective'], entry['mode'] = None, None
    return entry


def _lookup(path: str, entries: dict[str, dict[str, Any]], states: dict[str, str],
            gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the entry for ``path``, a synthetic missing entry, or ``None`` when unobserved."""
    if path in entries:
        return entries[path]
    if states.get(posixpath.dirname(path)) in ('listed', 'absent'):
        return {'path': path, 'type': 'missing', 'effective': 'missing', 'mode': None}
    _gap(gaps, 'metadata_missing', path, 'No metadata was supplied and the containing directory was not listed.')
    return None


def _runnable(entry: dict[str, Any] | None, gaps: list[dict[str, Any]]) -> tuple[str, str]:
    """pppd's run_program and run-parts rule: regular file after stat, any execute bit."""
    if entry is None:
        return 'unresolved', 'unresolved'
    effective = entry['effective']
    if effective == 'missing':
        return 'not_run', 'missing'
    if effective is None:
        code = 'symlink_target_unobserved' if entry['type'] == 'symlink' else 'metadata_missing'
        _gap(gaps, code, entry['path'], 'Required metadata for this entry was not supplied or is malformed.')
        return 'unresolved', 'unresolved'
    if effective == 'unresolvable':
        return 'not_run', 'unresolvable_symlink'
    if effective != 'file':
        return 'not_run', 'not_regular'
    if entry['mode'] is None:
        _gap(gaps, 'metadata_missing', entry['path'], 'The permission bits were not supplied.')
        return 'unresolved', 'unresolved'
    if not entry['mode'] & 0o111:
        return 'not_run', 'not_executable'
    return 'runs_as_root', 'runs_as_root'


def _local_outcome(entry: dict[str, Any] | None, gaps: list[dict[str, Any]]) -> str:
    """Outcome of the wrapper's ``[ -x .local ]`` test as root: replaces, fails, run_parts or unresolved."""
    if entry is None:
        return 'unresolved'
    effective = entry['effective']
    if effective in ('missing', 'unresolvable'):
        return 'run_parts'
    if effective is None:
        _gap(gaps, 'symlink_target_unobserved', entry['path'], 'The .local symlink target was not observed.')
        return 'unresolved'
    if effective == 'directory':
        return 'fails'  # root passes -x on a directory; exec then fails
    if entry['mode'] is None:
        _gap(gaps, 'metadata_missing', entry['path'], 'The permission bits were not supplied.')
        return 'unresolved'
    if not entry['mode'] & 0o111:
        return 'run_parts'
    return 'replaces' if effective == 'file' else 'fails'


def _record(entry: dict[str, Any], status: str, reason: str, **extra: Any) -> dict[str, Any]:
    record = {'path': entry['path'], 'type': entry['type'], 'status': status, 'reason_code': reason,
              'reason': REASONS[reason]}
    if entry.get('link_target') is not None:
        record['link_target'] = entry['link_target']
    record.update(extra)
    return record


def _configurations(options_text: Any, peers: Any, states: dict[str, str],
                    gaps: list[dict[str, Any]]) -> list[tuple[str, dict[str, str] | None]]:
    """Return (configuration, effective overrides or None when unknown) for options alone and each peer."""
    if states.get(CONF_DIR) == 'absent':
        base: dict[str, str] | None = {}
    elif options_text is None:
        _gap(gaps, 'options_not_observed', OPTIONS_FILE, 'The text of /etc/ppp/options was not supplied.')
        base = None
    elif options_text is False:
        base = {}  # the caller observed that the file does not exist
    else:
        base = parse_options(options_text, OPTIONS_FILE, gaps)
    configurations: list[tuple[str, dict[str, str] | None]] = [('options', base)]
    if peers is None:
        peers = {}
    if not isinstance(peers, dict):
        _gap(gaps, 'input_malformed', PEERS_DIR, 'Peer files must be a mapping of name to text.')
        return configurations
    names = sorted(peers)
    if len(names) > MAX_PEERS:
        _gap(gaps, 'too_many_peers', PEERS_DIR, f'Only the first {MAX_PEERS} peers are assessed.')
        names = names[:MAX_PEERS]
    for name in names:
        if not isinstance(name, str) or not _PEER_NAME.fullmatch(name) or name in ('.', '..'):
            _gap(gaps, 'input_malformed', PEERS_DIR, 'A peer name is not a valid file name.')
            continue
        peer = parse_options(peers[name], f'{PEERS_DIR}/{name}', gaps)
        merged = None if base is None or peer is None else {**base, **peer}
        configurations.append((f'peer:{name}', merged))
    return configurations


def evaluate(files: Any, *, options_text: Any = None, peers: Any = None, directories: Any = None,
             wrappers: Any = None, version: Any = None, family: Any = None) -> dict[str, Any]:
    """Resolve which programs pppd runs as root on each event from supplied text and metadata.

    ``files`` lists entries of ``/etc/ppp``, the five wrapper ``.d`` directories and any override target
    outside them. Each is ``{'path', 'type', 'mode'}`` with ``type`` from ``lstat`` (``file``,
    ``symlink``, ``directory`` or ``other``). A symlink carries ``target``: ``{'type', 'mode'}`` from
    ``stat``, or ``None`` when ``stat`` fails. ``options_text`` is the text of ``/etc/ppp/options``,
    or ``False`` when it was observed absent. ``peers`` maps each ``/etc/ppp/peers`` file name to its
    text. ``directories`` gives ``{'path', 'state'}`` for ``/etc/ppp``, ``/etc/ppp/peers`` and each
    wrapper ``.d`` directory. ``wrappers`` maps a shipped wrapper path to ``unchanged``,
    ``modified`` or ``unverified`` from package verification. ``version`` is the ppp package
    version, and ``family`` the distribution family; only ``debian`` is modelled.
    """
    gaps: list[dict[str, Any]] = []
    _check_environment(version, family, gaps)
    states = _directories(directories, gaps)
    if not isinstance(wrappers, dict):
        if wrappers is not None:
            _gap(gaps, 'input_malformed', detail='Wrapper verification must be a mapping.')
        wrappers = {}
    if not isinstance(files, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='File observations must be a list.')
        files = ()
    if len(files) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'Only the first {MAX_FILES} file observations are assessed.')
        files = files[:MAX_FILES]
    entries: dict[str, dict[str, Any]] = {}
    for item in files:
        entry = _normalize(item, gaps)
        if entry is None:
            continue
        if entry['path'] in entries:
            _gap(gaps, 'duplicate_path', entry['path'], 'The path was supplied more than once; the first is used.')
            continue
        if states.get(posixpath.dirname(entry['path'])) == 'absent':
            _gap(gaps, 'input_malformed', entry['path'], 'A file was supplied for a directory reported absent.')
        entries[entry['path']] = entry

    configurations = _configurations(options_text, peers, states, gaps)
    accounted: set[str] = set()
    unverified: set[str] = set()
    events: dict[str, Any] = {}
    for event, (default, option, shipped, when) in EVENTS.items():
        selected: dict[str, list[str]] = {}
        unknown: list[str] = []
        for name, overrides in configurations:
            if overrides is None:
                unknown.append(name)
                continue
            selected.setdefault(overrides.get(event, default), []).append(name)
        scripts = []
        for path, names in selected.items():
            scripts.append(_script(path, names, default, entries, states, wrappers, gaps, accounted, unverified))
        events[event] = {'when': when, 'default_path': default, 'override_option': option,
                         'package_wrapper': shipped, 'scripts': scripts, 'unknown_configurations': unknown}

    others = []
    for path, entry in entries.items():
        if path in accounted:
            continue
        parent = posixpath.dirname(path)
        if path.endswith('.local') and path[:-6] in SHIPPED_WRAPPERS:
            parent = path[:-6] + '.d'
        if parent in WRAPPER_DIR_PATHS:
            reason = 'wrapper_not_verified' if parent in unverified else 'wrapper_not_run'
        elif any(path.startswith(directory + '/') for directory in WRAPPER_DIR_PATHS):
            reason = 'nested_entry'
        else:
            reason = 'not_a_hook_location'
        others.append(_record(entry, 'unresolved' if reason == 'wrapper_not_verified' else 'not_run', reason))
    return {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'events': events,
        'other_files': others, 'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed',
        'note': NOT_A_VERDICT, 'complete': not any(gap['code'] in BLOCKING for gap in gaps),
    }


def _script(path: str, configurations: list[str], default: str, entries: dict[str, dict[str, Any]],
            states: dict[str, str], wrappers: dict[Any, Any], gaps: list[dict[str, Any]], accounted: set[str],
            unverified: set[str]) -> dict[str, Any]:
    if not path.startswith('/'):
        _gap(gaps, 'override_path_relative', path, 'A relative script path depends on pppd\'s working directory.')
        return {'path': path, 'type': 'unknown', 'status': 'unresolved', 'reason_code': 'unresolved',
                'reason': REASONS['unresolved'], 'configurations': configurations}
    if not _valid_path(path):
        _gap(gaps, 'input_malformed', detail='A script override is not a normalized absolute path.')
        return {'path': path, 'type': 'unknown', 'status': 'unresolved', 'reason_code': 'unresolved',
                'reason': REASONS['unresolved'], 'configurations': configurations}
    entry = _lookup(path, entries, states, gaps)
    status, reason = _runnable(entry, gaps)
    record = _record(entry or {'path': path, 'type': 'unknown'}, status, reason, configurations=configurations,
                     overridden=path != default, outside_conf_dir=not path.startswith(CONF_DIR + '/'))
    if path in entries:
        accounted.add(path)
    if path not in SHIPPED_WRAPPERS:
        if path == default and entry is not None and entry['effective'] != 'missing':
            record['not_shipped_by_package'] = True
        return record
    local_path, directory = f'{path}.local', f'{path}.d'
    if status != 'runs_as_root':
        record['expansion'] = {'mode': 'not_run'}
        return record
    if wrappers.get(path) != 'unchanged':
        state = wrappers.get(path) if wrappers.get(path) in WRAPPER_STATES else 'unverified'
        unverified.add(directory)
        _gap(gaps, 'wrapper_not_verified', path,
             f'Wrapper state is {state}; its .local and run-parts expansion is not reported.')
        record['expansion'] = {'mode': 'not_verified', 'wrapper_state': state}
        return record
    local = _lookup(local_path, entries, states, gaps)
    if local_path in entries:
        accounted.add(local_path)
    outcome = _local_outcome(local, gaps)
    expansion: dict[str, Any] = {'mode': outcome, 'local': local_path, 'directory': directory, 'entries': []}
    record['expansion'] = expansion
    if outcome == 'replaces':
        expansion['local_record'] = _record(local, 'runs_as_root', 'local_replaces')
    elif outcome == 'fails':
        expansion['local_record'] = _record(local, 'not_run', 'local_exec_fails')
    elif outcome == 'run_parts' and local is not None and local['effective'] != 'missing':
        expansion['local_record'] = _record(
            local, 'not_run', 'unresolvable_symlink' if local['effective'] == 'unresolvable' else 'not_executable')
    if outcome == 'unresolved':
        return record
    dir_state = states.get(directory)
    ordered: list[tuple[bytes, dict[str, Any]]] = []
    for child in sorted(p for p in entries if posixpath.dirname(p) == directory):
        child_entry = entries[child]
        name = posixpath.basename(child)
        if outcome != 'run_parts':
            child_record = _record(child_entry, 'not_run', 'skipped_by_local')
        elif dir_state == 'absent':
            child_record = _record(child_entry, 'not_run', 'directory_not_used')
        elif not run_parts_name(name):
            child_record = _record(child_entry, 'not_run', 'name_filtered')
        else:
            child_status, child_reason = _runnable(child_entry, gaps)
            child_record = _record(child_entry, child_status,
                                   'run_parts' if child_status == 'runs_as_root' else child_reason)
            if child_status == 'runs_as_root':
                ordered.append((name.encode('ascii'), child_record))
        accounted.add(child)
        expansion['entries'].append(child_record)
    for index, (_, child_record) in enumerate(sorted(ordered, key=lambda pair: pair[0])):
        child_record['order'] = index
    return record
