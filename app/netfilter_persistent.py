"""Pure netfilter-persistent plugin contract (roadmap F slice, #1479).

``netfilter-persistent.service`` runs ``/usr/sbin/netfilter-persistent start``
as root early in boot (``Before=network-pre.target``) and
``netfilter-persistent stop`` at shutdown; the SysV init script makes the same
calls. The program is a ``set -e`` ``/bin/sh`` script that:

1. sources ``/etc/default/netfilter-persistent`` with ``.`` when ``[ -f ]`` is
   true for it, so the whole file runs as root shell code;
2. runs ``run-parts -v -a <argument> ${PLUGINS}`` as root when
   ``[ -d ${PLUGINS} ]`` is true. ``PLUGINS`` is set to
   ``/usr/share/netfilter-persistent/plugins.d`` *before* the defaults file is
   sourced, so the defaults file can redirect it. Both expansions are unquoted;
3. maps ``start``, ``save`` and ``flush`` to themselves and ``restart`` and
   ``reload`` to ``start``. ``stop`` runs the plugins with ``flush`` only when
   ``[ ${FLUSH_ON_STOP} -gt 0 ]`` succeeds; the shipped defaults file sets
   ``FLUSH_ON_STOP=0``.

This module takes the captured state and text of the defaults file and the
captured plugin-directory listing and says, per action, which plugins run as
root, with which argv, in which order. It performs no I/O, never runs a shell
or a plugin and never authorizes a response action.

The rules follow ``netfilter-persistent`` 1.0.24 (the script is unchanged in
the 1.0.x series) under ``dash``, and ``run-parts.c`` in debianutils 5.24. A
differential against the packaged debianutils 5.17 ``run-parts`` and ``dash``
agreed on every case:

- Only names matching ``^[a-zA-Z0-9_-]+$`` are considered. run-parts never
  calls ``setlocale``, so the list is sorted with ``strcoll`` in the C locale,
  which is byte order.
- Every considered name is ``stat``-ed with symlinks followed; a name that does
  not resolve (a dangling symlink) is dropped. A directory is skipped silently.
  A regular file runs when root's ``access(X_OK)`` succeeds, which on Linux is
  any execute bit. Any other kind is reported and skipped; later plugins still
  run.
- Each plugin is executed directly as ``<PLUGINS>/<name> <argument>``.

Only a defaults file of comments, blank lines and single static
``NAME=value`` assignments is resolved. Anything else is root shell code this
contract cannot evaluate and is a blocking gap, as is an assignment to ``PATH``
(which selects the ``run-parts`` binary) or ``IFS`` (which changes word
splitting). A ``PLUGINS`` value that is relative, or that would be split into
several words or expanded as a glob, is unresolved. ``origin`` is always
``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = {'netfilter-persistent': '1.0.24', 'debianutils run-parts': '5.17-5.24', 'shell': 'dash'}
DEFAULTS_PATH = '/etc/default/netfilter-persistent'
DEFAULT_PLUGINS = '/usr/share/netfilter-persistent/plugins.d'
PROGRAM = '/usr/sbin/netfilter-persistent'
ACTIONS = ('start', 'stop', 'restart', 'reload', 'flush', 'save')
TRIGGERS = (
    {'event': 'boot', 'action': 'start',
     'via': ['netfilter-persistent.service ExecStart', '/etc/init.d/netfilter-persistent start']},
    {'event': 'shutdown', 'action': 'stop',
     'via': ['netfilter-persistent.service ExecStop', '/etc/init.d/netfilter-persistent stop']},
)
MAX_TEXT = 65536
MAX_ENTRIES = 1024
MAX_PATH = 4096
MAX_GAPS = 64
INTMAX = 2 ** 63 - 1

STATUSES = ('runs', 'ignored', 'skipped_directory', 'skipped_not_executable', 'skipped_non_file',
            'skipped_dangling', 'unresolved')
BLOCKING = frozenset({
    'defaults_not_observed', 'defaults_unreadable', 'defaults_over_limit', 'invalid_utf8', 'binary',
    'defaults_dynamic', 'path_assigned', 'ifs_assigned', 'plugins_unresolved', 'plugins_relative',
    'plugins_over_limit', 'flush_on_stop_unresolved', 'directory_not_observed', 'directory_mismatch',
    'directory_unreadable', 'entries_over_limit', 'malformed_entry', 'duplicate_entry', 'type_not_observed',
    'mode_not_observed', 'target_not_observed', 'gaps_truncated',
})
NOT_OBSERVED = (
    'Whether netfilter-persistent is installed and netfilter-persistent.service or the init script is enabled.',
    ('Which run-parts and whoami binaries PATH selects; under systemd, /usr/local/sbin and /usr/local/bin are '
     'searched before /usr/sbin and /usr/bin.'),
    ('Variables inherited from the environment; FLUSH_ON_STOP is treated as unset unless the defaults file '
     'assigns it, as in systemd\'s clean service environment.'),
    'Whether the plugin directory or a plugin is on a noexec mount, where root\'s access(X_OK) fails.',
    'The contents of plugins and of programs they run, and the rule files they load.',
    ('Older run-parts releases that accept one directory only; this matters only for a PLUGINS value with '
     'several words, which is reported as unresolved.'),
)

_NAME = re.compile(r'[a-zA-Z0-9_-]+')
_ASSIGN = re.compile(
    r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)='
    r'(?:(?P<bare>[A-Za-z0-9_./:,+@%=-]*)|\'(?P<single>[^\']*)\'|"(?P<double>[^"$`\\]*)")'
    r'(?:[ \t]+(?:#.*)?)?')
_INT = re.compile(r'[+-]?[0-9]+')
_GLOB = frozenset('*?[')


def _gap(gaps: list[dict[str, Any]], code: str, name: str | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if not any(g['code'] == 'gaps_truncated' for g in gaps):
            gaps.append({'code': 'gaps_truncated', 'name': None, 'detail': 'Further gaps were not recorded.',
                         'blocking': True})
        return
    gaps.append({'code': code, 'name': name, 'detail': detail[:300], 'blocking': code in BLOCKING})


def name_considered(name: str) -> bool:
    """run-parts' default ``^[a-zA-Z0-9_-]+$`` name filter (no ``--lsbsysinit``)."""
    return _NAME.fullmatch(name) is not None


def parse_defaults(text: str) -> dict[str, Any]:
    """Resolve the static assignments of a sourced defaults file.

    Returns ``{'static': bool, 'assignments': {name: value}, 'dynamic_lines': [line numbers]}``. A file is static
    only when every line is blank, a comment or one ``NAME=value`` assignment whose value needs no expansion.
    """
    assignments: dict[str, str] = {}
    dynamic: list[int] = []
    for number, raw in enumerate(text.split('\n'), start=1):
        line = raw.lstrip(' \t')
        if not line or line.startswith('#'):
            continue
        match = _ASSIGN.fullmatch(line)
        if match is None:
            dynamic.append(number)
            continue
        value = next(v for v in (match['bare'], match['single'], match['double']) if v is not None)
        assignments[match['name']] = value
    return {'static': not dynamic, 'assignments': assignments, 'dynamic_lines': dynamic[:32]}


def flush_on_stop(value: str | None) -> bool | None:
    """Outcome of ``[ ${FLUSH_ON_STOP} -gt 0 ]`` under dash, or None when it depends on unmodelled expansion."""
    if value is None:
        return False
    words = value.split()
    if not words:
        # "[ -gt 0 ]" is a test syntax error: status 2, so the else branch runs.
        return False
    if len(words) != 1 or any(c in _GLOB for c in words[0]):
        return None
    word = words[0]
    if not _INT.fullmatch(word):
        # dash's atomax10 rejects it ("Illegal number"): status 2.
        return False
    number = int(word)
    if number > INTMAX or number < -INTMAX - 1:
        return False
    return number > 0


def _decode(text: Any, gaps: list[dict[str, Any]]) -> str | None:
    if isinstance(text, bytes):
        if len(text) > MAX_TEXT:
            _gap(gaps, 'defaults_over_limit', DEFAULTS_PATH, f'More than {MAX_TEXT} bytes.')
            return None
        if b'\x00' in text:
            _gap(gaps, 'binary', DEFAULTS_PATH, 'The defaults file contains NUL bytes.')
            return None
        try:
            return text.decode('utf-8')
        except UnicodeDecodeError:
            _gap(gaps, 'invalid_utf8', DEFAULTS_PATH, 'The defaults file is not valid UTF-8.')
            return None
    if isinstance(text, str):
        if len(text.encode('utf-8', 'surrogatepass')) > MAX_TEXT:
            _gap(gaps, 'defaults_over_limit', DEFAULTS_PATH, f'More than {MAX_TEXT} bytes.')
            return None
        if '\x00' in text:
            _gap(gaps, 'binary', DEFAULTS_PATH, 'The defaults file contains NUL bytes.')
            return None
        try:
            text.encode('utf-8')
        except UnicodeEncodeError:
            _gap(gaps, 'invalid_utf8', DEFAULTS_PATH, 'The defaults file is not valid UTF-8.')
            return None
        return text
    _gap(gaps, 'defaults_not_observed', DEFAULTS_PATH, 'The defaults file text was not supplied.')
    return None


def _defaults(defaults: Any, result: dict[str, Any], gaps: list[dict[str, Any]]) -> tuple[str | None, bool | None]:
    """Return (PLUGINS value or None when unresolved, FLUSH_ON_STOP outcome or None when unresolved)."""
    record: dict[str, Any] = {'path': DEFAULTS_PATH, 'state': None, 'sourced_as_root': None, 'sha256': None,
                              'static': None, 'dynamic_lines': [], 'assignments': {}}
    result['defaults'] = record
    state = defaults.get('state') if isinstance(defaults, Mapping) else None
    if state not in ('file', 'absent', 'not_file', 'unreadable'):
        _gap(gaps, 'defaults_not_observed', DEFAULTS_PATH, 'Whether the defaults file exists was not observed; '
             'it is sourced as root and may reassign PLUGINS.')
        return None, None
    record['state'] = state
    if state in ('absent', 'not_file'):
        # "[ -f ]" is false, so nothing is sourced.
        record['sourced_as_root'] = False
        return DEFAULT_PLUGINS, False
    record['sourced_as_root'] = True
    if state == 'unreadable':
        _gap(gaps, 'defaults_unreadable', DEFAULTS_PATH, 'The defaults file exists but could not be read.')
        return None, None
    text = _decode(defaults.get('text'), gaps)
    if text is None:
        return None, None
    record['sha256'] = hashlib.sha256(text.encode('utf-8')).hexdigest()
    parsed = parse_defaults(text)
    record.update(static=parsed['static'], dynamic_lines=parsed['dynamic_lines'])
    assignments = parsed['assignments']
    record['assignments'] = {k: v[:MAX_PATH] for k, v in assignments.items() if k in ('PLUGINS', 'FLUSH_ON_STOP')}
    if not parsed['static']:
        _gap(gaps, 'defaults_dynamic', DEFAULTS_PATH, 'Lines ' + ', '.join(map(str, parsed['dynamic_lines']))
             + ' are shell code other than a static assignment; they run as root and may change PLUGINS, '
             'FLUSH_ON_STOP or PATH.')
        return None, None
    if 'PATH' in assignments:
        _gap(gaps, 'path_assigned', DEFAULTS_PATH, 'The defaults file assigns PATH, which selects the run-parts '
             'binary that runs the plugins.')
    if 'IFS' in assignments:
        _gap(gaps, 'ifs_assigned', DEFAULTS_PATH, 'The defaults file assigns IFS, which changes how the unquoted '
             'PLUGINS and FLUSH_ON_STOP expansions are split.')
    if 'PATH' in assignments or 'IFS' in assignments:
        return None, None
    flush = flush_on_stop(assignments.get('FLUSH_ON_STOP'))
    if flush is None:
        _gap(gaps, 'flush_on_stop_unresolved', DEFAULTS_PATH, 'FLUSH_ON_STOP expands to several words or a glob, so '
             'whether stop flushes is not modelled.')
    return assignments.get('PLUGINS', DEFAULT_PLUGINS), flush


def _entry(name: str, entry: Mapping[str, Any], directory: str, gaps: list[dict[str, Any]]) -> dict[str, Any]:
    record = {'name': name, 'path': f'{directory}/{name}', 'type': entry.get('type'), 'status': 'unresolved',
              'reason': None, 'mode': None, 'origin': 'not_assessed'}
    if not name_considered(name):
        return {**record, 'status': 'ignored', 'reason': 'name_filter'}
    kind = entry.get('type')
    mode_key = 'mode'
    if kind == 'symlink':
        target = entry.get('target_type')
        if target not in ('file', 'directory', 'other', 'missing'):
            _gap(gaps, 'target_not_observed', name, 'The followed symlink target kind was not observed.')
            return {**record, 'reason': 'target_not_observed'}
        if target == 'missing':
            return {**record, 'status': 'skipped_dangling', 'reason': 'dangling_symlink'}
        kind, mode_key = target, 'target_mode'
    if kind == 'directory':
        return {**record, 'status': 'skipped_directory', 'reason': 'directory'}
    if kind == 'other':
        return {**record, 'status': 'skipped_non_file', 'reason': 'not_regular_file'}
    if kind != 'file':
        _gap(gaps, 'type_not_observed', name, 'The entry kind was not observed.')
        return {**record, 'reason': 'type_not_observed'}
    mode = entry.get(mode_key)
    if type(mode) is not int or not 0 <= mode <= 0o7777:
        _gap(gaps, 'mode_not_observed', name, 'The permission bits were not observed.')
        return {**record, 'reason': 'mode_not_observed'}
    record['mode'] = f'{mode:04o}'
    if not mode & 0o111:
        return {**record, 'status': 'skipped_not_executable', 'reason': 'no_execute_bit'}
    return {**record, 'status': 'runs'}


def _finish(result: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    result['complete'] = not any(g['blocking'] for g in gaps)
    return result


def evaluate(*, defaults: Any = None, directory: Any = None, entries: Any = None) -> dict[str, Any]:
    """Resolve which netfilter-persistent plugins run as root, per action.

    ``defaults`` is ``{'state': 'file' | 'absent' | 'not_file' | 'unreadable', 'text': str | bytes}`` for
    ``/etc/default/netfilter-persistent``; ``state`` follows ``test -f`` (a symlink to a regular file is
    ``file``). ``directory`` is ``{'path': <effective PLUGINS>, 'state': 'directory' | 'absent' |
    'not_directory' | 'unreadable'}`` following ``test -d``. Each entry is ``{'name': '15-ip4tables', 'type':
    'file' | 'symlink' | 'directory' | 'other', 'mode': 0o755, 'target_type': ..., 'target_mode': ...}``,
    where ``target_type`` is the followed kind of a symlink (``'file'``, ``'directory'``, ``'other'`` or
    ``'missing'``).
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'format': 'netfilter_persistent', 'source_versions':
        dict(SOURCE_VERSIONS), 'program': PROGRAM, 'user': 'root', 'triggers': [dict(t) for t in TRIGGERS],
        'complete': False, 'defaults': None, 'plugins_directory': None, 'directory_exists': None,
        'flush_on_stop': None, 'plugins': [], 'entries': [], 'actions': {}, 'origin': 'not_assessed',
        'gaps': gaps, 'not_observed': list(NOT_OBSERVED),
    }
    plugins, flush = _defaults(defaults, result, gaps)
    result['flush_on_stop'] = flush
    arguments: dict[str, str | None] = {'start': 'start', 'restart': 'start', 'reload': 'start', 'flush': 'flush',
                                        'save': 'save', 'stop': None if flush is None else ('flush' if flush else '')}
    if plugins is not None:
        if len(plugins) > MAX_PATH:
            _gap(gaps, 'plugins_over_limit', 'PLUGINS', 'PLUGINS is over the path limit.')
            plugins = None
        elif plugins.split() != [plugins] and plugins != '' or any(c in _GLOB for c in plugins):
            _gap(gaps, 'plugins_unresolved', 'PLUGINS', f'PLUGINS "{plugins[:120]}" is expanded unquoted, so it '
                 'is split into words or expanded as a glob.')
            plugins = None
        elif plugins and not plugins.startswith('/'):
            _gap(gaps, 'plugins_relative', 'PLUGINS', f'PLUGINS "{plugins[:120]}" is relative to the working '
                 'directory, which was not observed.')
            plugins = None
    runs: list[dict[str, Any]] | None = None
    if plugins == '':
        # "[ -d ]" is true and "run-parts -v -a <arg>" has no directory: usage error, nothing runs.
        result.update(plugins_directory='', directory_exists=False)
        runs = []
    elif plugins is not None:
        result['plugins_directory'] = plugins
        runs = _directory(plugins, directory, entries, result, gaps)
    result['plugins'] = [] if runs is None else [{'name': r['name'], 'path': r['path']} for r in runs]
    for action in ACTIONS:
        argument = arguments[action]
        resolved = runs is not None and argument is not None
        result['actions'][action] = {
            'argument': argument or None,
            'runs_plugins': None if argument is None else bool(argument),
            'argv': ([[r['path'], argument] for r in runs] if argument else []) if resolved else None,
        }
    return _finish(result, gaps)


def _directory(plugins: str, directory: Any, entries: Any, result: dict[str, Any],
               gaps: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    if not isinstance(directory, Mapping) or directory.get('state') not in (
            'directory', 'absent', 'not_directory', 'unreadable'):
        _gap(gaps, 'directory_not_observed', plugins, f'No listing result was supplied for {plugins[:200]}.')
        return None
    if directory.get('path') != plugins:
        _gap(gaps, 'directory_mismatch', plugins, f'The listing is for {str(directory.get("path"))[:120]}, but '
             f'PLUGINS is {plugins[:120]}.')
        return None
    if directory['state'] in ('absent', 'not_directory'):
        result['directory_exists'] = False
        return []
    result['directory_exists'] = True
    if directory['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', plugins, f'{plugins[:200]} could not be listed.')
        return None
    entries = list(entries) if isinstance(entries, (list, tuple)) else None
    if entries is None:
        _gap(gaps, 'directory_not_observed', plugins, 'The directory listing was not supplied.')
        return None
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'entries_over_limit', plugins, f'More than {MAX_ENTRIES} directory entries.')
        return None
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    for entry in entries:
        name = entry.get('name') if isinstance(entry, Mapping) else None
        if not isinstance(name, str) or not name or '/' in name or '\x00' in name or len(name) > 255:
            _gap(gaps, 'malformed_entry', None, 'A directory entry has no usable name.')
            continue
        if name in ('.', '..'):
            continue
        if name in seen:
            _gap(gaps, 'duplicate_entry', name[:120], f'{name[:120]} was listed more than once.')
            continue
        seen.add(name)
        records.append(_entry(name, entry, plugins, gaps))
    records.sort(key=lambda r: r['name'].encode('utf-8', 'surrogatepass'))
    result['entries'] = records
    if any(r['status'] == 'unresolved' for r in records):
        return None
    return [r for r in records if r['status'] == 'runs']
