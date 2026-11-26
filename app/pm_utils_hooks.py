"""Pure pm-utils hook contract (roadmap F slice, #1367).

pm-utils runs hook programs as root on power events. ``pm-action`` (installed
as ``pm-suspend``, ``pm-hibernate`` and ``pm-suspend-hybrid``) runs every
``sleep.d`` hook before the system sleeps and again, in reverse order, when it
wakes. ``pm-powersave`` runs every ``power.d`` hook when the machine moves
between AC and battery power. Both source the shell files in
``/etc/pm/config.d`` as root first. This module turns captured directory
listings into the hooks pm-utils would run, in order, with their arguments,
and the configuration files it would source. It performs no I/O, never runs a
hook or a shell and never authorizes a response action.

The rules follow ``pm/pm-functions.in``, ``src/pm-action.in`` and
``src/pm-powersave.in`` in pm-utils 1.4.1 (Debian/Ubuntu ``pm-utils_1.4.1``):

- ``_run_hooks`` lists ``"$PM_UTILS_ETCDIR/<kind>.d/"*[!~]`` and then
  ``"$PM_UTILS_LIBDIR/<kind>.d/"*[!~]``. The ``sh`` glob skips names that start
  with a dot or end with ``~``. A name is kept only when ``[ -O "$f" ]`` holds:
  the entry, after following a symlink, is owned by the effective user, root.
- The kept names pass through ``echo ${f##*/}`` unquoted, then
  ``sort | uniq`` (``sort -r`` for the wakeup pass) with ``LC_COLLATE=C``, and
  are split again at newlines. ``echo`` word-splits, glob-expands and, in
  dash, interprets backslashes and ``-n``, so names with whitespace, glob
  characters, backslashes or a leading ``-`` are not modelled (blocking gap).
- For each name the ``/etc/pm`` copy is used when ``[ -f ]`` holds for it,
  otherwise the library copy. The ``/etc/pm`` copy wins even when only the
  library copy is root-owned, so a non-root-owned ``/etc/pm`` file can run as
  root; this is reported as ``selected_not_root_owned``. When neither copy is a
  regular file (a root-owned directory, say), ``$hook`` keeps its previous
  value and the previous hook runs again (``repeats_previous``); for the first
  name it is unset and nothing runs.
- ``hook_ok`` skips a hook disabled by a runtime ``disable_hook:<name>``
  marker (``HOOK_BLACKLIST`` writes these) and one that is not executable
  (``[ -x ]``; for root, any execute bit on a regular file).
- Hooks receive ``$2`` unquoted. ``pm-suspend`` passes ``suspend suspend`` and
  then ``resume suspend``, ``pm-hibernate`` ``hibernate hibernate`` and
  ``thaw hibernate``, ``pm-suspend-hybrid`` ``suspend suspend_hybrid`` and
  ``resume suspend_hybrid``; ``--help`` passes ``help``. ``pm-powersave``
  passes ``true`` on battery and ``false`` on AC.
- ``config.d/*[!~]`` and ``<stash>.config.d/*[!~]`` (``pm-suspend`` or
  ``pm-powersave``) regular files are sourced as root with ``set -a``.

Fail-closed rules: an unobserved listing or entry target, a name this module
cannot reproduce through ``echo``, invalid input and over-limit input mark the
result incomplete. A present ``config.d`` file is sourced shell that can change
the hook directories or the blacklist, so it is listed as sourced and also
marks the result incomplete. Runtime ``disable_hook`` markers, the
``HOOK_BLACKLIST`` and hook failures that stop later hooks can only remove
hooks, so a complete result is an upper bound on what runs. ``LC_ALL`` set to
a non-C locale in pm-utils' environment would change the order; this is
recorded as an assumption. The library files pm-utils itself sources
(``defaults``, ``functions``, ``module.d``) are package files outside this
slice. ``origin`` is always ``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSION = '1.4.1'
DEFAULT_ETCDIR = '/etc/pm'
DEFAULT_LIBDIR = '/usr/lib/pm-utils'
ROOT_UID = 0
MAX_ENTRIES = 1024
MAX_NAME = 255
MAX_GAPS = 64

KINDS = ('sleep', 'power')
STASHES = {'sleep': 'pm-suspend', 'power': 'pm-powersave'}
# (program, forward args, reverse args) for sleep; (event, args) for power.
SLEEP_PROGRAMS = (
    ('pm-suspend', ('suspend', 'suspend'), ('resume', 'suspend')),
    ('pm-hibernate', ('hibernate', 'hibernate'), ('thaw', 'hibernate')),
    ('pm-suspend-hybrid', ('suspend', 'suspend_hybrid'), ('resume', 'suspend_hybrid')),
)
POWER_EVENTS = (('battery', ('true',)), ('ac', ('false',)))
ENTRY_TYPES = frozenset({'file', 'dir', 'symlink', 'other'})
TARGET_TYPES = frozenset({'file', 'dir', 'other', 'missing'})
BLOCKING = frozenset({
    'listing_not_observed', 'listing_invalid', 'entry_invalid', 'target_not_observed',
    'unsafe_name', 'config_sourced_not_evaluated', 'too_many_entries', 'too_many_gaps',
})
# Characters that unquoted echo would split, expand or reinterpret.
_UNSAFE_NAME = re.compile(r'[\s*?\[\\]|^-')


def _gap(gaps: list[dict[str, Any]], code: str, path: str, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if not gaps or gaps[-1]['code'] != 'too_many_gaps':
            gaps.append({'code': 'too_many_gaps', 'path': '', 'detail': 'further gaps omitted', 'blocking': True})
        return
    gaps.append({'code': code, 'path': path, 'detail': detail, 'blocking': code in BLOCKING})


def glob_matches(name: str) -> bool:
    """``*[!~]``: at least one character, no leading dot, last character not ``~``."""
    return bool(name) and not name.startswith('.') and not name.endswith('~')


def _entries(listings: Mapping[str, Any], path: str, gaps: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    """Validated entries of one captured directory, ``[]`` when absent, ``None`` when unusable."""
    listing = listings.get(path)
    if listing is None:
        _gap(gaps, 'listing_not_observed', path)
        return None
    if not isinstance(listing, Mapping) or not isinstance(listing.get('exists'), bool):
        _gap(gaps, 'listing_invalid', path, 'expected {"exists": bool, "entries": [...]}')
        return None
    if not listing['exists']:
        return []
    raw = listing.get('entries')
    if not isinstance(raw, list):
        _gap(gaps, 'listing_invalid', path, 'entries missing')
        return None
    if len(raw) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', path, f'{len(raw)} entries exceed {MAX_ENTRIES}')
        return None
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    ok = True
    for item in raw:
        name = item.get('name') if isinstance(item, Mapping) else None
        if (not isinstance(name, str) or not name or '/' in name or '\0' in name or name in ('.', '..')
                or len(name.encode('utf-8', 'surrogatepass')) > MAX_NAME or name in seen
                or item.get('type') not in ENTRY_TYPES):
            _gap(gaps, 'entry_invalid', path, repr(name)[:80])
            ok = False
            continue
        seen.add(name)
        try:
            name.encode('utf-8')
        except UnicodeEncodeError:
            _gap(gaps, 'entry_invalid', f'{path}/{name!r}', 'name is not valid UTF-8')
            ok = False
            continue
        if not glob_matches(name):
            continue
        target = item.get('target')
        full = f'{path}/{name}'
        if target is None:
            _gap(gaps, 'target_not_observed', full, 'stat of the entry (following symlinks) was not captured')
            ok = False
            continue
        if (not isinstance(target, Mapping) or target.get('type') not in TARGET_TYPES
                or (target['type'] != 'missing' and not (
                    isinstance(target.get('uid'), int) and not isinstance(target.get('uid'), bool)
                    and isinstance(target.get('mode'), int) and not isinstance(target.get('mode'), bool)))):
            _gap(gaps, 'entry_invalid', full, 'target needs type and, unless missing, integer uid and mode')
            ok = False
            continue
        if item['type'] != 'symlink' and target['type'] == 'missing':
            _gap(gaps, 'entry_invalid', full, 'only a symlink can have a missing target')
            ok = False
            continue
        if _UNSAFE_NAME.search(name):
            _gap(gaps, 'unsafe_name', full, 'unquoted echo in _run_hooks would alter this name')
            ok = False
            continue
        out.append({'name': name, 'path': full, 'type': item['type'], 'target': dict(target)})
    return out if ok else None


def _root_owned(entry: dict[str, Any]) -> bool:
    target = entry['target']
    return target['type'] != 'missing' and target['uid'] == ROOT_UID


def _is_file(entry: dict[str, Any] | None) -> bool:
    return entry is not None and entry['target']['type'] == 'file'


def _executable(entry: dict[str, Any]) -> bool:
    return bool(entry['target']['mode'] & 0o111)


def hook_order(etc: list[dict[str, Any]], lib: list[dict[str, Any]], *, reverse: bool = False) -> list[dict[str, Any]]:
    """The hooks one ``_run_hooks`` pass visits, with what happens to each name."""
    names = {e['name'] for e in etc if _root_owned(e)} | {e['name'] for e in lib if _root_owned(e)}
    by_etc = {e['name']: e for e in etc}
    by_lib = {e['name']: e for e in lib}
    ordered = sorted(names, key=lambda n: n.encode('utf-8'), reverse=reverse)
    steps: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    for name in ordered:
        if _is_file(by_etc.get(name)):
            chosen, source = by_etc[name], 'etc'
        elif _is_file(by_lib.get(name)):
            chosen, source = by_lib[name], 'lib'
        else:
            chosen, source = previous, 'previous'
        step: dict[str, Any] = {'name': name, 'source': source, 'path': None, 'status': 'not_run',
                                'root_owned': None, 'shadows': None}
        if chosen is None:
            step['reason'] = 'no regular file for this name and no earlier hook; run_hook gets an empty path'
        else:
            step['path'] = chosen['path']
            step['root_owned'] = _root_owned(chosen)
            if source == 'etc' and name in by_lib:
                step['shadows'] = by_lib[name]['path']
            if not _executable(chosen):
                step['reason'] = 'not executable ([ -x ] fails)'
            else:
                step['status'] = 'repeats_previous' if source == 'previous' else 'runs'
                step['reason'] = ('no regular file for this name; $hook keeps the previous value'
                                  if source == 'previous' else '')
            previous = chosen
        steps.append(step)
    return steps


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def resolve(listings: Mapping[str, Any], *, etcdir: str = DEFAULT_ETCDIR,
            libdir: str = DEFAULT_LIBDIR) -> dict[str, Any]:
    """Resolve the pm-utils hooks and sourced configuration from captured listings.

    ``listings`` maps a directory path to ``{"exists": bool, "entries": [...]}``.
    Each entry has ``name``, ``type`` (lstat: ``file``, ``dir``, ``symlink``,
    ``other``) and ``target``: the stat after following symlinks, as
    ``{"type": "file"|"dir"|"other"|"missing", "uid": int, "mode": int}``.
    """
    gaps: list[dict[str, Any]] = []
    etcdir = etcdir.rstrip('/') or '/'
    libdir = libdir.rstrip('/') or '/'
    sourced: list[dict[str, Any]] = []
    hooks: dict[str, Any] = {}
    for cdir in (f'{etcdir}/config.d', *(f'{etcdir}/{STASHES[k]}.config.d' for k in KINDS)):
        for entry in _entries(listings, cdir, gaps) or []:
            if _is_file(entry):
                sourced.append({'directory': cdir, 'path': entry['path'], 'by': [], 'user': 'root',
                                'root_owned': _root_owned(entry)})
                _gap(gaps, 'config_sourced_not_evaluated', entry['path'],
                     'sourced shell can change PM_UTILS_ETCDIR/LIBDIR or HOOK_BLACKLIST')
    for kind in KINDS:
        etc = _entries(listings, f'{etcdir}/{kind}.d', gaps)
        lib = _entries(listings, f'{libdir}/{kind}.d', gaps)
        if etc is None or lib is None:
            hooks[kind] = None
            continue
        forward = hook_order(etc, lib)
        backward = hook_order(etc, lib, reverse=True)
        if kind == 'sleep':
            passes = []
            for program, fargs, rargs in SLEEP_PROGRAMS:
                passes.append({'program': program, 'phase': 'before_sleep', 'args': list(fargs), 'steps': forward})
                passes.append({'program': program, 'phase': 'after_wake', 'args': list(rargs), 'steps': backward})
            passes.append({'program': 'pm-suspend --help', 'phase': 'help', 'args': ['help'], 'steps': forward})
        else:
            passes = [{'program': 'pm-powersave', 'phase': event, 'args': list(args), 'steps': forward}
                      for event, args in POWER_EVENTS]
            passes.append({'program': 'pm-powersave --help', 'phase': 'help', 'args': ['help'], 'steps': forward})
        hooks[kind] = {'directories': [f'{etcdir}/{kind}.d', f'{libdir}/{kind}.d'], 'passes': passes}
    for item in sourced:
        name = item['directory'].rsplit('/', 1)[-1]
        item['by'] = [STASHES[k] for k in KINDS if name in ('config.d', f'{STASHES[k]}.config.d')]
    programs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for kind in KINDS:
        if not hooks.get(kind):
            continue
        for step in hooks[kind]['passes'][0]['steps']:
            if step['status'] == 'runs' and step['path'] not in seen:
                seen.add(step['path'])
                programs.append({'kind': kind, 'path': step['path'], 'user': 'root',
                                 'root_owned': step['root_owned'], 'origin': 'not_assessed'})
    notes = []
    for kind in KINDS:
        for step in (hooks.get(kind) or {'passes': [{'steps': []}]})['passes'][0]['steps']:
            if step['status'] in ('runs', 'repeats_previous') and step['root_owned'] is False:
                notes.append({'code': 'selected_not_root_owned', 'path': step['path'],
                              'detail': 'only the other copy is root-owned; this file still runs as root'})
            if step['status'] == 'repeats_previous':
                notes.append({'code': 'repeats_previous', 'path': step['path'],
                              'detail': f'{step["name"]!r} is not a regular file, so the previous hook runs again'})
    complete = not any(g['blocking'] for g in gaps)
    result = {
        'contract_version': CONTRACT_VERSION,
        'source_version': SOURCE_VERSION,
        'etcdir': etcdir,
        'libdir': libdir,
        'complete': complete,
        'upper_bound': True,
        'assumptions': ['pm-utils runs as root (euid 0)', 'LC_ALL is unset or C'],
        'hooks': hooks,
        'programs': programs,
        'sourced': sourced,
        'notes': notes,
        'gaps': gaps,
        'origin': 'not_assessed',
    }
    result['digest'] = _digest({k: v for k, v in result.items() if k != 'digest'})
    return result
