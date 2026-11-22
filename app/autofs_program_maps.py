"""Pure autofs map-source resolution contract for program maps (roadmap F slice, #1375).

automount(8) runs as root. For each master-map entry it resolves the entry's map
source. When that source resolves to a *program map*, automount runs the
program as root every time a key under the mount point is looked up, with argv
``[program, key]`` and the mount point as its working directory. This module
turns already-tokenized master-map entries, captured ``stat`` observations and
the configured ``automount:`` nsswitch sources into the program each entry would
run. It performs no I/O, never runs automount or a map program and never
authorizes a response action.

The rules follow ``daemon/lookup.c`` and ``modules/lookup_program.c`` in autofs
5.1.9 as built by Ubuntu 24.04 (``autofs_5.1.9-1ubuntu4.1``, ``--with-mapdir=/etc``):

- An entry with an explicit ``program`` type runs its map name only when the
  name is an absolute path and ``access(X_OK)`` succeeds, which for root means a
  regular file with any execute bit. Otherwise the program module refuses the
  map and nothing runs.
- An explicit ``file`` type is always read as a text map, never executed. A
  relative name is looked up as ``/etc/<name>``.
- ``hosts`` is the built-in hosts map. Other explicit types (``yp``, ``nis``,
  ``nisplus``, ``ldap``, ``ldaps``, ``sss``, ``hesiod``, ``dir``) read a map
  whose contents this capture cannot observe.
- With no type, a name starting ``//`` is an LDAP map. Any other absolute name
  is ``stat``-ed: a missing or non-regular path is not found, and a regular file
  whose *owner* execute bit (``S_IEXEC``) is set is a program map; otherwise it
  is a text file map.
- With no type and a relative name, the ``automount:`` nsswitch sources are
  tried in order (``files`` when nsswitch has no ``automount`` entry). For
  ``files`` a name containing ``/`` is not found, otherwise ``/etc/<name>`` is
  resolved as above; not found moves on to the next source. Any other source is
  a remote lookup this capture cannot observe. ``sss`` is skipped for amd-format
  maps.

Fail-closed rules: an unobserved ``stat``, a remote or LDAP source that could
answer, an amd-format relative name (its ``search_path`` comes from
configuration this contract does not read), a ``multi`` map, and any captured
text map that contains a ``+`` include or an autofs submount mark the result
incomplete. A text map whose contents were not captured is also incomplete,
because its includes and submounts can name further program maps. ``origin``
is always ``not_assessed`` and no result is a safety verdict.

The master-map grammar itself (``daemon/master_tok.l`` and
``daemon/master_parse.y``), master includes and ``auto.master.d`` are not parsed
here; callers pass tokenized entries.
"""
from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('5.1.9',)
MAP_DIR = '/etc'
RUN_AS = 'root'
DEFAULT_NSS_SOURCES = ('files',)
MAX_ENTRIES = 512
MAX_GAPS = 64
MAX_TEXT = 262144
S_IEXEC = 0o100
ANY_EXEC = 0o111

NSS_SOURCES = frozenset({'files', 'yp', 'nis', 'ldap', 'nisplus', 'hesiod', 'sss'})
REMOTE_TYPES = frozenset({'yp', 'nis', 'nisplus', 'ldap', 'ldaps', 'sss', 'hesiod', 'dir'})
STAT_KINDS = ('regular', 'directory', 'other', 'missing')

BLOCKING = frozenset({
    'stat_not_observed', 'remote_source_unobserved', 'amd_search_path_unobserved', 'multi_map_not_modelled',
    'map_text_not_observed', 'nested_map_unresolved', 'over_limit', 'invalid_entry', 'gaps_truncated',
})

NOT_OBSERVED = (
    'Whether autofs is installed, enabled and running, and which master map it was started with.',
    'The master map grammar, master-map includes and /etc/auto.master.d; entries are passed in tokenized.',
    'Map program behaviour: what a program prints, which keys are looked up and how often.',
    ('The program environment: map macros are exported with an AUTOFS_ prefix unless '
     'force_standard_program_map_env is set in autofs.conf.'),
    'The contents of NIS, NIS+, LDAP, SSSD and Hesiod maps.',
)

# A key that starts with "+" includes another map; "-fstype=autofs" mounts a
# sub-map, which can itself be a program map. Either can name further programs.
_NESTED = re.compile(r'(^\s*\+)|fstype\s*=\s*autofs', re.MULTILINE)


def _gap(gaps: list[dict[str, Any]], code: str, detail: str, **extra: Any) -> None:
    if len(gaps) >= MAX_GAPS:
        if not any(g['code'] == 'gaps_truncated' for g in gaps):
            gaps[-1] = {'code': 'gaps_truncated', 'detail': 'More gaps exist than are listed.', 'blocking': True}
        return
    gaps.append({'code': code, 'detail': detail, 'blocking': code in BLOCKING, **extra})


def _stat(stats: Mapping[str, Any], path: str) -> dict[str, Any] | None:
    seen = stats.get(path)
    if not isinstance(seen, Mapping) or seen.get('kind') not in STAT_KINDS:
        return None
    mode = seen.get('mode')
    if seen['kind'] != 'missing' and (not isinstance(mode, int) or isinstance(mode, bool) or mode < 0):
        return None
    return {'kind': seen['kind'], 'mode': mode if isinstance(mode, int) else 0}


def _classify_path(path: str, stats: Mapping[str, Any]) -> str | None:
    """``read_file_source_instance``: program, file or not_found; None when unobserved."""
    seen = _stat(stats, path)
    if seen is None:
        return None
    if seen['kind'] != 'regular':
        return 'not_found'
    return 'program' if seen['mode'] & S_IEXEC else 'file'


def _text_map(path: str, texts: Mapping[str, Any], gaps: list[dict[str, Any]], mount: str) -> None:
    text = texts.get(path)
    if not isinstance(text, str):
        _gap(gaps, 'map_text_not_observed', 'A text map was not captured; its includes and submounts can name '
             'further program maps.', path=path, mount_point=mount)
    elif len(text) > MAX_TEXT or '\x00' in text:
        _gap(gaps, 'over_limit', 'A captured text map is over the size limit or binary.', path=path,
             mount_point=mount)
    elif _NESTED.search(text):
        _gap(gaps, 'nested_map_unresolved', 'A text map includes another map or mounts an autofs sub-map; '
             'those maps are not resolved here.', path=path, mount_point=mount)


def _resolve_entry(entry: Mapping[str, Any], stats: Mapping[str, Any], texts: Mapping[str, Any],
                   sources: tuple[str, ...], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    mount = entry.get('mount_point')
    mtype = entry.get('type')
    fmt = entry.get('format')
    name = entry.get('map')
    out: dict[str, Any] = {'mount_point': mount, 'type': mtype, 'format': fmt, 'map': name,
                           'resolved': None, 'path': None, 'program': None}

    if not isinstance(mount, str) or not mount.startswith('/') or \
            (mtype is not None and not isinstance(mtype, str)) or (fmt is not None and not isinstance(fmt, str)) or \
            (name is not None and (not isinstance(name, str) or not name)) or \
            (name is None and mtype != 'hosts'):
        out['resolved'] = 'invalid'
        _gap(gaps, 'invalid_entry', 'A master-map entry is malformed.', mount_point=mount)
        return out

    def program(path: str) -> None:
        out.update(resolved='program', path=path,
                   program={'path': path, 'argv': [path, '<key>'], 'user': RUN_AS, 'cwd': mount,
                            'trigger': 'every lookup of a key under the mount point'})

    def resolved(kind: str | None, path: str) -> bool:
        if kind is None:
            _gap(gaps, 'stat_not_observed', 'A map path was not stat-ed in this capture.', path=path,
                 mount_point=mount)
            out['resolved'] = 'unknown'
            return True
        if kind == 'not_found':
            return False
        if kind == 'program':
            program(path)
        else:
            out.update(resolved='file', path=path)
            _text_map(path, texts, gaps, mount)
        return True

    if mtype is not None:
        if mtype.startswith('multi'):
            out['resolved'] = 'unknown'
            _gap(gaps, 'multi_map_not_modelled', 'A multi map combines several sources that are not resolved here.',
                 mount_point=mount)
        elif mtype == 'hosts':
            out['resolved'] = 'hosts'
        elif mtype == 'program':
            if not name.startswith('/'):
                out['resolved'] = 'refused'
                return out
            seen = _stat(stats, name)
            if seen is None:
                resolved(None, name)
            elif seen['kind'] == 'regular' and seen['mode'] & ANY_EXEC:
                program(name)
            else:
                out.update(resolved='refused', path=name)
        elif mtype.startswith('file'):
            path = name if name.startswith('/') else posixpath.join(MAP_DIR, name)
            seen = _stat(stats, path)
            if seen is None:
                resolved(None, path)
            elif seen['kind'] == 'missing':
                out.update(resolved='not_found', path=path)
            else:
                out.update(resolved='file', path=path)
                _text_map(path, texts, gaps, mount)
        else:
            out['resolved'] = 'remote' if mtype in REMOTE_TYPES else 'unknown'
            _gap(gaps, 'remote_source_unobserved', 'The map is read from a source this capture cannot observe.',
                 mount_point=mount, source=mtype)
        return out

    if name.startswith('//'):
        out['resolved'] = 'remote'
        _gap(gaps, 'remote_source_unobserved', 'An LDAP map is read from a directory this capture cannot observe.',
             mount_point=mount, source='ldap')
        return out
    if name.startswith('/'):
        if not resolved(_classify_path(name, stats), name):
            out.update(resolved='not_found', path=name)
        return out
    if fmt == 'amd':
        out['resolved'] = 'unknown'
        _gap(gaps, 'amd_search_path_unobserved', 'An amd-format map name is looked up on a configured '
             'search_path this contract does not read.', mount_point=mount)
        return out
    for source in sources:
        if source == 'files':
            if '/' in name:
                continue
            path = posixpath.join(MAP_DIR, name)
            if resolved(_classify_path(path, stats), path):
                return out
            continue
        out['resolved'] = 'remote'
        _gap(gaps, 'remote_source_unobserved', 'An nsswitch source is queried that this capture cannot observe.',
             mount_point=mount, source=source)
        return out
    out['resolved'] = 'not_found'
    return out


def evaluate(entries: Iterable[Mapping[str, Any]], stats: Mapping[str, Any] | None = None,
             map_texts: Mapping[str, Any] | None = None,
             nss_sources: Iterable[str] | None = None) -> dict[str, Any]:
    """Resolve tokenized master-map entries to the program maps automount would run.

    ``entries`` holds ``{'mount_point', 'type', 'format', 'map'}`` for each map
    source in master-map order. ``stats`` maps a path to ``{'kind': 'regular' |
    'directory' | 'other' | 'missing', 'mode': int}`` (``stat`` follows symlinks).
    ``map_texts`` maps a text-map path to its captured contents. ``nss_sources``
    is the ``automount:`` nsswitch source list, or ``None`` when nsswitch has no
    ``automount`` entry.
    """
    stats = stats if isinstance(stats, Mapping) else {}
    texts = map_texts if isinstance(map_texts, Mapping) else {}
    gaps: list[dict[str, Any]] = []
    if nss_sources is None:
        sources = DEFAULT_NSS_SOURCES
    else:
        # nss_parse.y adds only the sources it knows; unknown names are ignored.
        sources = tuple(s for s in nss_sources if s in NSS_SOURCES)
    listed = list(entries or ())
    if len(listed) > MAX_ENTRIES:
        _gap(gaps, 'over_limit', 'More master-map entries were captured than are evaluated.')
        listed = listed[:MAX_ENTRIES]
    results = [_resolve_entry(e if isinstance(e, Mapping) else {}, stats, texts, sources, gaps) for e in listed]
    programs = [r['program'] for r in results if r['program']]
    return {
        'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS),
        'entries': results,
        'programs': programs,
        'gaps': gaps,
        'complete': not any(g['blocking'] for g in gaps),
        'origin': 'not_assessed',
        'not_observed': list(NOT_OBSERVED),
        'authorizes_response': False,
    }
