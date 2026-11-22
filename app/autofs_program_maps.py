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

``read_master`` (increment 2) reads the master map as automount does: the
``read_one`` record splitter, ``+`` includes with self-include and depth-16
limits, ``+dir:`` ``*.autofs`` directories in ``versionsort`` order, typed and
nsswitch master sources and the ``auto_master`` fallback. ``parse_entry`` and
``entries_from_records`` (increment 3) parse each record with a fail-closed
subset of the ``daemon/master_tok.l``/``daemon/master_parse.y`` grammar and
apply the ``-null``, duplicate and amd-section bookkeeping of
``master_parse_entry``; ``evaluate_master`` runs all three steps.
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


# ---------------------------------------------------------------------------
# Increment 2: reading the master map (``modules/lookup_file.c``
# ``read_one``/``lookup_read_master``, ``modules/lookup_dir.c`` and
# ``daemon/lookup.c`` ``lookup_nss_read_master``/``read_master_map``).
# The entry grammar (``master_tok.l``/``master_parse.y``) is not parsed here:
# each non-include record is returned as the ``"<path> <entry>"`` buffer that
# ``lookup_read_master`` hands to ``master_parse_entry``.
# ---------------------------------------------------------------------------

DEFAULT_MASTER_MAP_NAME = 'auto.master'
KEY_MAX_LEN = 255  # NAME_MAX
MAPENT_MAX_LEN = 16384
MAX_INCLUDE_DEPTH = 16
DIR_EXT = '.autofs'
MAX_RECORDS = 2048
MAX_READS = 256
MASTER_REMOTE_TYPES = ('yp', 'nis', 'nisplus', 'ldap', 'ldaps', 'sss')
# lookup_nss_read_master only tries these nsswitch sources (strncmp prefixes,
# so "nis" also admits "nisplus"); "yp" and "hesiod" are skipped.
MASTER_NSS_PREFIXES = ('files', 'nis', 'nisplus', 'ldap', 'sss')

MASTER_BLOCKING = frozenset({
    'master_file_not_observed', 'master_dir_not_observed', 'remote_source_unobserved', 'master_source_not_modelled',
    'over_limit', 'gaps_truncated',
})

_C_SPACE = frozenset(' \t\n\v\f\r')
_C_BLANK = frozenset(' \t')
(_ST_BEGIN, _ST_COMPARE, _ST_STAR, _ST_BADENT, _ST_ENTSPC, _ST_GETENT) = range(6)
(_GOT_NOTHING, _GOT_STAR, _GOT_REAL, _GOT_PLUS) = range(4)
(_ESC_NONE, _ESC_CHAR, _ESC_VAL, _ESC_ALL) = range(4)


class _KeyOverflow(Exception):
    """read_one wrote past its KEY_MAX_LEN + 1 key buffer; automount's behaviour is undefined."""


class _Stream:
    def __init__(self, text: str) -> None:
        self.text, self.pos = text, 0

    def getc(self) -> str | None:
        if self.pos >= len(self.text):
            self.pos = len(self.text) + 1  # feof
            return None
        ch = self.text[self.pos]
        self.pos += 1
        return ch

    def ungetc(self, ch: str | None) -> None:
        if ch is not None:
            self.pos -= 1

    def eof(self) -> bool:
        return self.pos > len(self.text)


def _read_one(f: _Stream) -> tuple[str, str] | None:
    """Transcription of ``read_one``: the next (key, mapent) record, or None at EOF."""
    key: list[str] = []
    mapent: list[str] | None = None
    state, getting, gotten, escape = _ST_BEGIN, _GOT_NOTHING, _GOT_NOTHING, _ESC_NONE

    def reset() -> None:
        nonlocal key, mapent, getting, gotten, escape
        key, mapent = [], None
        getting = gotten = _GOT_NOTHING
        escape = _ESC_NONE

    while (ch := f.getc()) is not None:
        if escape == _ESC_NONE:
            if ch == '\\':
                nch = f.getc()
                if nch == '\n':
                    continue
                f.ungetc(nch)
                escape = _ESC_CHAR
            if ch == '"':
                escape = _ESC_ALL
        elif escape == _ESC_CHAR:
            escape = _ESC_VAL
        elif escape == _ESC_VAL or (escape == _ESC_ALL and ch == '"'):
            escape = _ESC_NONE

        got_it = nxt = False
        if state == _ST_BEGIN:
            if escape == _ESC_NONE:
                if ch in _C_SPACE:
                    pass
                elif ch == '#':
                    state = _ST_BADENT
                elif ch == '*':
                    state = _ST_STAR
                    key.append(ch)
                else:
                    if ch == '+':
                        gotten = _GOT_PLUS
                    state = _ST_COMPARE
                    key.append(ch)
            elif escape == _ESC_ALL:
                state = _ST_COMPARE
                key.append(ch)
            elif escape == _ESC_CHAR:
                pass
            else:
                state = _ST_BADENT
        elif state == _ST_COMPARE:
            if ch == '\n':
                state = _ST_BEGIN
                if gotten == _GOT_PLUS:
                    got_it = True
                elif escape == _ESC_ALL:
                    nxt = True
                elif escape != _ESC_VAL:
                    got_it = True
            elif ch in _C_SPACE and escape == _ESC_NONE:
                getting = _GOT_REAL
                state = _ST_ENTSPC
                if gotten == _GOT_PLUS:
                    got_it = True
            elif escape == _ESC_CHAR:
                pass
            elif len(key) == KEY_MAX_LEN:
                state = _ST_BADENT
                gotten = _GOT_NOTHING
            else:
                if escape == _ESC_VAL:
                    key.append('\\')
                key.append(ch)
                if len(key) > KEY_MAX_LEN:
                    # An escape at length KEY_MAX_LEN - 1 skips the equality test and overflows.
                    raise _KeyOverflow
        elif state == _ST_STAR:
            if ch == '\n':
                state = _ST_BEGIN
            elif ch in _C_SPACE and gotten < _GOT_STAR and escape == _ESC_NONE:
                getting = _GOT_STAR
                state = _ST_ENTSPC
            elif escape != _ESC_CHAR:
                state = _ST_BADENT
        elif state == _ST_BADENT:
            if ch == '\n':
                nch = f.getc()
                if nch is not None and nch in _C_BLANK:
                    f.ungetc(nch)
                else:
                    f.ungetc(nch)
                    state = _ST_BEGIN
                    if gotten == _GOT_REAL or gotten == getting:
                        got_it = True
                    else:
                        nxt = True
            elif ch not in _C_BLANK:
                gotten = _GOT_NOTHING
        elif state == _ST_ENTSPC:
            if ch == '\n':
                state = _ST_BEGIN
            elif ch not in _C_SPACE or escape != _ESC_NONE:
                if escape != _ESC_NONE:
                    if escape == _ESC_CHAR:
                        continue
                    if ord(ch) <= 32:
                        getting = _GOT_NOTHING
                        state = _ST_BADENT
                        continue
                    mapent = ['\\', ch] if escape == _ESC_VAL else [ch]
                else:
                    mapent = [ch]
                state = _ST_GETENT
                gotten = getting
        elif state == _ST_GETENT:
            if ch == '\n':
                if escape == _ESC_ALL:
                    state = _ST_BEGIN
                    nxt = True
                else:
                    nch = f.getc()
                    if nch is not None and nch in _C_BLANK:
                        f.ungetc(nch)
                        state = _ST_BADENT
                    else:
                        f.ungetc(nch)
                        state = _ST_BEGIN
                        if gotten == _GOT_REAL or gotten == getting:
                            got_it = True
            elif len(mapent or ()) < MAPENT_MAX_LEN:
                if mapent is not None:
                    mapent.append(ch)
                nch = f.getc()
                if nch is None and (gotten == _GOT_REAL or gotten == getting):
                    got_it = True
                else:
                    f.ungetc(nch)
            else:
                state = _ST_BADENT

        if got_it:
            if gotten == _GOT_NOTHING:
                nxt = True
            else:
                return ''.join(key), ''.join(mapent or ())
        if nxt:
            reset()
    return None


def _strverscmp(a: str, b: str) -> int:
    """glibc ``strverscmp`` (used by ``versionsort`` for ``auto.master.d``)."""
    s_n, s_i, s_f, s_z, cmp, ln = 0, 3, 6, 9, 2, 3
    next_state = (s_n, s_i, s_z, s_n, s_i, s_i, s_n, s_f, s_f, s_n, s_f, s_z)
    result_type = (cmp, cmp, cmp, cmp, ln, cmp, cmp, cmp, cmp,
                   cmp, -1, -1, 1, ln, ln, 1, ln, ln,
                   cmp, cmp, cmp, cmp, cmp, cmp, cmp, cmp, cmp,
                   cmp, 1, 1, -1, cmp, cmp, -1, cmp, cmp)
    p1, p2 = a.encode('latin-1') + b'\0', b.encode('latin-1') + b'\0'
    if a == b:
        return 0

    def cls(c: int) -> int:
        return (c == 0x30) + (0x30 <= c <= 0x39)

    i = 0
    c1, c2 = p1[0], p2[0]
    state = s_n + cls(c1)
    while (diff := c1 - c2) == 0:
        if c1 == 0:
            return diff
        state = next_state[state]
        i += 1
        c1, c2 = p1[i], p2[i]
        state += cls(c1)
    state = result_type[state * 3 + cls(c2)]
    if state == cmp:
        return diff
    if state == ln:
        j = i + 1
        while 0x30 <= p1[j] <= 0x39:
            if not 0x30 <= p2[j] <= 0x39:
                return 1
            j += 1
        return -1 if 0x30 <= p2[j] <= 0x39 else diff
    return state


def _versionsort(names: Iterable[str]) -> list[str]:
    import functools
    return sorted(names, key=functools.cmp_to_key(_strverscmp))


class _Master:
    def __init__(self, files: Mapping[str, Any], stats: Mapping[str, Any], dirs: Mapping[str, Any],
                 sources: tuple[str, ...], master_set: bool) -> None:
        self.files, self.stats, self.dirs, self.sources = files, stats, dirs, sources
        self.master_set = master_set
        self.depth = 0
        self.recurse = False
        self.reads = 0
        self.records: list[dict[str, Any]] = []
        self.gaps: list[dict[str, Any]] = []

    def gap(self, code: str, detail: str, **extra: Any) -> None:
        if len(self.gaps) >= MAX_GAPS:
            if not any(g['code'] == 'gaps_truncated' for g in self.gaps):
                self.gaps[-1] = {'code': 'gaps_truncated', 'detail': 'More gaps exist than are listed.',
                                 'blocking': True}
            return
        self.gaps.append({'code': code, 'detail': detail, 'blocking': code in MASTER_BLOCKING, **extra})

    # lookup_file.c lookup_read_master
    def read_file(self, mapname: str) -> str:
        # open_lookup runs do_init (absolute path, access(R_OK)) before lookup_read_master.
        if not mapname.startswith('/'):
            return 'unavail'
        seen = _stat(self.stats, mapname)
        if seen is None:
            self.gap('master_file_not_observed', 'A master map path was not stat-ed in this capture.', path=mapname)
            return 'unknown'
        if seen['kind'] == 'missing':
            return 'unavail'
        if self.recurse:
            return 'tryagain'
        if self.depth > MAX_INCLUDE_DEPTH:
            self.gap('include_depth_exceeded', 'automount stops including master maps past depth 16.', path=mapname)
            return 'unknown'
        if seen['kind'] == 'directory':
            return 'success'  # fopen succeeds and the first read fails with EISDIR
        if seen['kind'] != 'regular':
            self.gap('master_file_not_observed', 'A master map is neither a regular file nor a directory.',
                     path=mapname)
            return 'unknown'
        text = self.files.get(mapname)
        if not isinstance(text, str):
            self.gap('master_file_not_observed', 'A master map file was not captured.', path=mapname)
            return 'unknown'
        if len(text) > MAX_TEXT or '\x00' in text or any(ord(c) > 0xFF for c in text):
            self.gap('over_limit', 'A captured master map is over the size limit or binary.', path=mapname)
            return 'unknown'
        self.reads += 1
        if self.reads > MAX_READS:
            self.gap('over_limit', 'More master map reads were needed than are evaluated.', path=mapname)
            return 'unknown'
        f = _Stream(text)
        while True:
            try:
                rec = _read_one(f)
            except _KeyOverflow:
                self.gap('over_limit', 'A master map key overflows automount\'s key buffer; its behaviour is '
                         'undefined.', path=mapname)
                return 'unknown'
            if rec is None:
                break
            path, ent = rec
            if path.startswith('+'):
                inc = path[1:]
                # check_master_self_include: full path for '/' names, basenames otherwise.
                if inc.startswith('/'):
                    self_inc = inc == mapname
                else:
                    self_inc = posixpath.basename(inc) == posixpath.basename(mapname)
                if self_inc:
                    self.recurse = True
                self.depth += 1
                self.nss_read(inc)
                self.depth -= 1
                self.recurse = False
            else:
                if len(self.records) >= MAX_RECORDS:
                    self.gap('over_limit', 'More master map records were read than are evaluated.')
                    return 'unknown'
                self.records.append({'source': mapname, 'depth': self.depth, 'buffer': f'{path} {ent}'})
            if f.eof():
                break
        return 'success'

    # lookup_dir.c lookup_read_master
    def read_dir(self, mapname: str) -> str:
        if not mapname.startswith('/'):
            return 'unavail'
        seen = _stat(self.stats, mapname)
        if seen is None:
            self.gap('master_dir_not_observed', 'A master map directory was not stat-ed in this capture.',
                     path=mapname)
            return 'unknown'
        if seen['kind'] != 'directory':
            # access(R_OK) fails for a missing path; a non-directory is rejected by do_init.
            return 'unavail'
        if self.depth > MAX_INCLUDE_DEPTH:
            self.gap('include_depth_exceeded', 'automount stops including master maps past depth 16.', path=mapname)
            return 'unavail'
        names = self.dirs.get(mapname)
        if not isinstance(names, (list, tuple)) or not all(isinstance(n, str) for n in names):
            self.gap('master_dir_not_observed', 'A master map directory listing was not captured.', path=mapname)
            return 'unknown'
        accepted = [n for n in names if n and not n.startswith('.') and len(n) >= len(DIR_EXT) + 1
                    and n.endswith(DIR_EXT) and '/' not in n and '\x00' not in n and all(ord(c) <= 0xFF for c in n)]
        for entry in _versionsort(accepted):
            self.depth += 1
            self.nss_read(posixpath.join(mapname, entry))
            self.depth -= 1
        return 'success'

    def do_read(self, name: str, source: str) -> str:
        if source == 'file':
            return self.read_file(name)
        if source == 'dir':
            return self.read_dir(name)
        self.gap('remote_source_unobserved', 'A master map is read from a source this capture cannot observe.',
                 source=source, name=name)
        return 'unknown'

    # daemon/lookup.c lookup_nss_read_master
    def nss_read(self, name: str) -> str:
        if name.startswith('/'):
            return self.do_read(name, 'ldap' if name.startswith('//') else 'file')
        colon = name.find(':')
        if colon >= 0:
            def typed(t: str) -> bool:
                return name.startswith(t) and len(name) > len(t) and name[len(t)] in ',:'
            # Upstream tests "sss" as (!strncmp(name, "sss", 3) || name[3] in ",:"), so any
            # name whose fourth character is ',' or ':' takes this branch.
            if any(typed(t) for t in ('file', 'yp', 'nis', 'nisplus', 'ldap', 'ldaps', 'dir')) or \
                    name.startswith('sss') or (len(name) > 3 and name[3] in ',:'):
                source = name[:colon]
                if source in ('file', 'dir'):
                    return self.do_read(name[colon + 1:], source)
                if source in MASTER_REMOTE_TYPES:
                    return self.do_read(name, source)
                self.gap('master_source_not_modelled', 'A typed master map name selects a lookup module this '
                         'contract does not model.', name=name)
                return 'unknown'
        result = 'success'
        for source in self.sources:
            if not source.startswith(MASTER_NSS_PREFIXES):
                continue
            result = self.read_master_map(name, source)
            if result != 'success' and self.depth == 0 and not self.master_set and '.' in name:
                alt = name.replace('.', '_', 1)
                result = self.read_master_map(alt, source)
            if result in ('tryagain', 'unknown', 'notfound', 'unavail'):
                result = 'success'
                continue
            break
        return result

    def read_master_map(self, name: str, source: str) -> str:
        if source != 'files':
            self.gap('remote_source_unobserved', 'An nsswitch source is queried for a master map that this '
                     'capture cannot observe.', source=source, name=name)
            return 'unknown'
        if '/' in name:
            return 'notfound'
        return self.do_read(posixpath.join(MAP_DIR, name), 'file')


def read_master(master_map_name: str | None = None, files: Mapping[str, Any] | None = None,
                stats: Mapping[str, Any] | None = None, dirs: Mapping[str, Any] | None = None,
                nss_sources: Iterable[str] | None = None) -> dict[str, Any]:
    """Read the master map the way automount does and list every entry it would parse.

    ``master_map_name`` is ``master_map_name`` from autofs.conf, or ``None``
    when it is not set (``auto.master``, with the ``auto_master`` fallback).
    ``files`` maps a path to its captured text, ``stats`` follows the
    ``evaluate`` shape, and ``dirs`` maps a directory to its captured entry
    names. Each record's ``buffer`` is the text ``master_parse_entry`` parses.
    """
    files = files if isinstance(files, Mapping) else {}
    stats = stats if isinstance(stats, Mapping) else {}
    dirs = dirs if isinstance(dirs, Mapping) else {}
    if nss_sources is None:
        sources = DEFAULT_NSS_SOURCES
    else:
        sources = tuple(s for s in nss_sources if isinstance(s, str) and s in NSS_SOURCES)
    master_set = master_map_name is not None
    name = master_map_name if isinstance(master_map_name, str) and master_map_name else DEFAULT_MASTER_MAP_NAME
    m = _Master(files, stats, dirs, sources, master_set)
    m.nss_read(name)
    return {
        'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS),
        'master_map_name': name,
        'records': m.records,
        'gaps': m.gaps,
        'complete': not any(g['blocking'] for g in m.gaps),
        'origin': 'not_assessed',
        'not_observed': [
            'Whether automount was started with a master map on its command line, which overrides master_map_name.',
            'The entry grammar of each record; records are returned as the buffers master_parse_entry parses.',
        ],
        'authorizes_response': False,
    }


# ---------------------------------------------------------------------------
# Increment 3: the entry grammar (``daemon/master_tok.l``, ``daemon/master_parse.y``
# and the ``master_parse_entry`` bookkeeping in the same file).
#
# The flex scanner has longest-match rules that fire anywhere in a map name
# (``-hosts``, ``--``+blank, ``//``, ``<maptype>:``, ``<attr>=``) and keeps its
# start condition across buffers after an aborted parse. Rather than
# transcribe every quirk, ``parse_entry`` accepts only a narrow subset whose
# tokenization was checked rule by rule against the scanner; anything else is
# ``unmodelled``, and every later record in the same read is unmodelled too,
# because an aborted parse can leave the scanner in a non-initial state.
# ---------------------------------------------------------------------------

MAP_TYPES = ('file', 'program', 'exec', 'sss', 'yp', 'nis', 'nisplus', 'ldap', 'ldaps', 'hesiod', 'userdir')
MAP_FORMATS = ('sun', 'hesiod', 'amd')
_KEYWORDS = frozenset(MAP_TYPES) | {'multi'}

# PATHSTR without escapes or quotes: printable ASCII except blank, '"' and '\'.
_PATH = r'/[!#-\[\]-~]*'
# A map-name character in MAPSTR that no rule other than '.' can start or
# extend: printable ASCII except blank, '"', '\', ':', '=' and ','.
_NAME = r'[!#-+\--9;<>-\[\]-~]+'
_TYPED = r'(?P<type>' + '|'.join(sorted(MAP_TYPES, key=len, reverse=True)) + r')(?:,(?P<fmt>sun|hesiod|amd))?:'
# One OPTSTR word that lexes to exactly one OPTION token or daemon keyword,
# or a timeout option that lexes to OPT_TIMEOUT / OPT_NTIMEOUT then NUMBER.
_TIMEOUT = r'(?:-[tn]|--timeout|--negative-timeout)(?:[ \t]*=[ \t]*|[ \t]*)[0-9]+(?=[ \t,]|\Z)'
_OPT = r'(?:' + _TIMEOUT + r'|-?[A-Za-z_][A-Za-z0-9_-]*(?:=[A-Za-z0-9_.:-]+)?)'
_SEP = r'(?:[ \t]*,[ \t]*|[ \t]+)'
_ENTRY = re.compile(
    r'(?P<path>' + _PATH + r')[ \t]+'
    r'(?:(?P<int>-hosts|-null)|(?:' + _TYPED + r')?(?P<name>' + _NAME + r'))'
    r'(?P<opts>[ \t]+' + _OPT + r'(?:' + _SEP + _OPT + r')*)?'
    r'[ \t]*\Z')
_OPT_WORD = re.compile(_OPT)
_DAEMON_OPT = re.compile(
    r'(?:-?(?:symlink|nobind|nobrowse|shared|slave|private|strictexpire|browse)|-[gvdwr])\Z|' + _TIMEOUT)


def parse_entry(buffer: str) -> dict[str, Any]:
    """Parse one ``"<path> <entry>"`` record buffer as ``master_parse_entry`` would.

    Returns ``{'status': 'entry' | 'unmodelled', 'mount_point', 'type',
    'format', 'map', 'options'}``. ``status == 'entry'`` only for the subset
    this contract models; ``options`` are the mount options passed to the map
    module after the map name (daemon options such as ``--timeout`` are not).
    """
    out: dict[str, Any] = {'status': 'unmodelled', 'mount_point': None, 'type': None, 'format': None,
                           'map': None, 'options': []}
    if not isinstance(buffer, str) or len(buffer) > MAPENT_MAX_LEN + KEY_MAX_LEN + 2:
        return out
    m = _ENTRY.match(buffer)
    if not m:
        return out
    if m.group('int') is None:
        name = m.group('name')
        # Inside a map name the scanner starts other tokens at "-hosts",
        # "-null", "-xfn", "--"+blank and "//"; a name equal to a map-type
        # keyword followed by a blank lexes as MAPTYPE. A leading "-" is left
        # out rather than reasoned about.
        if name.startswith('-') or '//' in name or '--' in name or \
                any(k in name for k in ('-hosts', '-null', '-xfn')) or name in _KEYWORDS:
            return out
    words = _OPT_WORD.findall(m.group('opts') or '')
    # "-D NAME=value" with a blank is one MACROSTR token; not modelled.
    if '-D' in words:
        return out
    path = m.group('path')
    # master_parse_entry strips trailing slashes; "/" alone would become "".
    stripped = path.rstrip('/')
    if not stripped:
        return out
    mtype = m.group('type')
    if mtype == 'exec':
        mtype = 'program'
    if m.group('int') == '-hosts':
        mtype, name = 'hosts', None
    elif m.group('int') == '-null':
        mtype, name = 'null', None
    out.update(status='entry', mount_point=stripped, type=mtype, format=m.group('fmt'), map=name,
               options=[w for w in words if not _DAEMON_OPT.match(w)])
    return out


def entries_from_records(records: Iterable[Mapping[str, Any]],
                         amd_mount_paths: Iterable[str] | None = None) -> dict[str, Any]:
    """Turn ``read_master`` records into the entries automount would mount.

    Applies ``master_parse_entry`` bookkeeping: ``-null`` hides later entries
    for that mount point, a repeated indirect mount point in the same read is
    ignored (``/-`` direct maps accumulate), and an entry with no explicit
    format becomes ``amd`` when autofs.conf has a ``[ <mount point> ]`` amd
    section. ``amd_mount_paths`` is that section list (empty when autofs.conf
    was captured and has none), or ``None`` when it was not captured.
    """
    gaps: list[dict[str, Any]] = []
    amd = None if amd_mount_paths is None else {p.rstrip('/') for p in amd_mount_paths if isinstance(p, str)}
    nulled: set[str] = set()
    seen: set[str] = set()
    parsed: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    poisoned = False
    for rec in records or ():
        buf = rec.get('buffer') if isinstance(rec, Mapping) else None
        p = parse_entry(buf) if not poisoned else dict(parse_entry(''), status='unmodelled')
        if p['status'] != 'entry':
            if not poisoned:
                _gap(gaps, 'entry_grammar_not_modelled', 'A master map entry uses syntax this contract does not '
                     'model; it and every later entry in the read are not resolved.', buffer=(buf or '')[:200])
            poisoned = True
            parsed.append({'buffer': buf, 'status': 'unmodelled'})
            continue
        mount = p['mount_point']
        if p['type'] == 'null':
            nulled.add(mount)
            parsed.append({'buffer': buf, 'status': 'null', 'mount_point': mount})
            continue
        if mount in nulled:
            parsed.append({'buffer': buf, 'status': 'nulled', 'mount_point': mount})
            continue
        if mount in seen and mount != '/-':
            parsed.append({'buffer': buf, 'status': 'duplicate', 'mount_point': mount})
            continue
        seen.add(mount)
        fmt = p['format']
        if fmt is None:
            if amd is None:
                if p['type'] is None and p['map'] and not p['map'].startswith('/'):
                    _gap(gaps, 'amd_sections_not_observed', 'autofs.conf was not captured, so whether this '
                         'relative map is amd format is unknown.', mount_point=mount)
            elif mount in amd:
                fmt = 'amd'
        entry = {'mount_point': mount, 'type': p['type'], 'format': fmt, 'map': p['map'], 'options': p['options']}
        entries.append(entry)
        parsed.append({'buffer': buf, 'status': 'entry', **entry})
    return {'entries': entries, 'parsed': parsed, 'gaps': gaps}


ENTRY_BLOCKING = frozenset({'entry_grammar_not_modelled', 'amd_sections_not_observed'})


def evaluate_master(master_map_name: str | None = None, files: Mapping[str, Any] | None = None,
                    stats: Mapping[str, Any] | None = None, dirs: Mapping[str, Any] | None = None,
                    nss_sources: Iterable[str] | None = None, map_texts: Mapping[str, Any] | None = None,
                    amd_mount_paths: Iterable[str] | None = None) -> dict[str, Any]:
    """Read the master map, parse its entries and resolve the program maps automount runs as root.

    The arguments combine ``read_master``, ``entries_from_records`` and
    ``evaluate``. ``files`` supplies both master maps and text maps unless
    ``map_texts`` is given.
    """
    nss = None if nss_sources is None else list(nss_sources)
    read = read_master(master_map_name, files, stats, dirs, nss)
    built = entries_from_records(read['records'], amd_mount_paths)
    result = evaluate(built['entries'], stats, files if map_texts is None else map_texts, nss)
    for g in built['gaps']:
        g['blocking'] = g['code'] in ENTRY_BLOCKING
    gaps = read['gaps'] + built['gaps'] + result['gaps']
    if len(gaps) > MAX_GAPS:
        gaps = gaps[:MAX_GAPS - 1] + [{'code': 'gaps_truncated', 'detail': 'More gaps exist than are listed.',
                                        'blocking': True}]
    for e, src in zip(result['entries'], built['entries']):
        e['options'] = src['options']
    result.update(master_map_name=read['master_map_name'], records=built['parsed'], gaps=gaps,
                  complete=not any(g['blocking'] for g in gaps))
    result['not_observed'] = [
        ('Whether autofs is installed, enabled and running, and whether automount was started with a master map '
         'on its command line, which overrides master_map_name.'),
        *NOT_OBSERVED[2:],
    ]
    return result
