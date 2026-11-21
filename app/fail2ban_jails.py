"""Pure fail2ban jail contract (roadmap F slice, #1263).

``fail2ban-server`` runs as root. ``fail2ban-client start`` reads the jail
configuration under ``/etc/fail2ban``, starts every enabled jail and gives each
one the actions it names. A ``<name>`` action resolves to ``action.d/<name>``
files whose ``actionban``/``actionstart``/... values are shell commands run as
root; a ``<name>.py`` action is Python code loaded into the root server.

This module turns captured ``/etc/fail2ban`` file text and directory listings
into which jails are enabled, from which effective files in load order, and
which action specs each enabled jail names. It performs no I/O, never runs
fail2ban or a shell and never authorizes a response action. Resolving the
``action.d`` command text is a follow-up slice.

Semantics follow fail2ban 1.0.2 (Ubuntu ``1.0.2-3ubuntu0.1``) ``fail2ban/client``
``configreader.py``, ``configparserinc.py``, ``jailreader.py`` and
``jailsreader.py``. This is an independent reimplementation over the standard
library ``configparser``, with the same parser options upstream uses
(``inline_comment_prefixes=';'``, ``BasicInterpolation`` plus ``__name__`` and
``%(section/option)s`` mapping):

- **Load order.** ``jail.conf``, sorted ``jail.d/*.conf``, ``jail.local``,
  sorted ``jail.d/*.local``; only files that exist are kept. Globs skip names
  starting with ``.``.
- **Includes.** Every file is preceded by its ``[INCLUDES] before=`` files and
  followed by its ``after=`` files (newline-separated, relative to the
  including file's directory, recursive), and a file is followed by its sibling
  ``.local``. A path already on the ``seen`` chain is skipped, and include lists
  are cached per file list as upstream's ``share_config`` does.
- **Merging.** Later files update ``[DEFAULT]`` and each section key by key;
  overridden earlier values are kept in ``KNOWN/<section>``. A section named
  ``name?cond`` appends ``?cond`` to each of its keys and merges into ``name``.
- **Jails.** Every section except ``INCLUDES`` (and ``DEFAULT``) is a jail.
  ``enabled``, ``backend`` and ``filter`` are read first; only enabled jails
  go on. An invalid ``filter`` or ``action`` spec, or a filter or action with
  no ``.conf``/``.d/*.conf``/``.local``/``.d/*.local`` file, is a per-jail
  ``config_error``: that jail is skipped and the others still start.
  ``name.py`` actions become ``addaction`` with ``action.d/<name>.py`` and are
  never read by the client.

Fail-closed rules (``complete: False``): an unobserved file or directory, a
path with ``..``, NUL bytes, text that is not UTF-8, over-limit input, a parse
or interpolation error that makes upstream raise, any interpolation in an
enabled jail that reads ``known/`` values a filter would supply, and an
enabled jail's ``action`` option list that upstream's backtracking
``splitWithOptions`` regex could split more than one way
(``action_syntax_unresolved``; the scanner here is linear). Filter and
action file contents are not evaluated in this slice, so any enabled jail that
reads one carries the blocking ``definitions_not_evaluated`` gap. The
``logpath`` glob check in ``convert()`` (which can stop the whole start) is not
modeled. ``origin`` is always ``not_assessed`` and no result is a safety
verdict.
"""
from __future__ import annotations

import configparser
import hashlib
import json
import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('1.0.2',)
FAIL2BAN_VERSION = '1.0.2'
BASEDIR = '/etc/fail2ban'
MAX_FILES = 512
MAX_TEXT = 1048576
MAX_INCLUDE_RESULTS = 4096
MAX_INCLUDE_DEPTH = 32

BLOCKING = frozenset({
    'file_not_observed', 'path_traversal', 'file_nul', 'file_invalid_utf8',
    'too_large', 'parse_error', 'interpolation_error', 'include_limit',
    'known_values_not_evaluated', 'definitions_not_evaluated', 'action_syntax_unresolved',
})

_SECTION_OPTNAME_CRE = re.compile(r'^([\w\-]+)/([^\s>]+)$')
_SECTION_OPTSUBST_CRE = re.compile(r'%\(([\w\-]+/([^\)]+))\)s')
_CONDITIONAL_RE = re.compile(r'^(\w+)(\?.+)$')
# helpers.py OPTION_CRE / OPTION_EXTRACT_CRE (1.0.2). OPTION_SPLIT_CRE is
# replaced by the linear ``split_with_options`` scanner below.
_OPTION_CRE = re.compile(r'^([^\[]+)(?:\[(.*)\])?\s*$', re.DOTALL)
_OPTION_EXTRACT_CRE = re.compile(
    r'\s*([\w\-_\.]+)=(?:"([^"]*)"|\'([^\']*)\'|([^,\]]*))(?:,|\]\s*\[|$|(?P<wrngA>.+))|,?\s*$|(?P<wrngB>.+)',
    re.DOTALL)
_KEY_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.')

# jailreader.py _configOpts1st and _configOpts (with FilterReader._configOpts).
_OPTS_FIRST = (('enabled', 'bool', False), ('backend', 'string', 'auto'), ('filter', 'string', ''))
_OPTS_SECOND = (
    ('enabled', 'bool', False), ('backend', 'string', 'auto'), ('maxretry', 'int', None),
    ('maxmatches', 'int', None), ('findtime', 'string', None), ('bantime', 'string', None),
    ('bantime.increment', 'bool', None), ('bantime.factor', 'string', None),
    ('bantime.formula', 'string', None), ('bantime.multipliers', 'string', None),
    ('bantime.maxtime', 'string', None), ('bantime.rndtime', 'string', None),
    ('bantime.overalljails', 'bool', None), ('ignorecommand', 'string', None),
    ('ignoreself', 'bool', None), ('ignoreip', 'string', None), ('ignorecache', 'string', None),
    ('filter', 'string', ''), ('logtimezone', 'string', None), ('logencoding', 'string', None),
    ('logpath', 'string', None), ('action', 'string', ''),
    ('usedns', 'string', None), ('prefregex', 'string', None), ('ignoreregex', 'string', None),
    ('failregex', 'string', None), ('maxlines', 'int', None), ('datepattern', 'string', None),
    ('journalmatch', 'string', None),
)


class _Unresolved(Exception):
    def __init__(self, code: str, detail: str = ''):
        super().__init__(code)
        self.code = code
        self.detail = detail


class _JailDefError(Exception):
    pass


def _as_bool(val: Any) -> bool:
    return bool(val) if not isinstance(val, str) else val.lower() in ('1', 'on', 'true', 'yes')


class _FS:
    """Observed files and complete directory listings."""

    def __init__(self, files: Mapping[str, Any], listed_dirs: Iterable[str]):
        self.files: dict[str, str] = {}
        self.bad: dict[str, str] = {}
        self.dirs = {posixpath.normpath(d) for d in listed_dirs}
        for path, raw in files.items():
            key = posixpath.normpath(path)
            if isinstance(raw, bytes):
                if b'\0' in raw:
                    self.bad[key] = 'file_nul'
                    continue
                try:
                    raw = raw.decode('utf-8')
                except UnicodeDecodeError:
                    self.bad[key] = 'file_invalid_utf8'
                    continue
            if not isinstance(raw, str):
                self.bad[key] = 'file_not_observed'
                continue
            if '\0' in raw:
                self.bad[key] = 'file_nul'
                continue
            # open() in text mode translates universal newlines.
            self.files[key] = raw.replace('\r\n', '\n').replace('\r', '\n')

    def _key(self, path: str) -> str:
        if '..' in path.split('/'):
            raise _Unresolved('path_traversal', path)
        return posixpath.normpath(path)

    def exists(self, path: str) -> bool:
        if path.endswith('/'):
            return False  # a directory: open() fails and configparser skips it
        key = self._key(path)
        if key in self.bad:
            raise _Unresolved(self.bad[key], path)
        if key in self.files:
            return True
        if posixpath.dirname(key) in self.dirs:
            return False
        raise _Unresolved('file_not_observed', path)

    def text(self, path: str) -> str | None:
        return self.files[self._key(path)] if self.exists(path) else None

    def glob(self, directory: str, suffix: str) -> list[str]:
        key = self._key(directory)
        if key not in self.dirs:
            raise _Unresolved('file_not_observed', directory + '/*' + suffix)
        names = []
        for path in list(self.files) + list(self.bad):
            if posixpath.dirname(path) == key:
                base = posixpath.basename(path)
                if base.endswith(suffix) and not base.startswith('.'):
                    names.append(directory + '/' + base)
        return sorted(names)


class _Interpolation(configparser.BasicInterpolation):
    def _interpolate_some(self, parser, option, accum, rest, section, map, depth):
        if section:
            map = map.copy()
            map['__name__'] = section
            parser._map_section_options(section, option, rest, map)
        return super()._interpolate_some(parser, option, accum, rest, section, map, depth)


class _Parser(configparser.ConfigParser):
    def __init__(self, ctx: _Ctx):
        super().__init__(interpolation=_Interpolation(), inline_comment_prefixes=';')
        self._ctx = ctx
        self.track_known = False
        self.known_refs: list[str] = []

    # -- configparserinc.SafeConfigParserWithIncludes ---------------------
    def _map_section_options(self, section, option, rest, defaults):
        if '/' not in rest or '%(' not in rest:
            return
        for sopt, opt in _SECTION_OPTSUBST_CRE.findall(rest):
            if self.track_known and 'known' in sopt.lower():
                self.known_refs.append(sopt)
            if sopt in defaults:
                continue
            sec = sopt[:~len(opt)]
            seclwr = sec.lower()
            usedef = False
            v = None
            if seclwr != 'default':
                if seclwr == 'known':
                    try:
                        v = self._sections['KNOWN/' + section][opt]
                    except KeyError:
                        usedef = True
                else:
                    try:
                        secd = self._sections[sec]
                    except KeyError:
                        continue
                    try:
                        v = secd[opt]
                    except KeyError:
                        usedef = True
            else:
                usedef = True
            if usedef:
                try:
                    v = self._defaults[opt]
                except KeyError:
                    continue
            defaults[sopt] = v

    def read_single(self, path: str) -> bool:
        text = self._ctx.fs.text(path)
        if text is None:
            return False
        self._ctx.bytes_read += len(text)
        if self._ctx.bytes_read > MAX_TEXT:
            raise _Unresolved('too_large', path)
        try:
            self.read_string(text, source=path)
        except configparser.Error as exc:
            raise _Unresolved('parse_error', f'{path}: {type(exc).__name__}') from exc
        return True

    def options_with_default(self, section: str) -> set:
        return set(self._sections[section].keys()) | set(self._defaults)

    def merge_section(self, section: str, options: Mapping[str, Any], pref: str = '') -> None:
        sec = self._sections.setdefault(section, {})
        if not pref:
            sec.update(options)
            return
        sec.update({pref + k: v for k, v in options.items() if not k.startswith(pref) and k != '__name__'})


class _Ctx:
    def __init__(self, fs: _FS):
        self.fs = fs
        self.bytes_read = 0
        self.file_cache: dict[str, tuple[_Parser, bool]] = {}
        self.inc_cache: dict[str, list[str]] = {}
        self.include_results = 0

    def single(self, path: str) -> tuple[_Parser, bool]:
        hit = self.file_cache.get(path)
        if hit is None:
            cfg = _Parser(self)
            hit = (cfg, cfg.read_single(path))
            self.file_cache[path] = hit
        return hit

    def expand_local(self, filenames: list[str]) -> list[str]:
        out = []
        for name in filenames:
            out.append(name)
            local = posixpath.splitext(name)[0] + '.local'
            if local not in filenames and self.fs.exists(local):
                out.append(local)
        return out

    def includes(self, filenames: list[str], seen: list[str]) -> list[str]:
        filenames = self.expand_local(filenames)
        key = '\x01'.join(filenames)
        cached = self.inc_cache.get(key)
        if cached is not None:
            return cached
        full: list[str] = []
        for name in filenames:
            full += self._includes_one(name, seen)
        self.inc_cache[key] = full
        self.include_results += len(full)
        if self.include_results > MAX_INCLUDE_RESULTS:
            raise _Unresolved('include_limit', key)
        return full

    def _includes_one(self, resource: str, seen: list[str]) -> list[str]:
        # A sibling .local is never checked against ``seen``, so upstream can
        # recurse until Python's RecursionError; stop well before that.
        if len(seen) > MAX_INCLUDE_DEPTH:
            raise _Unresolved('include_limit', resource)
        parser, ok = self.single(resource)
        if not ok:
            return []
        rdir = posixpath.dirname(resource)
        lists: dict[str, list[str]] = {'before': [], 'after': []}
        if 'INCLUDES' in parser.sections():
            for opt in ('before', 'after'):
                if opt in parser.options_with_default('INCLUDES'):
                    try:
                        value = parser.get('INCLUDES', opt)
                    except configparser.Error as exc:
                        raise _Unresolved('interpolation_error', f'{resource} [INCLUDES] {opt}') from exc
                    for res in value.split('\n'):
                        r = res if posixpath.isabs(res) else posixpath.join(rdir, res)
                        if r in seen:
                            continue
                        lists[opt] += self.includes([r], seen + [resource])
        return lists['before'] + [resource] + lists['after']


def _config_files(fs: _FS, name: str) -> list[str]:
    base = posixpath.join(BASEDIR, name)
    candidates = [base + '.conf'] + fs.glob(base + '.d', '.conf') + [base + '.local'] + fs.glob(base + '.d', '.local')
    return [c for c in candidates if fs.exists(c)]


def _read_main(ctx: _Ctx) -> tuple[_Parser, list[str]]:
    main = _Parser(ctx)
    config_files = _config_files(ctx.fs, 'jail')
    full = ctx.includes(config_files, []) if config_files else []
    loaded = []
    for path in full:
        cfg, ok = ctx.single(path)
        if not ok:
            continue
        loaded.append(path)
        main._defaults.update(cfg._defaults)
        for n, s in cfg._sections.items():
            cond = _CONDITIONAL_RE.match(n)
            if cond:
                n, suffix = cond.groups()
                s = {k + suffix: v for k, v in s.items() if k != '__name__'}
            s2 = main._sections.get(n)
            if isinstance(s2, dict):
                main.merge_section('KNOWN/' + n, {k: v for k, v in s2.items() if k in s}, '')
                s2.update(s)
            else:
                main._sections[n] = dict(s)
    return main, loaded


def _get_options(cfg: _Parser, section: str, template) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name, kind, default in template:
        try:
            v = cfg.get(section, name)
        except configparser.NoOptionError:
            if default is not None:
                values[name] = default
            continue
        except configparser.Error as exc:
            raise _Unresolved('interpolation_error', f'[{section}] {name}') from exc
        values[name] = v
        if kind == 'bool':
            values[name] = _as_bool(v)
        elif kind == 'int':
            try:
                values[name] = int(v)
            except ValueError:
                values[name] = default
    return values


def extract_options(option: str) -> tuple[str, dict[str, str]]:
    match = _OPTION_CRE.match(option)
    if not match:
        raise ValueError('unexpected option syntax')
    name, optstr = match.groups()
    opts: dict[str, str] = {}
    if optstr:
        for m in _OPTION_EXTRACT_CRE.finditer(optstr):
            if m.group('wrngA') or m.group('wrngB'):
                raise ValueError('unexpected option syntax')
            opt = m.group(1)
            if not opt:
                continue
            value = next(val for val in m.group(2, 3, 4) if val is not None)
            opts[opt.strip()] = value.strip()
    return name, opts


class _SplitUnresolved(ValueError):
    pass


def _is_key_char(ch: str) -> bool:
    # ``[\w\-_\.]`` in upstream's pattern; ``\w`` is Unicode-aware (``isalnum``).
    return ch in _KEY_CHARS or ch.isalnum()


def _split_bracket(text: str, pos: int) -> int:
    """Return the index just past the closing ``]`` of the first-choice parse.

    ``pos`` is the index of the opening ``[``. Each step takes the alternative
    upstream's backtracking regex tries first; any point where that first
    choice fails (where the regex would start backtracking) raises
    ``_SplitUnresolved`` instead of exploring alternatives.
    """
    n = len(text)
    i = pos + 1
    while i < n and text[i].isspace():
        i += 1
    while True:
        if i >= n:
            raise _SplitUnresolved('unterminated option list')
        if not _is_key_char(text[i]):
            if text[i] == ']':
                return i + 1
            raise _SplitUnresolved('unexpected option character')
        while i < n and _is_key_char(text[i]):
            i += 1
        if i >= n or text[i] != '=':
            raise _SplitUnresolved('option without =')
        i += 1
        quoted = False
        if i < n and text[i] in '"\'':
            close = text.find(text[i], i + 1)
            if close >= 0:
                i = close + 1
                quoted = True
        if not quoted:
            while i < n and text[i] not in ',]':
                i += 1
        while i < n and text[i].isspace():
            i += 1
        if i < n and text[i] == ',':
            i += 1
        elif i < n and text[i] == ']':
            j = i + 1
            while j < n and text[j].isspace():
                j += 1
            if j < n and text[j] == '[':
                i = j + 1
        while i < n and text[i].isspace():
            i += 1


def split_with_options(option: str) -> list[str]:
    """Split an ``action`` value like upstream ``splitWithOptions`` (1.0.2).

    Upstream uses ``re.findall`` with a pattern whose ambiguous option list
    backtracks exponentially (CodeQL ``py/redos``). This linear scanner follows
    the regex's first-choice path for every token, which is exactly what the
    regex returns whenever that path succeeds. When it would fail and the regex
    would backtrack into alternative splits, ``_SplitUnresolved`` is raised and
    the caller reports a blocking gap instead of guessing.
    """
    text = option
    n = len(text)
    out: list[str] = []
    i = 0
    while i < n:
        if text[i].isspace():
            i += 1
            continue
        start = i
        if text[i] == '[':
            while i < n and not text[i].isspace():
                i += 1
            out.append(text[start:i])
            continue
        while i < n and text[i] != '[' and not text[i].isspace():
            i += 1
        j = i
        while j < n and text[j].isspace():
            j += 1
        if j < n and text[j] == '[' and ']' in text[j:]:
            i = _split_bracket(text, j)
        elif j < n and text[j] == '[' and j == i:
            # No ``]`` remains, so no option list can match: the regex falls
            # back to ``\S+``.
            while i < n and not text[i].isspace():
                i += 1
            out.append(text[start:i])
            continue
        elif j == i:
            out.append(text[start:i])
            continue
        # Trailing ``\s*`` then the ``(?=\s|$)`` lookahead: keep the whitespace
        # run except its last character, or all of it at the end of the text.
        j = i
        while j < n and text[j].isspace():
            j += 1
        if j == n:
            end = n
        elif j > i:
            end = j - 1
        else:
            raise _SplitUnresolved('option list not followed by whitespace')
        out.append(text[start:end])
        i = end
    return out


def _definition_files(fs: _FS, kind: str, name: str) -> list[str]:
    return _config_files(fs, posixpath.join(kind, name))


def _jail(cfg: _Parser, fs: _FS, name: str, any_filter: list[bool]) -> dict[str, Any]:
    first = _get_options(cfg, name, _OPTS_FIRST)
    out: dict[str, Any] = {'jail': name, 'enabled': bool(first.get('enabled')),
                           'filter': None, 'actions': [], 'status': 'not_started',
                           'config_error': None, 'definition_files': []}
    if not out['enabled']:
        return out
    try:
        flt = first['filter']
        if flt:
            try:
                fname, fopts = extract_options(flt)
            except ValueError as exc:
                raise _JailDefError('invalid_filter') from exc
            files = _definition_files(fs, 'filter.d', fname)
            out['filter'] = {'name': fname, 'options': fopts, 'files': files}
            if not files:
                raise _JailDefError('filter_not_found')
            out['definition_files'] += files
            any_filter[0] = True
        cfg.track_known = bool(flt)
        cfg.known_refs = []
        try:
            second = _get_options(cfg, name, _OPTS_SECOND)
        except _Unresolved:
            # The filter's known/ values may be what upstream interpolates here.
            if not cfg.known_refs:
                raise
        finally:
            cfg.track_known = False
        if cfg.known_refs:
            raise _Unresolved('known_values_not_evaluated', f'[{name}] ' + ', '.join(sorted(set(cfg.known_refs))))
        try:
            action_specs = split_with_options(second.get('action', ''))
        except _SplitUnresolved as exc:
            raise _Unresolved('action_syntax_unresolved', f'[{name}] {exc}') from exc
        for act in action_specs:
            act = act.strip()
            if not act:
                continue
            try:
                aname, aopts = extract_options(act)
            except ValueError as exc:
                raise _JailDefError('invalid_action') from exc
            if aname.endswith('.py'):
                actname = aopts.pop('actname', posixpath.splitext(aname)[0])
                out['actions'].append({'kind': 'python', 'name': aname, 'actname': actname,
                                       'options': aopts,
                                       'path': posixpath.join(BASEDIR, 'action.d', aname),
                                       'runs_as': 'root'})
                continue
            n = aopts.get('name', name)
            actname = aopts.get('actname')
            if actname is None:
                actname = aname
                if n != name:
                    actname += n[len(name):] if n.startswith(name) else '-' + n
            files = _definition_files(fs, 'action.d', aname)
            if not files:
                raise _JailDefError('action_not_found')
            out['definition_files'] += files
            out['actions'].append({'kind': 'command', 'name': aname, 'actname': actname,
                                   'options': aopts, 'files': files, 'runs_as': 'root'})
    except _JailDefError as exc:
        out['status'] = 'config_error'
        out['config_error'] = str(exc)
        out['actions'] = []
        return out
    out['status'] = 'starts'
    return out


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def assess(files: Mapping[str, Any] | None, listed_dirs: Iterable[str] | None) -> dict[str, Any]:
    """Resolve enabled fail2ban jails and their action specs.

    ``files`` maps absolute paths under ``/etc/fail2ban`` to captured text
    (``str`` or ``bytes``); ``listed_dirs`` names every directory whose full
    file listing was observed (an observed-empty or absent directory is listed
    with no files). A file outside both is unobserved.
    """
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
        'complete': False, 'gaps': [], 'loaded_files': [], 'jails': [],
        'reader_ok': None, 'origin': 'not_assessed', 'verdict': None,
    }
    if files is None or listed_dirs is None:
        result['gaps'].append({'code': 'file_not_observed', 'detail': BASEDIR, 'blocking': True})
        return result
    if len(files) > MAX_FILES:
        result['gaps'].append({'code': 'too_large', 'detail': 'files', 'blocking': True})
        return result
    fs = _FS(files, listed_dirs)
    ctx = _Ctx(fs)
    any_filter = [False]
    try:
        cfg, loaded = _read_main(ctx)
        result['loaded_files'] = loaded
        cfg._defaults.update({'fail2ban_version': FAIL2BAN_VERSION, 'fail2ban_confpath': BASEDIR})
        status = 0
        for sec in [s for s in cfg.sections() if not s.startswith('KNOWN/')]:
            if sec == 'INCLUDES':
                continue
            jail = _jail(cfg, fs, sec, any_filter)
            result['jails'].append(jail)
            if jail['status'] == 'starts':
                status |= 1
            elif jail['status'] == 'config_error':
                status |= 2
        result['reader_ok'] = bool(status & 1) or not (status & 2)
    except _Unresolved as exc:
        result['gaps'].append({'code': exc.code, 'detail': exc.detail, 'blocking': True})
        result['jails'] = []
        result['reader_ok'] = None
        return result
    pending = sorted({f for j in result['jails'] if j['status'] == 'starts' for f in j['definition_files']})
    if pending:
        result['gaps'].append({'code': 'definitions_not_evaluated', 'detail': ', '.join(pending),
                               'blocking': True})
    result['complete'] = not any(g['blocking'] for g in result['gaps'])
    result['digest'] = _digest({k: result[k] for k in ('loaded_files', 'jails', 'reader_ok')})
    return result
