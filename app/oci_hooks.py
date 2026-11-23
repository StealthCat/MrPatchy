"""Pure OCI hooks.d contract (roadmap F slice, #1471).

Podman and CRI-O load JSON hook definitions from ``hooks.d`` directories through
containers/common ``pkg/hooks``. Every matching hook program is injected into
the OCI runtime configuration of each new container. The runtime, or the
engine itself for its extension stages, then runs it at that lifecycle stage
with the engine's privileges, which are root for a rootful engine, outside the
container. This module turns captured directory listings, captured hook file
text and the captured existence of each hook program into the hooks the engine
would inject. It performs no I/O, never runs a hook or an engine and never
authorizes a response action.

The rules follow ``pkg/hooks`` in containers/common v0.60.4 (``read.go``,
``hooks.go``, ``0.1.0/hook.go``, ``1.0.0/hook.go``, ``1.0.0/when.go``) and
``pkg/fileutils/exists_unix.go`` in containers/storage v1.55.0:

- The engine's ordered ``hooks_dir`` list is read directory by directory. In
  each directory only entries whose name ends in ``.json`` are read, in
  ``os.ReadDir`` (byte) order. A file that loads replaces any earlier hook of
  the same file name. A file that fails to load masks nothing.
- A dangling ``.json`` entry is skipped. Any other per-file failure is kept,
  and the directory's error wraps the first one. The engine ignores the error
  only when that first failure is "does not exist": a missing directory, or a
  missing ``hook.path``. Any other failure makes the engine refuse the whole
  hook set (``status: aborts``).
- ``version`` ``"1.0.0"`` uses the current format. ``"0.1.0"`` and a missing
  version use the legacy format, which is converted to the current one. Any
  other version is a failure. Validation requires a non-empty ``hook.path``
  that exists (``faccessat`` ``F_OK``, following symlinks), regexes that
  compile, non-null ``stages`` and only known or extension stages.
- Hooks are injected in the order of their lower-cased file names. A current
  ``when`` is an AND of ``always``, ``hasBindMounts`` and every annotation
  pattern, and a non-empty ``commands`` list then decides on the container's
  first argument. ``always: false``, ``hasBindMounts: false`` or an empty
  ``when`` never match. A legacy hook is an OR of ``cmds``, ``annotations`` and
  ``hasbindmounts: true``, so a legacy hook without any of them never matches.

Go's ``encoding/json`` matches keys without regard to case, merges duplicate
objects and rejects wrong types, and Go's RE2 accepts a different regex syntax
from Python. Where this module cannot reproduce those exactly it records a
blocking gap instead of guessing. ``origin`` is always ``not_assessed`` and no
result is a safety verdict.
"""
from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('containers/common v0.60.4', 'containers/storage v1.55.0')
DEFAULT_DIR = '/usr/share/containers/oci/hooks.d'
OVERRIDE_DIR = '/etc/containers/oci/hooks.d'
CURRENT = '1.0.0'
LEGACY = '0.1.0'
STAGES = ('createContainer', 'createRuntime', 'prestart', 'poststart', 'poststop', 'startContainer')
MAX_TEXT = 65536
MAX_DIRS = 16
MAX_ENTRIES = 512
MAX_HOOKS = 256
MAX_GAPS = 64
_INT64 = (-(1 << 63), (1 << 63) - 1)

BLOCKING = frozenset({
    'directory_not_observed', 'file_not_observed', 'hook_path_not_observed', 'relative_path', 'rootful_unknown',
    'json_key_unverified', 'json_duplicate_key', 'json_string_unverified', 'regex_unverified', 'entry_unverified',
    'over_limit', 'invalid_utf8', 'binary', 'entries_over_limit', 'gaps_truncated', 'invalid_input',
})

NOT_OBSERVED = (
    ('Which engines are installed and which hooks_dir list each one uses. containers.conf, crio.conf and command '
     'line overrides decide it; the caller supplies the effective list.'),
    ('Which containers start, their annotations, first argument and bind mounts, so a conditional hook is '
     'reported with its conditions and not evaluated.'),
    'Whether each hook program is executable and what it does. The runtime only learns that when it runs it.',
    'Whether an engine watching its directories has picked up a change made after it started.',
    ('Podman with an explicitly empty hooks_dir list (rootful only) reads the default and override directories '
     'as two separate hook sets without masking. This contract models an explicit hooks_dir list only.'),
)


class _LoadError(Exception):
    def __init__(self, detail: str, not_exist: bool = False):
        super().__init__(detail)
        self.not_exist = not_exist


class _Unverified(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def _gap(gaps: list[dict[str, Any]], code: str, name: str | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'name': name, 'detail': detail[:240], 'blocking': code in BLOCKING})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'name': None, 'detail': 'Further gaps were not recorded.',
                     'blocking': True})


def _decode(path: str, raw: Any, gaps: list[dict[str, Any]]) -> str | None:
    if raw is None:
        _gap(gaps, 'file_not_observed', path)
        return None
    data = raw.encode('utf-8', 'surrogatepass') if isinstance(raw, str) else bytes(raw)
    if len(data) > MAX_TEXT:
        _gap(gaps, 'over_limit', path)
        return None
    if b'\0' in data:
        _gap(gaps, 'binary', path)
        return None
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', path)
        return None


# --- Go encoding/json, as far as this contract can reproduce it -------------------------------------------

class _Obj(list):
    """A JSON object kept as its ordered (key, value) pairs."""


class _Num(str):
    """A JSON number kept as its source token."""


def _no_constant(token: str) -> None:
    raise _LoadError(f'invalid character in JSON: {token}')


def _parse(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_Obj, parse_int=_Num, parse_float=_Num,
                          parse_constant=_no_constant)
    except ValueError as exc:
        raise _LoadError(f'invalid JSON: {exc}') from None


def _check_string(value: str) -> str:
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise _Unverified('json_string_unverified', 'a string holds an unpaired surrogate escape')
    return value


def _fields(value: Any, known: Iterable[str], where: str) -> dict[str, Any]:
    """Decode a JSON object into a struct with the given field names, as Go would, or refuse to guess."""
    if value is None:
        return {}
    if not isinstance(value, _Obj):
        raise _LoadError(f'{where}: cannot unmarshal {_kind(value)} into an object')
    known = tuple(known)
    seen: set[str] = set()
    out: dict[str, Any] = {}
    for key, item in value:
        if not key.isascii():
            raise _Unverified('json_key_unverified', f'{where}: non-ASCII key {key!r}')
        exact = key in known
        folded = [k for k in known if k.lower() == key.lower()]
        if folded and not exact:
            raise _Unverified('json_key_unverified', f'{where}: key {key!r} differs in case from {folded[0]!r}')
        if not folded:
            continue
        if key in seen:
            raise _Unverified('json_duplicate_key', f'{where}: duplicate key {key!r}')
        seen.add(key)
        out[key] = item
    return out


def _kind(value: Any) -> str:
    if isinstance(value, _Obj):
        return 'object'
    if isinstance(value, list):
        return 'array'
    if isinstance(value, _Num):
        return 'number'
    if isinstance(value, bool):
        return 'bool'
    return 'string' if isinstance(value, str) else 'null'


def _string(value: Any, where: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or isinstance(value, _Num):
        raise _LoadError(f'{where}: cannot unmarshal {_kind(value)} into a string')
    return _check_string(value)


def _strings(value: Any, where: str) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or isinstance(value, _Obj):
        raise _LoadError(f'{where}: cannot unmarshal {_kind(value)} into a string list')
    # Go stores a JSON null element of a string slice as "".
    return [_string(item, where) or '' for item in value]


def _bool(value: Any, where: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise _LoadError(f'{where}: cannot unmarshal {_kind(value)} into a bool')
    return value


def _int(value: Any, where: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, _Num) or not re.fullmatch(r'-?(0|[1-9][0-9]*)', value):
        raise _LoadError(f'{where}: cannot unmarshal {_kind(value)} {value!s:.40} into an int')
    number = int(value)
    if not _INT64[0] <= number <= _INT64[1]:
        raise _LoadError(f'{where}: number {value!s:.40} overflows an int')
    return number


def _string_map(value: Any, where: str) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, _Obj):
        raise _LoadError(f'{where}: cannot unmarshal {_kind(value)} into a string map')
    out: dict[str, str] = {}
    for key, item in value:
        out[_check_string(key)] = _string(item, where) or ''
    return out


# --- Go RE2 compilation, screened conservatively --------------------------------------------------------

_SAFE_ESCAPES = set('dDwWsSnrtfv') | set(r'.\-/^$*+?()[]{}|')
_SAFE_GROUP = re.compile(r'\(\?(?::|[imsU]+-?[imsU]*:|-[imsU]+:|[imsU]+-?[imsU]*\)|-[imsU]+\))')


def _check_regex(pattern: str, where: str) -> None:
    """Accept only syntax that RE2 and Python both compile the same way; otherwise refuse to guess."""
    reason = None
    in_class = False
    i = 0
    while i < len(pattern) and reason is None:
        ch = pattern[i]
        nxt = pattern[i + 1:i + 2]
        if ch == '\\':
            if nxt not in _SAFE_ESCAPES and not (nxt in 'bB' and not in_class):
                reason = f'escape \\{nxt}'
            i += 2
            continue
        if in_class:
            if ch == '[' and nxt in (':', '=', '.'):
                reason = 'character class syntax'
            elif ch == ']':
                in_class = False
        elif ch == '[':
            in_class = True
            j = i + 1
            if pattern[j:j + 1] == '^':
                j += 1
            if pattern[j:j + 1] == ']':
                j += 1
            if pattern[j:j + 1] in (':', '=', '.'):
                reason = 'character class syntax'
            i = j
            continue
        elif ch == '(' and nxt == '?' and not _SAFE_GROUP.match(pattern, i):
            reason = 'group syntax'
        elif ch in '*+?}' and nxt == '+':
            reason = 'possessive quantifier'
        elif ch == '{':
            reason = 'repetition syntax'
        i += 1
    if reason is None:
        try:
            re.compile(pattern.replace('(?U', '(?'))
        except re.error as exc:
            reason = str(exc)
    if reason is not None:
        raise _Unverified('regex_unverified', f'{where}: cannot verify {pattern[:60]!r} against RE2 ({reason})')


# --- hook formats -----------------------------------------------------------------------------------------

def _read(text: str) -> dict[str, Any]:
    """Return the hook as the current format, or raise _LoadError/_Unverified."""
    doc = _parse(text)
    if not isinstance(doc, _Obj):
        raise _LoadError(f'version check: cannot unmarshal {_kind(doc)} into an object')
    version = _string(_fields(doc, ('version',), 'version check').get('version'), 'version') or ''
    if version == CURRENT:
        return _read_current(doc)
    if version in ('', LEGACY):
        return _read_legacy(doc)
    raise _LoadError(f'unrecognized hook version: {version!r}')


def _read_current(doc: _Obj) -> dict[str, Any]:
    top = _fields(doc, ('version', 'hook', 'when', 'stages'), 'hook file')
    spec = _fields(top.get('hook'), ('path', 'args', 'env', 'timeout'), 'hook')
    when = _fields(top.get('when'), ('always', 'annotations', 'commands', 'hasBindMounts'), 'when')
    return {
        'format': CURRENT,
        'version': _string(top.get('version'), 'version') or '',
        'path': _string(spec.get('path'), 'hook.path') or '',
        'args': _strings(spec.get('args'), 'hook.args'),
        'env': _strings(spec.get('env'), 'hook.env'),
        'timeout': _int(spec.get('timeout'), 'hook.timeout'),
        'always': _bool(when.get('always'), 'when.always'),
        'annotations': _string_map(when.get('annotations'), 'when.annotations'),
        'commands': _strings(when.get('commands'), 'when.commands'),
        'has_bind_mounts': _bool(when.get('hasBindMounts'), 'when.hasBindMounts'),
        'or': False,
        'stages': _strings(top.get('stages'), 'stages'),
    }


def _read_legacy(doc: _Obj) -> dict[str, Any]:
    names = ('version', 'hook', 'arguments', 'stages', 'stage', 'cmds', 'cmd', 'annotations', 'annotation',
             'hasbindmounts')
    raw = _fields(doc, names, 'legacy hook file')
    hook = _string(raw.get('hook'), 'hook')
    arguments = _strings(raw.get('arguments'), 'arguments')
    pairs = {}
    for plural, single in (('stages', 'stage'), ('cmds', 'cmd'), ('annotations', 'annotation')):
        many, one = _strings(raw.get(plural), plural), _strings(raw.get(single), single)
        pairs[plural] = (many, one)
    has_bind = _bool(raw.get('hasbindmounts'), 'hasbindmounts')
    if hook is None:
        raise _LoadError('missing required property: hook')
    stages, stage = pairs['stages']
    if stages is not None and stage is not None:
        raise _LoadError("cannot set both 'stage' and 'stages'")
    stages = stage if stages is None else stages
    if stages is None:
        raise _LoadError('missing required property: stages')
    cmds, cmd = pairs['cmds']
    if cmds is not None and cmd is not None:
        raise _LoadError("cannot set both 'cmd' and 'cmds'")
    annotations, annotation = pairs['annotations']
    if annotations is not None and annotation is not None:
        raise _LoadError("cannot set both 'annotation' and 'annotations'")
    annotations = annotation if annotations is None else annotations
    return {
        'format': LEGACY, 'version': CURRENT, 'path': hook,
        'args': None if arguments is None else [hook, *arguments], 'env': None, 'timeout': None,
        'always': None,
        'annotations': None if annotations is None else {'.*': '|'.join(annotations)},
        'commands': cmd if cmds is None else cmds,
        'has_bind_mounts': has_bind, 'or': True, 'stages': stages,
    }


def _validate(hook: dict[str, Any], valid_stages: set[str], hook_paths: Mapping[str, Any]) -> None:
    if hook['version'] != CURRENT:
        raise _LoadError(f"unexpected hook version {hook['version']!r} (expecting {CURRENT})")
    path = hook['path']
    if path == '':
        raise _LoadError('missing required property: hook.path')
    if not path.startswith('/'):
        raise _Unverified('relative_path', f'hook.path {path[:120]!r} resolves against the engine working directory')
    state = hook_paths.get(path)
    if state is None:
        raise _Unverified('hook_path_not_observed', f'existence of {path[:200]} was not captured')
    if state == 'missing':
        raise _LoadError(f'faccessat {path}: no such file or directory', not_exist=True)
    if state != 'exists':
        raise _LoadError(f'faccessat {path}: {state}')
    for key, value in (hook['annotations'] or {}).items():
        _check_regex(key, 'annotation key')
        _check_regex(value, 'annotation value')
    for command in hook['commands'] or ():
        _check_regex(command, 'command')
    if hook['stages'] is None:
        raise _LoadError('missing required property: stages')
    for stage in hook['stages']:
        if stage not in valid_stages:
            raise _LoadError(f'unknown stage {stage!r}')


def _matches(hook: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    conditions = {
        'annotations': hook['annotations'] or {}, 'commands': list(hook['commands'] or ()),
        'has_bind_mounts': hook['has_bind_mounts'], 'combine': 'any' if hook['or'] else 'all',
    }
    if hook['or']:
        live = bool(hook['commands']) or hook['annotations'] is not None or hook['has_bind_mounts'] is True
        return ('conditional' if live else 'never'), conditions
    if hook['always'] is False or hook['has_bind_mounts'] is False:
        return 'never', conditions
    others = bool(hook['annotations']) or hook['has_bind_mounts'] is True or bool(hook['commands'])
    if others:
        return 'conditional', conditions
    return ('always' if hook['always'] else 'never'), conditions


# --- evaluation -------------------------------------------------------------------------------------------

def _result(status: str, gaps: list, hooks: list, files: list, *, dirs: list, rootful: bool | None,
            detail: str = '') -> dict[str, Any]:
    return {
        'contract': 'oci-hooks', 'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
        'hooks_dirs': dirs, 'rootful': rootful, 'status': status, 'detail': detail[:240],
        'complete': not any(g['blocking'] for g in gaps), 'origin': 'not_assessed',
        'hooks': hooks, 'files': files, 'gaps': gaps, 'not_observed': list(NOT_OBSERVED),
    }


def evaluate(*, hooks_dirs: Iterable[str], extension_stages: Iterable[str] = (), rootful: bool | None,
             directories: Mapping[str, Any], hook_paths: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve which hooks a containers/common engine injects from the captured hooks directories.

    ``hooks_dirs`` is the engine's effective ordered ``hooks_dir`` list and ``extension_stages`` the stages the
    engine runs itself (Podman 5.2 passes ``precreate`` and ``poststop``; CRI-O passes none). ``rootful`` says whether the engine runs as
    root (``None`` when unknown). ``directories`` maps each directory to ``'missing'``, ``None`` when unobserved,
    or a list of entries ``{'name', 'kind', 'text'}`` where ``kind`` is ``file`` (a regular file, or a symlink
    to one), ``dangling``, ``directory``, ``unreadable`` or ``other``. ``hook_paths`` maps each absolute hook
    program path to ``'exists'``, ``'missing'`` (ENOENT), another error string, or ``None`` when unobserved.
    """
    gaps: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    dirs = [d for d in hooks_dirs] if not isinstance(hooks_dirs, str) else [hooks_dirs]
    stages_extra = [s for s in extension_stages] if not isinstance(extension_stages, str) else [extension_stages]
    if (not dirs or len(dirs) > MAX_DIRS or not all(isinstance(d, str) for d in dirs)
            or not all(isinstance(s, str) for s in stages_extra)):
        _gap(gaps, 'invalid_input', 'hooks_dirs', 'hooks_dirs must list 1 to 16 directories')
        return _result('unresolved', gaps, [], files, dirs=[str(d)[:240] for d in dirs[:MAX_DIRS]],
                       rootful=rootful)
    if rootful is None:
        _gap(gaps, 'rootful_unknown', None, 'Whether the engine runs as root was not captured.')
    elif not isinstance(rootful, bool):
        _gap(gaps, 'invalid_input', 'rootful', 'rootful must be true, false or None')
        rootful = None
    valid_stages = set(STAGES) | set(stages_extra)
    loaded: dict[str, dict[str, Any]] = {}
    entries_seen = 0
    for directory in dirs:
        if not directory.startswith('/'):
            _gap(gaps, 'relative_path', directory)
            continue
        listing = directories.get(directory)
        if listing == 'missing':
            files.append({'directory': directory, 'name': None, 'path': directory, 'outcome': 'directory_missing',
                          'detail': ''})
            continue
        if listing is None:
            _gap(gaps, 'directory_not_observed', directory)
            continue
        if isinstance(listing, str) or not isinstance(listing, Iterable):
            _gap(gaps, 'invalid_input', directory, 'listing must be a list of entries')
            continue
        first_error: _LoadError | None = None
        first_error_file = None
        records = []
        for entry in listing:
            if not isinstance(entry, Mapping) or not isinstance(entry.get('name'), str):
                _gap(gaps, 'invalid_input', directory, 'listing entry must be a record with a string name')
                continue
            records.append(entry)
        ordered = sorted(records, key=lambda e: e['name'].encode('utf-8', 'surrogatepass'))
        for entry in ordered:
            name = entry['name']
            if not name.endswith('.json'):
                continue
            entries_seen += 1
            if entries_seen > MAX_ENTRIES:
                _gap(gaps, 'entries_over_limit', directory)
                break
            path = posixpath.join(directory, name)
            record = {'directory': directory, 'name': name, 'path': path, 'outcome': 'loaded', 'detail': ''}
            files.append(record)
            try:
                hook = _load_entry(entry, path, valid_stages, hook_paths, gaps)
            except _Unverified as exc:
                record.update(outcome='unverified', detail=str(exc))
                _gap(gaps, exc.code, path, str(exc))
                continue
            except _LoadError as exc:
                record.update(outcome='error', detail=str(exc), ignorable=exc.not_exist)
                if first_error is None:
                    first_error, first_error_file = exc, path
                continue
            if hook is None:
                record['outcome'] = 'skipped' if entry.get('kind') == 'dangling' else 'unverified'
                continue
            hook['source'] = path
            previous = loaded.get(name)
            hook['masks'] = ([*previous['masks'], previous['source']] if previous else [])
            loaded[name] = hook
        if first_error is not None and not first_error.not_exist:
            return _result('aborts', gaps, [], files, dirs=dirs, rootful=rootful,
                           detail=f'{first_error_file}: {first_error}')
    for record in files:
        if record['outcome'] == 'loaded':
            current = loaded.get(record['name'])
            if current is None or current['source'] != record['path']:
                record['outcome'] = 'masked'
    hooks = _inject(loaded, set(stages_extra), rootful, gaps)
    return _result('loads' if hooks else 'no_hooks', gaps, hooks, files, dirs=dirs, rootful=rootful)


def _load_entry(entry: Mapping[str, Any], path: str, valid_stages: set[str], hook_paths: Mapping[str, Any],
                gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    kind = entry.get('kind')
    if kind == 'dangling':
        return None
    if kind == 'directory':
        raise _LoadError(f'read {path}: is a directory')
    if kind == 'unreadable':
        raise _LoadError(f'open {path}: permission denied')
    if kind != 'file':
        raise _Unverified('entry_unverified', f'entry kind {str(kind)[:40]!r} is not modelled')
    text = _decode(path, entry.get('text'), gaps)
    if text is None:
        return None
    try:
        hook = _read(text)
    except _LoadError as exc:
        raise _LoadError(f'parsing hook {path!r}: {exc}') from None
    _validate(hook, valid_stages, hook_paths)
    return hook


def _inject(loaded: Mapping[str, dict[str, Any]], extension: set[str], rootful: bool | None,
            gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = sorted(loaded, key=str.lower)
    lowered = [n.lower() for n in names]
    if len(set(lowered)) != len(lowered) or not all(n.isascii() for n in names):
        _gap(gaps, 'order_unverified', None,
             'Two file names differ only in case, or a name is not ASCII, so the injection order may differ.')
    runs_as = 'root' if rootful else ('engine user' if rootful is False else None)
    out = []
    for name in names[:MAX_HOOKS]:
        hook = loaded[name]
        matches, conditions = _matches(hook)
        out.append({
            'name': name, 'source': hook['source'], 'masks': hook['masks'], 'format': hook['format'],
            'path': hook['path'], 'args': hook['args'], 'env': hook['env'], 'timeout': hook['timeout'],
            'stages': [{'stage': s, 'executor': 'engine' if s in extension else 'runtime',
                        'runtime_stage': None if s in extension else ('createRuntime' if s == 'prestart' else s)}
                       for s in hook['stages']],
            'runs_as': runs_as, 'matches': matches, 'conditions': conditions,
        })
    if len(names) > MAX_HOOKS:
        _gap(gaps, 'over_limit', None, f'{len(names) - MAX_HOOKS} further hooks were not reported.')
    return out
