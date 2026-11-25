"""Pure Zabbix agent UserParameter contract (roadmap F slice).

``zabbix_agentd`` is started at boot, usually as root, and then drops to
``User`` (default ``zabbix``) unless ``AllowRoot=1``. Each ``UserParameter=
<key>,<command>`` in its configuration registers an item key whose command the
agent runs through ``/bin/sh -c`` whenever a Zabbix server or proxy requests
that key, passively or as an active check. ``AllowKey``/``DenyKey`` (and the
deprecated ``EnableRemoteCommands``) decide whether the server may also run
arbitrary commands through ``system.run[...]``.

This module turns captured configuration text and captured ``Include``
directory listings into those commands. It performs no I/O, never runs the
agent or a shell, never looks up an account and never authorizes a response
action. ``origin`` is ``not_assessed``; no result is a safety verdict.

Semantics follow Zabbix 6.0.14 (Debian 12 ``zabbix-agent``)
``src/libs/zbxconf/cfg.c``, ``src/zabbix_agent/zabbix_agentd.c``,
``src/zabbix_agent/zbxconf.c`` and ``src/libs/zbxsysinfo/sysinfo.c``:

- **Lines.** Lines are read with ``fgets`` into a 2051-byte buffer. A chunk
  longer than 2048 bytes whose byte 2048 is not CR/LF stops the agent. Leading
  tab/space and trailing tab/space/CR/LF are trimmed, and empty lines and lines
  starting with ``#`` are skipped. A line must be UTF-8 and contain ``=``. The
  name is right-trimmed and the value left-trimmed; names are exact-case.
- **Include.** ``Include=`` may name a file, a directory (every regular file)
  or ``<absolute dir>/<pattern>`` where ``*`` is the only wildcard and appears
  only in the last component. A trailing ``/`` requires a directory. Directory
  entries are read in ``readdir`` order, not sorted. A missing target, a
  non-directory base for a pattern, a relative pattern, or more than ten
  nested levels stops the agent.
- **Values.** ``UserParameter`` accumulates in parse order. ``User`` and
  ``UserParameterDir`` keep the last value. ``AllowRoot`` and
  ``UnsafeUserParameters`` must be integers 0-1 (``KMGT`` suffixes multiply),
  and ``EnableRemoteCommands`` must be exactly ``0`` or ``1``.
- **Registration.** Each UserParameter is split at its first comma. The key
  must be ``[0-9A-Za-z._-]+`` optionally followed by exactly ``[*]`` (a
  flexible key receiving ``$1``-``$9``). A missing comma, any other key syntax
  or a key registered twice (``name`` and ``name[*]`` collide) stops the agent.
- **Execution.** Commands run with ``/bin/sh -c`` in ``UserParameterDir`` when
  set. With ``UnsafeUserParameters=0`` flexible parameters containing
  ``\\'"`*?[]{}~$!&;()<>|#@`` or a newline are refused before execution.

- **Modules.** ``LoadModule`` accumulates in parse order and ``LoadModulePath``
  keeps the last value (``modules.c`` ``zbx_load_module``). An absolute name is
  used as given; any other name becomes ``<LoadModulePath>/<name>``, truncated
  to 2047 bytes, and is ``dlopen``-ed with ``RTLD_NOW`` when the agent starts,
  after the privilege drop and before UserParameters are registered. Its
  constructors, ``zbx_module_init()`` and item callbacks therefore run inside
  the agent as the same user. Without ``LoadModulePath`` the compiled-in
  ``DEFAULT_LOAD_MODULE_PATH`` (``${libdir}/modules``) is distribution-specific
  and reported as a blocking gap, as is a resolved path that is not absolute
  (``dlopen`` resolves it against the agent's working directory). An empty
  name resolves to a directory, which ``dlopen`` refuses, so the agent stops.

Not modeled, so the result can only over-report: whether ``dlopen``, the
module API version check or ``zbx_module_init`` succeeds (a failure stops the
agent), collisions with built-in or loadable-module item keys, unknown parameter names (strict mode stops the
agent), ``AllowKey``/``DenyKey`` pattern validation and other parameters'
values. ``zabbix_agent2`` (Go) uses a different parser and is out of scope.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('zabbix-6.0.14',)
DEFAULT_CONFIG = '/etc/zabbix/zabbix_agentd.conf'
DEFAULT_USER = 'zabbix'
SHELL = ('/bin/sh', '-c')

MAX_STRING_LEN = 2048
FGETS_CHUNK = MAX_STRING_LEN + 2  # sizeof(line) - 1
MAX_INCLUDE_LEVEL = 10
MAX_FILES = 512
MAX_TOTAL_BYTES = 4 * 1024 * 1024
UNSAFE_PARAMETER_CHARS = '\\\'"`*?[]{}~$!&;()<>|#@\n'

_KEY = re.compile(r'[0-9A-Za-z._-]+(\[\*\])?\Z')
_UINT = re.compile(r'([0-9]+)([KMGT]?)\Z')
UINT64_MAX = 2 ** 64 - 1
_SUFFIX = {'': 1, 'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3, 'T': 1024 ** 4}
_POSITIONAL = re.compile(r'\$([1-9])')
BLOCKING_GAPS = frozenset({
    'unobserved_file', 'unobserved_directory', 'relative_include', 'invalid_utf8',
    'nul_byte', 'input_limit', 'default_module_path_unknown', 'relative_module_path',
})
FULL_NAME_MAX = MAX_STRING_LEN - 1  # zbx_snprintf into char full_name[MAX_STRING_LEN]


class _Stop(Exception):
    """The agent refuses to start (``config_error``)."""

    def __init__(self, code: str, source: str | None, line: int | None, detail: str = ''):
        super().__init__(code)
        self.record = {'code': code, 'source': source, 'line': line, 'detail': detail}


class _Gap(Exception):
    """The rest of the configuration cannot be determined from the capture."""

    def __init__(self, code: str, path: str):
        super().__init__(code)
        self.code = code
        self.path = path


def match_glob(name: str, pattern: str) -> bool:
    """Port of cfg.c ``match_glob``: ``*`` is the only wildcard."""
    f = 0
    p = 0
    while True:
        if p == len(pattern):
            return f == len(name)
        while p < len(pattern) and pattern[p] == '*':
            p += 1
        q = p
        while q < len(pattern) and pattern[q] != '*':
            q += 1
        literal = pattern[p:q]
        if p == 0:
            if not name.startswith(literal, f):
                return False
            f += len(literal)
            p = q
            continue
        if q == len(pattern):
            return len(name) - f >= len(literal) and name.endswith(literal)
        while True:
            if f >= len(name):
                return False
            if name.startswith(literal, f):
                f += len(literal)
                p = q
                break
            f += 1


def parse_glob(value: str) -> tuple[str, str | None]:
    """Port of cfg.c ``parse_glob``; raises ``ValueError`` on a refused glob."""
    star = value.find('*')
    if star < 0:
        path, pattern = value, None
    else:
        if '/' in value[star + 1:]:
            raise ValueError('glob pattern should be the last component of the path')
        slash = value.rfind('/', 0, star)
        if slash < 0:
            raise ValueError('path should be absolute')
        path, pattern = value[:slash], value[slash + 1:]
    stripped = path.rstrip('/')
    if stripped != path and pattern is None:
        pattern = '*'
    path = stripped
    if path == '' and value.startswith('/'):
        path = '/'
    return path, pattern


def _fgets(data: bytes) -> Iterable[bytes]:
    i = 0
    while i < len(data):
        nl = data.find(b'\n', i, i + FGETS_CHUNK)
        end = nl + 1 if nl >= 0 else min(i + FGETS_CHUNK, len(data))
        yield data[i:end]
        i = end


def _uint(value: str) -> int | None:
    """Port of ``str2uint64(value, "KMGT")``.

    ``is_uint64_n`` refuses digits above ``UINT64_MAX``, but the suffix factor
    is then applied with ``*value *= factor`` and no overflow check, so the
    product wraps modulo 2**64 (for example ``18014398509481984K`` is 0).
    """
    m = _UINT.match(value)
    if not m:
        return None
    number = int(m.group(1))
    if number > UINT64_MAX:
        return None
    return (number * _SUFFIX[m.group(2)]) & UINT64_MAX


def _as_bytes(value: str | bytes) -> bytes:
    return value.encode('utf-8', 'surrogateescape') if isinstance(value, str) else bytes(value)


def assess(files: Mapping[str, str | bytes],
           directories: Mapping[str, Sequence[str] | None] | None = None,
           absent: Iterable[str] = (),
           config_path: str = DEFAULT_CONFIG) -> dict[str, Any]:
    """Return which UserParameter commands zabbix_agentd runs, and as whom.

    ``files`` maps each observed regular file path to its bytes. ``directories``
    maps each observed directory to the names of its regular-file entries
    (after following symlinks) in ``readdir`` order, or ``None`` when the
    directory exists but its listing was not captured. ``absent`` lists paths
    confirmed not to exist. Anything else referenced is unobserved.
    """
    directories = directories or {}
    absent_set = set(absent)
    gaps: list[str] = []
    gap_paths: list[dict[str, str]] = []
    params: list[dict[str, Any]] = []
    module_lines: list[dict[str, Any]] = []
    scalars: dict[str, dict[str, Any]] = {}
    access_rules: list[dict[str, Any]] = []
    sources: list[str] = []
    state = {'bytes': 0}

    def gap(code: str, path: str) -> None:
        if code not in gaps:
            gaps.append(code)
        gap_paths.append({'code': code, 'path': path})

    def parse_file(path: str, level: int) -> None:
        level += 1
        if level > MAX_INCLUDE_LEVEL:
            raise _Stop('include_recursion', path, None)
        if path not in files:
            if path in absent_set or path in directories:
                raise _Stop('cannot_open', path, None)
            raise _Gap('unobserved_file', path)
        data = _as_bytes(files[path])
        state['bytes'] += len(data)
        sources.append(path)
        if len(sources) > MAX_FILES or state['bytes'] > MAX_TOTAL_BYTES:
            raise _Gap('input_limit', path)
        if b'\0' in data:
            raise _Gap('nul_byte', path)
        for lineno, chunk in enumerate(_fgets(data), start=1):
            if len(chunk) > MAX_STRING_LEN and chunk[MAX_STRING_LEN:MAX_STRING_LEN + 1] not in (b'\r', b'\n'):
                raise _Stop('line_too_long', path, lineno)
            line = chunk.lstrip(b'\t ').rstrip(b'\t \r\n')
            if not line or line.startswith(b'#'):
                continue
            try:
                text = line.decode('utf-8')
            except UnicodeDecodeError:
                raise _Gap('invalid_utf8', path) from None
            if '=' not in text:
                raise _Stop('not_key_value', path, lineno)
            name, value = text.split('=', 1)
            name = name.rstrip('\t \r\n')
            value = value.lstrip('\t ')
            if name == 'Include':
                parse_include(value, path, lineno, level)
            elif name == 'UserParameter':
                params.append({'raw': value, 'source': path, 'line': lineno})
            elif name == 'LoadModule':
                module_lines.append({'name': value, 'source': path, 'line': lineno})
            elif name in ('User', 'UserParameterDir', 'LoadModulePath'):
                scalars[name] = {'value': value, 'source': path, 'line': lineno}
            elif name in ('AllowRoot', 'UnsafeUserParameters'):
                number = _uint(value)
                if number is None or number > 1:
                    raise _Stop('wrong_value', path, lineno, name)
                scalars[name] = {'value': number, 'source': path, 'line': lineno}
            elif name == 'EnableRemoteCommands':
                if value not in ('0', '1'):
                    raise _Stop('wrong_value', path, lineno, name)
                access_rules.append({'type': 'allow' if value == '1' else 'deny',
                                     'pattern': 'system.run[*]', 'directive': name,
                                     'source': path, 'line': lineno})
            elif name in ('AllowKey', 'DenyKey'):
                access_rules.append({'type': 'allow' if name == 'AllowKey' else 'deny',
                                     'pattern': value, 'directive': name,
                                     'source': path, 'line': lineno})

    def parse_include(value: str, source: str, lineno: int, level: int) -> None:
        # An unobserved target leaves a gap, but parsing continues so that a
        # later modeled refusal is still reported.
        try:
            resolve_include(value, source, lineno, level)
        except _Gap as missing:
            gap(missing.code, missing.path)

    def resolve_include(value: str, source: str, lineno: int, level: int) -> None:
        try:
            path, pattern = parse_glob(value)
        except ValueError as exc:
            raise _Stop('invalid_include', source, lineno, str(exc)) from None
        if not path.startswith('/'):
            raise _Gap('relative_include', value)
        if path in directories:
            listing = directories[path]
            if listing is None:
                raise _Gap('unobserved_directory', path)
            for entry in listing:
                if pattern is not None and not match_glob(entry, pattern):
                    continue
                parse_file(path.rstrip('/') + '/' + entry if path != '/' else '/' + entry, level)
            return
        if path in files:
            if pattern is not None:
                raise _Stop('include_base_not_directory', source, lineno, value)
            parse_file(path, level)
            return
        if path in absent_set:
            raise _Stop('include_missing', source, lineno, value)
        raise _Gap('unobserved_file' if pattern is None else 'unobserved_directory', path)

    error: dict[str, Any] | None = None
    try:
        parse_file(config_path, 0)
    except _Stop as stop:
        error = stop.record
    except _Gap as missing:
        gap(missing.code, missing.path)

    module_path_entry = scalars.get('LoadModulePath')
    modules: list[dict[str, Any]] = []
    for item in module_lines:
        name = item['name']
        record = {'name': name, 'source': item['source'], 'line': item['line'],
                  'trigger': 'agent_start', 'load': 'dlopen_rtld_now',
                  'load_success': 'not_assessed'}
        if name.startswith('/'):
            full: str | None = name
        elif module_path_entry is None:
            full = None
            gap('default_module_path_unknown', name)
        else:
            full = module_path_entry['value'] + '/' + name
        if full is not None:
            raw = full.encode('utf-8')
            if len(raw) > FULL_NAME_MAX:
                full = raw[:FULL_NAME_MAX].decode('utf-8', 'surrogateescape')
                record['truncated'] = True
            if not full.startswith('/'):
                gap('relative_module_path', full)
        record['path'] = full
        record['path_source'] = (None if name.startswith('/') or module_path_entry is None
                                 else {k: module_path_entry[k] for k in ('source', 'line')})
        if name == '' and error is None:
            record['status'] = 'config_error'
            record['reason'] = 'module_path_is_directory'
            error = {'code': 'load_module_empty', 'source': item['source'],
                     'line': item['line'], 'detail': ''}
        else:
            record['status'] = 'configured'
        modules.append(record)

    entries: list[dict[str, Any]] = []
    registered: dict[str, dict[str, Any]] = {}
    for item in params:
        raw = item['raw']
        record: dict[str, Any] = {'source': item['source'], 'line': item['line']}
        if ',' not in raw:
            record.update({'key': None, 'command': None, 'status': 'config_error',
                           'reason': 'not_comma_separated'})
            entries.append(record)
            error = error or {'code': 'user_parameter_not_comma_separated',
                              'source': item['source'], 'line': item['line'], 'detail': ''}
            continue
        key, command = raw.split(',', 1)
        record.update({'key': key, 'command': command})
        if not _KEY.match(key):
            record.update({'status': 'config_error', 'reason': 'key_syntax'})
            error = error or {'code': 'user_parameter_key_syntax', 'source': item['source'],
                              'line': item['line'], 'detail': key}
            entries.append(record)
            continue
        flexible = key.endswith('[*]')
        base = key[:-3] if flexible else key
        if base in registered:
            record.update({'status': 'config_error', 'reason': 'duplicate_key',
                           'duplicate_of': {k: registered[base][k] for k in ('source', 'line')}})
            error = error or {'code': 'user_parameter_duplicate_key', 'source': item['source'],
                              'line': item['line'], 'detail': base}
            entries.append(record)
            continue
        registered[base] = record
        record.update({
            'status': 'registered', 'item_key': base, 'flexible': flexible,
            'argv': [*SHELL, command],
            'positional_parameters': sorted({int(n) for n in _POSITIONAL.findall(command)}) if flexible else [],
            'trigger': 'item_request',
        })
        entries.append(record)

    allow_root = scalars.get('AllowRoot', {}).get('value', 0)
    unsafe = scalars.get('UnsafeUserParameters', {}).get('value', 0)
    user_entry = scalars.get('User')
    configured_user = user_entry['value'] if user_entry else DEFAULT_USER
    workdir = scalars.get('UserParameterDir')
    started = error is None
    for record in entries:
        if record['status'] == 'registered':
            record['runs'] = started
            record['cwd'] = workdir['value'] if workdir else None
            record['unsafe_parameters_allowed'] = bool(unsafe) if record['flexible'] else None
        else:
            record['runs'] = False
        if not started and record['status'] == 'registered':
            record['reason'] = 'agent_refuses_to_start'

    for record in modules:
        record['runs'] = started and record['status'] == 'configured'
        if not record['runs'] and record['status'] == 'configured':
            record['reason'] = 'agent_refuses_to_start'

    system_run_allow = [r for r in access_rules if r['type'] == 'allow' and _may_match_system_run(r['pattern'])]
    # A modeled refusal is definitive even when other files were unobserved:
    # the agent stops either at that refusal or at an earlier one.
    complete = error is not None or not any(g in BLOCKING_GAPS for g in gaps)
    result = {
        'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS),
        'status': 'config_error' if error else ('complete' if complete else 'incomplete'),
        'complete': complete,
        'config_error': error,
        'gaps': gaps,
        'gap_paths': gap_paths,
        'config_path': config_path,
        'files_read': sources,
        'run_as': {
            'when_started_as_root': 'root' if allow_root else configured_user,
            'otherwise': 'starting_user',
            'user': configured_user,
            'user_source': {k: user_entry[k] for k in ('source', 'line')} if user_entry else None,
            'allow_root': bool(allow_root),
            'account_resolution': 'not_assessed',
        },
        'user_parameters': entries,
        'modules': modules,
        'remote_commands': {
            'system_run': ('possible' if system_run_allow else 'denied') if started else 'agent_refuses_to_start',
            'rules': access_rules,
            'rule_evaluation': 'not_modeled_over_reports',
        },
        'not_modeled': ['module_load_success', 'builtin_key_collisions', 'unknown_parameter_names',
                        'key_access_pattern_validation', 'other_parameter_values'],
        'origin': 'not_assessed',
        'verdict': None,
    }
    result['fingerprint'] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return result


def _may_match_system_run(pattern: str) -> bool:
    """Conservatively say whether an AllowKey pattern could match system.run[...]."""
    prefix = pattern.split('*', 1)[0]
    target = 'system.run'
    if '*' in pattern:
        return target.startswith(prefix) or prefix.startswith(target)
    return pattern == target or pattern.startswith(target + '[')
