"""Pure supervisord program contract (roadmap F slice, #1259).

supervisord starts every ``[program:x]``, ``[eventlistener:x]`` and
``[fcgi-program:x]`` section it loads. With ``autostart`` true (the default) the
command starts when supervisord starts, usually at boot, as the section's
``user`` or as supervisord's own user, which is normally root. This module turns
captured configuration text and captured include-glob results into the
processes supervisord would start. It performs no I/O, never runs supervisord or
a command and never authorizes a response action.

The rules follow ``supervisor/options.py`` and ``supervisor/datatypes.py`` in
supervisor 4.2.5 (Debian 12 ``supervisor_4.2.5-1``, Ubuntu 24.04
``supervisor_4.2.5-1``):

- The parser is the standard-library ``RawConfigParser`` with
  ``inline_comment_prefixes=(';', '#')`` and ``strict=False``, so option names
  are lower-cased, later duplicate options and sections merge, ``[DEFAULT]``
  values apply to every section, and a parse error stops supervisord. This
  module uses the same parser with the same settings.
- If an ``[include]`` section exists, ``%(here)s`` is first replaced in every
  value with the main file's directory. ``files`` is required; it is expanded
  with ``here``, ``host_node_name`` and the ``ENV_*`` names, split at
  whitespace, and each pattern is joined to the main file's directory. The
  sorted matches of each pattern are read in turn, and after each file
  ``%(here)s`` is replaced in every value with that file's directory. Only the
  main file's ``[include]`` is honoured: ``files`` is read before any include.
- ``[supervisord]`` is required. Its ``environment`` adds ``ENV_*`` names.
- ``[group:x]`` sections claim their listed programs, which must exist as a
  program or fcgi-program, but not both. Every other ``program:`` section forms
  its own group. Names may not contain a space, ``:`` or ``/``.
- For each process section the options are expanded with ``here`` (the main
  file's directory), ``program_name``, ``group_name``, ``host_node_name`` and the
  ``ENV_*`` names, and parsed with supervisor's ``integer``, ``boolean`` and
  related converters. ``numprocs`` greater than one requires ``%(process_num)``
  in ``process_name``. For each ``process_num`` in
  ``range(numprocs_start, numprocs_start + numprocs)`` the section's
  ``environment`` adds ``ENV_*`` names and ``command`` is expanded with
  ``process_num`` and ``numprocs`` as well. A missing ``command`` stops
  supervisord.

A configuration error stops supervisord, so no process starts. This module
reports ``config_error`` only for the errors it models exactly. Validations it
does not model, such as whether a ``user`` or log directory exists, can only
stop supervisord, so the result over-reports rather than under-reports and
states the limitation.

Fail-closed rules: an unobserved file or include-glob result, an expansion that
needs the unobserved host name or process environment in an include pattern,
invalid UTF-8, NUL bytes and over-limit input mark the result incomplete.
``origin`` is always ``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import configparser
import hashlib
import posixpath
import shlex
import signal
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('4.2.5',)
DEFAULT_PATHS = ('/etc/supervisor/supervisord.conf', '/etc/supervisord.conf')
DEFAULT_USER = 'root'
MAX_TEXT = 262144
MAX_FILES = 256
MAX_PROCESSES = 512
MAX_GAPS = 64
SECTION_KINDS = ('program', 'eventlistener', 'fcgi-program')

BLOCKING = frozenset({
    'file_not_observed', 'glob_not_observed', 'include_expansion_unresolved', 'over_limit', 'invalid_utf8',
    'binary', 'files_over_limit', 'gaps_truncated', 'relative_path',
})

NOT_OBSERVED = (
    'Whether supervisord is installed, enabled and running, and which configuration file it was started with.',
    ('Whether each user, log directory, child log directory and supervisord directory exists. A missing one '
     'stops supervisord, so no process starts, but the result still reports the processes.'),
    ('[supervisord] options other than user and environment, server sections and rpcinterface plugins. An '
     'invalid one stops supervisord; the result still reports the processes.'),
    'The process environment supervisord inherits and the host name, so %(ENV_*)s and %(host_node_name)s.',
    'Whether a command path exists, is executable, or what the program it starts does.',
    'Processes started later through supervisorctl or the XML-RPC interface.',
)

# supervisor.events.EventTypes in 4.2.5, without rpcinterface plugin registrations.
EVENT_TYPES = frozenset({
    'EVENT', 'PROCESS_STATE', 'PROCESS_STATE_STOPPED', 'PROCESS_STATE_EXITED', 'PROCESS_STATE_STARTING',
    'PROCESS_STATE_STOPPING', 'PROCESS_STATE_BACKOFF', 'PROCESS_STATE_FATAL', 'PROCESS_STATE_RUNNING',
    'PROCESS_STATE_UNKNOWN', 'PROCESS_COMMUNICATION', 'PROCESS_COMMUNICATION_STDOUT',
    'PROCESS_COMMUNICATION_STDERR', 'PROCESS_LOG', 'PROCESS_LOG_STDOUT', 'PROCESS_LOG_STDERR',
    'REMOTE_COMMUNICATION', 'SUPERVISOR_STATE_CHANGE', 'SUPERVISOR_STATE_CHANGE_RUNNING',
    'SUPERVISOR_STATE_CHANGE_STOPPING', 'TICK', 'TICK_5', 'TICK_60', 'TICK_3600', 'PROCESS_GROUP',
    'PROCESS_GROUP_ADDED', 'PROCESS_GROUP_REMOVED',
})
DEFAULT_RPC_FACTORY = 'supervisor.rpcinterface:make_main_rpcinterface'
_TRUE = ('yes', 'true', 'on', '1')
_FALSE = ('no', 'false', 'off', '0')
_SIGNUMS = frozenset(getattr(signal, k) for k in dir(signal) if k.startswith('SIG'))


class ConfigError(ValueError):
    """supervisord would refuse this configuration and exit."""


class Unresolved(Exception):
    """An expansion needs a value the capture does not contain."""


class _Expansions(dict):
    def __missing__(self, key):
        if key == 'host_node_name' or str(key).startswith('ENV_'):
            raise Unresolved(key)
        raise ConfigError('unknown expansion ' + repr(key))


def _expand(value: str, names: Mapping[str, Any]) -> str:
    """supervisor's ``expand``: ``value % names``, where any failure stops supervisord."""
    mapping = _Expansions(names)
    try:
        return value % mapping
    except (Unresolved, ConfigError):
        raise
    except Exception as exc:  # supervisor's expand() turns every other failure into ValueError
        raise ConfigError('bad format: ' + type(exc).__name__) from exc


def _name(value: str) -> str:
    s = str(value).strip()
    if any(c in s for c in ' :/'):
        raise ConfigError('invalid name ' + repr(value))
    return s


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (ValueError, OverflowError, TypeError) as exc:
        raise ConfigError('not an integer') from exc


def _boolean(value: Any) -> bool:
    s = str(value).lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    raise ConfigError('not a boolean')


def _autorestart(value: str) -> None:
    v = str(value.lower())
    if v not in _TRUE and v not in _FALSE and v != 'unexpected':
        raise ConfigError('invalid autorestart')


def _byte_size(value: str) -> int:
    v = value.lower()
    for suffix, mult in (('kb', 1024), ('mb', 1024 ** 2), ('gb', 1024 ** 3)):
        if v[-2:] == suffix:
            return _integer(v[:-2]) * mult
    return _integer(v)


def _signal(value: str) -> None:
    try:
        num = int(value)
    except (ValueError, TypeError):
        name = value.strip().upper()
        if not name.startswith('SIG'):
            name = 'SIG' + name
        num = getattr(signal, name, None)
        if num is None:
            raise ConfigError('invalid signal name') from None
    if num not in _SIGNUMS:
        raise ConfigError('invalid signal number')


def _exitcodes(value: str) -> None:
    if not value:
        return
    try:
        codes = list(map(int, value.split(',')))
    except Exception as exc:
        raise ConfigError('invalid exit codes') from exc
    if any(c > 255 or c < 0 for c in codes):
        raise ConfigError('invalid exit codes')


def _octal(value: str) -> None:
    try:
        int(value, 8)
    except (TypeError, ValueError) as exc:
        raise ConfigError('invalid umask') from exc


def _key_values(value: str) -> dict[str, str]:
    """supervisor.datatypes.dict_of_key_value_pairs."""
    lexer = shlex.shlex(str(value))
    lexer.wordchars += '/.+-():'
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise ConfigError('invalid environment') from exc
    out: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        kv = tokens[i:i + 3]
        if len(kv) != 3 or kv[1] != '=':
            raise ConfigError('invalid environment')
        out[kv[0]] = kv[2].strip('\'"')
        i += 4
    return out


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


def _expand_here(parser: configparser.RawConfigParser, here: str) -> None:
    for section in parser.sections():
        for key, value in parser.items(section):
            if '%(here)s' in value:
                parser.set(section, key, value.replace('%(here)s', here))


def _result(main_path: str, status: str, gaps: list, processes: list, files_read: list, detail: str = '',
            supervisord_user: str | None = None) -> dict[str, Any]:
    complete = not any(g['blocking'] for g in gaps)
    return {
        'contract': 'supervisor-programs', 'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS), 'main_path': main_path, 'status': status,
        'detail': detail[:240], 'complete': complete, 'origin': 'not_assessed',
        'supervisord_user': supervisord_user, 'files_read': files_read, 'processes': processes,
        'gaps': gaps, 'not_observed': list(NOT_OBSERVED),
    }


def evaluate(*, main_path: str, files: Mapping[str, Any], globs: Mapping[str, Iterable[str] | None],
             node_name: str | None = None) -> dict[str, Any]:
    """Resolve which processes supervisord starts from the captured configuration.

    ``files`` maps absolute paths to captured text (``None`` when unobserved). ``globs`` maps each absolute
    include pattern to its captured matches (``None`` when unobserved). ``node_name`` is the host name when it
    was observed.
    """
    gaps: list[dict[str, Any]] = []
    files_read: list[str] = []
    if not isinstance(main_path, str) or not main_path.startswith('/'):
        _gap(gaps, 'relative_path', str(main_path)[:240])
        return _result(str(main_path)[:240], 'unresolved', gaps, [], files_read)
    here = posixpath.dirname(posixpath.normpath(main_path))
    text = _decode(main_path, files.get(main_path), gaps)
    if text is None:
        return _result(main_path, 'unresolved', gaps, [], files_read)
    parser = configparser.RawConfigParser(inline_comment_prefixes=(';', '#'), strict=False)
    try:
        parser.read_string(text, source=main_path)
        files_read.append(main_path)
        if parser.has_section('include'):
            _expand_here(parser, here)
            if not parser.has_option('include', 'files'):
                raise ConfigError('[include] section has no files setting')
            names = {'here': here}
            if node_name is not None:
                names['host_node_name'] = node_name
            env = {}
            try:
                env = _supervisord_env(parser, here, node_name)
            except Unresolved:
                env = None
            try:
                patterns = _expand(parser.get('include', 'files'), {**names, **(env or {})}).split()
            except Unresolved as exc:
                _gap(gaps, 'include_expansion_unresolved', 'include.files', str(exc))
                patterns = []
            for pattern in patterns:
                full = posixpath.join(here, pattern)
                matches = globs.get(full)
                if matches is None:
                    _gap(gaps, 'glob_not_observed', full)
                    continue
                for filename in sorted(str(m) for m in matches):
                    if len(files_read) >= MAX_FILES:
                        _gap(gaps, 'files_over_limit', filename)
                        break
                    included = _decode(filename, files.get(filename), gaps)
                    if included is None:
                        continue
                    parser.read_string(included, source=filename)
                    files_read.append(filename)
                    _expand_here(parser, posixpath.dirname(filename))
        if 'supervisord' not in parser.sections():
            raise ConfigError('no [supervisord] section')
        try:
            env = _supervisord_env(parser, here, node_name)
        except Unresolved:
            env = None
        user = _section_get(parser, 'supervisord', 'user', None, {'here': here}, env, node_name)
        processes = _processes(parser, here, env, node_name, gaps)
    except (ConfigError, configparser.Error) as exc:
        return _result(main_path, 'config_error', gaps, [], files_read, detail=str(exc).split('\n')[0])
    status = 'loads' if processes else 'no_processes'
    sv_user = None if user is _UNRESOLVED else user
    if user is _UNRESOLVED:
        _gap(gaps, 'expansion_unresolved', 'supervisord.user')
    return _result(main_path, status, gaps, processes, files_read, supervisord_user=sv_user)


_UNRESOLVED = object()


def _supervisord_env(parser, here, node_name) -> dict[str, str]:
    """ENV_* names from [supervisord] environment. Raises Unresolved when they cannot be known."""
    if not parser.has_section('supervisord'):
        return {}
    raw = parser.get('supervisord', 'environment', fallback='')
    names = {'here': here}
    if node_name is not None:
        names['host_node_name'] = node_name
    # [supervisord] environment is expanded with the process environment, which is unobserved.
    value = _expand(raw, names)
    return {'ENV_' + k: v for k, v in _key_values(value).items()}


def _section_get(parser, section, option, default, names, env, node_name, expand=True):
    try:
        value = parser.get(section, option)
    except configparser.NoOptionError:
        value = default
    if not expand or not isinstance(value, str):
        return value
    merged = dict(names)
    if node_name is not None:
        merged['host_node_name'] = node_name
    try:
        return _expand(value, {**(env or {}), **merged})
    except Unresolved:
        return _UNRESOLVED


def _processes(parser, here, env, node_name, gaps) -> list[dict[str, Any]]:
    sections = parser.sections()
    exclude: list[str] = []
    out: list[dict[str, Any]] = []
    for section in sections:
        if not section.startswith('group:'):
            continue
        group = _name(section.split(':', 1)[1])
        programs = _strings(_plain(parser, section, 'programs', None, here, env, node_name))
        _integer(_plain(parser, section, 'priority', 999, here, env, node_name))
        for program in programs:
            p, f = 'program:%s' % program, 'fcgi-program:%s' % program
            if p not in sections and f not in sections:
                raise ConfigError('[%s] names unknown program %s' % (section, program))
            if p in sections and f in sections:
                raise ConfigError('[%s] name %s is ambiguous' % (section, program))
            target = p if p in sections else f
            exclude.append(target)
            out.extend(_from_section(parser, target, group, here, env, node_name, gaps))
    for section in sections:
        if section.startswith('program:') and section not in exclude:
            name = _name(section.split(':', 1)[1])
            _integer(_plain(parser, section, 'priority', 999, here, env, node_name))
            out.extend(_from_section(parser, section, name, here, env, node_name, gaps))
    rpc = [s for s in sections if s.startswith('rpcinterface:')]
    custom_rpc = any(parser.get(s, 'supervisor.rpcinterface_factory', fallback=None) != DEFAULT_RPC_FACTORY
                     for s in rpc)
    for section in sections:
        if not section.startswith('eventlistener:'):
            continue
        pool = section.split(':', 1)[1]
        _integer(_plain(parser, section, 'priority', -1, here, env, node_name))
        if _integer(_plain(parser, section, 'buffer_size', 10, here, env, node_name)) < 1:
            raise ConfigError('[%s] invalid buffer_size' % section)
        handler = _plain(parser, section, 'result_handler', 'supervisor.dispatchers:default_handler', here, env,
                         node_name)
        if handler != 'supervisor.dispatchers:default_handler':
            _gap(gaps, 'result_handler_not_modeled', section)
        events = {x.upper() for x in _strings(_plain(parser, section, 'events', '', here, env, node_name))}
        if not events:
            raise ConfigError('[%s] requires an events line' % section)
        unknown = events - EVENT_TYPES
        if unknown and not custom_rpc:
            raise ConfigError('Unknown event type in [%s]' % section)
        if unknown:
            _gap(gaps, 'event_type_not_modeled', section)
        if _boolean(_plain(parser, section, 'redirect_stderr', 'false', here, env, node_name)):
            raise ConfigError('[%s] sets redirect_stderr=true' % section)
        out.extend(_from_section(parser, section, pool, here, env, node_name, gaps))
    for section in sections:
        if section.startswith('fcgi-program:') and section not in exclude:
            name = _name(section.split(':', 1)[1])
            _integer(_plain(parser, section, 'priority', 999, here, env, node_name))
            _gap(gaps, 'fcgi_socket_not_modeled', section)
            out.extend(_from_section(parser, section, name, here, env, node_name, gaps))
    if len(out) > MAX_PROCESSES:
        _gap(gaps, 'over_limit', 'processes', 'Only the first %d processes are listed.' % MAX_PROCESSES)
        out = out[:MAX_PROCESSES]
    return out


def _strings(value):
    if not value:
        return []
    return [x.strip() for x in value.split(',')]


def _plain(parser, section, option, default, here, env, node_name, extra=None):
    """A section option expanded like ``saneget``; an unresolved expansion returns the raw-free sentinel."""
    names = {'here': here, **(extra or {})}
    value = _section_get(parser, section, option, default, names, env, node_name)
    if value is _UNRESOLVED:
        raise _NeedsUnobserved(section, option)
    return value


class _NeedsUnobserved(Exception):
    def __init__(self, section, option):
        super().__init__(section + '.' + option)
        self.section, self.option = section, option


def _from_section(parser, section, group, here, env, node_name, gaps) -> list[dict[str, Any]]:
    kind = section.split(':', 1)[0]
    program = _name(section.split(':', 1)[1])
    common = {'program_name': program, 'group_name': group}
    try:
        return _from_section_inner(parser, section, kind, program, group, common, here, env, node_name, gaps)
    except _NeedsUnobserved as exc:
        _gap(gaps, 'expansion_unresolved', str(exc),
             'An option needs %(host_node_name)s or %(ENV_*)s; supervisord may also reject it.')
        return [{'section': section, 'kind': kind, 'program_name': program, 'group_name': group,
                 'process_name': None, 'process_num': None, 'command': None, 'command_resolved': False,
                 'user': None, 'runs_as': None, 'autostart': None, 'starts': 'unresolved'}]


def _from_section_inner(parser, section, kind, program, group, common, here, env, node_name, gaps):
    def get(option, default, extra=None, expand=True):
        if not expand:
            try:
                return parser.get(section, option)
            except configparser.NoOptionError:
                return default
        return _plain(parser, section, option, default, here, env, node_name, {**common, **(extra or {})})

    _integer(get('priority', 999 if kind != 'eventlistener' else -1))
    autostart = _boolean(get('autostart', 'true'))
    _autorestart(get('autorestart', 'unexpected'))
    _integer(get('startsecs', 1))
    _integer(get('startretries', 3))
    _signal(get('stopsignal', 'TERM'))
    _integer(get('stopwaitsecs', 10))
    stopasgroup = _boolean(get('stopasgroup', 'false'))
    killasgroup = _boolean(get('killasgroup', stopasgroup))
    _exitcodes(get('exitcodes', '0'))
    _boolean(get('redirect_stderr', 'false'))
    numprocs = _integer(get('numprocs', 1))
    numprocs_start = _integer(get('numprocs_start', 0))
    environment_str = get('environment', '', expand=False)
    _byte_size(get('stdout_capture_maxbytes', '0'))
    _boolean(get('stdout_events_enabled', 'false'))
    _byte_size(get('stderr_capture_maxbytes', '0'))
    _boolean(get('stderr_events_enabled', 'false'))
    get('serverurl', None)
    user = get('user', None)
    umask = get('umask', None)
    if umask is not None:
        _octal(umask)
    process_name = _name(get('process_name', '%(program_name)s', expand=False))
    if numprocs > 1 and '%(process_num)' not in process_name:
        raise ConfigError('%(process_num) must be present within process_name when numprocs > 1')
    if stopasgroup and not killasgroup:
        raise ConfigError('Cannot set stopasgroup=true and killasgroup=false')
    out = []
    count = range(numprocs_start, numprocs + numprocs_start)
    if len(count) > MAX_PROCESSES:
        _gap(gaps, 'over_limit', section, 'numprocs exceeds the listing limit.')
        count = range(numprocs_start, numprocs_start + MAX_PROCESSES)
    names = {'here': here, **common}
    for num in count:
        per = {**names, 'process_num': num, 'numprocs': numprocs}
        try:
            local = _expand(environment_str, {**(env or {}), **per, **_node(node_name)})
        except Unresolved as exc:
            raise _NeedsUnobserved(section, 'environment') from exc
        local_env = {'ENV_' + k: v for k, v in _key_values(local).items()}
        get('directory', None, {'process_num': num, 'numprocs': numprocs, **local_env})
        for stream in ('stdout', 'stderr'):
            value = get(stream + '_logfile', None, {'process_num': num, 'numprocs': numprocs, **local_env})
            if isinstance(value, str):
                _expand(value, {**(env or {}), **local_env, **per, **_node(node_name)})
            _integer(get(stream + '_logfile_backups', 10))
            _byte_size(get(stream + '_logfile_maxbytes', '50MB'))
            _boolean(get(stream + '_syslog', False))
        extra = {'process_num': num, 'numprocs': numprocs, **local_env}
        command = get('command', None, extra)
        if command is None:
            raise ConfigError('program section %s does not specify a command' % section)
        pname = _expand(process_name, {**(env or {}), **local_env, **per, **_node(node_name)})
        out.append({
            'section': section, 'kind': kind, 'program_name': program, 'group_name': group,
            'process_name': pname, 'process_num': num, 'command': command, 'command_resolved': True,
            'command_sha256': hashlib.sha256(command.encode('utf-8', 'surrogatepass')).hexdigest(),
            'user': user, 'runs_as': user if user is not None else 'supervisord user',
            'autostart': autostart, 'starts': 'at_supervisord_start' if autostart else 'on_demand',
        })
    return out


def _node(node_name):
    return {} if node_name is None else {'host_node_name': node_name}
