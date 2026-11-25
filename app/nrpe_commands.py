"""Pure NRPE command contract (roadmap F slice, #1335).

Takes captured ``nrpe.cfg`` text, the text of the files it includes and the listings of
the directories it includes. It reports which ``command[NAME]`` definitions the Nagios
NRPE daemon will run when an allowed client asks for ``NAME``, with which ``/bin/sh -c``
command line and as which account. It never reads files, runs a command or authorizes a
response action.

The semantics come from nrpe 4.1.0 ``src/nrpe.c`` (``read_config_file``,
``read_config_dir``, ``add_command``, ``find_command``, ``process_macros``, ``my_system``,
``drop_privileges`` and ``check_privileges``):

* Lines are read with ``fgets(buf, 2047)``, so a physical line longer than 2046 bytes is
  parsed as several lines. Leading and trailing ``isspace`` characters are stripped, and
  ``#`` starts a comment only at the start of a line.
* The name is ``strtok(line, "=")`` and the value is the rest after that ``=``. A line
  with no value is an error. Names are compared exactly, so ``nrpe_user = x`` is an
  unknown option and is ignored. Any name containing ``command[`` defines a command. Its
  name is ``strtok(name, "[")`` followed by ``strtok(NULL, "]")``, and an empty result is
  an error. ``add_command`` pushes onto the head of a list and ``find_command`` returns
  the first match, so the last definition of a name wins.
* ``include``/``include_file`` read the named file as given. ``include_dir`` strips one
  trailing ``/`` and uses ``scandir`` with ``alphasort``. nrpe never calls ``setlocale``,
  so that is byte order. It reads every regular file whose name ends in ``.cfg``, hidden
  files included, and recurses into subdirectories whose names do not start with ``.``.
  An entry ending in ``.cfg`` that is not a regular file is skipped, even when it is a
  directory. ``stat`` follows symbolic links.
* An error stops that file at its line, and definitions read before it stay. An included
  file's error is only logged. An error in the main file makes nrpe refuse to start.
* For a request, nrpe copies the command line into a 2048-byte buffer: up to 2047 bytes
  with ``strncpy``, or up to 2046 bytes for ``"<command_prefix> <command line>"`` because
  that path uses ``snprintf(..., sizeof - 1, ...)``. ``process_macros`` splits it on ``$``
  with ``my_strsep``; every second token is a macro position, and a macro token that
  *starts* with ``ARG`` is replaced by client argument ``atoi(token + 3)`` when that is 1-16.
  The result runs with ``popen`` (``/bin/sh -c``). Client arguments reach those macros only
  with ``dont_blame_nrpe=1`` in a build with ``--enable-command-args``.
* In daemon, foreground and SRC modes ``set_stdio_sigs`` calls
  ``drop_privileges(nrpe_user, nrpe_group)`` and then ``check_privileges``, which exits when
  the effective UID *or* GID is still 0. A failed lookup or ``seteuid`` is only logged, so an
  unresolvable ``nrpe_user`` leaves the starting account, and nrpe exits if that is root. In
  inetd mode privileges are never dropped and ``check_privileges`` runs first. The check is
  on the *effective* account: a non-root start cannot ``setgid(0)`` or ``seteuid(0)``, so a
  configured ``nrpe_user``/``nrpe_group`` of root (or 0) leaves the starting account in effect
  and nrpe starts. So commands never run as root at start: the account is ``nrpe_user`` (or
  the starting account when that is not root), or nrpe does not start.

Unobserved, unreadable or over-limit input, relative include paths, include cycles,
truncated paths and build-dependent values are explicit blocking gaps. No record is
labelled safe, and ``origin`` is always ``not_assessed``.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'package': 'nrpe', 'version': '4.1.0', 'source': 'src/nrpe.c at nrpe-4.1.0'}
DEFAULT_CONFIG = '/etc/nagios/nrpe.cfg'
FGETS_CHUNK = 2046          # fgets(input_buffer, MAX_INPUT_BUFFER - 1) with MAX_INPUT_BUFFER 2048
MAX_COMMAND_LINE = 2047     # strncpy(raw_command, ..., sizeof(raw_command) - 1)
MAX_PREFIXED_LINE = 2046    # snprintf(raw_command, sizeof(raw_command) - 1, "%s %s", ...)
MAX_DIR_VALUE = 255         # strncpy(config_file[MAX_FILENAME_LENGTH], ..., 255)
MAX_ENTRY_PATH = 254        # snprintf(config_file, MAX_FILENAME_LENGTH - 1, "%s/%s")
MAX_ARGUMENTS = 16
MAX_BYTES = 262144
MAX_FILES = 256
MAX_DEPTH = 16
MAX_COMMANDS = 1024
MAX_GAPS = 64
_SPACE = b' \t\n\v\f\r'
INT_MIN, INT_MAX = -(2 ** 31), 2 ** 31 - 1
LONG_MIN, LONG_MAX = -(2 ** 63), 2 ** 63 - 1

BLOCKING = frozenset({
    'input_malformed', 'daemon_not_observed', 'file_not_observed', 'directory_not_observed', 'config_too_large',
    'too_many_files', 'include_cycle', 'include_too_deep', 'relative_include', 'path_truncated',
    'entry_stat_failed', 'value_not_modelled', 'too_many_commands', 'gaps_truncated', 'start_group_not_observed',
})
UNOBSERVED = (
    'Whether nrpe is installed, running and reachable, and which clients allowed_hosts or TLS admit, are not '
    'observed.',
    'Whether the build enables --enable-command-args or --enable-bash-command-substitution is not observed; '
    'arguments_accepted only reports the configuration switch.',
    'Whether nrpe_user and nrpe_group resolve to real accounts, and whether a name other than root or 0 maps to '
    'UID or GID 0, is not observed. A name that does not resolve leaves the starting account, and nrpe exits if '
    'that is root.',
    'With a root start, an initgroups failure other than EPERM makes drop_privileges return before seteuid, '
    'so nrpe stays root and exits; that failure is not observed.',
    'A SIGHUP reload re-reads the configuration without running check_privileges again, so a file changed to '
    'nrpe_user=root after start can run commands as root until restart; configuration text cannot show this.',
    'The contents of the programs that command lines name are not read.',
    'Values of options that cannot stop nrpe (for example allowed_hosts and ssl_* paths) are not validated.',
)
NOT_A_VERDICT = 'Configuration text only. This is not a safety verdict and origin is not assessed.'


class _FileError(Exception):
    def __init__(self, line: int, detail: str) -> None:
        super().__init__(detail)
        self.line = line
        self.detail = detail


class _Stop(Exception):
    """An unmodelled condition that makes the rest of the walk unreliable."""


def _gap(gaps: list[dict[str, Any]], code: str, detail: str, **where: Any) -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gaps.append({'code': code, 'detail': detail, **where})


def _strtok(data: bytes, start: int, delims: bytes) -> tuple[bytes | None, int]:
    """Mirror strtok: skip leading delimiters, return the token and the position after its terminator."""
    while start < len(data) and data[start] in delims:
        start += 1
    if start >= len(data):
        return None, len(data)
    end = start
    while end < len(data) and data[end] not in delims:
        end += 1
    return data[start:end], end + 1


def _atoi(value: bytes) -> int:
    match = re.match(rb'[ \t\n\v\f\r]*([+-]?)(\d*)', value)
    sign, digits = match.group(1), match.group(2)  # type: ignore[union-attr]
    if len(digits.lstrip(b'0')) > 9:
        raise ValueError('out of range')
    number = int(digits or b'0')
    return -number if sign == b'-' else number


def _c_atoi(value: bytes) -> int:
    """glibc atoi: (int)strtol(value, NULL, 10), saturating to long and truncating to int."""
    match = re.match(rb'[ \t\n\v\f\r]*([+-]?)(\d*)', value)
    sign, digits = match.group(1), match.group(2)  # type: ignore[union-attr]
    number = int(digits or b'0')
    number = -number if sign == b'-' else number
    number = max(LONG_MIN, min(LONG_MAX, number))
    number &= 0xFFFFFFFF
    return number - 2 ** 32 if number > INT_MAX else number


def _argument_macros(line: bytes) -> list[int]:
    """Mirror process_macros: split on '$', odd tokens are macros, 'ARG' prefix selects atoi(token + 3)."""
    indexes = set()
    for position, token in enumerate(line.split(b'$')):
        if position % 2 == 1 and token.startswith(b'ARG'):
            index = _c_atoi(token[3:])
            if 1 <= index <= MAX_ARGUMENTS:
                indexes.add(index)
    return sorted(indexes)


def _is_root(account: str | None) -> bool:
    """An account drop_privileges would map to ID 0 without a lookup we cannot observe."""
    if account is None:
        return False
    raw = account.encode('utf-8', 'surrogateescape')
    if raw and raw.isdigit():
        return _c_atoi(raw) == 0
    return account == 'root'


def _text(value: bytes) -> str:
    return value.decode('utf-8', 'surrogateescape')


def _chunks(data: bytes) -> list[bytes]:
    """Split like repeated fgets calls of at most FGETS_CHUNK bytes."""
    chunks: list[bytes] = []
    for line in re.findall(rb'[^\n]*\n|[^\n]+', data):
        while len(line) > FGETS_CHUNK:
            chunks.append(line[:FGETS_CHUNK])
            line = line[FGETS_CHUNK:]
        if line:
            chunks.append(line)
    return chunks


_VERSIONS = frozenset({b'TLSv1.3', b'TLSv1.3+', b'TLSv1.2', b'TLSv1.2+', b'TLSv1.1', b'TLSv1.1+', b'TLSv1',
                       b'TLSv1+', b'SSLv3', b'SSLv3+'})
# Options whose value read_config_file validates; every other known option is accepted as text.
_POSITIVE = {b'command_timeout', b'connection_timeout', b'ssl_shutdown_timeout'}
_SETTINGS = {b'nrpe_user', b'nrpe_group', b'dont_blame_nrpe', b'allow_bash_command_substitution'}


class _Walk:
    def __init__(self, files: dict[str, Any], directories: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
        self.files, self.directories, self.gaps = files, directories, gaps
        self.settings: dict[bytes, bytes] = {}
        self.definitions: list[dict[str, Any]] = []
        self.read: list[dict[str, Any]] = []
        self.stack: list[str] = []

    def file(self, path: str) -> bool:
        """Mirror read_config_file. Returns False where nrpe would return ERROR."""
        if not path.startswith('/'):
            _gap(self.gaps, 'relative_include', 'nrpe opens this path relative to its working directory, which '
                 'is not observed.', path=path)
            return False
        if path in self.stack:
            _gap(self.gaps, 'include_cycle', 'nrpe has no include-cycle guard and would recurse until an open '
                 'fails, so the outcome is not modelled.', path=path)
            raise _Stop
        if len(self.stack) >= MAX_DEPTH:
            _gap(self.gaps, 'include_too_deep', f'Includes nest more than {MAX_DEPTH} levels.', path=path)
            raise _Stop
        if len(self.read) >= MAX_FILES:
            _gap(self.gaps, 'too_many_files', f'More than {MAX_FILES} configuration files are read.', path=path)
            raise _Stop
        state = self.files.get(path)
        record: dict[str, Any] = {'path': path, 'depth': len(self.stack)}
        self.read.append(record)
        if state is None:
            record['state'] = 'not_observed'
            _gap(self.gaps, 'file_not_observed', 'This configuration file was not captured.', path=path)
            return False
        if state in ('absent', 'unreadable'):
            record['state'] = state
            return False
        if not isinstance(state, str):
            record['state'] = 'malformed'
            _gap(self.gaps, 'input_malformed', 'File text must be a string, "absent" or "unreadable".', path=path)
            return False
        try:
            data = state.encode('utf-8', 'surrogateescape')
        except UnicodeEncodeError:
            record['state'] = 'malformed'
            _gap(self.gaps, 'input_malformed', 'File text contains characters that are not bytes.', path=path)
            return False
        if len(data) > MAX_BYTES or b'\x00' in data:
            record['state'] = 'malformed'
            _gap(self.gaps, 'config_too_large' if len(data) > MAX_BYTES else 'input_malformed',
                 f'The file is larger than {MAX_BYTES} bytes or contains NUL bytes and was not assessed.', path=path)
            return False
        record['state'] = 'read'
        self.stack.append(path)
        try:
            for number, chunk in enumerate(_chunks(data), 1):
                self.line(chunk, path, number)
        except _FileError as error:
            record['error'] = {'line': error.line, 'detail': error.detail}
            return False
        finally:
            self.stack.pop()
        return True

    def directory(self, value: bytes) -> None:
        """Mirror the include_dir branch and read_config_dir."""
        if len(value) > MAX_DIR_VALUE:
            _gap(self.gaps, 'path_truncated', f'nrpe truncates include_dir values to {MAX_DIR_VALUE} bytes.',
                 path=_text(value))
            raise _Stop
        if value.endswith(b'/'):
            value = value[:-1]
        self.walk(_text(value))

    def walk(self, path: str) -> None:
        if not path.startswith('/'):
            _gap(self.gaps, 'relative_include', 'nrpe opens this directory relative to its working directory, '
                 'which is not observed.', path=path)
            return
        if path in self.stack or len(self.stack) >= MAX_DEPTH:
            _gap(self.gaps, 'include_cycle' if path in self.stack else 'include_too_deep',
                 'Directory recursion repeats or nests too deeply; nrpe has no guard.', path=path)
            raise _Stop
        listing = self.directories.get(path)
        if listing is None:
            _gap(self.gaps, 'directory_not_observed', 'This include_dir listing was not captured.', path=path)
            return
        if listing in ('absent', 'unreadable'):
            return
        if not isinstance(listing, list):
            _gap(self.gaps, 'input_malformed', 'A directory listing must be a list, "absent" or "unreadable".',
                 path=path)
            return
        entries = []
        for entry in listing:
            if (not isinstance(entry, dict) or set(entry) != {'name', 'type'} or not isinstance(entry['name'], str)
                    or entry['type'] not in ('file', 'directory', 'other', 'missing')
                    or entry['name'] in ('', '.', '..') or '/' in entry['name'] or '\x00' in entry['name']):
                _gap(self.gaps, 'input_malformed', 'Each entry needs a name and a file, directory, other or '
                     'missing type.', path=path)
                return
            entries.append((entry['name'].encode('utf-8', 'surrogateescape'), entry['name'], entry['type']))
        self.stack.append(path)
        try:
            for raw, name, kind in sorted(entries):
                child = f'{path}/{name}'
                if len(child.encode('utf-8', 'surrogateescape')) > MAX_ENTRY_PATH:
                    _gap(self.gaps, 'path_truncated', f'nrpe truncates entry paths to {MAX_ENTRY_PATH} bytes.',
                         path=child)
                    raise _Stop
                if kind == 'missing':
                    _gap(self.gaps, 'entry_stat_failed', 'stat failed, so nrpe reuses the previous entry\'s '
                         'result and the outcome is not modelled.', path=child)
                    raise _Stop
                if len(raw) > 4 and raw.endswith(b'.cfg'):
                    if kind != 'file':
                        continue
                    self.file(child)
                if kind == 'directory' and not raw.startswith(b'.'):
                    self.walk(child)
        finally:
            self.stack.pop()

    def line(self, chunk: bytes, path: str, number: int) -> None:
        text = chunk.lstrip(_SPACE).rstrip(_SPACE)
        if not text or text.startswith(b'#'):
            return
        name, after = _strtok(text, 0, b'=')
        if name is None:
            raise _FileError(number, 'No variable name; nrpe stops reading this file.')
        value, _ = _strtok(text, after, b'\n')
        if value is None:
            raise _FileError(number, 'No variable value; nrpe stops reading this file.')
        if name == b'include_dir':
            self.directory(value)
        elif name in (b'include', b'include_file'):
            self.file(_text(value))
        elif name == b'server_port':
            if self.number(value, path, number) < 1024:
                raise _FileError(number, 'server_port is below 1024; nrpe stops reading this file.')
        elif name == b'command_prefix':
            self.settings[name] = value
        elif b'command[' in name:
            self.command(name, value, path, number)
        elif b'debug' in name:
            pass
        elif name in _SETTINGS:
            self.settings[name] = value
        elif name in _POSITIVE:
            if self.number(value, path, number) < 1:
                raise _FileError(number, f'{_text(name)} is below 1; nrpe stops reading this file.')
        elif name == b'listen_queue_size':
            if self.number(value, path, number) == 0:
                raise _FileError(number, 'listen_queue_size is 0; nrpe stops reading this file.')
        elif name == b'ssl_version':
            if value in (b'SSLv2', b'SSLv2+'):
                _gap(self.gaps, 'value_not_modelled', 'Whether SSLv2 is accepted depends on the OpenSSL build.',
                     path=path, line=number)
                raise _Stop
            if value not in _VERSIONS:
                raise _FileError(number, 'Invalid ssl_version; nrpe stops reading this file.')
        elif name in (b'ssl_use_adh', b'ssl_client_certs'):
            if not 0 <= self.number(value, path, number) <= 2:
                raise _FileError(number, f'Invalid {_text(name)}; nrpe stops reading this file.')

    def number(self, value: bytes, path: str, number: int) -> int:
        try:
            return _atoi(value)
        except ValueError:
            _gap(self.gaps, 'value_not_modelled', 'An integer outside the int range has undefined atoi behaviour.',
                 path=path, line=number)
            raise _Stop from None

    def command(self, name: bytes, value: bytes, path: str, number: int) -> None:
        _, after = _strtok(name, 0, b'[')
        command, _ = _strtok(name, after, b']')
        if command is None:
            raise _FileError(number, 'Invalid command name; nrpe stops reading this file.')
        if len(self.definitions) >= MAX_COMMANDS:
            _gap(self.gaps, 'too_many_commands', f'More than {MAX_COMMANDS} command definitions are read.')
            raise _Stop
        self.definitions.append({'name': _text(command), 'raw': value, 'path': path, 'line': number})


def _flag(settings: dict[bytes, bytes], name: bytes) -> bool:
    try:
        return name in settings and _atoi(settings[name]) == 1
    except ValueError:
        return False


def evaluate(files: Any = None, directories: Any = None, *, config_path: str = DEFAULT_CONFIG,
             daemon: Any = None) -> dict[str, Any]:
    """Resolve which commands nrpe runs on request, with which command line, as which account.

    ``files`` maps absolute paths to captured text, ``"absent"`` or ``"unreadable"``; a path that is
    missing from the mapping was not observed. ``directories`` maps absolute include_dir paths to a
    list of ``{"name", "type"}`` entries (``type`` is ``file``, ``directory``, ``other`` or ``missing``
    after following symbolic links), ``"absent"`` or ``"unreadable"``. ``daemon`` is ``None`` when the
    nrpe invocation was not observed, otherwise ``{"mode": "daemon" | "inetd", "start_user": str}`` with
    an optional ``"start_group"`` (the starting effective group). Without it, a run whose effective group
    is not set by ``nrpe_group`` gets a blocking ``start_group_not_observed`` gap, because nrpe exits when
    that group is root.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'config_path': config_path,
        'starts': None, 'files': [], 'commands': [], 'gaps': gaps, 'unobserved': list(UNOBSERVED),
        'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    mode, start_user, start_group = 'daemon', 'root', None
    if daemon is None:
        _gap(gaps, 'daemon_not_observed', 'The nrpe invocation was not observed, so daemon mode started as root '
             'is assumed.')
    elif (not isinstance(daemon, dict) or not {'mode', 'start_user'} <= set(daemon)
          or not set(daemon) <= {'mode', 'start_user', 'start_group'}
          or daemon['mode'] not in ('daemon', 'inetd') or not isinstance(daemon['start_user'], str)
          or not daemon['start_user']
          or ('start_group' in daemon and (not isinstance(daemon['start_group'], str) or not daemon['start_group']))):
        _gap(gaps, 'input_malformed', 'daemon must be a mapping with mode (daemon or inetd), start_user and an '
             'optional start_group.')
    else:
        mode, start_user, start_group = daemon['mode'], daemon['start_user'], daemon.get('start_group')
    if (not isinstance(files, dict) or not isinstance(directories, dict) or not isinstance(config_path, str)
            or not config_path.startswith('/') or not all(isinstance(key, str) for key in [*files, *directories])):
        _gap(gaps, 'input_malformed', 'files and directories must be mappings keyed by path and config_path must '
             'be absolute.')
        result['complete'] = False
        return result
    walk = _Walk(files, directories, gaps)
    try:
        result['starts'] = walk.file(config_path)
    except _Stop:
        result['starts'] = None
    result['files'] = walk.read
    if walk.read and walk.read[0]['state'] in ('not_observed', 'malformed'):
        result['starts'] = None
    if result['starts'] is False:
        result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
        result['refusal'] = 'nrpe reports that the main configuration contained errors and does not start.'
        return result
    settings = walk.settings
    prefix = settings.get(b'command_prefix')
    arguments = _flag(settings, b'dont_blame_nrpe')
    configured_user = _text(settings[b'nrpe_user']) if b'nrpe_user' in settings else None
    configured_group = _text(settings[b'nrpe_group']) if b'nrpe_group' in settings else None
    if mode == 'inetd':
        # drop_privileges returns at once under inetd, so the starting account is the effective one.
        user, group = start_user, start_group
    elif _is_root(start_user):
        user = start_user if configured_user is None else configured_user
        group = start_group if configured_group is None else configured_group
    else:
        # A non-root start cannot setgid(0) or seteuid(0); drop_privileges only logs the failure, so a
        # configured root account leaves the starting account in effect and check_privileges passes.
        user = start_user if configured_user is None or _is_root(configured_user) else configured_user
        group = start_group if configured_group is None or _is_root(configured_group) else configured_group
    if _is_root(user) or _is_root(group):
        if result['starts'] is not True:
            result['complete'] = False
            return result
        result['starts'] = False
        result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
        result['refusal'] = ('check_privileges finds effective user or group root after the privilege drop, so nrpe '
                             'exits ("NRPE daemon cannot be run as user/group root") and runs no commands.')
        return result
    if group is None:
        _gap(gaps, 'start_group_not_observed', 'The effective group is not set by nrpe_group and the starting group '
             'was not observed; nrpe exits if it is root.')
    fallback = None if mode == 'inetd' or _is_root(start_user) or user == start_user else start_user
    latest: dict[str, dict[str, Any]] = {}
    overridden: dict[str, list[dict[str, Any]]] = {}
    for definition in walk.definitions:
        previous = latest.get(definition['name'])
        if previous is not None:
            overridden.setdefault(definition['name'], []).append({'path': previous['path'], 'line': previous['line']})
        latest[definition['name']] = definition
    for name in sorted(latest):
        definition = latest[name]
        line = definition['raw'] if prefix is None else prefix + b' ' + definition['raw']
        limit = MAX_COMMAND_LINE if prefix is None else MAX_PREFIXED_LINE
        truncated = len(line) > limit
        line = line[:limit]
        macros = _argument_macros(line)
        result['commands'].append({
            'name': name, 'path': definition['path'], 'line': definition['line'],
            'command_line': _text(line), 'sha256': hashlib.sha256(line).hexdigest(), 'via': '/bin/sh -c',
            'user': user, 'group': group, 'fallback_user': fallback,
            'prefixed': prefix is not None, 'truncated': truncated, 'argument_macros': macros,
            'arguments_accepted': arguments, 'overrides': overridden.get(name, []),
        })
    result['arguments_accepted'] = arguments
    result['bash_command_substitution'] = arguments and _flag(settings, b'allow_bash_command_substitution')
    result['complete'] = result['starts'] is True and not any(gap['code'] in BLOCKING for gap in gaps)
    return result
