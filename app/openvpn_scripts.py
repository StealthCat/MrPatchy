"""Pure OpenVPN script and plugin contract (roadmap F slice, #1361).

Each ``openvpn@``, ``openvpn-server@`` and ``openvpn-client@`` unit starts one
OpenVPN daemon as root from a configuration file. That configuration names
programs OpenVPN runs on tunnel, routing, address and client events
(``up``, ``down``, ``ipchange``, ``route-up``, ``route-pre-down``,
``client-connect``, ``client-disconnect``, ``client-crresponse``,
``learn-address``, ``tls-verify``, ``tls-crypt-v2-verify`` and
``auth-user-pass-verify``), and the ``plugin`` shared objects it loads into the
root-started process. This module turns captured unit arguments and captured
configuration files into those programs and plugins. It performs no I/O, never
runs OpenVPN or a program, and never authorizes a response action.

The rules follow ``src/openvpn/options.c``, ``argv.c``, ``run_command.c``,
``plugin.c`` and ``init.c`` in OpenVPN 2.6.19 (Ubuntu 24.04
``openvpn_2.6.19-0ubuntu0.24.04.5``); 2.6.3 (Debian 12) has the same option
reader:

- Command-line arguments are read in order. Each ``--name`` takes the following
  arguments up to the next ``--`` argument; a lone argument without ``--`` is
  ``--config``. Any other argument without ``--`` stops OpenVPN.
- ``config`` reads a file relative to the current directory, at most 10 levels
  deep. Each line is read with ``fgets`` into a 257-byte buffer; a line of 256
  bytes or more stops OpenVPN. A UTF-8 BOM on the first line is skipped.
- ``parse_line`` splits a line at C whitespace into at most 16 parameters.
  ``"..."`` and ``'...'`` quote; a backslash escapes ``\\``, ``"`` or
  whitespace outside single quotes, and any other escaped character stops
  OpenVPN. ``#`` or ``;`` at the start of a parameter ends the line. A leading
  ``--`` on the option name is removed.
- A lone ``<tag>`` parameter starts an inline block that ends at the first line
  whose leading-whitespace-stripped text starts with ``</tag>``; a missing end
  tag stops OpenVPN. Script, plugin and include options cannot be inline.
- ``cd`` changes the process directory immediately, so it affects later relative
  ``config`` paths, and the final directory is where relative scripts and
  ``./`` plugins are found. A later script option replaces an earlier one.
  ``ipchange`` and ``tls-verify`` replace ``,`` with a space.
- A script command is split with the same ``parse_line`` rules; if that fails
  the whole string is the program. OpenVPN calls ``execve`` without a PATH
  search and appends event arguments.
- ``script-security`` (``atoi``, default 1) applies when a script runs: level 2
  or higher runs user scripts, and level 3 also passes passwords in the
  environment. Plugins load regardless of the level.
- OpenVPN starts as root and drops to ``user``/``group`` after initialization,
  later with ``--client``, ``--pull`` or ``--up-delay``. ``up`` runs before the
  drop, and again after it with ``up-restart``. Other scripts can run before or
  after it, so the result lists both identities.

Option errors this module models exactly stop OpenVPN, so the result reports
``config_error`` with no scripts or plugins. Errors it does not model, such as
an unknown option, a missing or non-executable script, a failed ``cd`` or a
server-only script without ``--mode server``, can only stop OpenVPN. The
result over-reports in those cases and says so.

Fail-closed rules: an unobserved file, ``config stdin``, invalid UTF-8, NUL
bytes, over-limit input and ``chroot`` path effects mark the result
incomplete. ``origin`` is always ``not_assessed`` and no result is a safety
verdict.
"""
from __future__ import annotations

import hashlib
import posixpath
from collections.abc import Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('2.6.3', '2.6.19')
DEFAULT_PLUGIN_LIBDIR = '/usr/lib/x86_64-linux-gnu/openvpn/plugins'
DEFAULT_SCRIPT_SECURITY = 1
SSEC_SCRIPTS = 2
SSEC_PW_ENV = 3
MAX_PARMS = 16
OPTION_LINE_SIZE = 256
MAX_LEVELS = 10
MAX_PLUGINS = 16
MAX_TEXT = 262144
MAX_FILES = 64
MAX_GAPS = 64
_SPACE = frozenset(b' \t\n\v\f\r\0')

# Unit command lines in Debian 12 and Ubuntu 24.04 openvpn packages.
UNITS: dict[str, tuple[str, tuple[str, ...]]] = {
    'openvpn@': ('/etc/openvpn', (
        '--daemon', 'ovpn-%i', '--status', '/run/openvpn/%i.status', '10', '--cd', '/etc/openvpn',
        '--script-security', '2', '--config', '/etc/openvpn/%i.conf', '--writepid', '/run/openvpn/%i.pid')),
    'openvpn-server@': ('/etc/openvpn/server', (
        '--status', '%t/openvpn-server/status-%i.log', '--status-version', '2', '--suppress-timestamps',
        '--config', '%i.conf')),
    'openvpn-client@': ('/etc/openvpn/client', ('--suppress-timestamps', '--nobind', '--config', '%i.conf')),
}

# option -> (event, max parameters including the name, substitutes ',' with ' ').
SCRIPT_OPTIONS: dict[str, tuple[str, int, bool]] = {
    'up': ('after the tunnel device opens', 2, False),
    'down': ('after the tunnel device closes, or before with down-pre', 2, False),
    'ipchange': ('when the remote address is first authenticated or changes', 2, True),
    'route-up': ('after routes are added', 2, False),
    'route-pre-down': ('before routes are removed', 2, False),
    'client-connect': ('when a client connects (server mode)', 2, False),
    'client-disconnect': ('when a client disconnects (server mode)', 2, False),
    'client-crresponse': ('when a client answers a challenge (server mode)', 2, False),
    'learn-address': ('when a client address is added, updated or deleted (server mode)', 2, False),
    'tls-verify': ('for each peer certificate during the TLS handshake', 2, True),
    'tls-crypt-v2-verify': ('before a tls-crypt-v2 client key is accepted (server mode)', 2, False),
    'auth-user-pass-verify': ('when a client sends a username and password (server mode)', 3, False),
}
_FLAGS = ('up-restart', 'up-delay', 'down-pre')
_SINGLE = ('config', 'cd', 'chroot', 'user', 'group', 'script-security')
_MODELED = frozenset(SCRIPT_OPTIONS) | frozenset(_FLAGS) | frozenset(_SINGLE) | {'plugin'}

BLOCKING = frozenset({
    'file_not_observed', 'stdin_config', 'invalid_utf8', 'binary', 'over_limit', 'files_over_limit',
    'chroot_paths', 'gaps_truncated',
})

NOT_OBSERVED = (
    'Whether OpenVPN is installed, which units are enabled and running, and the unit instance names.',
    ('Whether each script exists and is executable, and whether each cd succeeds. OpenVPN refuses to start '
     'otherwise, so no script runs, but the result still reports them.'),
    ('Options this contract does not model. An unknown, misspelled or invalid one stops OpenVPN; the result '
     'still reports the scripts.'),
    ('Whether the configuration runs in server mode. Server-only scripts without --mode server stop OpenVPN; '
     'the result still reports them.'),
    'The event arguments and environment OpenVPN passes, and what each program or plugin does.',
    'Whether a user or group exists, and the account OpenVPN itself was started as (root for the packaged units).',
    'Options a server pushes to a client. Pushed options cannot set scripts or plugins.',
)


class ConfigError(ValueError):
    """OpenVPN would refuse this configuration and exit."""


def _atoi(text: str) -> int:
    s = text.lstrip(' \t\n\v\f\r')
    sign, i = 1, 0
    if s[:1] in ('+', '-'):
        sign, i = (-1 if s[0] == '-' else 1), 1
    digits = ''
    while i < len(s) and s[i] in '0123456789':
        digits += s[i]
        i += 1
    return max(-(2 ** 31), min(2 ** 31 - 1, sign * int(digits))) if digits else 0


def parse_line(line: bytes, n: int = MAX_PARMS) -> list[bytes] | None:
    """OpenVPN 2.6 ``parse_line``; ``None`` where OpenVPN reports an error."""
    initial, quoted, unquoted, done, squoted = 0, 1, 2, 3, 4
    out_parms: list[bytes] = []
    parm = bytearray()
    state = initial
    backslash = False
    data = bytes(line).split(b'\0', 1)[0] + b'\0'
    for ch in data:
        out = 0
        if not backslash and ch == 0x5C and state != squoted:
            backslash = True
        else:
            if state == initial:
                if ch not in _SPACE:
                    if ch in (0x3B, 0x23):
                        break
                    if not backslash and ch == 0x22:
                        state = quoted
                    elif not backslash and ch == 0x27:
                        state = squoted
                    else:
                        out = ch
                        state = unquoted
            elif state == unquoted:
                if not backslash and ch in _SPACE:
                    state = done
                else:
                    out = ch
            elif state == quoted:
                if not backslash and ch == 0x22:
                    state = done
                else:
                    out = ch
            elif state == squoted:
                if ch == 0x27:
                    state = done
                else:
                    out = ch
            if state == done:
                out_parms.append(bytes(parm))
                parm.clear()
                state = initial
            if backslash and out and not (out == 0x5C or out == 0x22 or out in _SPACE):
                return None
            backslash = False
        if out:
            if len(parm) >= OPTION_LINE_SIZE:
                return None
            parm.append(out)
        if len(out_parms) >= n:
            break
    if state != initial:
        return None
    return out_parms


def _fgets(data: bytes, pos: int, size: int) -> tuple[bytes, int]:
    """One ``fgets(buf, size)`` call from ``pos``: up to ``size - 1`` bytes, through a newline."""
    end = data.find(b'\n', pos, pos + size - 1)
    stop = end + 1 if end >= 0 else min(len(data), pos + size - 1)
    return data[pos:stop], stop


def _identity(user: str | None, group: str | None) -> dict[str, str | None]:
    return {'user': user or 'root', 'group': group}


def _split_command(command: str) -> list[str]:
    parms = parse_line(command.encode('utf-8'), MAX_PARMS)
    if parms:
        return [p.decode('utf-8') for p in parms]
    return [command]


def unit_arguments(unit: str, instance: str, runtime_dir: str = '/run') -> tuple[list[str], str]:
    """Return the packaged unit's OpenVPN arguments and working directory for one instance."""
    if unit not in UNITS:
        raise ValueError('unknown OpenVPN unit ' + repr(unit))
    if not instance or '/' in instance:
        raise ValueError('invalid instance name')
    cwd, args = UNITS[unit]
    return [a.replace('%i', instance).replace('%t', runtime_dir) for a in args], cwd


class _State:
    def __init__(self, files: Mapping[str, Any], cwd: str):
        self.files = files
        self.cwd = cwd
        self.script_security = DEFAULT_SCRIPT_SECURITY
        self.scripts: dict[str, dict[str, Any]] = {}
        self.flags: set[str] = set()
        self.values: dict[str, str] = {}
        self.plugins: list[dict[str, Any]] = []
        self.files_read: list[str] = []
        self.gaps: list[dict[str, str]] = []
        self.overrides: list[dict[str, Any]] = []

    def gap(self, code: str, detail: str) -> None:
        if len(self.gaps) < MAX_GAPS:
            self.gaps.append({'code': code, 'detail': detail})
        elif self.gaps[-1]['code'] != 'gaps_truncated':
            self.gaps.append({'code': 'gaps_truncated', 'detail': 'further gaps omitted'})

    def path(self, value: str) -> str:
        return posixpath.normpath(value if value.startswith('/') else posixpath.join(self.cwd, value))


def _add_option(st: _State, p: list[str], *, is_inline: bool, level: int, where: dict[str, Any]) -> None:
    name = p[0]
    if name not in _MODELED:
        return
    if is_inline:
        raise ConfigError('option %r is not expected to be inline' % name)
    args = p[1:]
    if name in SCRIPT_OPTIONS:
        _event, max_parms, comma = SCRIPT_OPTIONS[name]
        if not args or (name == 'tls-crypt-v2-verify' and len(args) != 1):
            raise ConfigError('unrecognized option or missing parameter: ' + name)
        if len(p) > max_parms:
            raise ConfigError('--%s takes at most %d parameters' % (name, max_parms - 1))
        method = None
        if name == 'auth-user-pass-verify':
            if len(args) < 2 or args[1] not in ('via-env', 'via-file'):
                raise ConfigError('--auth-user-pass-verify needs via-env or via-file')
            method = args[1]
        command = args[0].replace(',', ' ') if comma else args[0]
        if name in st.scripts:
            st.overrides.append({'option': name, 'replaced': st.scripts[name]['source'], 'by': where})
        st.scripts[name] = {'command': command, 'method': method, 'source': where}
    elif name in _FLAGS:
        if args:
            raise ConfigError('unrecognized option or extra parameter: ' + name)
        st.flags.add(name)
    elif name == 'plugin':
        if not args:
            raise ConfigError('unrecognized option or missing parameter: plugin')
        if len(st.plugins) >= MAX_PLUGINS:
            raise ConfigError('plugin add failed: more than %d plugins' % MAX_PLUGINS)
        st.plugins.append({'argv': list(args), 'source': where})
    else:
        if len(args) != 1:
            raise ConfigError('unrecognized option or missing or extra parameter: ' + name)
        value = args[0]
        if name == 'config':
            _read_config(st, value, level, where)
        elif name == 'cd':
            st.cwd = st.path(value)
            st.values['cd'] = st.cwd
        elif name == 'script-security':
            st.script_security = _atoi(value)
        else:
            st.values[name] = value


def _read_config(st: _State, value: str, level: int, where: dict[str, Any]) -> None:
    level += 1
    if level > MAX_LEVELS:
        raise ConfigError('maximum recursive include levels exceeded')
    if value == 'stdin':
        st.gap('stdin_config', 'configuration is read from standard input')
        return
    path = st.path(value)
    if len(st.files_read) >= MAX_FILES:
        st.gap('files_over_limit', path)
        return
    raw = st.files.get(path)
    if raw is None:
        st.gap('file_not_observed', path)
        return
    data = raw.encode('utf-8') if isinstance(raw, str) else bytes(raw)
    st.files_read.append(path)
    if len(data) > MAX_TEXT:
        st.gap('over_limit', path)
        return
    if b'\0' in data:
        st.gap('binary', path)
        return
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        st.gap('invalid_utf8', path)
        return
    pos, number = 0, 0
    while pos < len(data):
        line, pos = _fgets(data, pos, OPTION_LINE_SIZE + 1)
        number += 1
        if len(line) == OPTION_LINE_SIZE:
            raise ConfigError('%s:%d: maximum option line length exceeded' % (path, number))
        if number == 1 and line.startswith(b'\xef\xbb\xbf'):
            line = line[3:]
        parms = parse_line(line, MAX_PARMS)
        if parms is None:
            raise ConfigError('%s:%d: option parse error' % (path, number))
        if not parms:
            continue
        p = [x.decode('utf-8') for x in parms]
        if len(p[0]) >= 3 and p[0].startswith('--'):
            p[0] = p[0][2:]
        is_inline = False
        where = {'file': path, 'line': number}
        if len(p) == 1 and p[0][:1] == '<' and p[0][-1:] == '>':
            tag = p[0][1:-1]
            close = ('</%s>' % tag).encode('utf-8')
            while True:
                if pos >= len(data):
                    raise ConfigError('%s:%d: end tag </%s> missing' % (path, number, tag))
                inner, pos = _fgets(data, pos, OPTION_LINE_SIZE)
                number += 1
                if inner.lstrip(b' \t\n\v\f\r').startswith(close):
                    break
            p = [tag, '']
            is_inline = True
        _add_option(st, p, is_inline=is_inline, level=level, where=where)


def _parse_argv(st: _State, args: Sequence[str]) -> None:
    args = [str(a) for a in args]
    if len(args) == 1 and not args[0].startswith('--'):
        _add_option(st, ['config', args[0]], is_inline=False, level=0, where={'argument': 0})
        return
    i = 0
    while i < len(args):
        if not args[i].startswith('--'):
            raise ConfigError('argument %r is not an --option' % args[i])
        p = [args[i][2:]]
        j = 1
        while j < MAX_PARMS and i + j < len(args) and not args[i + j].startswith('--'):
            p.append(args[i + j])
            j += 1
        _add_option(st, p, is_inline=False, level=0, where={'argument': i})
        i += j


def _executable(st: _State, program: str) -> str:
    return program if program.startswith('/') else st.path(program)


def _plugin_path(st: _State, module: str, libdir: str) -> str:
    if module.startswith('/'):
        return module
    if module.startswith('.'):
        return st.path(module)
    return posixpath.join(libdir, module)


def evaluate(*, args: Sequence[str], files: Mapping[str, Any], working_directory: str,
             plugin_libdir: str = DEFAULT_PLUGIN_LIBDIR) -> dict[str, Any]:
    """Return the scripts and plugins OpenVPN would run for one invocation."""
    cwd = posixpath.normpath(str(working_directory or '/'))
    if not cwd.startswith('/'):
        raise ValueError('working_directory must be absolute')
    st = _State(files, cwd)
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS),
        'origin': 'not_assessed',
        'not_observed': list(NOT_OBSERVED),
    }
    try:
        _parse_argv(st, args)
    except ConfigError as exc:
        result.update({
            'status': 'config_error', 'config_error': str(exc), 'complete': not any(
                g['code'] in BLOCKING for g in st.gaps),
            'files_read': st.files_read, 'scripts': [], 'plugins': [], 'gaps': st.gaps,
            'script_security': st.script_security, 'privilege_drop': None, 'overridden': [],
        })
        return result
    user, group = st.values.get('user'), st.values.get('group')
    dropped = _identity(user, group) if (user or group) else None
    root = {'user': 'root', 'group': None}
    if st.values.get('chroot'):
        st.gap('chroot_paths', 'chroot %s changes where scripts are found after privileges drop'
               % st.values['chroot'])
    scripts = []
    for name in SCRIPT_OPTIONS:
        if name not in st.scripts:
            continue
        entry = st.scripts[name]
        argv = _split_command(entry['command'])
        if name == 'up':
            identities = [root] + ([dropped] if dropped and 'up-restart' in st.flags else [])
        else:
            identities = [root] + ([dropped] if dropped else [])
        permitted = st.script_security >= SSEC_SCRIPTS
        item = {
            'option': name,
            'event': SCRIPT_OPTIONS[name][0],
            'command': entry['command'],
            'command_sha256': hashlib.sha256(entry['command'].encode('utf-8')).hexdigest(),
            'argv': argv,
            'executable': _executable(st, argv[0]),
            'permitted': permitted,
            'permission': ('script-security %d allows user scripts' % st.script_security if permitted else
                           'script-security %d refuses user scripts; OpenVPN logs a warning and does not run it'
                           % st.script_security),
            'may_run_as': identities,
            'source': entry['source'],
        }
        if name == 'auth-user-pass-verify':
            item['method'] = entry['method']
            item['password_in_environment'] = entry['method'] == 'via-env' and st.script_security >= SSEC_PW_ENV
        if name == 'down' and 'down-pre' in st.flags:
            item['event'] = 'before the tunnel device closes (down-pre)'
        if name == 'up' and 'up-restart' in st.flags:
            item['event'] += ', and on every restart (up-restart)'
        scripts.append(item)
    plugins = []
    for plugin in st.plugins:
        module = plugin['argv'][0]
        entry = {
            'module': module,
            'path': _plugin_path(st, module, plugin_libdir),
            'arguments': plugin['argv'][1:],
            'loads_as': root,
            'script_security_applies': False,
            'source': plugin['source'],
        }
        if posixpath.basename(module) == 'openvpn-plugin-down-root.so':
            entry['root_command_arguments'] = plugin['argv'][1:]
        plugins.append(entry)
    result.update({
        'status': 'loads',
        'complete': not any(g['code'] in BLOCKING for g in st.gaps),
        'files_read': st.files_read,
        'working_directory': st.cwd,
        'script_security': st.script_security,
        'privilege_drop': dropped,
        'chroot': st.values.get('chroot'),
        'scripts': scripts,
        'plugins': plugins,
        'overridden': st.overrides,
        'gaps': st.gaps,
    })
    return result
