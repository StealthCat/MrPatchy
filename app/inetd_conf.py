"""Pure openbsd-inetd ``/etc/inetd.conf`` contract (roadmap F slice, #1114).

inetd listens on every socket its configuration names and, when a connection
or datagram arrives, starts the configured program as the configured user, or
answers with one of its built-in services. A single line such as
``31337 stream tcp nowait root /bin/sh sh -i`` is a root shell on a port, so the
file is a classic persistence location. This module turns captured
``/etc/inetd.conf`` text into the services inetd loads and what each one runs.
It performs no I/O, never runs inetd or a program, performs no name lookup and
never authorizes a response action.

The rules follow ``inetd.c`` in openbsd-inetd 0.20221205 with the Debian
patches applied (Ubuntu ``openbsd-inetd_0.20221205-3build5``; the systemd unit
runs ``/usr/sbin/inetd`` with no arguments, so it reads ``/etc/inetd.conf``):

- ``nextline()`` reads with ``fgets`` into a 1024-byte buffer, so a line of
  more than 1023 bytes is read in 1023-byte pieces, and cuts each piece at its
  newline. ``getconfigent()`` skips pieces whose *first* byte is ``#``; an
  indented ``#`` is not a comment and is parsed as fields.
- ``skip()`` splits fields at spaces and tabs only. When a line runs out, it
  peeks at the next byte of the file: if that is a space or tab, the next line
  continues the current entry. Otherwise a missing required field is a syntax
  error, and a missing argument ends argv. A blank line followed by an indented
  line therefore starts an entry on that indented line.
- The first field may carry a ``host:`` prefix (``[addr]:`` for IPv6, ``:`` for
  ``*``); a field that is only ``host:`` sets the default host for later lines.
  Hosts are comma-separated, and each one becomes its own listener.
- Fields: service, socket type (``stream``/``dgram``; anything else is kept as
  an unusable type), protocol with optional ``,sndbuf=``/``,rcvbuf=`` sizes,
  ``wait``/``nowait`` with an optional ``.max`` rate, ``user`` with an optional
  ``.group`` or ``:group``, the server program or ``internal``, then up to 20
  arguments; further arguments are dropped. Without arguments, argv[0] is the
  program's base name.
- Debian's ``default_v4v6`` patch: a protocol without a trailing ``4`` or ``6``
  (``tcp``, ``udp``, ``rpc/tcp``) loads once as IPv4 and then a second time as
  IPv6 with ``6`` appended. The second pass re-parses only a saved copy of the
  entry's *first* physical line, so fields or arguments on continuation lines
  are missing from the IPv6 copy.
- A later entry with the same service, host, protocol and address replaces the
  earlier entry's user, group, program, argv and rate. Its wait mode is taken
  only when the earlier entry was ``wait`` or the later one is ``nowait``, and
  never from a built-in. The socket type and built-in of the first entry stay.
- At spawn time a root user's ``group`` is ignored: inetd sets root's own
  primary group. For any other user the group replaces the primary group.
  ``execv`` runs the program path as written, without a PATH search.

Fail-closed rules: unobserved, binary, invalid UTF-8 or over-limit text, an
unreadable file, input-dependent undefined behaviour in inetd's buffer-size
parser and an entry that makes the IPv6 re-parse loop forever mark the result
incomplete. ``origin`` is always ``not_assessed`` and no result is a safety
verdict.
"""
from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSION = '0.20221205-3build5'
CONFIG_PATH = '/etc/inetd.conf'
LINE_BUFFER = 1024  # char line[1024]; fgets reads at most 1023 bytes.
MAXARGV = 20
TOOMANY = 256  # default -R invocation rate per CNT_INTVL seconds.
CNT_INTVL = 60
SUN_PATH = 108
PROTONAME = 11  # char protoname[11] for getservbyname().
INT_MAX = 2**31 - 1
MAX_TEXT = 262144
MAX_ENTRIES = 1024
MAX_GAPS = 64
BUILTINS = {
    # (service, socket type): forks
    ('echo', 'stream'): True, ('echo', 'dgram'): False,
    ('discard', 'stream'): True, ('discard', 'dgram'): False,
    ('time', 'stream'): False, ('time', 'dgram'): False,
    ('daytime', 'stream'): False, ('daytime', 'dgram'): False,
    ('chargen', 'stream'): True, ('chargen', 'dgram'): False,
}
BLOCKING = frozenset({
    'text_not_observed', 'file_unreadable', 'over_limit', 'binary', 'invalid_utf8', 'entries_over_limit',
    'buffer_size_undefined', 'reparse_never_ends', 'gaps_truncated',
})
NOT_OBSERVED = (
    ('Whether openbsd-inetd is installed, enabled and running, and whether it was started with another '
    'configuration file or with -R, -l or other options.'),
    ('Name lookups: host names, /etc/services port names and /etc/rpc program names. A service that needs '
    'one is listed with the lookup; it does not listen if the lookup fails.'),
    ('Which uid and gid each user and group name maps to. A user other than "root" with uid 0 also runs as '
    'root, and an unknown user or group makes every spawn fail.'),
    'Whether the kernel supports IPv6; without it, inetd skips every IPv6 listener.',
    'Whether each socket binds; a port already in use leaves the service retrying every 10 minutes.',
    ('The contents of the programs inetd runs, and the working directory a relative program or unix socket '
    'path resolves against.'),
)
_SPACE = b' \t'


def _gap(gaps: list[dict[str, Any]], code: str, line: int | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'line': line, 'detail': detail[:240], 'blocking': code in BLOCKING})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'line': None, 'detail': 'Further gaps were not recorded.',
                     'blocking': True})


class _Reader:
    """The ``fconfig`` stream as ``nextline()`` and ``skip()`` see it."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.number = 0

    def nextline(self) -> bytes | None:
        if self.pos >= len(self.data):
            return None
        limit = self.pos + LINE_BUFFER - 1
        newline = self.data.find(b'\n', self.pos, limit)
        end = newline + 1 if newline >= 0 else min(limit, len(self.data))
        piece = self.data[self.pos:end]
        self.pos = end
        self.number += 1
        return piece.split(b'\n', 1)[0]

    def peek(self) -> bytes:
        return self.data[self.pos:self.pos + 1]


class _Cursor:
    """``char *cp`` with ``skip()`` semantics; ``line is None`` is ``cp == NULL``."""

    def __init__(self, reader: _Reader, line: bytes) -> None:
        self.reader = reader
        self.line: bytes | None = line
        self.index = 0
        self.continued = False

    def skip(self) -> bytes | None:
        if self.line is None:
            return None
        while True:
            while self.index < len(self.line) and self.line[self.index:self.index + 1] in _SPACE:
                self.index += 1
            if self.index < len(self.line):
                break
            if self.reader.peek() in (b' ', b'\t'):
                following = self.reader.nextline()
                if following is not None:
                    self.line, self.index, self.continued = following, 0, True
                    continue
            self.line = None
            return None
        start = self.index
        while self.index < len(self.line) and self.line[self.index:self.index + 1] not in _SPACE:
            self.index += 1
        token = self.line[start:self.index]
        if self.index < len(self.line):
            self.index += 1
        return token


def _strtol(text: str, base: int = 0) -> tuple[int | None, str]:
    """C ``strtol``/``strtoul`` prefix parse; returns (value or None when no digits, rest)."""
    index = 0
    while index < len(text) and text[index] in ' \t\n\v\f\r':
        index += 1
    sign = 1
    if index < len(text) and text[index] in '+-':
        sign = -1 if text[index] == '-' else 1
        index += 1
    if base == 0:
        if text[index:index + 2].lower() == '0x' and index + 2 < len(text) and \
                text[index + 2].lower() in '0123456789abcdef':
            base, index = 16, index + 2
        elif text[index:index + 1] == '0':
            base = 8
        else:
            base = 10
    digits = '0123456789abcdef'[:base]
    start = index
    while index < len(text) and text[index].lower() in digits:
        index += 1
    if index == start:
        return None, text
    return sign * int(text[start:index], base), text[index:]


def _max_field(value: str) -> tuple[int | None, bool]:
    """``se_max = strtoul(s, &p, 0)``; ``(None, invalid)`` means the -R default."""
    number, rest = _strtol(value)
    if number is None or rest:
        return None, True
    number %= 2**64  # strtoul wraps negatives; overflow saturates at ULONG_MAX.
    as_int = number % 2**32
    if as_int >= 2**31:
        as_int -= 2**32
    return (as_int, False) if as_int >= 1 else (None, True)


def _buffers(proto: str) -> tuple[str, dict[str, int], str | None]:
    """Apply the ``,sndbuf=``/``,rcvbuf=`` parser; returns (proto, sizes, failure).

    inetd replaces each comma with NUL inside one buffer and then checks ``cp0[1]``, the byte after the
    first non-digit of each size. For a size of digits only that is the next option's first byte (so the
    entry is malformed) or, for the last option, the byte after the string's end, which is undefined.
    """
    if ',' not in proto:
        return proto, {}, None
    base, _, rest = proto.partition(',')
    parts = rest.split(',')
    if len(parts) > 2:
        return base, {}, 'too_many_buffer_sizes'
    if any('=' not in part for part in parts):
        return base, {}, 'malformed_buffer_option'
    sizes: dict[str, int] = {}
    for position, part in enumerate(parts):
        name, _, size = part.partition('=')
        if not size[:1].isdigit() or not size[:1].isascii():
            return base, {}, 'malformed_buffer_option'
        number, after = _strtol(size, 10)
        assert number is not None
        if not after:
            if position + 1 < len(parts):
                return base, {}, 'malformed_buffer_option'
            return base, {}, 'buffer_size_undefined'
        if len(after) > 1:
            return base, {}, 'malformed_buffer_option'
        number *= {'k': 1024, 'm': 1024 * 1024}.get(after, 1)
        if number > INT_MAX:
            return base, {}, 'buffer_size_undefined'
        if number < 1:
            return base, {}, 'invalid_buffer_size'
        if name not in ('sndbuf', 'rcvbuf'):
            return base, {}, 'malformed_buffer_option'
        sizes[name] = number
    return base, sizes, None


def _rpc(service: str) -> tuple[str, dict[str, Any] | None, str | None]:
    name, slash, version = service.partition('/')
    if not slash:
        return service, None, 'no_rpc_version'
    low, rest = _strtol(version)
    if low is None or low < 0 or low > INT_MAX:
        return name, None, 'bad_rpc_version'
    high = low
    if rest.startswith('-'):
        high, tail = _strtol(rest[1:])
        if high is None or high < 0 or high > INT_MAX or high < low or tail:
            return name, None, 'bad_rpc_version'
    elif rest:
        return name, None, 'bad_rpc_version'
    return name, {'versions': [low, high]}, None


def _host(host: str, family: str) -> tuple[str, str | None]:
    """Return (kind, address) for one host under ``getaddrinfo(AI_PASSIVE)``."""
    if host == '*':
        return 'wildcard', '0.0.0.0' if family == 'inet' else '::'
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return 'lookup', None
    if (address.version == 4) != (family == 'inet'):
        return 'wrong_family', None
    return 'literal', str(address)


def _port(service: str) -> int | None:
    if service.isdigit() and service.isascii():
        value = int(service)
        return value if 1 <= value <= 65535 else None
    return None


def _decode(token: bytes) -> str:
    return token.decode('utf-8', 'surrogateescape')


def _parse_entry(cursor: _Cursor, line: int, defhost: list[str], override: str | None
                 ) -> dict[str, Any]:
    """One ``getconfigent()`` pass; returns ``{'kind': ...}`` describing its outcome."""
    arg = cursor.skip()
    if arg is None:
        return {'kind': 'blank'}
    text = _decode(arg)
    host: str
    colon = text.rfind(':')
    if colon >= 0:
        prefix = text[:colon]
        if prefix.startswith('[') and colon > 0 and prefix.endswith(']'):
            host = prefix[1:-1]
        elif colon == 0:
            host = '*'
        else:
            host = prefix
        text = text[colon + 1:]
        if not text:
            following = cursor.skip()
            if cursor.line is None:
                defhost[0] = host
                return {'kind': 'default_host', 'host': host}
            assert following is not None
            text = _decode(following)
    else:
        host = defhost[0]
    entry: dict[str, Any] = {'kind': 'entry', 'line': line, 'host': host, 'service': text}

    def fail(reason: str) -> dict[str, Any]:
        return {**entry, 'kind': 'rejected', 'reason': reason, 'continued': cursor.continued}

    socktype = cursor.skip()
    if socktype is None:
        return fail('syntax_error')
    entry['socket_type'] = _decode(socktype)
    proto_raw = cursor.skip()
    if proto_raw is None:
        return fail('syntax_error')
    proto, sizes, problem = _buffers(_decode(proto_raw))
    entry['buffers'] = sizes
    entry['undefined'] = problem == 'buffer_size_undefined'
    if problem and not entry['undefined']:
        return fail(problem)
    entry['override_ipv6'] = False
    if proto == 'unix':
        family = 'unix'
    elif override is not None:
        family, proto = 'inet6', proto + '6'
    elif proto.endswith('4'):
        family = 'inet'
    elif proto.endswith('6'):
        family = 'inet6'
    else:
        family = 'inet'
        entry['override_ipv6'] = True
    entry.update(family=family, protocol=proto, rpc=None)
    if family != 'unix' and proto.startswith('rpc/'):
        name, rpc, rpc_problem = _rpc(entry['service'])
        entry['service'] = name
        if rpc_problem:
            return fail(rpc_problem)
        entry['rpc'] = rpc
    wait_raw = cursor.skip()
    if wait_raw is None:
        return fail('syntax_error')
    wait_text = _decode(wait_raw)
    mode, dot, max_text = wait_text.partition('.')
    entry['max'], entry['max_field_invalid'] = _max_field(max_text) if dot else (None, False)
    entry['wait'] = mode == 'wait'
    user_raw = cursor.skip()
    if user_raw is None:
        return fail('syntax_error')
    user = _decode(user_raw)
    split = user.find('.')
    if split < 0:
        split = user.find(':')
    entry['user'], entry['group'] = (user[:split], user[split + 1:]) if split >= 0 else (user, None)
    server_raw = cursor.skip()
    if server_raw is None:
        return fail('syntax_error')
    server = _decode(server_raw)
    entry['builtin'] = None
    if server == 'internal':
        key = (entry['service'], entry['socket_type'])
        if key not in BUILTINS:
            return fail('unknown_internal_service')
        entry['builtin'] = entry['service']
        entry['builtin_forks'] = BUILTINS[key]
        entry['wait'] = False
    entry['server'] = server
    argv: list[str] = []
    dropped = 0
    while True:
        token = cursor.skip()
        if cursor.line is None or token is None:
            break
        if len(argv) < MAXARGV:
            argv.append(_decode(token))
        else:
            dropped += 1
    if not argv and entry['builtin'] is None:
        argv = [server.rsplit('/', 1)[-1]]
    entry.update(argv=argv, argv_dropped=dropped, continued=cursor.continued)
    return entry


def _listeners(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand the comma-separated host list as getconfigent()'s getaddrinfo loop does."""
    if entry['family'] == 'unix':
        return [{'host': entry['host'], 'address': None, 'lookups': []}]
    found = []
    for host in entry['host'].split(','):
        if not host:
            continue
        kind, address = _host(host, entry['family'])
        if kind == 'wrong_family':
            continue
        lookups = [{'kind': 'host', 'name': host}] if kind == 'lookup' else []
        found.append({'host': host, 'address': address, 'lookups': lookups})
    return found


def _service(entry: dict[str, Any], listener: dict[str, Any]) -> dict[str, Any]:
    family = entry['family']
    builtin = entry['builtin']
    user = entry['user']
    record: dict[str, Any] = {
        'lines': [entry['line']], 'host': listener['host'], 'address': listener['address'],
        'family': family, 'service': entry['service'], 'port': None, 'unix_path': None,
        'socket_type': entry['socket_type'], 'protocol': entry['protocol'], 'rpc': entry['rpc'],
        'buffers': entry['buffers'], 'wait': entry['wait'], 'max': entry['max'],
        'max_default': TOOMANY if entry['max'] is None else None, 'max_interval_seconds': CNT_INTVL,
        'max_field_invalid': entry['max_field_invalid'], 'user': user, 'group': entry['group'],
        'group_applied': None if entry['group'] is None else user != 'root',
        'builtin': builtin, 'builtin_forks': entry.get('builtin_forks') if builtin else None,
        'program': None if builtin else entry['server'], 'argv': [] if builtin else list(entry['argv']),
        'argv_dropped': entry['argv_dropped'], 'program_relative': None,
        'runs_as_root': True if builtin or user == 'root' else None,
        'ipv6_copy': entry.get('ipv6_copy', False), 'requires_kernel_ipv6': family == 'inet6',
        'lookups': list(listener['lookups']), 'continued': entry['continued'],
        'undefined': entry['undefined'], 'status': 'listens', 'reason': None, 'origin': 'not_assessed',
    }
    if not builtin:
        record['program_relative'] = not entry['server'].startswith('/')
    return record


def _resolve(record: dict[str, Any]) -> None:
    """Apply the config() checks that decide whether a merged service listens."""
    if record['undefined']:
        record.update(status='unresolved', reason='buffer_size_undefined')
    if record['socket_type'] not in ('stream', 'dgram'):
        record.update(status='never_listens', reason='unknown_socket_type')
        return
    if record['family'] == 'unix':
        record['unix_path'] = record['service']
        if len(record['service'].encode('utf-8', 'surrogateescape')) >= SUN_PATH:
            record.update(status='never_listens', reason='unix_path_too_long')
        return
    if record['rpc'] is not None:
        number = _port(record['service'])
        record['rpc'] = {**record['rpc'], 'program': number}
        if number is None:
            record['lookups'].append({'kind': 'rpc', 'name': record['service']})
        return
    port = _port(record['service'])
    if port is not None:
        record['port'] = port
        return
    protoname = record['protocol'][:PROTONAME - 1]
    if record['family'] == 'inet':
        for index, char in enumerate(protoname):
            if char.isdigit() and char.isascii():
                protoname = protoname[:index]
                break
    elif protoname[-1:].isdigit():
        protoname = protoname[:-1]
    record['lookups'].append({'kind': 'service', 'name': record['service'], 'protocol': protoname})


def _merge(old: dict[str, Any], new: dict[str, Any]) -> None:
    if new['builtin'] is None and (old['wait'] or not new['wait']):
        old['wait'] = new['wait']
    for key in ('max', 'max_default', 'max_field_invalid', 'user', 'group', 'argv_dropped'):
        old[key] = new[key]
    old['rpc'] = new['rpc']
    old['lines'].append(new['lines'][0])
    old['undefined'] = old['undefined'] or new['undefined']
    if old['builtin'] is None:
        # The first entry's built-in stays; a later "internal" only swaps the program name.
        old['program'] = new['program'] if new['builtin'] is None else 'internal'
        old['argv'] = list(new['argv'])
        old['program_relative'] = not old['program'].startswith('/')
        old['runs_as_root'] = True if old['user'] == 'root' else None
    old['group_applied'] = None if old['group'] is None else old['user'] != 'root'


def evaluate(text: str | bytes | None, *, state: str = 'read', path: str = CONFIG_PATH) -> dict[str, Any]:
    """Resolve the services openbsd-inetd loads from captured ``/etc/inetd.conf`` text.

    ``state`` is ``'read'`` when ``text`` is the file's content, ``'absent'`` when the file does not exist
    (the packaged systemd unit and init script then do not start inetd) and ``'unreadable'`` when it could not
    be read.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'format': 'openbsd_inetd_conf', 'source_version': SOURCE_VERSION,
        'path': path, 'complete': False, 'inetd_starts': None, 'sha256': None, 'size': None,
        'services': [], 'rejected': [], 'default_hosts': [], 'origin': 'not_assessed', 'gaps': gaps,
        'not_observed': list(NOT_OBSERVED),
        'execution': {'exec': 'execv(program, argv) without a PATH search', 'stdio': 'the accepted socket',
                      'environment': 'cleared unless inetd runs with -E', 'umask': '022'},
    }
    if state == 'absent':
        result.update(inetd_starts=False, complete=True)
        return result
    if state == 'unreadable':
        _gap(gaps, 'file_unreadable', None, f'{path[:200]} could not be read.')
        return result
    if text is None or state != 'read':
        _gap(gaps, 'text_not_observed', None, f'The text of {path[:200]} was not captured.')
        return result
    data = text.encode('utf-8', 'surrogatepass') if isinstance(text, str) else text
    if not isinstance(data, bytes) or len(data) > MAX_TEXT:
        _gap(gaps, 'over_limit', None, f'More than {MAX_TEXT} bytes.')
        return result
    if b'\x00' in data:
        _gap(gaps, 'binary', None, 'The file contains NUL bytes.')
        return result
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', None, 'The file is not valid UTF-8.')
        return result
    result.update(sha256=hashlib.sha256(data).hexdigest(), size=len(data), inetd_starts=True)
    reader = _Reader(data)
    defhost = ['*']
    services: list[dict[str, Any]] = []
    saved: tuple[bytes, int] | None = None
    passes = 0
    while True:
        passes += 1
        if passes > MAX_ENTRIES * 2:
            _gap(gaps, 'entries_over_limit', reader.number, f'More than {MAX_ENTRIES} entries.')
            break
        reparse = saved is not None
        if saved is not None:
            first, line = saved
            position = reader.pos
            entry = _parse_entry(_Cursor(reader, first), line, defhost, 'ipv6')
            if 'family' not in entry:
                # proto_override is cleared only once the protocol is parsed again.
                if reader.pos == position:
                    _gap(gaps, 'reparse_never_ends', line, 'The IPv6 re-parse of this entry\'s first line '
                         'never reaches the protocol, so getconfigent() repeats it forever and inetd never '
                         'finishes loading its configuration.')
                    break
                continue
            saved = None
            entry['ipv6_copy'] = True
        else:
            while True:
                first_line = reader.nextline()
                if first_line is None or not first_line.startswith(b'#'):
                    break
            if first_line is None:
                break
            line = reader.number
            entry = _parse_entry(_Cursor(reader, first_line), line, defhost, None)
            if entry.get('override_ipv6'):
                saved = (first_line, line)
        if entry['kind'] == 'default_host':
            result['default_hosts'].append({'line': line, 'host': entry['host']})
            continue
        if entry['kind'] == 'blank':
            continue
        if entry['kind'] == 'rejected':
            result['rejected'].append({'line': entry['line'], 'service': entry['service'],
                                       'protocol': entry.get('protocol'), 'ipv6_copy': reparse,
                                       'reason': entry['reason']})
            continue
        if entry['undefined']:
            _gap(gaps, 'buffer_size_undefined', entry['line'], 'inetd reads past the end of the buffer-size '
                 'value, so whether this entry loads depends on heap contents.')
        listeners = _listeners(entry)
        if not listeners:
            result['rejected'].append({'line': entry['line'], 'service': entry['service'],
                                       'protocol': entry['protocol'], 'ipv6_copy': reparse,
                                       'reason': 'no_resolvable_address'})
            continue
        for listener in listeners:
            record = _service(entry, listener)
            match = next((s for s in services if s['service'] == record['service'] and s['host'] == record['host']
                          and s['protocol'] == record['protocol'] and s['address'] == record['address']), None)
            if match is None:
                services.append(record)
            else:
                _merge(match, record)
    for record in services:
        _resolve(record)
        if record['lookups']:
            _gap(gaps, 'lookup_not_observed', record['lines'][0], f'{record["service"][:60]}/'
                 f'{record["protocol"][:20]} needs a name lookup that was not observed.')
    result['services'] = services
    result['complete'] = not any(g['blocking'] for g in gaps)
    return result
