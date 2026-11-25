"""Pure Postfix master.cf service contract (roadmap F slice, #1338).

Postfix ``master(8)`` reads ``master.cf`` when Postfix starts and on every
``postfix reload``. It starts each service listed there as root, from
``$daemon_directory``. The ``pipe(8)`` and ``spawn(8)`` services then run the
external command named by ``argv=`` as the account named by ``user=``, which is
the usual way to attach content filters and mail-triggered scripts. This module
turns captured ``master.cf`` text and captured ``main.cf`` parameter values into
the services master would start and the external commands they run. It performs
no I/O, never runs Postfix or a command and never authorizes a response action.

The rules follow Postfix 3.8.6 (``src/master/master_ent.c``,
``src/master/master_conf.c``, ``src/util/readlline.c``, ``src/util/mystrtok.c``,
``src/util/extpar.c``, ``src/util/host_port.c``, ``src/global/match_service.c``,
``src/master/single_server.c``, ``src/pipe/pipe.c`` and ``src/spawn/spawn.c``):

- Logical lines follow ``readllines``. Empty, all-whitespace and ``#`` lines
  (after leading whitespace) are dropped anywhere, including inside a
  continuation. A line that starts with whitespace continues the previous
  logical line and is appended without a separator. A logical line that itself
  starts with whitespace is skipped with a warning.
- Fields are split at ``" \\t\\r\\n"``. ``#`` later in a line is not a comment.
  The first two fields (name, type) are read first, and an entry whose
  ``name/type`` matches ``master_service_disable`` is skipped before any other
  validation. If ``inet_protocols`` is empty, ``inet`` is disabled as well. The
  match list is split at ``", \\t\\r\\n"``, a ``name.type`` pattern without
  ``/`` becomes ``name/type``, leading ``!`` toggles the result, matching is
  case-insensitive and the first match wins.
- ``-`` selects a field's default. ``private``, ``unprivileged`` and ``chroot``
  must be ``y`` or ``n``. ``wakeup`` and ``maxproc`` must start with a digit
  and are read with ``atoi``, so a ``wakeup`` of ``60?`` is a conditional
  wakeup. The ``chroot`` default is ``y`` below compatibility level 1 and ``n``
  from level 1. An inet service cannot be private. The command field has no
  default.
- The remaining fields are split with ``{}`` grouping. A field that starts with
  ``{`` must be one balanced group, whose content is stripped of surrounding
  whitespace.
- A service is identified by its type and its canonical endpoint:
  ``private/NAME`` or ``public/NAME`` for local types and the canonical host and
  port for inet. A later entry with the same identity replaces the earlier
  entry, so the last entry wins.
- master runs ``$daemon_directory/COMMAND`` as root with the arguments it
  builds: ``-l`` for maxproc 1, ``-z`` for maxproc 0, ``-n NAME`` when the
  command's basename differs from the service name, ``-t TYPE``, ``-u`` when
  unprivileged, ``-c`` when chrooted, ``-o stress=`` for non-local services with
  maxproc above 1 and ``-s N`` for several inet sockets, then the entry's own
  fields.
- ``pipe`` and ``spawn`` parse the argument vector with
  ``getopt("+cdDi:lm:n:o:r:s:St:uvVz")``. The first non-option starts the
  service attributes: ``user=name[:group]`` and ``argv=command...`` for both,
  plus ``flags=``, ``directory=``, ``chroot=``, ``eol=``, ``null_sender=`` and
  ``size=`` for pipe. Everything after ``argv=`` is the external command. A
  missing ``user=`` or ``argv=``, an unknown attribute or flag, ``root`` or the
  mail owner as ``user=``, or ``root`` as the group is fatal in the daemon, so
  the service starts but the command never runs.

A master.cf error stops master, so no service starts. This module reports
``config_error`` only for the errors it models exactly. Validations it does not
model, such as host name syntax, address resolution and account lookup, can only
stop master or the daemon, so the result over-reports rather than under-reports
and states the limitation.

Fail-closed rules: unobserved ``master.cf`` or ``main.cf``, a needed parameter
whose value needs ``$`` expansion, an endpoint identity that needs name
resolution and could collide with another entry, invalid UTF-8, NUL bytes and
over-limit input mark the result incomplete. ``origin`` is always
``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import hashlib
import ipaddress
import posixpath
import re
from collections.abc import Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('3.8.6',)
DEFAULT_PATH = '/etc/postfix/master.cf'
MAX_TEXT = 262144
MAX_SERVICES = 512
MAX_GAPS = 64
TRANSPORTS = ('inet', 'unix', 'unix-dgram', 'fifo', 'pass')
BLANKS = ' \t\r\n'
LIST_DELIMS = ', \t\r\n'
DEFAULTS = {
    'master_service_disable': '', 'inet_protocols': 'all', 'default_process_limit': '100',
    'compatibility_level': '0', 'mail_owner': 'postfix',
}
SINGLE_SERVER_OPTS = 'cdDi:lm:n:o:r:s:St:uvVz'
PIPE_FLAGS = frozenset('BDFOXR.>hqu')
PIPE_ATTRS = ('flags', 'user', 'directory', 'chroot', 'eol', 'null_sender', 'size', 'argv')
SPAWN_ATTRS = ('user', 'argv')
_MACRO = re.compile(r'\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|\(([A-Za-z_][A-Za-z0-9_]*)\)|([A-Za-z_][A-Za-z0-9_]*))')
_COMPAT = re.compile(r'^([0-9]+)(?:\.([0-9]+)(?:\.([0-9]+))?)?$')

BLOCKING = frozenset({
    'file_not_observed', 'main_cf_not_observed', 'parameter_expansion_unresolved', 'parameter_invalid',
    'identity_unresolved', 'over_limit', 'invalid_utf8', 'binary', 'gaps_truncated', 'services_over_limit',
    'integer_out_of_range',
})

NOT_OBSERVED = (
    'Whether Postfix is installed and running, and which master.cf and main.cf (config_directory) it uses.',
    ('Host name syntax, address resolution and inet_interfaces. An invalid or unresolvable inet endpoint stops '
     'master, so no service starts, but the result still reports the services.'),
    ('Whether each user= account and group exists, and their numeric IDs. pipe and spawn refuse UID 0, GID 0 and '
     "the mail owner's IDs; only the literal names root and mail_owner are checked here."),
    'Whether each command exists in daemon_directory, and what a non-Postfix program there does with -u.',
    'Per-delivery expansion of pipe argv= macros such as ${recipient}, and which mail reaches each transport.',
    'Services started outside master, such as postdrop and sendmail, and main.cf content_filter routing.',
    ('Commands named by main.cf or by -o overrides, such as mailbox_command or milters. -o overrides are '
     'reported only as raw arguments.'),
    ('The -d, -v and -s arguments and whether a virtual inet service is loopback-only, which depend on how '
     'master was started and on inet_interfaces, so args and program_sha256 can differ from the live process.'),
)


class ConfigError(ValueError):
    """master would refuse this master.cf and exit."""


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


def _isspace(ch: str) -> bool:
    return ch in ' \t\n\v\f\r'


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Return ``(first_line_number, logical_line)`` pairs the way ``readllines`` builds them."""
    physical = text.split('\n')
    if physical and physical[-1] == '':
        physical.pop()
    out: list[tuple[int, str]] = []
    buf = ''
    first = 0
    for number, line in enumerate(physical, 1):
        stripped = line.lstrip(' \t\n\v\f\r')
        if stripped == '' or stripped.startswith('#'):
            continue
        if buf and _isspace(line[0]):
            buf += line
            continue
        if buf:
            out.append((first, buf))
        buf, first = line, number
    if buf:
        out.append((first, buf))
    return [(n, s) for n, s in out if not _isspace(s[0])]


def _tokens(line: str) -> list[str]:
    return [t for t in re.split('[' + re.escape(BLANKS) + ']+', line) if t]


def _brace_tokens(rest: str) -> list[str]:
    """``mystrtokq(bufp, BLANKS, "{}")`` followed by ``extpar(..., EXTPAR_FLAG_STRIP)``."""
    out: list[str] = []
    i, n = 0, len(rest)
    while True:
        while i < n and rest[i] in BLANKS:
            i += 1
        if i >= n:
            return out
        start, level = i, 0
        while i < n:
            ch = rest[i]
            if ch == '{':
                level += 1
            elif level > 0 and ch == '}':
                level -= 1
            elif level == 0 and ch in BLANKS:
                break
            i += 1
        token = rest[start:i]
        i += 1
        if token.startswith('{'):
            length = _balpar(token)
            if length == 0:
                raise ConfigError("missing '}' in \"%s\"" % token[:80])
            if length != len(token):
                raise ConfigError("syntax error after '}' in \"%s\"" % token[:80])
            token = token[1:length - 1].strip(' \t\n\v\f\r')
        out.append(token)


def _balpar(text: str) -> int:
    level = 1
    for index, ch in enumerate(text[1:], 1):
        if ch == '}':
            level -= 1
            if level == 0:
                return index + 1
        elif ch == '{':
            level += 1
    return 0


def _disable_patterns(value: str, inet_off: bool) -> list[str]:
    items = [t for t in re.split('[' + re.escape(LIST_DELIMS) + ']+', value) if t]
    if inet_off:
        items = ['inet'] + items
    out = []
    for item in items:
        if '/' not in item and '.' in item:
            head, _, tail = item.rpartition('.')
            item = head + '/' + tail
        out.append(item)
    return out


def _disabled(patterns: list[str], name: str, transport: str) -> bool:
    name_type = name + '/' + transport
    for pattern in patterns:
        match = True
        while pattern.startswith('!'):
            match = not match
            pattern = pattern[1:]
        subject = name_type if '/' in pattern else transport
        if subject.lower() == pattern.lower():
            return match
    return False


def _atoi_field(value: str, field: str, minimum: int, gaps: list, where: str) -> int:
    if not value[:1].isdigit() or not value[:1].isascii():
        raise ConfigError('field "%s": bad value: "%s"' % (field, value[:80]))
    digits = re.match('[0-9]+', value).group(0)
    if len(digits) > 9:
        _gap(gaps, 'integer_out_of_range', where, field)
    number = int(digits)
    if number < minimum:
        raise ConfigError('field "%s": bad value: "%s"' % (field, value[:80]))
    return number


def _field(tokens: list[str], index: int, field: str, default: str | None) -> str:
    if index >= len(tokens):
        raise ConfigError('missing "%s" field' % field)
    value = tokens[index]
    if value == '-':
        if default is None:
            raise ConfigError('field "%s" has no default value' % field)
        return default
    return value


def _bool(value: str, field: str) -> bool:
    if value == 'y':
        return True
    if value == 'n':
        return False
    raise ConfigError('field "%s": bad value: "%s"' % (field, value[:80]))


def _inet_endpoint(name: str, services: Mapping[str, int] | None) -> tuple[Any, Any, bool]:
    """Return ``(host, port, resolved)`` following ``host_port(name, &host, "", &port, 0)``."""
    if name.startswith('['):
        body = name[1:]
        ipv6 = body[:5].lower() == 'ipv6:'
        if ipv6:
            body = body[5:]
        if ']' not in body:
            raise ConfigError('missing "]" in "%s"' % name[:80])
        host, _, after = body.partition(']')
        if after and not after.startswith(':'):
            raise ConfigError('garbage after "]" in "%s"' % name[:80])
        port = after[1:] if after else ''
        if ipv6:
            try:
                ipaddress.IPv6Address(host)
            except ValueError as exc:
                raise ConfigError('malformed IPv6 address in "%s"' % name[:80]) from exc
        if port == '':
            raise ConfigError('missing service information in "%s"' % name[:80])
    elif ':' in name:
        host, _, port = name.rpartition(':')
        if port == '':
            raise ConfigError('missing service information in "%s"' % name[:80])
    else:
        host, port = '', name
    if port[:1].isdigit() and not port.isdigit():
        raise ConfigError('garbage after numerical service in "%s"' % name[:80])
    resolved = True
    if port.isdigit() and port.isascii():
        port_key: Any = int(port)
    elif services is not None and port in services:
        port_key = int(services[port])
    else:
        port_key, resolved = port, False
    if host == '':
        host_key: Any = ''
    else:
        try:
            host_key = ipaddress.ip_address(host).compressed
        except ValueError:
            host_key, resolved = host.lower(), False
    return host_key, port_key, resolved


def _getopt(args: list[str], optstring: str) -> tuple[list[tuple[str, str | None]], list[str], str | None]:
    """POSIX ``getopt`` with a leading ``+``: stop at the first non-option. Returns opts, rest, error."""
    takes = {c for i, c in enumerate(optstring) if c != ':' and optstring[i + 1:i + 2] == ':'}
    known = {c for c in optstring if c != ':'}
    opts: list[tuple[str, str | None]] = []
    i = 1
    while i < len(args):
        arg = args[i]
        if arg == '--':
            return opts, args[i + 1:], None
        if not arg.startswith('-') or arg == '-':
            return opts, args[i:], None
        j = 1
        while j < len(arg):
            c = arg[j]
            if c not in known:
                return opts, [], 'invalid option: %s' % c
            if c in takes:
                if j + 1 < len(arg):
                    opts.append((c, arg[j + 1:]))
                elif i + 1 < len(args):
                    i += 1
                    opts.append((c, args[i]))
                else:
                    return opts, [], 'invalid option: %s' % c
                break
            opts.append((c, None))
            j += 1
        i += 1
    return opts, [], None


def _atoi(value: str) -> int:
    match = re.match(r'[ \t\n\v\f\r]*([+-]?)([0-9]*)', value)
    digits = match.group(2)[:12] or '0'
    return -int(digits) if match.group(1) == '-' else int(digits)


def _macros(argv: list[str]) -> list[str]:
    found: list[str] = []
    for word in argv:
        for match in _MACRO.finditer(word):
            name = next(g for g in match.groups() if g)
            if name not in found:
                found.append(name)
    return found


def _daemon(kind: str, args: list[str], mail_owner: str | None) -> dict[str, Any]:
    opts, rest, error = _getopt(args, SINGLE_SERVER_OPTS)
    out: dict[str, Any] = {'daemon': kind, 'status': 'runs', 'detail': '', 'user': None, 'group': None,
                           'argv': None, 'command_line': None, 'command_sha256': None, 'macros': [],
                           'attributes': {}}
    if error is None:
        for c, value in opts:
            if c == 'o' and (value is None or '=' not in value or not value.split('=', 1)[0].strip(' \t\r\n')):
                error = 'invalid "-o %s" option value' % (value or '')[:80]
                break
            if c in 'rs' and _atoi(value or '') <= 0:
                error = 'invalid -%s value: %s' % (c, (value or '')[:80])
                break
    allowed = PIPE_ATTRS if kind == 'pipe' else SPAWN_ATTRS
    if error is None:
        user = group = None
        argv = None
        for index, word in enumerate(rest):
            key = word.split('=', 1)[0].lower() if '=' in word else None
            if key not in allowed:
                error = 'unknown attribute name: %s' % word[:80]
                break
            value = word[len(key) + 1:]
            if key == 'argv':
                argv = [value] + rest[index + 1:]
                break
            if key == 'user':
                user, _, grp = value.partition(':')
                group = grp or None
            elif key == 'flags':
                bad = [ch for ch in value if ch not in PIPE_FLAGS]
                if bad:
                    error = 'unknown flag: %s' % bad[0]
                    break
            elif key == 'size' and not re.fullmatch('[0-9]*', value):
                error = 'bad size= value: %s' % value[:80]
                break
            out['attributes'][key] = value
        if error is None:
            if user is None:
                error = 'missing user= attribute'
            elif user == '':
                error = 'unknown username: (empty)'
            elif argv is None:
                error = 'missing argv= attribute'
            elif user == 'root':
                error = 'user= specifies root privileges'
            elif group == 'root':
                error = 'user= specifies privileged group root'
            elif mail_owner is not None and user == mail_owner:
                error = 'user= specifies the mail system owner %s' % mail_owner
        out['user'], out['group'] = user, group
        if error is None:
            out['argv'] = argv
            out['command_line'] = ' '.join(argv)
            out['command_sha256'] = hashlib.sha256('\0'.join(argv).encode('utf-8', 'surrogatepass')).hexdigest()
            out['macros'] = _macros(argv)
    if error is not None:
        out['status'] = 'daemon_refused'
        out['detail'] = error[:240]
    return out


def _result(path: str, status: str, gaps: list, services: list, detail: str = '',
            daemon_directory: str | None = None) -> dict[str, Any]:
    return {
        'contract': 'postfix-master', 'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS), 'path': path, 'status': status, 'detail': detail[:240],
        'complete': not any(g['blocking'] for g in gaps), 'origin': 'not_assessed',
        'daemon_directory': daemon_directory, 'services': services, 'gaps': gaps,
        'not_observed': list(NOT_OBSERVED),
    }


def _params(main_cf: Mapping[str, Any] | None, gaps: list) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    if main_cf is None:
        _gap(gaps, 'main_cf_not_observed', 'main.cf')
    for name in ('daemon_directory', *DEFAULTS):
        raw = None if main_cf is None else main_cf.get(name)
        if raw is None:
            raw = DEFAULTS.get(name)
        if raw is not None and '$' in str(raw):
            _gap(gaps, 'parameter_expansion_unresolved', name)
            raw = None
        values[name] = None if raw is None else str(raw).strip(' \t\r\n')
    if main_cf is not None and main_cf.get('daemon_directory') is None:
        _gap(gaps, 'parameter_invalid', 'daemon_directory', 'The build default is distribution-specific.')
    return values


def evaluate(*, master_cf: Any, main_cf: Mapping[str, Any] | None, path: str = DEFAULT_PATH,
             inet_services: Mapping[str, int] | None = None) -> dict[str, Any]:
    """Resolve which services master starts, and which pipe/spawn commands they run.

    ``master_cf`` is the captured file text (``None`` when unobserved). ``main_cf`` maps main.cf parameter
    names to their effective values as ``postconf`` prints them (``None`` when unobserved); a parameter that
    is absent from an observed mapping takes its Postfix default. ``inet_services`` maps symbolic TCP service
    names to ports, as captured from ``/etc/services``, and is only used to decide whether two inet entries
    name the same endpoint.
    """
    gaps: list[dict[str, Any]] = []
    text = _decode(path, master_cf, gaps)
    params = _params(main_cf, gaps)
    if text is None:
        return _result(path, 'unresolved', gaps, [], daemon_directory=params['daemon_directory'])
    daemon_dir = params['daemon_directory']
    disable_raw = params['master_service_disable']
    protocols = params['inet_protocols']
    inet_off = protocols is not None and not [t for t in re.split('[' + re.escape(LIST_DELIMS) + ']+',
                                                                  protocols) if t]
    patterns = _disable_patterns(disable_raw or '', inet_off)
    proc_limit = params['default_process_limit']
    if proc_limit is not None and not re.fullmatch('[0-9]+', proc_limit):
        _gap(gaps, 'parameter_invalid', 'default_process_limit', proc_limit[:80])
        proc_limit = None
    compat = params['compatibility_level']
    chroot_default: str | None = None
    if compat is not None:
        match = _COMPAT.match(compat)
        if match is None:
            _gap(gaps, 'parameter_invalid', 'compatibility_level', compat[:80])
        else:
            chroot_default = 'y' if int(match.group(1)) < 1 else 'n'
    entries: list[dict[str, Any]] = []
    try:
        for line_no, line in logical_lines(text):
            where = '%s:%d' % (path, line_no)
            tokens = _tokens(line)
            name = tokens[0]
            transport = _field(tokens, 1, 'transport type', None)
            if _disabled(patterns, name, transport):
                entries.append({'line': line_no, 'name': name, 'type': transport, 'disabled': True})
                continue
            if transport not in TRANSPORTS:
                raise ConfigError('%s: bad transport type: %s' % (where, transport[:80]))
            private = _bool(_field(tokens, 2, 'private', 'y'), 'private')
            resolved = True
            if transport == 'inet':
                if private:
                    raise ConfigError('%s: inet service cannot be private' % where)
                host, port, resolved = _inet_endpoint(name, inet_services)
                identity: tuple = ('inet', host, port)
            else:
                identity = (transport, ('private/' if private else 'public/') + name)
            unprivileged = _bool(_field(tokens, 3, 'unprivileged', 'y'), 'unprivileged')
            chroot_raw = tokens[4] if len(tokens) > 4 else None
            if chroot_raw == '-' and chroot_default is None:
                chroot: bool | None = None
                _gap(gaps, 'chroot_default_unresolved', where)
            else:
                chroot = _bool(_field(tokens, 4, 'chroot', chroot_default or 'n'), 'chroot')
            wake_raw = _field(tokens, 5, 'wakeup_time', '0')
            wakeup = _atoi_field(wake_raw, 'wakeup_time', 0, gaps, where)
            conditional = wakeup > 0 and wake_raw.endswith('?')
            if len(tokens) > 6 and tokens[6] == '-' and proc_limit is None:
                raise _Unresolved(where, 'default_process_limit')
            max_proc = _atoi_field(_field(tokens, 6, 'max_proc', proc_limit or '100'), 'max_proc', 0, gaps, where)
            command = _field(tokens, 7, 'command', None)
            rest = _rest_after_fields(line, 8)
            extra = _brace_tokens(rest)
            entries.append({
                'line': line_no, 'name': name, 'type': transport, 'disabled': False, 'identity': identity,
                'identity_resolved': resolved, 'private': private, 'unprivileged': unprivileged, 'chroot': chroot,
                'wakeup': wakeup, 'conditional_wakeup': conditional, 'max_proc': max_proc, 'command': command,
                'extra': extra,
            })
    except ConfigError as exc:
        return _result(path, 'config_error', gaps, [], detail=str(exc), daemon_directory=daemon_dir)
    except _Unresolved as exc:
        _gap(gaps, 'parameter_expansion_unresolved', exc.args[1], exc.args[0])
        return _result(path, 'unresolved', gaps, [], daemon_directory=daemon_dir)
    services = _effective(entries, gaps, daemon_dir, params['mail_owner'])
    if len(services) > MAX_SERVICES:
        _gap(gaps, 'services_over_limit', path)
        services = services[:MAX_SERVICES]
    return _result(path, 'loads' if services else 'no_services', gaps, services, daemon_directory=daemon_dir)


class _Unresolved(Exception):
    pass


def _rest_after_fields(line: str, count: int) -> str:
    i, n = 0, len(line)
    for _ in range(count):
        while i < n and line[i] in BLANKS:
            i += 1
        while i < n and line[i] not in BLANKS:
            i += 1
    return line[i + 1:] if i < n else ''


def _effective(entries: list[dict[str, Any]], gaps: list, daemon_dir: str | None,
               mail_owner: str | None) -> list[dict[str, Any]]:
    active = [e for e in entries if not e['disabled']]
    inet = [e for e in active if e['type'] == 'inet']
    for entry in inet:
        if entry['identity_resolved']:
            continue
        _, host, port = entry['identity']
        for other in inet:
            if other is entry or other['identity'] == entry['identity']:
                continue
            _, ohost, oport = other['identity']
            hosts_may_match = host == ohost or (host != '' and ohost != '' and (_is_name(host) or _is_name(ohost)))
            ports_may_match = port == oport or isinstance(port, str) or isinstance(oport, str)
            if hosts_may_match and ports_may_match:
                _gap(gaps, 'identity_unresolved', '%s/inet' % entry['name'],
                     'Line %d and line %d may name the same endpoint.' % (entry['line'], other['line']))
                break
    order: list[tuple] = []
    by_identity: dict[tuple, list[dict[str, Any]]] = {}
    for entry in active:
        key = entry['identity']
        if key not in by_identity:
            order.append(key)
            by_identity[key] = []
        by_identity[key].append(entry)
    out = []
    for key in order:
        chain = by_identity[key]
        entry = chain[-1]
        out.append(_service(entry, [e['line'] for e in chain[:-1]], daemon_dir, mail_owner))
    for entry in entries:
        if entry['disabled']:
            out.append({'line': entry['line'], 'name': entry['name'], 'type': entry['type'], 'starts': False,
                        'reason': 'master_service_disable', 'overridden_lines': []})
    return out


def _is_name(host: Any) -> bool:
    if not isinstance(host, str) or host == '':
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def _service(entry: dict[str, Any], overridden: list[int], daemon_dir: str | None,
             mail_owner: str | None) -> dict[str, Any]:
    command = entry['command']
    args = [command]
    if entry['max_proc'] == 1:
        args.append('-l')
    if entry['max_proc'] == 0:
        args.append('-z')
    if posixpath.basename(command) != entry['name']:
        args += ['-n', entry['name']]
    args += ['-t', entry['type']]
    if entry['unprivileged']:
        args.append('-u')
    if entry['chroot']:
        args.append('-c')
    local_only = entry['type'] in ('unix', 'unix-dgram', 'fifo')
    if entry['type'] == 'inet':
        host = entry['identity'][1]
        local_only = host != '' and not _is_name(host) and ipaddress.ip_address(host).is_loopback
    if not local_only and entry['max_proc'] > 1:
        args += ['-o', 'stress=']
    args += entry['extra']
    program = None if daemon_dir is None else daemon_dir + '/' + command
    service = {
        'line': entry['line'], 'name': entry['name'], 'type': entry['type'], 'starts': True, 'reason': '',
        'overridden_lines': overridden, 'private': entry['private'], 'unprivileged': entry['unprivileged'],
        'chroot': entry['chroot'], 'wakeup': entry['wakeup'], 'conditional_wakeup': entry['conditional_wakeup'],
        'max_proc': entry['max_proc'], 'command': command, 'program': program,
        'program_normalized': None if program is None else posixpath.normpath(program),
        'outside_daemon_directory': None if program is None else not posixpath.normpath(program).startswith(
            posixpath.normpath(daemon_dir).rstrip('/') + '/'),
        'args': args,
        'starts_as': 'root',
        'privileges': 'drops_to_mail_owner' if entry['unprivileged'] else 'keeps_root',
        'program_sha256': None if program is None else hashlib.sha256(
            '\0'.join([program] + args[1:]).encode('utf-8', 'surrogatepass')).hexdigest(),
        'external_command': None,
    }
    base = posixpath.basename(command)
    if base in ('pipe', 'spawn'):
        service['external_command'] = _daemon(base, args, mail_owner)
        if entry['unprivileged'] and service['external_command']['status'] == 'runs':
            service['external_command']['detail'] = (
                'The service is unprivileged, so the daemon runs as the mail owner and is not expected to be '
                'able to switch to user=. The command is still reported.')
    return service
