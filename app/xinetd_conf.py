"""Pure xinetd configuration contract (roadmap F slice, issue #1122).

Given captured ``/etc/xinetd.conf`` text, the files it ``include``s and the
listings and files of its ``includedir`` directories, resolve which xinetd
services survive configuration loading and, for each, which program runs,
with which arguments and as which user.

The rules follow xinetd 2.3.15.4 as packaged by Ubuntu
(``xinetd_2.3.15.4-6build1``): ``parsesup.c`` (``next_line``,
``get_attr_op``, ``parse_line``, ``skip_entry``, ``line_has_only_1_char``),
``parse.c`` (``parse_conf_file``, ``find_next_entry``, ``parse_entry``,
``identify_attribute``), ``includedir.c`` (``handle_includedir``),
``parsers.c`` and ``confparse.c`` (``remove_disabled_services``,
``fix_server_argv``, ``check_entry``, ``service_attr_check``).

This module performs no I/O and authorizes nothing. Facts that need the
live host (``/etc/services``, ``/etc/protocols``, ``/etc/rpc``, passwd and
group lookups, whether ``server`` is executable, whether xinetd is installed
or running, Debian ``INETD_COMPAT``) are reported as required lookups or
``not_observed`` coverage gaps, never assumed.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

CONTRACT_VERSION = 1
MAIN_CONFIG = '/etc/xinetd.conf'
MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 512
MAX_INCLUDE_DEPTH = 16

# name -> a_nvalues from parse.c: >0 exact count, -1 any count, -2 any
# count with += / -= allowed (modifiable).
SERVICE_ATTRIBUTES: dict[str, int] = {
    'socket_type': 1, 'protocol': 1, 'wait': 1, 'user': 1, 'group': 1,
    'server': 1, 'server_args': -1, 'instances': 1, 'log_on_success': -2,
    'log_on_failure': -2, 'log_type': -1, 'only_from': -2, 'no_access': -2,
    'access_times': -1, 'type': -1, 'rpc_version': 1, 'rpc_number': 1,
    'id': 1, 'env': -2, 'port': 1, 'passenv': -2, 'flags': -1, 'nice': 1,
    'redirect': 2, 'banner': 1, 'bind': 1, 'interface': 1, 'per_source': 1,
    'groups': 1, 'banner_success': 1, 'banner_fail': 1, 'cps': 2,
    'disable': 1, 'max_load': 1, 'rlimit_as': 1, 'rlimit_cpu': 1,
    'rlimit_data': 1, 'rlimit_files': 1, 'rlimit_rss': 1, 'rlimit_stack': 1,
    'v6only': 1, 'deny_time': 1, 'umask': 1, 'libwrap': 1,
}
# 'interface' is an alias of 'bind' (same attribute id).
_ATTR_ID = {'interface': 'bind'}
DEFAULT_ATTRIBUTES: dict[str, int] = {
    'log_type': -2, 'log_on_success': -2, 'log_on_failure': -2,
    'disabled': -2, 'no_access': -2, 'only_from': -2, 'instances': 1,
    'passenv': -2, 'banner': 1, 'bind': 1, 'interface': 1, 'per_source': 1,
    'groups': 1, 'banner_success': 1, 'banner_fail': 1, 'cps': 2,
    'enabled': -2, 'max_load': 1, 'v6only': 1, 'umask': 1,
}
# Defaults attributes whose parsers cannot fail on their values: the
# enabled/disabled parsers only collect service ids. Every other defaults
# parser (instances, log_type, per_source, cps, umask, bind, banner, ...)
# can return FAILED, and a failing defaults parser makes parse_entry() log a
# fatal error and terminate xinetd. Those parsers are not evaluated here, so
# each one reached is a blocking gap rather than an assumed success.
_DEFAULTS_MODELLED = {'enabled', 'disabled'}
# Service attributes whose parsers this contract evaluates exactly. Any
# other recognised attribute can still fail its parser on the host (which
# disables the service), so its presence leaves the service unresolved.
_MODELLED = {
    'socket_type', 'wait', 'user', 'group', 'server', 'server_args', 'type',
    'id', 'disable', 'flags', 'port', 'protocol', 'redirect',
}
SOCKET_TYPES = {'stream', 'dgram', 'raw', 'seqpacket'}
SERVICE_TYPES = {'RPC', 'INTERNAL', 'UNLISTED', 'SPECIAL', 'TCPMUX', 'TCPMUXPLUS'}
SERVICE_FLAGS = {
    'REUSE', 'INTERCEPT', 'NORETRY', 'IDONLY', 'NAMEINARGS', 'NODELAY',
    'KEEPALIVE', 'NOLIBWRAP', 'SENSOR', 'IPv4', 'IPv6', 'LABELED',
}

NOT_OBSERVED = (
    'xinetd_installed_or_running',
    'xinetd_command_line_options_and_config_path',
    'debian_inetd_compat_and_etc_inetd_conf',
    'services_protocols_and_rpc_lookups',
    'passwd_and_group_lookups',
    'server_executable_access',
    'bind_address_resolution',
    'duplicate_port_protocol_bind_conflicts',
    'builtin_availability',
    'program_contents',
)


def _digits(value: str) -> bool:
    return bool(value) and value.isascii() and value.isdigit()


def _content_lines(text: str):
    """Yield (line_no, line) for lines next_line() returns.

    next_line() skips a line when, scanning from its start past
    whitespace, it reaches NUL or '#'. A '#' after other text is data.
    """
    for number, line in enumerate(text.split('\n'), start=1):
        stripped = line.lstrip(' \t\r\n\v\f')
        if not stripped or stripped.startswith('#'):
            continue
        yield number, line


def _only_char(line: str, ch: str) -> bool:
    """line_has_only_1_char(): exactly one ch and otherwise whitespace."""
    return line.strip(' \t\r\n\v\f') == ch


def _parse_attr_line(line: str):
    """get_attr_op() + parse_line(). Returns (name, op, values) or reason."""
    p = line.lstrip(' \t\r\n\v\f')
    index = 0
    while index < len(p) and not p[index].isspace() and p[index] != '=':
        index += 1
    if index >= len(p):
        return 'nothing_after_attribute'
    if p[index] == '=':
        return 'attribute_needs_space_before_operator'
    name, rest = p[:index], p[index + 1:].lstrip(' \t\r\n\v\f')
    if not rest:
        return 'nothing_after_attribute'
    if rest[0] == '=':
        op, rest = '=', rest[1:]
    elif rest[0] in '+-' and rest[1:2] == '=':
        op, rest = rest[0] + '=', rest[2:]
    else:
        return 'bad_operator'
    values = [part for part in rest.replace('\t', ' ').split(' ') if part]
    return name, op, values


class _Service:
    def __init__(self, name: str, path: str, line: int):
        self.name = name
        self.path = path
        self.line = line
        self.specified: dict[str, list[str]] = {}
        self.enabled = True
        self.reasons: list[str] = []
        self.ignored: list[dict[str, Any]] = []
        self.unmodelled: list[str] = []
        self.lookups: set[str] = set()
        self.types: set[str] = set()
        self.flags: set[str] = set()
        self.disabled_by_disable = False


class _Parser:
    def __init__(self, files, directories):
        self.files = files
        self.directories = directories
        self.services: list[_Service] = []
        self.defaults: dict[str, list[str]] = {}
        self.enabled_list: list[str] | None = None
        self.disabled_list: list[str] = []
        self.dropped: list[dict[str, Any]] = []
        self.gaps: list[dict[str, Any]] = []
        self.blocking = False
        self.read_order: list[str] = []
        self.fatal: str | None = None

    def gap(self, kind: str, blocking: bool = True, **extra):
        self.gaps.append({'kind': kind, 'blocking': blocking, **extra})
        if blocking:
            self.blocking = True

    def text_for(self, path: str):
        if path not in self.files:
            self.gap('file_not_observed', path=path)
            return None
        text = self.files[path]
        if text is None:
            self.gap('file_unreadable', path=path)
            return None
        if not isinstance(text, str) or '\x00' in text:
            self.gap('file_binary_or_invalid', path=path)
            return None
        if len(text.encode('utf-8', 'surrogatepass')) > MAX_FILE_BYTES:
            self.gap('file_over_limit', path=path)
            return None
        if len(self.read_order) >= MAX_FILES:
            self.gap('too_many_files', path=path)
            return None
        return text

    def parse_file(self, path: str, depth: int = 0):
        if self.fatal:
            return
        if depth > MAX_INCLUDE_DEPTH:
            # xinetd recurses without a guard; a cycle never terminates.
            self.gap('include_depth_exceeded', path=path)
            return
        text = self.text_for(path)
        if text is None:
            return
        self.read_order.append(path)
        lines = list(_content_lines(text))
        position = 0
        found_defaults = False

        def next_line():
            nonlocal position
            if position >= len(lines):
                return None
            item = lines[position]
            position += 1
            return item

        def skip_entry():
            while True:
                item = next_line()
                if item is None or _only_char(item[1], '}'):
                    return

        while not self.fatal:
            item = next_line()
            if item is None:
                return
            number, line = item
            tokens = [t for t in line.replace('\t', ' ').split(' ') if t]
            keyword = tokens[0].strip('\r\n\v\f') if tokens else ''
            if keyword in ('service', 'include', 'includedir'):
                if len(tokens) < 2:
                    self.dropped.append({'path': path, 'line': number,
                                         'reason': 'name_missing'})
                    skip_entry()
                    continue
                target = tokens[1]
                if keyword == 'include':
                    self.parse_file(target, depth + 1)
                    continue
                if keyword == 'includedir':
                    self.parse_dir(target, depth + 1)
                    continue
            elif keyword != 'defaults':
                self.dropped.append({'path': path, 'line': number,
                                     'reason': 'missing_service_keyword'})
                skip_entry()
                continue
            brace = next_line()
            if brace is None or not _only_char(brace[1], '{'):
                self.dropped.append({'path': path, 'line': number,
                                     'reason': 'missing_open_brace'})
                skip_entry()
                continue
            if keyword == 'defaults':
                if found_defaults:
                    self.dropped.append({'path': path, 'line': number,
                                         'reason': 'duplicate_defaults'})
                    skip_entry()
                    continue
                found_defaults = self.parse_defaults(next_line, path)
                continue
            service = _Service(tokens[1], path, number)
            if self.parse_service(service, next_line):
                self.services.append(service)
            else:
                skip_entry()
                self.dropped.append({
                    'path': path, 'line': number, 'service': service.name,
                    'reason': service.reasons[-1] if service.reasons else 'parse_failed',
                })

    def parse_dir(self, directory: str, depth: int):
        listing = self.directories.get(directory)
        if listing is None:
            self.gap('directory_not_observed', path=directory)
            return
        for name, kind in sorted(listing, key=lambda e: e[0].encode('utf-8', 'surrogatepass')):
            if not name or '.' in name or name.endswith('~'):
                continue
            path = directory.rstrip('/') + '/' + name
            if kind != 'file':
                self.dropped.append({'path': path, 'reason': 'not_regular_file'})
                continue
            self.parse_file(path, depth)

    def parse_defaults(self, next_line, path) -> bool:
        while True:
            item = next_line()
            if item is None:
                self.dropped.append({'path': path, 'reason': 'incomplete_defaults'})
                return False
            if _only_char(item[1], '}'):
                return True
            parsed = _parse_attr_line(item[1])
            if isinstance(parsed, str):
                # parse_entry FAILED: found_defaults stays false and the
                # remaining lines are read as new entries. That re-entry
                # path is not modelled exactly.
                self.gap('defaults_line_unparsed', path=path, line=item[0],
                         reason=parsed)
                return False
            name, op, values = parsed
            nvalues = DEFAULT_ATTRIBUTES.get(name)
            if nvalues is None:
                continue
            attr = _ATTR_ID.get(name, name)
            if nvalues != -2:
                if attr in self.defaults or op != '=':
                    continue
                if nvalues > 0 and len(values) != nvalues:
                    continue
                self.defaults_parser_not_evaluated(path, item[0], name)
                self.defaults[attr] = values
                continue
            if op == '-=':
                self.gap('defaults_subtraction_not_modelled', path=path,
                         line=item[0], attribute=name)
                continue
            if name not in _DEFAULTS_MODELLED:
                self.defaults_parser_not_evaluated(path, item[0], name)
            # In defaults '=' means '+=' for modifiable attributes.
            if name == 'enabled':
                self.enabled_list = (self.enabled_list or []) + values
            elif name == 'disabled':
                self.disabled_list += values
            self.defaults.setdefault(attr, []).extend(values)

    def defaults_parser_not_evaluated(self, path: str, line: int, name: str):
        # identify_attribute() returns FAILED for a failing defaults parser
        # (debug off) and parse_entry() then terminates xinetd, so an
        # unevaluated value could mean no service runs at all.
        self.gap('defaults_attribute_not_evaluated', path=path, line=line,
                 attribute=name)

    def parse_service(self, svc: _Service, next_line) -> bool:
        while True:
            item = next_line()
            if item is None:
                svc.reasons.append('incomplete_entry')
                return False
            number, line = item
            if _only_char(line, '}'):
                return True
            parsed = _parse_attr_line(line)
            if isinstance(parsed, str):
                svc.reasons.append(parsed)
                return False
            name, op, values = parsed
            self.identify(svc, number, name, op, values)
            # parse_entry(): as soon as a 'disable' line is seen while the
            # service is disabled (by that line or an earlier parser
            # failure), the entry is abandoned.
            if name == 'disable' and not svc.enabled:
                svc.reasons.append('disabled_at_disable_line')
                return False

    def identify(self, svc: _Service, number: int, name: str, op: str,
                 values: list[str]) -> None:
        """identify_attribute() for a service entry."""
        nvalues = SERVICE_ATTRIBUTES.get(name)
        if nvalues is None:
            svc.ignored.append({'line': number, 'attribute': name,
                                'reason': 'unknown_attribute'})
            return
        attr = _ATTR_ID.get(name, name)
        if nvalues != -2:
            if attr in svc.specified:
                svc.ignored.append({'line': number, 'attribute': name,
                                    'reason': 'already_set'})
                return
            if op != '=':
                svc.ignored.append({'line': number, 'attribute': name,
                                    'reason': 'operator_not_allowed'})
                return
        if nvalues > 0 and len(values) != nvalues:
            svc.ignored.append({'line': number, 'attribute': name,
                                'reason': 'wrong_value_count'})
            return
        if self.apply(svc, attr, values, op):
            if nvalues == -2:
                svc.specified.setdefault(attr, []).extend(values)
            else:
                svc.specified[attr] = values
        else:
            svc.enabled = False
            svc.reasons.append(f'attribute_parse_failed:{name}')

    def apply(self, svc: _Service, attr: str, values: list[str], op: str) -> bool:
        if attr not in _MODELLED:
            svc.unmodelled.append(attr)
            return True
        value = values[0] if values else ''
        if attr == 'disable':
            if value == 'yes':
                svc.enabled = False
                return True
            if value == 'no':
                svc.enabled = True
                return True
            return False
        if attr == 'wait':
            return value in ('yes', 'no')
        if attr == 'socket_type':
            return value in SOCKET_TYPES
        if attr == 'server_args':
            return bool(values)
        if attr == 'type':
            if not values or any(v not in SERVICE_TYPES for v in values):
                return False
            svc.types.update(values)
            return True
        if attr == 'flags':
            if any(v not in SERVICE_FLAGS for v in values):
                return False
            svc.flags.update(values)
            return True
        if attr == 'user':
            if not _digits(value):
                svc.lookups.add('passwd:' + value)
            return True
        if attr == 'group':
            if not _digits(value):
                svc.lookups.add('group:' + value)
            return True
        if attr == 'server':
            svc.lookups.add('executable:' + value)
            return True
        if attr == 'port':
            return _digits(value) and int(value) <= 65535
        if attr == 'protocol':
            svc.lookups.add('protocol:' + value)
            return True
        return True  # id, redirect


def _entry_checks(svc: _Service) -> list[str]:
    """check_entry()/fix_server_argv()/service_attr_check() rules that do
    not depend on host lookups."""
    spec = svc.specified
    internal = 'INTERNAL' in svc.types or 'SENSOR' in svc.flags
    unlisted = 'UNLISTED' in svc.types
    rpc = 'RPC' in svc.types
    mux = 'TCPMUX' in svc.types or 'TCPMUXPLUS' in svc.types
    nameinargs = 'NAMEINARGS' in svc.flags
    failures: list[str] = []
    if 'redirect' not in spec and not internal and 'server' not in spec:
        failures.append('server_missing')
    if not internal and nameinargs and 'server_args' not in spec:
        failures.append('nameinargs_without_server_args')
    # service_fill(): without a port, every non-TCPMUX, non-RPC service
    # (internal and redirected ones included) needs a port from
    # getservbyname(name, protocol); UNLISTED ones are rejected outright.
    if not mux and not rpc and 'port' not in spec:
        if unlisted:
            failures.append('unlisted_without_port')
        elif 'protocol' not in spec and 'socket_type' not in spec:
            failures.append('port_and_protocol_missing')
    if mux and not unlisted:
        failures.append('tcpmux_not_unlisted')
    if 'redirect' in spec:
        if spec.get('socket_type', [''])[0] != 'stream':
            failures.append('redirect_requires_stream')
        if spec.get('wait', [''])[0] == 'yes':
            failures.append('redirect_must_not_wait')
        if nameinargs:
            failures.append('redirect_with_nameinargs')
    if nameinargs and internal:
        failures.append('internal_with_nameinargs')
    if spec.get('socket_type', [''])[0] == 'dgram' and spec.get('wait', [''])[0] != 'yes':
        failures.append('dgram_without_wait')
    required = ['socket_type', 'wait']
    if not internal:
        required += ['user'] + ([] if 'redirect' in spec and not rpc else ['server'])
        if unlisted:
            required += ['protocol'] if mux else ['protocol', 'port']
    if rpc:
        required = [a for a in required if a != 'port'] + ['protocol', 'rpc_version']
        if unlisted:
            required.append('rpc_number')
    for attr in required:
        if attr not in spec:
            failures.append('missing_attribute:' + attr)
    return failures


def _report(svc: _Service, failures: list[str]) -> dict[str, Any]:
    spec = svc.specified
    internal = 'INTERNAL' in svc.types or 'SENSOR' in svc.flags
    user = spec.get('user', [None])[0]
    server = spec.get('server', [None])[0]
    if 'redirect' in spec:
        server = '/bin/true'
    args = spec.get('server_args', [])
    if internal or 'redirect' in spec:
        # Built-ins run inside xinetd; redirects forward the connection
        # and never exec the placeholder /bin/true server.
        argv = None
    elif 'NAMEINARGS' in svc.flags:
        argv = list(args)
    elif server is not None:
        argv = [server.rsplit('/', 1)[-1]] + list(args)
    else:
        argv = None
    lookups = set(svc.lookups)
    unlisted = 'UNLISTED' in svc.types
    if not unlisted and 'RPC' not in svc.types and 'TCPMUX' not in svc.types \
            and 'TCPMUXPLUS' not in svc.types:
        protocol = spec.get('protocol', [None])[0]
        lookups.add(f'services:{svc.name}/{protocol or "<from socket_type>"}')
    if 'RPC' in svc.types and not unlisted:
        lookups.add('rpc:' + svc.name)
    if failures:
        status = 'disabled'
    elif svc.unmodelled:
        status = 'unresolved'
    else:
        status = 'loads_if_lookups_succeed'
    return {
        'name': svc.name,
        'id': spec.get('id', [svc.name])[0],
        'path': svc.path,
        'line': svc.line,
        'status': status,
        'disabled_reasons': failures,
        'internal': internal,
        'builtin': (svc.name if internal and 'SENSOR' not in svc.flags
                    else ('sensor' if 'SENSOR' in svc.flags else None)),
        'server': server,
        'argv': argv,
        'redirect': spec.get('redirect'),
        'user': user,
        'group': spec.get('group', [None])[0],
        'runs_as_root': (True if user in ('root', '0')
                         else (None if user is not None and not _digits(user) else
                               (False if user is not None else None))),
        'socket_type': spec.get('socket_type', [None])[0],
        'protocol': spec.get('protocol', [None])[0],
        'port': spec.get('port', [None])[0],
        'wait': spec.get('wait', [None])[0],
        'types': sorted(svc.types),
        'flags': sorted(svc.flags),
        'bind': spec.get('bind', [None])[0],
        'only_from': spec.get('only_from'),
        'unmodelled_attributes': sorted(set(svc.unmodelled)),
        'ignored_attributes': svc.ignored,
        'required_lookups': sorted(lookups),
    }


def resolve_xinetd(
    files: Mapping[str, str | None],
    directories: Mapping[str, Sequence[tuple[str, str]]] | None = None,
    main_path: str = MAIN_CONFIG,
) -> dict[str, Any]:
    """Resolve xinetd services from captured configuration.

    ``files`` maps absolute paths to captured text (``None`` when the file
    exists but could not be read; absent when not observed).
    ``directories`` maps each observed ``includedir`` directory to its
    entries as ``(name, kind)`` pairs, ``kind`` being ``'file'`` for a
    regular file (after stat, so symlinks to files count) or anything else.
    """
    parser = _Parser(files, directories or {})
    parser.parse_file(main_path)

    services = []
    for svc in parser.services:
        sid = svc.specified.get('id', [svc.name])[0]
        # remove_disabled_services(): an 'enabled' list first disables every
        # service, then re-enables listed ids, overriding parser failures.
        if parser.enabled_list is not None:
            failures = [] if sid in parser.enabled_list else ['not_in_defaults_enabled']
        elif not svc.enabled:
            failures = [r for r in svc.reasons
                        if r.startswith('attribute_parse_failed')] or ['disabled']
        else:
            failures = []
        if not failures and sid in parser.disabled_list:
            failures.append('in_defaults_disabled')
        if not failures:
            failures = _entry_checks(svc)
        services.append(_report(svc, failures))

    complete = not parser.blocking
    loaded = [s for s in services if s['status'] != 'disabled']
    return {
        'contract': 'xinetd_conf',
        'contract_version': CONTRACT_VERSION,
        'complete': complete,
        'origin': 'not_assessed',
        'files_read': parser.read_order,
        'defaults': {
            'enabled': parser.enabled_list,
            'disabled': parser.disabled_list,
        },
        'services': services,
        'loaded_services': [s['name'] for s in loaded],
        'root_services': [s['name'] for s in loaded if s['runs_as_root'] is True],
        'dropped_entries': parser.dropped,
        'gaps': parser.gaps,
        'not_observed': list(NOT_OBSERVED),
    }
