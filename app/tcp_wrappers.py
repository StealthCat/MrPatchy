"""Pure TCP wrappers (libwrap) shell-command contract (roadmap F slice, #1390).

Takes captured, read-only observations of ``/etc/hosts.allow`` and
``/etc/hosts.deny`` and says which ``spawn``, ``twist`` and ``aclexec`` shell
commands a libwrap-linked daemon (``tcpd`` started from inetd or xinetd, or a
daemon linked against ``libwrap0``) would run on a matching connection. For each
command it gives the daemon and client lists, the identity it runs under, and
whether an earlier entry makes it unreachable.

Semantics follow ``tcp-wrappers_7.6.q.orig.tar.gz`` with the 35 patches of the
Debian/Ubuntu ``7.6.q-33`` source package. That package builds with
``-DPROCESS_OPTIONS -DACLEXEC`` (patch ``12_makefile_config``). The rules are:

* ``hosts_access()`` reads ``/etc/hosts.allow`` and then ``/etc/hosts.deny``. A
  missing file is empty. A file that exists but cannot be opened is an error.
* ``table_match()`` stops at the first entry whose daemon and client lists
  match. Later entries in that file are never read, whatever the entry's
  options do. A match in ``hosts.allow`` returns before ``hosts.deny`` is read,
  unless an ``aclexec`` command exits non-zero, which turns the match into "no
  match" and lets ``hosts.deny`` be consulted.
* ``xgets()`` joins backslash-newline continuations into one 2048-byte logical
  line. A logical line that does not fit, or that ends at end of file without a
  newline, is the "missing newline or line too long" error. It stops the rest
  of that file. In ``hosts.deny`` it denies the request.
* A line is a comment only when ``#`` is in column 0. Blank lines are skipped.
  An entry without ``:`` is skipped with a warning.
* ``split_at()`` splits the daemon, client and option fields at the first ``:``
  outside ``[...]``. List tokens are separated by ``, \\t\\r\\n``. ``ALL`` and
  ``EXCEPT`` are compared case-insensitively.
* ``process_options()`` runs the options in order. Fields are split at ``:``,
  ``\\:`` is a literal colon, and keywords are case-insensitive. An empty
  field, an unknown keyword, a missing or unexpected value, or a
  ``twist``/``allow``/``deny`` that is not last raises an error *at that
  option*. Options before it have already run, so an earlier ``spawn`` command
  has already executed.
* ``spawn`` forks ``/bin/sh -c <command>`` with stdin, stdout and stderr on
  ``/dev/null`` and waits for it. ``twist`` replaces the daemon process with
  ``/bin/sh -c <command>``, with the client socket as stdin, stdout and stderr.
  ``aclexec`` forks and waits, and a non-zero exit unmatches the entry. All
  three expand ``%a %A %c %d %h %H %n %N %p %r %R %s %u %%`` first.
  ``percent_x()`` replaces every character of an expansion outside
  ``[0-9A-Za-z!@%=+:,./_-]`` with ``_``. Any other ``%<char>`` expands to
  nothing.
* **Identity.** The Debian ``initgroups`` patch, taken from Red Hat, changed
  ``dry_run == 0 && setuid(...)`` into ``if (dry_run != 0) { setuid(...) }``.
  ``dry_run`` is non-zero only in ``tcpdchk`` and ``tcpdmatch``, so in a real
  daemon ``user`` and ``group`` change no identity. They still look the
  account up, and an unknown name aborts the remaining options. Every command
  therefore runs as the daemon process's own user, often root. ``user`` and
  ``group`` options before a command are reported as ``identity_options_ignored``.

An entry is reported as shadowed only when an earlier entry in the same file
has an unconditional daemon list and client list: each list contains ``ALL``
and no ``EXCEPT``. An unconditional ``hosts.allow`` entry shadows all of
``hosts.deny`` unless it, or any earlier ``hosts.allow`` entry, names
``aclexec`` (a failing ``aclexec`` unmatches the entry, and the process-wide
``aclexec_matched`` flag persists until a later ``aclexec`` succeeds).
Line lengths are counted in UTF-8 bytes, as ``fgets()`` does. Weaker patterns, such as ``*``, are
never treated as shadowing, so shadowing is never overclaimed.

It performs no I/O, never runs a command and never authorizes a response
action. File states that are not observed or not modelled, NUL bytes and
over-limit input become explicit gaps, and a result with any gap is not
``complete``.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
MAX_TEXT = 1 << 20
MAX_GAPS = 256
BUFLEN = 2048

HOSTS_ALLOW = '/etc/hosts.allow'
HOSTS_DENY = '/etc/hosts.deny'
FILE_STATES = ('absent', 'regular', 'unreadable', 'not_regular', 'unknown')

_SEP = ', \t\r\n'
_LINE_BLANK = ' \t\r\n'
_OPT_WS = ' \t\r\n'
_ISSPACE = ' \t\n\v\f\r'
_EXPANSIONS = frozenset('aAcdhHnNprRsu%')

# keyword -> (needs value, value optional, must be last, value expanded)
_OPTIONS = {
    'user': (True, False, False, False),
    'group': (True, False, False, False),
    'umask': (True, False, False, False),
    'linger': (True, False, False, False),
    'keepalive': (False, False, False, False),
    'aclexec': (True, False, False, True),
    'spawn': (True, False, False, True),
    'twist': (True, False, True, True),
    'rfc931': (False, True, False, False),
    'setenv': (True, False, False, True),
    'nice': (False, True, False, False),
    'severity': (True, False, False, False),
    'allow': (False, False, True, False),
    'deny': (False, False, True, False),
    'banners': (True, False, False, False),
}
_COMMANDS = ('spawn', 'twist', 'aclexec')
_RUNTIME_REFUSABLE = frozenset({'user', 'group', 'umask', 'linger', 'keepalive', 'nice',
                                'severity', 'setenv', 'rfc931', 'banners', 'aclexec'})
_COMMAND_EFFECT = {
    'spawn': 'forked_shell_waited_stdio_dev_null',
    'twist': 'replaces_daemon_with_shell_client_socket_stdio',
    'aclexec': 'forked_shell_waited_nonzero_exit_unmatches_entry',
}
NOT_MODELLED = (
    'which_daemons_link_libwrap',
    'per_request_daemon_and_client_matching',
    'netgroup_dns_and_ident_lookups',
    'runtime_account_and_option_value_lookups',
    'twist_refused_in_resident_process',
    'contents_of_the_commands_run',
)


class Invalid(ValueError):
    """Raised for observations that do not have the documented shape."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})


def _bytes(value: str) -> int:
    # fgets()/xgets() count bytes; text is the UTF-8 (surrogateescape) decoding of the file.
    return len(value.encode('utf-8', 'surrogateescape'))


def _logical_lines(text: str):
    """Yield ``(first_line, logical_line)``. ``logical_line`` is None on the xgets error."""
    physical: list[str] = []
    start = 0
    while start < len(text):
        end = text.find('\n', start)
        if end < 0:
            physical.append(text[start:])
            break
        physical.append(text[start:end + 1])
        start = end + 1
    lineno = 0
    index = 0
    while index < len(physical):
        kept = ''
        first = lineno + 1
        while index < len(physical):
            line = physical[index]
            index += 1
            if not line.endswith('\n') or _bytes(kept) + _bytes(line) > BUFLEN - 1:
                yield first, None
                return
            lineno += 1
            if len(line) >= 2 and line[-2] == '\\':
                kept += line[:-2]
                continue
            yield first, kept + line
            break
        else:
            if kept:
                yield first, None
            return


def _split_at(value: str, delimiter: str) -> tuple[str, str | None]:
    bracket = 0
    for position, char in enumerate(value):
        if char == '[':
            bracket += 1
        elif char == ']':
            bracket -= 1
        elif bracket == 0 and char == delimiter:
            return value[:position], value[position + 1:]
    return value, None


def _tokens(value: str) -> list[str]:
    out: list[str] = []
    word = ''
    for char in value:
        if char in _SEP:
            if word:
                out.append(word)
            word = ''
        else:
            word += char
    if word:
        out.append(word)
    return out


def _ascii_lower(value: str) -> str:
    # strcasecmp() in the C locale folds ASCII letters only.
    return ''.join(chr(ord(char) + 32) if 'A' <= char <= 'Z' else char for char in value)


def _unconditional(tokens: list[str]) -> bool:
    lower = [_ascii_lower(token) for token in tokens]
    return 'all' in lower and 'except' not in lower


def _fields(value: str) -> list[str]:
    fields: list[str] = []
    index = 0
    while index < len(value):
        field = ''
        while index < len(value):
            char = value[index]
            if char == ':':
                index += 1
                break
            if char == '\\' and index + 1 < len(value) and value[index + 1] == ':':
                index += 1
            field += value[index]
            index += 1
        fields.append(field)
    return fields


def _chop(value: str) -> str:
    return value.strip(_ISSPACE)


def _option(field: str) -> tuple[str, str | None]:
    current = _chop(field)
    cut = len(current)
    for position, char in enumerate(current):
        if char in '=' + _OPT_WS:
            cut = position
            break
    if cut == len(current):
        return current, None
    key, rest = current[:cut], current[cut:]
    if rest[0] != '=':
        rest = rest[1:].lstrip(_OPT_WS)
    if rest.startswith('='):
        rest = rest[1:].lstrip(_OPT_WS)
    return key, rest or None


def _expansions(value: str) -> tuple[list[str], list[str]]:
    used: list[str] = []
    unknown: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == '%' and index + 1 < len(value):
            letter = value[index + 1]
            target = used if letter in _EXPANSIONS else unknown
            if '%' + letter not in target:
                target.append('%' + letter)
            index += 2
        else:
            index += 1
    return used, unknown


def _options(text: str | None) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if text is None:
        return [], None
    fields = _fields(text)
    done: list[dict[str, Any]] = []
    for index, field in enumerate(fields):
        key, value = _option(field)
        name = _ascii_lower(key)
        spec = _OPTIONS.get(name)
        last = index == len(fields) - 1
        reason = None
        if not key:
            reason = 'missing_option_name'
        elif spec is None:
            reason = 'bad_option_name'
        elif value is None and spec[0]:
            reason = 'option_requires_value'
        elif value is not None and not (spec[0] or spec[1]):
            reason = 'option_requires_no_value'
        elif not last and spec[2]:
            reason = 'option_must_be_at_end'
        if reason:
            return done, {'index': index, 'option': key, 'reason': reason}
        if value is not None and spec[3]:
            value = _chop(value)
        done.append({'name': name, 'value': value})
    return done, None


def _file(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {'state': 'unknown'}
    if not isinstance(value, dict):
        raise Invalid(f'{name} must be an object')
    state = value.get('state')
    if state not in FILE_STATES:
        raise Invalid(f'{name}.state must be one of {FILE_STATES}')
    text = value.get('text')
    if state == 'regular':
        if not isinstance(text, str):
            raise Invalid(f'{name}.text must be a string for a regular file')
        if len(text) > MAX_TEXT:
            raise Invalid(f'{name}.text exceeds {MAX_TEXT} characters')
        try:
            text.encode('utf-8', 'surrogateescape')
        except UnicodeEncodeError as error:
            raise Invalid(f'{name}.text is not a surrogateescape decoding of file bytes') from error
    elif text is not None:
        raise Invalid(f'{name}.text is only allowed for a regular file')
    return {'state': state, 'text': text}


def _table(path: str, observed: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    table: dict[str, Any] = {'path': path, 'state': observed['state'], 'entries': [],
                             'skipped': [], 'error': None, 'unconditional': None}
    state = observed['state']
    if state == 'absent':
        return table
    if state == 'unreadable':
        table['error'] = {'code': 'cannot_open', 'line': None}
        return table
    if state in ('unknown', 'not_regular'):
        _gap(gaps, 'file_unobserved' if state == 'unknown' else 'file_not_modelled', path=path)
        table['modelled'] = False
        return table
    text = observed['text']
    if '\0' in text:
        _gap(gaps, 'nul_byte', path=path)
        table['modelled'] = False
        return table
    for line, logical in _logical_lines(text):
        if logical is None:
            table['error'] = {'code': 'missing_newline_or_line_too_long', 'line': line}
            break
        if logical[0] == '#' or not logical.strip(_LINE_BLANK):
            continue
        daemons_text, rest = _split_at(logical, ':')
        if rest is None:
            table['skipped'].append({'line': line, 'reason': 'missing_separator'})
            continue
        clients_text, options_text = _split_at(rest, ':')
        daemons, clients = _tokens(daemons_text), _tokens(clients_text)
        options, option_error = _options(options_text)
        entry = {
            'line': line,
            'daemons': daemons,
            'clients': clients,
            'unconditional': _unconditional(daemons) and _unconditional(clients),
            'options': options,
            'option_error': option_error,
            'names_aclexec': option_error is not None and _ascii_lower(option_error['option']) == 'aclexec'
            or any(item['name'] == 'aclexec' for item in options),
            'shadowed_by': None,
        }
        if table['unconditional'] is not None:
            entry['shadowed_by'] = {'path': path, 'line': table['unconditional']}
        elif entry['unconditional']:
            table['unconditional'] = line
        table['entries'].append(entry)
    return table


def _commands(table: dict[str, Any], deny_shadow: dict[str, Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in table['entries']:
        shadow = entry['shadowed_by'] or deny_shadow
        before: list[str] = []
        identity: list[dict[str, Any]] = []
        for option in entry['options']:
            name = option['name']
            if name in _COMMANDS:
                used, unknown = _expansions(option['value'])
                out.append({
                    'path': table['path'],
                    'line': entry['line'],
                    'option': name,
                    'command': option['value'],
                    'argv': ['/bin/sh', '-c', option['value']],
                    'effect': _COMMAND_EFFECT[name],
                    'expansions': used,
                    'unrecognized_expansions': unknown,
                    'daemons': entry['daemons'],
                    'clients': entry['clients'],
                    'matches_every_request': entry['unconditional'],
                    'runs_as': 'daemon_process_user',
                    'identity_options_ignored': list(identity),
                    'after_runtime_checks': list(before),
                    'reachable': shadow is None,
                    'shadowed_by': shadow,
                })
            if name in ('user', 'group'):
                identity.append({'option': name, 'value': option['value']})
            if name in _RUNTIME_REFUSABLE:
                before.append(name)
    return out


def resolve(observation: Any) -> dict[str, Any]:
    """Return the shell commands hosts.allow and hosts.deny make libwrap daemons run."""
    if not isinstance(observation, dict):
        raise Invalid('observation must be an object')
    unknown = set(observation) - {'hosts_allow', 'hosts_deny'}
    if unknown:
        raise Invalid(f'unknown observation keys: {sorted(unknown)}')
    gaps: list[dict[str, Any]] = []
    allow = _table(HOSTS_ALLOW, _file(observation.get('hosts_allow'), 'hosts_allow'), gaps)
    deny = _table(HOSTS_DENY, _file(observation.get('hosts_deny'), 'hosts_deny'), gaps)
    deny_shadow = None
    for entry in allow['entries']:
        # A failing aclexec on any matched allow entry turns the match into "no match", and
        # aclexec_matched is a process-wide flag only a successful aclexec clears. So any
        # aclexec up to and including the first catch-all keeps hosts.deny reachable.
        if entry['names_aclexec']:
            break
        if entry['unconditional']:
            deny_shadow = {'path': HOSTS_ALLOW, 'line': entry['line']}
            break
    commands = _commands(allow, None) + _commands(deny, deny_shadow)
    if deny_shadow is not None:
        deny['shadowed_by'] = deny_shadow
    for table in (allow, deny):
        table.setdefault('modelled', True)
        table.setdefault('shadowed_by', None)
    return {
        'contract_version': CONTRACT_VERSION,
        'complete': not gaps,
        'tables': [allow, deny],
        'commands': commands,
        'reachable_commands': sum(1 for item in commands if item['reachable']),
        'gaps': gaps,
        'not_modelled': list(NOT_MODELLED),
        'authorizes_response': False,
    }
