"""Pure net-snmp snmpd program contract (roadmap F slice, #1327).

snmpd runs configured programs whenever an SNMP manager reads (or, for
writable entries, sets) the object identifiers they serve. This module turns
captured ``snmpd.conf``-style file text, read in snmpd's order, plus the
effective snmpd argv and captured ``/etc/passwd`` and ``/etc/group`` text into
the programs snmpd would run, with their argv or shell command and the user and
group they run as. It performs no I/O, never runs snmpd or a program and never
authorizes a response action.

The rules follow net-snmp 5.9.4 as packaged in Ubuntu 24.04
``net-snmp_5.9.4+dfsg-1.1ubuntu3.3``. That build includes ``agent/extend``,
``ucd-snmp/pass`` and ``ucd-snmp/pass_persist`` and does not build
``ucd-snmp/extensible``, so ``exec``, ``sh`` and ``execFix`` are handled by the
extend module:

- ``read_config`` reads whole lines (no length limit) and skips leading
  whitespace. A line whose first non-blank character is ``#`` is ignored.
  ``skip_white`` also returns "nothing" when the text after a word starts with
  ``#``, so a ``#`` that begins a later word ends the line there.
- Words are copied by ``copy_nword``: a leading ``"`` or ``'`` quotes up to
  the matching quote, a backslash copies the next byte literally, and a word
  is truncated to the destination buffer less one byte.
- Directive names match handlers case-insensitively (``strcasecmp``), but the
  handlers compare the line's own spelling case-sensitively (``strcmp``) when
  choosing shell or writable behaviour. ``EXTEND-SH`` therefore runs through
  ``execv``, not the shell. Trailing whitespace is removed before a handler
  runs. A directive with no value is reported and skipped.
- ``[snmpd]`` selects the agent's handlers. Any other bracketed type sends the
  line (or, alone on a line, the rest of the file) to other handlers.
- ``extend_parse_config`` takes optional ``-cacheTime N`` then
  ``-execType sh|exec``, an optional ``.``-prefixed root OID, the name and the
  command word. The rest of the line is kept verbatim as the arguments. ``exec``
  and ``sh`` with an OID are refused as deprecated. ``*Fix`` directives append
  ``Fix`` to the name and make the entry writable. A name already registered
  under the same root OID is refused, so the first entry wins.
- ``extend_load_cache`` joins ``command`` and the arguments with one space into
  a 512-byte buffer (511 bytes kept). Shell entries run that text with
  ``popen``, which is ``/bin/sh -c``. Others split it with
  ``tokenize_exec_command`` (``copy_nword`` words, at most 98, then the raw
  remainder as one more word) and ``execv`` the first word without a PATH
  search.
- ``pass`` and ``pass_persist`` accept ``-p PRIORITY`` options, then a numeric
  OID, then everything up to the first ``#`` or ``;`` as the command.
  ``pass`` runs ``<command> -g|-n|-s OID ...`` through ``run_exec_command``.
  ``pass_persist`` starts ``<command>`` once through ``parse_cmd``, which
  splits only at a space byte and then skips any whitespace.
- ``-u``/``-g`` on the command line set the run user and group, and later
  ``agentuser``/``agentgroup`` lines replace them. A uid or gid of 0 keeps
  root. Names are resolved from the captured account databases.
- ``-I`` lists select or exclude modules by name (``extend``, ``pass``,
  ``pass_persist``). The packaged unit passes
  ``-I -smux,mteTrigger,mteTriggerConf``.

Read order (``evaluate_snapshot``) follows ``read_config_files_of_type`` and
``read_config`` over a captured filesystem snapshot:

- Without ``SNMPCONFPATH`` snmpd searches ``/etc/snmp``, ``/usr/share/snmp``,
  ``/usr/lib/<multiarch>/snmp`` and, only when ``HOME`` is set,
  ``$HOME/.snmp``, then the persistent directory (``SNMP_PERSISTENT_DIR`` or
  ``/var/lib/snmp``). With ``SNMPCONFPATH`` it searches only that list. The
  list stops at its first empty element, and missing or non-directory entries
  are skipped.
- In each directory it reads ``<type>.conf`` then ``<type>.local.conf``. A
  directory whose name starts with the persistent directory (or
  ``SNMP_PERSISTENT_FILE``) first gets ``<type>.0.conf`` to ``<type>.10.conf``,
  stopping at the first missing one.
- The ``snmpd`` type is read, then the ``snmp`` type. snmpd handlers reached
  from an ``snmp`` file depend on the type registration order, which is not
  derived, so they are a blocking gap. So is ``persistentDir``, a premib token
  that moves the persistent directory.
- ``includeFile`` resolves a relative name against the including file's
  directory. ``includeDir`` reads its ``*.conf`` entries (not dot files) in
  readdir order, so more than one entry, or a relative directory (resolved
  against snmpd's working directory), is a blocking gap. ``includeSearch``
  searches the path for ``<name>`` with one ``.conf`` suffix removed. The
  target is the raw rest of the line, trailing blanks included. Included files
  start in the includer's permanent context and do not change it, and nesting
  deeper than 16 is refused.
- ``-c FILE[,FILE...]`` (the last one wins) reads absolute, existing files
  with the snmpd handlers after both types, or before them when the value
  starts with ``-``. A relative name resolves against snmpd's working
  directory, which is not observed, so it is a blocking gap. ``-C`` stays a
  gap.

Fail-closed rules: ``evaluate`` takes the order on trust, so it always carries
the blocking ``read_order_not_derived`` gap and treats includes as
``include_not_modelled``. In both modes, command-line configuration
(``-C``, ``-Y``, ``--token=value`` and, in ``evaluate``, ``-c``), unknown bracketed types,
paths the snapshot does not describe, an unobserved environment,
directives that load code (``dlmod``, ``perl``, ``procfix``), symbolic OIDs,
unobserved files and account databases, NUL bytes, invalid UTF-8 and
over-limit input are blocking gaps. ``origin`` is always ``not_assessed`` and
no result is a safety verdict.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSION = '5.9.4+dfsg-1.1ubuntu3.3'
SHELL = '/bin/sh'
STRINGMAX = 1024
STRMAX = 1024
EXTEND_COMMAND_BUFFER = 512
EXEC_MAX_TOKENS = 98
MAX_OID_LEN = 128
# Conservative bound: longer names may not fit the nsExtendTable index OID.
MAX_NAME_BYTES = 100
DEFAULT_ARGV = (
    '/usr/sbin/snmpd', '-LOw', '-u', 'Debian-snmp', '-g', 'Debian-snmp',
    '-I', '-smux,mteTrigger,mteTriggerConf', '-f',
)
MAX_TEXT = 262144
MAX_FILES = 64
MAX_ARGV = 128
MAX_GAPS = 64
MAX_LINE_NOTES = 512

EXTEND_TOKENS = ('extend', 'extend-sh', 'extendfix', 'exec2', 'sh2', 'execFix2', 'exec', 'sh', 'execFix')
SHELL_TOKENS = frozenset({'sh', 'extend-sh', 'sh2'})
FIX_TOKENS = frozenset({'execFix', 'extendfix', 'execFix2'})
CODE_LOADING_TOKENS = ('dlmod', 'perl', 'perlinitfile', 'procfix')
NS_EXTEND_OID = '.1.3.6.1.4.1.8072.1.3.2'
# Debian/Ubuntu configure paths (SNMPCONFPATH, SNMPSHAREPATH, SNMPLIBPATH for amd64,
# NETSNMP_PERSISTENT_DIRECTORY).
CONF_PATH = '/etc/snmp'
SHARE_PATH = '/usr/share/snmp'
LIB_PATH = '/usr/lib/x86_64-linux-gnu/snmp'
PERSISTENT_DIR = '/var/lib/snmp'
NETSNMP_MAX_PERSISTENT_BACKUPS = 10
MAX_PERSISTENT_BACKUPS = NETSNMP_MAX_PERSISTENT_BACKUPS
CONFIG_FILE_BUFFER = 300
MAX_INCLUDE_DEPTH = 16
SNMPD_OPTIONS = 'aAc:CdD::fhHI:l:L:m:M:n:p:P:qrsS:UvV-:Y:g:u:x:X'
BLOCKING = frozenset({
    'read_order_not_derived', 'file_not_observed', 'file_invalid', 'too_many_files', 'argv_invalid',
    'argv_config_not_modelled', 'include_not_modelled', 'context_unresolved', 'code_loading_directive',
    'oid_unresolved', 'account_unresolved', 'accounts_not_observed', 'name_unresolved', 'snmpd_crash',
    'path_not_observed', 'path_truncated', 'directory_not_listed', 'include_dir_relative', 'include_dir_order_unknown',
    'persistent_dir_directive', 'type_order_not_derived', 'environment_not_observed', 'optional_config_relative',
})

_C_SPACE = ' \t\n\v\f\r'
_DIGITS = frozenset('0123456789')


def _isdigit(text: str) -> bool:
    """C ``isdigit`` in the C locale, for every character of ``text``."""
    return bool(text) and all(ch in _DIGITS for ch in text)


def _skip_white(text: str) -> str | None:
    """``skip_white_const``: None at end of text or at a ``#``."""
    stripped = text.lstrip(_C_SPACE)
    if not stripped or stripped[0] == '#':
        return None
    return stripped


def copy_nword(text: str, size: int) -> tuple[str, str | None, bool]:
    """Emulate ``copy_nword_const``; returns (word, rest, truncated)."""
    out: list[str] = []
    room = size
    truncated = False
    index = 0
    length = len(text)

    def take(ch: str) -> None:
        nonlocal room, truncated
        if room > 0:
            out.append(ch)
            room -= 1
            if room == 0:
                out.pop()
                truncated = True
        else:
            truncated = True

    if text[:1] in ('"', "'"):
        quote = text[0]
        index = 1
        while index < length and text[index] != quote:
            if text[index] == '\\' and index + 1 < length:
                take(text[index + 1])
                index += 2
            else:
                take(text[index])
                index += 1
        if index < length:
            index += 1
    else:
        while index < length and text[index] not in _C_SPACE:
            if text[index] == '\\' and index + 1 < length:
                take(text[index + 1])
                index += 2
            else:
                take(text[index])
                index += 1
    return ''.join(out), _skip_white(text[index:]), truncated


def tokenize_exec_command(command: str) -> list[str]:
    """``tokenize_exec_command`` from ``utilities/execute.c``."""
    argv: list[str] = []
    rest: str | None = command
    while rest is not None and len(argv) + 2 < 100:
        word, rest, _ = copy_nword(rest, STRMAX)
        argv.append(word)
    if rest is not None:
        argv.append(rest)
    return argv


def parse_cmd(command: str) -> list[str]:
    """``parse_cmd`` from ``util_funcs.c`` (used to start pass_persist)."""
    argv: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(command):
        ch = command[index]
        if ch == ' ':
            argv.append(''.join(current))
            current = []
            following = _skip_white(command[index:])
            if following is None:
                return argv
            index = len(command) - len(following)
            continue
        current.append(ch)
        index += 1
    argv.append(''.join(current))
    return argv


def _numeric_oid(text: str) -> tuple[int, ...] | None:
    parts = text.split('.')
    if not parts or any(not _isdigit(part) for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _parse_accounts(text: str | None, kind: str) -> dict[str, tuple[int, int | None]] | None:
    if text is None:
        return None
    accounts: dict[str, tuple[int, int | None]] = {}
    for line in text.splitlines():
        fields = line.split(':')
        if len(fields) < 3 or not fields[0] or fields[0] in accounts:
            continue
        if not _isdigit(fields[2]):
            continue
        primary = int(fields[3]) if kind == 'passwd' and len(fields) > 3 and _isdigit(fields[3]) else None
        accounts[fields[0]] = (int(fields[2]), primary)
    return accounts


class _State:
    def __init__(self) -> None:
        self.gaps: list[dict[str, Any]] = []
        self.lines: list[dict[str, Any]] = []
        self.programs: list[dict[str, Any]] = []
        self.extend_names: dict[str, set[str]] = {}
        self.user_specs: list[tuple[str, str]] = []
        self.group_specs: list[tuple[str, str]] = []
        self.optional_config: str | None = None

    def gap(self, code: str, **detail: Any) -> None:
        if len(self.gaps) < MAX_GAPS:
            self.gaps.append({'code': code, 'blocking': code in BLOCKING, **detail})
        elif not any(item['code'] == 'gaps_truncated' for item in self.gaps):
            self.gaps.append({'code': 'gaps_truncated', 'blocking': True})

    def note(self, path: str, line: int, directive: str, status: str, reason: str | None = None) -> None:
        if len(self.lines) < MAX_LINE_NOTES:
            self.lines.append({'path': path, 'line': line, 'directive': directive, 'status': status, 'reason': reason})


def _parse_argv(argv: Sequence[str], state: _State) -> dict[str, Any]:
    """glibc ``getopt`` over snmpd's option string, with argument permutation."""
    takes: dict[str, str] = {}
    index = 0
    while index < len(SNMPD_OPTIONS):
        char = SNMPD_OPTIONS[index]
        colons = 0
        while index + 1 + colons < len(SNMPD_OPTIONS) and SNMPD_OPTIONS[index + 1 + colons] == ':':
            colons += 1
        takes[char] = ('none', 'required', 'optional')[colons]
        index += 1 + colons
    init: list[str] = []
    noinit: list[str] = []
    position = 1
    while position < len(argv):
        word = argv[position]
        position += 1
        if word == '--':
            break
        if not word.startswith('-') or word == '-':
            continue
        offset = 1
        while offset < len(word):
            char = word[offset]
            mode = takes.get(char)
            if mode is None:
                state.gap('argv_invalid', option=char)
                return {'init': init, 'noinit': noinit}
            value: str | None = None
            if mode == 'none':
                if char == 'C':
                    state.gap('argv_config_not_modelled', option=char)
                elif char in 'hHv':
                    state.gap('argv_invalid', option=char)
                offset += 1
                continue
            if offset + 1 < len(word):
                value = word[offset + 1:]
            elif mode == 'required':
                if position >= len(argv):
                    state.gap('argv_invalid', option=char)
                    return {'init': init, 'noinit': noinit}
                value = argv[position]
                position += 1
            offset = len(word)
            if char == 'I':
                target = noinit if value and value[0] in '-!' else init
                body = value[1:] if value and value[0] in '-!' else (value or '')
                target.extend(part for part in _strtok(body, ', :'))
            elif char == 'u':
                state.user_specs.append(('argv', value or ''))
            elif char == 'g':
                state.group_specs.append(('argv', value or ''))
            elif char == 'c':
                # netsnmp_ds_set_string: the last -c wins.
                state.optional_config = value or ''
            elif char in 'Y-':
                if char == '-' and (value or '').lower() in ('help', 'version'):
                    state.gap('argv_invalid', option='--' + (value or ''))
                    return {'init': init, 'noinit': noinit}
                state.gap('argv_config_not_modelled', option=char)
    return {'init': init, 'noinit': noinit}


def _strtok(text: str, separators: str) -> Iterable[str]:
    word = ''
    for ch in text:
        if ch in separators:
            if word:
                yield word
            word = ''
        else:
            word += ch
    if word:
        yield word


def _module_enabled(name: str, lists: Mapping[str, list[str]]) -> bool:
    if lists['init']:
        return name in lists['init']
    return name not in lists['noinit']


def _handler_for(token: str, modules: Mapping[str, bool]) -> str | None:
    lowered = token.lower()
    if modules['extend'] and lowered in {name.lower() for name in EXTEND_TOKENS}:
        return 'extend'
    if modules['pass'] and lowered == 'pass':
        return 'pass'
    if modules['pass_persist'] and lowered == 'pass_persist':
        return 'pass_persist'
    if lowered in ('agentuser', 'agentgroup'):
        return lowered
    if lowered in CODE_LOADING_TOKENS:
        return 'code_loading'
    return None


def _extend(token: str, value: str, path: str, line: int, state: _State) -> None:
    name, rest, _ = copy_nword(value, STRMAX)
    exec_type = 'exec'
    cache_time = None
    if name == '-cacheTime':
        seconds, rest, _ = copy_nword(rest or '', 32)
        digits = ''
        for ch in seconds.lstrip(_C_SPACE):
            if not (_isdigit(ch) or (not digits and ch in '+-')):
                break
            digits += ch
        try:
            cache_time = int(digits)
        except ValueError:
            cache_time = 0
        name, rest, _ = copy_nword(rest or '', STRMAX)
    if name == '-execType':
        kind, rest, _ = copy_nword(rest or '', 16)
        exec_type = 'shell' if kind == 'sh' else 'exec'
        name, rest, _ = copy_nword(rest or '', STRMAX)
    root = NS_EXTEND_OID
    if name.startswith('.'):
        oid = _numeric_oid(name[1:])
        if oid is None or len(oid) > MAX_OID_LEN - 2:
            state.note(path, line, token, 'unresolved', 'oid_unresolved')
            state.gap('oid_unresolved', path=path, line=line)
            return
        root = name
        name, rest, _ = copy_nword(rest or '', STRMAX)
        if token in ('sh', 'exec'):
            state.note(path, line, token, 'rejected', 'deprecated_oid_form')
            return
    command, rest, _ = copy_nword(rest or '', STRMAX)
    shell = token in SHELL_TOKENS or exec_type == 'shell'
    writable = token in FIX_TOKENS
    if writable:
        if len(name) + 3 >= STRMAX:
            state.note(path, line, token, 'rejected', 'name_too_long')
            return
        name += 'Fix'
    if len(name) > MAX_NAME_BYTES:
        state.note(path, line, token, 'unresolved', 'name_unresolved')
        state.gap('name_unresolved', path=path, line=line)
        return
    names = state.extend_names.setdefault(root, set())
    if name in names:
        state.note(path, line, token, 'rejected', 'duplicate_name')
        return
    names.add(name)
    joined = f'{command} {rest}' if rest is not None else command
    kept = joined[:EXTEND_COMMAND_BUFFER - 1]
    row: dict[str, Any] = {
        'module': 'extend', 'directive': token, 'path': path, 'line': line, 'name': name,
        'root_oid': root, 'writable': writable, 'cache_time': cache_time,
        'exec_type': 'shell' if shell else 'exec', 'command_truncated': kept != joined,
    }
    if shell:
        row['argv'] = [SHELL, '-c', kept]
    else:
        row['argv'] = tokenize_exec_command(kept)
        row['relative_program'] = not row['argv'][0].startswith('/')
    state.programs.append(row)
    state.note(path, line, token, 'runs')


def _pass(token: str, value: str, path: str, line: int, module: str, state: _State) -> None:
    rest: str | None = value
    priority = 127
    while rest is not None and rest.startswith('-'):
        rest = rest[1:]
        if not rest.startswith('p'):
            state.note(path, line, token, 'rejected', 'unknown_option')
            return
        rest = _skip_white(rest[1:])
        if rest is None:
            state.note(path, line, token, 'unresolved', 'snmpd_crash')
            state.gap('snmpd_crash', path=path, line=line)
            return
        if not _isdigit(rest[0]):
            state.note(path, line, token, 'rejected', 'priority_not_integer')
            return
        priority, used = _strtol0(rest)
        if priority is None:
            state.note(path, line, token, 'rejected', 'priority_overflow')
            return
        rest = _skip_white(rest[used:])
    if rest is None:
        state.note(path, line, token, 'unresolved', 'snmpd_crash')
        state.gap('snmpd_crash', path=path, line=line)
        return
    rest = rest.removeprefix('.')
    if not _isdigit(rest[:1]):
        state.note(path, line, token, 'rejected', 'oid_not_numeric')
        return
    end = 0
    while end < len(rest) and (_isdigit(rest[end]) or rest[end] == '.'):
        end += 1
    oid_text = rest[:end]
    remaining = _skip_white(rest[end:])
    if remaining is None:
        command = ''
    else:
        stop = len(remaining)
        for index, ch in enumerate(remaining):
            if ch in '#;':
                stop = index
                break
        command = remaining[:stop]
    name = command[:STRMAX - 1]
    row: dict[str, Any] = {
        'module': module, 'directive': token, 'path': path, 'line': line, 'oid': '.' + oid_text,
        'priority': priority, 'command': name, 'command_truncated': name != command,
    }
    if module == 'pass':
        row['argv_prefix'] = tokenize_exec_command(name)
        row['request_arguments'] = ['-g OID', '-n OID', '-s OID TYPE VALUE']
    else:
        row['argv'] = parse_cmd(name)
        row['protocol'] = 'persistent stdin/stdout PING/get/getnext/set'
    program = (row.get('argv_prefix') or row.get('argv') or [''])[0]
    row['relative_program'] = not program.startswith('/')
    if not command:
        row['empty_command'] = True
    state.programs.append(row)
    state.note(path, line, token, 'runs' if command else 'runs_empty_command')


def _strtol0(text: str) -> tuple[int | None, int]:
    """``strtol(text, &end, 0)`` for text starting with a digit."""
    if text[:2].lower() == '0x' and text[2:3] and text[2] in '0123456789abcdefABCDEF':
        end = 2
        while end < len(text) and text[end] in '0123456789abcdefABCDEF':
            end += 1
        value = int(text[2:end], 16)
    elif text.startswith('0'):
        end = 1
        while end < len(text) and text[end] in '01234567':
            end += 1
        value = int(text[:end], 8)
    else:
        end = 0
        while end < len(text) and _isdigit(text[end]):
            end += 1
        value = int(text[:end])
    if value >= 2**63 - 1:
        return None, end
    return value, end


def _resolve_identity(state: _State, passwd: Mapping[str, tuple[int, int | None]] | None,
                      groups: Mapping[str, tuple[int, int | None]] | None) -> dict[str, Any]:
    """Apply ``-u``/``-g`` then ``agentuser``/``agentgroup`` in order, as snmpd.c does."""
    uid: int | None = 0
    gid: int | None = 0
    for database, specs, table in (('passwd', state.user_specs, passwd), ('group', state.group_specs, groups)):
        value: int | None = 0
        for source, text in specs:
            if source == 'argv' and _isdigit(text):
                value = int(text)
            elif source == 'argv' and text == '':
                value = 0
            elif table is None:
                state.gap('accounts_not_observed', database=database)
                value = None
            elif text in table:
                value = table[text][0]
            elif source == 'argv':
                # snmpd prints "Bad user id" or "Bad group id" and exits.
                state.gap('account_unresolved', database=database, name=text, effect='snmpd_exits')
                value = None
            else:
                # config_perror keeps the earlier value.
                state.note('', 0, 'agentuser' if database == 'passwd' else 'agentgroup', 'rejected', 'account_not_found')
            if value is None:
                break
        if database == 'passwd':
            uid = value
        else:
            gid = value
    user = None
    if uid == 0:
        user = 'root'
    elif uid is not None and passwd is not None:
        user = next((name for name, (number, _) in passwd.items() if number == uid), None)
    group = None
    if gid == 0:
        group = 'root'
    elif gid is not None and groups is not None:
        group = next((name for name, (number, _) in groups.items() if number == gid), None)
    return {
        'user': user, 'uid': uid, 'group': group, 'gid': gid,
        # setgid() runs only for gid > 0, so a dropped user keeps gid 0 unless a group is set.
        'supplementary_groups': 'not_modelled' if uid else None,
    }


def _prepare(argv: Sequence[str] | None, state: _State) -> dict[str, bool]:
    if argv is None:
        state.gap('argv_invalid', reason='not_observed')
        argv = DEFAULT_ARGV
    if len(argv) > MAX_ARGV:
        state.gap('argv_invalid', reason='too_long')
        argv = list(argv[:MAX_ARGV])
    lists = _parse_argv(list(argv), state)
    return {name: _module_enabled(name, lists) for name in ('extend', 'pass', 'pass_persist')}


def _checked_text(path: str, text: Any, state: _State) -> str | None:
    if text is None:
        state.gap('file_not_observed', path=path)
        return None
    if isinstance(text, bytes):
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            state.gap('file_invalid', path=path, reason='invalid_utf8')
            return None
    if not isinstance(text, str) or len(text) > MAX_TEXT or '\0' in text:
        state.gap('file_invalid', path=path, reason='nul_or_oversized')
        return None
    return text


def _finish(state: _State, modules: Mapping[str, bool], digest: Any, passwd_text: str | None,
            group_text: str | None, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    _decode_rows(state)
    passwd = _parse_accounts(passwd_text, 'passwd')
    groups = _parse_accounts(group_text, 'group')
    identity = _resolve_identity(state, passwd, groups)
    for row in state.programs:
        row['run_user'] = identity['user']
        row['run_uid'] = identity['uid']
        row['run_group'] = identity['group']
        row['run_gid'] = identity['gid']
    blocking = [gap for gap in state.gaps if gap['blocking']]
    result = {
        'contract': 'snmpd_programs',
        'contract_version': CONTRACT_VERSION,
        'source_version': SOURCE_VERSION,
        'input_sha256': digest.hexdigest(),
        'complete': not blocking,
        'modules': modules,
        'run_identity': identity,
        'programs': state.programs,
        'lines': state.lines,
        'gaps': state.gaps,
        'origin': 'not_assessed',
        'authorizes_response': False,
    }
    if extra:
        result.update(extra)
    return result


def evaluate(config_files: Sequence[Mapping[str, Any]], *, argv: Sequence[str] | None = DEFAULT_ARGV,
             passwd_text: str | None = None, group_text: str | None = None) -> dict[str, Any]:
    """Return the programs snmpd runs for captured files read in ``config_files`` order.

    The caller asserts the order, so the result always carries the blocking
    ``read_order_not_derived`` gap. Use :func:`evaluate_snapshot` to derive it.
    """
    state = _State()
    state.gap('read_order_not_derived')
    modules = _prepare(argv, state)
    if state.optional_config is not None:
        state.gap('argv_config_not_modelled', option='c')
    digest = hashlib.sha256()
    if len(config_files) > MAX_FILES:
        state.gap('too_many_files', count=len(config_files))
    for entry in list(config_files)[:MAX_FILES]:
        path = str(entry.get('path') or '')
        digest.update(path.encode('utf-8', 'replace') + b'\0')
        text = _checked_text(path, entry.get('text'), state)
        if text is None:
            continue
        digest.update(text.encode('utf-8') + b'\0')
        _read_file(path, text, modules, state)
    return _finish(state, modules, digest, passwd_text, group_text)


def _normal_path(path: str) -> str:
    """Collapse repeated and trailing slashes; ``.``/``..`` and symlinks are not resolved."""
    while '//' in path:
        path = path.replace('//', '/')
    if len(path) > 1 and path.endswith('/'):
        path = path.rstrip('/') or '/'
    return path


class _Reader:
    """``read_config_files_of_type`` and ``read_config`` over a captured filesystem snapshot."""

    def __init__(self, snapshot: Mapping[str, Any], modules: Mapping[str, bool], state: _State,
                 environ: Mapping[str, str], lib_path: str) -> None:
        self.files = {_normal_path(str(k)): v for k, v in dict(snapshot.get('files') or {}).items()}
        self.dirs = {_normal_path(str(k)): v for k, v in dict(snapshot.get('directories') or {}).items()}
        self.absent = {_normal_path(str(k)) for k in snapshot.get('absent') or ()}
        self.modules = modules
        self.state = state
        self.digest = hashlib.sha256()
        self.read_count = 0
        self.order: list[dict[str, Any]] = []
        self.type_header = 'snmpd'
        home = environ.get('HOME')
        self.confpath = f'{CONF_PATH}:{SHARE_PATH}:{lib_path}' + ('' if home is None else f':{home}/.snmp')
        self.envconfpath = environ.get('SNMPCONFPATH')
        # getenv() returns an empty value as-is, so only an unset variable selects the default.
        persdir = environ.get('SNMP_PERSISTENT_DIR')
        self.perspath = PERSISTENT_DIR if persdir is None else persdir
        self.persfile = environ.get('SNMP_PERSISTENT_FILE')

    def kind(self, path: str) -> str | None:
        key = _normal_path(path)
        if key in self.files:
            return 'file'
        if key in self.dirs:
            return 'dir'
        if key in self.absent:
            return 'absent'
        # A path under a listed directory that the listing omits does not exist.
        parent, _, name = key.rpartition('/')
        listing = self.dirs.get(parent or '/')
        if listing is not None and name not in listing:
            return 'absent'
        return None

    def exists(self, path: str) -> bool | None:
        kind = self.kind(path)
        if kind is None:
            self.state.gap('path_not_observed', path=path)
            return None
        return kind != 'absent'

    def read_type(self, header: str, context: str, level: int = 0) -> None:
        """``read_config_files_of_type``: the configuration path, then the persistent directory."""
        perspath = self.perspath
        if self.envconfpath is None:
            self.read_in_path(self.confpath, header, context, perspath, level)
            self.read_in_path(self.perspath, header, context, perspath, level)
        else:
            self.read_in_path(self.envconfpath, header, context, perspath, level)

    def read_in_path(self, path: str, header: str, context: str, perspath: str, level: int) -> None:
        for directory in path.split(':'):
            if directory == '':
                # The C loop stops at the first empty element.
                break
            kind = self.kind(directory)
            if kind is None:
                self.state.gap('path_not_observed', path=directory)
                continue
            if kind != 'dir':
                continue
            if directory.startswith(perspath) or (self.persfile is not None and directory.startswith(self.persfile)):
                for number in range(MAX_PERSISTENT_BACKUPS + 1):
                    backup = f'{directory}/{header}.{number}.conf'
                    if self._truncated(backup):
                        break
                    if not self.exists(backup):
                        break
                    self.read(backup, context, level, 'persistent_backup')
            for suffix in ('.conf', '.local.conf'):
                candidate = f'{directory}/{header}{suffix}'
                if not self._truncated(candidate):
                    self.read(candidate, context, level, 'search_path')

    def _truncated(self, path: str) -> bool:
        if len(path.encode('utf-8', 'replace')) >= CONFIG_FILE_BUFFER:
            self.state.gap('path_truncated', path=path)
            return True
        return False

    def read(self, path: str, context: str, level: int, via: str) -> bool:
        """``read_config``; returns whether snmpd would open the file."""
        kind = self.kind(path)
        if kind is None:
            self.state.gap('file_not_observed', path=path)
            return False
        if kind == 'absent':
            return False
        if level > MAX_INCLUDE_DEPTH:
            self.state.note(path, 0, 'read_config', 'rejected', 'include_depth_exceeded')
            return False
        if self.read_count >= MAX_FILES:
            self.state.gap('too_many_files', path=path)
            return False
        self.read_count += 1
        self.order.append({'path': path, 'type': self.type_header, 'context': context, 'via': via, 'depth': level})
        self.digest.update(path.encode('utf-8', 'replace') + b'\0')
        if kind == 'dir':
            # fopen succeeds on a directory and fgets reads nothing.
            return True
        text = _checked_text(path, self.files.get(_normal_path(path)), self.state)
        if text is None:
            return True
        self.digest.update(text.encode('utf-8') + b'\0')
        _read_file(path, text, self.modules, self.state, context=context, reader=self, level=level + 1)
        return True

    def read_optional(self, value: str) -> None:
        """``read_configs_optional``: comma-separated files read with the snmpd handlers."""
        self.type_header = 'snmpd'
        for name in value.split(','):
            if not name:
                continue
            if not name.startswith('/'):
                # stat() and fopen() resolve a relative name against snmpd's working directory.
                self.state.gap('optional_config_relative', path=name)
                continue
            if self.exists(name):
                self.read(name, 'snmpd', 0, 'argv_c')

    def include(self, token: str, target: str, path: str, line: int, context: str, level: int) -> None:
        lowered = token.lower()
        if lowered == 'includefile':
            if target.startswith('/'):
                name = target
            else:
                cut = path.rfind('/')
                name = (path[:cut + 1] if cut >= 0 else '') + target
            opened = self.read(name, context, level, 'includeFile')
            self.state.note(path, line, token, 'included' if opened else 'rejected', None if opened else 'not_found')
        elif lowered == 'includedir':
            if not target.startswith('/'):
                # opendir() resolves a relative name against snmpd's working directory.
                self.state.note(path, line, token, 'unresolved', 'relative_include_dir')
                self.state.gap('include_dir_relative', path=path, line=line, target=target)
                return
            kind = self.kind(target)
            if kind is None:
                self.state.gap('path_not_observed', path=target)
                return
            if kind != 'dir':
                self.state.note(path, line, token, 'rejected', 'not_a_directory')
                return
            listing = self.dirs.get(_normal_path(target))
            if listing is None:
                self.state.gap('directory_not_listed', path=target)
                return
            names = [name for name in listing if not name.startswith('.') and len(name.encode('utf-8', 'replace')) > 5
                     and name.endswith('.conf')]
            if len(names) > 1:
                # readdir() order is filesystem-specific, and the first extend name wins.
                self.state.gap('include_dir_order_unknown', path=target, count=len(names))
            self.state.note(path, line, token, 'included')
            for name in names:
                self.read(f'{target}/{name}', context, level, 'includeDir')
        else:
            header = target[:-5] if len(target.encode('utf-8', 'replace')) > 5 and target.endswith('.conf') else target
            self.state.note(path, line, token, 'included')
            self.read_type(header, context, level)


def evaluate_snapshot(snapshot: Mapping[str, Any], *, argv: Sequence[str] | None = DEFAULT_ARGV,
                      environ: Mapping[str, str] | None = None, passwd_text: str | None = None,
                      group_text: str | None = None, lib_path: str = LIB_PATH) -> dict[str, Any]:
    """Derive snmpd's read order from a captured filesystem snapshot and return its programs.

    ``snapshot`` holds ``files`` (path to text, or None when the file exists
    but was not captured), ``directories`` (path to entry names in readdir
    order, or None when unlisted) and ``absent`` paths. A path the snapshot
    does not describe is a blocking gap. ``environ`` is snmpd's environment;
    when it is not observed the result is blocking and an empty environment
    is assumed.
    """
    state = _State()
    modules = _prepare(argv, state)
    if environ is None:
        state.gap('environment_not_observed')
        environ = {}
    reader = _Reader(snapshot, modules, state, environ, lib_path)
    optional = state.optional_config
    if optional is not None and optional.startswith('-'):
        # read_configs(): a leading '-' reads the -c files before the search path.
        reader.read_optional(optional[1:])
        optional = None
    reader.read_type('snmpd', 'snmpd')
    reader.type_header = 'snmp'
    reader.read_type('snmp', 'snmp')
    if optional is not None:
        reader.type_header = 'snmpd'
        reader.read_optional(optional)
    extra = {'read_order': reader.order, 'search_path': reader.envconfpath if reader.envconfpath is not None
             else reader.confpath, 'persistent_dir': reader.perspath}
    return _finish(state, modules, reader.digest, passwd_text, group_text, extra)


def _read_file(path: str, text: str, modules: Mapping[str, bool], state: _State, *, context: str = 'snmpd',
               reader: _Reader | None = None, level: int = 1) -> None:
    raw_lines = text.split('\n')
    for number, raw in enumerate(raw_lines, start=1):
        latin = raw.encode('utf-8').decode('latin-1')
        cptr = _skip_white(latin)
        if cptr is None:
            continue
        token, cptr, _ = copy_nword(cptr, STRINGMAX)
        line_context = context
        if token.startswith('['):
            if not token.endswith(']') or len(token) < 2:
                state.note(path, number, token, 'rejected', 'unmatched_bracket')
                continue
            kind = token[1:-1]
            if kind not in ('snmpd', 'snmp'):
                if cptr is None:
                    state.gap('context_unresolved', path=path, line=number, context=kind)
                    context = '?'
                state.note(path, number, token, 'ignored', 'other_context')
                continue
            if cptr is None:
                context = kind
                continue
            line_context = kind
            token, cptr, _ = copy_nword(cptr, STRINGMAX)
        elif token[:1] == 'i' and token[:7].lower() == 'include':
            if token.lower() == 'include':
                state.note(path, number, token, 'ignored', 'ambiguous_include')
                continue
            if token.lower() in ('includedir', 'includefile', 'includesearch'):
                if cptr is None:
                    state.note(path, number, token, 'rejected', 'no_value')
                elif context == '?':
                    state.note(path, number, token, 'unresolved', 'context_unresolved')
                elif reader is None:
                    state.note(path, number, token, 'unresolved', 'include_not_modelled')
                    state.gap('include_not_modelled', path=path, line=number, directive=token)
                else:
                    # The include target is the raw rest of the line, trailing blanks included.
                    target = cptr.encode('latin-1').decode('utf-8', 'replace')
                    reader.include(token, target, path, number, context, level)
                continue
        if line_context == '?':
            state.note(path, number, token, 'unresolved', 'context_unresolved')
            continue
        if line_context == 'snmp' and token.lower() == 'persistentdir':
            # A premib token: it moves the persistent directory before this pass reads it.
            state.note(path, number, token, 'unresolved', 'persistent_dir_directive')
            state.gap('persistent_dir_directive', path=path, line=number)
            continue
        if line_context != 'snmpd':
            state.note(path, number, token, 'ignored', 'other_context')
            continue
        if reader is not None and reader.type_header != 'snmpd' and _handler_for(token, modules) is not None:
            # Lines for snmpd handlers in another file type depend on the registration order of types.
            state.gap('type_order_not_derived', path=path, line=number)
        handler = _handler_for(token, modules)
        if handler is None:
            continue
        if cptr is None:
            state.note(path, number, token, 'rejected', 'no_value')
            continue
        value = cptr.rstrip(_C_SPACE)
        display = token.encode('latin-1').decode('utf-8', 'replace')
        if handler == 'extend':
            _extend(token, value, path, number, state)
        elif handler in ('pass', 'pass_persist'):
            _pass(token, value, path, number, handler, state)
        elif handler == 'agentuser':
            state.user_specs.append(('config', value))
            state.note(path, number, display, 'sets_user')
        elif handler == 'agentgroup':
            state.group_specs.append(('config', value))
            state.note(path, number, display, 'sets_group')
        else:
            state.note(path, number, display, 'unresolved', 'code_loading_directive')
            state.gap('code_loading_directive', path=path, line=number, directive=display)


def _decode_rows(state: _State) -> None:
    """Rows were parsed byte-wise (latin-1); return their text as UTF-8."""
    def fix(value: Any) -> Any:
        if isinstance(value, str):
            return value.encode('latin-1', 'replace').decode('utf-8', 'replace')
        if isinstance(value, list):
            return [fix(item) for item in value]
        return value

    for row in state.programs:
        for key in ('name', 'argv', 'argv_prefix', 'command', 'directive'):
            if key in row:
                row[key] = fix(row[key])
