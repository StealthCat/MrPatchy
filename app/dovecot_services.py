"""Pure Dovecot service contract (roadmap F slice, #1620).

The Dovecot master process runs as root and starts the ``executable`` of
every ``service`` section, either at master start (``process_min_avail``
above zero) or when the first client connects to one of its listeners.

The service ``user`` does not make the master drop privileges before it
execs the program. The master passes the restriction settings in the
environment and applies them before exec only when the service sets
``drop_priv_before_exec = yes``. Otherwise every program is **exec'd as
root**, even when ``user = nobody`` is configured. Dovecot's own binaries
drop to the service user after they start, but a path under ``libexec_dir``
names a file, not verified provenance, so that later drop is reported as
``expected_drop_account`` and the verified ``program_account`` is unknown
(None). ``root_exec`` lists every enabled service exec'd as root, whatever
its expected later drop; ``unverified_program_accounts`` lists those whose
post-exec account is not verified. The ``script`` wrapper is a Dovecot
binary: it is expected to drop to the service user and then exec its
program with the client's arguments appended.

This module turns captured configuration text, captured ``!include`` glob
matches and captured ``/etc/passwd`` and ``/etc/group`` text into the
configured services whose executable differs from the package default. It
reports their argv, resolved program, wrapper, exec account, start timing,
protocol enablement and source file/line. It performs no I/O, never runs
Dovecot or a program and never authorizes a response action.

The rules follow Dovecot 2.3.21, checked against Ubuntu 24.04
``dovecot-core 1:2.3.21+dfsg1-2ubuntu6.5``. ``doveconf -n`` and ``-a``
confirmed the parser rules and defaults, and traced ``dovecot -F`` runs
confirmed the exec accounts:

- ``#`` outside quotes starts a comment anywhere on a line. Values may be
  double or single quoted, with ``\\`` escapes inside double quotes. A
  trailing ``\\`` joins the next line with one blank.
- ``name [arg] {`` opens a section, and nothing may follow the ``{``. ``}``
  closes it. Same-name ``service`` sections merge, and the last assignment
  wins.
- ``!include`` paths are relative to the including file's directory. A
  pattern that matches nothing is fatal; ``!include_try`` skips it.
- ``$protocols`` in ``protocols`` expands to its earlier value.
  ``$default_internal_user`` and ``$default_login_user`` in a service
  ``user`` resolve to those settings' final values (``dovecot`` and
  ``dovenull`` by default).
- A service whose ``protocol`` is set starts only when that protocol is in
  ``protocols`` (empty by default; Ubuntu's ``protocols.d`` files add to it).

Unobserved files or glob listings, ``<file`` values, malformed sections,
services inside filter sections, unknown accounts, NUL bytes and over-limit
input are blocking gaps, and ``complete`` is false whenever one is present.
``script-login`` post-login account switching is source-derived and not
traced. checkpassword passdb/userdb programs, ``quota_warning`` and sieve
extprograms are not assessed. ``origin`` is always ``not_assessed`` and
``authorizes_response`` is always false.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from collections.abc import Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSION = 'Dovecot 2.3.21 (Ubuntu 24.04 dovecot-core 1:2.3.21+dfsg1-2ubuntu6.5)'

DEFAULT_CONFIG = '/etc/dovecot/dovecot.conf'
MAX_TEXT = 1024 * 1024
MAX_FILES = 256
MAX_DEPTH = 16
MAX_SERVICES = 500
WRAPPERS = ('script', 'script-login')
GLOBAL_DEFAULTS = {
    'protocols': '',
    'default_internal_user': 'dovecot',
    'default_login_user': 'dovenull',
    'libexec_dir': '/usr/lib/dovecot',
}
# ``doveconf -a`` on dovecot-core 2.3.21: name -> (executable, user, drop_priv_before_exec, protocol).
BUILTIN_SERVICES: dict[str, tuple[str, str, bool, str]] = {
    'aggregator': ('aggregator', '$default_internal_user', False, ''),
    'anvil': ('anvil', '$default_internal_user', False, ''),
    'auth-worker': ('auth -w', '', False, ''),
    'auth': ('auth', '$default_internal_user', False, ''),
    'config': ('config', '', False, ''),
    'dict-async': ('dict', '$default_internal_user', False, ''),
    'dict': ('dict', '$default_internal_user', False, ''),
    'director': ('director', '$default_internal_user', False, ''),
    'dns-client': ('dns-client', '$default_internal_user', False, ''),
    'doveadm': ('doveadm-server', '', False, ''),
    'health-check': ('script -p health-check.sh', '$default_internal_user', True, ''),
    'imap-hibernate': ('imap-hibernate', '$default_internal_user', False, 'imap'),
    'imap-login': ('imap-login', '$default_login_user', False, 'imap'),
    'imap-urlauth-login': ('imap-urlauth-login', '$default_login_user', False, 'imap'),
    'imap-urlauth-worker': ('imap-urlauth-worker', '', False, 'imap'),
    'imap-urlauth': ('imap-urlauth', '$default_internal_user', False, 'imap'),
    'imap': ('imap', '', False, 'imap'),
    'indexer-worker': ('indexer-worker', '', False, ''),
    'indexer': ('indexer', '$default_internal_user', False, ''),
    'ipc': ('ipc', '$default_internal_user', False, ''),
    'lmtp': ('lmtp', '', False, 'lmtp'),
    'log': ('log', '', False, ''),
    'old-stats': ('old-stats', '$default_internal_user', False, ''),
    'pop3-login': ('pop3-login', '$default_login_user', False, 'pop3'),
    'pop3': ('pop3', '', False, 'pop3'),
    'replicator': ('replicator', '', False, ''),
    'stats': ('stats', '$default_internal_user', False, ''),
    'submission-login': ('submission-login', '$default_login_user', False, 'submission'),
    'submission': ('submission', '', False, 'submission'),
    'tcpwrap': ('tcpwrap', '$default_internal_user', False, ''),
}
SERVICE_KEYS = ('executable', 'user', 'group', 'drop_priv_before_exec', 'process_min_avail', 'protocol', 'chroot')
_GLOB = re.compile(r'[*?\[]')
_SECTION = re.compile(r'([A-Za-z0-9_-]+)(?:\s+("(?:[^"\\]|\\.)*"|[^\s{]+))?\s*\{(.*)$')
_ASSIGN = re.compile(r'([A-Za-z0-9_/-]+)\s*=(.*)$')
_ACCOUNT_VARS = {'$default_internal_user': 'default_internal_user', '$default_login_user': 'default_login_user'}


class _Reject(Exception):
    pass


def _strip_comment(line: str) -> str:
    """Remove a ``#`` comment that is outside quotes."""
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == '\\' and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in '"\'':
            quote = c
        elif c == '#':
            return line[:i]
        i += 1
    return line


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        inner = value[1:-1]
        return re.sub(r'\\(.)', r'\1', inner) if value[0] == '"' else inner
    return value


class _Reader:
    def __init__(self, files: Mapping[str, str | bytes | None], globs: Mapping[str, Sequence[str] | None]):
        self.files, self.globs = files, globs
        self.gaps: list[dict[str, Any]] = []
        self.read: list[dict[str, Any]] = []
        self.settings: dict[str, str] = dict(GLOBAL_DEFAULTS)
        self.services: dict[str, dict[str, Any]] = {}
        self.stack: list[tuple[str, str | None, str, int]] = []
        self.count = 0
        self.rejected = False

    def gap(self, code: str, *, blocking: bool = True, **detail: Any) -> None:
        self.gaps.append({'code': code, 'blocking': blocking, **detail})

    def reject(self, code: str, **detail: Any) -> None:
        self.gap(code, **detail)
        self.rejected = True
        raise _Reject(code)

    def text(self, path: str) -> str | None:
        raw = self.files.get(path)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            if b'\x00' in raw:
                self.reject('nul_byte', path=path)
            raw = raw.decode('utf-8', 'replace')
        if '\x00' in raw:
            self.reject('nul_byte', path=path)
        if len(raw) > MAX_TEXT:
            self.reject('input_over_limit', path=path, limit=MAX_TEXT)
        return raw

    def include(self, pattern: str, base: str, optional: bool, source: str, line: int, depth: int) -> None:
        path = posixpath.normpath(posixpath.join(base, pattern))
        if _GLOB.search(path):
            if path not in self.globs or self.globs[path] is None:
                self.reject('unobserved_glob', glob=path, source=source, line=line)
            matches = sorted(posixpath.normpath(p) for p in self.globs[path])
        else:
            if path not in self.files:
                self.reject('unobserved_file', path=path, source=source, line=line)
            matches = [] if self.files[path] is None else [path]
        if not matches:
            if optional:
                return
            # config-parser: "No matches" is fatal for !include.
            self.reject('include_not_found', path=path, source=source, line=line)
        for match in matches:
            if match not in self.files:
                self.reject('unobserved_file', path=match, source=source, line=line)
            self.read.append({'path': match, 'included_from': source, 'line': line})
            self.source(match, depth + 1)

    def source(self, path: str, depth: int) -> None:
        self.count += 1
        if self.count > MAX_FILES or depth > MAX_DEPTH:
            self.reject('input_over_limit', path=path, limit=MAX_FILES if depth <= MAX_DEPTH else MAX_DEPTH)
        text = self.text(path)
        if text is None:
            self.reject('include_not_found', path=path)
        start_depth = len(self.stack)
        pending, first = '', 0
        for number, raw in enumerate(text.splitlines(), 1):
            # doveconf removes a line's comment before it looks for a trailing backslash.
            line = _strip_comment(raw.strip()).strip()
            if not line:
                # Native doveconf 2.3.21 skips empty and comment-only lines and discards a pending
                # backslash continuation: the continued setting is never assigned.
                pending = ''
                continue
            if not pending:
                first = number
            if line.endswith('\\'):
                pending += line[:-1].rstrip() + ' '
                continue
            line = (pending + line).strip()
            pending = ''
            self.statement(line, path, first, depth)
        if pending:
            self.statement(pending.strip(), path, first, depth)
        if len(self.stack) != start_depth:
            name, _, src, at = self.stack[-1]
            self.reject('unterminated_section', section=name, source=src, line=at)

    def statement(self, line: str, path: str, number: int, depth: int) -> None:
        if not line:
            return
        if line.startswith('!include'):
            word, _, rest = line.partition(' ')
            if word not in ('!include', '!include_try') or not rest.strip():
                self.reject('parse_error', source=path, line=number)
            self.include(_unquote(rest), posixpath.dirname(path), word == '!include_try', path, number, depth)
            return
        if line == '}':
            if not self.stack:
                self.reject('parse_error', source=path, line=number, detail="unexpected '}'")
            self.stack.pop()
            return
        match = _ASSIGN.match(line)
        if match and not match.group(2).rstrip().endswith('{'):
            self.assign(match.group(1), match.group(2).strip(), path, number)
            return
        match = _SECTION.match(line)
        if not match or match.group(3).strip():
            self.reject('parse_error', source=path, line=number)
        kind, name = match.group(1), match.group(2)
        name = _unquote(name) if name is not None else None
        if kind == 'service':
            if self.stack:
                self.reject('service_in_filter', service=name, source=path, line=number)
            if not name:
                self.reject('service_missing_name', source=path, line=number)
            if name not in self.services:
                if len(self.services) >= MAX_SERVICES:
                    self.reject('input_over_limit', limit=MAX_SERVICES)
                self.services[name] = {'sections': [], 'values': {}}
            self.services[name]['sections'].append({'source': path, 'line': number})
        self.stack.append((kind, name, path, number))

    def assign(self, key: str, value: str, path: str, number: int) -> None:
        if value.startswith('<'):
            self.gap('file_value_not_assessed', key=key, source=path, line=number)
            return
        value = _unquote(value)
        if not self.stack:
            if key == 'protocols':
                value = value.replace('$protocols', self.settings['protocols'])
            self.settings[key] = value
            return
        kind, name, _, _ = self.stack[-1]
        if len(self.stack) == 1 and kind == 'service' and key in SERVICE_KEYS:
            self.services[name]['values'][key] = {'value': value, 'source': path, 'line': number}


def _accounts(text: str | None, *, users: bool) -> dict[str, tuple[int, int]] | None:
    if text is None:
        return None
    table: dict[str, tuple[int, int]] = {}
    for raw in text.splitlines():
        parts = raw.split(':')
        if len(parts) >= (7 if users else 4) and parts[2].isdigit() and parts[0] not in table:
            table[parts[0]] = (int(parts[2]), int(parts[3]) if users and parts[3].isdigit() else int(parts[2]))
    return table


def _yes(value: str) -> bool:
    return value.strip().lower() in ('yes', 'y', '1', 'true')


def _fingerprint(rows: list[dict[str, Any]]) -> str:
    material = [{k: row[k] for k in ('service', 'argv', 'exec_account', 'program_account',
                                  'program_account_basis', 'expected_drop_account', 'enabled', 'starts')}
                for row in rows]
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def _service_row(name: str, entry: dict[str, Any], reader: _Reader,
                 passwd: dict[str, tuple[int, int]] | None,
                 groups: dict[str, tuple[int, int]] | None) -> dict[str, Any] | None:
    default = BUILTIN_SERVICES.get(name)
    values = entry['values']

    def value(key: str, fallback: str) -> str:
        return values[key]['value'] if key in values else fallback

    executable = value('executable', default[0] if default else '')
    builtin_unchanged = default is not None and executable == default[0]
    if builtin_unchanged or not executable.strip():
        if not executable.strip():
            reader.gap('missing_executable', blocking=False, service=name)
        return None
    user = value('user', default[1] if default else '')
    drop_priv = _yes(value('drop_priv_before_exec', 'yes' if default and default[2] else 'no'))
    protocol = value('protocol', default[3] if default else '')
    try:
        min_avail = int(value('process_min_avail', '0'))
    except ValueError:
        reader.gap('unrecognized_number', service=name, key='process_min_avail')
        min_avail = 0
    account_name = reader.settings.get(_ACCOUNT_VARS[user], '') if user in _ACCOUNT_VARS else user
    account_name = account_name or 'root'
    uid = gid = None
    if passwd is None:
        reader.gap('passwd_not_captured')
    elif account_name not in passwd:
        reader.gap('unknown_user', service=name, user=account_name)
    else:
        uid, gid = passwd[account_name]
    group = value('group', '')
    if group:
        if groups is None:
            reader.gap('group_not_captured')
        elif group not in groups:
            reader.gap('unknown_group', service=name, group=group)
        else:
            gid = groups[group][0]
    argv = executable.split()
    libexec = reader.settings['libexec_dir']
    program = argv[0] if argv[0].startswith('/') else posixpath.join(libexec, argv[0])
    wrapper = posixpath.basename(argv[0]) if posixpath.dirname(program) == libexec and \
        posixpath.basename(argv[0]) in WRAPPERS else None
    dovecot_binary = posixpath.dirname(program) == libexec
    service_account = {'account': account_name, 'uid': uid, 'gid': gid}
    root = {'account': 'root', 'uid': 0, 'gid': 0}
    target: dict[str, Any] | None = None
    expected: dict[str, Any] | None = None
    if drop_priv:
        # The master applies the restriction settings before exec, so the program starts as this account.
        exec_account, basis = service_account, 'drop_priv_before_exec'
        program_account, program_basis = service_account, 'restricted_before_exec'
    else:
        # The master execs as root. Any later drop is the program's own behaviour, which the
        # captured configuration does not verify: the path names a file, not its provenance.
        exec_account = root
        program_account, program_basis = None, 'post_exec_drop_unverified'
        if dovecot_binary:
            basis = 'dovecot_binary_path_not_dropped_before_exec'
            expected = service_account
        else:
            basis = 'not_dropped_before_exec'
            if account_name != 'root':
                reader.gap('service_user_not_applied', blocking=False, service=name, user=account_name,
                           detail='a non-Dovecot executable runs as root unless drop_priv_before_exec = yes')
        if account_name != 'root':
            reader.gap('post_exec_account_unverified', blocking=False, service=name, exec_account='root',
                       expected_account=account_name if dovecot_binary else None)
    if wrapper:
        args = argv[1:]
        while args and args[0].startswith('-'):
            args = args[1:]
        if not args:
            reader.gap('wrapper_without_program', service=name)
            target = None
        else:
            target = {'program': args[0], 'argv': args, 'appends_client_arguments': True}
            if not args[0].startswith('/'):
                reader.gap('relative_wrapper_program', blocking=False, service=name, program=args[0])
        if wrapper == 'script-login':
            expected = {'account': 'authenticated_mail_user', 'uid': None, 'gid': None}
            program_account, program_basis = None, 'post_login_switch_unverified'
            reader.gap('script_login_account_not_traced', blocking=False, service=name)
    protocols = reader.settings['protocols'].split()
    enabled = not protocol or protocol in protocols
    source = values.get('executable') or entry['sections'][0]
    return {
        'service': name,
        'builtin': default is not None,
        'executable': executable,
        'argv': argv,
        'program': program,
        'wrapper': wrapper,
        'wrapped': target,
        'exec_account': exec_account['account'],
        'exec_uid': exec_account['uid'],
        'exec_gid': exec_account['gid'],
        'exec_account_basis': basis,
        'program_account': program_account['account'] if program_account else None,
        'program_uid': program_account['uid'] if program_account else None,
        'program_account_basis': program_basis,
        'expected_drop_account': expected['account'] if expected else None,
        'service_user': account_name,
        'drop_priv_before_exec': drop_priv,
        'chroot': value('chroot', '') or None,
        'protocol': protocol or None,
        'enabled': enabled,
        'starts': 'master_start' if min_avail > 0 else 'on_demand',
        'process_min_avail': min_avail,
        'source': source['source'],
        'line': source['line'],
        'sections': entry['sections'],
    }


def evaluate(*, files: Mapping[str, str | bytes | None], globs: Mapping[str, Sequence[str] | None] | None = None,
             passwd_text: str | None = None, group_text: str | None = None,
             config_path: str = DEFAULT_CONFIG) -> dict[str, Any]:
    """Report the non-default service programs the Dovecot master starts for ``config_path``.

    ``files`` maps absolute paths to captured text, or None for a path observed
    to be absent. ``globs`` maps an absolute ``!include`` glob to the paths it
    matched (an empty list when it matched nothing).
    """
    config_path = posixpath.normpath(config_path)
    reader = _Reader(files, {posixpath.normpath(k): v for k, v in (globs or {}).items()})
    try:
        if config_path not in files:
            reader.reject('unobserved_file', path=config_path)
        reader.read.append({'path': config_path, 'included_from': None, 'line': None})
        reader.source(config_path, 0)
    except _Reject:
        pass
    passwd = _accounts(passwd_text, users=True)
    groups = _accounts(group_text, users=False)
    rows: list[dict[str, Any]] = []
    if not reader.rejected:
        for name in sorted(reader.services):
            row = _service_row(name, reader.services[name], reader, passwd, groups)
            if row is not None:
                rows.append(row)
    seen: set[tuple[str, str]] = set()
    gaps = []
    for gap in reader.gaps:
        key = json.dumps(gap, sort_keys=True)
        if (gap['code'], key) not in seen:
            seen.add((gap['code'], key))
            gaps.append(gap)
    blocking = [gap for gap in gaps if gap['blocking']]
    return {
        'service_sha256': _fingerprint(rows),
        'contract': 'dovecot_services',
        'contract_version': CONTRACT_VERSION,
        'source_version': SOURCE_VERSION,
        'complete': not blocking,
        'config_path': config_path,
        'config_accepted': None if not reader.rejected else False,
        'protocols': reader.settings['protocols'].split(),
        'files': reader.read,
        'services': rows,
        'root_exec': [i for i, row in enumerate(rows) if row['enabled'] and row['exec_account'] == 'root'],
        'unverified_program_accounts': [i for i, row in enumerate(rows)
                                        if row['enabled'] and row['program_account'] is None],
        'gaps': gaps,
        'origin': 'not_assessed',
        'authorizes_response': False,
    }
