"""Pure sshd command contract (roadmap F slice, #1357).

OpenSSH ``sshd`` runs four kinds of configured command on login and
authentication events:

- ``AuthorizedKeysCommand`` on each public-key authentication attempt, as
  ``AuthorizedKeysCommandUser``;
- ``AuthorizedPrincipalsCommand`` on each certificate authentication attempt, as
  ``AuthorizedPrincipalsCommandUser``;
- ``ForceCommand`` for each session, as the authenticating user through their
  login shell;
- each ``Subsystem`` command when a client requests it, as the authenticating
  user through their login shell.

This module turns captured ``sshd_config`` text and captured ``Include`` glob
results into those commands. It performs no I/O, never runs sshd or a command
and never authorizes a response action.

The rules follow upstream OpenSSH ``servconf.c``, ``misc.c`` and
``auth2-pubkey.c`` at tags ``V_9_2_P1`` (Debian 12) and ``V_9_6_P1``
(Ubuntu 24.04):

- Trailing whitespace and form feeds are stripped. The keyword ends at
  whitespace, a quote or ``=``, and at most one ``=`` is skipped with the
  surrounding whitespace. Keywords are case-insensitive; a line whose keyword
  starts with ``#`` is a comment. A keyword with no argument or unbalanced
  quotes is a bad option, and any bad option stops sshd. Upstream also refuses
  an unknown keyword, but distribution patches add keywords, so an
  unrecognized keyword is skipped and reported as a non-blocking gap.
- Most options keep their first value. ``AuthorizedKeysCommand``,
  ``AuthorizedPrincipalsCommand`` and ``ForceCommand`` store the rest of the
  line after the keyword, unchanged. The two authentication commands must start
  with ``/`` or be ``none``, even inside an inactive ``Match`` block. In 9.2p1 an
  ``AuthorizedPrincipalsCommand`` is stored only while no
  ``AuthorizedKeysCommand`` has been stored; 9.6p1 fixed that.
- ``Subsystem`` is global-only in 9.2p1; a repeated name stops sshd. In 9.6p1
  it is allowed in ``Match`` blocks, a repeated name keeps the first command,
  and a matched block's subsystems replace or add to the global ones.
- ``Include`` patterns not starting with ``/`` or ``~`` are relative to
  ``/etc/ssh``. Each pattern's sorted glob matches are read in turn, at most 16
  levels deep, and the containing file's Match state is restored after each.
- At startup only ``Match all`` is active. A directive not allowed in ``Match``
  inside an inactive block stops sshd. For each connection, sshd re-reads only
  the ``Match`` blocks, and the first matching block that sets an option
  overrides the startup value. ``Match all`` always matches. A block inside an
  included file ends at the end of that file; an ``Include`` inside a block
  makes its blocks conditional on both.
- At run time the authentication commands are split like a shell would without
  expansion (``argv_split``), ``%`` tokens are expanded in arguments after the
  first, and the program path must be absolute. ``sshd.c`` refuses to start
  when a startup authentication command other than ``none`` has no command
  user; a command whose user is unset only for a Match block is skipped.
  ``ForceCommand none`` clears the setting.

``Match`` criteria are reported, never evaluated. Validation this module does not
model, such as address-list syntax, the values of other options or whether a
user exists, can only stop sshd or skip a command, so the result over-reports
rather than under-reports. Unobserved files or glob results, invalid UTF-8, NUL
bytes and over-limit input mark the result incomplete. ``origin`` is always
``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import hashlib
import posixpath
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('9.2p1', '9.6p1')
DEFAULT_PATH = '/etc/ssh/sshd_config'
SSHDIR = '/etc/ssh'
MAX_TEXT = 262144
MAX_FILES = 128
MAX_DEPTH = 16
MAX_ENTRIES = 512
WHITESPACE = ' \t\r\n'

BLOCKING = frozenset({
    'file_not_observed', 'glob_not_observed', 'over_limit', 'invalid_utf8', 'binary', 'files_over_limit',
    'entries_over_limit', 'relative_path', 'home_relative_include', 'unsupported_version',
})

NOT_OBSERVED = (
    'Whether sshd is installed and running, which configuration file and command-line options it uses.',
    'Which Match block applies to a given connection; criteria are reported, not evaluated.',
    ('Address-list, port and other option-value validation. An invalid value stops sshd, but the result '
     'still reports the commands.'),
    'Whether a command user exists, or whether a command path exists, is executable and is safely owned.',
    'Commands named in authorized_keys command= options, ~/.ssh/rc and /etc/ssh/sshrc.',
)

# Keywords from servconf.c keywords[] (identical in both tags apart from Subsystem).
# True means SSHCFG_MATCH: allowed in a Match block.
_KEYWORDS = {
    'acceptenv': True, 'addressfamily': False, 'afstokenpassing': False, 'allowagentforwarding': True,
    'allowgroups': True, 'allowstreamlocalforwarding': True, 'allowtcpforwarding': True, 'allowusers': True,
    'authenticationmethods': True, 'authorizedkeyscommand': True, 'authorizedkeyscommanduser': True,
    'authorizedkeysfile': True, 'authorizedkeysfile2': True, 'authorizedprincipalscommand': True,
    'authorizedprincipalscommanduser': True, 'authorizedprincipalsfile': True, 'banner': True,
    'casignaturealgorithms': True, 'challengeresponseauthentication': True, 'channeltimeout': True,
    'checkmail': False, 'chrootdirectory': True, 'ciphers': False, 'clientalivecountmax': True,
    'clientaliveinterval': True, 'compression': False, 'denygroups': True, 'denyusers': True,
    'disableforwarding': True, 'dsaauthentication': False, 'exposeauthinfo': True, 'fingerprinthash': False,
    'forcecommand': True, 'gatewayports': True, 'gssapiauthentication': True,
    'gssapicleanupcredentials': False, 'gssapistrictacceptorcheck': False,
    'hostbasedacceptedalgorithms': True, 'hostbasedacceptedkeytypes': True, 'hostbasedauthentication': True,
    'hostbasedusesnamefrompacketonly': True, 'hostcertificate': False, 'hostdsakey': False, 'hostkey': False,
    'hostkeyagent': False, 'hostkeyalgorithms': False, 'ignorerhosts': True, 'ignoreuserknownhosts': False,
    'include': True, 'ipqos': True, 'kbdinteractiveauthentication': True, 'keepalive': False,
    'kerberosauthentication': True, 'kerberosgetafstoken': False, 'kerberosorlocalpasswd': False,
    'kerberostgtpassing': False, 'kerberosticketcleanup': False, 'kexalgorithms': False,
    'keyregenerationinterval': False, 'listenaddress': False, 'logingracetime': False, 'loglevel': True,
    'logverbose': True, 'macs': False, 'match': True, 'maxauthtries': True, 'maxsessions': True,
    'maxstartups': False, 'modulifile': False, 'pamauthenticationviakbdint': False,
    'passwordauthentication': True, 'permitemptypasswords': True, 'permitlisten': True, 'permitopen': True,
    'permitrootlogin': True, 'permittty': True, 'permittunnel': True, 'permituserenvironment': False,
    'permituserrc': True, 'persourcemaxstartups': False, 'persourcenetblocksize': False, 'pidfile': False,
    'port': False, 'printlastlog': False, 'printmotd': False, 'protocol': False,
    'pubkeyacceptedalgorithms': True, 'pubkeyacceptedkeytypes': True, 'pubkeyauthentication': True,
    'pubkeyauthoptions': True, 'rdomain': True, 'rekeylimit': True, 'requiredrsasize': True,
    'reversemappingcheck': False, 'revokedkeys': True, 'rhostsauthentication': False,
    'rhostsrsaauthentication': True, 'rsaauthentication': True, 'securitykeyprovider': False,
    'serverkeybits': False, 'setenv': True, 'skeyauthentication': True, 'streamlocalbindmask': True,
    'streamlocalbindunlink': True, 'strictmodes': False, 'subsystem': False, 'syslogfacility': False,
    'tcpkeepalive': False, 'trustedusercakeys': True, 'unusedconnectiontimeout': True, 'usedns': False,
    'uselogin': False, 'usepam': False, 'useprivilegeseparation': False, 'verifyreversemapping': False,
    'versionaddendum': False, 'x11displayoffset': True, 'x11forwarding': True, 'x11uselocalhost': True,
    'xauthlocation': False,
}
_MATCH_ATTRS = frozenset({'user', 'group', 'host', 'localaddress', 'localport', 'rdomain', 'address'})
_AKC_TOKENS = frozenset('Uuhtfk')
_APC_TOKENS = frozenset('UuhtTfFkKis')
_KINDS = {
    'authorizedkeyscommand': 'authorized_keys_command',
    'authorizedprincipalscommand': 'authorized_principals_command',
    'forcecommand': 'force_command',
}
_USERS = {
    'authorizedkeyscommanduser': 'authorized_keys_command_user',
    'authorizedprincipalscommanduser': 'authorized_principals_command_user',
}


class ConfigError(ValueError):
    """sshd would refuse this configuration and exit at startup."""


def argv_split(s: str, terminate_on_comment: bool) -> list[str] | None:
    """``misc.c`` argv_split: None for an unterminated quote."""
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        if s[i] in ' \t':
            i += 1
            continue
        if terminate_on_comment and s[i] == '#':
            break
        quote = ''
        arg: list[str] = []
        while i < n:
            c = s[i]
            if c == '\\':
                nxt = s[i + 1] if i + 1 < n else ''
                if nxt in ('\'', '"', '\\') or (not quote and nxt == ' '):
                    i += 1
                    arg.append(nxt)
                else:
                    arg.append(c)
            elif not quote and c in ' \t':
                break
            elif not quote and c in '"\'':
                quote = c
            elif quote and c == quote:
                quote = ''
            else:
                arg.append(c)
            i += 1
        out.append(''.join(arg))
        if i >= n:
            if quote:
                return None
            break
    return out


def _strdelim(s: str | None, split_equals: bool = True) -> tuple[str | None, str | None]:
    """``misc.c`` strdelim_internal: (token, rest); token None for an unmatched quote."""
    if s is None:
        return None, None
    stops = WHITESPACE + '"' + ('=' if split_equals else '')
    pos = next((k for k, c in enumerate(s) if c in stops), -1)
    if pos < 0:
        return s, None
    if s[pos] == '"':
        body = s[:pos] + s[pos + 1:]
        q = body.find('"', pos)
        if q < 0:
            return None, None
        rest = body[q + 1:]
        return body[:q], rest[len(rest) - len(rest.lstrip(WHITESPACE)):]
    wspace = split_equals and s[pos] == '='
    token, rest = s[:pos], s[pos + 1:]
    rest = rest.lstrip(WHITESPACE)
    if split_equals and rest.startswith('=') and not wspace:
        rest = rest[1:].lstrip(WHITESPACE)
    return token, rest


def percent_tokens(arg: str) -> list[str] | None:
    """Tokens ``percent_expand`` would replace; None for a trailing lone ``%``."""
    found: list[str] = []
    i = 0
    while i < len(arg):
        if arg[i] == '%':
            if i + 1 >= len(arg):
                return None
            if arg[i + 1] != '%':
                found.append(arg[i + 1])
            i += 2
            continue
        i += 1
    return found


def _match_criteria(rest: str | None) -> list[list[str]] | str:
    """``match_cfg_line`` syntax at startup: criteria pairs, ['all'] or an error string."""
    cp = rest
    criteria: list[list[str]] = []
    while True:
        attrib, cp = _strdelim(cp, False)
        if attrib is None or attrib == '':
            break
        if attrib.startswith('#'):
            break
        if attrib.lower() == 'all':
            arg, _ = _strdelim(cp, False)
            if criteria or (arg not in (None, '') and not arg.startswith('#')):
                return "'all' cannot be combined with other Match attributes"
            return [['all']]
        arg, cp = _strdelim(cp, False)
        if arg is None or arg == '' or arg.startswith('#'):
            return 'Missing Match criteria for ' + attrib
        if attrib.lower() not in _MATCH_ATTRS:
            return 'Unsupported Match attribute ' + attrib
        if attrib.lower() == 'localport' and not (arg.isdigit() and arg.isascii() and 0 < int(arg) <= 65535):
            return 'Invalid LocalPort on Match line'
        criteria.append([attrib.lower(), arg])
    if not criteria:
        return 'One or more attributes required for Match'
    return criteria


def _decode(raw: Any) -> tuple[str | None, str | None]:
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > MAX_TEXT:
            return None, 'over_limit'
        if b'\0' in raw:
            return None, 'binary'
        try:
            return bytes(raw).decode('utf-8'), None
        except UnicodeDecodeError:
            return None, 'invalid_utf8'
    if type(raw) is not str:
        return None, 'file_not_observed'
    if len(raw) > MAX_TEXT:
        return None, 'over_limit'
    if '\0' in raw:
        return None, 'binary'
    return raw, None


class _Parser:
    def __init__(self, files, globs, version):
        self.files = files
        self.globs = globs
        self.version = version
        self.gaps: list[dict[str, str]] = []
        self.errors: list[dict[str, Any]] = []
        self.read: list[str] = []
        self.blocks: list[dict[str, Any]] = []
        self.entries: list[dict[str, Any]] = []
        self.subsystems: list[dict[str, Any]] = []

    def gap(self, reason: str, path: str) -> None:
        if {'reason': reason, 'path': path} not in self.gaps:
            self.gaps.append({'reason': reason, 'path': path})

    def fatal(self, path: str, line: int, message: str) -> None:
        self.errors.append({'path': path, 'line': line, 'message': message})
        raise ConfigError(message)

    def parse_file(self, path: str, active: bool, nevermatch: bool, block: int | None, depth: int) -> None:
        if depth > MAX_DEPTH:
            self.fatal(path, 0, 'Too many recursive configuration includes')
        if len(self.read) >= MAX_FILES:
            self.gap('files_over_limit', path)
            return
        text, problem = _decode(self.files.get(path))
        if problem:
            self.gap(problem, path)
            return
        self.read.append(path)
        bad = 0
        base = block  # A Match line replaces the file's current block; it nests only under an Include.
        for number, line in enumerate(text.split('\n'), 1):
            try:
                consumed = self.line(path, number, line, active, nevermatch, block, base, depth)
            except _BadOption as exc:
                self.errors.append({'path': path, 'line': number, 'message': str(exc)})
                bad += 1
                continue
            if consumed is not None:
                active, block = consumed
        if bad:
            raise ConfigError('%s: terminating, %d bad configuration options' % (path, bad))

    def line(self, path, number, line, active, nevermatch, block, base, depth):
        line = line.rstrip(WHITESPACE + '\f')
        if not line:
            return None
        keyword, rest = _strdelim(line)
        if keyword == '':
            keyword, rest = _strdelim(rest)
        if not keyword or keyword.startswith('#'):
            return None
        if rest is None or rest == '':
            raise _BadOption('no argument after keyword "%s"' % keyword)
        key = keyword.lower()
        if key not in _KEYWORDS:
            # Upstream sshd refuses an unknown keyword, but distribution patches add keywords (Debian's
            # GSSAPI key exchange, for example), so the line is skipped and reported instead.
            self.gap('unrecognized_keyword', '%s:%d:%s' % (path, number, keyword))
            return None
        args = argv_split(rest, True)
        if args is None:
            raise _BadOption('invalid quotes')
        allowed = _KEYWORDS[key] or (key == 'subsystem' and self.version == '9.6p1')
        if not active and not allowed:
            self.fatal(path, number, "Directive '%s' is not allowed within a Match block" % keyword)
        where = {'path': path, 'line': number}
        if key == 'match':
            criteria = _match_criteria(rest)
            if isinstance(criteria, str):
                self.fatal(path, number, 'Bad Match condition: ' + criteria)
            parent = self.blocks[base]['conditions'] if base is not None else []
            self.blocks.append({'index': len(self.blocks), 'conditions': parent + [criteria], 'parent': base,
                                'matches_always': all(c == [['all']] for c in parent + [criteria]),
                                **where})
            starts_active = criteria == [['all']] and not nevermatch
            return starts_active, len(self.blocks) - 1
        if key == 'include':
            self.include(path, number, args, active, block, depth)
            return None
        if key in _KINDS:
            value = rest.lstrip(WHITESPACE)
            if key != 'forcecommand' and not value.startswith('/') and value.lower() != 'none':
                self.fatal(path, number, '%s must be an absolute path' % keyword)
            self.record(_KINDS[key], value, active, block, where)
        elif key in _USERS:
            self.record(_USERS[key], args[0], active, block, where)
        elif key == 'subsystem':
            self.subsystem(path, number, args, active, block, where)
        return None

    def include(self, path, number, args, active, block, depth):
        if not args:
            self.fatal(path, number, 'Include missing filename argument')
        for pattern in args:
            if pattern == '':
                raise _BadOption('keyword Include empty argument')
            if pattern.startswith('~'):
                self.gap('home_relative_include', pattern)
                continue
            selector = pattern if pattern.startswith('/') else SSHDIR + '/' + pattern
            matches = self.globs.get(selector)
            if matches is None and not any(c in selector for c in '*?['):
                matches = [selector] if selector in self.files else None
            if matches is None:
                self.gap('glob_not_observed', selector)
                continue
            for item in sorted(str(m) for m in matches):
                if not item.startswith('/'):
                    self.gap('relative_path', item)
                    continue
                self.parse_file(posixpath.normpath(item), active, not active, block, depth + 1)

    def record(self, field, value, active, block, where):
        if len(self.entries) >= MAX_ENTRIES:
            self.gap('entries_over_limit', where['path'])
            return
        self.entries.append({'field': field, 'value': value, 'block': block, **where})

    def subsystem(self, path, number, args, active, block, where):
        name = args[0] if args else ''
        if name == '':
            self.fatal(path, number, 'Subsystem missing argument.')
        if not active:
            if self.version == '9.6p1' and len(args) >= 2 and args[1] != '':
                self.subsystems.append({'name': name, 'argv': args[1:], 'block': block, **where})
            return
        if len(args) < 2 or args[1] == '':
            self.fatal(path, number, 'Missing subsystem command.')
        if self.version == '9.2p1' and any(e['name'] == name and self.startup_active(e['block'])
                                           for e in self.subsystems):
            self.fatal(path, number, "Subsystem '%s' already defined." % name)
        self.subsystems.append({'name': name, 'argv': args[1:], 'block': block, **where})

    def startup_active(self, block: int | None) -> bool:
        return block is None or self.blocks[block]['matches_always']

    def chain(self, block: int | None) -> set[int | None]:
        """Blocks that match whenever ``block`` matches, plus every Match-all block."""
        out: set[int | None] = {b['index'] for b in self.blocks if b['matches_always']}
        while block is not None:
            out.add(block)
            block = self.blocks[block]['parent']
        return out

    def fold(self, blocks: set[int | None]) -> dict[str, dict[str, Any]]:
        """Apply servconf.c's storage rules to the entries in ``blocks``, in file order."""
        stored: dict[str, dict[str, Any]] = {}
        for entry in self.entries:
            if entry['block'] not in blocks:
                continue
            field = entry['field']
            if field in _KINDS.values() and field != 'force_command' and self.version == '9.2p1':
                # 9.2p1 parse_command tests authorized_keys_command for both commands.
                if 'authorized_keys_command' not in stored:
                    stored[field] = entry
            else:
                stored.setdefault(field, entry)
        return stored

    def subsystem_fold(self, blocks: set[int | None]) -> dict[str, dict[str, Any]]:
        stored: dict[str, dict[str, Any]] = {}
        for entry in self.subsystems:
            if entry['block'] in blocks:
                stored.setdefault(entry['name'], entry)
        return stored

    def effective(self, block: int | None) -> tuple[dict[str, Any], dict[str, Any]]:
        """Startup values overridden by the re-read Match blocks that match with ``block``."""
        startup = self.fold({None} | {b['index'] for b in self.blocks if b['matches_always']})
        subs = self.subsystem_fold({None} | {b['index'] for b in self.blocks if b['matches_always']})
        matched = self.chain(block)
        values = {**startup, **self.fold(matched)}
        if self.version == '9.6p1':
            subs = {**subs, **self.subsystem_fold(matched)}
        return values, subs


class _BadOption(Exception):
    pass


def _command_view(kind: str, entry: dict[str, Any] | None, user: dict[str, Any] | None) -> dict[str, Any]:
    view: dict[str, Any] = {'kind': kind, 'source': None, 'command': None, 'argv': [], 'run_as': None,
                            'runs': False, 'reason': 'not_set', 'percent_tokens': []}
    if entry is None:
        return view
    value = entry['value']
    view.update(source={'path': entry['path'], 'line': entry['line']}, command=value)
    if kind == 'force_command':
        if value.lower() == 'none':
            view['reason'] = 'cleared_by_none'
            return view
        view.update(run_as='authenticating_user', runs=True, reason='runs_through_login_shell')
        return view
    view['run_as'] = user['value'] if user else None
    argv = argv_split(value, False)
    if argv is None:
        view['reason'] = 'invalid_quotes'
        return view
    view['argv'] = argv
    if not argv:
        view['reason'] = 'no_arguments'
        return view
    if user is None:
        view['reason'] = 'no_command_user'
        return view
    if not argv[0].startswith('/'):
        view['reason'] = 'none' if value.lower() == 'none' else 'path_not_absolute'
        return view
    allowed = _AKC_TOKENS if kind == 'authorized_keys_command' else _APC_TOKENS
    tokens: list[str] = []
    for arg in argv[1:]:
        found = percent_tokens(arg)
        if found is None or any(t not in allowed for t in found):
            view['reason'] = 'invalid_percent_token'
            return view
        tokens.extend(t for t in found if t not in tokens)
    view.update(percent_tokens=tokens, runs=True, reason='runs_on_authentication')
    return view


def resolve(files: Mapping[str, Any], globs: Mapping[str, Iterable[str] | None] | None = None, *,
            version: str = '9.2p1', path: str = DEFAULT_PATH) -> dict[str, Any]:
    """Resolve which commands sshd runs from captured configuration.

    ``files`` maps absolute paths to captured text (``None`` when unreadable).
    ``globs`` maps each absolute Include pattern to its captured matches.
    """
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_version': version, 'path': path,
        'status': 'complete', 'config_error': None, 'errors': [], 'files_read': [], 'gaps': [],
        'commands': [], 'subsystems': [], 'conditional': [], 'origin': 'not_assessed',
        'not_observed': list(NOT_OBSERVED), 'digest': None,
    }
    if version not in SOURCE_VERSIONS:
        result.update(status='incomplete', gaps=[{'reason': 'unsupported_version', 'path': path}])
        return result
    if not isinstance(files, Mapping) or (globs is not None and not isinstance(globs, Mapping)):
        result.update(status='incomplete', gaps=[{'reason': 'file_not_observed', 'path': path}])
        return result
    norm_globs = {str(k): (None if v is None else [str(x) for x in v]) for k, v in (globs or {}).items()}
    parser = _Parser(files, norm_globs, version)
    try:
        parser.parse_file(path, True, False, None, 0)
        startup = parser.fold({None} | {b['index'] for b in parser.blocks if b['matches_always']})
        for field, label in (('authorized_keys_command', 'AuthorizedKeysCommand'),
                             ('authorized_principals_command', 'AuthorizedPrincipalsCommand')):
            entry = startup.get(field)
            if entry and entry['value'].lower() != 'none' and field + '_user' not in startup:
                parser.errors.append({'path': entry['path'], 'line': entry['line'],
                                      'message': '%s set without %sUser' % (label, label)})
                raise ConfigError('%s set without %sUser' % (label, label))
    except ConfigError as exc:
        result['config_error'] = str(exc)
    result.update(errors=parser.errors, files_read=parser.read, gaps=parser.gaps)
    if any(g['reason'] in BLOCKING for g in parser.gaps):
        result['status'] = 'incomplete'
    if result['config_error'] is not None:
        result['status'] = 'config_error'
        return result
    pairs = (('authorized_keys_command', 'authorized_keys_command_user'),
             ('authorized_principals_command', 'authorized_principals_command_user'),
             ('force_command', None))

    def views(values: dict[str, Any], only: set[str] | None = None) -> list[dict[str, Any]]:
        out = []
        for kind, user_field in pairs:
            if only is None or kind in only or (user_field and user_field in only):
                out.append(_command_view(kind, values.get(kind), values.get(user_field) if user_field else None))
        return out

    values, subs = parser.effective(None)
    result['commands'] = views(values)
    result['subsystems'] = [_subsystem_view(e) for e in subs.values()]
    for block in parser.blocks:
        if block['matches_always']:
            continue
        own = {e['field'] for e in parser.entries if e['block'] == block['index']}
        own_subs = {e['name'] for e in parser.subsystems if e['block'] == block['index']}
        if not own and not own_subs:
            continue
        b_values, b_subs = parser.effective(block['index'])
        result['conditional'].append({
            'path': block['path'], 'line': block['line'], 'conditions': block['conditions'],
            'commands': views(b_values, own),
            'subsystems': [_subsystem_view(e) for n, e in b_subs.items() if n in own_subs],
            'overridden_fields': sorted(f for f in own if b_values.get(f, {}).get('block') != block['index']),
        })
    payload = repr((result['commands'], result['subsystems'], result['conditional'], result['status']))
    result['digest'] = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    return result


def _subsystem_view(entry: dict[str, Any]) -> dict[str, Any]:
    program = entry['argv'][0]
    internal = program == 'internal-sftp'
    return {'name': entry['name'], 'argv': entry['argv'], 'source': {'path': entry['path'], 'line': entry['line']},
            'run_as': 'authenticating_user', 'runs': True,
            'reason': 'in_process_sftp' if internal else 'runs_through_login_shell'}
