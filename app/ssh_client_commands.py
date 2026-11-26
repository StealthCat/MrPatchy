"""Pure OpenSSH client ``ssh_config`` command contract (roadmap F slice, #1509).

This module takes captured, read-only observations of the system-wide OpenSSH
client configuration: ``/etc/ssh/ssh_config``, every file its ``Include``
lines match, and those globs' expansions. It reports which local programs
that configuration makes ``ssh`` run. The same applies to ``scp``, ``sftp``,
``rsync -e ssh``, ``git`` over SSH and automation tools, for every user that
invokes them, root included.

Semantics follow OpenSSH portable (10.6) ``readconf.c``, ``misc.c``, ``ssh.c``
and ``sshconnect.c``:

* Each line is trimmed of trailing whitespace and form feeds. The keyword is
  split off by ``strdelim`` (whitespace or a single ``=``), and the rest is
  checked by ``argv_split(..., terminate_on_comment=1)``. Unbalanced quotes,
  a missing argument, an unknown keyword (unless ``IgnoreUnknown`` covers it),
  a bad ``Match`` condition, an invalid flag value and a ``~`` include path are
  configuration errors. ssh finishes reading that file and then exits
  (``terminating, N bad configuration options``), so nothing after
  configuration parsing runs.
* ``Host`` and ``Match`` set whether later lines apply. The first obtained
  value of each option wins. An earlier unconditional value, ``none``
  included, therefore shadows every later candidate.
* ``Include`` resolves relative paths under ``/etc/ssh``. It expands globs in
  sorted order and reads each file with the including block's activation
  state, which is restored afterwards. A file included from an inactive block
  is read with ``SSHCONF_NEVERMATCH``: none of its blocks apply. Included
  files must be owned by root (or the invoking user) and must not be group- or
  world-writable, otherwise ssh exits at once. Nesting deeper than 16 is
  fatal. A glob match that vanished before it could be opened is also an
  error.
* ``Match exec "cmd"`` runs ``$SHELL -c cmd`` (``/bin/sh`` when ``SHELL`` is
  unset) *while the configuration is parsed*, before any connection. It is
  skipped only when an earlier criterion on the same ``Match`` line failed. It
  still runs in files included from inactive blocks, because
  ``SSHCONF_NEVERMATCH`` only forces the block result afterwards.
* ``ProxyCommand`` runs ``$SHELL -c "exec <cmd>"``. ``none`` disables it and
  ``-`` means no command. ``LocalCommand`` runs ``$SHELL -c <cmd>`` after the
  connection, and only when ``PermitLocalCommand`` is yes. ``KnownHostsCommand``
  is split with ``argv_split`` and exec'd directly, and its argv[0] must be
  absolute or it is not run. ``PKCS11Provider`` and ``SecurityKeyProvider``
  name shared libraries the client loads (``internal`` is built in, and
  ``$VAR`` reads the path from the environment). When an effective
  ``ProxyJump`` precedes an effective ``ProxyCommand``, that ``ProxyCommand``
  never runs, but the outcome depends on the client version: OpenSSH 9.6 and
  10.2 ignore the later ``ProxyCommand`` and use the jump host, while 10.6
  stores it and exits with ``inconsistent options``. A ``ProxyCommand`` that
  comes first always wins, because ``parse_jump`` ignores a later jump.
* ``RemoteCommand`` runs on the remote server and is not reported.

Every command runs as the user who invoked ssh, with that user's environment.

Limits, which are stated in the result: per-user ``~/.ssh/config`` is read
*before* this file and takes precedence (first value wins), and ``-F``/``-o``
override both. Values of directives the contract does not interpret are not
validated, and ssh rejects invalid ones. ``Host``/``Match`` criteria other than
``Host *`` and ``Match all`` are reported as conditions, not evaluated.

The contract performs no I/O, never runs a command and never authorizes a
response action. Every input that is unknown, malformed or over a cap, or that
cannot be resolved without knowing the invocation, becomes an explicit coverage
gap and never yields a covered result.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
SYSTEM_CONFIG = '/etc/ssh/ssh_config'
SSHDIR = '/etc/ssh'
MAX_DEPTH = 16  # READCONF_MAX_DEPTH
MAX_FILES = 512
MAX_READS = 2048
MAX_TEXT = 1 << 20
MAX_LINES = 50000
MAX_GAPS = 256
MAX_PATH = 4096
FILE_STATES = ('present', 'absent', 'unknown')
FILE_KINDS = ('regular', 'directory', 'other')

_WHITESPACE = ' \t\r\n'
_GLOB_MAGIC = re.compile(r'[*?\[]')
_TOKEN = re.compile(r'%[A-Za-z%]')
_ENV = re.compile(r'\$\{')

# Every keyword in readconf.c keywords[], including deprecated, unsupported
# and ignored ones: these are not errors.
KEYWORDS = frozenset((
    'protocol', 'cipher', 'fallbacktorsh', 'globalknownhostsfile2', 'rhostsauthentication',
    'userknownhostsfile2', 'useroaming', 'usersh', 'useprivilegedport', 'afstokenpassing',
    'kerberosauthentication', 'kerberostgtpassing', 'rsaauthentication', 'rhostsrsaauthentication',
    'compressionlevel', 'gssapiauthentication', 'gssapidelegatecredentials', 'pkcs11provider',
    'smartcarddevice', 'forwardagent', 'forwardx11', 'forwardx11trusted', 'forwardx11timeout',
    'exitonforwardfailure', 'xauthlocation', 'gatewayports', 'passwordauthentication',
    'kbdinteractiveauthentication', 'kbdinteractivedevices', 'challengeresponseauthentication',
    'skeyauthentication', 'tisauthentication', 'pubkeyauthentication', 'dsaauthentication',
    'hostbasedauthentication', 'identityfile', 'identityfile2', 'identitiesonly', 'certificatefile',
    'addkeystoagent', 'identityagent', 'hostname', 'hostkeyalias', 'proxycommand', 'port', 'ciphers', 'macs',
    'remoteforward', 'localforward', 'permitremoteopen', 'user', 'host', 'match', 'tag', 'escapechar',
    'globalknownhostsfile', 'userknownhostsfile', 'connectionattempts', 'batchmode', 'checkhostip',
    'stricthostkeychecking', 'compression', 'tcpkeepalive', 'keepalive', 'numberofpasswordprompts',
    'syslogfacility', 'loglevel', 'logverbose', 'dynamicforward', 'preferredauthentications',
    'hostkeyalgorithms', 'casignaturealgorithms', 'bindaddress', 'bindinterface', 'clearallforwardings',
    'enablesshkeysign', 'verifyhostkeydns', 'nohostauthenticationforlocalhost', 'rekeylimit',
    'connecttimeout', 'addressfamily', 'serveraliveinterval', 'serveralivecountmax', 'sendenv', 'setenv',
    'controlpath', 'controlmaster', 'controlpersist', 'hashknownhosts', 'include', 'tunnel', 'tunneldevice',
    'localcommand', 'permitlocalcommand', 'remotecommand', 'visualhostkey', 'kexalgorithms', 'ipqos',
    'requesttty', 'sessiontype', 'stdinnull', 'forkafterauthentication', 'proxyusefdpass', 'canonicaldomains',
    'canonicalizefallbacklocal', 'canonicalizehostname', 'canonicalizemaxdots', 'canonicalizepermittedcnames',
    'streamlocalbindmask', 'streamlocalbindunlink', 'revokedhostkeys', 'fingerprinthash', 'updatehostkeys',
    'hostbasedacceptedalgorithms', 'hostbasedkeytypes', 'pubkeyacceptedalgorithms', 'pubkeyacceptedkeytypes',
    'ignoreunknown', 'proxyjump', 'securitykeyprovider', 'knownhostscommand', 'requiredrsasize',
    'enableescapecommandline', 'obscurekeystroketiming', 'channeltimeout', 'versionaddendum',
    'refuseconnection', 'warnweakcrypto',
))

# Directives whose candidates are tracked. The value is the parse style.
_COMMANDS = {'proxycommand': 'ProxyCommand', 'localcommand': 'LocalCommand',
             'knownhostscommand': 'KnownHostsCommand'}
_LIBRARIES = {'pkcs11provider': 'PKCS11Provider', 'smartcarddevice': 'PKCS11Provider',
              'securitykeyprovider': 'SecurityKeyProvider'}
_FLAGS = {'true': True, 'yes': True, 'false': False, 'no': False}
_MATCH_NO_ARG = ('canonical', 'final')
_MATCH_ARG = ('exec', 'localnetwork', 'host', 'originalhost', 'tagged', 'command',
              'user', 'localuser', 'version', 'sessiontype')
_MATCH_EMPTY_OK = ('tagged', 'command')


class Invalid(ValueError):
    """An observation that cannot be interpreted safely."""


class _Fatal(Exception):
    def __init__(self, record: dict[str, Any]):
        super().__init__(record['code'])
        self.record = record


class _Stop(Exception):
    """A cap was hit; the result is not covered."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps[-1] = {'code': 'gaps_truncated'}


def _abs(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith('/') or len(value) > MAX_PATH or '\0' in value:
        raise Invalid('invalid absolute path')
    return value


def _file(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not set(value) <= {'state', 'kind', 'text', 'uid', 'mode'}:
        raise Invalid('invalid file observation')
    state = value.get('state')
    if state not in FILE_STATES:
        raise Invalid('invalid file state')
    kind, text, uid, mode = (value.get(k) for k in ('kind', 'text', 'uid', 'mode'))
    if state != 'present':
        if any(v is not None for v in (kind, text, uid, mode)):
            raise Invalid('details supplied for a file that is not present')
        return {'state': state}
    if kind not in FILE_KINDS:
        raise Invalid('invalid file kind')
    if text is not None and (kind != 'regular' or not isinstance(text, str)):
        raise Invalid('invalid file text')
    if isinstance(text, str) and len(text) > MAX_TEXT:
        raise Invalid('file text over the cap')
    for name, v in (('uid', uid), ('mode', mode)):
        if v is not None and (type(v) is not int or v < 0 or (name == 'mode' and v > 0o7777)):
            raise Invalid(f'invalid {name}')
    return {'state': state, 'kind': kind, 'text': text, 'uid': uid, 'mode': mode}


def _observation(obs: Any) -> tuple[dict[str, dict[str, Any]], dict[str, list[str] | None]]:
    if not isinstance(obs, dict) or not set(obs) <= {'files', 'globs'}:
        raise Invalid('invalid observation')
    files_in = obs.get('files') or {}
    globs_in = obs.get('globs') or {}
    if not isinstance(files_in, dict) or not isinstance(globs_in, dict):
        raise Invalid('invalid observation')
    if len(files_in) > MAX_FILES or len(globs_in) > MAX_FILES:
        raise Invalid('too many observed files or globs')
    files = {_abs(p): _file(v) for p, v in files_in.items()}
    globs: dict[str, list[str] | None] = {}
    for pattern, matches in globs_in.items():
        _abs(pattern)
        if matches is None:
            globs[pattern] = None
            continue
        if not isinstance(matches, list) or len(matches) > MAX_FILES:
            raise Invalid('invalid glob matches')
        # glob(3) without GLOB_NOSORT returns matches sorted; ssh sets only LC_CTYPE.
        globs[pattern] = sorted({_abs(m) for m in matches}, key=lambda s: s.encode('utf-8', 'surrogateescape'))
    return files, globs


def argv_split(s: str, terminate_on_comment: bool) -> list[str] | None:
    """Port of misc.c ``argv_split``; ``None`` means invalid quotes."""
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
                    arg.append(s[i])
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


def _strdelim(s: str | None) -> tuple[str | None, str | None]:
    """Port of misc.c ``strdelim_internal(s, split_equals=1)``. Returns (token, rest)."""
    if s is None:
        return None, None
    idx = next((k for k, c in enumerate(s) if c in _WHITESPACE + '"='), None)
    if idx is None:
        return s, None
    if s[idx] == '"':
        raise _QuotedKeyword
    token = s[:idx]
    equals = s[idx] == '='
    j = idx + 1
    while j < len(s) and s[j] in _WHITESPACE:
        j += 1
    if not equals and j < len(s) and s[j] == '=':
        j += 1
        while j < len(s) and s[j] in _WHITESPACE:
            j += 1
    return token, s[j:]


class _QuotedKeyword(Exception):
    pass


def _host_condition(patterns: list[str]) -> str:
    negated = [p for p in patterns if p.startswith('!')]
    if any(p == '!*' for p in negated):
        return 'never'
    if '*' in patterns and not negated:
        return 'always'
    return 'conditional'


class _Parser:
    def __init__(self, files: dict[str, dict[str, Any]], globs: dict[str, list[str] | None]):
        self.files = files
        self.globs = globs
        self.gaps: list[dict[str, Any]] = []
        self.reads: list[str] = []
        self.candidates: dict[str, list[dict[str, Any]]] = {}
        self.match_exec: list[dict[str, Any]] = []
        self.final_pass = False
        self.fatal: dict[str, Any] | None = None
        self.seq = 0

    # -- helpers -----------------------------------------------------------
    def _candidate(self, name: str, loc: dict[str, Any], cond: list[dict[str, Any]], value: Any, **extra: Any) -> None:
        self.seq += 1
        self.candidates.setdefault(name, []).append({**loc, 'seq': self.seq, 'condition': [dict(c) for c in cond],
                                                     'value': value, **extra})

    def _ignored_unknown(self, keyword: str, loc: dict[str, Any]) -> bool | None:
        for cand in self.candidates.get('IgnoreUnknown', []):
            if _never(cand['condition']):
                continue
            if _always(cand['condition']):
                return _match_pattern_list(keyword, cand['value'])
            # The value in force depends on which blocks applied.
            _gap(self.gaps, 'conditional_ignore_unknown', keyword=keyword, **loc)
            return True
        return False

    # -- reading -----------------------------------------------------------
    def read(self, path: str, cond: list[dict[str, Any]], nevermatch: bool, depth: int, checkperm: bool) -> bool:
        """Mirror ``read_config_file_depth``. Returns whether the file was read (r == 1)."""
        if depth > MAX_DEPTH:
            raise _Fatal({'code': 'include_depth_exceeded', 'file': path})
        if len(self.reads) >= MAX_READS:
            _gap(self.gaps, 'too_many_file_reads')
            raise _Stop
        obs = self.files.get(path)
        if obs is None or obs['state'] == 'unknown':
            _gap(self.gaps, 'file_unobserved', file=path)
            raise _Stop
        if obs['state'] == 'absent':
            return False
        if obs['kind'] == 'other':
            _gap(self.gaps, 'file_not_regular', file=path)
            raise _Stop
        if checkperm:
            if obs['uid'] is None or obs['mode'] is None:
                _gap(self.gaps, 'include_permissions_unobserved', file=path)
            elif obs['mode'] & 0o022:
                raise _Fatal({'code': 'include_bad_permissions', 'file': path, 'mode': f'{obs["mode"]:04o}'})
            elif obs['uid'] != 0:
                # Fatal for every invoking user except this uid: invoker-dependent.
                _gap(self.gaps, 'include_owner_not_root', file=path, uid=obs['uid'])
        self.reads.append(path)
        if obs['kind'] == 'directory':
            return True  # fopen succeeds, getline fails at once: an empty file.
        text = obs['text']
        if text is None:
            _gap(self.gaps, 'file_text_unobserved', file=path)
            raise _Stop
        lines = text.split('\n')
        if lines and lines[-1] == '':
            lines.pop()
        if len(lines) > MAX_LINES:
            _gap(self.gaps, 'file_too_long', file=path)
            raise _Stop
        # The file starts with the includer's activation state; a Host/Match
        # in it replaces only the innermost block (``*activep`` is shared).
        state: dict[str, Any] = {'outer': list(cond), 'cond': list(cond), 'bad': []}
        for number, line in enumerate(lines, 1):
            if '\0' in line:
                _gap(self.gaps, 'nul_in_line', file=path, line=number)
                raise _Stop
            state['reason'] = None
            if not self._line(line, {'file': path, 'line': number}, state, nevermatch, depth):
                state['bad'].append({'line': number, 'reason': state['reason']})
        if state['bad']:
            # readconf.c: "terminating, N bad configuration options" after the whole file.
            raise _Fatal({'code': 'bad_configuration_options', 'file': path, 'errors': state['bad'][:32],
                          'count': len(state['bad'])})
        return True

    def _error(self, state: dict[str, Any], reason: str) -> bool:
        state['reason'] = state['reason'] or reason
        return False

    def _line(self, raw: str, loc: dict[str, Any], state: dict[str, Any], nevermatch: bool, depth: int) -> bool:
        line = raw.rstrip(_WHITESPACE + '\f')
        if not line:
            return True
        try:
            keyword, rest = _strdelim(line)
            if keyword == '':
                keyword, rest = _strdelim(rest)
        except _QuotedKeyword:
            _gap(self.gaps, 'quoted_keyword', **loc)
            return True
        if not keyword or keyword.startswith('#'):
            return True
        keyword = keyword.lower()
        if rest is not None:
            rest = rest.lstrip(_WHITESPACE)
        if not rest:
            return self._error(state, f'no argument after keyword {keyword!r}')
        known = keyword in KEYWORDS
        if not known and not self._ignored_unknown(keyword, loc):
            return self._error(state, f'unknown keyword {keyword!r}')
        av = argv_split(rest, True)
        if av is None:
            return self._error(state, 'invalid quotes')
        if not known:
            return True
        cond = state['cond']
        if keyword == 'host':
            return self._host(av, loc, state, nevermatch)
        if keyword == 'match':
            return self._match(av, loc, state, nevermatch)
        if keyword == 'include':
            return self._include(av, loc, state, nevermatch, depth)
        if keyword in _COMMANDS:
            self._candidate(_COMMANDS[keyword], loc, cond, rest.lstrip(_WHITESPACE + '='))
            return True
        if keyword in _LIBRARIES:
            if not av or av[0] == '':
                return self._error(state, 'missing argument')
            self._candidate(_LIBRARIES[keyword], loc, cond, av[0])
            return True
        if keyword == 'permitlocalcommand':
            flag = _FLAGS.get(av[0].lower()) if av else None
            if flag is None:
                return self._error(state, 'invalid PermitLocalCommand value')
            self._candidate('PermitLocalCommand', loc, cond, flag)
            return True
        if keyword == 'proxyjump':
            self._candidate('ProxyJump', loc, cond, rest.lstrip(_WHITESPACE + '='))
            return True
        if keyword == 'ignoreunknown':
            if not av or av[0] == '':
                return self._error(state, 'missing argument')
            self._candidate('IgnoreUnknown', loc, cond, av[0])
            return True
        if keyword == 'canonicalizehostname':
            if av and av[0].lower() in ('yes', 'true', 'always'):
                self.final_pass = True
            return True
        return True

    def _host(self, av: list[str], loc: dict[str, Any], state: dict[str, Any], nevermatch: bool) -> bool:
        patterns: list[str] = []
        for arg in av:
            if arg == '':
                return self._error(state, 'empty Host argument')
            if nevermatch:
                break
            patterns.append(arg)
        state['cond'] = [*state['outer'], {'block': 'host', **loc, 'patterns': patterns,
                                           'evaluated': 'never' if nevermatch else _host_condition(patterns)}]
        return True

    def _match(self, av: list[str], loc: dict[str, Any], state: dict[str, Any], nevermatch: bool) -> bool:
        criteria: list[dict[str, Any]] = []
        evaluated = 'conditional'
        i = 0
        attributes = 0
        while i < len(av):
            attrib = av[i]
            i += 1
            if attrib.startswith('#'):
                break
            negate = attrib.startswith('!')
            name = (attrib[1:] if negate else attrib).lower()
            if name == 'all':
                nxt = av[i] if i < len(av) else None
                if attributes > 1 or (nxt is not None and nxt != '' and not nxt.startswith('#')):
                    return self._error(state, "'all' cannot be combined with other Match attributes")
                if attributes == 0:
                    evaluated = 'never' if negate else 'always'
                criteria.append({'criterion': 'all', 'negated': negate})
                break
            attributes += 1
            if name in _MATCH_NO_ARG:
                if name == 'final' and not negate:
                    self.final_pass = True
                criteria.append({'criterion': name, 'negated': negate})
                continue
            if name not in _MATCH_ARG:
                return self._error(state, f'unsupported Match attribute {name!r}')
            arg = av[i] if i < len(av) else None
            i += 1
            if arg is None or (arg == '' and name not in _MATCH_EMPTY_OK) or (arg != '' and arg.startswith('#')):
                return self._error(state, f'missing argument for Match {name!r}')
            if name == 'exec':
                gate = [dict(c) for c in criteria]
                self.match_exec.append({
                    **loc, 'command': arg, 'negated': negate,
                    'runs': 'every_parse' if not gate else 'when_prior_criteria_match',
                    'prior_criteria': gate, 'in_inactive_include': nevermatch,
                    'include_context': _public_condition(state['outer']),
                    'tokens': sorted(set(_TOKEN.findall(arg))),
                    'invocation': {'via': 'shell', 'argv_template': ['$SHELL', '-c', arg]},
                })
            criteria.append({'criterion': name, 'negated': negate, 'argument': arg})
        if attributes == 0 and evaluated == 'conditional':
            return self._error(state, 'Match requires one or more attributes')
        state['cond'] = [*state['outer'], {'block': 'match', **loc, 'criteria': criteria,
                                           'evaluated': 'never' if nevermatch else evaluated}]
        return True

    def _include(self, av: list[str], loc: dict[str, Any], state: dict[str, Any], nevermatch: bool, depth: int) -> bool:
        ok = True
        for arg in av:
            if arg == '':
                return self._error(state, 'empty Include argument')
            if '%' in arg or '${' in arg:
                _gap(self.gaps, 'include_path_depends_on_invocation', path=arg, **loc)
                continue
            if arg.startswith('~'):
                return self._error(state, f'bad include path {arg}')
            path = arg if arg.startswith('/') else f'{SSHDIR}/{arg}'
            if '\\' in path:
                _gap(self.gaps, 'include_glob_escape', path=path, **loc)
                continue
            if _GLOB_MAGIC.search(path):
                if path not in self.globs or self.globs[path] is None:
                    _gap(self.gaps, 'include_glob_unobserved', pattern=path, **loc)
                    raise _Stop
                matches = self.globs[path]
            else:
                obs = self.files.get(path)
                if obs is None or obs['state'] == 'unknown':
                    _gap(self.gaps, 'file_unobserved', file=path, include=loc)
                    raise _Stop
                matches = [path] if obs['state'] == 'present' else []
            if not matches:
                continue
            outer = list(state['cond'])
            for match in matches:
                # flags | (oactive ? 0 : SSHCONF_NEVERMATCH); *activep restored afterwards.
                if not self.read(match, outer, nevermatch or _never(outer), depth + 1, True):
                    # A glob match that vanished: ENOENT, but r != 1 still marks the line bad.
                    ok = False
                    state['reason'] = state['reason'] or f'included file {match} could not be read'
        return ok


def _never(cond: list[dict[str, Any]]) -> bool:
    return any(c.get('evaluated') == 'never' for c in cond)


def _always(cond: list[dict[str, Any]]) -> bool:
    return all(c.get('evaluated') == 'always' for c in cond)


def _match_pattern(s: str, pattern: str) -> bool:
    # match.c match_pattern: '*' and '?' only.
    rx = ''.join('.*' if c == '*' else '.' if c == '?' else re.escape(c) for c in pattern)
    return re.fullmatch(rx, s, re.DOTALL) is not None


def _match_pattern_list(s: str, plist: str) -> bool:
    # match_pattern_list(s, list, dolower=1): a negated match wins outright.
    got = False
    for raw in plist.split(','):
        neg = raw.startswith('!')
        pat = (raw[1:] if neg else raw).lower()
        if _match_pattern(s.lower(), pat):
            if neg:
                return False
            got = True
    return got


def _public_condition(cond: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(c) for c in cond]


def _resolve(cands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """First obtained value wins.

    ``effective``: applies to every invocation. ``fallback``: applies to every
    invocation that no earlier ``conditional`` candidate claimed.
    ``shadowed``: an earlier unconditional candidate always wins.
    """
    out = []
    winner: dict[str, Any] | None = None
    conditional_before = False
    for cand in cands:
        item = {k: v for k, v in cand.items() if k != 'condition'}
        item['condition'] = _public_condition(cand['condition'])
        if _never(cand['condition']):
            item['status'] = 'never_applies'
        elif winner is not None:
            item['status'] = 'shadowed'
            item['shadowed_by'] = {'file': winner['file'], 'line': winner['line']}
        elif _always(cand['condition']):
            item['status'] = 'fallback' if conditional_before else 'effective'
            winner = cand
        else:
            item['status'] = 'conditional'
            conditional_before = True
        out.append(item)
    return out


_APPLIES = ('effective', 'fallback', 'conditional')


def _is_none(value: str) -> bool:
    return value.lower() == 'none'


def _command_entry(directive: str, item: dict[str, Any], permit: str, fatal: bool) -> dict[str, Any]:
    value = item['value']
    entry = {**item, 'directive': directive}
    if _is_none(value):
        entry['kind'] = 'disabled'
    elif directive == 'ProxyCommand' and value == '-':
        entry['kind'] = 'stdio_no_command'
    elif directive == 'KnownHostsCommand':
        argv = argv_split(value, False)
        if argv is None or not argv:
            entry['kind'] = 'not_run_invalid_command'
        elif not argv[0].startswith('/'):
            entry['kind'] = 'not_run_relative_path'
            entry['argv_template'] = argv
        else:
            entry['kind'] = 'exec'
            entry['invocation'] = {'via': 'direct', 'argv_template': argv, 'executable': argv[0]}
        entry['tokens'] = sorted(set(_TOKEN.findall(value)))
        entry['env_references'] = bool(_ENV.search(value))
    else:
        entry['kind'] = 'shell'
        shell_arg = f'exec {value}' if directive == 'ProxyCommand' else value
        entry['invocation'] = {'via': 'shell', 'argv_template': ['$SHELL', '-c', shell_arg]}
        entry['tokens'] = sorted(set(_TOKEN.findall(value)))
    if directive == 'LocalCommand':
        entry['permit_local_command'] = permit
        if permit == 'no' and entry['kind'] == 'shell' and entry['status'] in _APPLIES:
            entry['status'] = 'not_permitted'
    if fatal and entry['status'] in _APPLIES:
        entry['status'] = 'never_runs_config_fatal'
    return entry


def _library_entry(directive: str, item: dict[str, Any], fatal: bool) -> dict[str, Any]:
    value = item['value']
    entry = {**item, 'directive': directive}
    if _is_none(value):
        entry['kind'] = 'disabled'
    elif directive == 'SecurityKeyProvider' and value.lower() == 'internal':
        entry['kind'] = 'builtin'
    elif directive == 'SecurityKeyProvider' and value.startswith('$') and len(value) > 1:
        entry['kind'] = 'library_from_environment'
        entry['environment_variable'] = value[1:]
    else:
        entry['kind'] = 'library'
        entry['library'] = value
    if fatal and entry['status'] in _APPLIES:
        entry['status'] = 'never_runs_config_fatal'
    return entry


def _permit(items: list[dict[str, Any]]) -> str:
    # Default no. Any conditional candidate makes the outcome host-dependent
    # unless every candidate that can apply agrees.
    values = {item['value'] for item in items if item['status'] in _APPLIES}
    if not any(item['status'] in ('effective', 'fallback') for item in items):
        values.add(False)
    if len(values) > 1:
        return 'conditional'
    return 'yes' if values == {True} else 'no'


def evaluate(observation: Any) -> dict[str, Any]:
    """Return which programs the system-wide ssh client configuration runs."""
    files, globs = _observation(observation)
    parser = _Parser(files, globs)
    complete = True
    try:
        parser.read(SYSTEM_CONFIG, [], False, 0, False)
    except _Fatal as exc:
        parser.fatal = exc.record
    except _Stop:
        complete = False
    fatal = parser.fatal is not None
    resolved = {name: _resolve(c) for name, c in parser.candidates.items()}
    permit = _permit(resolved.get('PermitLocalCommand', []))
    commands = []
    for directive in ('ProxyCommand', 'LocalCommand', 'KnownHostsCommand'):
        commands += [_command_entry(directive, item, permit, fatal) for item in resolved.get(directive, [])]
    libraries = []
    for directive in ('PKCS11Provider', 'SecurityKeyProvider'):
        libraries += [_library_entry(directive, item, fatal) for item in resolved.get(directive, [])]
    for entry in parser.match_exec:
        entry['condition_note'] = 'runs during configuration parsing, before any connection'
    conflicts = []
    # parse_jump() only sets the jump host while no ProxyCommand is set. A
    # later ProxyCommand is version-dependent: OpenSSH 9.6 and 10.2 readconf.c
    # skip it ("Ignore ProxyCommand if ProxyJump already specified"), while
    # 10.6 stores it and ssh.c exits with "inconsistent options:
    # ProxyCommand+ProxyJump". Either way that ProxyCommand never runs.
    jump = next((j for j in resolved.get('ProxyJump', []) if j['status'] == 'effective'), None)
    proxy = next((p for p in commands if p['directive'] == 'ProxyCommand' and p['status'] == 'effective'), None)
    if jump and proxy and not _is_none(jump['value']) and proxy['kind'] != 'disabled' and jump['seq'] < proxy['seq']:
        proxy['status'] = 'never_runs_after_proxyjump'
        proxy['status_note'] = ('ignored in favour of the jump host by OpenSSH 9.6 and 10.2; '
                                'OpenSSH 10.6 exits with inconsistent options')
        conflicts.append({'code': 'proxyjump_before_proxycommand',
                          'outcome': 'version_dependent',
                          'outcome_by_version': {'9.6': 'proxycommand_ignored_jump_used',
                                                 '10.2': 'proxycommand_ignored_jump_used',
                                                 '10.6': 'fatal_inconsistent_options'},
                          'proxy_jump': {'file': jump['file'], 'line': jump['line']},
                          'proxy_command': {'file': proxy['file'], 'line': proxy['line']}})
    gaps = parser.gaps
    if not complete and not any(g['code'] != 'gaps_truncated' for g in gaps):
        _gap(gaps, 'evaluation_incomplete')
    return {
        'contract_version': CONTRACT_VERSION,
        'covered': complete and not gaps,
        'config_present': SYSTEM_CONFIG in parser.reads,
        'files_read': list(parser.reads),
        'config_fatal': parser.fatal,
        'match_exec': parser.match_exec,
        'commands': commands,
        'libraries': libraries,
        'permit_local_command': permit,
        'final_pass_possible': parser.final_pass,
        'conflicts': conflicts,
        'runs_as': 'invoking_user',
        'limits': [
            'per-user ~/.ssh/config is read first and its values take precedence',
            'ssh -F and -o options override this configuration',
            'Host and Match criteria other than Host * and Match all are reported, not evaluated',
            'values of directives this contract does not interpret are not validated',
        ],
        'gaps': gaps,
    }
