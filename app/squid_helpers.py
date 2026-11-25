"""Pure Squid helper-program contract (roadmap F slice, #1519).

Takes captured ``squid.conf`` text plus the files each ``include`` pattern matched
and reports which helper programs squid starts: ``url_rewrite_program``,
``store_id_program``, ``auth_param <scheme> program`` and ``external_acl_type``
helpers, with their executable, argv and the account squid runs them as. It never
reads a file, expands a glob, resolves a user name or runs a command.

Ported from Squid 6.10:

* ``cache_cf.cc`` ``parseOneConfigFile``: each physical line is cut at its first
  CR, stripped of leading white space and skipped when it starts with ``#`` or is
  empty. A line ending in ``\\`` continues onto the next non-comment line, whose
  leading white space is dropped. Trailing white space is trimmed and the
  ``${service_name}``, ``${process_name}`` and ``${process_number}`` macros are
  replaced. ``if``/``else``/``endif`` are tracked per file, and only the innermost
  ``if`` state gates a line. ``include`` globs each word with ``GLOB_APPEND`` and
  reads the matches in order, nested at most 16 deep.
* ``parse_line`` matches the directive name case-sensitively up to the first
  space, tab, CR or LF.
* ``ConfigParser::TokenParse``/``UnQuote`` split the values. ``#`` at the start of
  a token ends the list, and ``"``/``'`` quoting (with ``\\r``, ``\\n`` and ``\\t``
  escapes) applies to wordlists and, once ``configuration_includes_quoted_values
  on`` is seen, to every token. That setting also turns on strict unquoted-token
  checking. ``parameters("file")`` reads tokens from a file.
* ``parse_wordlist`` appends: repeated ``url_rewrite_program`` and
  ``store_id_program`` lines (and their ``redirect_program`` and
  ``storeurl_rewrite_program`` aliases) extend one command line.
  ``auth_param <scheme> program`` replaces the scheme's earlier command, and each
  ``external_acl_type`` line adds a helper after its options and ``%`` format tokens.
* ``helper.cc``: argv[0] is ``(basename)``, followed by the remaining words up to
  64 entries in all. ``ipc.cc`` runs the executable with execvp, so a name without
  ``/`` is looked up in PATH.
* ``tools.cc`` ``leave_suid``: when squid starts as root, helpers run as
  ``cache_effective_user`` (last value wins, otherwise the compiled-in default)
  and ``cache_effective_group`` (otherwise that user's primary group).

It performs no I/O and never authorizes a response action. Constructs it does
not model (runtime macros without a supplied process context, ``parameters()``
files, malformed quoting, strict-mode token errors, unknown auth schemes,
unobserved or unmatched includes, unbalanced ``if`` blocks, NUL bytes, physical
lines that fgets would split, helper directives outside this slice) and
over-limit input are explicit blocking gaps. A result with any of them is never
reported complete.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'squid': '6.10'}
MAX_TEXT = 262144
MAX_FILES = 256
MAX_INCLUDE_DEPTH = 16  # parseOneConfigFile: depth > 16 is fatal
MAX_GAPS = 32
MAX_WORDS = 4096
BUFSIZ = 8192  # fgets(config_input_line, BUFSIZ, fp)
CONFIG_LINE_LIMIT = 2048  # UnQuote's LOCAL_ARRAY
HELPER_MAX_ARGS = 64
W_SPACE = ' \t\n\r'
C_SPACE = ' \t\n\v\f\r'  # xisspace
AUTH_SCHEMES = ('basic', 'digest', 'negotiate', 'ntlm')
MACROS = ('${service_name}', '${process_name}', '${process_number}')
REDIRECT = ('url_rewrite_program', 'redirect_program')
STORE_ID = ('store_id_program', 'storeurl_rewrite_program')
UNMODELLED_HELPERS = frozenset({'sslcrtd_program', 'sslcrtvalidator_program', 'logfile_daemon', 'unlinkd_program',
                                'diskd_program', 'pinger_program', 'sslpassword_program', 'cache_dns_program'})
EXT_ACL_OPTION_PREFIXES = ('ttl=', 'negative_ttl=', 'children=', 'children-max=', 'children-startup=',
                           'children-idle=', 'concurrency=', 'queue-size=', 'cache=', 'grace=')
EXT_ACL_OPTION_WORDS = ('protocol=2.5', 'protocol=3.0', 'quote=url', 'quote=shell', 'ipv4', 'ipv6')
STRICT_CHARS = frozenset('.,()-=_/:+')
BLOCKING = frozenset({
    'input_malformed', 'text_too_large', 'nul_byte', 'line_too_long', 'too_many_files', 'too_many_words',
    'include_not_observed', 'include_no_match', 'include_too_deep', 'include_quoting', 'runtime_macro',
    'if_expression_invalid', 'else_without_if', 'endif_without_if', 'unterminated_if', 'quoted_token_malformed',
    'unknown_cfg_function', 'parameters_function', 'strict_mode_token', 'directive_malformed',
    'unknown_auth_scheme', 'empty_program', 'external_acl_malformed', 'unmodelled_helper_directive',
    'gaps_truncated',
})
UNOBSERVED = (
    'User and group names are reported as written; squid resolves them with getpwnam/getgrnam at startup.',
    'The compiled-in cache_effective_user default (configure --with-default-user; "nobody" upstream, "proxy" on '
    'Debian and Ubuntu) is not observed.',
    'Helpers run as the effective user only when squid starts as root; otherwise they run as the starting user.',
    'Helpers that squid starts without a config line (unlinkd for ufs/aufs cache_dirs, pinger, the logfile '
    'daemon) are outside this slice.',
    'Whether each executable exists, and which file PATH resolves a bare name to, is not checked.',
    'Include matches are taken in the order supplied; the collector must supply glob(3) order per pattern.',
    'Helper counts (children, startup, idle) are not modelled; a configured helper may start on demand.',
    'Other syntax is not validated; squid refuses to start on a fatal configuration error, and then no helper runs.',
    'Each SMP worker parses the configuration with its own process macros and starts its own helpers.',
    'Locations are physical lines; "#line" directives that rewrite squid\'s own messages are ignored.',
)
NOT_A_VERDICT = 'Configuration text only. This is not a safety verdict and origin is not assessed.'


def _gap(gaps: list[dict[str, Any]], code: str, where: dict[str, Any] | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if not any(g['code'] == 'gaps_truncated' for g in gaps):
            gaps.append({'code': 'gaps_truncated', 'detail': 'More gaps were found than are listed.'})
        return
    gap: dict[str, Any] = {'code': code}
    if where:
        gap.update(where)
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def _strtol_full(text: str) -> int | None:
    """``StrToInt``: strtol(str, &end, 0) consuming the whole string."""
    s = text.lstrip(C_SPACE)
    sign = 1
    if s[:1] in ('+', '-'):
        sign = -1 if s[0] == '-' else 1
        s = s[1:]
    if s[:2].lower() == '0x' and len(s) > 2:
        digits, base = s[2:], 16
    elif s[:1] == '0' and len(s) > 1:
        digits, base = s[1:], 8
    else:
        digits, base = s, 10
    allowed = {8: '01234567', 10: '0123456789', 16: '0123456789abcdefABCDEF'}[base]
    if not digits or any(c not in allowed for c in digits):
        return None
    return sign * int(digits, base)


class _Tokens:
    """``ConfigParser`` state for the rest of one directive line."""

    def __init__(self, rest: str | None, state: '_Parser', where: dict[str, Any]):
        self.text = rest or ''
        self.pos = 0
        self.state = state
        self.where = where
        self.failed = False

    def next(self, quoted: bool = False) -> str | None:
        if self.failed:
            return None
        recognize = quoted or self.state.quoted_values
        text = self.text
        pos = self.pos
        if pos >= len(text):
            return None
        while pos < len(text) and text[pos] in W_SPACE:
            pos += 1
        if pos >= len(text) or text[pos] == '#':
            self.pos = pos
            return None
        if recognize and text[pos] in '"\'':
            return self._unquote(pos)
        start = pos
        sep = W_SPACE if (not recognize or text[pos] == '(') else W_SPACE + '('
        while pos < len(text) and text[pos] not in sep:
            pos += 1
        token = text[start:pos]
        if recognize and pos < len(text) and text[pos] == '(':
            if len(token) <= len('parameters') and 'parameters'.startswith(token):
                _gap(self.state.gaps, 'parameters_function', self.where,
                     'parameters("file") reads further tokens from a file that was not observed.')
            else:
                _gap(self.state.gaps, 'unknown_cfg_function', self.where, f'{token}( is fatal in squid.')
            self.failed = True
            return None
        if self.state.strict and token:
            is_number = True
            for i, ch in enumerate(token):
                valid = (ch.isascii() and ch.isalnum()) or ch in STRICT_CHARS or (
                    is_number and ch == '%' and i == len(token) - 1)
                if not ch.isdigit():
                    is_number = False
                if not valid:
                    _gap(self.state.gaps, 'strict_mode_token', self.where,
                         f'Unquoted token {token!r} has a character squid rejects in strict mode.')
                    self.failed = True
                    return None
        if pos < len(text) and text[pos] != '#':
            pos += 1
        self.pos = pos
        return token or None

    def _unquote(self, pos: int) -> str | None:
        text = self.text
        quote = text[pos]
        s = pos + 1
        out: list[str] = []
        error = ''
        while s < len(text) and text[s] != quote and not error and len(out) < CONFIG_LINE_LIMIT:
            ch = text[s]
            if ch == '\\':
                s += 1
                nxt = text[s] if s < len(text) else ''
                if nxt == '':
                    error = 'a backslash ends the line inside a quoted token'
                    break
                if nxt in 'rnt':
                    out.append({'r': '\r', 'n': '\n', 't': '\t'}[nxt])
                else:
                    if nxt.isascii() and nxt.isalnum():
                        error = 'unsupported escape sequence'
                    out.append(nxt)
            else:
                out.append(ch)
            s += 1
        if not error and len(out) >= CONFIG_LINE_LIMIT:
            error = 'quoted token reaches the 2048-byte limit'
        if not error and (s >= len(text) or text[s] != quote):
            error = 'missing closing quote'
        if not error and s + 1 < len(text) and text[s + 1] not in W_SPACE + '()#':
            error = 'no space after the closing quote'
        if error:
            _gap(self.state.gaps, 'quoted_token_malformed', self.where, error)
            self.failed = True
            return None
        self.pos = s + 1
        return ''.join(out)

    def wordlist(self) -> list[str]:
        words: list[str] = []
        while (token := self.next(quoted=True)) is not None:
            words.append(token)
        return words


class _Parser:
    def __init__(self, includes: dict[str, Any], process: dict[str, Any] | None, gaps: list[dict[str, Any]]):
        self.includes = includes
        self.process = process
        self.gaps = gaps
        self.files = 0
        self.words = 0
        self.quoted_values = False
        self.strict = False
        self.redirect: dict[str, Any] | None = None
        self.store_id: dict[str, Any] | None = None
        self.auth: dict[str, dict[str, Any]] = {}
        self.external: list[dict[str, Any]] = []
        self.user: dict[str, Any] | None = None
        self.group: dict[str, Any] | None = None
        self.stopped = False

    def read(self, path: str, text: Any, depth: int) -> None:
        if self.stopped:
            return
        where = {'file': path}
        if depth > MAX_INCLUDE_DEPTH:
            _gap(self.gaps, 'include_too_deep', where)
            return
        if not isinstance(text, str):
            _gap(self.gaps, 'input_malformed', where, 'File text must be a string.')
            return
        if len(text) > MAX_TEXT:
            _gap(self.gaps, 'text_too_large', where)
            return
        self.files += 1
        if self.files > MAX_FILES:
            _gap(self.gaps, 'too_many_files', where)
            self.stopped = True
            return
        if '\x00' in text:
            _gap(self.gaps, 'nul_byte', where, 'fgets and the string handling stop at NUL; not modelled.')
            return
        physical = text.split('\n')
        if physical and physical[-1] == '':
            physical.pop()
        if_states: list[bool] = []
        pending = ''
        start_line = 0
        for number, raw in enumerate(physical, start=1):
            if self.stopped:
                return
            if len(raw) + 1 >= BUFSIZ:
                _gap(self.gaps, 'line_too_long', {'file': path, 'line': number},
                     'fgets would split this line into several configuration lines.')
                continue
            line = raw.split('\r', 1)[0].lstrip(C_SPACE)
            if not line or line[0] == '#':
                continue
            if not pending:
                start_line = number
                pending = line
            else:
                pending += line.lstrip(C_SPACE)
            if pending.endswith('\\'):
                pending = pending[:-1]
                continue
            logical = pending.rstrip(C_SPACE)
            pending = ''
            loc = {'file': path, 'line': start_line}
            logical = self._macros(logical, loc)
            if (expr := _statement(logical, 'if')) is not None:
                if_states.append(self._eval(expr, loc))
            elif _statement(logical, 'endif') is not None:
                if if_states:
                    if_states.pop()
                else:
                    _gap(self.gaps, 'endif_without_if', loc)
            elif _statement(logical, 'else') is not None:
                if if_states:
                    if_states[-1] = not if_states[-1]
                else:
                    _gap(self.gaps, 'else_without_if', loc)
            elif not if_states or if_states[-1]:
                if len(logical) >= 9 and logical.startswith('include') and logical[7] in C_SPACE:
                    self._include(logical[8:], loc, depth)
                else:
                    self._directive(logical, loc)
        if if_states:
            _gap(self.gaps, 'unterminated_if', where, 'An if block has no endif; squid refuses to start.')

    def _macros(self, line: str, loc: dict[str, Any]) -> str:
        present = [m for m in MACROS if m in line]
        if not present:
            return line
        if not isinstance(self.process, dict):
            _gap(self.gaps, 'runtime_macro', loc, 'The line uses per-process macros and no process context was '
                                                  'supplied.')
            return line
        values = {'${service_name}': self.process.get('service_name'),
                  '${process_name}': self.process.get('process_name'),
                  '${process_number}': self.process.get('process_number')}
        for macro in MACROS:
            value = values[macro]
            if macro not in line:
                continue
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                _gap(self.gaps, 'runtime_macro', loc, f'The process context has no usable value for {macro}.')
                continue
            line = line.replace(macro, str(value))
        return line

    def _eval(self, expr: str, loc: dict[str, Any]) -> bool:
        if expr == 'true':
            return True
        if expr == 'false':
            return False
        if '=' in expr:
            left, right = expr.split('=', 1)
            a = _strtol_full(left.rstrip(C_SPACE))
            b = _strtol_full(right.lstrip(C_SPACE))
            if a is not None and b is not None:
                return a == b
        _gap(self.gaps, 'if_expression_invalid', loc, f'squid cannot evaluate {expr!r} and refuses to start.')
        return False

    def _include(self, rest: str, loc: dict[str, Any], depth: int) -> None:
        if '"' in rest or '\\' in rest:
            _gap(self.gaps, 'include_quoting', loc, 'strwordtok quoting and escapes in include paths are not '
                                                    'modelled.')
            return
        matches: list[Any] = []
        for pattern in rest.split():
            found = self.includes.get(pattern)
            if found is None:
                _gap(self.gaps, 'include_not_observed', {**loc, 'pattern': pattern})
                return
            if not isinstance(found, list):
                _gap(self.gaps, 'input_malformed', loc, 'Include matches must be a list.')
                return
            if not found:
                _gap(self.gaps, 'include_no_match', {**loc, 'pattern': pattern},
                     'glob(3) found nothing; squid refuses to start.')
                return
            matches.extend(found)
        for match in matches:
            if not isinstance(match, dict) or not isinstance(match.get('path'), str):
                _gap(self.gaps, 'input_malformed', loc, 'Each include match needs {path, text}.')
                return
            self.read(match['path'], match.get('text'), depth + 1)

    def _count(self, words: list[str], loc: dict[str, Any]) -> bool:
        self.words += len(words)
        if self.words > MAX_WORDS:
            _gap(self.gaps, 'too_many_words', loc)
            self.stopped = True
            return False
        return True

    def _directive(self, line: str, loc: dict[str, Any]) -> None:
        cut = next((i for i, ch in enumerate(line) if ch in W_SPACE), None)
        name = line if cut is None else line[:cut]
        tokens = _Tokens(None if cut is None else line[cut + 1:], self, loc)
        if name in REDIRECT or name in STORE_ID:
            words = tokens.wordlist()
            if not self._count(words, loc):
                return
            kind = 'url_rewrite' if name in REDIRECT else 'store_id'
            current = self.redirect if kind == 'url_rewrite' else self.store_id
            if current is None:
                current = {'kind': kind, 'name': None, 'words': [], 'lines': []}
                if kind == 'url_rewrite':
                    self.redirect = current
                else:
                    self.store_id = current
            current['words'].extend(words)
            current['lines'].append({**loc, 'directive': name})
        elif name == 'auth_param':
            scheme = tokens.next()
            param = tokens.next()
            if scheme is None or param is None:
                if not tokens.failed:
                    _gap(self.gaps, 'directive_malformed', loc, 'auth_param needs a scheme and a parameter.')
                return
            if scheme not in AUTH_SCHEMES:
                _gap(self.gaps, 'unknown_auth_scheme', loc, f'Unknown authentication scheme {scheme!r} is fatal.')
                return
            if param != 'program':
                return
            words = tokens.wordlist()
            if not self._count(words, loc):
                return
            if not words:
                if not tokens.failed:
                    _gap(self.gaps, 'empty_program', loc, 'auth_param program without a command is not modelled.')
                return
            self.auth[scheme] = {'kind': 'auth', 'name': scheme, 'words': words,
                                 'lines': [{**loc, 'directive': name}]}
        elif name == 'external_acl_type':
            self._external(tokens, loc)
        elif name in ('cache_effective_user', 'cache_effective_group'):
            value = tokens.next()
            if value is None:
                if not tokens.failed:
                    _gap(self.gaps, 'directive_malformed', loc, f'{name} needs a value.')
                return
            record = {'name': value, **loc}
            if name == 'cache_effective_user':
                self.user = record
            else:
                self.group = record
        elif name == 'configuration_includes_quoted_values':
            value = tokens.next()
            if value in ('on', 'enable'):
                self.quoted_values = self.strict = True
            elif value in ('off', 'disable'):
                self.quoted_values = self.strict = False
            elif not tokens.failed:
                _gap(self.gaps, 'directive_malformed', loc, 'Boolean options can only be on or off.')
        elif name in UNMODELLED_HELPERS:
            _gap(self.gaps, 'unmodelled_helper_directive', {**loc, 'directive': name},
                 'This helper directive is outside this contract slice.')

    def _external(self, tokens: _Tokens, loc: dict[str, Any]) -> None:
        acl_name = tokens.next()
        if acl_name is None:
            if not tokens.failed:
                _gap(self.gaps, 'external_acl_malformed', loc, 'external_acl_type needs a name.')
            return
        token = tokens.next()
        options: list[str] = []
        while token is not None and (token.startswith(EXT_ACL_OPTION_PREFIXES) or token in EXT_ACL_OPTION_WORDS):
            options.append(token)
            token = tokens.next()
        formats: list[str] = []
        while token is not None and token.startswith('%'):
            formats.append(token)
            token = tokens.next()
        if tokens.failed:
            return
        if not formats or token is None:
            _gap(self.gaps, 'external_acl_malformed', loc,
                 'external_acl_type needs at least one % format token and a helper; squid refuses to start.')
            return
        words = [token] + tokens.wordlist()
        if tokens.failed or not self._count(words, loc):
            return
        self.external.append({'kind': 'external_acl', 'name': acl_name, 'words': words, 'options': options,
                              'format': formats, 'lines': [{**loc, 'directive': 'external_acl_type'}]})


def _statement(line: str, statement: str) -> str | None:
    """``FindStatement``: the expression after ``statement`` or None."""
    text = line.lstrip(C_SPACE)
    if not text.startswith(statement):
        return None
    rest = text[len(statement):]
    if rest == '':
        return ''
    if rest[0] in C_SPACE:
        return rest.lstrip(C_SPACE)
    return None


def _helper(entry: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    words = entry['words']
    if not words:
        return None
    executable = words[0]
    shortname = executable.rsplit('/', 1)[-1]
    argv = [f'({shortname})'] + words[1:HELPER_MAX_ARGS]
    helper = {'kind': entry['kind'], 'name': entry['name'], 'executable': executable,
              'path_lookup': '/' not in executable, 'argv': argv, 'arguments_dropped': max(0, len(words) - 64),
              'lines': entry['lines']}
    if entry['kind'] == 'external_acl':
        helper['options'] = entry['options']
        helper['format'] = entry['format']
    return helper


def evaluate(payload: Any) -> dict[str, Any]:
    """Resolve the helper programs one ``squid.conf`` and its includes configure.

    ``payload`` keys: ``config`` (``{'path', 'text'}``), ``includes``: a map from
    each include word as squid passes it to glob(3) to the list of matched files
    (``{'path', 'text'}``) in glob order (an empty list means no match), and
    optionally ``process`` (``{'service_name', 'process_name', 'process_number'}``)
    for one squid process's macro values.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'helpers': [],
                              'run_as': None, 'gaps': gaps, 'complete': False, 'unobserved': list(UNOBSERVED),
                              'note': NOT_A_VERDICT}
    config = payload.get('config') if isinstance(payload, dict) else None
    includes = payload.get('includes', {}) if isinstance(payload, dict) else None
    process = payload.get('process') if isinstance(payload, dict) else None
    if not isinstance(config, dict) or not isinstance(config.get('path'), str) or not isinstance(includes, dict) \
            or (process is not None and not isinstance(process, dict)):
        _gap(gaps, 'input_malformed', detail='The payload needs config {path, text}, an includes object and an '
                                             'optional process object.')
        return result
    parser = _Parser(includes, process, gaps)
    parser.read(config['path'], config.get('text'), 0)
    entries = [e for e in (parser.redirect, parser.store_id) if e is not None]
    entries += list(parser.auth.values()) + parser.external
    for entry in entries:
        helper = _helper(entry, gaps)
        if helper is not None:
            result['helpers'].append(helper)
    user = parser.user
    group = parser.group
    result['run_as'] = {
        'when_started_as_root': True,
        'user': user['name'] if user else None,
        'user_source': 'cache_effective_user' if user else 'compiled_default',
        'group': group['name'] if group else None,
        'group_source': 'cache_effective_group' if group else 'user_primary_group',
        'lines': [r for r in (user, group) if r],
    }
    result['complete'] = not any(g['code'] in BLOCKING for g in gaps)
    return result
