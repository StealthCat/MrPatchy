"""Pure Monit control-file program contract (roadmap F slice, #1373).

Takes captured control-file text plus the files each ``include`` pattern matched
and reports which programs monit runs: ``start``/``stop``/``restart program``
commands, ``check program ... with path`` probes and ``then exec`` actions, with
their argv, the service they belong to and any ``as uid``/``and gid`` override.
It never reads a file, expands a glob, resolves a user name or runs a command.

Lexing follows Monit 5.33.0 ``src/l.l`` (built with ``flex -i``, so keywords are
case-insensitive) and ``src/p.y``:

* ``start|stop|restart [program] [=] "`` and ``exec[ute] "`` open an argument
  list, as does ``path "`` inside a ``check program`` service. Inside it, words
  are split on space and tab, a newline is allowed, ``"`` closes the list and a
  ``'...'`` chunk is one argument (the longer of a quoted chunk and a plain word
  wins, as flex does). Quoted chunks are unquoted with ``Str_unquote``, which
  also strips leading and trailing white space and quote characters.
* ``as uid``/``and gid`` take a name or a number and ``timeout N seconds`` sets
  the command timeout. Without a uid or gid the program runs as monit's own user.
* ``subject:``, ``message:``, ``from:``/``reply-to:`` mail-format fields, URLs and ``http headers`` lists
  are consumed as l.l does, so quote characters inside them never open a string.
* ``#`` starts a comment outside an argument list. ``include`` takes a quoted or
  bare glob, and each match is lexed in place; including the control file or a
  file already being included is skipped as a loop, as monit does.

It performs no I/O and never authorizes a response action. Constructs it does
not model (unquoted program arguments, escape sequences that ``Util_handleEscapes``
rewrites, CR characters, unbalanced quotes, unobserved include patterns, extra
argument strings after a list) and over-limit input are explicit blocking gaps,
and the result is never reported complete with any of them.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'monit': '5.33.0'}
MAX_TEXT = 262144
MAX_FILES = 256
MAX_INCLUDE_DEPTH = 16
MAX_COMMANDS = 512
MAX_GAPS = 32
ARGMAX = 64  # p.y addargument: an error at ARGMAX arguments
MONIT_INT_MAX = 2**31 - 1  # l.l converts ASCII NUMBER tokens with atoi on Linux.
BLOCKING = frozenset({
    'input_malformed', 'text_too_large', 'carriage_return', 'unbalanced_quotes', 'unterminated_arguments',
    'escape_sequence', 'unquoted_arguments', 'extra_arguments', 'empty_arguments', 'too_many_arguments',
    'include_not_observed', 'include_too_deep', 'too_many_files', 'too_many_commands', 'user_option_malformed',
    'timeout_option_malformed', 'command_outside_service', 'gaps_truncated',
    'unmodelled_url', 'unmodelled_http_headers',
})
UNOBSERVED = (
    'User and group names are reported as written; monit resolves them with getpwnam/getgrnam when it parses.',
    'Whether each program exists and is executable is not checked (monit only warns).',
    'Include matches are taken in the order supplied; the collector must supply glob(3) order.',
    'Control-file syntax is not validated; monit refuses to start on a syntax error, and these programs then '
    'do not run.',
    'Programs started from the web interface, M/Monit or the monit CLI use these same definitions.',
)
NOT_A_VERDICT = 'Control-file text only. This is not a safety verdict and origin is not assessed.'
NOISE = frozenset({'as', 'and', 'with', 'within', 'without', 'is', 'are', 'for', 'via', 'on', 'only', 'using', 'use',
                   'the', 'to', 'program', 'programs', '='})
_WS = re.compile(r'[ \t;,()]+')
_ARGSTART = re.compile(r'(start|stop|restart|exec(?:ute)?|path)[ \t]*(?:program[ \t]*)?(?:=[ \t]*)?"', re.I)
_EXECSTART = re.compile(r'exec(?:ute)?[ \t]*"', re.I)
_PATHSTART = re.compile(r'path[ \t]*"', re.I)
_CHECK = re.compile(r'check[ \t]+(?:(device|filesystem|file|directory|host|network|fifo|system)'
                    r'|(program[ \t]?)|(process[ \t])?)', re.I)
_INCLUDE = re.compile(r'include', re.I)
_WORD = re.compile(r'[^\s"\';,()@:{}%]+')
_INCLUDE_QUOTED = re.compile(r'"[^"\r\n]+"|\'[^\'\r\n]+\'')
_INCLUDE_BARE = re.compile(r'[^ \t\r\n]+')
_STRIP = '"\' \t\n\v\f\r'
# INITIAL rules whose text, quotes included, never reaches the program grammar: mail-format fields, URLs and
# http headers lists. Each is matched only where flex's longest match would pick it over a plain word.
_MAILFIELD = re.compile(r'(subject|message|from|reply-to):', re.I)
_URL = re.compile(r'[a-zA-Z0-9]+://')
_HEADERS = re.compile(r'http headers[ \r\t]+', re.I)
_URL_PASSWORD = re.compile(r':[^@ ]+@')


def _gap(gaps: list[dict[str, Any]], code: str, where: dict[str, Any] | None = None, detail: str = '') -> None:
    key = (code, (where or {}).get('file'), (where or {}).get('line'))
    if any((g['code'], g.get('file'), g.get('line')) == key for g in gaps):
        return
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code, **(where or {})}
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


class _Lexer:
    """Turns control-file text into the few token kinds the program rules need."""

    def __init__(self, includes: dict[str, Any], control: str, gaps: list[dict[str, Any]]):
        self.includes, self.control, self.gaps = includes, control, gaps
        self.tokens: list[dict[str, Any]] = []
        self.stack: list[str] = []
        self.files = 0
        self.program_state = False

    def lex(self, path: str, text: Any) -> None:
        if not isinstance(text, str):
            _gap(self.gaps, 'input_malformed', {'file': path}, 'File text must be a string.')
            return
        if len(text) > MAX_TEXT:
            _gap(self.gaps, 'text_too_large', {'file': path}, f'Over {MAX_TEXT} characters; nothing was parsed.')
            return
        self.files += 1
        if self.files > MAX_FILES:
            _gap(self.gaps, 'too_many_files', {'file': path})
            return
        if '\r' in text:
            _gap(self.gaps, 'carriage_return', {'file': path}, 'CR is white space in some lexer states and part of '
                                                               'a word in others; not modelled.')
        self.stack.append(path)
        i, line, n = 0, 1, len(text)
        while i < n:
            ch = text[i]
            where = {'file': path, 'line': line}
            m = _WS.match(text, i)
            if m:
                i = m.end()
                continue
            if ch == '\n':
                line += 1
                i += 1
                continue
            if ch == '#':
                j = text.find('\n', i)
                i = n if j < 0 else j
                continue
            word = _WORD.match(text, i)
            wlen = word.end() - i if word else 0
            skipped = self._skip_context(text, i, wlen, where)
            if skipped is not None:
                line += text.count('\n', i, skipped)
                i = skipped
                continue
            arg = _ARGSTART.match(text, i)
            if arg and arg.end() - i > wlen:
                role = arg.group(1).lower()
                if role.startswith('exec'):
                    role = 'exec'
                if role == 'path' and not self.program_state:
                    # Outside check program, "path" is a keyword and the string that follows is an ordinary one.
                    self.tokens.append({'kind': 'word', 'value': 'path', **where})
                    i += 4
                    continue
                if role in ('exec', 'path') and not (_EXECSTART if role == 'exec' else _PATHSTART).match(text, i):
                    # "exec program = "..."" or "path = "..."" do not open an argument list in monit.
                    role = None
                if role is not None:
                    i, line = self._arguments(text, arg.end(), line, path, role)
                    continue
            check = _CHECK.match(text, i)
            if check and check.end() - i >= wlen:
                self.program_state = bool(check.group(2))
                kind = 'program' if check.group(2) else (check.group(1) or 'process').lower()
                self.tokens.append({'kind': 'check', 'value': kind, **where})
                i = check.end()
                continue
            inc = _INCLUDE.match(text, i)
            if inc and wlen == 7:
                j = inc.end()
                while j < n and text[j] in ' \t':
                    j += 1
                quoted, bare = _INCLUDE_QUOTED.match(text, j), _INCLUDE_BARE.match(text, j)
                if not bare:
                    _gap(self.gaps, 'input_malformed', where, 'include has no pattern.')
                    i = j
                    continue
                if quoted and quoted.end() >= bare.end():
                    # A quoted pattern goes through Str_unquote; flex prefers the longer bare match.
                    self._include(quoted.group(0).strip(_STRIP), where)
                    i = quoted.end()
                else:
                    self._include(bare.group(0), where)
                    i = bare.end()
                continue
            if ch in '"\'':
                j = text.find(ch, i + 1)
                if j < 0:
                    _gap(self.gaps, 'unbalanced_quotes', where)
                    break
                value = text[i + 1:j]
                self.tokens.append({'kind': 'string', 'value': value, **where})
                line += value.count('\n')
                i = j + 1
                continue
            if wlen:
                self.tokens.append({'kind': 'word', 'value': word.group(0), **where})
                i = word.end()
                continue
            self.tokens.append({'kind': 'char', 'value': ch, **where})
            if ch not in '=':
                self.program_state = False  # l.l's single-character rule resets check_state
            i += 1
        self.stack.pop()

    def _skip_context(self, text: str, i: int, wlen: int, where: dict[str, Any]) -> int | None:
        """Return where a mail-format field, URL or http headers list that starts at ``i`` ends, or None.

        l.l consumes ``subject:`` to ``}`` or a newline, ``message:`` to ``}`` (across lines), ``from:`` and
        ``reply-to:`` addresses (ADDRESS_COND) to ``}``, a newline, ``{`` or a control character, a URL
        (URL_COND) to white space, and an ``http headers`` list (HTTP_HEADER_COND) to ``]``. Quote characters
        inside them never open a string, so lexing them as ordinary tokens could hide real program definitions.
        """
        n = len(text)
        field = _MAILFIELD.match(text, i)
        if field and field.end() - i > wlen:
            kind, j = field.group(1).lower(), field.end()
            if kind == 'subject':
                while j < n and text[j] not in '}\n':
                    j += 1
            elif kind == 'message':
                end = text.find('}', j)
                j = n if end < 0 else end
            else:
                while j < n and text[j] not in '}{\n' and ord(text[j]) >= 0x20:
                    j += 1
                if j < n and text[j] == '\n':
                    j += 1
            return j
        url = _URL.match(text, i)
        if url and url.end() - i > wlen:
            j = url.end()
            while j < n and text[j] not in ' \r\n\t':
                j += 1
            # A tab or CR inside a path, query or fragment does not end the URL, and the user:password@ rules can
            # match across a newline; neither is modelled.
            spans_line = any(
                (m := _URL_PASSWORD.match(text, k)) is not None and any(c in m.group(0) for c in '\n\r\t')
                for k in range(url.end() - 1, j) if text[k] == ':')
            user = re.compile(r'[^:@ ]+:[^@: ]+@').match(text, url.end())
            if (j < n and text[j] in '\r\t') or spans_line or (user and any(c in user.group(0) for c in '\n\r\t')):
                _gap(self.gaps, 'unmodelled_url', where, 'The URL is not ended by a space or newline; '
                                                         'URL_COND is not modelled there.')
            return j
        headers = _HEADERS.match(text, i)
        if headers and headers.end() - i > wlen:
            end = text.find(']', headers.end())
            j = n if end < 0 else end + 1
            if end < 0 or any(c in text[headers.end():j] for c in '"\''):
                _gap(self.gaps, 'unmodelled_http_headers', where, 'Quoted or unterminated http headers lists '
                                                                  'are not modelled.')
                return None if end < 0 else j
            return j
        return None

    def _arguments(self, text: str, i: int, line: int, path: str, role: str) -> tuple[int, int]:
        start = {'file': path, 'line': line}
        argv: list[str] = []
        n = len(text)
        while True:
            if i >= n:
                _gap(self.gaps, 'unterminated_arguments', start, 'The argument list has no closing double quote.')
                break
            ch = text[i]
            if ch in ' \t\r':
                i += 1
                continue
            if ch == '\n':
                line += 1
                i += 1
                continue
            if ch == '"':
                i += 1
                break
            plain = re.compile(r'[^ \t\n"]+').match(text, i)
            plain_len = plain.end() - i
            if ch == "'":
                j = text.find("'", i + 1)
                if j >= 0 and j + 1 - i >= plain_len:
                    chunk = text[i:j + 1]
                    if '\\' in chunk:
                        _gap(self.gaps, 'escape_sequence', {'file': path, 'line': line},
                             'Util_handleEscapes rewrites backslash sequences in quoted arguments; not modelled.')
                    argv.append(chunk.strip(_STRIP))
                    line += chunk.count('\n')
                    i = j + 1
                    continue
                if plain_len == 1:
                    _gap(self.gaps, 'unbalanced_quotes', {'file': path, 'line': line})
                    i += 1
                    continue
            argv.append(plain.group(0))
            i = plain.end()
        self.tokens.append({'kind': 'arguments', 'role': role, 'argv': argv, **start})
        return i, line

    def _include(self, pattern: str, where: dict[str, Any]) -> None:
        if len(self.stack) >= MAX_INCLUDE_DEPTH:
            _gap(self.gaps, 'include_too_deep', where)
            return
        matches = self.includes.get(pattern)
        if not isinstance(matches, list):
            _gap(self.gaps, 'include_not_observed', where, f'No matches were supplied for include {pattern!r}.')
            return
        for item in matches:
            if not isinstance(item, dict) or not isinstance(item.get('path'), str):
                _gap(self.gaps, 'input_malformed', where, 'Each include match needs a path and text.')
                continue
            if not item['path'] or item['path'].endswith(('~', '/')):
                continue  # include_file skips GLOB_MARK directories and backup copies
            if item['path'] == self.control or item['path'] in self.stack:
                continue  # monit warns "Include loop detected" and skips it
            self.lex(item['path'], item.get('text'))


def _parse_monit_number(raw: str) -> int | None:
    if not raw.isascii() or not raw.isdecimal():
        return None
    digits = raw.lstrip('0') or '0'
    if len(digits) > 10:
        return None
    number = int(digits)
    return number if number <= MONIT_INT_MAX else None


def _user_options(tokens: list[dict[str, Any]], k: int, command: dict[str, Any],
                  gaps: list[dict[str, Any]]) -> int:
    while k < len(tokens):
        tok = tokens[k]
        value = str(tok.get('value', '')).lower()
        if tok['kind'] in ('word', 'char') and value in NOISE:
            k += 1
            continue
        if tok['kind'] == 'word' and value in ('uid', 'gid'):
            nxt = tokens[k + 1] if k + 1 < len(tokens) else None
            if nxt is None or nxt['kind'] not in ('word', 'string'):
                _gap(gaps, 'user_option_malformed', {'file': tok['file'], 'line': tok['line']})
                return k + 1
            raw = nxt['value'] if nxt['kind'] == 'word' else nxt['value'].strip(_STRIP)
            if nxt['kind'] == 'word' and raw.isdigit():
                number = _parse_monit_number(raw)
                if number is None:
                    _gap(gaps, 'user_option_malformed', {'file': tok['file'], 'line': tok['line']},
                         'Numeric UID and GID must fit a non-negative Monit integer.')
                else:
                    command[value] = number
            else:
                command[value] = raw
            k += 2
            continue
        if tok['kind'] == 'word' and value == 'timeout':
            nxt = tokens[k + 1] if k + 1 < len(tokens) else None
            raw = nxt['value'] if nxt is not None and nxt['kind'] == 'word' else ''
            number = _parse_monit_number(raw)
            if number is None:
                _gap(gaps, 'timeout_option_malformed', {'file': tok['file'], 'line': tok['line']},
                     'The timeout must fit a non-negative Monit integer.')
                return k + 1
            command['timeout_seconds'] = number
            k += 2
            if k < len(tokens) and str(tokens[k].get('value', '')).lower() in ('s', 'second', 'seconds'):
                k += 1
            continue
        if tok['kind'] == 'string' or (tok['kind'] == 'word' and tok['value'].startswith('/')):
            _gap(gaps, 'extra_arguments', {'file': tok['file'], 'line': tok['line']},
                 'Another string or path follows the argument list; monit may append it as an argument.')
        return k
    return k


def evaluate(payload: Any) -> dict[str, Any]:
    """Resolve the programs one Monit control file and its includes define.

    ``payload`` keys: ``control`` (``{'path', 'text'}``) and ``includes``: a map from
    each include pattern as monit passes it to glob(3) (quoted patterns unquoted)
    to the list of matched files (``{'path', 'text'}``) in glob order, with
    directories marked by a trailing ``/`` (GLOB_MARK) or left out. Matches that
    end in ``/`` or ``~`` are skipped, as monit does. An empty list means no match.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'services': [],
                              'commands': [], 'gaps': gaps, 'complete': False, 'unobserved': list(UNOBSERVED),
                              'note': NOT_A_VERDICT}
    control = payload.get('control') if isinstance(payload, dict) else None
    includes = payload.get('includes', {}) if isinstance(payload, dict) else None
    if not isinstance(control, dict) or not isinstance(control.get('path'), str) or not isinstance(includes, dict):
        _gap(gaps, 'input_malformed', detail='The payload needs control {path, text} and an includes object.')
        return result
    lexer = _Lexer(includes, control['path'], gaps)
    lexer.lex(control['path'], control.get('text'))
    tokens = lexer.tokens
    service: dict[str, Any] | None = None
    k = 0
    while k < len(tokens):
        tok = tokens[k]
        where = {'file': tok['file'], 'line': tok['line']}
        if tok['kind'] == 'check':
            nxt = tokens[k + 1] if k + 1 < len(tokens) else None
            name = nxt['value'] if nxt and nxt['kind'] in ('word', 'string') else None
            service = {'kind': tok['value'], 'name': name, **where}
            result['services'].append(service)
            k += 2 if name is not None else 1
            continue
        if tok['kind'] == 'arguments':
            role = 'check' if tok['role'] == 'path' else tok['role']
            command: dict[str, Any] = {'role': role, 'argv': tok['argv'], 'uid': None, 'gid': None,
                                       'service': service['name'] if service else None, **where}
            if not tok['argv']:
                _gap(gaps, 'empty_arguments', where)
            elif len(tok['argv']) >= ARGMAX:
                _gap(gaps, 'too_many_arguments', where)
            if service is None:
                _gap(gaps, 'command_outside_service', where)
            k = _user_options(tokens, k + 1, command, gaps)
            if len(result['commands']) >= MAX_COMMANDS:
                _gap(gaps, 'too_many_commands', where)
                break
            result['commands'].append(command)
            continue
        if tok['kind'] == 'word' and re.fullmatch(r'start|stop|restarts?|exec(ute)?|path', tok['value'], re.I):
            j = k + 1
            while j < len(tokens) and str(tokens[j].get('value', '')).lower() in NOISE:
                j += 1
            nxt = tokens[j] if j < len(tokens) else None
            if nxt and (nxt['kind'] == 'string' or (nxt['kind'] == 'word' and nxt['value'].startswith('/'))) \
                    and not (tok['value'].lower() == 'path' and not (service and service['kind'] == 'program')):
                _gap(gaps, 'unquoted_arguments', where, f'{tok["value"]} is followed by an argument that does not '
                                                        'open a double-quoted argument list; not modelled.')
        k += 1
    result['complete'] = not any(g['code'] in BLOCKING for g in gaps)
    return result
