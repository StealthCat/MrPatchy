"""Pure Monit control-file program contract (roadmap F slice, #1611).

Takes captured monit control-file text (``/etc/monit/monitrc`` on Debian,
``/etc/monitrc`` on RHEL) and reports which administrator-configured programs
monit runs, for which service, with which argv and as which account:

* ``start program``, ``stop program`` and ``restart program`` service commands;
* ``exec`` actions (``if ... then exec "..."`` and ``else if ... then exec``);
* ``check program NAME with path "..."`` status programs.

The contract never reads a file, resolves an account or runs a command. It is
ported from the monit 5.33.0 flex scanner ``src/l.l`` and the parser actions in
``src/p.y``:

* Outside a command, ``#`` at the start of a token begins a comment to the end
  of the line, and double- or single-quoted strings are single tokens, so a
  ``#`` or keyword inside quotes is not a comment or a statement.
* ``startarg``/``stoparg``/``restartarg`` (``start{ws}?(program)?{ws}?([=]{ws}?)?["]``)
  and ``execarg`` (``exec(ute)?{ws}?["]``) switch to ``ARGUMENT_COND``, as does
  ``path{ws}?["]`` inside a ``check program`` service. Keywords are case-sensitive.
* In ``ARGUMENT_COND`` spaces, tabs, carriage returns and newlines separate
  words and the next ``"`` ends the command. A word that starts with ``'`` and
  has a closing ``'`` is one argument (it may contain spaces, newlines and
  ``"``); it loses surrounding quotes and whitespace (``Str_unquote``) and its
  ``\\n``, ``\\t``, ``\\r``, ``\\ `` and ``\\\\`` escapes (``Util_handleEscapes``).
  A longer unquoted run wins (flex longest match), so ``a'b'c`` stays literal.
  Unquoted words are not unescaped. An unbalanced ``'`` rejects the file.
* ``uid``/``gid`` options after a command set the account; the words ``as``,
  ``and`` and ``with`` are ignored by the scanner. Without ``uid`` a command
  runs as the monit daemon's own account.
* ``check[ \\t]+(process[ \\t])?`` matches before ``program``, so a bare
  ``check NAME`` is a process check.

``include`` statements, an unknown daemon account, NUL bytes, over-limit input,
unbalanced quotes, unterminated commands and the ``\\0`` escapes that monit
handles inconsistently are explicit blocking gaps. A result with any of them is
never ``complete``. Whether monit's grammar accepts the rest of the file is
not evaluated, so a reported command may never run when monit rejects the file
(a false positive, never a missed command). ``origin`` is always
``not_assessed`` and ``authorizes_response`` is always false.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'monit': '5.33.0'}
MAX_TEXT = 1048576
MAX_COMMANDS = 256
CONTROL_FILES = ('/etc/monit/monitrc', '/etc/monitrc')

_WS = r'[ \r\t]'
_ARG_START = re.compile(r'(start|stop|restart)' + _WS + r'*(?:program)?' + _WS + r'*(?:=' + _WS + r'*)?"')
_EXEC_START = re.compile(r'exec(?:ute)?' + _WS + r'*"')
_PATH_START = re.compile(r'path' + _WS + r'*"')
_CHECK = re.compile(r'check[ \t]+(?:(process|program|filesystem|file|directory|host|network|fifo|system|device)'
                    r'(?=[ \t\r\n]|$))?')
_WORD = re.compile(r'[^ \r\t\n;,()"\']+')
_SKIP = re.compile(r'[ \r\t;,()]+')
_IGNORED = frozenset({'as', 'and', 'with', 'is', 'are', 'for', 'via', 'the', 'to', 'using', 'use'})
_ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', ' ': ' ', '\\': '\\'}


class _Gap(Exception):
    def __init__(self, gap: dict[str, Any]):
        super().__init__(gap['reason'])
        self.gap = gap


def _unescape(text: str, line: int) -> str:
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                i += 2
                continue
            if nxt == '0':
                raise _Gap({'kind': 'unsupported_escape', 'line': line, 'blocking': True,
                            'reason': 'A \\0 escape in a quoted argument is handled inconsistently by monit.'})
        out.append(ch)
        i += 1
    return out and ''.join(out) or ''


def _unquote(text: str) -> str:
    return text.strip('"\' \t\n\r\f\v')


def _account(started_as: str | None, uid: str | None, gid: str | None) -> dict[str, Any]:
    if uid is None and gid is None:
        return {'user': started_as, 'group': None, 'source': 'monit_daemon'}
    return {'user': uid if uid is not None else started_as, 'group': gid, 'source': 'option'}


def _scan(text: str, started_as: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    commands: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    includes: list[str] = []
    service: dict[str, Any] | None = None
    i, line, n = 0, 1, len(text)
    expect_name = False

    def skip_ws(pos: int) -> int:
        m = _SKIP.match(text, pos)
        return m.end() if m else pos

    while i < n:
        ch = text[i]
        if ch == '\n':
            line += 1
            i += 1
            continue
        m = _SKIP.match(text, i)
        if m:
            i = m.end()
            continue
        if ch == '#':
            end = text.find('\n', i)
            i = n if end < 0 else end
            continue
        if ch in '"\'':
            end = text.find(ch, i + 1)
            if end < 0:
                raise _Gap({'kind': 'unbalanced_quote', 'line': line, 'blocking': True,
                            'reason': 'An unbalanced quote makes monit reject the control file.'})
            token = text[i:end + 1]
            if expect_name and service is not None:
                service['name'] = _unescape(_unquote(token), line)
                expect_name = False
            line += token.count('\n')
            i = end + 1
            continue
        program_state = service is not None and service['type'] == 'program'
        start = _ARG_START.match(text, i)
        exec_m = _EXEC_START.match(text, i)
        path_m = _PATH_START.match(text, i) if program_state else None
        arg = start or exec_m or path_m
        if arg is not None:
            kind = start.group(1) if start else ('exec' if exec_m else 'check_program')
            cmd_line = line
            argv, i, line = _arguments(text, arg.end(), line)
            uid = gid = None
            j = i
            while True:
                j = skip_ws(j)
                w = _WORD.match(text, j)
                if not w or w.group(0) not in _IGNORED | {'uid', 'gid'}:
                    break
                if w.group(0) in ('uid', 'gid'):
                    k = skip_ws(w.end())
                    if k < n and text[k] in '"\'':
                        end = text.find(text[k], k + 1)
                        if end < 0:
                            break
                        value = _unescape(_unquote(text[k:end + 1]), line)
                        nxt = end + 1
                    else:
                        v = _WORD.match(text, k)
                        if not v:
                            break
                        value, nxt = v.group(0), v.end()
                    if w.group(0) == 'uid':
                        uid = value
                    else:
                        gid = value
                    j = nxt
                else:
                    j = w.end()
            if len(commands) >= MAX_COMMANDS:
                raise _Gap({'kind': 'over_limit', 'line': cmd_line, 'blocking': True,
                            'reason': f'More than {MAX_COMMANDS} commands were found.'})
            commands.append({
                'service': None if service is None else service.get('name'),
                'service_type': None if service is None else service['type'],
                'kind': kind, 'line': cmd_line, 'argv': argv,
                'program': argv[0] if argv else None,
                'account': _account(started_as, uid, gid),
                'invocation': 'execv',
            })
            if not argv:
                gaps.append({'kind': 'empty_command', 'line': cmd_line, 'blocking': True,
                             'reason': 'A command with no program makes monit reject the control file.'})
            continue
        check = _CHECK.match(text, i)
        if check is not None:
            service = {'type': check.group(1) or 'process', 'name': None}
            if service['type'] == 'device':
                service['type'] = 'filesystem'
            expect_name = True
            i = check.end()
            continue
        w = _WORD.match(text, i)
        if w is None:
            i += 1
            continue
        word = w.group(0)
        if word == 'include':
            k = skip_ws(w.end())
            end = text.find('\n', k)
            target = text[k:n if end < 0 else end].strip()
            includes.append(_unquote(target))
            gaps.append({'kind': 'include_not_resolved', 'line': line, 'blocking': True, 'path': _unquote(target),
                         'reason': 'Files named by include statements are not resolved, so their commands are '
                                   'not reported.'})
        elif expect_name and service is not None:
            service['name'] = word
            expect_name = False
        i = w.end()
    return commands, gaps, includes


def _arguments(text: str, i: int, line: int) -> tuple[list[str], int, int]:
    argv: list[str] = []
    n = len(text)
    start_line = line
    while True:
        if i >= n:
            raise _Gap({'kind': 'unterminated_command', 'line': start_line, 'blocking': True,
                        'reason': 'A command has no closing double quote.'})
        ch = text[i]
        if ch in ' \t\r':
            i += 1
            continue
        if ch == '\n':
            line += 1
            i += 1
            continue
        if ch == '"':
            return argv, i + 1, line
        bare = re.compile(r'[^ \t\n"]+').match(text, i)
        bare_len = bare.end() - i if bare else 0
        if ch == "'":
            end = text.find("'", i + 1)
            if end < 0 and bare_len <= 1:
                raise _Gap({'kind': 'unbalanced_quote', 'line': line, 'blocking': True,
                            'reason': 'An unbalanced quote makes monit reject the control file.'})
            if end >= 0 and end + 1 - i >= bare_len:
                token = text[i:end + 1]
                argv.append(_unescape(_unquote(token), line))
                line += token.count('\n')
                i = end + 1
                continue
        argv.append(bare.group(0))
        i = bare.end()


def resolve(*, control_file: str | bytes | None = None, path: str = CONTROL_FILES[0],
            daemon_account: str | None = None) -> dict[str, Any]:
    """Report the programs a monit control file makes monit run.

    ``daemon_account`` is the account monit itself runs as (``root`` for the
    packaged service). ``None`` means it was not observed.
    """
    gaps: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    includes: list[str] = []
    if control_file is None:
        gaps.append({'kind': 'configuration_not_observed', 'path': path, 'blocking': True,
                     'reason': 'The monit control file was not observed.'})
    else:
        raw = control_file.encode('utf-8', 'surrogateescape') if isinstance(control_file, str) else control_file
        if len(raw) > MAX_TEXT:
            gaps.append({'kind': 'over_limit', 'path': path, 'blocking': True,
                         'reason': f'The control file is larger than {MAX_TEXT} bytes.'})
        elif b'\0' in raw:
            gaps.append({'kind': 'nul_byte', 'path': path, 'blocking': True,
                         'reason': 'The control file contains a NUL byte.'})
        else:
            try:
                commands, scan_gaps, includes = _scan(raw.decode('utf-8', 'surrogateescape'), daemon_account)
                gaps.extend(scan_gaps)
            except _Gap as exc:
                commands = []
                gaps.append({**exc.gap, 'path': path})
    if daemon_account is None and commands:
        gaps.append({'kind': 'daemon_account_unknown', 'blocking': True,
                     'reason': 'The account monit runs as was not observed, so commands without uid have an '
                               'unknown account.'})
    return {
        'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'path': path,
        'commands': commands, 'includes': includes, 'gaps': gaps,
        'complete': not any(g.get('blocking') for g in gaps),
        'limits': ['Whether monit grammar accepts the rest of the file is not evaluated; a reported command may '
                   'never run if monit rejects the file.',
                   'Programs are not checked for existence or executability, and uid/gid names are not resolved.'],
        'origin': 'not_assessed', 'authorizes_response': False,
    }
