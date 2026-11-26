"""Pure HAProxy program-section contract (roadmap F slice, #1555).

Takes the captured HAProxy configuration files in load order and reports which
``program`` sections the master process starts: each program's ``command`` argv,
the ``user``/``group`` it switches to and whether it restarts on reload. In
master-worker mode the master forks these programs itself. Ubuntu and Debian
start it with ``-Ws``, as root. The global ``user``/``group`` settings drop
privileges for workers only, so a program without its own ``user`` runs with the
master's identity. The contract never reads a file, resolves a user or group,
evaluates the environment or runs a command.

Ported from HAProxy 2.8:

* ``cfgparse.c`` ``readcfgfile``: lines are read with a growing buffer, so they
  have no length limit. A NUL byte or a last line without LF is fatal. Leading
  ``isspace`` characters are skipped, a ``[`` line is a scope directive and every
  other line is split by ``parse_line``. ``.if``/``.elif``/``.else``/``.endif``
  nest at most 100 deep. ``.alert`` aborts, and ``.warning``, ``.notice`` and
  ``.diag`` take one argument. ``no`` and ``default`` prefixes shift the words
  left, and only ``option``, ``log`` and a few global flags accept them. A
  registered section keyword switches the section, and section state starts empty
  in every file.
* ``tools.c`` ``parse_line`` with ``PARSE_OPT_ENV | DQUOTE | SQUOTE | BKSLASH |
  SHARP | WORD_EXPAND``. Words split on unquoted ``isspace`` and ``#`` starts a
  comment. ``"``/``'`` quote, and backslash handles ``\\ `` ``\\\\`` ``\\t``
  ``\\n`` ``\\r`` ``\\#`` ``\\'`` ``\\"`` ``\\$`` and ``\\xHH`` (anything else
  stays literal). ``$VAR``/``${VAR}`` expand inside double quotes only. At most
  64 words are allowed, and a trailing empty word is not counted.
* ``cfgcond.c``: a ``.if`` term that ``strtol`` reads completely is a constant
  condition.
* ``mworker-prog.c`` ``cfg_parse_program``: ``program <id>`` (a duplicate id is
  fatal); the last ``command`` replaces earlier ones, and its argv stops at the
  first empty word; ``[no] option start-on-reload`` (on by default);
  ``user``/``group``, where the first value wins and a repeat only alerts.
  ``cfg_program_postparser`` rejects a program without a command and a program
  section outside master-worker mode. ``mworker_ext_launch_all`` drops
  supplementary groups and calls setgid when a group is set, then setuid when a
  user is set, then ``execvp(command[0], command)``.

It performs no I/O and never authorizes a response action. Constructs it does not
model (environment variables, ``.if`` conditions other than integer constants,
scope directives, ``external-check`` health-check commands) and configuration
errors that stop HAProxy from starting are explicit blocking gaps, as is
over-limit input. A result with any of them is never reported complete.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'haproxy': '2.8.30'}
MAX_TEXT = 262144
MAX_FILES = 256
MAX_GAPS = 32
MAX_PROGRAMS = 256
MAX_LINE_ARGS = 64  # include/haproxy/defaults.h
MAXNESTEDCONDS = 100  # include/haproxy/cfgcond-t.h
C_SPACE = ' \t\n\v\f\r'  # isspace() in the C locale
HEX = '0123456789abcdefABCDEF'
SECTIONS = frozenset({
    'cache', 'listen', 'frontend', 'backend', 'defaults', 'global', 'userlist', 'peers', 'mailers',
    'namespace_list', 'fcgi-app', 'http-errors', 'log-forward', 'program', 'resolvers', 'ring',
})
PROXY_SECTIONS = frozenset({'listen', 'frontend', 'backend', 'defaults'})
KWM_ALLOWED = frozenset({'option', 'log', 'busy-polling', 'set-dumpable', 'strict-limits',
                         'insecure-fork-wanted', 'numa-cpu-mapping'})
# strtol(in, &end, 0) consuming the whole term.
STRTOL_FULL = re.compile(r'[ \t\n\v\f\r]*[+-]?(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)\Z')
BLOCKING = frozenset({
    'input_malformed', 'text_too_large', 'too_many_files', 'too_many_programs', 'nul_byte',
    'missing_final_lf', 'environment_variable', 'quote_unmatched', 'brace_unmatched', 'variable_name_invalid',
    'hex_escape_invalid', 'word_expand_invalid', 'too_many_words', 'scope_directive', 'condition_unevaluated',
    'condition_malformed', 'too_many_nested_conditions', 'unterminated_condition', 'config_alert',
    'unknown_directive', 'modifier_not_supported', 'out_of_section', 'program_malformed',
    'program_duplicate', 'program_without_command', 'external_check_unmodelled', 'gaps_truncated',
})
UNOBSERVED = (
    ('Files are taken in the order supplied; the collector must reproduce the -f order HAProxy loads, with '
     'directory entries in the order HAProxy lists them.'),
    ('Master-worker mode is usually set on the command line (-W or -Ws, as in the packaged systemd unit); the '
     'contract only sees a "master-worker" line in the global section.'),
    ('The master\'s own identity is not observed; under the packaged unit it is root, so a program without '
     '"user" runs as root.'),
    'User and group names are reported as written; HAProxy resolves them with getpwnam/getgrnam while parsing.',
    'Whether each executable exists, and which file PATH resolves a bare name to, is not checked.',
    ('Other syntax is not validated; HAProxy refuses to start on a fatal configuration error, and then no '
     'program runs.'),
    ('On a reload, a program with "no option start-on-reload" keeps its running instance; the contract does not '
     'observe which instances are running.'),
)
NOT_A_VERDICT = 'Configuration text only. This is not a safety verdict and origin is not assessed.'


class _TokenError(Exception):
    def __init__(self, code: str, detail: str = '') -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


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


def parse_line(line: str, pseudo: dict[str, str | None]) -> list[str]:
    """Split one configuration line exactly as ``parse_line`` does for readcfgfile.

    ``pseudo`` supplies the ``.LINE``, ``.FILE`` and ``.SECTION`` values. A
    reference to a real environment variable raises ``environment_variable``,
    because the process environment is not observed.
    """
    out: list[list[str]] = [[]]
    squote = dquote = False
    quote = False
    i, n = 0, len(line)

    def at(k: int) -> str:
        return line[k] if k < n else '\0'

    def separate() -> None:
        out.append([])
        if len(out) - 1 >= MAX_LINE_ARGS:
            raise _TokenError('too_many_words', f'More than {MAX_LINE_ARGS} words.')

    while True:
        c = at(i)
        if c >= '-' and c != '\\':
            out[-1].append(c)
            i += 1
        elif c in '\0\n\r' or (c == '#' and not squote and not dquote):
            break  # end of line or comment
        elif c == '"' and not squote:
            dquote = not dquote
            quote = dquote
            i += 1
        elif c == "'" and not dquote:
            squote = not squote
            quote = squote
            i += 1
        elif c == '\\' and not squote:
            nxt = at(i + 1)
            send = c
            if nxt in ' \\':
                send, i = nxt, i + 1
            elif nxt in 'tnr':
                send, i = {'t': '\t', 'n': '\n', 'r': '\r'}[nxt], i + 1
            elif nxt in '#\'"' or (nxt == '$' and dquote):
                send, i = nxt, i + 1
            elif nxt == 'x':
                if at(i + 2) not in HEX or at(i + 3) not in HEX:
                    raise _TokenError('hex_escape_invalid')
                send, i = chr(int(line[i + 2:i + 4], 16)), i + 3
            i += 1
            out[-1].append(send)
        elif c in C_SPACE and not squote and not dquote:
            while at(i) in C_SPACE and at(i) != '\0':
                i += 1
            separate()
        elif c == '$' and dquote:
            i += 1
            brace = at(i) == '{'
            if brace:
                i += 1
            if not (at(i).isascii() and (at(i).isalpha() or at(i) in '_.')) or at(i) == '\0':
                raise _TokenError('variable_name_invalid')
            start = i
            if at(i) == '.':
                i += 1
            while at(i) != '\0' and at(i).isascii() and (at(i).isalnum() or at(i) == '_'):
                i += 1
            name = line[start:i]
            if not name.startswith('.'):
                raise _TokenError('environment_variable', f'${name} depends on the process environment.')
            if name not in pseudo:
                raise _TokenError('variable_name_invalid', f'Unsupported pseudo-variable ${name}.')
            value = pseudo[name]
            expand = False
            if at(i) == '[' and brace:
                if at(i + 1) != '*' or at(i + 2) != ']':
                    raise _TokenError('word_expand_invalid')
                expand, i = True, i + 3
            if brace:
                if at(i) == '-':
                    end = line.find('}', i)
                    if end < 0:
                        raise _TokenError('brace_unmatched')
                    if value is None:
                        value = line[i + 1:end]
                    i = end
                elif at(i) != '}':
                    raise _TokenError('brace_unmatched')
                i += 1
            k = 0
            text = value or ''
            while k < len(text):
                if expand and text[k] in C_SPACE:
                    separate()
                    k += 1
                    while k < len(text) and text[k] in C_SPACE:
                        k += 1
                else:
                    out[-1].append(text[k])
                    k += 1
        else:
            out[-1].append(c)
            i += 1
    if quote:
        raise _TokenError('quote_unmatched')
    words = [''.join(w) for w in out]
    if words and words[-1] == '':
        words.pop()  # parse_line does not count a trailing empty word
    return words


def _condition(words: list[str]) -> bool | None:
    """A ``.if`` expression that is one integer constant, read as ``strtol(in, &end, 0)``."""
    expr = ' '.join(words[1:])
    if not STRTOL_FULL.match(expr):
        return None
    digits = expr.lstrip(C_SPACE).lstrip('+-')
    base = 16 if digits[:2] in ('0x', '0X') else 8 if digits.startswith('0') else 10
    return int(digits, base) != 0


def evaluate(files: Any) -> dict[str, Any]:
    """Report the program sections HAProxy's master starts for ``files``.

    ``files`` is a sequence of ``{'path': str, 'text': str}`` in HAProxy load order.
    """
    gaps: list[dict[str, Any]] = []
    programs: list[dict[str, Any]] = []
    master_worker: dict[str, Any] | None = None
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'complete': False, 'programs': programs,
        'master_worker_in_config': None, 'gaps': gaps, 'unobserved': list(UNOBSERVED), 'not_a_verdict': NOT_A_VERDICT,
    }
    if not isinstance(files, (list, tuple)) or not all(
            isinstance(f, dict) and isinstance(f.get('path'), str) and isinstance(f.get('text'), str) for f in files):
        _gap(gaps, 'input_malformed', detail='Expected a list of {"path": str, "text": str}.')
        return result
    if len(files) > MAX_FILES:
        _gap(gaps, 'too_many_files')
        return result
    if sum(len(f['text']) for f in files) > MAX_TEXT:
        _gap(gaps, 'text_too_large')
        return result

    current: dict[str, Any] | None = None  # cfg_parse_program's static ext_child
    for f in files:
        path, text = f['path'], f['text']
        section: str | None = None
        label: str | None = None
        conds: list[str] = []  # 'take', 'drop' (no branch taken yet), 'done', 'unknown'
        else_seen: list[bool] = []
        lines = text.split('\n')
        if lines and lines[-1] == '':
            lines.pop()
        elif lines:
            _gap(gaps, 'missing_final_lf', {'path': path, 'line': len(lines)},
                 'HAProxy 2.8 rejects a configuration whose last line has no LF.')
        for num, raw in enumerate(lines, 1):
            where = {'path': path, 'line': num}
            if '\0' in raw:
                _gap(gaps, 'nul_byte', where)
                break
            line = raw.lstrip(C_SPACE)
            if line.startswith('['):
                _gap(gaps, 'scope_directive', where)
                continue
            try:
                words = parse_line(line, {'.LINE': str(num), '.FILE': path, '.SECTION': label})
            except _TokenError as exc:
                _gap(gaps, exc.code, where, exc.detail)
                continue
            if not words:
                continue
            head = words[0]
            if head in ('.if', '.elif', '.else', '.endif'):
                if head == '.if':
                    if len(conds) + 1 >= MAXNESTEDCONDS:
                        _gap(gaps, 'too_many_nested_conditions', where)
                        return result
                    else_seen.append(False)
                    if conds and conds[-1] in ('drop', 'done'):
                        conds.append('done')
                        continue
                    value = _condition(words)
                    if value is None:
                        _gap(gaps, 'condition_unevaluated', where, 'Only integer-constant conditions are evaluated.')
                        conds.append('unknown')
                    else:
                        conds.append('take' if value else 'drop')
                    continue
                if not conds:
                    _gap(gaps, 'condition_malformed', where, f'"{head}" without ".if".')
                    return result
                if head == '.elif':
                    if else_seen[-1]:
                        _gap(gaps, 'condition_malformed', where, '".elif" after ".else".')
                        return result
                    if conds[-1] in ('take', 'done'):
                        conds[-1] = 'done'
                    elif conds[-1] == 'drop':
                        value = _condition(words)
                        if value is None:
                            _gap(gaps, 'condition_unevaluated', where)
                            conds[-1] = 'unknown'
                        else:
                            conds[-1] = 'take' if value else 'drop'
                    continue
                if len(words) > 1 and words[1]:
                    _gap(gaps, 'condition_malformed', where, f'Unexpected argument for "{head}".')
                    return result
                if head == '.else':
                    else_seen[-1] = True
                    conds[-1] = {'drop': 'take', 'take': 'done'}.get(conds[-1], conds[-1])
                else:
                    conds.pop()
                    else_seen.pop()
                continue
            if conds and conds[-1] in ('drop', 'done'):
                continue
            if head.startswith('.'):
                if head == '.alert':
                    _gap(gaps, 'config_alert', where)
                    return result
                if head in ('.warning', '.notice', '.diag'):
                    if len(words) > 2 and words[2]:
                        _gap(gaps, 'unknown_directive', where, f'"{head}" takes one argument.')
                    continue
                _gap(gaps, 'unknown_directive', where, head)
                continue
            kwm = 'std'
            if head in ('no', 'default'):
                kwm = head
                words = words[1:] + ['']
                head = words[0]
                if head not in KWM_ALLOWED:
                    _gap(gaps, 'modifier_not_supported', where, f'"{kwm} {head}" is a fatal error.')
            if head in SECTIONS:
                section = head
                label = words[1] if len(words) > 1 and words[1] else head
            if section is None:
                _gap(gaps, 'out_of_section', where)
                continue

            def arg(k: int, words: list[str] = words) -> str:
                return words[k] if k < len(words) else ''

            if section in PROXY_SECTIONS and (head == 'external-check'
                                              or (head == 'option' and arg(1) == 'external-check')):
                _gap(gaps, 'external_check_unmodelled', where, 'external-check commands are outside increment 1.')
                continue
            if section == 'global':
                if head == 'master-worker' and kwm == 'std' and arg(1) in ('', 'no-exit-on-failure') and not arg(2):
                    master_worker = where
                continue
            if section != 'program':
                continue
            if head == 'program':
                if arg(2) or not arg(1):
                    _gap(gaps, 'program_malformed', where, '"program" takes exactly one id.')
                    current = None
                    continue
                if any(p['id'] == arg(1) for p in programs):
                    _gap(gaps, 'program_duplicate', where, arg(1))
                    current = None
                    continue
                if len(programs) >= MAX_PROGRAMS:
                    _gap(gaps, 'too_many_programs', where)
                    return result
                current = {'id': arg(1), 'argv': None, 'executable': None, 'path_lookup': None, 'user': None,
                           'group': None, 'start_on_reload': True, 'location': where, 'command_location': None}
                programs.append(current)
                continue
            if current is None:
                _gap(gaps, 'program_malformed', where, 'The enclosing program section was rejected.')
                continue
            if head == 'command':
                if not arg(1):
                    _gap(gaps, 'program_malformed', where, '"command" needs a command.')
                    continue
                argv: list[str] = []
                for word in words[1:]:
                    if not word:
                        break
                    argv.append(word)
                current.update(argv=argv, executable=argv[0], path_lookup='/' not in argv[0],
                               command_location=where)
            elif head == 'option':
                if arg(1) != 'start-on-reload' or arg(2):
                    _gap(gaps, 'program_malformed', where, f'Unknown or malformed option "{arg(1)}".')
                elif kwm == 'std':
                    current['start_on_reload'] = True
                elif kwm == 'no':
                    current['start_on_reload'] = False
            elif head in ('user', 'group'):
                if not arg(1) or arg(2):
                    _gap(gaps, 'program_malformed', where, f'"{head}" takes exactly one name.')
                elif current[head] is None:  # a repeat only alerts; the first value stays
                    current[head] = arg(1)
            else:
                _gap(gaps, 'program_malformed', where, f'Unknown keyword "{head}" in a program section.')
        if conds:
            _gap(gaps, 'unterminated_condition', {'path': path})
            return result
    for program in programs:
        if program['argv'] is None:
            _gap(gaps, 'program_without_command', program['location'], program['id'])
        program['runs_as'] = (
            {'user': program['user'], 'group': program['group'],
             'supplementary_groups_dropped': program['group'] is not None}
        )
        if program['user'] is None:
            program['runs_as']['user_note'] = 'master process identity (root under the packaged systemd unit)'
    result['master_worker_in_config'] = master_worker
    result['complete'] = not any(g['code'] in BLOCKING for g in gaps)
    return result
