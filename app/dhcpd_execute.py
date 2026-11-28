"""Pure ISC dhcpd ``execute()`` contract, first increment (roadmap F slice, #1593).

ISC DHCP server (``isc-dhcp-server``) runs the ``execute()`` statements of
``/etc/dhcp/dhcpd.conf`` synchronously with ``fork`` and ``execvp`` (no shell)
whenever it evaluates the statement. This module ports, from dhcpd
4.4.3-P1 (Ubuntu 24.04 ``isc-dhcp-server 4.4.3-P1-4ubuntu2``, built with
``ENABLE_EXECUTE``), the parts that decide *which programs a configuration
makes dhcpd run, when, and as which user*:

- ``get_raw_token``, ``read_string``, ``read_number`` and ``read_num_or_name``
  in ``common/conflex.c``: ``#`` comments to end of line, double-quoted strings
  with ``\\t \\r \\n \\b``, three-digit octal and two-digit hex escapes, case-
  insensitive keywords and a 1500-byte token buffer.
- ``EXECUTE`` in ``parse_executable_statement`` (``common/parse.c``): the
  program must be a quoted string (anything else rejects the configuration);
  each further argument is a data expression evaluated per event. The program
  is copied with ``strcpy``, so an escaped NUL truncates it.
- ``parse_on_statement``: ``on commit``/``release``/``expiry``/``transmission``
  joined by ``or``. Executing an ``on`` statement *replaces* the lease's
  statements for each named event (``execute_statements``), and
  ``execute_statements_in_scope`` runs scopes from the outermost group to the
  innermost (subnet or shared-network, pool, matching classes, then host), so
  the last ``on`` for an event in the innermost evaluated scope wins.
- ``postconf_initialization`` (``server/dhcpd.c``) evaluates the root group
  before the ``-t`` config test exits and before ``-user`` drops privileges:
  global-scope ``execute()`` statements (outside ``on`` blocks) therefore run as
  **root** at every start and every ``dhcpd -t``, and again as the process user
  whenever a packet is processed.

Native traces (veth pair in two network namespaces, ``strace -f -e execve``,
dhcpd started as the packaged unit starts it) confirmed each rule; see
``tests/test_dhcpd_execute.py``.

Not modelled in this increment (a result that meets them is incomplete, never
silently wrong): ``include`` files, DHCPv6 ``dhcpd6.conf`` event timing,
whether a ``class`` or ``host`` actually matches a client, expression
evaluation (arguments are reported as source text) and failover peers.

This module performs no I/O, runs nothing and authorizes nothing; ``origin``
is always ``not_assessed``.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('4.4.3-P1',)
DEFAULT_CONFIG = '/etc/dhcp/dhcpd.conf'
FILE_STATES = ('regular', 'missing', 'unreadable', 'not_regular', 'unknown')
MAX_TEXT = 262144
MAX_GAPS = 64
MAX_DEPTH = 32
TOKBUF = 1500
PACKAGED_ARGV = ('dhcpd', '-user', 'dhcpd', '-group', 'dhcpd', '-f', '-4')

EVENTS = ('commit', 'release', 'expiry', 'transmission')
SCOPE_KINDS = frozenset({'shared-network', 'subnet', 'subnet6', 'pool', 'pool6', 'group', 'host',
                         'class', 'subclass'})
# Blocks whose contents are not executable statements; an execute() there is a parse error.
DATA_BLOCK_KINDS = frozenset({'failover', 'key', 'zone', 'option', 'authoritative', 'range6',
                              'prefix6', 'fixed-prefix6'})
BLOCKING = frozenset({
    'over_limit', 'binary', 'invalid_utf8', 'file_not_observed', 'file_state_unknown',
    'file_state_not_modelled', 'file_text_missing', 'include', 'unterminated_string',
    'token_over_buffer', 'unusual_escape', 'unbalanced_brace', 'unterminated_block',
    'nesting_too_deep', 'nested_on_statement', 'execute_in_data_block', 'gaps_truncated',
})
NOT_MODELLED = (
    'include files', 'dhcpd6.conf event timing', 'class and host matching for a client',
    'argument expression evaluation', 'failover peer state',
)


class _Tok:
    __slots__ = ('kind', 'value', 'line')

    def __init__(self, kind: str, value: str, line: int) -> None:
        self.kind = kind
        self.value = value
        self.line = line

    def word(self) -> str:
        return self.value.lower() if self.kind == 'name' else ''


def tokenize(text: str, gap: Any = None) -> list[_Tok]:
    """Port of ``get_raw_token``. ``gap(code, line, detail)`` receives lexer gaps."""
    toks: list[_Tok] = []
    i = 0
    line = 1
    n = len(text)

    def report(code: str, detail: str = '') -> None:
        if gap is not None:
            gap(code, line, detail)

    while i < n:
        c = text[i]
        if c == '\n':
            line += 1
            i += 1
            continue
        if c.isascii() and c.isspace():
            i += 1
            continue
        if c == '#':
            while i < n and text[i] != '\n':
                i += 1
            continue
        if c == '"':
            start_line = line
            i += 1
            out: list[str] = []
            closed = False
            while i < n:
                ch = text[i]
                if ch == '"':
                    closed = True
                    i += 1
                    break
                if ch == '\n':
                    line += 1
                if ch == '\\':
                    if i + 1 >= n:
                        break
                    nxt = text[i + 1]
                    simple = {'t': '\t', 'r': '\r', 'n': '\n', 'b': '\b'}
                    if nxt in simple:
                        out.append(simple[nxt])
                        i += 2
                    elif nxt in '0123':
                        digits = text[i + 1:i + 4]
                        if len(digits) == 3 and all(d in '01234567' for d in digits):
                            out.append(chr(int(digits, 8)))
                            i += 4
                        else:
                            report('unusual_escape', 'incomplete octal escape')
                            out.append('�')
                            i += 2
                    elif nxt == 'x':
                        digits = text[i + 2:i + 4]
                        if len(digits) == 2 and all(d in '0123456789abcdefABCDEF' for d in digits):
                            out.append(chr(int(digits, 16)))
                            i += 4
                        else:
                            report('unusual_escape', 'incomplete hex escape')
                            out.append('�')
                            i += 2
                    else:
                        if nxt == '\n':
                            line += 1
                        out.append(nxt)
                        i += 2
                    continue
                out.append(ch)
                i += 1
            if not closed:
                report('unterminated_string', 'eof in string constant')
            value = ''.join(out)
            if len(value.encode('utf-8', 'surrogateescape')) >= TOKBUF:
                report('token_over_buffer', 'string constant larger than internal buffer')
            toks.append(_Tok('string', value, start_line))
            continue
        if c.isascii() and (c.isalnum() or c == '-'):
            j = i + 1
            while j < n and text[j].isascii() and (text[j].isalnum() or text[j] in '-_'):
                j += 1
            value = text[i:j]
            if len(value) >= TOKBUF:
                report('token_over_buffer', 'token larger than internal buffer')
            kind = 'name' if c.isalpha() else 'number'
            if value == '-':
                kind = 'punct'
            toks.append(_Tok(kind, value, line))
            i = j
            continue
        toks.append(_Tok('punct', c, line))
        i += 1
    return toks


def _source(tokens: list[_Tok]) -> str:
    parts = []
    for tok in tokens:
        parts.append('"%s"' % tok.value.replace('\\', '\\\\').replace('"', '\\"')
                     if tok.kind == 'string' else tok.value)
    text = ' '.join(parts)
    for a, b in ((' ( ', '('), ('( ', '('), (' )', ')'), (' ,', ','), (' .', '.'), ('. ', '.')):
        text = text.replace(a, b)
    return text


def _rank(scope: tuple[str, ...]) -> int:
    rank = 0
    for label in scope:
        kind = label.split(' ', 1)[0].lower()
        rank = max(rank, 3 if kind == 'host' else 2 if kind in ('class', 'subclass') else 1)
    return rank


def _evaluated_after(later: tuple[str, ...], earlier: tuple[str, ...]) -> bool:
    """Whether scope ``later`` can run after scope ``earlier`` for one lease."""
    if len(later) > len(earlier) and later[:len(earlier)] == earlier:
        return True
    return _rank(later) > _rank(earlier)


def process_user(argv: list[str] | None) -> dict[str, Any]:
    """Effective user after ``-user``/``-group`` (``server/dhcpd.c`` argument loop)."""
    if argv is None:
        return {'user': 'dhcpd', 'group': 'dhcpd', 'source': 'packaged_unit_default'}
    user = group = None
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg in ('-user', '-group') and i + 1 < len(argv):
            if arg == '-user':
                user = argv[i + 1]
            else:
                group = argv[i + 1]
            i += 2
            continue
        i += 1
    return {'user': user or 'root', 'group': group, 'source': 'observed_command_line'}


def assess_config(files: list[dict[str, Any]] | None, *, config_path: str = DEFAULT_CONFIG,
                  argv: list[str] | None = None) -> dict[str, Any]:
    """Return the programs one dhcpd configuration makes dhcpd run.

    ``files`` holds records ``{'path', 'state', 'text'}``; ``state`` is one of
    ``FILE_STATES`` and ``text`` is required for ``regular`` files. ``argv`` is
    the observed dhcpd command line; ``None`` assumes the packaged unit.
    """
    runtime_user = process_user(argv)
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
        'config_path': config_path, 'complete': True, 'rejected_by_parser': False,
        'process_user': runtime_user, 'programs': [], 'config_errors': [], 'gaps': [],
        'not_modelled': list(NOT_MODELLED), 'origin': 'not_assessed',
    }
    gaps: list[dict[str, Any]] = result['gaps']

    def gap(code: str, line: int | None = None, detail: str = '') -> None:
        blocking = code in BLOCKING
        if blocking:
            result['complete'] = False
        if len(gaps) < MAX_GAPS:
            gaps.append({'code': code, 'file': config_path, 'line': line, 'detail': detail[:240],
                         'blocking': blocking})
        elif gaps[-1]['code'] != 'gaps_truncated':
            result['complete'] = False
            gaps.append({'code': 'gaps_truncated', 'file': config_path, 'line': None,
                         'detail': 'Further gaps were not recorded.', 'blocking': True})

    def reject(line: int, reason: str, detail: str = '') -> None:
        result['rejected_by_parser'] = True
        result['config_errors'].append({'file': config_path, 'line': line, 'reason': reason,
                                        'detail': detail[:240]})

    if argv is None:
        gap('process_user_unobserved', None,
            'dhcpd command line not observed; the packaged unit runs -user dhcpd -group dhcpd.')

    record = None
    for item in files or []:
        if isinstance(item, dict) and item.get('path') == config_path:
            record = item
            break
    if record is None:
        gap('file_not_observed', None, config_path)
        return result
    state = record.get('state')
    if state not in FILE_STATES:
        gap('file_state_not_modelled', None, str(state))
        return result
    if state == 'unknown':
        gap('file_state_unknown', None, config_path)
        return result
    if state != 'regular':
        # readconf() fails: dhcpd does not start, so nothing runs.
        reject(0, 'config_file_not_readable', str(state))
        return result
    text = record.get('text')
    if not isinstance(text, str):
        gap('file_text_missing', None, config_path)
        return result
    raw = text.encode('utf-8', 'surrogateescape')
    if len(raw) > MAX_TEXT:
        gap('over_limit', None, '%d bytes' % len(raw))
        return result
    if '\x00' in text:
        gap('binary', None, 'NUL byte in configuration')
        return result
    try:
        raw.decode('utf-8')
    except UnicodeDecodeError:
        gap('invalid_utf8', None, 'configuration is not valid UTF-8')
        return result

    toks = tokenize(text, gap)
    programs: list[dict[str, Any]] = result['programs']
    on_records: list[dict[str, Any]] = []
    pos = 0

    def at(k: int) -> _Tok | None:
        return toks[k] if k < len(toks) else None

    def skip_statement(k: int) -> tuple[int, bool]:
        """Skip to after ``;`` at depth 0; returns (index, opened_block)."""
        depth = 0
        while k < len(toks):
            v = toks[k].value if toks[k].kind == 'punct' else ''
            if v == '(':
                depth += 1
            elif v == ')':
                depth = max(0, depth - 1)
            elif v == ';' and depth == 0:
                return k + 1, False
            elif v == '{' and depth == 0:
                return k + 1, True
            elif v == '}' and depth == 0:
                return k, False
            k += 1
        return k, False

    def parse_execute(k: int, scope: tuple[str, ...], events: tuple[str, ...] | None,
                      conditions: tuple[str, ...]) -> int:
        line = toks[k].line
        k += 1
        tok = at(k)
        if tok is None or tok.value != '(' or tok.kind != 'punct':
            reject(line, 'left_parenthesis_expected')
            return skip_statement(k)[0]
        k += 1
        tok = at(k)
        if tok is None or tok.kind != 'string':
            reject(line, 'expecting_quoted_string', 'execute() program must be a quoted string')
            return skip_statement(k)[0]
        program = tok.value.split('\x00', 1)[0]
        truncated = program != tok.value
        k += 1
        args: list[dict[str, Any]] = []
        while True:
            tok = at(k)
            if tok is None:
                reject(line, 'right_parenthesis_expected')
                return k
            if tok.kind == 'punct' and tok.value == ')':
                k += 1
                break
            if not (tok.kind == 'punct' and tok.value == ','):
                reject(line, 'right_parenthesis_expected')
                return skip_statement(k)[0]
            k += 1
            start = k
            depth = 0
            while k < len(toks):
                t = toks[k]
                if t.kind == 'punct' and t.value == '(':
                    depth += 1
                elif t.kind == 'punct' and t.value == ')':
                    if depth == 0:
                        break
                    depth -= 1
                elif t.kind == 'punct' and t.value in ',;{}' and depth == 0:
                    break
                k += 1
            expr = toks[start:k]
            if not expr:
                reject(line, 'expecting_expression')
                return skip_statement(k)[0]
            literal = len(expr) == 1 and expr[0].kind == 'string'
            args.append({'literal': literal, 'value': expr[0].value if literal else None,
                         'expression': _source(expr)})
        tok = at(k)
        if tok is None or tok.kind != 'punct' or tok.value != ';':
            reject(line, 'semicolon_expected')
            return skip_statement(k)[0]
        k += 1
        if events is None:
            when = ['scope_evaluation']
            if not scope:
                when = ['startup', 'config_test', 'scope_evaluation']
        else:
            when = list(events)
        root_at_startup = not scope and events is None
        users = [runtime_user['user']]
        if root_at_startup and 'root' not in users:
            users.insert(0, 'root')
        programs.append({
            'program': program, 'path_search': '/' not in program, 'truncated_at_nul': truncated,
            'argv_literal': [program] + [a['value'] for a in args] if all(a['literal'] for a in args)
            else None,
            'arguments': args, 'via_shell': False, 'synchronous': True,
            'events': when, 'scope': list(scope), 'conditions': list(conditions),
            'run_as': users, 'runs_as_root_at_startup': root_at_startup,
            'replaced_in_same_scope': False, 'replaced_events': [], 'may_be_replaced_by': [],
            'line': line, 'file': config_path, 'origin': 'not_assessed',
        })
        if truncated:
            gap('program_truncated_at_nul', line, program)
        return k

    def parse_block(k: int, scope: tuple[str, ...], events: tuple[str, ...] | None,
                    conditions: tuple[str, ...], depth: int, block_kind: str,
                    top: bool) -> int:
        if depth > MAX_DEPTH:
            gap('nesting_too_deep', at(k).line if at(k) else None)
            return len(toks)
        while k < len(toks):
            tok = toks[k]
            if tok.kind == 'punct' and tok.value == '}':
                if top:
                    reject(tok.line, 'unbalanced_brace', 'unexpected right brace')
                    gap('unbalanced_brace', tok.line)
                    k += 1
                    continue
                return k + 1
            if tok.kind == 'punct' and tok.value == ';':
                k += 1
                continue
            word = tok.word()
            if word == 'include':
                gap('include', tok.line, at(k + 1).value if at(k + 1) else '')
                k = skip_statement(k)[0]
                continue
            if word == 'execute':
                if block_kind in DATA_BLOCK_KINDS:
                    gap('execute_in_data_block', tok.line, block_kind)
                k = parse_execute(k, scope, events, conditions)
                continue
            if word == 'on':
                line = tok.line
                k += 1
                evs: list[str] = []
                while True:
                    t = at(k)
                    if t is None or t.word() not in EVENTS:
                        reject(line, 'expecting_lease_event_type')
                        k = skip_statement(k)[0]
                        evs = []
                        break
                    evs.append(t.word())
                    k += 1
                    if at(k) is not None and at(k).word() == 'or':
                        k += 1
                        continue
                    break
                if not evs:
                    continue
                t = at(k)
                if t is not None and t.kind == 'punct' and t.value == ';':
                    k += 1
                    body_empty = True
                elif t is not None and t.kind == 'punct' and t.value == '{':
                    body_empty = False
                else:
                    reject(line, 'left_brace_expected')
                    k = skip_statement(k)[0]
                    continue
                if events is not None:
                    gap('nested_on_statement', line)
                record_on = {'scope': scope, 'events': tuple(evs), 'conditional': bool(conditions),
                             'line': line, 'first': len(programs), 'last': len(programs)}
                if not body_empty:
                    k = parse_block(k + 1, scope, tuple(evs), conditions, depth + 1, 'on', False)
                record_on['last'] = len(programs)
                on_records.append(record_on)
                continue
            if word in ('if', 'elsif'):
                k = parse_conditional(k, scope, events, conditions, depth)
                continue
            if word == 'switch':
                line = tok.line
                end, opened = skip_statement(k + 1)
                if not opened:
                    reject(line, 'left_brace_expected')
                    k = end
                    continue
                cond = 'switch ' + _source(toks[k + 1:end - 1])
                k = parse_block(end, scope, events, conditions + (cond,), depth + 1, 'switch',
                                False)
                continue
            if word in ('case', 'default') and block_kind == 'switch':
                k += 1
                # Only a punctuation ':' ends the label; a string ":" is the case expression (#1716).
                while k < len(toks) and not (toks[k].kind == 'punct' and toks[k].value == ':'):
                    k += 1
                k += 1
                continue
            # Declarations and parameters: skip to ';' or descend into a block.
            line = tok.line
            end, opened = skip_statement(k)
            if not opened:
                if end == k:
                    k += 1
                else:
                    k = end
                continue
            if word in SCOPE_KINDS:
                label = _source(toks[k:end - 1])
                if events is not None:
                    reject(line, 'declaration_in_executable_block', label)
                k = parse_block(end, scope + (label,), events, conditions, depth + 1, word, False)
            else:
                k = parse_block(end, scope, events, conditions, depth + 1, word or 'block', False)
        if not top:
            gap('unterminated_block', toks[-1].line if toks else None)
            reject(toks[-1].line if toks else 0, 'unterminated_block')
        return k

    def parse_conditional(k: int, scope: tuple[str, ...], events: tuple[str, ...] | None,
                          conditions: tuple[str, ...], depth: int) -> int:
        previous: list[str] = []
        while True:
            line = toks[k].line
            end, opened = skip_statement(k + 1)
            if not opened:
                reject(line, 'left_brace_expected')
                return end
            cond = _source(toks[k + 1:end - 1])
            branch = tuple('not (%s)' % p for p in previous) + ('if %s' % cond,)
            k = parse_block(end, scope, events, conditions + branch, depth + 1, 'if', False)
            previous.append(cond)
            t = at(k)
            if t is not None and t.word() == 'elsif':
                continue
            if t is not None and t.word() == 'else':
                nxt = at(k + 1)
                if nxt is not None and nxt.word() == 'if':
                    k += 1
                    continue
                if nxt is None or nxt.kind != 'punct' or nxt.value != '{':
                    reject(t.line, 'left_brace_expected')
                    return skip_statement(k + 1)[0]
                branch = tuple('not (%s)' % p for p in previous)
                return parse_block(k + 2, scope, events, conditions + branch, depth + 1, 'else',
                                   False)
            return k

    while pos < len(toks):
        pos = parse_block(pos, (), None, (), 0, 'root', True)

    # Replacement analysis. Executing an ``on`` statement replaces the lease's statements
    # for each event it names, and scopes run from outermost to innermost (subnet or
    # shared-network and pool, then matching classes, then the host), so a later ``on`` in
    # the same scope, or any ``on`` in a scope evaluated later, can replace a program.
    for rec in on_records:
        for other in on_records:
            if other is rec:
                continue
            shared = set(rec['events']) & set(other['events'])
            if not shared:
                continue
            if other['scope'] == rec['scope']:
                if other['line'] <= rec['line'] and other['first'] <= rec['first']:
                    continue
                if other['first'] < rec['last'] and other['last'] <= rec['last']:
                    continue  # nested inside rec (reported as a gap)
            elif not _evaluated_after(other['scope'], rec['scope']):
                continue
            for prog in programs[rec['first']:rec['last']]:
                if other['scope'] == rec['scope'] and not other['conditional']:
                    done = set(prog['replaced_events']) | (set(prog['events']) & shared)
                    prog['replaced_events'] = [e for e in prog['events'] if e in done]
                    prog['replaced_in_same_scope'] = len(done) == len(prog['events'])
                    continue
                entry = {'scope': list(other['scope']), 'line': other['line'],
                         'events': sorted(shared), 'conditional': other['conditional']}
                if entry not in prog['may_be_replaced_by']:
                    prog['may_be_replaced_by'].append(entry)
    if result['rejected_by_parser']:
        for prog in programs:
            prog['runs_only_if_config_accepted'] = True
    return result
