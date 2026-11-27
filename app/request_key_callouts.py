"""Pure keyutils request-key callout contract (roadmap F slice, #1632).

When a process calls ``request_key()`` (or ``keyctl request2``) for a key that
is not present, the kernel runs ``/sbin/request-key`` as **root**. That helper
reads every ``/etc/request-key.d/*.conf`` file and then
``/etc/request-key.conf``, picks the best-matching line and runs its program,
still as root (the ``setuid()`` call upstream is commented out). An
unprivileged user can request key types such as ``user`` and chooses the
description and callout information that ``%d`` and ``%c`` pass to that root
program, or that a ``|`` program receives on standard input.

This module turns captured configuration text into the rules request-key would
consider, which arguments carry requester-controlled data and which lines make
lookups abort. :func:`select_rule` replays request-key's best-match selection
for one request. The module performs no I/O, never runs request-key and never
authorizes a response action.

The rules follow ``request-key.c`` in keyutils 1.6.3 (Ubuntu 24.04
``keyutils 1.6.3-3build1``) and were checked against that helper and a real
kernel upcall:

- Drop-ins are read in ``readdir()`` order, which the caller captures. Names
  starting with ``.``, names not ending in ``.conf`` and entries whose type is
  neither regular nor unknown (symlinks included) are skipped.
  ``request-key.conf`` is read last. All files are scanned before anything
  runs.
- Lines are read with ``fgets()`` into a 4098-byte buffer. A line of 4096
  bytes or more, counting its newline, aborts the whole lookup. A line of
  exactly one byte, or starting with ``#`` or any C-locale white space, is
  ignored. The last byte of every other line is dropped: normally the newline,
  but the final character of a last line that has none.
- ``OP TYPE DESCRIPTION CALLOUT PROGRAM [ARG...]`` fields are white-space
  separated and matched left to right. A line that ends early aborts the
  lookup, but only for requests matching the fields read before the end.
- Each pattern may contain one ``*``. The best match has the smallest wildcard
  skip, compared OP, TYPE, DESCRIPTION, CALLOUT in turn; ties keep the first
  line read. For ``abc*def`` upstream compares the datum's tail against the
  pattern's *start*; :func:`select_rule` reproduces that.
- A ``|`` before the program pipes callout information to its standard input
  and reads the payload from its standard output. ``argv[0]`` is the text
  after the last ``/``; a program without ``/`` fails. Whole-argument macros
  are ``%o %k %t %d %c %u %g %T %P %S`` and ``%{type:description}`` (the
  payload of a key on the requester's keyrings); ``%%`` escapes. ``%`` alone,
  other one-letter macros and malformed ``%{...}`` fail when the rule is
  selected.

Which key types an unprivileged requester may ask for, whether a program
exists or what it does with its arguments is not visible from the text.
``origin`` is always ``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 1
CONF_PATH = '/etc/request-key.conf'
DROPIN_DIR = '/etc/request-key.d'
KERNEL_OP = 'create'
MAX_DROPINS = 64
MAX_TEXT_BYTES = 256 * 1024
MAX_RULES = 512
# fgets(buf, 4098): ``len >= sizeof(buf) - 2`` is "Line too long".
LINE_ABORT_BYTES = 4096
# ``if (argc >= 254) line_error("Too many arguments")`` before argv[argc].
MAX_ARGC = 253
RUNS_AS = 'root'
_SPACE = ' \t\n\v\f\r'
_MACROS = {'o': 'operation', 'k': 'key_id', 't': 'key_type', 'd': 'description', 'c': 'callout_info',
           'u': 'requester_uid', 'g': 'requester_gid', 'T': 'thread_keyring', 'P': 'process_keyring',
           'S': 'session_keyring'}
_REQUESTER_CONTROLLED = {'d': 'description', 'c': 'callout_info'}
NOT_OBSERVED = (
    'which key types an unprivileged requester may ask for',
    'whether each program exists, is trusted or how it uses its arguments',
    'the readdir() order of request-key.d beyond what the caller captured',
    'request-key binaries other than keyutils 1.6.3 or a replaced /sbin/request-key',
)


def _gap(gaps: list, code: str, where: str, detail: str = '', *, blocking: bool = True) -> None:
    gaps.append({'code': code, 'where': where, 'detail': detail, 'blocking': blocking})


def _decode(text: Any, path: str, gaps: list) -> str | None:
    if isinstance(text, str):
        raw = text.encode('utf-8', 'surrogatepass')
    elif isinstance(text, (bytes, bytearray)):
        raw = bytes(text)
    else:
        _gap(gaps, 'text_not_captured', path)
        return None
    if len(raw) > MAX_TEXT_BYTES:
        _gap(gaps, 'text_over_limit', path, f'{len(raw)} bytes')
        return None
    if b'\x00' in raw:
        _gap(gaps, 'nul_byte', path)
        return None
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', path)
        return None


def match(pattern: str, datum: str) -> int | None:
    """Return the wildcard skip of upstream ``match()``, or ``None`` on no match (bytes)."""
    pat, dat = pattern.encode('utf-8'), datum.encode('utf-8')
    plen, dlen = len(pat), len(dat)
    star = pat.find(b'*')
    if star < 0:
        return 0 if pat == dat else None
    if dlen < plen - 1:
        return None
    skip = dlen - (plen - 1)
    if star == 0:
        tail = pat[1:]
        return skip if not tail or dat[dlen - len(tail):] == tail else None
    if dat[:star] != pat[:star]:
        return None
    rest = plen - star - 1
    if not rest:
        return skip
    # Upstream advances ``asterisk`` but compares from ``pattern``: the datum's
    # last ``rest`` bytes must equal the pattern's first ``rest`` bytes.
    return skip if dat[dlen - rest:] == pat[:rest] else None


def _universal(pattern: str, index: int) -> bool:
    return match(pattern, KERNEL_OP) is not None if index == 0 else pattern == '*'


def _scan_line(s: str) -> tuple[list[str], str | None]:
    """Mirror scan_conf_file(): the patterns read and the command, or ``None`` on syntax error."""
    i, n, pats = 0, len(s), []
    for field in range(4):
        if field:
            while i < n and s[i] in _SPACE:
                i += 1
            if i == n:
                return pats, None
        start = i
        while i < n and s[i] not in _SPACE:
            i += 1
        if i == n:
            return pats, None
        pats.append(s[start:i])
        i += 1
    while i < n and s[i] in _SPACE:
        i += 1
    if i == n:
        return pats, None
    return pats, s[i:]


def _split(s: str) -> list[str]:
    out, word = [], []
    for ch in s:
        if ch in _SPACE:
            if word:
                out.append(''.join(word))
                word = []
        else:
            word.append(ch)
    if word:
        out.append(''.join(word))
    return out


def _parse_command(command: str) -> dict[str, Any]:
    """Mirror execute_program(): program, argv template and the first selection-time failure."""
    pipe = command.startswith('|')
    if pipe:
        command = command[1:]
    i = 0
    while i < len(command) and command[i] not in _SPACE:
        i += 1
    program, words = command[:i], _split(command[i:])
    failure = None
    if '/' not in program:
        failure = 'program_without_slash'
    args: list[dict[str, Any]] = []
    controlled: list[str] = []
    for word in words:
        if len(args) >= MAX_ARGC:
            failure = failure or 'too_many_arguments'
            break
        arg: dict[str, Any] = {'template': word, 'kind': 'literal', 'value': word, 'macro': None}
        if word.startswith('%'):
            q = word[1:]
            if not q:
                failure = failure or 'missing_macro_name'
                arg['kind'] = 'invalid'
            elif q[0] == '%':
                arg.update(kind='escaped', value=word[1:])
            elif len(q) == 1:
                if q in _MACROS:
                    arg.update(kind='macro', value=None, macro=_MACROS[q])
                    if q in _REQUESTER_CONTROLLED:
                        controlled.append(_REQUESTER_CONTROLLED[q])
                else:
                    failure = failure or 'unsupported_macro'
                    arg['kind'] = 'invalid'
            elif q[0] == '{':
                body = q[1:]
                colon = body.find(':')
                end = body.find('}', colon + 1) if colon >= 0 else -1
                if colon < 0 or end < 0 or end != len(body) - 1 or not body[:colon] or colon + 1 == end:
                    failure = failure or 'malformed_keysub'
                    arg['kind'] = 'invalid'
                else:
                    arg.update(kind='keysub', value=None, macro='keysub',
                               keysub={'type': body[:colon], 'description': body[colon + 1:end]})
                    controlled.append('keysub_payload')
        args.append(arg)
    if pipe:
        controlled.append('stdin_callout_info')
    return {
        'program': program,
        'pipe': pipe,
        'argv0': program.rsplit('/', 1)[-1] if '/' in program else None,
        'args': args,
        'requester_controlled': sorted(set(controlled)),
        'fails_when_selected': failure,
        'absolute_program': program.startswith('/'),
    }


def _scan_file(path: str, text: str, order: list, rules: list, aborts: list, gaps: list) -> None:
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
        last_has_newline = True
    else:
        last_has_newline = False
    for number, line in enumerate(lines, 1):
        where = f'{path}:{number}'
        newline = number < len(lines) or last_has_newline
        size = len(line.encode('utf-8')) + (1 if newline else 0)
        if size >= LINE_ABORT_BYTES:
            entry = {'source': where, 'reason': 'line_too_long', 'scope': [], 'universal': True}
            aborts.append(entry)
            order.append(('abort', entry))
            continue
        if size == 1 or line[:1] == '#' or line[:1] in tuple(_SPACE):
            continue
        content = line if newline else line[:-1]
        if not newline:
            _gap(gaps, 'last_byte_dropped', where, 'request-key drops the last byte of a final line without a newline',
                 blocking=False)
        pats, command = _scan_line(content)
        if command is None:
            entry = {'source': where, 'reason': 'syntax_error', 'scope': pats,
                     'universal': all(_universal(p, k) for k, p in enumerate(pats))}
            aborts.append(entry)
            order.append(('abort', entry))
            continue
        if len(rules) >= MAX_RULES:
            _gap(gaps, 'too_many_rules', where)
            return
        parsed = _parse_command(command)
        reached = match(pats[0], KERNEL_OP) is not None
        rule = {'source': where, 'op': pats[0], 'type': pats[1], 'description': pats[2],
                'callout_info': pats[3], 'kernel_upcall': reached, 'runs_as': RUNS_AS, **parsed}
        if not reached:
            rule['code_runs'] = 'never'
        elif parsed['fails_when_selected']:
            rule['code_runs'] = 'fails_when_selected'
        else:
            rule['code_runs'] = 'on_matching_request'
        if not parsed['absolute_program'] and '/' in parsed['program']:
            _gap(gaps, 'program_not_absolute', where, parsed['program'], blocking=False)
        rules.append(rule)
        order.append(('rule', rule))


def evaluate(*, conf: Mapping[str, Any] | None, dropins: Mapping[str, Any] | None) -> dict[str, Any]:
    """Evaluate captured request-key configuration.

    ``conf`` has ``exists`` (``True``, ``False`` or ``None`` when unchecked)
    and ``text`` (str or bytes). ``dropins`` has ``exists`` and ``entries`` in
    ``readdir()`` order, each with ``name``, ``kind`` (``regular``,
    ``symlink``, ``directory``, ``other`` or ``unknown`` for ``DT_UNKNOWN``)
    and ``text`` for entries request-key reads.
    """
    gaps: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    aborts: list[dict[str, Any]] = []
    order: list[tuple[str, dict[str, Any]]] = []

    def read(path: str, entry: Mapping[str, Any]) -> None:
        text = _decode(entry.get('text'), path, gaps)
        if text is None:
            files.append({'path': path, 'state': 'unreadable', 'sha256': None})
            return
        files.append({'path': path, 'state': 'read', 'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()})
        _scan_file(path, text, order, rules, aborts, gaps)

    if dropins is None or dropins.get('exists') is None:
        _gap(gaps, 'dropins_not_checked', DROPIN_DIR)
    elif dropins.get('exists'):
        entries = dropins.get('entries')
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
            _gap(gaps, 'dropins_not_listed', DROPIN_DIR)
            entries = ()
        elif len(entries) > MAX_DROPINS:
            _gap(gaps, 'too_many_dropins', DROPIN_DIR, str(len(entries)))
            entries = entries[:MAX_DROPINS]
        for entry in entries:
            name = str(entry.get('name') or '')
            path = f'{DROPIN_DIR}/{name}'
            kind = entry.get('kind')
            if name.startswith('.') or len(name) < 5 or not name.endswith('.conf'):
                skipped.append({'path': path, 'reason': 'name_not_read'})
            elif kind not in ('regular', 'unknown'):
                if kind not in ('symlink', 'directory', 'other'):
                    _gap(gaps, 'entry_kind_unknown', path, str(kind))
                skipped.append({'path': path, 'reason': f'{kind}_not_read'})
            else:
                read(path, entry)
        if len([f for f in files if f['state'] == 'read']) > 1:
            _gap(gaps, 'readdir_order_assumed', DROPIN_DIR,
                 'ties between drop-ins resolve in the captured readdir() order', blocking=False)
    if conf is None or conf.get('exists') is None:
        _gap(gaps, 'conf_not_checked', CONF_PATH)
    elif conf.get('exists'):
        read(CONF_PATH, conf)

    blocking = any(g['blocking'] for g in gaps)
    universal_abort = [a['source'] for a in aborts if a['universal']]
    runnable = [r for r in rules if r['code_runs'] == 'on_matching_request']
    if blocking:
        status = 'unresolved'
    elif universal_abort:
        status = 'all_lookups_abort'
    elif runnable:
        status = 'runs'
    elif not files:
        status = 'absent'
    else:
        status = 'no_runnable_rules'
    if universal_abort:
        for rule in runnable:
            rule['code_runs'] = 'lookup_aborts'
    controlled = sorted({name for r in runnable if not universal_abort for name in r['requester_controlled']})
    return {
        'contract_version': CONTRACT_VERSION,
        'origin': 'not_assessed',
        'authorizes_response': False,
        'status': status,
        'complete': not blocking,
        'files': files,
        'skipped': skipped,
        'rules': rules,
        'aborts': aborts,
        'universal_aborts': universal_abort,
        'requester_controlled': controlled,
        'gaps': gaps,
        'not_observed': list(NOT_OBSERVED),
        'scan_order': [(kind, item['source']) for kind, item in order],
    }


def select_rule(result: Mapping[str, Any], key_type: str, description: str, callout_info: str,
                op: str = KERNEL_OP, values: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Replay request-key's selection for one request against an :func:`evaluate` result."""
    if not result.get('complete'):
        return {'outcome': 'unresolved'}
    by_source = {('rule', r['source']): r for r in result['rules']}
    by_source.update({('abort', a['source']): a for a in result['aborts']})
    datum = (op, key_type, description, callout_info)
    best, best_wild = None, None
    for kind, source in result['scan_order']:
        item = by_source[(kind, source)]
        if kind == 'abort':
            if all(match(p, datum[k]) is not None for k, p in enumerate(item['scope'])):
                return {'outcome': 'aborts', 'source': source, 'reason': item['reason']}
            continue
        wild = []
        for k, pattern in enumerate((item['op'], item['type'], item['description'], item['callout_info'])):
            w = match(pattern, datum[k])
            if w is None:
                break
            wild.append(w)
        else:
            if best_wild is None or tuple(wild) < best_wild:
                best, best_wild = item, tuple(wild)
    if best is None:
        return {'outcome': 'no_match'}
    if best['fails_when_selected']:
        return {'outcome': 'fails', 'source': best['source'], 'reason': best['fails_when_selected'],
                'wildness': list(best_wild)}
    known = {'operation': op, 'key_type': key_type, 'description': description, 'callout_info': callout_info,
             **(values or {})}
    argv = [best['argv0']]
    for arg in best['args']:
        if arg['kind'] == 'macro':
            argv.append(known.get(arg['macro'], arg['template']))
        else:
            argv.append(arg['value'] if arg['value'] is not None else arg['template'])
    return {'outcome': 'runs', 'source': best['source'], 'program': best['program'], 'pipe': best['pipe'],
            'argv': argv, 'runs_as': RUNS_AS, 'wildness': list(best_wild)}
