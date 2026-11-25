"""Pure procmail rcfile execution contract (roadmap F slice, #1507).

Procmail is often the local delivery agent. Postfix ``mailbox_command``, a
``~/.forward`` ``"|procmail"`` entry or the system MTA starts it for each
message. Procmail then reads ``/etc/procmailrc`` and the recipient's
``~/.procmailrc``. Every rcfile is an event-driven execution trigger, because
any delivered mail can start its programs with no login. This module turns the
captured text of one rcfile into the programs procmail may start, the recipe
that guards each one, whether it goes through ``$SHELL`` and the user it runs
as. It performs no I/O, never runs procmail or a command, and never authorizes
a response action.

The rules follow the procmail 3.24 sources: ``procmail.c`` (``mainloop``,
``tryopen`` and the ``/etc/procmailrc`` start), ``misc.c`` (``conditions``),
``goodies.c`` (``readparse`` and ``metaparse``), ``variables.c``
(``DROPPRIVS``, ``renvint``, ``TRAP``) and ``config.h`` (``RECFLAGS``,
``DEFshellmetas``).

- Statements: leading blanks are skipped; ``#`` starts a comment line; ``:``
  starts a recipe; ``}`` closes a block; anything else is an assignment
  ``NAME=value`` (``NAME`` alone unsets). An assignment value ends at the first
  unquoted blank, so ``A=1 B=2`` is two assignments and ``A=1 # c`` has a
  trailing comment. A backslash before a newline joins lines.
- Recipe header ``:0[flags][:[lockfile]]`` with flags from ``HBDAahbfcwWiEer``.
  A legacy header with a positive condition count is ``unresolved``.
- Conditions are ``*`` lines. Once one condition was read, comment and blank
  lines are skipped. Before the first, they are skipped only for the
  ``A a E e`` flags; otherwise the next line is the action, and this module
  reports that case as ``unresolved`` rather than guessing.
- In a condition, an optional ``weight^exponent`` and any ``!`` (negate) and
  ``$`` (expand, then re-examine) prefixes are followed by ``?`` for a program
  whose exit status is the test. A ``$`` condition whose expansion starts with
  a variable could become a program and is ``unresolved``.
- Actions: ``|cmd`` pipes the message to a program (with the ``f`` flag, a
  filter); ``|`` alone writes to stdout; ``!`` forwards via sendmail;
  ``{`` opens a nested block; ``VAR=|cmd`` captures program output; anything
  else is a folder.
- Backticks run a program wherever ``readparse`` expands: assignment values,
  folders, forward arguments and ``$`` conditions, but not inside single
  quotes. An unterminated backtick is ``unresolved``.
- ``TRAP`` names a command run when procmail exits.
- ``metaparse`` passes a command to ``$SHELL -c`` when it contains a
  ``SHELLMETAS`` character (default ``&|<>~;?*[``) and otherwise splits it
  itself. After ``SHELL``, ``SHELLMETAS`` or ``SHELLFLAGS`` is assigned,
  ``via_shell`` is ``unknown``.
- Run-as: a ``user`` rcfile runs as the recipient. The ``global`` rcfile runs
  as root when procmail started privileged (setuid root or invoked by root,
  without ``-p`` or a command-line rcfile), until a truthy ``DROPPRIVS``
  (``renvint``: a non-zero number, or a value starting with ``y``, ``t``,
  ``e``, ``a`` or ``on``). A ``DROPPRIVS`` inside a recipe block, or with an
  expanded value, makes later entries ``unknown``. An unknown start gives
  ``unknown``.

Fail-closed rules: input that was not observed or is over the limits, an
unbalanced block, an unterminated backtick or quote, and the unmodeled forms
above make the result incomplete. ``INCLUDERC`` and ``SWITCHRC`` files are not
followed and are reported as gaps. Commands are reported as written, before
``$VAR`` expansion. ``origin`` is always ``not_assessed`` and no result is a
safety verdict.

Not modeled: whether a condition matches, ``LOGFILE``/``DEFAULT`` delivery,
``/etc/procmailrcs`` and command-line rcfiles, the secure-PATH difference of
the global rcfile, the ``test`` builtin fallback, and collection, inventory, UI
or AI wiring.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('procmail-3.24',)
MAX_TEXT = 262144
MAX_STATEMENTS = 4096
RECFLAGS = 'HBDAahbfcwWiEer'
DEFAULT_SHELLMETAS = '&|<>~;?*['
RCFILE_KINDS = ('global', 'user')
EXECUTION_KINDS = ('pipe', 'filter', 'capture', 'condition', 'backtick', 'trap')

_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
_WEIGHT = re.compile(r'[-+.,0-9][-+.,0-9eE]*\s*\^\s*[-+]?[0-9.]+\s*')
_SHELL_VARS = ('SHELL', 'SHELLMETAS', 'SHELLFLAGS')


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash-newline continuations; keep the first physical line number."""
    out: list[tuple[int, str]] = []
    buf, start = '', 0
    for number, raw in enumerate(text.split('\n'), 1):
        if not buf:
            start = number
        trailing = len(raw) - len(raw.rstrip('\\'))
        if trailing % 2:
            buf += raw[:-1]
            continue
        out.append((start, buf + raw))
        buf = ''
    if buf:
        out.append((start, buf))
    return out


def _scan(text: str, *, stop_at_blank: bool) -> tuple[int, list[str], str | None]:
    """Scan readparse-style text.

    Returns the end offset, the backtick commands found outside single quotes
    and an error reason. With ``stop_at_blank`` the scan ends at the first
    unquoted blank (``sarg==1``). A ``#`` at the start of a word ends the text.
    """
    backticks: list[str] = []
    quote = ''
    i, n = 0, len(text)
    word_start = True
    while i < n:
        c = text[i]
        if quote == "'":
            if c == "'":
                quote = ''
            i += 1
            continue
        if c == '\\':
            i += 2
            word_start = False
            continue
        if c == '`':
            j, cmd = i + 1, []
            while j < n and text[j] != '`':
                if text[j] == '"' and quote == '"':
                    break
                if text[j] == '\\' and j + 1 < n:
                    cmd.append(text[j:j + 2])
                    j += 2
                    continue
                cmd.append(text[j])
                j += 1
            if j >= n or text[j] != '`':
                return i, backticks, 'unterminated_backtick'
            backticks.append(''.join(cmd).strip())
            i = j + 1
            word_start = False
            continue
        if c == '"':
            quote = '' if quote == '"' else '"'
        elif c == "'" and quote != '"':
            quote = "'"
        elif quote == '' and c in ' \t':
            if stop_at_blank:
                return i, backticks, None
            word_start = True
            i += 1
            continue
        elif quote == '' and c == '#' and word_start:
            return i, backticks, None
        word_start = False
        i += 1
    if quote:
        return n, backticks, 'unterminated_quote'
    return n, backticks, None


def _renvint_true(value: str) -> bool:
    m = re.match(r'\s*[-+]?\d+', value)
    if m:
        return int(m.group()) != 0
    v = value.lstrip(' \t\n\v\f\r')
    if v[:2].lower() == 'on':
        return True
    return bool(v) and v[0] in 'yYtTeEaA'


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        return value[1:-1]
    return value


def assess_rcfile(text: str | None, *, kind: str, recipient: str | None = None,
                  privileged_start: bool | None = None) -> dict[str, Any]:
    """Return the programs one procmail rcfile can start and as which user."""
    if kind not in RCFILE_KINDS:
        raise ValueError(f'kind must be one of {RCFILE_KINDS}')
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
        'kind': kind, 'complete': True, 'executions': [], 'forwards': [],
        'includes': [], 'gaps': [], 'warnings': [], 'origin': 'not_assessed',
    }
    gaps, warnings = result['gaps'], result['warnings']
    if text is None:
        result['complete'] = False
        gaps.append({'reason': 'not_observed'})
        return result
    if len(text) > MAX_TEXT:
        result['complete'] = False
        gaps.append({'reason': 'text_too_large', 'limit': MAX_TEXT})
        return result
    result['sha256'] = hashlib.sha256(text.encode('utf-8', 'surrogateescape')).hexdigest()

    recipient_id = recipient or 'recipient'
    if kind == 'user':
        run_as = recipient_id
    elif privileged_start is None:
        run_as = 'unknown'
    else:
        run_as = 'root' if privileged_start else recipient_id
    shell_known = True
    depth = 0
    recipe: dict[str, Any] | None = None  # recipe awaiting conditions/action
    pending = list(reversed(_logical_lines(text)))
    statements = 0

    def gap(line: int, reason: str, **extra: Any) -> None:
        result['complete'] = False
        gaps.append({'line': line, 'reason': reason, **extra})

    def via_shell(command: str) -> bool | str:
        if not shell_known:
            return 'unknown'
        return any(c in DEFAULT_SHELLMETAS for c in command)

    def guard() -> dict[str, Any]:
        return {'block_depth': depth, 'guarded': recipe is not None or depth > 0}

    def execute(line: int, exec_kind: str, command: str, **extra: Any) -> None:
        entry = {'line': line, 'kind': exec_kind, 'command': command,
                 'via_shell': via_shell(command), 'run_as': run_as,
                 'expands_variables': '$' in command, 'origin': 'not_assessed'}
        entry.update(guard())
        entry.update(extra)
        result['executions'].append(entry)

    def backtick_execs(line: int, found: list[str], where: str) -> None:
        for command in found:
            execute(line, 'backtick', command, context=where)

    while pending:
        statements += 1
        if statements > MAX_STATEMENTS:
            gap(0, 'too_many_statements', limit=MAX_STATEMENTS)
            break
        line, raw = pending.pop()
        body = raw.lstrip(' \t')

        if recipe is not None:
            header = recipe
            if body.startswith('*'):
                header['conditions'] += 1
                cond = body[1:].strip(' \t')
                m = _WEIGHT.match(cond)
                if m:
                    cond = cond[m.end():]
                expanded = False
                while cond[:1] in ('!', '$'):
                    if cond[0] == '$':
                        if expanded:  # already expanded: this ``$`` is a variable reference
                            break
                        expanded = True
                    cond = cond[1:].lstrip(' \t')
                if expanded:
                    _end, found, err = _scan(cond, stop_at_blank=False)
                    if err:
                        gap(line, err)
                    backtick_execs(line, found, 'condition')
                    if cond.startswith('$'):
                        gap(line, 'expanded_condition_unresolved', text=cond)
                if cond.startswith('?'):
                    execute(line, 'condition', cond[1:].strip(' \t'), flags=header['flags'])
                continue
            if body == '' or body.startswith('#'):
                if header['conditions'] or header['early_skip']:
                    header['skipped_blank'] |= body == ''
                    continue
                gap(line, 'blank_line_before_action', text=body)
                recipe = None
                continue
            if header['skipped_blank'] and body.startswith(':'):
                warnings.append({'line': line, 'reason': 'missing_action'})
                recipe = None
                pending.append((line, raw))
                continue
            # action line
            flags = header['flags']
            recipe_line = header['line']
            if body.startswith('|'):
                command = body[1:].strip(' \t')
                recipe = header
                if command:
                    execute(line, 'filter' if 'f' in flags else 'pipe', command,
                            flags=flags, recipe_line=recipe_line)
                recipe = None
                continue
            if body.startswith('!'):
                _end, found, err = _scan(body[1:], stop_at_blank=False)
                if err:
                    gap(line, err)
                backtick_execs(line, found, 'forward')
                result['forwards'].append({'line': line, 'arguments': body[1:].strip(' \t'),
                                           'run_as': run_as, **guard()})
                recipe = None
                continue
            if body.startswith('{') and (len(body) == 1 or body[1] in ' \t'):
                recipe = None
                depth += 1
                rest = body[1:].strip(' \t')
                if rest:
                    pending.append((line, rest))
                continue
            cap = re.match(r'([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*([|!])', body)
            if cap:
                if cap.group(2) == '|':
                    command = body[cap.end():].strip(' \t')
                    if command:
                        execute(line, 'capture', command, variable=cap.group(1), flags=flags,
                                recipe_line=recipe_line)
                else:
                    result['forwards'].append({'line': line, 'arguments': body[cap.end():].strip(' \t'),
                                               'run_as': run_as, 'capture': cap.group(1), **guard()})
                recipe = None
                continue
            _end, found, err = _scan(body, stop_at_blank=False)
            if err:
                gap(line, err)
            backtick_execs(line, found, 'folder')
            recipe = None
            continue

        if body == '' or body.startswith('#'):
            continue
        if body.startswith(':'):
            m = re.match(r':(\d*)([^:#]*)(?::(.*))?$', body)
            count, flag_text = (m.group(1), m.group(2)) if m else ('', body[1:])
            if count and int(count) > 0:
                gap(line, 'legacy_condition_count', count=int(count))
            flags = ''.join(c for c in flag_text if c in RECFLAGS)
            unknown = ''.join(c for c in flag_text if c not in RECFLAGS and c not in ' \t')
            if unknown:
                warnings.append({'line': line, 'reason': 'unknown_flags', 'text': unknown})
            recipe = {'line': line, 'flags': flags, 'conditions': 0, 'skipped_blank': False,
                      'early_skip': any(f in flags for f in 'AaEe')}
            continue
        if body.startswith('}'):
            if depth == 0:
                warnings.append({'line': line, 'reason': 'closing_brace_unexpected'})
            else:
                depth -= 1
            rest = body[1:].strip(' \t')
            if rest:
                pending.append((line, rest))
            continue
        m = _NAME.match(body)
        if not m:
            warnings.append({'line': line, 'reason': 'skipped_text', 'text': body[:80]})
            continue
        name = m.group()
        after = body[m.end():].lstrip(' \t')
        if not after.startswith('='):
            rest = after
            value = None
        else:
            value_text = after[1:].lstrip(' \t')
            end, found, err = _scan(value_text, stop_at_blank=True)
            if err:
                gap(line, err)
                continue
            value = value_text[:end]
            rest = value_text[end:].strip(' \t')
            backtick_execs(line, found, 'assignment')
        if rest and not rest.startswith('#'):
            pending.append((line, rest))
        if value is None:
            if name in _SHELL_VARS:
                shell_known = False
            continue
        dynamic = '$' in value or '`' in value
        if name in _SHELL_VARS:
            shell_known = False
        elif name == 'TRAP':
            command = _unquote(value)
            if command:
                execute(line, 'trap', command)
        elif name in ('INCLUDERC', 'SWITCHRC'):
            result['includes'].append({'line': line, 'variable': name, 'path': _unquote(value),
                                       'followed': False, 'run_as': run_as, **guard()})
            gap(line, 'include_not_followed', variable=name, path=_unquote(value))
        elif name == 'DROPPRIVS' and kind == 'global' and run_as == 'root':
            if dynamic or depth > 0:
                run_as = 'unknown'
            elif _renvint_true(_unquote(value)):
                run_as = recipient_id

    if recipe is not None:
        gap(recipe['line'], 'incomplete_recipe')
    if depth:
        gap(0, 'unclosed_block', depth=depth)
    return result
