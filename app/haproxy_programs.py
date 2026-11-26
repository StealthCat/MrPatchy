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
  stays literal). Words are C strings, so a NUL from ``\\x00`` ends the word.
  ``$VAR``/``${VAR}`` expand inside double quotes only. At most
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

Increment 2 adds ``external-check`` health-check commands, ported from
``extcheck.c`` (``proxy_parse_extcheck``, ``proxy_parse_external_check_opt``,
``prepare_external_check``, ``connect_proc_chk``), the proxy post-parser in
``cfgparse.c``, ``proxy_preset_defaults`` in ``proxy.c``, the global
``external-check``/``user``/``uid``/``group``/``gid``/``chroot``/
``insecure-fork-wanted`` keywords and ``set_identity``/``run_thread_poll_loop``
in ``haproxy.c``:

* ``option external-check`` and the other check-type options (``httpchk``,
  ``tcp-check``, ...) each replace the proxy's single check type; the negated or
  ``default`` forms are fatal. ``external-check command <cmd>`` and
  ``external-check path <path>`` take exactly one non-empty word, and the last
  one wins. A regular proxy copies the check type, command and path of the last
  ``defaults`` section parsed (in any earlier file); a ``defaults`` section
  starts empty.
* After parsing, every listen/frontend/backend whose check type is external
  needs the global ``external-check`` keyword and a command. A command without
  a leading ``/`` needs a path even when the check type is not external. Each of
  these is fatal. Otherwise a command or path without the external check type is
  ignored.
* A worker forks ``execvp(command, [command, <proxy addr>, <proxy port>,
  <server addr>, <server port>])`` for each server with health checks. ``PATH``
  is the configured path, or empty. The environment holds only ``PATH`` and the
  ``HAPROXY_*`` variables unless ``external-check preserve-env`` is set.
* The worker runs inside the global ``chroot``, after ``setgroups(0)`` and
  ``setgid`` when a group is set and ``setuid`` when a user is set. Without
  ``insecure-fork-wanted`` the worker sets ``RLIMIT_NPROC`` to 0, so the fork
  fails unless the worker is still root.

It performs no I/O and never authorizes a response action. Constructs it does not
model (environment variables, ``.if`` conditions other than integer constants,
scope directives, named ``defaults ... from`` inheritance, a repeated global
user/group whose first value may resolve to 0) and configuration errors that stop
HAProxy from starting are explicit blocking gaps, as is over-limit input. A
result with any of them is never reported complete.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 2
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
CHECK_TYPE_OPTIONS = frozenset({'httpchk', 'ssl-hello-chk', 'smtpchk', 'pgsql-check', 'redis-check', 'mysql-check',
                                'ldap-check', 'spop-check', 'tcp-check', 'external-check'})
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
    'program_duplicate', 'program_without_command', 'external_check_malformed', 'external_check_not_enabled',
    'external_check_without_command', 'external_check_relative_without_path', 'defaults_from_unmodelled',
    'global_identity_ambiguous', 'gaps_truncated',
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
    ('An external check runs once per check interval for each server with health checks enabled; "check", '
     '"default-server", "server-template", "no-check" and "disabled" are not evaluated, so every proxy with an '
     'external check type is listed with its server lines.'),
    ('External checks run in worker processes. Without a global "user"/"uid" the worker keeps the identity HAProxy '
     'was started with (root under the packaged systemd unit), including its supplementary groups unless a '
     'group is set.'),
    'A chroot path is reported as written; the command and PATH entries are resolved inside it.',
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
    # Words are C strings: a NUL produced by \x00 ends the word, as strdup and strcmp see it.
    words = [''.join(w).split('\0', 1)[0] for w in out]
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


def _new_proxy(kind: str, name: str, where: dict[str, Any], base: dict[str, Any] | None) -> dict[str, Any]:
    proxy = {'check_type': None, 'option_location': None, 'command': None, 'command_location': None,
             'path': None, 'path_location': None}
    if base:  # proxy_preset_defaults copies options2, check_command and check_path
        proxy.update({k: base[k] for k in proxy})
    proxy.update(kind=kind, id=name, location=where, servers=[])
    return proxy


def _external_checks(proxies: list[dict[str, Any]], glob: dict[str, Any],
                     gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply the cfgparse.c proxy post-parser and describe each external check a worker forks."""
    checks: list[dict[str, Any]] = []
    for proxy in proxies:
        where = {'path': proxy['location']['path'], 'line': proxy['location']['line']}
        external = proxy['check_type'] == 'external-check'
        command, path = proxy['command'], proxy['path']
        if external and glob['enabled'] is None:
            _gap(gaps, 'external_check_not_enabled', where, f'{proxy["id"]}: no global "external-check".')
        if external and command is None:
            _gap(gaps, 'external_check_without_command', where, proxy['id'])
        if command is not None and not command.startswith('/') and path is None:
            _gap(gaps, 'external_check_relative_without_path', where, proxy['id'])
        if not external or command is None or proxy['kind'] == 'frontend':
            continue  # ignored without the external check type; a frontend has no servers
        runs_as: dict[str, Any] = {
            'user': glob['user'], 'uid': glob['uid'], 'group': glob['group'], 'gid': glob['gid'],
            'supplementary_groups_dropped': glob['group'] is not None or glob['gid'] is not None,
        }
        as_root = glob['user'] is None and glob['uid'] is None
        if as_root:
            runs_as['user_note'] = 'HAProxy process identity (root under the packaged systemd unit)'
        if glob['insecure_fork_wanted']:
            fork = 'allowed'
        elif as_root:
            fork = 'allowed_for_root_worker_only'
        else:
            fork = 'fails_unless_user_resolves_to_root'
        checks.append({
            'proxy': proxy['id'], 'proxy_type': proxy['kind'], 'location': proxy['location'],
            'command': command, 'command_location': proxy['command_location'],
            'option_location': proxy['option_location'],
            'argv_template': [command, '<first bind address or NOT_USED>', '<first bind port or NOT_USED>',
                              '<server address>', '<server port>'],
            'path_env': path or '', 'path_location': proxy['path_location'], 'path_lookup': '/' not in command,
            'environment': 'preserved_and_merged' if glob['preserve_env'] else 'only_path_and_haproxy_variables',
            'chroot': glob['chroot'], 'runs_as': runs_as, 'fork': fork,
            'insecure_fork_wanted': glob['insecure_fork_wanted'], 'servers': list(proxy['servers']),
        })
    if checks and glob['identity_repeats']:
        _gap(gaps, 'global_identity_ambiguous', glob['identity_repeats'][0],
             'A repeated user/uid or group/gid is skipped only when the first value resolved to a non-zero id.')
    return checks


def evaluate(files: Any) -> dict[str, Any]:
    """Report the program sections HAProxy's master starts for ``files``.

    ``files`` is a sequence of ``{'path': str, 'text': str}`` in HAProxy load order.
    """
    gaps: list[dict[str, Any]] = []
    programs: list[dict[str, Any]] = []
    master_worker: dict[str, Any] | None = None
    external_checks: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'complete': False, 'programs': programs,
        'external_checks': external_checks, 'master_worker_in_config': None, 'gaps': gaps,
        'unobserved': list(UNOBSERVED), 'not_a_verdict': NOT_A_VERDICT,
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
    glob: dict[str, Any] = {'enabled': None, 'preserve_env': False, 'insecure_fork_wanted': False, 'user': None,
                            'uid': None, 'group': None, 'gid': None, 'chroot': None, 'identity_repeats': []}
    proxies: list[dict[str, Any]] = []
    proxy: dict[str, Any] | None = None
    last_defaults: dict[str, Any] | None = None  # cfg_parse_listen's static last_defproxy spans files
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

            if section in PROXY_SECTIONS:
                if head == section:
                    if 'from' in words[1:]:
                        _gap(gaps, 'defaults_from_unmodelled', where, 'Named defaults inheritance is not modelled.')
                    if head == 'defaults':
                        proxy = last_defaults = _new_proxy(head, arg(1), where, None)
                    else:
                        proxy = _new_proxy(head, arg(1), where, last_defaults)
                        proxies.append(proxy)
                    continue
                if proxy is None:
                    continue
                if head == 'option' and arg(1) in CHECK_TYPE_OPTIONS:
                    if kwm != 'std':
                        if arg(1) == 'external-check':
                            _gap(gaps, 'external_check_malformed', where, f'"{kwm} option external-check" is fatal.')
                        continue
                    proxy['check_type'] = arg(1)  # each check-type option replaces PR_O2_CHK_ANY
                    if arg(1) == 'external-check':
                        proxy['option_location'] = where
                        if arg(2):
                            _gap(gaps, 'external_check_malformed', where, '"option external-check" takes no argument.')
                elif head == 'external-check':
                    if arg(1) in ('command', 'path') and arg(2) and not arg(3) and kwm == 'std':
                        proxy[arg(1)] = arg(2)
                        proxy[arg(1) + '_location'] = where
                    else:
                        _gap(gaps, 'external_check_malformed', where,
                             '"external-check" takes "command <cmd>" or "path <path>".')
                elif head in ('server', 'server-template') and section in ('backend', 'listen') and arg(1):
                    proxy['servers'].append({'name': arg(1), 'keyword': head, 'location': where})
                continue
            if section == 'global':
                if head == 'master-worker' and kwm == 'std' and arg(1) in ('', 'no-exit-on-failure') and not arg(2):
                    master_worker = where
                elif head == 'external-check' and kwm == 'std':
                    if arg(1) in ('', 'preserve-env') and not arg(2):
                        glob['enabled'] = where
                        glob['preserve_env'] = arg(1) == 'preserve-env'
                    else:
                        _gap(gaps, 'external_check_malformed', where, 'Only "preserve-env" is accepted.')
                elif head == 'insecure-fork-wanted' and not arg(1):
                    glob['insecure_fork_wanted'] = kwm != 'no'
                elif head in ('user', 'uid', 'group', 'gid') and kwm == 'std' and arg(1):
                    pair = ('user', 'uid') if head in ('user', 'uid') else ('group', 'gid')
                    if any(glob[k] is not None for k in pair):
                        glob['identity_repeats'].append(where)  # skipped only if the first id is non-zero
                    else:
                        glob[head] = arg(1)
                elif head == 'chroot' and kwm == 'std' and arg(1) and glob['chroot'] is None:
                    glob['chroot'] = arg(1)
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
    external_checks.extend(_external_checks(proxies, glob, gaps))
    result['external_check_global'] = {k: glob[k] for k in ('enabled', 'preserve_env', 'insecure_fork_wanted')}
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
