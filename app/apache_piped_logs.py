"""Pure Apache httpd piped-log program contract (roadmap F slice, #1502).

Takes the captured httpd configuration (the main file, every file an ``Include``
matched, the observed ``-D`` defines and the environment httpd starts with) and
reports which programs httpd starts as *piped loggers*: ``CustomLog``,
``TransferLog``, ``GlobalLog`` and ``ErrorLog`` targets that begin with ``|``.
httpd's own documentation says these "are spawned by the parent Apache httpd
process, and inherit the userid of that process", so they normally run as root;
``User``/``Group`` never apply to them. It never reads a file, expands a glob,
resolves a user or runs a command.

Semantics follow httpd 2.4.62 and APR 1.7.5 source:

* ``ap_cfg_getline``: a ``\\`` directly before the newline (optionally ``\\r\\n``)
  joins the next line, then each line is trimmed. A line whose first character is
  ``#`` is a comment; ``#`` anywhere else is ordinary text.
* ``ap_resolve_env`` runs on the whole line before it is split: ``${NAME}`` takes the
  ``Define`` value first and then the environment. An unknown name stays as written
  (httpd warns unless the name contains ``:``).
* ``ap_getword_conf`` splits words. A ``"`` or ``'`` word runs to the matching quote
  (or the end of the line), where ``\\<quote>`` and ``\\\\`` are unescaped; a bare word
  ends at white space and only ``\\\\`` is unescaped.
* ``Include``/``IncludeOptional`` resolve against the ``ServerRoot`` in force when they
  are read, and the matches are processed in sorted order. A non-optional include
  that matches nothing stops httpd. ``<IfDefine>`` is decided from ``-D`` and
  ``Define``/``UnDefine`` as they are read; a false section is skipped unparsed.
  Other ``<If...>`` containers are kept as conditions on what they contain.
* ``ap_open_piped_log``/``open_error_log``: after the first ``|`` an optional second
  ``|`` is dropped, and a following ``$`` selects ``APR_SHELLCMD_ENV``. Otherwise
  ``APR_PROGRAM_ENV`` execs ``argv[0]`` directly with ``execv`` (no ``PATH`` search).
  Words come from ``apr_tokenize_to_argv``. In shell mode APR joins those words with
  single spaces and runs ``/bin/sh -c`` on the result, so quotes and backslashes are
  already gone. The working directory is the final ``ServerRoot``.
* Every ``CustomLog``/``TransferLog``/``GlobalLog`` directive opens its own logger.
  Only the last ``ErrorLog`` of a server counts, and a virtual host whose
  ``ErrorLog`` string equals an earlier server's shares that logger.

It performs no I/O and never authorizes a response action. Constructs that make
the answer uncertain are explicit gaps; the result is never complete while a
blocking gap is present.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'httpd': '2.4.62', 'apr': '1.7.5'}
MAX_TEXT = 524288
MAX_FILES = 512
MAX_INCLUDE_DEPTH = 32
MAX_PROGRAMS = 512
MAX_GAPS = 48
SHELL_PATH = '/bin/sh'
RUNS_AS = ('httpd parent process user (root when httpd is started as root); User and Group do not apply '
           'to piped loggers')
BLOCKING = frozenset({
    'input_malformed', 'text_too_large', 'too_many_files', 'nul_byte', 'include_not_observed',
    'file_not_observed', 'include_failed', 'include_too_deep', 'container_unbalanced', 'container_malformed',
    'nested_virtual_host', 'directive_not_allowed', 'arguments_malformed', 'variable_unresolved',
    'variable_conditional', 'server_root_conditional', 'server_root_malformed', 'macro_unmodelled',
    'empty_program', 'error_log_conditional', 'too_many_programs', 'gaps_truncated',
})
UNOBSERVED = (
    '<IfModule>, <IfFile>, <IfDirective>, <IfSection> and <IfVersion> are not evaluated; programs inside them are '
    'reported with the condition.',
    'Whether mod_log_config is loaded, and whether each program exists and is executable, is not checked. httpd '
    'refuses to start when a piped logger cannot be spawned.',
    'The user httpd itself starts as comes from its service manager and is not observed here.',
    'Piped loggers are started again on every restart and graceful restart, and are restarted if they exit.',
    'Programs started by other mechanisms (RewriteMap prg:, ExtFilterDefine, SSLPassPhraseDialog exec:, '
    'SSLRandomSeed exec:, CGI) are listed under other_programs but not resolved.',
)
NOT_A_VERDICT = 'Configuration text only. This is not a safety verdict and origin is not assessed.'
_CONDITIONAL = frozenset({'<ifmodule', '<iffile', '<ifdirective', '<ifsection', '<ifversion'})
_PER_REQUEST = frozenset({'<if', '<elseif', '<else'})
_LOGS = frozenset({'customlog', 'globallog', 'transferlog', 'errorlog'})
_VAR = re.compile(r'\$\{([^}]*)\}')
_WILDCARD = re.compile(r'[*?\[]')


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


def config_lines(text: str) -> list[tuple[int, str]]:
    """Split text into (first line number, trimmed logical line) as ap_cfg_getline does."""
    out: list[tuple[int, str]] = []
    physical = text.split('\n')
    if physical and physical[-1] == '':
        physical.pop()
    buf, start = '', None
    for number, raw in enumerate(physical, 1):
        if start is None:
            start = number
        piece = raw[:-1] if raw.endswith('\r') else raw
        if piece.endswith('\\') and (number < len(physical) or text.endswith('\n')):
            buf += piece[:-1]
            continue
        buf += piece
        out.append((start, buf.strip(' \t\n\v\f\r')))
        buf, start = '', None
    return out


def getword_conf(line: str) -> tuple[str, str]:
    """Return (word, rest) like ap_getword_conf; the rest has leading white space skipped."""
    i, n = 0, len(line)
    while i < n and line[i].isspace():
        i += 1
    if i >= n:
        return '', ''
    quote = line[i] if line[i] in '"\'' else ''
    out: list[str] = []
    if quote:
        j = i + 1
        while j < n and line[j] != quote:
            if line[j] == '\\' and j + 1 < n and line[j + 1] in (quote, '\\'):
                out.append(line[j + 1])
                j += 2
            else:
                out.append(line[j])
                j += 1
        if j < n:
            j += 1
    else:
        j = i
        while j < n and not line[j].isspace():
            if line[j] == '\\' and j + 1 < n and line[j + 1] == '\\':
                out.append('\\')
                j += 2
            else:
                out.append(line[j])
                j += 1
    while j < n and line[j].isspace():
        j += 1
    return ''.join(out), line[j:]


def tokenize_to_argv(arg: str) -> list[str]:
    """Port of apr_tokenize_to_argv (APR 1.7.5 strings/apr_cpystrn.c)."""
    argv: list[str] = []
    i, n = 0, len(arg)

    def skip_ws(k: int) -> int:
        while k < n and arg[k] in ' \t':
            k += 1
        return k

    i = skip_ws(i)
    while i < n:
        quoted = 0
        if arg[i] == '"':
            quoted, i = 1, i + 1
        elif arg[i] == "'":
            quoted, i = 2, i + 1
        start = i
        while i < n:
            if arg[i] == '\\' and i + 1 < n and arg[i + 1] in ' \t"\'':
                i += 2
                continue
            if (not quoted and arg[i] in ' \t') or (quoted == 1 and arg[i] == '"') or \
                    (quoted == 2 and arg[i] == "'"):
                break
            i += 1
        raw = arg[start:min(i, n)]
        cleaned, escaped = [], False
        for ch in raw:
            if not escaped and ch == '\\':
                escaped = True
            else:
                escaped = False
                cleaned.append(ch)
        argv.append(''.join(cleaned))
        if i < n:
            i += 1
        i = skip_ws(i)
    return argv


def piped_program(target: str, server_root: str) -> dict[str, Any] | None:
    """Describe the process httpd spawns for a ``|`` log target, or None for a file/syslog target."""
    if not target.startswith('|'):
        return None
    program = target[1:]
    if program.startswith('|'):
        program = program[1:]
    shell = program.startswith('$')
    if shell:
        program = program[1:]
    words = tokenize_to_argv(program)
    if not words:
        return {'invocation': 'shell' if shell else 'direct', 'argv': [], 'executable': None}
    if shell:
        command = ' '.join(words)
        return {'invocation': 'shell', 'argv': [SHELL_PATH, '-c', command], 'executable': SHELL_PATH,
                'shell_command': command}
    executable = words[0] if words[0].startswith('/') else posixpath.normpath(posixpath.join(server_root, words[0]))
    return {'invocation': 'direct', 'argv': words, 'executable': executable}


def _relative(root: str, path: str) -> str:
    return path if path.startswith('/') else posixpath.join(root, path)


class _Parser:
    def __init__(self, payload: dict[str, Any], gaps: list[dict[str, Any]]):
        self.files: dict[str, Any] = payload['files']
        self.includes: dict[str, Any] = payload['includes']
        self.env: dict[str, str] = payload['environment']
        self.server_root: str = payload['server_root']
        self.defines: dict[str, str | None] = {name: None for name in payload['defines']}
        self.uncertain: set[str] = set()
        self.gaps = gaps
        self.stack: list[dict[str, Any]] = []
        self.active: list[str] = []
        self.servers: list[dict[str, Any]] = [{'name': 'main', 'error_logs': []}]
        self.logs: list[dict[str, Any]] = []
        self.other: list[dict[str, Any]] = []
        self.parsed: list[str] = []

    # -- helpers -------------------------------------------------------------
    def conditions(self) -> list[str]:
        return [c['condition'] for c in self.stack if c.get('condition')]

    def in_vhost(self) -> dict[str, Any] | None:
        for c in self.stack:
            if c['kind'] == 'vhost':
                return c
        return None

    def resolve(self, line: str, relevant: bool, where: dict[str, Any]) -> str:
        def sub(m: re.Match[str]) -> str:
            name = m.group(1)
            if name in self.uncertain and relevant:
                _gap(self.gaps, 'variable_conditional', where, f'${{{name}}} is set inside an unevaluated condition.')
            if name in self.defines and self.defines[name] is not None:
                return str(self.defines[name])
            if name in self.env:
                return self.env[name]
            if relevant and ':' not in name:
                _gap(self.gaps, 'variable_unresolved', where, f'${{{name}}} is neither defined nor in the '
                                                              'observed environment.')
            return m.group(0)
        return _VAR.sub(sub, line)

    # -- parsing -------------------------------------------------------------
    def parse_file(self, path: str, depth: int) -> None:
        if depth > MAX_INCLUDE_DEPTH:
            _gap(self.gaps, 'include_too_deep', {'file': path})
            return
        if path in self.active:
            _gap(self.gaps, 'include_too_deep', {'file': path}, 'The file includes itself.')
            return
        text = self.files.get(path)
        if text is None:
            _gap(self.gaps, 'file_not_observed', {'file': path})
            return
        if not isinstance(text, str):
            _gap(self.gaps, 'input_malformed', {'file': path}, 'File text must be a string.')
            return
        if len(text) > MAX_TEXT:
            _gap(self.gaps, 'text_too_large', {'file': path})
            return
        if '\0' in text:
            _gap(self.gaps, 'nul_byte', {'file': path})
            return
        if len(self.parsed) >= MAX_FILES:
            _gap(self.gaps, 'too_many_files', {'file': path})
            return
        self.parsed.append(path)
        self.active.append(path)
        base = len(self.stack)
        lines = config_lines(text)
        k = 0
        while k < len(lines):
            number, line = lines[k]
            k = self.line(path, lines, k, number, line, depth)
        if len(self.stack) > base:
            _gap(self.gaps, 'container_unbalanced', {'file': path},
                 f'{self.stack[-1]["tag"]}> is not closed in the same file.')
            del self.stack[base:]
        self.active.pop()

    def soak(self, path: str, lines: list[tuple[int, str]], k: int, tag: str) -> int:
        """Skip an unparsed section, as ap_soak_end_container does. Returns the index after its end."""
        while k < len(lines):
            number, line = lines[k]
            k += 1
            word, rest = getword_conf(line)
            if not word.startswith('<'):
                continue
            if word.startswith('</'):
                if word[2:-1].lower() != tag[1:].lower():
                    _gap(self.gaps, 'container_unbalanced', {'file': path, 'line': number},
                         f'Expected </{tag[1:]}> but saw {word}.')
                return k
            k = self.soak(path, lines, k, word[:-1] if not rest and word.endswith('>') else word)
        _gap(self.gaps, 'container_unbalanced', {'file': path}, f'{tag}> is not closed.')
        return k

    def line(self, path: str, lines: list[tuple[int, str]], k: int, number: int, line: str, depth: int) -> int:
        where = {'file': path, 'line': number}
        if not line or line.startswith('#'):
            return k + 1
        first, _ = getword_conf(line)
        name = first.lower()
        relevant = name in _LOGS or name in ('include', 'includeoptional', 'serverroot', 'define', 'undefine',
                                             '<ifdefine', '<virtualhost')
        line = self.resolve(line, relevant, where)
        word, args = getword_conf(line)
        name = word.lower()
        if name.startswith('</'):
            if not self.stack or not word.endswith('>') or name[2:-1] != self.stack[-1]['tag'][1:].lower():
                _gap(self.gaps, 'container_unbalanced', where, f'{word} has no matching opening section.')
                return k + 1
            self.stack.pop()
            return k + 1
        if name.startswith('<'):
            return self.container(path, lines, k, where, word, args)
        if name == 'define' or name == 'undefine':
            words = self.words(args)
            if not words or len(words) > (2 if name == 'define' else 1):
                _gap(self.gaps, 'arguments_malformed', where, f'{word} takes {"one or two" if name == "define" else "one"} '
                                                              'arguments.')
                return k + 1
            if self.conditions():
                self.uncertain.add(words[0])
            elif name == 'define':
                self.defines[words[0]] = words[1] if len(words) == 2 else None
                self.uncertain.discard(words[0])
            else:
                self.defines.pop(words[0], None)
                self.uncertain.discard(words[0])
            return k + 1
        if name == 'serverroot':
            words = self.words(args)
            if len(words) != 1 or not words[0]:
                _gap(self.gaps, 'server_root_malformed', where)
            elif self.conditions():
                _gap(self.gaps, 'server_root_conditional', where)
            else:
                self.server_root = posixpath.normpath(_relative(self.server_root, words[0]))
            return k + 1
        if name in ('include', 'includeoptional'):
            self.include(where, name == 'includeoptional', args, depth)
            return k + 1
        if name in _LOGS:
            self.log(where, word, name, args)
            return k + 1
        if name in ('use',):
            _gap(self.gaps, 'macro_unmodelled', where, 'mod_macro Use expands text that is not modelled.')
            return k + 1
        self.other_program(where, word, name, args)
        return k + 1

    def words(self, args: str) -> list[str]:
        out = []
        while args:
            word, args = getword_conf(args)
            out.append(word)
        return out

    def container(self, path: str, lines: list[tuple[int, str]], k: int, where: dict[str, Any], word: str,
                  args: str) -> int:
        if args:
            if not args.endswith('>'):
                _gap(self.gaps, 'container_malformed', where, f'{word} is missing its closing ">".')
                return self.soak(path, lines, k + 1, word)
            tag, arg = word, args[:-1].strip()
        elif word.endswith('>'):
            tag, arg = word[:-1], ''
        else:
            _gap(self.gaps, 'container_malformed', where, f'{word} is missing its closing ">".')
            return self.soak(path, lines, k + 1, word)
        lower = tag.lower()
        entry: dict[str, Any] = {'tag': tag, 'kind': 'other', 'condition': None}
        if lower == '<ifdefine':
            negate = arg.startswith('!')
            define = arg[1:] if negate else arg
            if not define:
                _gap(self.gaps, 'container_malformed', where, '<IfDefine> needs a parameter name.')
                return self.soak(path, lines, k + 1, tag)
            if define in self.uncertain:
                entry.update(kind='condition', condition=f'<IfDefine {arg}>')
            elif (define in self.defines) == negate:
                return self.soak(path, lines, k + 1, tag)
            else:
                entry['kind'] = 'transparent'
        elif lower in _CONDITIONAL:
            entry.update(kind='condition', condition=f'{tag} {arg}>' if arg else f'{tag}>')
        elif lower == '<virtualhost':
            if self.in_vhost() is not None:
                _gap(self.gaps, 'nested_virtual_host', where)
                return self.soak(path, lines, k + 1, tag)
            server = {'name': f'<VirtualHost {arg}>', 'error_logs': [], **where}
            self.servers.append(server)
            entry.update(kind='vhost', server=server)
        elif lower == '<macro':
            _gap(self.gaps, 'macro_unmodelled', where, '<Macro> bodies are expanded by Use, which is not modelled.')
            return self.soak(path, lines, k + 1, tag)
        elif lower in _PER_REQUEST:
            entry['kind'] = 'per_request'
        self.stack.append(entry)
        return k + 1

    def include(self, where: dict[str, Any], optional: bool, args: str, depth: int) -> None:
        words = self.words(args)
        if len(words) != 1 or not words[0]:
            _gap(self.gaps, 'arguments_malformed', where, 'Include takes one argument.')
            return
        pattern = posixpath.normpath(_relative(self.server_root, words[0]))
        matches = self.includes.get(pattern)
        if matches is None:
            _gap(self.gaps, 'include_not_observed', where, f'No captured matches for {pattern}.')
            return
        if not isinstance(matches, list) or not all(isinstance(m, str) for m in matches):
            _gap(self.gaps, 'input_malformed', where, f'Matches for {pattern} must be a list of paths.')
            return
        if not matches:
            if not optional:
                kind = 'wildcard matches nothing' if _WILDCARD.search(pattern) else 'file does not exist'
                _gap(self.gaps, 'include_failed', where, f'Include {pattern}: {kind}; httpd does not start.')
            return
        for match in sorted(matches):
            self.parse_file(match, depth + 1)

    def log(self, where: dict[str, Any], word: str, name: str, args: str) -> None:
        if any(c['kind'] in ('other', 'per_request') for c in self.stack):
            _gap(self.gaps, 'directive_not_allowed', where, f'{word} is only allowed in the server config or a '
                                                            '<VirtualHost>; httpd does not start.')
            return
        vhost = self.in_vhost()
        if name == 'globallog' and vhost is not None:
            _gap(self.gaps, 'directive_not_allowed', where, 'GlobalLog cannot be used inside <VirtualHost>.')
            return
        words = self.words(args)
        if name in ('customlog', 'globallog'):
            ok = len(words) in (2, 3) and all(words[:2]) and (
                len(words) == 2 or words[2][:4].lower() == 'env=' or words[2][:5].lower() == 'expr=')
        else:
            ok = len(words) == 1 and bool(words[0])
        if not ok:
            _gap(self.gaps, 'arguments_malformed', where, f'{word} has the wrong arguments; httpd does not start.')
            return
        server = vhost['server'] if vhost is not None else self.servers[0]
        record = {'directive': word, 'target': words[0], 'server': server['name'], 'conditions': self.conditions(),
                  **where}
        if name == 'errorlog':
            server['error_logs'].append(record)
            return
        record['log_condition'] = words[2] if len(words) == 3 else None
        self.logs.append(record)

    def other_program(self, where: dict[str, Any], word: str, name: str, args: str) -> None:
        words = self.words(args)
        hit = (name == 'rewritemap' and len(words) >= 2 and words[1][:4].lower() == 'prg:') or \
            name == 'extfilterdefine' or \
            (name == 'sslpassphrasedialog' and words[:1] and words[0][:5].lower() == 'exec:') or \
            (name == 'sslrandomseed' and len(words) >= 2 and words[1][:5].lower() == 'exec:')
        if hit:
            self.other.append({'directive': word, 'status': 'not_modelled', 'conditions': self.conditions(), **where})


def _program(record: dict[str, Any], server_root: str, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    spawn = piped_program(record['target'], server_root)
    if spawn is None:
        return None
    if not spawn['argv']:
        _gap(gaps, 'empty_program', {'file': record['file'], 'line': record['line']},
             'The pipe names no program; httpd cannot start the logger.')
        return None
    entry = {key: value for key, value in record.items() if key != 'target'}
    entry.update(spawn)
    entry.update(target=record['target'], working_directory=server_root, runs_as=RUNS_AS)
    return entry


def evaluate(payload: Any) -> dict[str, Any]:
    """Resolve the piped-log programs one httpd configuration starts.

    ``payload`` keys: ``server_root`` (absolute; the compiled default or ``-d``),
    ``config_file`` (absolute path of the main file, the compiled default or ``-f``),
    ``files`` (path to text for the main file and every included file), ``includes``
    (each ``Include``/``IncludeOptional`` argument resolved against ``ServerRoot`` and
    normalised, mapped to the list of matched file paths; an empty list means no
    match), optional ``defines`` (the ``-D`` names from httpd's argv) and optional
    ``environment`` (the variables httpd starts with, such as Debian's ``envvars``).
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'programs': [],
                              'shared_error_logs': [], 'other_programs': [], 'files_parsed': [], 'gaps': gaps,
                              'complete': False, 'unobserved': list(UNOBSERVED), 'note': NOT_A_VERDICT,
                              'origin': 'not_assessed'}
    if not isinstance(payload, dict):
        _gap(gaps, 'input_malformed', detail='The payload must be an object.')
        return result
    clean = {'server_root': payload.get('server_root'), 'files': payload.get('files'),
             'includes': payload.get('includes', {}), 'defines': payload.get('defines', []),
             'environment': payload.get('environment', {})}
    config = payload.get('config_file')
    if not (isinstance(clean['server_root'], str) and clean['server_root'].startswith('/')
            and isinstance(config, str) and config.startswith('/') and isinstance(clean['files'], dict)
            and isinstance(clean['includes'], dict) and isinstance(clean['defines'], list)
            and all(isinstance(d, str) and d for d in clean['defines'])
            and isinstance(clean['environment'], dict)
            and all(isinstance(a, str) and isinstance(b, str) for a, b in clean['environment'].items())):
        _gap(gaps, 'input_malformed', detail='The payload needs absolute server_root and config_file, files and '
                                             'includes objects, a defines list and a string environment.')
        return result
    clean['server_root'] = posixpath.normpath(clean['server_root'])
    parser = _Parser(clean, gaps)
    parser.parse_file(config, 0)
    root = parser.server_root
    result['files_parsed'] = parser.parsed
    result['server_root'] = root
    programs: list[dict[str, Any]] = []
    for record in parser.logs:
        program = _program(record, root, gaps)
        if program is not None:
            programs.append(program)
    # (ErrorLog string, server, conditional) in server order, as ap_open_logs compares them.
    owners: list[tuple[str, str, bool]] = []
    for index, server in enumerate(parser.servers):
        logs = server['error_logs']
        if len(logs) > 1 and any(r['conditions'] for r in logs[1:]):
            _gap(gaps, 'error_log_conditional', {'file': logs[-1]['file'], 'line': logs[-1]['line']},
                 f'Which ErrorLog wins for {server["name"]} depends on an unevaluated condition.')
        chosen = logs[-1] if logs else None
        if chosen is None:
            if index == 0:
                owners.append(('logs/error_log', server['name'], False))  # DEFAULT_ERRORLOG, a file
            continue  # a virtual host without ErrorLog writes to the main server's log
        owner = next((o for o in owners if o[0] == chosen['target']), None) if index else None
        if owner is not None and not owner[2]:
            result['shared_error_logs'].append({'server': server['name'], 'file': chosen['file'],
                                                'line': chosen['line'], 'shares_with': owner[1]})
            continue
        owners.append((chosen['target'], server['name'], bool(chosen['conditions'])))
        program = _program(chosen, root, gaps)
        if program is not None:
            if owner is not None:
                # The earlier server's identical ErrorLog is itself conditional; report this one rather than
                # assume it is shared.
                program['may_share_with'] = owner[1]
            programs.append(program)
    if len(programs) > MAX_PROGRAMS:
        _gap(gaps, 'too_many_programs', detail=f'Only the first {MAX_PROGRAMS} programs are listed.')
        programs = programs[:MAX_PROGRAMS]
    result['programs'] = programs
    result['other_programs'] = parser.other
    result['complete'] = not any(g['code'] in BLOCKING for g in gaps)
    return result
