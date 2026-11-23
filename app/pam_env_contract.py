"""Pure pam_env contract: which variables pam_env sets in a PAM session.

``pam_env.so`` is stacked in the session (and often auth) phase of login,
sshd, su, sudo, cron and display-manager PAM services. Every variable it
sets is exported to the processes those services start. Variables such as
``LD_PRELOAD``, ``BASH_ENV`` or ``PATH`` in ``/etc/environment`` or
``/etc/security/pam_env.conf`` therefore make every later login load or run
code chosen by whoever can write those files.

This module answers, without touching the host, which variables one
``pam_env.so`` instance sets or removes, with which value, from which file
and line, and whether the module call succeeds. It follows Linux-PAM 1.5.3
``modules/pam_env/pam_env.c`` as built by Debian/Ubuntu (no libeconf, no
vendor directory):

* Module arguments: ``conffile=``, ``envfile=``, ``user_envfile=`` (empty
  values ignored), ``readenv=`` and ``user_readenv=`` (C ``atoi``) and
  ``debug``. Unknown arguments are logged and ignored.
* The configuration file (``/etc/security/pam_env.conf``) is read first.
  If it cannot be opened the module returns ``PAM_IGNORE`` and the
  environment file is **not** read. The status of the configuration file's
  *last* line decides whether the module succeeds: a malformed final line or
  removal of an unset variable makes it return ``PAM_ABORT`` and skip the
  environment file, although earlier lines still took effect.
* ``VARIABLE [DEFAULT=[value]] [OVERRIDE=[value]]`` with ``${VAR}`` (PAM
  environment) and ``@{ITEM}`` (``PAM_USER``, ``PAM_TTY``, ``PAM_RUSER``,
  ``PAM_RHOST``, ``PAM_USER_PROMPT``, ``HOME``, ``SHELL``) expansion and
  ``\\$``/``\\@`` escapes. A non-empty override wins; otherwise a present
  default (even ``""``) defines the variable and an absent default removes
  it.
* The environment file (``/etc/environment`` unless ``envfile=``) is then
  read when ``readenv`` is non-zero: ``[export ]NAME=value`` lines with
  pam_env's partial quote stripping and no expansion; a bare ``NAME``
  removes the variable.
* With ``user_readenv`` non-zero, ``$HOME/<user_envfile>`` is read with the
  configuration-file syntax, as the user.
* Both files use pam_env's line assembly: text after the first ``#`` is
  dropped, a trailing backslash joins the next line, and a final
  unterminated continuation line is discarded.

Fail-closed: values that depend on unknown PAM items, an incompletely known
starting environment or unobserved files are reported as unresolved and the
result is ``complete: False``. Oversized lines, NUL bytes and expansions
near pam_env's 8 KiB buffers are gaps rather than guesses.

Not modelled: which PAM services stack ``pam_env.so`` and with which control
flag (see ``app/pam_stacks.py``), whether ``pam_open_session`` failure
stops the login, ``pam_sm_setcred`` invocation in the auth phase (same
logic, separate call), libeconf/vendordir builds (``/usr/etc``), the
session's later shell start-up and whether a privileged program sanitises
the variables. Nothing here executes, reads or changes anything.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 1

DEFAULT_CONF_FILE = '/etc/security/pam_env.conf'
DEFAULT_ENV_FILE = '/etc/environment'
DEFAULT_USER_ENV_FILE = '.pam_environment'

BUF_SIZE = 8192
MAX_ENV = 8192

_ITEM_NAMES = frozenset({'PAM_USER', 'PAM_USER_PROMPT', 'PAM_TTY', 'PAM_RUSER', 'PAM_RHOST', 'HOME', 'SHELL'})

# Variables whose value makes later processes load or run something.
_RISK: dict[str, tuple[str, str]] = {
    'LD_PRELOAD': ('dynamic_loader', 'the dynamic loader injects these libraries into every non-setuid program'),
    'LD_LIBRARY_PATH': ('dynamic_loader', 'the dynamic loader searches these directories before the system ones'),
    'LD_AUDIT': ('dynamic_loader', 'the dynamic loader loads these audit libraries into every non-setuid program'),
    'GCONV_PATH': ('dynamic_loader', 'glibc iconv loads conversion modules from these directories'),
    'BASH_ENV': ('shell_startup', 'non-interactive bash sources this file before running any script'),
    'ENV': ('shell_startup', 'interactive POSIX sh/dash and bash in POSIX mode source this file'),
    'PROMPT_COMMAND': ('shell_startup', 'interactive bash runs this command before every prompt'),
    'PYTHONSTARTUP': ('interpreter_startup', 'interactive Python runs this file at start-up'),
    'PYTHONPATH': ('interpreter_startup', 'Python imports modules from these directories first'),
    'PYTHONHOME': ('interpreter_startup', 'Python loads its standard library from this prefix'),
    'PERL5OPT': ('interpreter_startup', 'perl applies these command-line switches, including -M module loads'),
    'PERL5LIB': ('interpreter_startup', 'perl loads modules from these directories first'),
    'PERLLIB': ('interpreter_startup', 'perl loads modules from these directories first'),
    'RUBYOPT': ('interpreter_startup', 'ruby applies these options, including -r library loads'),
    'RUBYLIB': ('interpreter_startup', 'ruby loads libraries from these directories first'),
    'NODE_OPTIONS': ('interpreter_startup', 'node applies these options, including --require module loads'),
    'JAVA_TOOL_OPTIONS': ('interpreter_startup', 'every JVM applies these options, including -javaagent'),
    '_JAVA_OPTIONS': ('interpreter_startup', 'HotSpot JVMs apply these options'),
    'LESSOPEN': ('command_hook', 'less runs this input preprocessor command for every file it opens'),
    'LESSCLOSE': ('command_hook', 'less runs this postprocessor command after every file it opens'),
}

_STANDARD_PATH_DIRS = frozenset({
    '/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin',
    '/usr/games', '/usr/local/games', '/snap/bin',
})

_UNKNOWN = object()   # value or existence that cannot be determined


class _Unknown(Exception):
    pass


class _Abort(Exception):
    """pam_env returns PAM_ABORT/PAM_BUF_ERR while parsing the file."""


class _Gap(Exception):
    pass


def _atoi(text: str) -> int:
    i = 0
    while i < len(text) and text[i] in ' \t\n\v\f\r':
        i += 1
    sign = 1
    if i < len(text) and text[i] in '+-':
        sign = -1 if text[i] == '-' else 1
        i += 1
    start = i
    while i < len(text) and '0' <= text[i] <= '9':
        i += 1
    return sign * int(text[start:i]) if i > start else 0


def parse_arguments(args: Iterable[str]) -> dict[str, Any]:
    """Return pam_env's effective options for one module line's arguments."""
    conffile = envfile = None
    user_envfile = DEFAULT_USER_ENV_FILE
    readenv, user_readenv = 1, 0
    ignored: list[str] = []
    debug = False
    for arg in args:
        if arg == 'debug':
            debug = True
        elif arg.startswith('conffile='):
            if arg[9:]:
                conffile = arg[9:]
            else:
                ignored.append(arg)
        elif arg.startswith('envfile='):
            if arg[8:]:
                envfile = arg[8:]
            else:
                ignored.append(arg)
        elif arg.startswith('user_envfile='):
            if arg[13:]:
                user_envfile = arg[13:]
            else:
                ignored.append(arg)
        elif arg.startswith('readenv='):
            readenv = _atoi(arg[8:])
        elif arg.startswith('user_readenv='):
            user_readenv = _atoi(arg[13:])
        else:
            ignored.append(arg)
    return {
        'conffile': conffile or DEFAULT_CONF_FILE,
        'envfile': envfile or DEFAULT_ENV_FILE,
        'user_envfile': user_envfile,
        'readenv': readenv != 0,
        'user_readenv': user_readenv != 0,
        'debug': debug,
        'ignored_arguments': ignored,
    }


def _assemble_lines(text: str) -> list[tuple[int, str]]:
    """Model ``read_file``/``_assemble_line``; returns (first line number, logical line)."""
    if '\0' in text:
        raise _Gap('nul_byte')
    physical = text.split('\n')
    if physical and physical[-1] == '':
        physical.pop()
        terminated_last = True
    else:
        terminated_last = False
    lines: list[tuple[int, str]] = []
    buffer = ''
    start = None
    for index, raw in enumerate(physical):
        is_last = index == len(physical) - 1
        piece = raw + ('\n' if (not is_last or terminated_last) else '')
        if len(buffer) + len(piece) >= BUF_SIZE - 1:
            raise _Gap('oversized_line')
        stripped = piece.lstrip(' \n\t')
        if not stripped or stripped[0] == '#':
            # Blank or comment-only line: nothing is kept, a pending
            # continuation stays pending.
            continue
        lead = piece[:len(piece) - len(stripped)]
        if start is None:
            start = index + 1
        hash_at = stripped.find('#')
        if hash_at >= 0:
            lines.append((start, buffer + lead + stripped[:hash_at]))
            buffer, start = '', None
            continue
        body = stripped.rstrip(' \t\n')
        if body.endswith('\\'):
            buffer += lead + body[:-1]
            continue
        lines.append((start, buffer + lead + stripped))
        buffer, start = '', None
    # An unterminated continuation at end of file is an incomplete read: the
    # assembled text is discarded.
    return lines


def _parse_conf_line(line: str) -> tuple[str, Any, Any] | None:
    """Model ``_parse_line``. Returns (name, default, override) or None for BAD_LINE.

    ``default``/``override`` are None when absent, ``''`` for the quoted
    empty string marker, otherwise the raw (unexpanded) text.
    """
    length = 0
    while length < len(line) and line[length] not in ' \t\n':
        length += 1
    name = line[:length]
    pos = length
    values: dict[str, Any] = {'DEFAULT': None, 'OVERRIDE': None}
    quoteflg = 0
    while True:
        ws = 0
        while pos + ws < len(line) and line[pos + ws] in ' \t':
            ws += 1
        if ws == 0:
            break
        pos += ws
        rest = line[pos:]
        if rest.startswith('DEFAULT='):
            key, pos = 'DEFAULT', pos + 8
        elif rest.startswith('OVERRIDE='):
            key, pos = 'OVERRIDE', pos + 9
        else:
            return None
        if pos >= len(line) or line[pos] != '"':
            end = pos
            while end < len(line) and line[end] not in ' \t\n':
                end += 1
            value = line[pos:end]
            nxt = end
        else:
            close = line.find('"', pos + 1)
            if close < 0:
                return None
            value = line[pos + 1:close]
            nxt = close + 1
            if nxt < len(line) and line[nxt] not in ' \t\n':
                return None
            quoteflg += 1
        if value:
            values[key] = ('text', value)
        elif quoteflg:
            quoteflg -= 1
            values[key] = ('empty', '')
        pos = nxt
    return name, values['DEFAULT'], values['OVERRIDE']


class _Session:
    def __init__(self, initial_env: Mapping[str, str], initial_complete: bool,
                 items: Mapping[str, str | None], user: Mapping[str, Any] | None):
        self.env: dict[str, Any] = dict(initial_env)
        self.initial_complete = initial_complete
        self.items = items
        self.user = user

    def getenv(self, name: str) -> Any:
        if name in self.env:
            return self.env[name]
        return None if self.initial_complete else _UNKNOWN

    def exists(self, name: str) -> Any:
        if name in self.env:
            return True
        return False if self.initial_complete else _UNKNOWN

    def item(self, name: str) -> Any:
        if name not in _ITEM_NAMES:
            return None
        if name in ('HOME', 'SHELL'):
            pam_user = self.items.get('PAM_USER', _UNKNOWN) if 'PAM_USER' in self.items else _UNKNOWN
            if pam_user is _UNKNOWN:
                return _UNKNOWN
            if pam_user is None:
                return None
            if self.user is None or self.user.get('name') != pam_user:
                return _UNKNOWN
            if not self.user.get('exists', True):
                return None
            key = 'home' if name == 'HOME' else 'shell'
            return self.user.get(key, _UNKNOWN)
        if name not in self.items:
            return _UNKNOWN
        return self.items[name]

    def putenv(self, name_value: str) -> str:
        """Model ``pam_putenv``; returns 'success' or 'bad_item'."""
        eq = name_value.find('=')
        l2eq = len(name_value) if eq < 0 else eq
        if l2eq <= 0:
            return 'bad_item'
        name = name_value[:l2eq]
        if eq >= 0:
            self.env[name] = name_value[eq + 1:]
            return 'success'
        state = self.exists(name)
        if state is _UNKNOWN:
            # Absent afterwards either way; only pam_putenv's status is unknown.
            self.env.pop(name, None)
            self.env_forgotten.discard(name)
            raise _Unknown(name)
        if not state:
            return 'bad_item'
        del self.env[name]
        return 'success'

    env_forgotten: set[str]


def _expand(session: _Session, raw: str) -> Any:
    """Model ``_expand_arg``. Returns the expanded text or _UNKNOWN."""
    out: list[str] = []
    unknown = False
    i = 0
    size = 0
    while i < len(raw):
        ch = raw[i]
        if ch == '\\':
            i += 1
            if i < len(raw) and raw[i] in '$@':
                out.append(raw[i])
                size += 1
                i += 1
            continue
        if ch in '$@':
            if i + 1 >= len(raw) or raw[i + 1] != '{':
                out.append(ch)
                size += 1
                i += 1
                continue
            close = raw.find('}', i + 2)
            if close < 0:
                raise _Abort('unterminated_expansion')
            name = raw[i + 2:close]
            if len(name) >= BUF_SIZE - 1:
                raise _Gap('oversized_expansion')
            value = session.getenv(name) if ch == '$' else session.item(name)
            i = close + 1
            if value is _UNKNOWN:
                unknown = True
                continue
            if value:
                out.append(value)
                size += len(value)
            continue
        out.append(ch)
        size += 1
        i += 1
        if size >= MAX_ENV - 1:
            raise _Gap('oversized_value')
    if size >= MAX_ENV - 1:
        raise _Gap('oversized_value')
    return _UNKNOWN if unknown else ''.join(out)


def _run_conf(session: _Session, text: str, source: str, events: list[dict[str, Any]],
              notes: list[dict[str, Any]]) -> str:
    """Model ``_parse_config_file`` on readable text; returns success/abort/unknown."""
    last = 'success'
    for lineno, line in _assemble_lines(text):
        parsed = _parse_conf_line(line)
        if parsed is None:
            notes.append({'source': source, 'line': lineno, 'reason': 'malformed_line_ignored'})
            last = 'bad'
            continue
        name, default, override = parsed
        try:
            dval = None if default is None else (
                '' if default[0] == 'empty' else _expand(session, default[1]))
            oval = None if override is None else (
                '' if override[0] == 'empty' else _expand(session, override[1]))
        except _Abort:
            notes.append({'source': source, 'line': lineno, 'reason': 'unterminated_expansion_aborts'})
            return 'abort'
        if oval is _UNKNOWN:
            # Whether the override or the default applies is unknown.
            session.env.pop(name.split('=', 1)[0], None)
            session.env_forgotten.add(name.split('=', 1)[0])
            events.append({'source': source, 'line': lineno, 'name': name.split('=', 1)[0],
                           'action': 'unresolved', 'value': None})
            last = 'unknown'
            continue
        if oval:
            value = oval
        elif default is not None:
            value = dval
        else:
            value = None
        if default is None and not oval:
            try:
                status = session.putenv(name)
            except _Unknown:
                events.append({'source': source, 'line': lineno, 'name': name, 'action': 'removed',
                               'value': None})
                last = 'unknown'
                continue
            if status == 'success':
                if '=' in name:
                    key, val = name.split('=', 1)
                    events.append({'source': source, 'line': lineno, 'name': key, 'action': 'set',
                                   'value': val})
                else:
                    events.append({'source': source, 'line': lineno, 'name': name, 'action': 'removed',
                                   'value': None})
                last = 'success'
            else:
                last = 'bad'
            continue
        key = name.split('=', 1)[0]
        if not key:
            notes.append({'source': source, 'line': lineno, 'reason': 'empty_variable_name_ignored'})
            last = 'bad'
            continue
        if value is _UNKNOWN:
            session.env.pop(key, None)
            session.env_forgotten.add(key)
            events.append({'source': source, 'line': lineno, 'name': key, 'action': 'unresolved',
                           'value': None})
            last = 'success'
            continue
        full = name + '=' + value
        session.putenv(full)
        events.append({'source': source, 'line': lineno, 'name': key, 'action': 'set',
                       'value': full[len(key) + 1:]})
        last = 'success'
    if last == 'unknown':
        return 'unknown'
    return 'success' if last == 'success' else 'abort'


def _run_envfile(session: _Session, text: str, source: str, events: list[dict[str, Any]],
                 notes: list[dict[str, Any]]) -> str:
    """Model ``_parse_env_file`` on readable text."""
    result = 'success'
    for lineno, line in _assemble_lines(text):
        key = line.lstrip(' \n\t')
        if key.startswith('#'):
            continue
        key = key.removeprefix('export ')
        cut = len(key)
        for idx, ch in enumerate(key):
            if ch in '\n#':
                cut = idx
                break
        key = key[:cut]
        if key.startswith('='):
            notes.append({'source': source, 'line': lineno, 'reason': 'missing_key_ignored'})
            continue
        i = 0
        while i < len(key) and key[i] != '=':
            if not (key[i].isascii() and (key[i].isalnum() or key[i] == '_')):
                break
            i += 1
        if i < len(key) and key[i] != '=':
            notes.append({'source': source, 'line': lineno, 'reason': 'non_alphanumeric_key_ignored'})
            continue
        if i < len(key) and key[i] == '=' and i + 1 < len(key) and key[i + 1] in '"\'':
            chars = list(key)
            dst = i + 1
            for t in range(i + 2, len(chars)):
                if chars[t] not in '"\'' or t + 1 < len(chars):
                    chars[dst] = chars[t]
                    dst += 1
            key = ''.join(chars[:dst])
        if not key:
            continue
        if '=' not in key:
            state = session.exists(key)
            if state is False:
                continue
            session.env.pop(key, None)
            if state is _UNKNOWN:
                session.env_forgotten.discard(key)
            events.append({'source': source, 'line': lineno, 'name': key, 'action': 'removed',
                           'value': None})
            continue
        name, value = key.split('=', 1)
        session.putenv(key)
        session.env_forgotten.discard(name)
        events.append({'source': source, 'line': lineno, 'name': name, 'action': 'set', 'value': value})
    return result


def _risk(name: str, value: Any) -> dict[str, Any] | None:
    if name in _RISK:
        category, why = _RISK[name]
        return {'category': category, 'reason': why}
    if name.startswith('LD_'):
        return {'category': 'dynamic_loader', 'reason': 'dynamic-loader variables change how programs load'}
    if name == 'PATH':
        if value is None:
            return {'category': 'command_path', 'reason': 'the command search path could not be resolved'}
        entries = value.split(':')
        odd = [e for e in entries if not e.startswith('/')]
        extra = [e for e in entries if e.startswith('/') and e.rstrip('/') not in _STANDARD_PATH_DIRS]
        if odd:
            return {'category': 'command_path',
                    'reason': 'empty or relative PATH entries resolve commands from the current directory',
                    'entries': odd}
        if extra:
            return {'category': 'command_path',
                    'reason': 'non-standard PATH directories are searched for commands', 'entries': extra}
    return None


def evaluate(*, conf_text: str | None, env_text: str | None = None, args: Sequence[str] = (),
             user_env_text: str | None = None, items: Mapping[str, str | None] | None = None,
             user: Mapping[str, Any] | None = None, initial_env: Mapping[str, str] | None = None,
             initial_env_complete: bool = False, unobserved: Iterable[str] = ()) -> dict[str, Any]:
    """Evaluate one ``pam_env.so`` call.

    ``conf_text``/``env_text``/``user_env_text`` are the observed contents
    of the configuration, environment and user files named by ``args``; None
    means the file does not exist. Names in ``unobserved`` (``conf``,
    ``env``, ``user_env``) mark files whose content or existence is unknown.
    ``items`` maps PAM item names (``PAM_USER``, ``PAM_TTY``...) to their
    value, None when unset; missing keys are unknown. ``user`` describes the
    passwd entry of ``PAM_USER`` as ``{'name', 'home', 'shell', 'exists'}``.
    ``initial_env`` is the PAM environment before this call (for example
    from an earlier pam_env instance); unless ``initial_env_complete`` other
    variables may already exist.
    """
    options = parse_arguments(args)
    unobserved = set(unobserved)
    session = _Session(initial_env or {}, initial_env_complete, items or {}, user)
    session.env_forgotten = set()
    events: list[dict[str, Any]] = []
    notes: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    for arg in options['ignored_arguments']:
        notes.append({'source': 'arguments', 'reason': 'argument_ignored', 'argument': arg})

    def gap(reason: str, **extra: Any) -> None:
        gaps.append({'reason': reason, **extra})

    result = 'success'
    stage = 'conf'
    try:
        conf_path = options['conffile']
        if 'conf' in unobserved:
            files.append({'role': 'conf', 'path': conf_path, 'state': 'unobserved'})
            gap('conf_unobserved', path=conf_path)
            raise _Unknown('conf')
        if conf_text is None:
            files.append({'role': 'conf', 'path': conf_path, 'state': 'missing'})
            result = 'ignore'
        else:
            files.append({'role': 'conf', 'path': conf_path, 'state': 'read'})
            result = _run_conf(session, conf_text, conf_path, events, notes)
        stage = 'env'
        if result == 'success' and options['readenv']:
            env_path = options['envfile']
            if 'env' in unobserved:
                files.append({'role': 'env', 'path': env_path, 'state': 'unobserved'})
                gap('env_unobserved', path=env_path)
                raise _Unknown('env')
            if env_text is None:
                files.append({'role': 'env', 'path': env_path, 'state': 'missing'})
            else:
                files.append({'role': 'env', 'path': env_path, 'state': 'read'})
                _run_envfile(session, env_text, env_path, events, notes)
        elif options['readenv']:
            files.append({'role': 'env', 'path': options['envfile'], 'state': 'not_read'})
        stage = 'user_env'
        if result == 'success' and options['user_readenv']:
            pam_user = session.items.get('PAM_USER', _UNKNOWN) if 'PAM_USER' in session.items else _UNKNOWN
            rel = options['user_envfile']
            if pam_user is _UNKNOWN or user is None or user.get('name') != pam_user:
                gap('user_env_unresolved', file=rel)
                raise _Unknown('user')
            if pam_user is None or not user.get('exists', True):
                notes.append({'source': 'user_env', 'reason': 'no_such_user'})
            else:
                home = user.get('home')
                path = f'{home}/{rel}' if home is not None else None
                if path is None or 'user_env' in unobserved:
                    files.append({'role': 'user_env', 'path': path, 'state': 'unobserved'})
                    gap('user_env_unobserved', path=path)
                    raise _Unknown('user_env')
                if user_env_text is None:
                    files.append({'role': 'user_env', 'path': path, 'state': 'missing'})
                else:
                    files.append({'role': 'user_env', 'path': path, 'state': 'read'})
                    user_result = _run_conf(session, user_env_text, path, events, notes)
                    if user_result != 'success':
                        result = user_result
    except _Unknown:
        result = 'unknown'
    except _Gap as exc:
        gap(str(exc), stage=stage)
        result = 'unknown'

    unresolved = sorted(session.env_forgotten)
    for name in unresolved:
        gap('value_unresolved', name=name)
    if result == 'unknown' and not any(g['reason'] in ('conf_unobserved', 'env_unobserved',
                                                        'user_env_unobserved', 'user_env_unresolved',
                                                        'oversized_line', 'nul_byte', 'oversized_value',
                                                        'oversized_expansion') for g in gaps):
        gap('module_result_unresolved')

    variables = []
    for name, value in session.env.items():
        origin = next((e for e in reversed(events) if e['name'] == name and e['action'] == 'set'), None)
        entry: dict[str, Any] = {'name': name, 'value': value,
                                 'source': origin['source'] if origin else 'initial',
                                 'line': origin['line'] if origin else None}
        risk = _risk(name, value)
        if risk:
            entry['risk'] = risk
        variables.append(entry)
    for name in unresolved:
        entry = {'name': name, 'value': None, 'source': None, 'line': None, 'unresolved': True}
        risk = _risk(name, None)
        if risk:
            entry['risk'] = risk
        variables.append(entry)
    removed = sorted({e['name'] for e in events if e['action'] == 'removed'} - set(session.env)
                     - set(unresolved))
    return {
        'contract_version': CONTRACT_VERSION,
        'options': options,
        'files': files,
        'module_result': result,
        'variables': variables,
        'removed': removed,
        'events': events,
        'risky': [v for v in variables if 'risk' in v],
        'notes': notes,
        'gaps': gaps,
        'complete': not gaps,
    }
