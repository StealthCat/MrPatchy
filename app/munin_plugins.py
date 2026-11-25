"""Pure munin-node plugin contract (roadmap F slice, #1498).

``munin-node`` starts at boot as root. Whenever a Munin master connects it
runs the executables in ``/etc/munin/plugins`` (``fetch`` with no argument,
``config`` with one). By default each plugin drops to ``nobody``. A ``user``
line in any ``/etc/munin/plugin-conf.d`` section, including a wildcard
section such as ``[if_*]`` or ``[*]``, can keep it as root. A ``command`` line
replaces the program that is executed, and ``env.*`` lines set environment
variables such as ``PATH`` or ``LD_PRELOAD`` for it.

This module turns captured ``munin-node.conf`` text, the ``plugin-conf.d``
regular files, the plugins directory listing and the observed ``munin-node``
argv into those plugins, accounts, argv and environment names. It performs no
I/O, never runs a plugin, a shell or Perl, never looks up an account unless the
caller passes an observed ``passwd`` map and never authorizes a response
action.

Semantics follow munin 2.0.75 ``Munin::Node::Config``, ``Munin::Node::Service``,
``Munin::Node::OS``, ``Munin::Node::Server``, ``Munin::Common::Config`` and
``sbin/munin-node``, with Debian's build defaults (``nobody``/``munin``,
``/etc/munin``):

- **Lines.** Files split after each ``\\n``. ``#`` not preceded by a backslash
  starts a comment, and ``\\#`` then becomes ``#``. Lines are trimmed of ASCII
  whitespace. An empty line is skipped, and so is a plugin-conf.d line that
  reads ``0`` because Perl treats it as false.
- **munin-node.conf.** Every line must be ``name value``, or the daemon dies.
  ``default_plugin_user``/``default_client_user`` and the group equivalents
  set the default account (last wins). ``ignore_file`` adds a filename regex.
  ``paranoia`` is a boolean. ``allow``/``deny``/``cidr_*``/``reverse_lookups``
  belong to Net::Server, and any other name is kept as a plain string in the
  service table (first wins). A plugin-conf.d section, wildcard or runnable
  plugin with that name later fails as Perl fails on a string used as a hash.
- **plugin-conf.d.** Regular files load in sorted order. A name outside
  ``[-\\w.:]``, a hidden name and a name matched by an ``ignore_file`` regex
  are skipped. ``[name]`` opens a section, and a section named ``0`` is false
  in Perl. Keys are ``user``, ``group`` (split on whitespace and commas, with
  optional ``(group)`` entries), ``command`` (split on whitespace, ``%c``
  stands for the plugin path and its argument), ``host_name``, ``timeout``,
  ``update_rate`` and ``env.NAME``. Any other key, an ``env NAME=value`` line,
  a malformed line or a key before the first section drops the rest of that
  file and keeps what was already read. Later files replace earlier keys, and
  env merges per variable.
- **Wildcards.** A section whose name ends with ``*`` matches plugins by the
  regex ``^prefix``, and one that starts with ``*`` by ``suffix$``. The
  section text is a Perl regex, so only a conservative subset is modeled.
  Wildcards apply in descending string order. They never replace a key that a
  plugin's own section, or an earlier wildcard, already set.
- **Plugins.** A plugin runs when it is a regular executable file and its name
  is in ``[-\\w@.:]``, is not hidden, does not end in ``.conf`` and matches no
  ``ignore_file`` regex.
- **Account.** The ``user`` key, else the default plugin user, else
  ``nobody``. ``group`` replaces the default group (``munin``). A daemon that
  is not root runs every plugin as itself.
- **Command.** Without ``command`` the argv is the plugin path and its
  argument. Perl's ``exec`` uses ``execvp`` (with a ``PATH`` search when
  ``argv[0]`` has no ``/``) for more than one word. A single word is passed to
  ``/bin/sh -c`` when it contains a shell metacharacter or starts with
  ``NAME=``.
- **Environment.** munin-node sets ``PATH=/usr/sbin:/usr/bin:/sbin:/bin``
  and ``env.*`` values then override it. Values are reported only for
  variables that change what runs (``PATH``, loader, interpreter and
  ``MUNIN_LIBDIR``); other values, such as ``env.password``, are withheld.

Fail-closed rules: unobserved inputs, NUL bytes, text that is not UTF-8,
over-limit input, malformed listing entries, an argv that is not modeled or
that exits instead of serving, a ``--config`` path other than the captured
one, a fatal ``munin-node.conf`` line, an unresolvable daemon account, paranoia
without permission evidence, Perl regexes outside the modeled subset and
filenames containing a newline make the result incomplete. Account existence
is checked only against a passed ``passwd`` map; group existence is not
modeled, so the contract can over-report a plugin that fails before running
but does not under-report. ``origin`` is always ``not_assessed`` and no result
is a safety verdict.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('2.0.75',)
CONFDIR = '/etc/munin'
CONF_PATH = f'{CONFDIR}/munin-node.conf'
SERVICEDIR = f'{CONFDIR}/plugins'
SCONFDIR = f'{CONFDIR}/plugin-conf.d'
BUILD_DEFAULT_USER = 'nobody'
BUILD_DEFAULT_GROUP = 'munin'
DEFAULT_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
SHELL = '/bin/sh'
CONFIG_ARGUMENT = 'config'
MAX_TEXT = 262144
MAX_FILES = 512
MAX_PLUGINS = 4096
MAX_ARGV = 64
MAX_ARGV_WORD = 4096
MAX_LINE_NOTES = 256

# Values of these variables decide which code a plugin runs, so they are
# reported. Every other env.* value is withheld.
REPORTED_ENV = frozenset({
    'PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'GCONV_PATH',
    'PERL5LIB', 'PERLLIB', 'PERL5OPT', 'PYTHONPATH', 'PYTHONHOME',
    'PYTHONSTARTUP', 'RUBYLIB', 'RUBYOPT', 'NODE_OPTIONS', 'NODE_PATH',
    'BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS', 'IFS', 'PS4', 'MUNIN_LIBDIR',
})
CONFIG_VARIABLES = frozenset({
    'global_timeout', 'ignore_file', 'paranoia', 'spooldir', 'timeout', 'tls',
    'tls_ca_certificate', 'tls_certificate', 'tls_private_key',
    'tls_verify_certificate', 'tls_verify_depth', 'tls_match',
})
BOOLEAN_VARIABLES = frozenset({'paranoia', 'tls_verify_certificate'})
BOOLS = frozenset({'yes', 'no', 'true', 'false', 'on', 'off', '1', '0'})
NET_SERVER_VARIABLES = frozenset({'allow', 'deny', 'cidr_allow', 'cidr_deny', 'reverse_lookups'})
# Getopt::Long options of sbin/munin-node.
NEGATABLE = frozenset({'debug', 'pidebug', 'foreground', 'paranoia'})
EXITING = frozenset({'version', 'help'})
# Perl_do_exec3: characters that send a one-word exec through /bin/sh.
PERL_SHELL_METACHARS = frozenset('$&*(){}[]\'";\\|?<>~`\n')

BLOCKING = frozenset({
    'config_not_observed', 'config_invalid', 'config_nul', 'config_too_large',
    'plugin_conf_not_observed', 'plugin_conf_invalid', 'plugin_conf_too_large',
    'plugins_not_observed', 'plugins_invalid', 'plugins_too_large',
    'argv_not_observed', 'argv_invalid', 'argv_too_large', 'argv_unmodeled',
    'argv_exits', 'config_path_mismatch', 'daemon_user_unresolved',
    'paranoia_not_observed', 'regex_unmodeled', 'name_unmodeled', 'startup_fatal',
})

_WS = ' \t\n\r\f\v'
_SECTION = re.compile(r'\[([^\]]+)\]', re.S)
_CONF_LINE = re.compile(r'(\w+)[ \t\n\r\f\v]+(.+)', re.S | re.A)
_PLUGIN_LINE = re.compile(r'[ \t\n\r\f\v]*([\w.]+)[ \t\n\r\f\v]+(.+)', re.S | re.A)
_DEPRECATED_ENV = re.compile(r'[ \t\n\r\f\v]*env[ \t\n\r\f\v]+[^=\s]+[ \t\n\r\f\v]*=[ \t\n\r\f\v]*.+', re.S | re.A)
_CONF_NAME = re.compile(r'[-\w.:]+\n?', re.A)
_PLUGIN_NAME = re.compile(r'[-\w@.:]+\n?', re.A)
_OPTIONAL_GROUP = re.compile(r'\(([^)]+)\)', re.S)
_SPLIT_GROUPS = re.compile(r'[ \t\n\r\f\v,]+')
_SPLIT_WORDS = re.compile(r'[ \t\n\r\f\v]+')
_UNHANDLED = object()


class _Abort(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _perl_regex(fragment: str) -> re.Pattern | None:
    """Compile a Perl regex only when its meaning is identical in Python.

    The subset covers literals, ``.``, anchors, alternation, plain groups,
    ``? * +`` and ``{n,m}`` quantifiers, bracket classes without POSIX names and
    the escapes below. Anything else is unmodeled and returns ``None``.
    """
    if len(fragment) > 1024:
        return None
    i = 0
    in_class = False
    while i < len(fragment):
        ch = fragment[i]
        if ord(ch) > 0x7e or ord(ch) < 0x20:
            return None
        if ch == '\\':
            if i + 1 >= len(fragment):
                return None
            nxt = fragment[i + 1]
            if not (nxt in 'wdsWDS' or (not nxt.isalnum() and nxt != '_')):
                return None
            i += 2
            continue
        if in_class:
            if ch == '[' and fragment[i + 1:i + 2] in (':', '.', '='):
                return None
            if ch == ']':
                in_class = False
        elif ch == '[':
            in_class = True
            # A leading ] or ^] is a literal in both dialects.
            if fragment[i + 1:i + 2] == '^':
                i += 1
            if fragment[i + 1:i + 2] == ']':
                i += 1
        elif ch == '(' and fragment[i + 1:i + 2] == '?':
            return None
        elif ch == '$' and i + 1 < len(fragment) and fragment[i + 1] not in '|)':
            # Perl interpolates $name and $) in a pattern built from text.
            return None
        elif ch in '@#' or ch == ' ':
            # Literal in both dialects without /x; allowed.
            pass
        i += 1
    if in_class:
        return None
    try:
        return re.compile(fragment, re.A)
    except (re.error, OverflowError, RecursionError):
        return None


def _decode(value: Any, code: str, gaps: list, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        gaps.append({'code': f'{code}_not_observed'})
        return None
    if isinstance(value, bytes):
        if b'\0' in value:
            gaps.append({'code': f'{code}_nul' if code == 'config' else f'{code}_invalid'})
            return None
        try:
            value = value.decode('utf-8')
        except UnicodeDecodeError:
            gaps.append({'code': f'{code}_invalid'})
            return None
    if not isinstance(value, str):
        gaps.append({'code': f'{code}_invalid'})
        return None
    if '\0' in value:
        gaps.append({'code': f'{code}_nul' if code == 'config' else f'{code}_invalid'})
        return None
    if len(value.encode('utf-8')) > limit:
        gaps.append({'code': f'{code}_too_large'})
        return None
    return value


def _lines(text: str) -> list[str]:
    parts = text.split('\n')
    lines = [p + '\n' for p in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def _clean(line: str) -> str:
    # Munin::Common::Config: _strip_comment, then _trim (chomp + strip).
    line = re.sub(r'(?<!\\)#.*', '', line)
    line = line.replace('\\#', '#')
    if line.endswith('\n'):
        line = line[:-1]
    return line.strip(_WS)


def _parse_bool(value: str) -> bool:
    if value.lower() not in BOOLS:
        raise _Abort('not_a_boolean')
    return value.lower() not in ('no', 'false', 'off', '0')


def _parse_node_conf(text: str, gaps: list) -> dict | None:
    conf: dict[str, Any] = {'ignores': [], 'sconf': {}, 'paranoia': None,
                            'defuser': None, 'defgroup': None, 'user_lines': []}
    for number, raw in enumerate(_lines(text), 1):
        line = _clean(raw)
        if not line:
            continue
        m = _CONF_LINE.fullmatch(line)
        if not m:
            gaps.append({'code': 'config_invalid', 'line': number, 'reason': 'line_not_well_formed'})
            return None
        name, value = m.group(1), m.group(2)
        if name == 'user':
            conf['user_lines'].append(value)
        if name in NET_SERVER_VARIABLES:
            continue
        if name in CONFIG_VARIABLES:
            if name == 'ignore_file':
                conf['ignores'].append(value)
            elif name in BOOLEAN_VARIABLES:
                try:
                    parsed = _parse_bool(value)
                except _Abort:
                    gaps.append({'code': 'config_invalid', 'line': number, 'reason': 'not_a_boolean'})
                    return None
                if name == 'paranoia':
                    conf['paranoia'] = parsed
        elif name in ('host_name', 'hostname'):
            continue
        elif name in ('default_plugin_user', 'default_client_user'):
            conf['defuser'] = value
        elif name in ('default_plugin_group', 'default_client_group'):
            conf['defgroup'] = value
        else:
            conf['sconf'].setdefault(name, _UNHANDLED)
    return conf


def _parse_argv(argv: Any, conf_path: str, gaps: list) -> dict | None:
    if argv is None:
        gaps.append({'code': 'argv_not_observed'})
        return None
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
        gaps.append({'code': 'argv_invalid'})
        return None
    if len(argv) > MAX_ARGV:
        gaps.append({'code': 'argv_too_large'})
        return None
    words = list(argv)
    if any(not isinstance(w, str) or '\0' in w for w in words):
        gaps.append({'code': 'argv_invalid'})
        return None
    if any(len(w) > MAX_ARGV_WORD for w in words):
        gaps.append({'code': 'argv_too_large'})
        return None
    state = {'config': CONF_PATH, 'paranoia': False}
    i = 0
    while i < len(words):
        word = words[i]
        i += 1
        if word == '--':
            break
        if not word.startswith('-') or word == '-':
            continue  # Getopt::Long permutes non-options and munin-node ignores them.
        if not word.startswith('--'):
            gaps.append({'code': 'argv_unmodeled', 'word': i})
            return None
        name, eq, value = word[2:].partition('=')
        if name == 'config':
            if not eq:
                if i >= len(words):
                    gaps.append({'code': 'argv_exits', 'reason': 'missing_argument'})
                    return None
                value = words[i]
                i += 1
            state['config'] = value
        elif name in EXITING:
            gaps.append({'code': 'argv_exits', 'reason': name})
            return None
        elif name in NEGATABLE or (name.startswith('no') and name[2:] in NEGATABLE):
            if eq:
                gaps.append({'code': 'argv_exits', 'reason': 'unexpected_argument'})
                return None
            if name.endswith('paranoia'):
                state['paranoia'] = not name.startswith('no')
        else:
            gaps.append({'code': 'argv_unmodeled', 'word': i})
            return None
    # munin-node chdir()s to / before reading options.
    config = state['config'] if state['config'].startswith('/') else '/' + state['config']
    if config != conf_path:
        gaps.append({'code': 'config_path_mismatch'})
    return state


def _daemon_user(user_lines: list[str], gaps: list) -> str | None:
    # Net::Server reads user from the same file; only one plain value is modeled.
    values = {v for v in user_lines}
    if len(values) != 1:
        gaps.append({'code': 'daemon_user_unresolved',
                     'reason': 'not_configured' if not values else 'ambiguous'})
        return None
    value = next(iter(values))
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', value):
        gaps.append({'code': 'daemon_user_unresolved', 'reason': 'unmodeled_value'})
        return None
    return value


def _is_root(account: str, passwd: Mapping[str, int] | None) -> bool | None:
    if account.isascii() and account.isdigit():
        return int(account) == 0
    if account == 'root':
        return True
    if passwd is not None and account in passwd:
        return passwd[account] == 0
    return None


def _account_exists(account: str, passwd: Mapping[str, int] | None) -> bool | None:
    if passwd is None:
        return None
    if account.isascii() and account.isdigit():
        return int(account) in set(passwd.values())
    return account in passwd


def _note(notes: list, entry: dict) -> None:
    if len(notes) < MAX_LINE_NOTES:
        notes.append(entry)


def _parse_plugin_conf(name: str, text: str, sconf: dict, notes: list) -> dict:
    service = None
    for number, raw in enumerate(_lines(text), 1):
        line = _clean(raw)
        if not line or line == '0':
            continue
        m = _SECTION.fullmatch(line)
        if m:
            service = m.group(1)
            continue
        try:
            if not service or service == '0':
                raise _Abort('clutter_before_section')
            if _DEPRECATED_ENV.fullmatch(line):
                raise _Abort('deprecated_env_format')
            pm = _PLUGIN_LINE.fullmatch(line)
            if not pm:
                raise _Abort('line_not_well_formed')
            key, value = pm.group(1), pm.group(2)
            if key == 'user':
                parsed = ('user', value)
            elif key == 'group':
                parsed = ('group', _SPLIT_GROUPS.split(value))
                while parsed[1] and parsed[1][-1] == '':
                    parsed[1].pop()
            elif key == 'command':
                parsed = ('command', [w for w in _SPLIT_WORDS.split(value)])
                while parsed[1] and parsed[1][-1] == '':
                    parsed[1].pop()
            elif key in ('host_name', 'timeout', 'update_rate'):
                parsed = (key, value)
            elif key.startswith('env.'):
                parsed = ('env', (key[4:], value))
            else:
                raise _Abort('unknown_key')
            if sconf.get(service) is _UNHANDLED:
                # Perl dies using a munin-node.conf string as a hash reference.
                raise _Abort('section_is_node_setting')
        except _Abort as exc:
            _note(notes, {'file': name, 'line': number, 'status': exc.reason})
            return {'name': name, 'status': 'aborted', 'line': number, 'reason': exc.reason}
        entry = sconf.setdefault(service, {})
        field, val = parsed
        if field == 'env':
            entry.setdefault('env', {})[val[0]] = {'value': val[1], 'source': f'{name}:{number}'}
        else:
            entry[field] = val
            entry.setdefault('_src', {})[field] = f'{name}:{number}'
    return {'name': name, 'status': 'loaded'}


def _wildcard_pattern(section: str) -> re.Pattern | None:
    if section.endswith('*'):
        return _perl_regex('^' + section[:-1])
    return _perl_regex(section[1:] + '$')


def _apply_wildcards(sconf: dict, services: list[str], gaps: list) -> None:
    for wild in sorted((k for k in sconf if k.endswith('*') or k.startswith('*')), reverse=True):
        source = sconf[wild]
        pattern = _wildcard_pattern(wild)
        if pattern is None:
            gaps.append({'code': 'regex_unmodeled', 'section': wild})
            del sconf[wild]
            continue
        for service in services:
            if not pattern.search(service):
                continue
            target = sconf.get(service)
            if target is _UNHANDLED or source is _UNHANDLED:
                gaps.append({'code': 'startup_fatal', 'reason': 'wildcard_on_node_setting', 'section': wild})
                continue
            target = target or {}
            for key, val in source.get('env', {}).items():
                if key not in target.get('env', {}):
                    target.setdefault('env', {})[key] = {**val, 'wildcard': wild}
            for key, val in source.items():
                if key in ('env', '_src') or key in target:
                    continue
                target[key] = val
                target.setdefault('_src', {})[key] = f"[{wild}] {source.get('_src', {}).get(key, '')}".strip()
            sconf[service] = target
        del sconf[wild]


def _exec_plan(words: list[str]) -> dict:
    if len(words) == 1:
        word = words[0]
        lead = re.match(r'\w*', word, re.A).end()
        shell = (lead < len(word) and word[lead] == '=') or any(
            ch != ' ' and not ch.isalpha() and ch in PERL_SHELL_METACHARS for ch in word)
        if shell:
            return {'argv': [SHELL, '-c', word], 'via_shell': True, 'path_lookup': False}
    return {'argv': list(words), 'via_shell': False, 'path_lookup': bool(words) and '/' not in words[0]}


def _command(entry: dict, plugin: str, argument: str | None) -> list[str]:
    path = f'{SERVICEDIR}/{plugin}'
    args = [argument] if argument is not None else []
    words = entry.get('command')
    if not words:
        return [path, *args]
    out: list[str] = []
    for word in words:
        out.extend([path, *args] if word == '%c' else [word])
    return out


def _env(entry: dict) -> list[dict]:
    env = entry.get('env', {})
    out = []
    if 'PATH' not in env:
        out.append({'name': 'PATH', 'value': DEFAULT_PATH, 'source': 'munin-node'})
    for name in sorted(env):
        item = env[name]
        row = {'name': name, 'source': item['source']}
        if 'wildcard' in item:
            row['wildcard'] = item['wildcard']
        if name in REPORTED_ENV:
            row['value'] = item['value']
        else:
            row['value_withheld'] = True
        out.append(row)
    return out


def assess(node_conf: Any, plugin_conf: Mapping[str, Any] | None,
           plugins: Mapping[str, Mapping[str, Any]] | None, argv: Sequence[str] | None,
           conf_path: str = CONF_PATH, *, passwd: Mapping[str, int] | None = None,
           paranoia_safe: Mapping[str, bool] | None = None) -> dict:
    """Return which plugins munin-node runs, as whom, with which argv and env.

    ``plugin_conf`` maps each regular file name in ``plugin-conf.d`` to its text
    (``None`` when unread). ``plugins`` maps each ``plugins`` directory entry to
    ``{'regular': bool, 'executable': bool}`` after following symlinks.
    ``passwd`` optionally maps observed account names to uids.
    ``paranoia_safe`` maps ``plugins``, ``plugins/<name>`` and
    ``plugin-conf.d/<name>`` to munin's paranoia permission outcome and is only
    needed when paranoia is enabled.
    """
    gaps: list[dict] = []
    notes: list[dict] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
        'config_path': conf_path, 'origin': 'not_assessed', 'verdict': None,
        'daemon': None, 'default_user': None, 'default_group': None,
        'plugin_conf_files': [], 'plugins': [], 'line_notes': notes, 'gaps': gaps,
    }

    def finish() -> dict:
        result['complete'] = not any(g['code'] in BLOCKING for g in gaps)
        return result

    text = _decode(node_conf, 'config', gaps)
    state = _parse_argv(argv, conf_path, gaps)
    conf = _parse_node_conf(text, gaps) if text is not None else None
    if conf is None or state is None:
        return finish()
    paranoia = conf['paranoia'] if conf['paranoia'] is not None else state['paranoia']
    daemon_user = _daemon_user(conf['user_lines'], gaps)
    daemon_root = _is_root(daemon_user, passwd) if daemon_user is not None else None
    if daemon_user is not None and daemon_root is None:
        gaps.append({'code': 'daemon_user_unresolved', 'reason': 'account_not_observed'})
    result['daemon'] = {'user': daemon_user, 'root': daemon_root, 'paranoia': paranoia}
    default_user = conf['defuser'] if conf['defuser'] is not None else BUILD_DEFAULT_USER
    default_group = conf['defgroup'] if conf['defgroup'] is not None else BUILD_DEFAULT_GROUP
    result['default_user'] = {'name': default_user,
                              'source': 'munin-node.conf' if conf['defuser'] is not None else 'build_default'}
    result['default_group'] = {'name': default_group,
                               'source': 'munin-node.conf' if conf['defgroup'] is not None else 'build_default'}

    ignores = []
    for regex in conf['ignores']:
        compiled = _perl_regex(regex)
        if compiled is None:
            gaps.append({'code': 'regex_unmodeled', 'ignore_file': regex})
        else:
            ignores.append(compiled)
    ignore_unmodeled = len(ignores) != len(conf['ignores'])

    if paranoia and paranoia_safe is None:
        gaps.append({'code': 'paranoia_not_observed'})
        return finish()

    def safe(key: str) -> bool | None:
        if not paranoia:
            return True
        return paranoia_safe.get(key) if paranoia_safe is not None else None

    if safe('plugins') is None:
        gaps.append({'code': 'paranoia_not_observed', 'path': 'plugins'})
        return finish()
    if safe('plugins') is False:
        gaps.append({'code': 'startup_fatal', 'reason': 'plugins_directory_unsafe'})
        return finish()

    # Plugin listing (Munin::Node::Service::list / is_a_runnable_service).
    if plugins is None:
        gaps.append({'code': 'plugins_not_observed'})
        return finish()
    if not isinstance(plugins, Mapping):
        gaps.append({'code': 'plugins_invalid'})
        return finish()
    if len(plugins) > MAX_PLUGINS:
        gaps.append({'code': 'plugins_too_large'})
        return finish()
    if any(not isinstance(n, str) for n in plugins):
        gaps.append({'code': 'plugins_invalid'})
        return finish()
    listing: list[dict] = []
    runnable: list[str] = []
    for name in sorted(plugins):
        info = plugins[name]
        if (not isinstance(name, str) or '\0' in name or '/' in name or not isinstance(info, Mapping)
                or not isinstance(info.get('regular'), bool) or not isinstance(info.get('executable'), bool)):
            gaps.append({'code': 'plugins_invalid'})
            return finish()
        row: dict[str, Any] = {'name': name}
        listing.append(row)
        if not (info['regular'] and info['executable']):
            row['status'] = 'not_executable_file'
        elif name.startswith('.'):
            row['status'] = 'hidden'
        elif re.search(r'\.conf\n?\Z', name):
            row['status'] = 'config_file'
        elif not _PLUGIN_NAME.fullmatch(name):
            row['status'] = 'invalid_name'
        elif '\n' in name:
            row['status'] = 'unresolved'
            gaps.append({'code': 'name_unmodeled', 'plugin': name})
        elif any(r.search(name) for r in ignores):
            row['status'] = 'ignored'
        elif ignore_unmodeled:
            row['status'] = 'unresolved'
        else:
            row['status'] = 'candidate'
            runnable.append(name)

    # plugin-conf.d (process_plugin_configuration_files).
    if plugin_conf is None:
        gaps.append({'code': 'plugin_conf_not_observed'})
        return finish()
    if not isinstance(plugin_conf, Mapping) or len(plugin_conf) > MAX_FILES:
        gaps.append({'code': 'plugin_conf_too_large' if isinstance(plugin_conf, Mapping) else 'plugin_conf_invalid'})
        return finish()
    sconf = conf['sconf']
    conf_ignores = ignores + [re.compile(r'^\.')]
    if any(not isinstance(n, str) for n in plugin_conf):
        gaps.append({'code': 'plugin_conf_invalid'})
        return finish()
    for name in sorted(plugin_conf):
        if not isinstance(name, str) or '\0' in name or '/' in name:
            gaps.append({'code': 'plugin_conf_invalid'})
            return finish()
        if not _CONF_NAME.fullmatch(name):
            result['plugin_conf_files'].append({'name': name, 'status': 'invalid_name'})
            continue
        if '\n' in name:
            gaps.append({'code': 'name_unmodeled', 'plugin_conf': name})
            result['plugin_conf_files'].append({'name': name, 'status': 'unresolved'})
            continue
        if any(r.search(name) for r in conf_ignores):
            result['plugin_conf_files'].append({'name': name, 'status': 'ignored'})
            continue
        if ignore_unmodeled:
            result['plugin_conf_files'].append({'name': name, 'status': 'unresolved'})
            continue
        ok = safe(f'plugin-conf.d/{name}')
        if ok is None:
            gaps.append({'code': 'paranoia_not_observed', 'path': f'plugin-conf.d/{name}'})
            result['plugin_conf_files'].append({'name': name, 'status': 'unresolved'})
            continue
        if ok is False:
            result['plugin_conf_files'].append({'name': name, 'status': 'unsafe_permissions'})
            continue
        file_gaps: list[dict] = []
        body = _decode(plugin_conf[name], 'plugin_conf', file_gaps)
        if body is None:
            for gap in file_gaps:
                gaps.append({**gap, 'file': name})
            result['plugin_conf_files'].append({'name': name, 'status': 'unresolved'})
            continue
        result['plugin_conf_files'].append(_parse_plugin_conf(name, body, sconf, notes))

    _apply_wildcards(sconf, runnable, gaps)

    for row in listing:
        if row['status'] != 'candidate':
            continue
        name = row['name']
        entry = sconf.get(name)
        if entry is _UNHANDLED:
            row['status'] = 'fails_before_exec'
            row['reason'] = 'service_is_node_setting'
            continue
        entry = entry or {}
        src = entry.get('_src', {})
        if 'user' in entry:
            user, user_source = entry['user'], src.get('user')
        elif conf['defuser'] is not None:
            user, user_source = default_user, 'default_plugin_user'
        else:
            user, user_source = default_user, 'build_default'
        exists = _account_exists(user, passwd)
        if exists is False:
            row['status'] = 'fails_before_exec'
            row['reason'] = 'user_missing'
            row['configured_user'] = user
            continue
        groups = []
        for group in entry.get('group', []):
            m = _OPTIONAL_GROUP.fullmatch(group)
            groups.append({'name': m.group(1), 'optional': True} if m else {'name': group, 'optional': False})
        ok = safe(f'plugins/{name}')
        if ok is None:
            gaps.append({'code': 'paranoia_not_observed', 'path': f'plugins/{name}'})
            row['status'] = 'unresolved'
            continue
        if ok is False:
            row['status'] = 'refused_by_paranoia'
            continue
        if daemon_root is False:
            run_user, run_root, groups_out = daemon_user, False, None
            row['account_source'] = 'daemon'
            row['configured_user'] = user
        else:
            run_user, run_root = user, _is_root(user, passwd)
            groups_out = groups or [{'name': default_group, 'optional': False}]
            row['account_source'] = user_source
        row.update({
            'status': 'runs', 'user': run_user, 'root': run_root, 'groups': groups_out,
            'groups_source': src.get('group') if groups else 'default_group',
            'command_source': src.get('command'),
            'fetch': _exec_plan(_command(entry, name, None)),
            'config': _exec_plan(_command(entry, name, CONFIG_ARGUMENT)),
            'environment': _env(entry),
        })
        if run_root is None:
            gaps.append({'code': 'account_not_observed', 'plugin': name})
    result['plugins'] = listing
    return finish()
