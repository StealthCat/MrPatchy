"""Pure sudo.conf plugin and path contract (roadmap F slice, #1425).

``sudo`` is setuid root. Every ``sudo`` and ``sudoedit`` invocation reads
``/etc/sudo.conf`` and then ``dlopen``\\s the plugins it names into the root
process, which runs each object's constructors as root before sudo checks any
policy. ``Path`` lines choose the ``noexec`` and ``intercept`` libraries that
sudo preloads into commands, the ``sesh`` helper and the plugin directory.
This module turns captured file text, plus the file's captured type, owner and
mode, into the plugins sudo would load and the paths it would use. It performs
no I/O, never runs sudo and never authorizes a response action.

The rules follow ``lib/util/sudo_conf.c``, ``lib/util/parseln.c``,
``lib/util/strsplit.c`` and ``src/load_plugins.c`` in sudo 1.9.15p5 (Ubuntu
24.04 ``sudo_1.9.15p5-3ubuntu5``):

- sudo opens ``/etc/sudo.conf`` and ignores the whole file, keeping its
  built-in defaults, unless it is a regular file owned by uid 0 that is neither
  group- nor world-writable. A missing file also leaves the defaults.
- Lines are read with ``sudo_parseln``: trailing CR/LF is removed, everything
  from the first ``#`` is a comment, a trailing single backslash on a line
  without a comment joins the next line, and leading blanks (and trailing
  blanks on a line that does not continue) are removed.
- A line whose first word is ``Debug``, ``Path``, ``Plugin`` or ``Set``
  (ASCII case-insensitive) followed by a blank is a directive. Anything else is
  ignored. Fields are separated by spaces and tabs.
- ``Plugin symbol path [option ...]`` needs two fields. Plugins load in file
  order. A path that does not start with ``/`` is appended to ``plugin_dir``
  with no separator added. sudo stops with a fatal error if ``plugin_dir`` is
  unset for such a path, or if a second, different policy plugin is listed.
  A duplicate I/O, audit or approval symbol is ignored unless the object
  exports ``<symbol>_clone``.
- With no policy plugin configured, sudo loads ``sudoers_policy``, then the
  optional ``sudoers_audit``, then ``sudoers_io`` if no I/O plugin was
  configured, all from ``sudoers.so`` in the effective ``plugin_dir``. With
  ``sudoers_policy`` configured and no ``sudoers_audit``, it also loads
  ``sudoers_audit`` and moves the policy plugin's options to it.
- ``Path name [value]`` sets one of ``askpass``, ``sesh``, ``intercept``,
  ``noexec``, ``plugin_dir`` and ``devsearch`` (ASCII case-insensitive); a
  missing value unsets it, later lines win and unknown names are ignored. The
  value is everything from its first character to the end of the line, so
  ``Path noexec /a /b`` sets ``/a /b``, blanks included.
- ``Debug program file flags`` needs three fields; sudo writes debug output to
  ``file`` as root.

A plugin's type is declared by the loaded object, not by its name. The type is
reported as resolved only for the symbols sudo's own packaged objects export at
their packaged path. For any other object the type is a blocking gap, because a
policy-type object changes which default plugins load.

Fail-closed rules: an unobserved file, file type, owner or mode, invalid UTF-8,
NUL bytes and over-limit input mark the result incomplete. Whether each object
exists, exports the symbol and loads cannot be seen from the text; a load
failure makes sudo exit after the earlier objects have already run their
constructors. ``origin`` is always ``not_assessed`` and no result is a safety
verdict.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('1.9.15p5',)
CONF_PATH = '/etc/sudo.conf'
SUDOERS_PLUGIN = 'sudoers.so'
PATH_MAX = 4096
MAX_TEXT = 262144
MAX_PLUGINS = 128
MAX_GAPS = 64
BLANKS = ' \t'
DIRECTIVES = ('debug', 'path', 'plugin', 'set')
PATH_NAMES = ('askpass', 'sesh', 'intercept', 'noexec', 'plugin_dir', 'devsearch')

# Compiled defaults of the Ubuntu 24.04 sudo 1.9.15p5 build (``strings libsudo_util.so.0``).
DEFAULT_PATHS: Mapping[str, str | None] = {
    'askpass': None,
    'sesh': '/usr/libexec/sudo/sesh',
    'intercept': '/usr/libexec/sudo/sudo_intercept.so',
    'noexec': '/usr/libexec/sudo/sudo_noexec.so',
    'plugin_dir': '/usr/libexec/sudo/',
    'devsearch': '/dev/pts:/dev/vt:/dev/term:/dev/zcons:/dev/pty:/dev/',
}

PATH_USE = {
    'askpass': 'Program sudo runs, as the invoking user, to read a password when -A is used or no tty exists.',
    'sesh': 'Helper sudo runs as root for sudoedit and SELinux role changes.',
    'intercept': 'Library sudo preloads into commands run with intercept or log_subcmds.',
    'noexec': 'Library sudo preloads into commands run with noexec.',
    'plugin_dir': 'Directory prepended to relative Plugin paths and to the default sudoers.so.',
    'devsearch': 'Directories sudo searches to name the terminal device.',
}

# Symbols exported by sudo's own plugin objects, by object file name, and their plugin type.
PACKAGED_SYMBOLS: Mapping[str, Mapping[str, str]] = {
    'sudoers.so': {'sudoers_policy': 'policy', 'sudoers_io': 'io', 'sudoers_audit': 'audit'},
    'audit_json.so': {'audit_json': 'audit'},
    'python_plugin.so': {'python_policy': 'policy', 'python_io': 'io', 'python_audit': 'audit',
                         'python_approval': 'approval'},
    'sample_approval.so': {'sample_approval': 'approval'},
}
# Symbols whose object exports ``<symbol>_clone``, so a repeated entry loads another instance.
CLONEABLE = frozenset({('python_plugin.so', 'python_io'), ('python_plugin.so', 'python_audit'),
                       ('python_plugin.so', 'python_approval')})

BLOCKING = frozenset({
    'file_not_observed', 'file_security_not_observed', 'over_limit', 'invalid_utf8', 'binary',
    'plugin_type_unresolved', 'plugins_truncated', 'gaps_truncated',
})

NOT_OBSERVED = (
    'Whether sudo is installed, and whether it is the 1.9.15p5 build with these compiled defaults.',
    ('Whether each plugin object exists, exports its symbol and declares a compatible API. A failure makes '
     'sudo exit, but every object loaded before it has already run its constructors as root.'),
    'What each plugin object, library or helper does, and who can write to it.',
    'sudoers rules, Defaults (including group_plugin) and the SUDO_ASKPASS environment variable.',
    'Set lines (coredump, group source, interface probing), which are parsed but not reported.',
)

_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')


def _ascii_lower(value: str) -> str:
    """``strncasecmp`` in the C locale folds only ASCII letters."""
    return value.translate(_LOWER)


def _gap(gaps: list, code: str, where: str, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if not gaps or gaps[-1]['code'] != 'gaps_truncated':
            gaps.append({'code': 'gaps_truncated', 'where': 'result', 'detail': 'Further gaps were omitted.',
                         'blocking': True})
        return
    gaps.append({'code': code, 'where': where, 'detail': detail, 'blocking': code in BLOCKING})


def logical_lines(text: str) -> list[tuple[int, str]]:
    """``sudo_parseln`` with flags 0: comments, continuation and blank trimming, with line numbers."""
    physical = text.split('\n')
    if physical and physical[-1] == '':
        physical.pop()
    out: list[tuple[int, str]] = []
    buf, lineno = '', 0
    pending = False
    for raw in physical:
        lineno += 1
        line = raw.rstrip('\r\n')
        comment = False
        hash_at = line.find('#')
        if hash_at != -1:
            line = line[:hash_at]
            comment = True
        continued = False
        if not comment and line.endswith('\\') and (len(line) == 1 or line[-2] != '\\'):
            line = line[:-1]
            continued = True
        if not continued:
            line = line.rstrip(BLANKS)
        line = line.lstrip(BLANKS)
        buf += line
        pending = True
        if not continued:
            out.append((lineno, buf))
            buf, pending = '', False
    if pending and buf:
        out.append((lineno, buf))
    return out


def _split(entry: str) -> list[str]:
    """``sudo_strsplit`` over spaces and tabs, as a list of fields."""
    fields, cur = [], ''
    for ch in entry:
        if ch in BLANKS:
            if cur:
                fields.append(cur)
                cur = ''
        else:
            cur += ch
    if cur:
        fields.append(cur)
    return fields


def _after_first_field(entry: str, count: int) -> str:
    """The text starting at field ``count`` (zero-based), as ``Debug`` keeps its free-form flags."""
    i, n = 0, len(entry)
    for _ in range(count):
        while i < n and entry[i] in BLANKS:
            i += 1
        while i < n and entry[i] not in BLANKS:
            i += 1
    while i < n and entry[i] in BLANKS:
        i += 1
    return entry[i:]


def parse(text: str) -> dict[str, Any]:
    """Directives exactly as ``sudo_conf_read`` stores them (before any plugin is loaded)."""
    paths: dict[str, dict[str, Any]] = {
        name: {'value': DEFAULT_PATHS[name], 'source': 'default', 'line': None} for name in PATH_NAMES}
    plugins: list[dict[str, Any]] = []
    debug: list[dict[str, Any]] = []
    for lineno, line in logical_lines(text):
        if not line:
            continue
        keyword = None
        for name in DIRECTIVES:
            if _ascii_lower(line[:len(name)]) == name and len(line) > len(name) and line[len(name)] in BLANKS:
                keyword = name
                break
        if keyword is None:
            continue
        entry = line[len(keyword):].lstrip(BLANKS)
        fields = _split(entry)
        if keyword == 'plugin':
            if len(fields) < 2:
                continue
            plugins.append({'line': lineno, 'symbol': fields[0], 'path': fields[1], 'options': fields[2:]})
        elif keyword == 'path':
            if not fields:
                continue
            name = _ascii_lower(fields[0])
            if name in paths:
                # parse_path strdup()s from the second field to the end of the line, blanks included.
                paths[name] = {'value': _after_first_field(entry, 1) if len(fields) > 1 else None,
                               'source': CONF_PATH, 'line': lineno}
        elif keyword == 'debug':
            if len(fields) < 3:
                continue
            debug.append({'line': lineno, 'program': fields[0], 'file': fields[1],
                          'flags': _after_first_field(entry, 2)})
    return {'paths': paths, 'plugins': plugins, 'debug': debug}


def _qualify(path: str, plugin_dir: str | None) -> tuple[str | None, str | None]:
    """``sudo_qualify_plugin``: (resolved path, fatal reason)."""
    if path.startswith('/'):
        full = path
    elif plugin_dir is None:
        return None, 'plugin_dir_unset'
    else:
        full = plugin_dir + path
    if len(full.encode('utf-8', 'surrogateescape')) >= PATH_MAX:
        return None, 'path_too_long'
    return full, None


def _plugin_type(resolved: str, symbol: str) -> tuple[str | None, bool]:
    """(type, resolved_from_packaged_object). Only a packaged object at its packaged path counts."""
    pdir = DEFAULT_PATHS['plugin_dir'] or ''
    if resolved.startswith(pdir) and '/' not in resolved[len(pdir):]:
        table = PACKAGED_SYMBOLS.get(resolved[len(pdir):], {})
        if symbol in table:
            return table[symbol], True
    return None, False


def _packaged_name(resolved: str) -> str | None:
    pdir = DEFAULT_PATHS['plugin_dir'] or ''
    if resolved.startswith(pdir) and '/' not in resolved[len(pdir):]:
        return resolved[len(pdir):]
    return None


def load_order(parsed: Mapping[str, Any], gaps: list) -> tuple[list[dict[str, Any]], str | None]:
    """``sudo_load_plugins``: each plugin's outcome in load order, and a fatal reason if sudo exits."""
    plugin_dir = parsed['paths']['plugin_dir']['value']
    out: list[dict[str, Any]] = []
    policy: dict[str, Any] | None = None
    loaded: dict[str, list[str]] = {'io': [], 'audit': [], 'approval': []}
    uncertain = False

    def entry(info, source, resolved, ptype, known, outcome, fatal=None):
        row = {
            'source': source, 'line': info.get('line'), 'symbol': info['symbol'],
            'configured_path': info['path'], 'resolved_path': resolved, 'options': list(info.get('options', [])),
            'type': ptype, 'type_basis': 'packaged_object' if known else 'unresolved',
            'outcome': outcome, 'runs_as': 'root', 'code_runs': resolved is not None,
        }
        if resolved is not None:
            row['resolved_path_sha256'] = hashlib.sha256(resolved.encode('utf-8', 'surrogateescape')).hexdigest()
        if fatal:
            row['fatal'] = fatal
        out.append(row)
        return row

    configured = list(parsed['plugins'])
    if len(configured) > MAX_PLUGINS:
        _gap(gaps, 'plugins_truncated', CONF_PATH, f'Only the first {MAX_PLUGINS} Plugin lines are evaluated.')
        configured = configured[:MAX_PLUGINS]
    for info in configured:
        resolved, fatal = _qualify(info['path'], plugin_dir)
        if fatal:
            entry(info, CONF_PATH, None, None, False, 'fatal', fatal)
            return out, fatal
        ptype, known = _plugin_type(resolved, info['symbol'])
        if ptype is None:
            uncertain = True
            _gap(gaps, 'plugin_type_unresolved', f"{CONF_PATH}:{info['line']}",
                 'The object declares its own plugin type; a policy-type object changes the default plugins.')
            entry(info, CONF_PATH, resolved, None, False, 'loaded_type_unresolved')
            continue
        if ptype == 'policy':
            if policy is not None:
                if policy['symbol'] == info['symbol']:
                    entry(info, CONF_PATH, resolved, ptype, known, 'ignored_duplicate')
                    continue
                entry(info, CONF_PATH, resolved, ptype, known, 'fatal', 'second_policy_plugin')
                return out, 'second_policy_plugin'
            policy = entry(info, CONF_PATH, resolved, ptype, known, 'loaded')
            continue
        if info['symbol'] in loaded[ptype]:
            name = _packaged_name(resolved)
            if (name, info['symbol']) in CLONEABLE:
                entry(info, CONF_PATH, resolved, ptype, known, 'loaded_clone')
            else:
                entry(info, CONF_PATH, resolved, ptype, known, 'ignored_duplicate')
            continue
        loaded[ptype].append(info['symbol'])
        entry(info, CONF_PATH, resolved, ptype, known, 'loaded')

    def default(symbol, optional):
        info = {'symbol': symbol, 'path': SUDOERS_PLUGIN, 'line': None, 'options': []}
        resolved, fatal = _qualify(SUDOERS_PLUGIN, plugin_dir)
        if fatal:
            if optional:
                entry(info, 'default', None, None, False, 'not_loaded', fatal)
                return None, None
            entry(info, 'default', None, None, False, 'fatal', fatal)
            return None, fatal
        ptype, known = _plugin_type(resolved, symbol)
        if not known:
            _gap(gaps, 'plugin_type_unresolved', 'default ' + symbol,
                 'plugin_dir is not the packaged directory, so sudoers.so is not the packaged object.')
            ptype = {'sudoers_policy': 'policy', 'sudoers_io': 'io', 'sudoers_audit': 'audit'}[symbol]
        outcome = 'loaded_if_no_policy_above' if uncertain else ('loaded_if_present' if optional else 'loaded')
        return entry(info, 'default', resolved, ptype, known, outcome), None

    if policy is None:
        _, fatal = default('sudoers_policy', False)
        if fatal:
            return out, fatal
        default('sudoers_audit', True)
        if not loaded['io']:
            _, fatal = default('sudoers_io', False)
            if fatal:
                return out, fatal
    elif policy['symbol'] == 'sudoers_policy' and 'sudoers_audit' not in loaded['audit']:
        row, _ = default('sudoers_audit', True)
        if row is not None and policy['options']:
            row['options'], row['options_moved_from_line'] = policy['options'], policy['line']
            policy['options'] = []
    return out, None


def _security(stat: Mapping[str, Any]) -> str | None:
    """``sudo_secure_fd(fd, S_IFREG, ROOT_UID, -1)``: why sudo ignores the file, or None."""
    if stat.get('type') != 'file':
        return 'not_regular_file'
    if stat.get('uid') != 0:
        return 'not_owned_by_root'
    mode = int(stat.get('mode', 0))
    if mode & 0o002:
        return 'world_writable'
    if mode & 0o020:
        return 'group_writable'
    return None


def evaluate(*, exists: bool | None, text: str | bytes | None = None,
             stat: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Which plugins and paths ``sudo`` uses, from the captured ``/etc/sudo.conf``.

    ``exists`` is None when the file was not checked, ``stat`` holds the opened
    file's ``type`` ('file', 'directory', ...), ``uid`` and ``mode``.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS), 'path': CONF_PATH,
        'origin': 'not_assessed', 'not_observed': list(NOT_OBSERVED), 'text_sha256': None,
        'ignored_reason': None, 'fatal': None,
    }

    def finish(status, parsed=None):
        parsed = parsed or parse('')
        plugins, fatal = ([], None) if status in ('not_observed', 'unresolved') else load_order(parsed, gaps)
        if fatal:
            status = 'fails'
        paths = {name: {**row, 'use': PATH_USE[name],
                        'absolute': None if row['value'] is None else row['value'].startswith('/')}
                 for name, row in parsed['paths'].items()}
        for name, row in paths.items():
            if row['source'] != 'default' and row['absolute'] is False:
                _gap(gaps, 'relative_path_value', f"{CONF_PATH}:{row['line']}",
                     f'Path {name} is not absolute; sudo does not reject it.')
        result.update({
            'status': status, 'fatal': fatal, 'plugins': plugins, 'paths': paths, 'debug': parsed['debug'],
            'gaps': gaps, 'complete': not any(g['blocking'] for g in gaps),
        })
        return result

    if exists is None:
        _gap(gaps, 'file_not_observed', CONF_PATH)
        return finish('not_observed')
    if not exists:
        return finish('absent')
    if text is None:
        _gap(gaps, 'file_not_observed', CONF_PATH)
        return finish('not_observed')
    if stat is None:
        _gap(gaps, 'file_security_not_observed', CONF_PATH,
             'sudo ignores the file unless it is a root-owned regular file that is not group- or world-writable.')
        return finish('not_observed')
    raw = text.encode('utf-8', 'surrogateescape') if isinstance(text, str) else bytes(text)
    result['text_sha256'] = hashlib.sha256(raw).hexdigest()
    reason = _security(stat)
    if reason:
        result['ignored_reason'] = reason
        return finish('ignored_insecure')
    if len(raw) > MAX_TEXT:
        _gap(gaps, 'over_limit', CONF_PATH, f'Text exceeds {MAX_TEXT} bytes.')
        return finish('unresolved')
    if b'\0' in raw:
        _gap(gaps, 'binary', CONF_PATH, 'sudo stops reading a line at a NUL byte; not modeled.')
        return finish('unresolved')
    try:
        decoded = raw.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', CONF_PATH)
        decoded = raw.decode('utf-8', 'surrogateescape')
    return finish('loads', parse(decoded))
