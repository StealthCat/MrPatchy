"""Pure system gitconfig execution contract (roadmap F slice, #1535).

Every ``git`` invocation, by any user and by root, reads the system
configuration (normally ``/etc/gitconfig``) and the files it includes before
the user's own configuration. Several keys make git start programs, so one
line there is a persistence trigger that fires the next time an administrator
or an automation job runs git, with no cron entry or unit file. This module
turns the captured text of the system file and its includes into the programs
git may start, the key and trigger that start each one, whether git runs it
through ``sh -c`` and the include chain it came from. It performs no I/O,
never runs git or a command, and never authorizes a response action.

The rules follow the git 2.43 sources: ``config.c`` (``get_next_char``,
``parse_value``, ``get_value``, ``get_base_var``, ``get_extended_base_var``,
``git_parse_source``, ``handle_path_include``, ``include_by_gitdir``),
``parse.c`` (``git_parse_maybe_bool``), ``pager.c``, ``editor.c``,
``connect.c``, ``credential.c``, ``diff.c``, ``convert.c``, ``ll-merge.c``,
``fsmonitor.c``, ``gpg-interface.c`` and ``upload-pack.c``.

- Syntax: CRLF reads as LF and a leading UTF-8 BOM is skipped. ``#`` and
  ``;`` start comments outside values. ``[section]`` names use alphanumerics,
  ``-`` and ``.`` and are lowercased, so the legacy ``[section.Sub]`` form
  lowercases its subsection. ``[section "Sub"]`` keeps the subsection's case
  and drops the backslash of any escape; a newline inside it, or any
  character other than ``]`` after its closing quote, is an error. A key
  starts with a letter, continues with alphanumerics or ``-`` and is
  lowercased. A key with no ``=`` is a boolean true (``value`` None); any
  other trailing text, a comment included, is an error. Several statements
  may share a line, so ``[core] pager = x`` is valid, and a key before any
  section header is named by the key alone.
- Values: leading and trailing whitespace is dropped; each inner unquoted
  whitespace character becomes one space; ``"`` toggles quoting; ``#`` and
  ``;`` start a comment outside quotes (so ``!f() { a; }; f`` is cut at the
  first ``;``); ``\\n``, ``\\t``, ``\\b``, ``\\\\`` and ``\\"`` are escapes,
  backslash-newline joins lines, and any other escape or an unterminated
  quote is an error. git refuses to run with any syntax error, so each error
  makes the result incomplete.
- Includes: the ``include.path`` entry is reported first, then the included
  file's entries at that point. ``~/`` and ``~user/`` paths are resolved per
  invoking user and are reported as gaps. A relative path is relative to the
  including file's directory. A file that git cannot read is silently
  skipped, as git does. More than 10 nested includes is fatal in git.
  ``includeIf.<condition>.path`` depends on the repository (``gitdir:``,
  ``gitdir/i:``, ``onbranch:``, ``hasconfig:remote.*.url:``), so its file is
  followed and its entries are tagged with the condition rather than guessed.
  An unknown condition never matches and is not followed.
- Effective values: single-valued keys use the last value. A later value
  from a conditional include is also reported as a possible override. The
  user, XDG and repository configuration and environment variables such as
  ``GIT_PAGER`` can override every system value, so each entry is a default
  for every user, not a guarantee.
- ``credential.helper`` and ``credential.<url>.helper`` form one ordered
  list; an empty value resets it. ``!cmd`` runs ``cmd``, an absolute path
  runs that path, and any other name runs ``git credential-<name>``; git
  appends ``get``, ``store`` or ``erase`` and runs the result with ``sh -c``.
- ``core.pager`` and ``pager.<cmd>``: empty and ``cat`` start no pager and a
  ``pager.<cmd>`` boolean only switches the pager on or off.
  ``core.fsmonitor`` true selects git's built-in daemon and false disables
  it; any other value is a hook program. ``!`` aliases run ``sh -c``; other
  aliases expand to git subcommands, but one that passes ``-c``,
  ``--config-env`` or ``--exec-path`` can change configuration or the
  program search path and is reported as a gap.
- ``protocol.allow`` / ``protocol.ext.allow`` set to ``always`` enable the
  ``ext::`` transport, which runs an arbitrary command from a URL; it is
  reported as a transport risk.

Fail-closed rules: input that was not observed or is over the limits, a
syntax error, an include that was not captured, a per-user include path and
include nesting beyond git's limit make the result incomplete. Values are
reported as written; nothing is hashed, because configuration text can hold
credentials. ``origin`` is always ``not_assessed`` and no result is a safety
verdict.

Not modeled: whether an ``includeIf`` condition matches, which repositories
activate diff/filter/merge drivers through gitattributes, alias names that a
built-in command shadows, ``sendemail``/``remote.*.uploadpack`` programs,
newer-git ``hook.<name>.command`` keys (reported as warnings), the per-user,
XDG and repository files, and collection, inventory, UI or AI wiring.
"""
from __future__ import annotations

import posixpath
from typing import Any, Mapping

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('git-2.43.0',)
SYSTEM_PATH = '/etc/gitconfig'
MAX_TEXT = 262144
MAX_ENTRIES = 8192
MAX_INCLUDE_DEPTH = 10

_SPACE = ' \t\n\r'
_TRUE = ('true', 'yes', 'on')
_FALSE = ('false', 'no', 'off')
_INCLUDE_CONDITIONS = ('gitdir:', 'gitdir/i:', 'onbranch:', 'hasconfig:remote.*.url:')
_ALIAS_OPTIONS = ('-c', '--config-env', '--exec-path')

# Simple keys: canonical name -> (kind, via_shell, trigger, environment override).
_SIMPLE_KEYS: dict[str, tuple[str, Any, str, str | None]] = {
    'core.pager': ('pager', True, 'paged output of any command', 'GIT_PAGER'),
    'core.editor': ('editor', True, 'commit, tag, rebase and other edits', 'GIT_EDITOR'),
    'sequence.editor': ('editor', True, 'interactive rebase', 'GIT_SEQUENCE_EDITOR'),
    'core.sshcommand': ('ssh_command', True, 'fetch, push or clone over ssh', 'GIT_SSH_COMMAND'),
    'core.askpass': ('askpass', 'unknown', 'credential prompts', 'GIT_ASKPASS'),
    'core.gitproxy': ('git_proxy', False, 'fetch or clone over git://', 'GIT_PROXY_COMMAND'),
    'core.fsmonitor': ('fsmonitor_hook', True, 'status and index refresh in any repository', None),
    'diff.external': ('external_diff', True, 'diff output', 'GIT_EXTERNAL_DIFF'),
    'interactive.difffilter': ('diff_filter', True, 'interactive add and patch modes', None),
    'gpg.program': ('gpg_program', False, 'signing and signature verification', None),
    'gpg.openpgp.program': ('gpg_program', False, 'OpenPGP signing and verification', None),
    'gpg.x509.program': ('gpg_program', False, 'X.509 signing and verification', None),
    'gpg.ssh.program': ('gpg_program', False, 'SSH signing and verification', None),
    'gpg.ssh.defaultkeycommand': ('gpg_key_command', False, 'SSH signing without a key', None),
    'uploadpack.packobjectshook': ('pack_objects_hook', True, 'serving fetch or clone from this host', None),
    'web.browser': ('browser_name', 'not_applicable', 'git web--browse and help --web', None),
}
# Driver keys: (section, key) -> (kind, trigger) for section.<name>.key.
_DRIVER_KEYS: dict[tuple[str, str], tuple[str, str]] = {
    ('diff', 'command'): ('diff_driver', 'diff of a path whose gitattributes select the driver'),
    ('diff', 'textconv'): ('textconv', 'diff or blame of a path whose gitattributes select the driver'),
    ('filter', 'clean'): ('filter_clean', 'add or status of a path whose gitattributes select the filter'),
    ('filter', 'smudge'): ('filter_smudge', 'checkout of a path whose gitattributes select the filter'),
    ('filter', 'process'): ('filter_process', 'checkout or add of a path whose gitattributes select the filter'),
    ('merge', 'driver'): ('merge_driver', 'merge of a path whose gitattributes select the driver'),
    ('difftool', 'cmd'): ('difftool', 'git difftool --tool=<name>'),
    ('mergetool', 'cmd'): ('mergetool', 'git mergetool --tool=<name>'),
    ('browser', 'cmd'): ('browser', 'git web--browse --browser=<name>'),
}
EXECUTION_KINDS = tuple(sorted({v[0] for v in _SIMPLE_KEYS.values()} | {v[0] for v in _DRIVER_KEYS.values()}
                               | {'alias', 'credential_helper', 'pager', 'hooks_path'}))


class _SyntaxError(Exception):
    def __init__(self, line: int, reason: str) -> None:
        super().__init__(reason)
        self.line = line
        self.reason = reason


class _Reader:
    """Character reader that mirrors ``get_next_char``: CRLF -> LF, EOF -> LF."""

    def __init__(self, text: str) -> None:
        self.text = text[1:] if text.startswith('﻿') else text
        self.pos = 0
        self.line = 1
        self.eof = False

    def next(self) -> str:
        if self.pos >= len(self.text):
            self.eof = True
            return '\n'
        c = self.text[self.pos]
        self.pos += 1
        if c == '\r' and self.text[self.pos:self.pos + 1] == '\n':
            c = '\n'
            self.pos += 1
        if c == '\n':
            self.line += 1
        return c


def _parse_value(r: _Reader) -> str:
    out: list[str] = []
    quote = comment = False
    space = 0
    start = r.line
    while True:
        c = r.next()
        if c == '\n':
            if quote:
                raise _SyntaxError(start, 'unterminated_quote')
            return ''.join(out)
        if comment:
            continue
        if c in _SPACE and not quote:
            if out:
                space += 1
            continue
        if not quote and c in ';#':
            comment = True
            continue
        out.extend(' ' * space)
        space = 0
        if c == '\\':
            c = r.next()
            if c == '\n':
                continue
            mapped = {'t': '\t', 'b': '\b', 'n': '\n', '\\': '\\', '"': '"'}.get(c)
            if mapped is None:
                raise _SyntaxError(r.line, 'invalid_escape')
            out.append(mapped)
            continue
        if c == '"':
            quote = not quote
            continue
        out.append(c)


def _parse_section(r: _Reader) -> tuple[str, str | None]:
    name: list[str] = []
    while True:
        c = r.next()
        if r.eof:
            raise _SyntaxError(r.line, 'unterminated_section')
        if c in _SPACE:
            break
        if c == ']':
            return ''.join(name), None
        if not (c.isascii() and (c.isalnum() or c in '-.')):
            raise _SyntaxError(r.line, 'invalid_section')
        name.append(c.lower())
    # Extended form: [section "subsection"].
    c = r.next()
    while c == ' ' or c == '\t':
        c = r.next()
    if c != '"':
        raise _SyntaxError(r.line, 'invalid_section')
    sub: list[str] = []
    while True:
        c = r.next()
        if c == '\n':
            raise _SyntaxError(r.line - 1, 'invalid_subsection')
        if c == '"':
            break
        if c == '\\':
            c = r.next()
            if c == '\n':
                raise _SyntaxError(r.line - 1, 'invalid_subsection')
        sub.append(c)
    if r.next() != ']':
        raise _SyntaxError(r.line, 'invalid_section')
    return ''.join(name), ''.join(sub)


def parse_config(text: str) -> list[dict[str, Any]]:
    """Return the entries of one config file in order, as git reads them.

    Each entry has ``line``, ``name`` (the canonical ``git config --list``
    name), ``section``, ``subsection``, ``key`` and ``value`` (None for a bare
    key). Raises ``ValueError`` with ``(line, reason)`` on a syntax error.
    """
    r = _Reader(text)
    entries: list[dict[str, Any]] = []
    section: str | None = None
    subsection: str | None = None
    comment = False
    try:
        while True:
            c = r.next()
            if c == '\n':
                if r.eof:
                    return entries
                comment = False
                continue
            if comment or c in _SPACE:
                continue
            if c in '#;':
                comment = True
                continue
            if c == '[':
                section, subsection = _parse_section(r)
                if not section:
                    raise _SyntaxError(r.line, 'invalid_section')
                if subsection is None and '.' in section:
                    section, _, subsection = section.partition('.')
                continue
            if not (c.isascii() and c.isalpha()):
                raise _SyntaxError(r.line, 'invalid_key')
            line = r.line
            key = [c.lower()]
            while True:
                c = r.next()
                if r.eof or not (c.isascii() and (c.isalnum() or c == '-')):
                    break
                key.append(c.lower())
            while c == ' ' or c == '\t':
                c = r.next()
            value: str | None = None
            if c != '\n':
                if c != '=':
                    raise _SyntaxError(line, 'invalid_key_line')
                value = _parse_value(r)
            k = ''.join(key)
            name = '.'.join(p for p in (section, subsection, k) if p is not None)
            entries.append({'line': line, 'name': name, 'section': section,
                            'subsection': subsection, 'key': k, 'value': value})
            if len(entries) > MAX_ENTRIES:
                raise _SyntaxError(line, 'too_many_entries')
    except _SyntaxError as exc:
        raise ValueError(exc.line, exc.reason) from None


def _maybe_bool(value: str | None) -> bool | None:
    if value is None:
        return True
    low = value.lower()
    if low in _TRUE:
        return True
    if low in _FALSE or low == '':
        return False
    if value.lstrip('-').isdigit():
        return int(value) != 0
    return None


def _expand_include(path: str, base_file: str) -> tuple[str | None, str | None]:
    """Return (resolved path, gap reason) for an include path."""
    if path.startswith('~'):
        return None, 'include_per_user_path'
    if path.startswith('%(prefix)/'):
        return None, 'include_runtime_prefix'
    if not posixpath.isabs(path):
        path = posixpath.join(posixpath.dirname(base_file), path)
    return posixpath.normpath(path), None


def assess_system_gitconfig(files: Mapping[str, str | None] | None, *,
                            path: str = SYSTEM_PATH) -> dict[str, Any]:
    """Return the programs the system gitconfig can make every git call start.

    ``files`` maps absolute paths to captured text. A value of None records
    that the file was observed to be absent or unreadable; a path missing from
    the mapping was not captured.
    """
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
        'path': path, 'complete': True, 'files': [], 'entries': [], 'includes': [],
        'executions': [], 'transport_risks': [], 'gaps': [], 'warnings': [],
        'origin': 'not_assessed',
    }
    gaps, warnings = result['gaps'], result['warnings']

    def gap(reason: str, **extra: Any) -> None:
        result['complete'] = False
        gaps.append({'reason': reason, **extra})

    if files is None or path not in files:
        gap('not_observed', file=path)
        return result
    if files[path] is None:
        result['files'].append({'path': path, 'present': False})
        return result

    entries: list[dict[str, Any]] = result['entries']
    total = 0

    def read(file: str, depth: int, condition: str | None, chain: tuple[str, ...]) -> None:
        nonlocal total
        text = files.get(file)  # type: ignore[union-attr]
        if text is None:
            return
        total += len(text)
        if len(text) > MAX_TEXT or total > MAX_TEXT * 4:
            gap('text_too_large', file=file, limit=MAX_TEXT)
            return
        result['files'].append({'path': file, 'present': True, 'depth': depth, 'condition': condition})
        try:
            parsed = parse_config(text)
        except ValueError as exc:
            line, reason = exc.args
            gap('syntax_error', file=file, line=line, detail=reason)
            return
        for entry in parsed:
            entry = {**entry, 'file': file, 'condition': condition, 'include_chain': list(chain)}
            entries.append(entry)
            if len(entries) > MAX_ENTRIES:
                gap('too_many_entries', limit=MAX_ENTRIES)
                return
            target_condition: str | None | bool = False
            if entry['name'] == 'include.path':
                target_condition = condition
            elif entry['section'] == 'includeif' and entry['key'] == 'path' and entry['subsection'] is not None:
                cond = entry['subsection']
                if not cond.startswith(_INCLUDE_CONDITIONS):
                    warnings.append({'file': file, 'line': entry['line'], 'reason': 'unknown_include_condition',
                                     'condition': cond})
                    continue
                target_condition = cond if condition is None else f'{condition} && {cond}'
            if target_condition is False:
                continue
            include = {'file': file, 'line': entry['line'], 'path': entry['value'],
                       'condition': target_condition, 'resolved': None, 'followed': False}
            result['includes'].append(include)
            if entry['value'] is None:
                gap('syntax_error', file=file, line=entry['line'], detail='include_without_value')
                continue
            resolved, reason = _expand_include(entry['value'], file)
            if reason:
                gap(reason, file=file, line=entry['line'], include=entry['value'])
                continue
            include['resolved'] = resolved
            if resolved not in files:  # type: ignore[operator]
                gap('include_not_captured', file=file, line=entry['line'], include=resolved)
                continue
            if files[resolved] is None:  # type: ignore[index]
                include['present'] = False
                continue
            if depth + 1 > MAX_INCLUDE_DEPTH:
                gap('include_depth_exceeded', file=file, line=entry['line'], limit=MAX_INCLUDE_DEPTH)
                return
            include['followed'] = True
            read(resolved, depth + 1, target_condition or None, chain + (file,))  # type: ignore[arg-type]
            if not result['complete'] and gaps and gaps[-1]['reason'] in ('include_depth_exceeded',
                                                                          'too_many_entries'):
                return

    read(path, 0, None, ())
    _derive_executions(result)
    return result


def _source(entry: dict[str, Any]) -> dict[str, Any]:
    return {'file': entry['file'], 'line': entry['line'], 'key': entry['name'],
            'condition': entry['condition'], 'include_chain': entry['include_chain']}


def _candidates(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Last-one-wins for one key, keeping later conditional overrides."""
    chosen: list[dict[str, Any]] = []
    for entry in entries:
        if entry['condition'] is None:
            chosen = [entry]
        else:
            chosen.append(entry)
    return chosen


def _derive_executions(result: dict[str, Any]) -> None:
    executions: list[dict[str, Any]] = result['executions']
    entries: list[dict[str, Any]] = result['entries']
    by_name: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        by_name.setdefault(entry['name'], []).append(entry)

    def add(entry: dict[str, Any], kind: str, command: str, via_shell: Any, trigger: str, **extra: Any) -> None:
        possible_override = entry['condition'] is not None
        executions.append({'kind': kind, 'command': command, 'via_shell': via_shell, 'trigger': trigger,
                           'run_as': 'invoking_user', 'overridable': True,
                           'conditional': possible_override, **_source(entry), **extra})

    for name, (kind, via_shell, trigger, env) in _SIMPLE_KEYS.items():
        for entry in _candidates(by_name.get(name, [])):
            value = entry['value']
            if value is None:
                result['warnings'].append({**_source(entry), 'reason': 'value_missing'})
                continue
            if name == 'core.pager' and value in ('', 'cat'):
                continue
            if name == 'core.fsmonitor' and _maybe_bool(value) is not None:
                if _maybe_bool(value):
                    result['warnings'].append({**_source(entry), 'reason': 'builtin_fsmonitor_daemon'})
                continue
            if value == '':
                continue
            add(entry, kind, value, via_shell, trigger, environment_override=env)

    for entry in _candidates(by_name.get('core.hookspath', [])):
        if entry['value']:
            add(entry, 'hooks_path', entry['value'], 'not_applicable',
                'repository hooks (commit, merge, checkout, push, receive and others) in every repository',
                directory=True)

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for entry in entries:
        section, sub, key = entry['section'], entry['subsection'], entry['key']
        if section == 'alias':
            groups.setdefault(('alias', entry['name'][len('alias.'):]), []).append(entry)
        elif section == 'pager' and sub is None:
            groups.setdefault(('pager', key), []).append(entry)
        elif (section, key) in _DRIVER_KEYS and sub is not None:
            groups.setdefault((f'{section}.{key}', sub), []).append(entry)
        elif section == 'hook' and key == 'command':
            result['warnings'].append({**_source(entry), 'reason': 'newer_git_hook_key'})
        elif entry['name'] in ('protocol.allow', 'protocol.ext.allow'):
            if entry['value'] is not None and entry['value'].lower() == 'always':
                result['transport_risks'].append({**_source(entry), 'reason': 'ext_transport_enabled',
                                                  'value': entry['value']})

    for (group, name), items in groups.items():
        for entry in _candidates(items):
            value = entry['value']
            if group == 'alias':
                if value is None:
                    continue
                if value.startswith('!'):
                    add(entry, 'alias', value[1:], True, f'git {name}', alias=name)
                elif any(word in _ALIAS_OPTIONS or word.startswith(tuple(o + '=' for o in _ALIAS_OPTIONS))
                         for word in value.split()):
                    result['complete'] = False
                    result['gaps'].append({**_source(entry), 'reason': 'alias_sets_global_options',
                                           'alias': name})
            elif group == 'pager':
                if value is None or _maybe_bool(value) is not None or value in ('', 'cat'):
                    continue
                add(entry, 'pager', value, True, f'paged output of git {name}', command_name=name,
                    environment_override='GIT_PAGER')
            else:
                section, key = group.split('.')
                kind, trigger = _DRIVER_KEYS[(section, key)]
                if not value:
                    continue
                add(entry, kind, value, True, trigger.replace('<name>', name), driver=name)

    helpers: list[dict[str, Any]] = []
    for entry in entries:
        if entry['section'] != 'credential' or entry['key'] != 'helper':
            continue
        value = entry['value']
        if value is None:
            result['warnings'].append({**_source(entry), 'reason': 'value_missing'})
            continue
        if value == '':
            if entry['condition'] is None and entry['subsection'] is None:
                helpers = []
            else:
                for helper in helpers:
                    helper['may_be_reset'] = True
            continue
        if value.startswith('!'):
            program = value[1:]
        elif value.startswith('/'):
            program = value
        else:
            program = f'git credential-{value}'
        helpers.append({'entry': entry, 'program': program, 'may_be_reset': False})
    for helper in helpers:
        entry = helper['entry']
        add(entry, 'credential_helper', helper['program'], True,
            'credential lookup, storage or erasure for '
            + (f"URLs matching {entry['subsection']}" if entry['subsection'] else 'any URL'),
            helper=entry['value'], url_scope=entry['subsection'], may_be_reset=helper['may_be_reset'],
            appended_argument='get|store|erase')
