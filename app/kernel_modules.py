"""Pure kernel-module configuration contract (roadmap F slice, #952).

Turns captured, read-only text of ``modprobe.d`` and ``modules-load.d``
configuration into typed, bounded records, and resolves which ``install``
commands a boot-time module request would run. It performs no I/O, never runs
``modprobe``, ``systemd-modules-load`` or a configured command, and never
authorizes a response action.

Documented behavior this module follows (``modprobe.d(5)``, ``modules-load.d(5)``
and libkmod):

- Only ``*.conf`` files are read; hidden names and non-regular entries are
  skipped. A name in a higher-priority directory (``/etc`` → ``/run`` →
  ``/usr/local/lib`` → ``/usr/lib`` → ``/lib``) replaces the same name in a
  lower one. The remaining files are processed in name order.
- ``modprobe.d`` lines: ``#`` starts a comment only at the start of a line, a
  trailing backslash continues the line, and ``-`` equals ``_`` in module names.
- ``install``/``remove`` commands are handed to a shell as root whenever the
  module is requested. libkmod uses the first matching entry in processing
  order, and the module name of an entry may be a shell wildcard.
- A configuration ``alias`` is consulted before the module name itself.
  ``softdep`` ``pre:`` modules are requested before, ``post:`` modules after.
- A module that has a non-empty ``softdep`` does not run its own ``install``
  command; only its soft dependencies' commands run. (The alias, first-match
  and softdep rules were checked against ``modprobe -n -v`` from kmod 31.)
- ``modules-load.d`` and Debian's ``/etc/modules`` name one module per line;
  ``#`` and ``;`` start comment lines.

Fail-closed rules:

- Unreadable files, symlinks that were not followed, invalid UTF-8, NUL bytes
  and over-limit input become explicit gaps and mark the result incomplete. An
  unreadable winning file still shadows lower-priority files of the same name;
  the contract never falls back to a file the tools would not read.
- Command text is returned bounded with the SHA-256 of the full command.
- ``/bin/true`` and ``/bin/false`` commands are labelled ``disable`` (the common
  hardening idiom). That label describes the command text only.
- Nothing is labelled a package default or safe. ``origin`` is always
  ``not_assessed`` and every result says it is not a safety verdict.
- ``unobserved`` always names the inputs this contract cannot see: the kernel
  command line, the kernel's own alias and dependency tables, the initramfs
  copy of the configuration and command-line or environment overrides.
"""
from __future__ import annotations

import fnmatch
import hashlib
import posixpath
import re
from collections.abc import Iterable
from typing import Any

CONTRACT_VERSION = 1
MAX_FILES = 512
MAX_TEXT = 262144
MAX_ENTRIES = 4096
MAX_COMMAND = 2048
MAX_FIELD = 256
MAX_GAPS = 64
MAX_DEPTH = 8
MAX_CHAINS = 1024
MAX_VISITS = 20000

MODPROBE_DIRS = ('/etc/modprobe.d', '/run/modprobe.d', '/usr/local/lib/modprobe.d', '/usr/lib/modprobe.d',
                 '/lib/modprobe.d')
MODULES_LOAD_DIRS = ('/etc/modules-load.d', '/run/modules-load.d', '/usr/local/lib/modules-load.d',
                     '/usr/lib/modules-load.d', '/lib/modules-load.d')
ETC_MODULES = '/etc/modules'
DIRECTIVES = ('install', 'remove', 'alias', 'blacklist', 'options', 'softdep', 'weakdep')
DEPRECATED = ('include', 'config')
# Gaps that can hide a directive the real tools would read.
BLOCKING = frozenset({'input_malformed', 'too_many_files', 'too_many_entries', 'duplicate_path', 'file_unreadable',
                      'symlink_not_followed', 'invalid_utf8', 'nul_byte', 'text_over_limit', 'field_over_limit',
                      'chain_depth_exceeded', 'too_many_chains', 'resolution_budget_exceeded',
                      'dependency_incomplete'})
UNOBSERVED_MODPROBE = (
    {'code': 'kernel_command_line', 'detail': 'modprobe.blacklist= and module parameters on the kernel command '
                                                'line are not observed.'},
    {'code': 'kernel_alias_and_dependency_tables', 'detail': 'modules.alias, modules.dep and modules.softdep under '
                                                               '/lib/modules are not observed, so hardware aliases '
                                                               'and module dependencies are not resolved.'},
    {'code': 'initramfs_copy', 'detail': 'The initramfs carries its own copy of this configuration from when it was '
                                         'built; early boot may use different commands.'},
    {'code': 'tool_overrides', 'detail': 'modprobe -C/--config, MODPROBE_OPTIONS and callers that ignore install '
                                         'commands are not observed.'},
)
UNOBSERVED_MODULES_LOAD = (
    {'code': 'kernel_command_line', 'detail': 'modules_load= and rd.modules_load= on the kernel command line are '
                                                'not observed.'},
    {'code': 'other_boot_requests', 'detail': 'Modules requested at boot by udev, services, the initramfs or the '
                                              'kernel itself are not listed here.'},
)
NOT_A_VERDICT = 'Parsed configuration only. This is not a safety verdict and origin is not assessed.'

_DISABLE = re.compile(r'(?:(?:/usr)?/s?bin/)?(?:true|false)')
_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, line: int | None = None,
         detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code}
    if path is not None:
        gap['path'] = path
    if line is not None:
        gap['line'] = line
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def _complete(gaps: list[dict[str, Any]]) -> bool:
    # A truncated gap list may have dropped a blocking gap.
    return not any(g['code'] in BLOCKING or g['code'] == 'gaps_truncated' for g in gaps)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()


def normalize(name: str) -> str:
    """Apply libkmod's module-name rule: ``-`` becomes ``_`` outside ``[...]``."""
    out, bracket = [], False
    for char in name:
        if char == '[':
            bracket = True
        elif char == ']':
            bracket = False
        out.append('_' if char == '-' and not bracket else char)
    return ''.join(out)


def _decode(path: str, text: Any, gaps: list[dict[str, Any]]) -> str | None:
    if isinstance(text, bytes):
        if len(text) > MAX_TEXT:
            _gap(gaps, 'text_over_limit', path)
            return None
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            _gap(gaps, 'invalid_utf8', path)
            return None
    if not isinstance(text, str):
        _gap(gaps, 'file_unreadable', path)
        return None
    if len(text) > MAX_TEXT:
        _gap(gaps, 'text_over_limit', path)
        return None
    if '\x00' in text:
        _gap(gaps, 'nul_byte', path)
        return None
    return text


def _link(directory: str, target: Any) -> str | None:
    if not isinstance(target, str) or not target or len(target) > 4096:
        return None
    return posixpath.normpath(posixpath.join(directory, target))


def _effective_files(files: Any, dirs: tuple[str, ...], gaps: list[dict[str, Any]],
                     extra: tuple[str, ...] = ()) -> tuple[list[dict[str, Any]], list[tuple[str, str]],
                                                           dict[str, str]]:
    """Return every file's record, the readable effective ``(path, text)`` list and extra-path text."""
    try:
        supplied = list(files)
    except TypeError:
        _gap(gaps, 'input_malformed', detail='files must be an iterable of mappings.')
        return [], [], {}
    if len(supplied) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'More than {MAX_FILES} files were supplied; none were parsed.')
        return [], [], {}
    records: list[dict[str, Any]] = []
    by_name: dict[str, list[tuple[int, dict[str, Any], dict[str, Any]]]] = {}
    extras: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for item in supplied:
        path = item.get('path') if isinstance(item, dict) else None
        if (not isinstance(path, str) or not path.startswith('/') or len(path) > 4096 or _CONTROL.search(path)
                or posixpath.normpath(path) != path):
            _gap(gaps, 'input_malformed', detail='A file entry has no normalized absolute path.')
            continue
        if path in seen:
            _gap(gaps, 'duplicate_path', path)
            continue
        seen.add(path)
        directory, name = posixpath.split(path)
        record: dict[str, Any] = {'path': path, 'name': name, 'directory': directory}
        records.append(record)
        kind = item.get('type', 'file')
        if path in extra:
            extras[path] = item
            record['status'] = 'pending'
            continue
        if directory not in dirs:
            record.update(status='ignored', reason='outside_known_directories')
        elif name.startswith('.'):
            record.update(status='ignored', reason='hidden')
        elif not name.endswith('.conf'):
            record.update(status='ignored', reason='not_conf_suffix')
        elif kind not in ('file', 'symlink'):
            record.update(status='ignored', reason='not_regular_file')
        else:
            by_name.setdefault(name, []).append((dirs.index(directory), record, item))
    effective: list[tuple[str, str]] = []
    extra_text: dict[str, str] = {}
    linked: dict[str, str] = {}
    for name in sorted(by_name):  # str order equals byte order for the ASCII names these tools ship
        candidates = sorted(by_name[name], key=lambda entry: entry[0])
        _, winner, item = candidates[0]
        for _, record, _ in candidates[1:]:
            record.update(status='overridden', overridden_by=winner['path'])
        text = item.get('text')
        if item.get('type', 'file') == 'symlink' and text is None:
            target = _link(winner['directory'], item.get('link_target'))
            if target == '/dev/null':
                winner.update(status='masked', reason='symlink_to_dev_null')
            elif target in extra and target in extras:
                winner.update(status='effective', reason='symlink_to_supplied_file', link_target=target)
                if target in linked:
                    continue  # already read through an earlier link
                linked[target] = winner['path']
                decoded = _decode(target, extras[target].get('text'), gaps)
                if decoded is not None:
                    extra_text[target] = decoded
                    effective.append((target, decoded))
            else:
                winner.update(status='unreadable', reason='symlink_not_followed')
                _gap(gaps, 'symlink_not_followed', winner['path'],
                     detail='The link target was not read; lower-priority files of this name stay overridden.')
            continue
        decoded = _decode(winner['path'], text, gaps)
        if decoded is None:
            winner.update(status='unreadable', reason=gaps[-1]['code'])
            continue
        winner.update(status='effective', sha256=_sha(decoded))
        effective.append((winner['path'], decoded))
    for path, item in extras.items():
        record = next(r for r in records if r['path'] == path)
        if path in linked:
            record.update(status='effective' if path in extra_text else 'unreadable', linked_from=linked[path])
        else:
            decoded = _decode(path, item.get('text'), gaps)
            if decoded is None:
                record.update(status='unreadable', reason=gaps[-1]['code'])
                continue
            # Read by Debian's kmod init script even without the modules-load.d link.
            record.update(status='effective', reason='not_linked_from_modules_load_d')
            effective.append((path, decoded))
            extra_text[path] = decoded
        if path in extra_text:
            record['sha256'] = _sha(extra_text[path])
    return records, effective, extra_text


def _logical_lines(text: str) -> Iterable[tuple[int, str]]:
    """Yield ``(first line number, logical line)`` with backslash continuations joined."""
    start, parts = 0, []
    for number, line in enumerate(text.split('\n'), 1):
        line = line.rstrip('\r')
        if not parts:
            start = number
        if line.endswith('\\'):
            parts.append(line[:-1])
            continue
        parts.append(line)
        yield start, ''.join(parts)
        parts = []
    if parts:
        yield start, ''.join(parts)


def _field(value: str, path: str, line: int, gaps: list[dict[str, Any]]) -> str | None:
    if len(value) > MAX_FIELD or _CONTROL.search(value):
        _gap(gaps, 'field_over_limit', path, line, 'A module name is too long or holds control characters.')
        return None
    return normalize(value)


def _command(action: str, module: str, command: str, path: str, line: int, order: int) -> dict[str, Any]:
    command = command.strip()
    return {'action': action, 'module': module, 'wildcard': any(c in module for c in '*?['),
            'kind': 'disable' if _DISABLE.fullmatch(command) else 'command',
            'command': command[:MAX_COMMAND], 'command_truncated': len(command) > MAX_COMMAND,
            'command_sha256': _sha(command), 'path': path, 'line': line, 'order': order, 'shadowed_by': None}


def resolve_modprobe(files: Any) -> dict[str, Any]:
    """Resolve the effective ``modprobe.d`` configuration from supplied file entries.

    Each entry is a mapping with ``path``, ``text`` (``str``, ``bytes`` or ``None`` when unread),
    optional ``type`` (``file``, ``symlink`` or anything else for non-regular entries) and optional
    ``link_target`` for symlinks.
    """
    gaps: list[dict[str, Any]] = []
    records, effective, _ = _effective_files(files, MODPROBE_DIRS, gaps)
    result: dict[str, Any] = {'install': [], 'remove': [], 'aliases': [], 'blacklist': [], 'options': [],
                              'softdeps': [], 'weakdeps': []}
    first: dict[tuple[str, str], int] = {}
    count = 0
    for path, text in effective:
        for line, logical in _logical_lines(text):
            logical = logical.lstrip(' \t')
            if not logical or logical.startswith('#'):
                continue
            if count >= MAX_ENTRIES:
                _gap(gaps, 'too_many_entries', path, line, f'Parsing stopped after {MAX_ENTRIES} directives.')
                break
            parts = logical.split(None, 2)
            directive = parts[0]
            if directive in DEPRECATED:
                _gap(gaps, 'deprecated_directive_ignored', path, line, f'kmod does not parse "{directive}" lines.')
                continue
            if directive not in DIRECTIVES:
                _gap(gaps, 'unknown_directive', path, line, 'kmod ignores this line.')
                continue
            if len(parts) < 2:
                _gap(gaps, 'malformed_directive', path, line, f'"{directive}" needs a module name.')
                continue
            module = _field(parts[1], path, line, gaps)
            if module is None:
                continue
            rest = parts[2].strip() if len(parts) > 2 else ''
            where = {'path': path, 'line': line}
            if directive == 'blacklist':
                result['blacklist'].append({'module': module, **where})
            elif directive in ('softdep', 'weakdep'):
                groups: dict[str, list[str]] = {'pre': [], 'post': [], 'weak': []}
                mode = 'weak' if directive == 'weakdep' else None
                bad = False
                for token in rest.split():
                    if directive == 'softdep' and token in ('pre:', 'post:'):
                        mode = token[:-1]
                    elif mode is None:
                        bad = True
                    else:
                        name = _field(token, path, line, gaps)
                        if name is not None:
                            groups[mode].append(name)
                if bad or not rest:
                    _gap(gaps, 'malformed_directive', path, line, f'"{directive}" has no usable module list.')
                if directive == 'softdep':
                    result['softdeps'].append({'module': module, 'pre': groups['pre'], 'post': groups['post'], **where})
                else:
                    result['weakdeps'].append({'module': module, 'modules': groups['weak'], **where})
            elif not rest:
                _gap(gaps, 'malformed_directive', path, line, f'"{directive}" needs a value after the module name.')
                continue
            elif directive == 'alias':
                target = _field(rest.split()[0], path, line, gaps)
                if target is not None:
                    result['aliases'].append({'alias': module, 'module': target, **where})
            elif directive == 'options':
                result['options'].append({'module': module, 'options': rest[:MAX_COMMAND],
                                          'options_truncated': len(rest) > MAX_COMMAND,
                                          'options_sha256': _sha(rest), **where})
            else:
                entry = _command(directive, module, rest, path, line, len(result[directive]))
                entry['shadowed_by'] = first.setdefault((directive, module), entry['order'])
                if entry['shadowed_by'] == entry['order']:
                    entry['shadowed_by'] = None
                result[directive].append(entry)
            count += 1
        else:
            continue
        break
    return {'contract_version': CONTRACT_VERSION, 'mechanism': 'modprobe', 'complete': _complete(gaps),
            'files': records, **result, 'gaps': gaps, 'unobserved': [dict(u) for u in UNOBSERVED_MODPROBE],
            'origin': 'not_assessed', 'note': NOT_A_VERDICT}


def resolve_modules_load(files: Any) -> dict[str, Any]:
    """Resolve the modules requested at boot from ``modules-load.d`` files and ``/etc/modules``.

    ``files`` uses the :func:`resolve_modprobe` entry shape. ``/etc/modules`` may be supplied as an
    entry; Debian's ``modules-load.d/modules.conf`` symlink to it is then resolved to that text.
    """
    gaps: list[dict[str, Any]] = []
    records, effective, _ = _effective_files(files, MODULES_LOAD_DIRS, gaps, extra=(ETC_MODULES,))
    modules: list[dict[str, Any]] = []
    for path, text in effective:
        for line, raw in enumerate(text.split('\n'), 1):
            tokens = raw.strip().split()
            if not tokens or tokens[0][0] in '#;':
                continue
            if len(modules) >= MAX_ENTRIES:
                _gap(gaps, 'too_many_entries', path, line, f'Parsing stopped after {MAX_ENTRIES} modules.')
                break
            module = _field(tokens[0], path, line, gaps)
            if module is None:
                continue
            entry = {'module': module, 'path': path, 'line': line, 'extra_tokens': len(tokens) - 1}
            if len(tokens) > 1:
                _gap(gaps, 'extra_tokens_not_interpreted', path, line,
                     'Text after the module name is not interpreted.')
            modules.append(entry)
        else:
            continue
        break
    return {'contract_version': CONTRACT_VERSION, 'mechanism': 'modules_load', 'complete': _complete(gaps),
            'files': records, 'modules': modules, 'gaps': gaps,
            'unobserved': [dict(u) for u in UNOBSERVED_MODULES_LOAD], 'origin': 'not_assessed',
            'note': NOT_A_VERDICT}


def _entries(result: Any, key: str) -> list[dict[str, Any]]:
    value = result.get(key) if isinstance(result, dict) else None
    return [e for e in value if isinstance(e, dict)] if isinstance(value, list) else []


def commands_for(modprobe: Any, module: str, action: str = 'install') -> dict[str, Any]:
    """Return the first matching ``install``/``remove`` entry for a module and the later matches it shadows."""
    if action not in ('install', 'remove') or not isinstance(module, str):
        return {'selected': None, 'shadowed': []}
    name = normalize(module)
    matches = [e for e in _entries(modprobe, action)
               if isinstance(e.get('module'), str) and fnmatch.fnmatchcase(name, e['module'])]
    return {'selected': matches[0] if matches else None, 'shadowed': matches[1:]}


def boot_commands(modprobe: Any, modules_load: Any) -> dict[str, Any]:
    """List the ``install`` commands that the boot-time module requests would run.

    For each requested module the resolver applies configuration aliases first, then requests
    ``softdep`` ``pre:`` modules, the module itself and ``post:`` modules, to a bounded depth.
    Every step records how it was reached. Entries for blacklisted modules are kept and flagged,
    because whether a blacklist applies depends on the requesting tool. A module with a non-empty
    ``softdep`` does not run its own command; that command is listed under ``ignored`` instead.
    A wildcard ``install`` pattern is matched against every requested name, although kmod applies
    it only to modules that exist in the unobserved kernel tables, so the list errs toward more.
    """
    gaps: list[dict[str, Any]] = []
    for name, result in (('modprobe', modprobe), ('modules_load', modules_load)):
        if not isinstance(result, dict) or result.get('mechanism') != name:
            _gap(gaps, 'input_malformed', detail=f'{name} is not a result of this contract.')
        elif result.get('complete') is not True:
            _gap(gaps, 'dependency_incomplete', detail=f'The {name} result is incomplete; chains may be missing.')
    aliases = [a for a in _entries(modprobe, 'aliases')
               if isinstance(a.get('alias'), str) and isinstance(a.get('module'), str)]
    softdeps = [s for s in _entries(modprobe, 'softdeps') if isinstance(s.get('module'), str)]
    blacklisted = {b['module'] for b in _entries(modprobe, 'blacklist') if isinstance(b.get('module'), str)}
    chains: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    listed: set[tuple[int, str]] = set()
    visits = 0

    def visit(name: str, via: list[dict[str, str]], active: frozenset[str], request: dict[str, Any]) -> None:
        nonlocal visits
        visits += 1
        if visits > MAX_VISITS:
            if not any(g['code'] == 'resolution_budget_exceeded' for g in gaps):
                _gap(gaps, 'resolution_budget_exceeded',
                     detail=f'Resolution stopped after {MAX_VISITS} steps; chains may be missing.')
            return
        if len(chains) >= MAX_CHAINS:
            if not any(g['code'] == 'too_many_chains' for g in gaps):
                _gap(gaps, 'too_many_chains', detail=f'Only the first {MAX_CHAINS} chains are listed.')
            return
        if name in active:
            return  # a dependency loop adds no new command
        if len(via) > MAX_DEPTH:
            if not any(g['code'] == 'chain_depth_exceeded' for g in gaps):  # first occurrence only
                _gap(gaps, 'chain_depth_exceeded', request['path'], request.get('line'),
                     f'Resolution stopped {MAX_DEPTH} steps after "{request["module"]}".')
            return
        active = active | {name}
        targets = [a['module'] for a in aliases if fnmatch.fnmatchcase(name, a['alias'])]
        if targets:
            for target in dict.fromkeys(targets):
                visit(target, via + [{'relation': 'alias', 'module': target}], active, request)
            return
        deps = [s for s in softdeps if fnmatch.fnmatchcase(name, s['module'])]
        for dep in deps:
            for pre in dep.get('pre') or []:
                if isinstance(pre, str):
                    visit(pre, via + [{'relation': 'softdep_pre', 'module': pre}], active, request)
        found = commands_for(modprobe, name)
        has_softdeps = any(dep.get('pre') or dep.get('post') for dep in deps)
        if found['selected'] is not None and (id(request), name) not in listed:
            listed.add((id(request), name))  # one probe requests each module once
            command = found['selected']
            (ignored if has_softdeps else chains).append({'boot_module': request['module'],
                           'requested_by': {'path': request['path'], 'line': request.get('line')},
                           'via': via, 'module': name, 'blacklisted': name in blacklisted,
                           'kind': command.get('kind'), 'command': command.get('command'),
                           'command_truncated': command.get('command_truncated'),
                           'command_sha256': command.get('command_sha256'),
                           'source': {'path': command.get('path'), 'line': command.get('line')},
                           'shadowed_definitions': len(found['shadowed']),
                           **({'reason': 'module_has_softdep'} if has_softdeps else {})})
        for dep in deps:
            for post in dep.get('post') or []:
                if isinstance(post, str):
                    visit(post, via + [{'relation': 'softdep_post', 'module': post}], active, request)

    for request in _entries(modules_load, 'modules'):
        if isinstance(request.get('module'), str) and isinstance(request.get('path'), str):
            visit(request['module'], [], frozenset(), request)
    return {'contract_version': CONTRACT_VERSION, 'complete': _complete(gaps), 'chains': chains,
            'ignored': ignored[:MAX_CHAINS],
            'commands': sum(1 for c in chains if c['kind'] == 'command'),
            'disabled': sum(1 for c in chains if c['kind'] == 'disable'), 'gaps': gaps,
            'unobserved': [dict(u) for u in UNOBSERVED_MODPROBE + UNOBSERVED_MODULES_LOAD],
            'origin': 'not_assessed', 'note': NOT_A_VERDICT}
