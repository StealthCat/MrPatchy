"""Pure systemd-sysctl contract for settings that make the kernel run a program (roadmap F slice, #1088).

At boot ``systemd-sysctl`` writes ``sysctl.d`` assignments into ``/proc/sys``.
A few of those keys name a program that the kernel itself later executes as
root, so a drop-in that points one at a dropped binary is a persistence path.
This module turns captured, read-only ``sysctl.d`` text into the effective
assignment of each such key. It performs no I/O, never runs ``sysctl`` or
``systemd-sysctl``, never writes ``/proc/sys`` and never authorizes a response
action.

Watched keys and what the kernel does with them:

- ``kernel.core_pattern`` beginning with ``|`` runs the named program on every
  core dump; any other value is a file name and runs nothing.
- ``kernel.modprobe`` is executed for every kernel module autoload request.
- ``kernel.hotplug`` (the uevent helper) is executed for every uevent when the
  kernel is built with ``CONFIG_UEVENT_HELPER``; empty means none.
- ``kernel.poweroff_cmd`` is executed on an orderly poweroff.
- ``fs.binfmt_misc.register`` registers a binfmt_misc interpreter when
  binfmt_misc is mounted at that moment, so matching programs are executed
  through that interpreter.

systemd-sysctl rules this module follows (checked against systemd v255
``src/sysctl/sysctl.c``, ``src/basic/sysctl-util.c`` and ``conf-files.c``):

- Only ``*.conf`` names are read; hidden names and directories are skipped. A
  name in a higher-priority directory (``/etc`` → ``/run`` → ``/usr/local/lib``
  → ``/usr/lib`` → ``/lib``) replaces the same name in a lower one, and a
  symlink to ``/dev/null`` masks it. Files are processed in name order.
  ``/lib/sysctl.d`` is read only by split-usr builds; entries found only there
  are reported with the ``split_usr_build_only`` condition rather than dropped.
- Lines are stripped; empty lines and lines starting with ``#`` or ``;`` are
  skipped. There are no continuation lines. A line without ``=`` is ignored
  unless it starts with ``-``, which makes it a *negative match* that excludes
  that key from glob assignments. A ``-`` before an assignment means a failed
  write is ignored.
- Keys accept ``.`` or ``/`` separators: when the first separator is a dot,
  dots and slashes are swapped (``sysctl_normalize``).
- A later assignment of a key replaces an earlier one and moves to the end of
  the apply order; repeating the same value keeps the earlier position.
- A key containing ``*``, ``?`` or ``[`` is a glob. A glob is applied to every
  matching ``/proc/sys`` key that has no explicit (or negative-match) entry of
  its own, regardless of file order. When several globs match one key, the last
  one in apply order is written last.
- Credentials (``sysctl.extra``) are parsed after every file; they are not
  observed here.

Fail-closed rules:

- Unreadable files, unfollowed symlinks, invalid UTF-8, NUL bytes and
  over-limit input become explicit gaps and mark the result incomplete. An
  unreadable winning file still shadows lower-priority files of the same name;
  the contract never falls back to a file systemd would not read.
- ``/etc/sysctl.conf`` is read by systemd-sysctl only through a ``sysctl.d``
  link. When it is supplied but not linked, its watched assignments are still
  reported under ``other_readers`` because procps ``sysctl --system`` reads it
  last.
- Glob matching is evaluated against the watched key names only; ``/proc/sys``
  is not observed, so a glob is reported as applying to a watched key whenever
  its pattern matches that key name.
- systemd expands globs with glob(3) and ``GLOB_BRACE``. Only ``*``, ``?``
  and bracket expressions with ``!`` negation and ranges are modelled. A glob
  key that also uses braces, backslash escapes, ``[^`` negation or
  ``[:class:]``/``[=x=]``/``[.x.]`` forms is never matched here: it becomes a
  blocking ``glob_not_modelled`` gap, and every watched key without an explicit
  entry gets the ``unmodelled_glob_may_apply`` condition.
- Values are returned bounded with the SHA-256 of the full value. Nothing is
  labelled safe or a package default; ``origin`` is always ``not_assessed``.
"""
from __future__ import annotations

import fnmatch
import hashlib
import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
MAX_FILES = 512
MAX_TEXT = 262144
MAX_ASSIGNMENTS = 20000
MAX_VALUE = 2048
MAX_KEY = 512
MAX_HISTORY = 32
MAX_GAPS = 64

SYSCTL_DIRS = ('/etc/sysctl.d', '/run/sysctl.d', '/usr/local/lib/sysctl.d', '/usr/lib/sysctl.d', '/lib/sysctl.d')
SPLIT_USR_DIR = '/lib/sysctl.d'
SYSCTL_CONF = '/etc/sysctl.conf'

# Path-form key -> (kind, what the kernel runs it for, kernel default as documented).
WATCHED: dict[str, dict[str, str]] = {
    'kernel/core_pattern': {'kind': 'core_pattern', 'trigger': 'every core dump', 'default': 'core'},
    'kernel/modprobe': {'kind': 'program', 'trigger': 'every kernel module autoload request',
                        'default': '/sbin/modprobe'},
    'kernel/hotplug': {'kind': 'program', 'trigger': 'every uevent (CONFIG_UEVENT_HELPER kernels)', 'default': ''},
    'kernel/poweroff_cmd': {'kind': 'command', 'trigger': 'orderly poweroff', 'default': '/sbin/poweroff'},
    'fs/binfmt_misc/register': {'kind': 'binfmt_register', 'trigger': 'execution of programs matching the '
                                'registration, when binfmt_misc is mounted at write time', 'default': ''},
}

# Bytes the kernel keeps from a write (buffer size minus the terminator); proc_dostring truncates longer values.
KERNEL_LIMITS = {'kernel/core_pattern': 127, 'kernel/modprobe': 255, 'kernel/hotplug': 255,
                 'kernel/poweroff_cmd': 255}

BLOCKING = frozenset({'input_malformed', 'too_many_files', 'duplicate_path', 'file_unreadable', 'symlink_not_followed',
                      'invalid_utf8', 'nul_byte', 'text_over_limit', 'too_many_assignments',
                      'glob_not_modelled'})
UNOBSERVED = (
    {'code': 'kernel_command_line', 'detail': 'sysctl.<key>= parameters on the kernel command line are applied '
                                              'before systemd-sysctl and are not observed.'},
    {'code': 'credentials', 'detail': 'The sysctl.extra system credential is parsed after every file and is not '
                                      'observed.'},
    {'code': 'runtime_writes', 'detail': 'Values written later by services (for example apport or '
                                         'systemd-coredump at start), sysctl -w or direct /proc/sys writes are '
                                         'not observed.'},
    {'code': 'live_value', 'detail': 'The live /proc/sys value is not observed; this is the configured boot '
                                     'assignment only.'},
    {'code': 'proc_sys_keys', 'detail': 'The keys present under /proc/sys are not observed, so glob matches are '
                                        'evaluated against key names only.'},
)
NOT_A_VERDICT = 'Parsed configuration only. This is not a safety verdict and origin is not assessed.'

_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
_EOL = re.compile(r'\r\n|\r|\n')
_WHITESPACE = ' \t\n\r'
_GLOB = frozenset('*?[')
# glob(3)/GLOB_BRACE syntax that fnmatch does not reproduce: brace expansion, backslash quoting,
# ``[^`` negation and POSIX character/equivalence/collating classes.
_UNMODELLED_GLOB = ('{', '}', '\\', '[^', '[:', '[=', '[.')


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
    return not any(g['code'] in BLOCKING or g['code'] == 'gaps_truncated' for g in gaps)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()


def normalize_key(key: str) -> str:
    """Apply systemd's ``sysctl_normalize``: when the first separator is a dot,
    swap dots and slashes; collapse repeated slashes and ``.`` components; drop
    a leading slash."""
    first = re.search(r'[/.]', key)
    if first and first.group() == '.':
        key = key[:first.start()] + key[first.start():].translate(str.maketrans('./', '/.'))
    absolute = key.startswith('/')
    parts = [p for p in key.split('/') if p not in ('', '.')]
    simplified = '/'.join(parts)
    if absolute and not simplified:
        return '/'
    return simplified


def display_key(key: str) -> str:
    """Return the conventional dotted spelling of a path-form key."""
    return key.translate(str.maketrans('./', '/.'))


def is_glob(key: str) -> bool:
    return any(c in _GLOB for c in key)


def glob_modelled(pattern: str) -> bool:
    """Return whether ``glob_matches`` reproduces glob(3) for this pattern."""
    return not any(token in pattern for token in _UNMODELLED_GLOB)


def glob_matches(pattern: str, key: str) -> bool:
    """glob(3) over ``/proc/sys``: each path component is matched separately.

    Patterns outside the modelled subset never match; callers report them as gaps."""
    if not glob_modelled(pattern):
        return False
    pattern_parts, key_parts = pattern.split('/'), key.split('/')
    return len(pattern_parts) == len(key_parts) and all(
        fnmatch.fnmatchcase(k, p) for p, k in zip(pattern_parts, key_parts))


def _decode(path: str, text: Any, gaps: list[dict[str, Any]]) -> tuple[str | None, str]:
    """Return ``(text, '')``, or ``(None, code)`` naming this file's own failure.

    The code is returned rather than read back from ``gaps`` because a capped gap
    list ends in ``gaps_truncated`` and would hide the file's real cause."""
    if isinstance(text, bytes):
        if len(text) > MAX_TEXT:
            return _unreadable(gaps, 'text_over_limit', path)
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            return _unreadable(gaps, 'invalid_utf8', path)
    if not isinstance(text, str):
        return _unreadable(gaps, 'file_unreadable', path)
    if len(text) > MAX_TEXT:
        return _unreadable(gaps, 'text_over_limit', path)
    if '\x00' in text:
        return _unreadable(gaps, 'nul_byte', path)
    return text, ''


def _unreadable(gaps: list[dict[str, Any]], code: str, path: str) -> tuple[None, str]:
    _gap(gaps, code, path)
    return None, code


def _effective_files(files: Any, gaps: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[tuple[str, str]],
                                                                      dict[str, Any] | None]:
    """Return every file's record, the ordered readable ``(path, text)`` list and
    the unlinked ``/etc/sysctl.conf`` record and text, if any."""
    try:
        supplied = list(files)
    except TypeError:
        _gap(gaps, 'input_malformed', detail='files must be an iterable of mappings.')
        return [], [], None
    if len(supplied) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'More than {MAX_FILES} files were supplied; none were parsed.')
        return [], [], None
    records: list[dict[str, Any]] = []
    items: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    by_name: dict[str, list[tuple[int, dict[str, Any], dict[str, Any]]]] = {}
    for item in supplied:
        path = item.get('path') if isinstance(item, dict) else None
        if (not isinstance(path, str) or not path.startswith('/') or len(path) > 4096 or _CONTROL.search(path)
                or posixpath.normpath(path) != path):
            _gap(gaps, 'input_malformed', detail='A file entry has no normalized absolute path.')
            continue
        if path in items:
            _gap(gaps, 'duplicate_path', path)
            continue
        directory, name = posixpath.split(path)
        record: dict[str, Any] = {'path': path, 'name': name, 'directory': directory}
        records.append(record)
        items[path] = (record, item)
        kind = item.get('type', 'file')
        if path == SYSCTL_CONF:
            record['status'] = 'pending'
        elif directory not in SYSCTL_DIRS:
            record.update(status='ignored', reason='outside_known_directories')
        elif name.startswith('.'):
            record.update(status='ignored', reason='hidden')
        elif not name.endswith('.conf'):
            record.update(status='ignored', reason='not_conf_suffix')
        elif kind not in ('file', 'symlink'):
            record.update(status='ignored', reason='not_regular_file')
        else:
            by_name.setdefault(name, []).append((SYSCTL_DIRS.index(directory), record, item))
    effective: list[tuple[str, str]] = []
    linked: set[str] = set()
    for name in sorted(by_name, key=lambda n: n.encode('utf-8', 'surrogatepass')):  # strcmp order
        candidates = sorted(by_name[name], key=lambda entry: entry[0])
        _, winner, item = candidates[0]
        for _, record, _ in candidates[1:]:
            record.update(status='overridden', overridden_by=winner['path'])
        if winner['directory'] == SPLIT_USR_DIR:
            winner['condition'] = 'split_usr_build_only'
        source, text = winner['path'], item.get('text')
        if item.get('type', 'file') == 'symlink' and text is None:
            target = item.get('link_target')
            target = (posixpath.normpath(posixpath.join(winner['directory'], target))
                      if isinstance(target, str) and target and len(target) <= 4096 else None)
            if target == '/dev/null':
                winner.update(status='masked', reason='symlink_to_dev_null')
                continue
            linked_item = items.get(target) if target else None
            if linked_item is None or linked_item[1].get('type', 'file') != 'file':
                winner.update(status='unreadable', reason='symlink_not_followed')
                _gap(gaps, 'symlink_not_followed', winner['path'],
                     detail='The link target was not read; lower-priority files of this name stay overridden.')
                continue
            winner.update(link_target=target)
            linked.add(target)
            source, text = target, linked_item[1].get('text')
        decoded, reason = _decode(source, text, gaps)
        if decoded is None:
            winner.update(status='unreadable', reason=reason)
            continue
        winner.update(status='effective', sha256=_sha(decoded))
        effective.append((winner['path'], decoded))
    unlinked: dict[str, Any] | None = None
    if SYSCTL_CONF in items:
        record, item = items[SYSCTL_CONF]
        if SYSCTL_CONF in linked:
            record.update(status='read_through_link')
        else:
            if item.get('type', 'file') == 'file':
                decoded, reason = _decode(SYSCTL_CONF, item.get('text'), gaps)
            else:
                decoded, reason = None, 'not_regular_file'
                _gap(gaps, 'file_unreadable', SYSCTL_CONF, detail='/etc/sysctl.conf is not a regular file.')
            if decoded is None:
                record.update(status='unreadable', reason=reason)
            else:
                record.update(status='not_read_by_systemd_sysctl', reason='not_linked_from_sysctl_d',
                              sha256=_sha(decoded))
                unlinked = {'path': SYSCTL_CONF, 'text': decoded}
    return records, effective, unlinked


def _parse(path: str, text: str, gaps: list[dict[str, Any]], budget: list[int]) -> list[dict[str, Any]]:
    """Return the file's assignments in order, as systemd-sysctl ``parse_file`` reads them."""
    out: list[dict[str, Any]] = []
    for number, raw in enumerate(_EOL.split(text), 1):
        line = raw.strip(_WHITESPACE)
        if not line or line[0] in '#;':
            continue
        ignore_failure, value = False, None
        if '=' in line:
            key, value = line.split('=', 1)
            if key.startswith('-'):
                ignore_failure, key = True, key[1:]
            value = value.strip(_WHITESPACE)
        elif line.startswith('-'):
            key = line[1:]  # negative match: excludes the key from globs
        else:
            _gap(gaps, 'line_not_assignment', path, number, 'systemd-sysctl ignores this line.')
            continue
        key = key.strip(_WHITESPACE)
        if len(key) > MAX_KEY or _CONTROL.search(key):
            _gap(gaps, 'key_not_normalized', path, number, 'The key is too long or holds control characters.')
            continue
        key = normalize_key(key)
        if value is not None and is_glob(key) and not glob_modelled(key):  # negative globs write nothing
            _gap(gaps, 'glob_not_modelled', path, number,
                 'This glob uses brace, backslash, [^ or character-class syntax that is not modelled; it may '
                 'assign any watched key without an explicit entry.')
        if budget[0] <= 0:
            _gap(gaps, 'too_many_assignments', path, number,
                 f'More than {MAX_ASSIGNMENTS} assignments; the rest were not parsed.')
            break
        budget[0] -= 1
        out.append({'key': key, 'value': value, 'ignore_failure': ignore_failure, 'path': path, 'line': number})
    return out


def _program(kind: str, value: str) -> tuple[bool, str | None, list[str]]:
    """Return ``(executes, program, conditions)`` for a watched value."""
    if kind == 'core_pattern':
        if not value.startswith('|'):
            return False, None, []
        tokens = value[1:].split()
        return True, (tokens[0] if tokens else None), []
    if kind == 'binfmt_register':
        if not value:
            return False, None, []
        fields = value[1:].split(value[0])
        interpreter = fields[5] if len(fields) >= 6 and fields[5] else None
        return True, interpreter, ['binfmt_misc_mounted_at_write_time']
    tokens = value.split()
    if not tokens:
        return False, None, []
    # kernel.modprobe and kernel.hotplug are executed as one path; poweroff_cmd is split into argv.
    return True, (tokens[0] if kind == 'command' else value), []


def _bounded(value: str) -> dict[str, Any]:
    return {'value': value[:MAX_VALUE], 'value_truncated': len(value) > MAX_VALUE, 'value_sha256': _sha(value)}


def _resolve(assignments: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Replay the ordered-hashmap semantics and return each watched key's result."""
    options: dict[str, dict[str, Any]] = {}
    history: dict[str, list[dict[str, Any]]] = {key: [] for key in WATCHED}
    unmodelled = any(entry['value'] is not None and is_glob(entry['key'])
                     and not glob_modelled(entry['key']) for entry in assignments)
    for entry in assignments:
        key = entry['key']
        existing = options.get(key)
        if existing is not None and existing['value'] == entry['value']:
            existing['ignore_failure'] = existing['ignore_failure'] or entry['ignore_failure']
            outcome = 'same_value_kept_earlier'
        else:
            if existing is not None:
                del options[key]  # re-inserted at the end of the apply order
            options[key] = dict(entry)
            outcome = 'assigned'
        for watched in WATCHED:
            if key == watched or (is_glob(key) and glob_matches(key, watched)):
                if len(history[watched]) < MAX_HISTORY:
                    history[watched].append({'path': entry['path'], 'line': entry['line'], 'pattern': key,
                                             'via': 'glob' if key != watched else 'explicit',
                                             'negative_match': entry['value'] is None, 'outcome': outcome})
    results: dict[str, dict[str, Any]] = {}
    for watched, meta in WATCHED.items():
        result: dict[str, Any] = {'key': watched, 'name': display_key(watched), 'kind': meta['kind'],
                                  'runs_on': meta['trigger'], 'kernel_default': meta['default'],
                                  'assignments': history[watched],
                                  'assignments_truncated': len(history[watched]) >= MAX_HISTORY,
                                  'origin': 'not_assessed'}
        explicit = options.get(watched)
        winner, via = None, None
        if explicit is not None:
            if explicit['value'] is None:
                result.update(state='excluded_from_globs')
            else:
                winner, via = explicit, 'explicit'
        else:
            for key, option in options.items():  # apply order; the last matching glob is written last
                if option['value'] is not None and is_glob(key) and glob_matches(key, watched):
                    winner, via = option, 'glob'
        if winner is None:
            result.setdefault('state', 'not_configured')
            result.update(executes=None, program=None, conditions=['kernel_default_or_runtime_value'])
        else:
            executes, program, conditions = _program(meta['kind'], winner['value'])
            if executes and watched == 'kernel/hotplug':
                conditions.append('kernel_config_uevent_helper')
            limit = KERNEL_LIMITS.get(watched)
            if limit is not None and len(winner['value'].encode('utf-8', 'surrogatepass')) > limit:
                conditions.append(f'kernel_keeps_first_{limit}_bytes')
            if winner['path'].startswith(SPLIT_USR_DIR + '/'):
                conditions.append('split_usr_build_only')
            result.update(state='configured', via=via, pattern=winner['key'], path=winner['path'],
                          line=winner['line'], ignore_failure=winner['ignore_failure'], executes=executes,
                          program=program, conditions=conditions, **_bounded(winner['value']))
        if unmodelled and explicit is None:
            result['conditions'].append('unmodelled_glob_may_apply')
        results[watched] = result
    return results


def resolve(files: Any) -> dict[str, Any]:
    """Resolve the boot-time assignment of every watched key from captured ``sysctl.d`` files.

    ``files`` is an iterable of mappings with ``path``, optional ``type``
    (``file``, ``symlink``, ``directory`` ...), ``text`` (str or bytes, ``None``
    when unreadable) and, for symlinks, ``link_target``.
    """
    gaps: list[dict[str, Any]] = []
    records, effective, unlinked = _effective_files(files, gaps)
    budget = [MAX_ASSIGNMENTS]
    assignments: list[dict[str, Any]] = []
    for path, text in effective:
        assignments.extend(_parse(path, text, gaps, budget))
    keys = _resolve(assignments)
    other_readers: list[dict[str, Any]] = []
    if unlinked is not None:
        procps = _resolve(assignments + _parse(unlinked['path'], unlinked['text'], gaps, budget))
        for watched, result in procps.items():
            if result.get('path') == SYSCTL_CONF:
                other_readers.append({'reader': 'procps sysctl --system',
                                      'detail': 'Precedence approximated with systemd-sysctl rules, with '
                                                '/etc/sysctl.conf read last.', **result})
        _gap(gaps, 'sysctl_conf_not_linked', SYSCTL_CONF,
             detail='systemd-sysctl does not read this file without a sysctl.d link; procps sysctl --system reads '
                    'it last. Its watched assignments are listed under other_readers.')
    executes = [k['name'] for k in keys.values() if k.get('executes')]
    return {'contract_version': CONTRACT_VERSION, 'complete': _complete(gaps), 'files': records,
            'keys': list(keys.values()), 'executing_keys': executes, 'other_readers': other_readers,
            'gaps': gaps, 'unobserved': [dict(u) for u in UNOBSERVED], 'not_a_verdict': NOT_A_VERDICT}
