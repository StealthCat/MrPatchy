"""Pure Debian ``Xsession`` contract (roadmap F slice, #1054).

Takes captured, read-only metadata for ``/etc/X11/Xsession.d``,
``/etc/X11/Xsession.options`` and ``/etc/X11/Xsession.options.d`` and says which
session parts the Debian/Ubuntu ``/etc/X11/Xsession`` wrapper sources into every
user's X session, in what order, which ``Xsession.options`` are in effect and
whether the per-user ``~/.xsessionrc``, ``~/.xsession`` and ``~/.Xsession``
hooks run.

Semantics follow x11-common ``1:7.7+23ubuntu3`` (``/etc/X11/Xsession`` and its
``x11-common_*`` parts) and debianutils ``run-parts`` 5.17. The run-parts rules
were checked against the real binary:

* ``SESSIONFILES=$(run-parts --list /etc/X11/Xsession.d)``: a name must match
  ``^[A-Za-z0-9_-]+$``. Entries are sorted with ``alphasort`` and run-parts never
  calls ``setlocale``, so the order is byte order. Symlinks are followed. Only
  regular files are listed; directories, devices (including a ``/dev/null``
  link) and dangling links are skipped. ``--list`` does not need the executable
  bit, and every listed part is sourced with ``.`` as the logging-in user.
* Options are the bytes of ``Xsession.options`` (when readable) followed by
  ``Xsession.options.d`` entries from ``run-parts --list --regex '\\.conf$'``
  concatenated with ``cat``. That regex admits dot files and spaces, and no
  newline is inserted between files. ``has_option`` is true when the last line
  starting ``(no-)?<option>`` followed by a GNU grep word boundary is the
  positive form.
* ``40x11-common_xsessionrc`` sources ``~/.xsessionrc`` when readable.
  ``50x11-common_determine-startup`` runs the first existing of ``~/.xsession``
  and ``~/.Xsession`` (directly when executable, otherwise with ``$SHELL``) when
  ``allow-user-xsession`` is set and no session program was chosen.
  ``20x11-common_process-args`` sets that program when the display manager
  passes one, so the user hooks run only for the default session.

The per-user hooks are concluded only when the implementing parts are listed and
byte-identical to the reference parts. A modified, missing or unhashed part
makes that hook ``undetermined``. Other parts are listed but never interpreted.

It performs no I/O, never runs or sources a script and never authorizes a
response action. An unobserved or unreadable directory, malformed or over-limit
input, missing option text and an unverified ``/etc/X11/Xsession`` are explicit
blocking gaps and are never reported as covered. ``origin`` is always
``not_assessed``.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE_VERSIONS = ('x11-common 1:7.7+23ubuntu3', 'debianutils run-parts 5.17')
XSESSION = '/etc/X11/Xsession'
SESSION_DIR = '/etc/X11/Xsession.d'
OPTIONS_FILE = '/etc/X11/Xsession.options'
OPTIONS_DIR = '/etc/X11/Xsession.options.d'
DIRECTORIES = (SESSION_DIR, OPTIONS_DIR)
MAX_FILES = 512
MAX_PATH = 4096
MAX_OPTION_TEXT = 65536
MAX_TOTAL_OPTION_TEXT = 262144
MAX_GAPS = 64

# SHA-256 of the reference x11-common 1:7.7+23ubuntu3 files whose behavior this contract interprets.
REFERENCE_XSESSION_SHA256 = '55fd60f9b2b2c6589719a85c94407bfc5bace37aa90866e882d8cdc45fd461ca'
REFERENCE_PARTS = {
    '20x11-common_process-args': 'ec8cce2ca0022c33088113e930ceda164746ba82262a9dc37ae5874ee300ac51',
    '40x11-common_xsessionrc': '76944eea06861af747d0ed1cd516ef597d4f1543b040e025bfa1df15906ce73f',
    '50x11-common_determine-startup': 'c8aa9d6622178eeae1b0c20475338384f0f4e6a3b1a2f788906006bdacf3792a',
}
KNOWN_OPTIONS = ('allow-failsafe', 'allow-user-resources', 'allow-user-xsession', 'use-session-dbus', 'use-ssh-agent')
FILE_TYPES = ('file', 'symlink', 'directory', 'other')
BLOCKING = frozenset({
    'input_malformed', 'too_many_files', 'duplicate_path', 'metadata_missing', 'directory_not_observed',
    'directory_unreadable', 'xsession_not_observed', 'xsession_unverified', 'options_not_observed',
    'option_text_missing', 'option_text_too_large', 'option_text_binary', 'option_text_escape', 'gaps_truncated',
})
UNOBSERVED = (
    'Whether a display manager starts sessions through /etc/X11/Xsession, and which session it passes, is not observed.',
    'Part contents other than the reference x11-common parts are not interpreted; a part may change later behavior.',
    'Home directories are not read: whether ~/.xsessionrc, ~/.xsession or ~/.Xsession exist is not observed.',
    'Directory ownership and write permissions, and which accounts can read each part, are not observed.',
    'Wayland sessions and display-manager-specific session scripts are not covered.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'sourced': 'Xsession sources this part into every X session as the logging-in user.',
    'option_file': 'Read as Xsession options.',
    'name_filtered': 'run-parts only lists names made of letters, digits, "_" and "-".',
    'option_name_filtered': 'Only names ending in ".conf" are read as options.',
    'not_regular': 'run-parts only lists regular files.',
    'dev_null_link': 'A symlink to /dev/null is a device, not a regular file, so it is skipped.',
    'dangling_symlink': 'The symlink target does not exist; run-parts reports an error and skips it.',
    'outside_directories': 'Xsession does not read this location.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
OBSERVATIONS = {
    'not_world_readable': 'Not readable by other accounts: their X session would abort when sourcing it.',
    'not_root_owned': 'Not owned by root, yet sourced into every X session.',
    'group_or_other_writable': 'Writable by group or other, yet sourced into every X session.',
    'modified_reference_part': 'Has a reference x11-common name but different content.',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_PART_NAME = re.compile(r'[A-Za-z0-9_-]+')
_SHA256 = re.compile(r'[0-9a-f]{64}')


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code}
    if path is not None:
        gap['path'] = path
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def part_name_listed(name: str) -> bool:
    """Return whether ``run-parts`` (no ``--lsbsysinit``, no ``--regex``) considers this entry name."""
    return bool(_PART_NAME.fullmatch(name))


def option_name_listed(name: str) -> bool:
    """Return whether ``run-parts --regex '\\.conf$'`` considers this entry name."""
    return name.endswith('.conf') and '\n' not in name


def _int(value: Any, upper: int | None = None) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0 and (upper is None or value <= upper)


def _valid_path(path: Any) -> bool:
    return (isinstance(path, str) and 1 < len(path) <= MAX_PATH and path.startswith('/')
            and not _CONTROL.search(path) and posixpath.normpath(path) == path and not path.startswith('//'))


def _stat(meta: Any) -> dict[str, Any] | None:
    """Validate one stat-like mapping; keeps optional ``sha256`` and ``text``."""
    if not isinstance(meta, dict) or meta.get('type') not in FILE_TYPES or meta.get('type') == 'symlink':
        return None
    if not (_int(meta.get('mode'), 0o7777) and _int(meta.get('uid')) and _int(meta.get('size'))):
        return None
    stat = {'type': meta['type'], 'mode': meta['mode'], 'uid': meta['uid'], 'size': meta['size']}
    sha = meta.get('sha256')
    stat['sha256'] = sha if isinstance(sha, str) and _SHA256.fullmatch(sha) else None
    stat['text'] = meta.get('text') if isinstance(meta.get('text'), str) else None
    return stat


def _normalize(item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_path(item.get('path')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', detail='A file observation has no valid absolute path or type.')
        return None
    entry: dict[str, Any] = {'path': item['path'], 'type': item['type'], 'stat': None, 'resolved': True}
    if item['type'] == 'symlink':
        link = item.get('link_target')
        if not isinstance(link, str) or not link or len(link) > MAX_PATH or '\x00' in link:
            entry['resolved'] = False
            return entry
        entry['link_target'] = link
        if link == '/dev/null':
            entry['stat'] = {'type': 'other', 'mode': 0o666, 'uid': 0, 'size': 0, 'sha256': None, 'text': None}
        elif 'target' not in item:
            entry['resolved'] = False
        elif item['target'] is None:
            entry['dangling'] = True
        else:
            entry['stat'] = _stat(item['target'])
            entry['resolved'] = entry['stat'] is not None
        return entry
    entry['stat'] = _stat(item)
    entry['resolved'] = entry['stat'] is not None
    return entry


def _record(entry: dict[str, Any], status: str, reason: str, **extra: Any) -> dict[str, Any]:
    record: dict[str, Any] = {'path': entry['path'], 'type': entry['type'], 'status': status, 'reason_code': reason,
                              'reason': REASONS[reason]}
    if entry.get('link_target') is not None:
        record['link_target'] = entry['link_target']
    stat = entry.get('stat')
    if stat is not None and stat.get('sha256'):
        record['sha256'] = stat['sha256']
    record.update(extra)
    return record


def _listed(entry: dict[str, Any]) -> tuple[str, str]:
    """Apply run-parts' stat check. Returns ``(status, reason)``: ``listed``, ``ignored`` or ``unresolved``."""
    if not entry['resolved']:
        return 'unresolved', 'unresolved'
    if entry['type'] == 'symlink':
        if entry['link_target'] == '/dev/null':
            return 'ignored', 'dev_null_link'
        if entry.get('dangling'):
            return 'ignored', 'dangling_symlink'
    if entry['stat']['type'] != 'file':
        return 'ignored', 'not_regular'
    return 'listed', ''


def _observations(name: str, stat: dict[str, Any]) -> list[dict[str, str]]:
    found = []
    if not stat['mode'] & 0o004:
        found.append('not_world_readable')
    if stat['uid'] != 0:
        found.append('not_root_owned')
    if stat['mode'] & 0o022:
        found.append('group_or_other_writable')
    if name in REFERENCE_PARTS and stat['sha256'] is not None and stat['sha256'] != REFERENCE_PARTS[name]:
        found.append('modified_reference_part')
    return [{'code': code, 'detail': OBSERVATIONS[code]} for code in found]


def _word_char(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char == '_')


def has_option(text: str, option: str) -> bool | None:
    """Evaluate ``has_option`` over the concatenated option text.

    Returns ``None`` when the result depends on the locale: a non-ASCII character right after an
    option name is a word character for GNU grep in a UTF-8 locale but not in the C locale.
    """
    last = None
    undetermined = False
    for line in text.split('\n'):
        negated = line.startswith('no-')
        body = line[3:] if negated else line
        if not body.startswith(option):
            continue
        following = body[len(option):len(option) + 1]
        if following and not following.isascii():
            undetermined = True
            last = None
            continue
        if following and _word_char(following):
            continue
        last = not negated
        undetermined = False
    if undetermined:
        return None
    return bool(last)


def evaluate(files: Any, *, directories: Any = None, xsession_sha256: Any = None) -> dict[str, Any]:
    """Resolve what Debian's Xsession sources and runs from supplied metadata.

    ``files`` lists mappings with ``path`` (absolute, normalized) and ``type`` (``file``, ``symlink``,
    ``directory`` or ``other``). Anything but a symlink carries ``mode`` (0–0o7777), ``uid``, ``size`` and
    optionally ``sha256`` (lowercase hex). ``Xsession.options`` and options-directory files carry their
    decoded ``text``. A symlink carries ``link_target`` and ``target``: the same fields for what it resolves
    to, or ``None`` when it resolves to nothing. Include ``/etc/X11/Xsession.options`` with type ``absent``
    when it does not exist. ``directories`` lists ``{'path', 'state'}`` with state ``listed``, ``absent`` or
    ``unreadable`` for both directories. ``xsession_sha256`` is the SHA-256 of ``/etc/X11/Xsession``.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference_versions': list(REFERENCE_VERSIONS),
        'files': [], 'session_parts': [], 'options': {}, 'user_hooks': [], 'session_aborts': False,
        'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    if xsession_sha256 is None:
        _gap(gaps, 'xsession_not_observed', XSESSION, 'The SHA-256 of /etc/X11/Xsession was not supplied.')
    elif xsession_sha256 != REFERENCE_XSESSION_SHA256:
        _gap(gaps, 'xsession_unverified', XSESSION,
             'The wrapper differs from the reference x11-common script, so its behavior is not assumed.')

    states: dict[str, str] = {}
    if directories is not None and not isinstance(directories, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='Directory observations must be a list.')
    for item in directories if isinstance(directories, (list, tuple)) else ():
        path = item.get('path') if isinstance(item, dict) else None
        state = item.get('state') if isinstance(item, dict) else None
        if path not in DIRECTORIES or state not in ('listed', 'absent', 'unreadable') or path in states:
            _gap(gaps, 'input_malformed', detail='A directory observation is malformed, unknown or repeated.')
            continue
        states[path] = state
    for path in DIRECTORIES:
        if path not in states:
            _gap(gaps, 'directory_not_observed', path, 'No listing result was supplied for this directory.')
        elif states[path] == 'unreadable':
            _gap(gaps, 'directory_unreadable', path, 'The directory exists but could not be listed.')
    if states.get(SESSION_DIR) == 'absent':
        result['session_aborts'] = True

    if not isinstance(files, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='File observations must be a list.')
        files = ()
    if len(files) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'Only the first {MAX_FILES} file observations are assessed.')
        files = files[:MAX_FILES]

    seen: set[str] = set()
    parts: list[tuple[bytes, dict[str, Any]]] = []
    option_entries: list[tuple[bytes, dict[str, Any]]] = []
    options_file: dict[str, Any] | None = None
    options_file_absent = False
    for item in files:
        if isinstance(item, dict) and item.get('path') == OPTIONS_FILE and item.get('type') == 'absent':
            if OPTIONS_FILE in seen:
                _gap(gaps, 'duplicate_path', OPTIONS_FILE, 'The path was supplied more than once; the first is used.')
                continue
            seen.add(OPTIONS_FILE)
            options_file_absent = True
            continue
        entry = _normalize(item, gaps)
        if entry is None:
            continue
        path = entry['path']
        if path in seen:
            _gap(gaps, 'duplicate_path', path, 'The path was supplied more than once; the first is used.')
            continue
        seen.add(path)
        directory, name = posixpath.split(path)
        if directory in states and states[directory] == 'absent':
            _gap(gaps, 'input_malformed', path, 'A file was supplied for a directory reported absent.')
        if path == OPTIONS_FILE:
            options_file = entry
        elif directory == SESSION_DIR:
            if not part_name_listed(name):
                result['files'].append(_record(entry, 'ignored', 'name_filtered'))
                continue
            parts.append((name.encode('utf-8', 'surrogateescape'), entry))
        elif directory == OPTIONS_DIR:
            if not option_name_listed(name):
                result['files'].append(_record(entry, 'ignored', 'option_name_filtered'))
                continue
            option_entries.append((name.encode('utf-8', 'surrogateescape'), entry))
        else:
            result['files'].append(_record(entry, 'ignored', 'outside_directories'))

    sourced: dict[str, dict[str, Any]] = {}
    for _key, entry in sorted(parts, key=lambda pair: pair[0]):
        status, reason = _listed(entry)
        if status == 'unresolved':
            _gap(gaps, 'metadata_missing', entry['path'], 'Type, mode, owner or size is missing for this part.')
            result['files'].append(_record(entry, 'unresolved', 'unresolved'))
            continue
        if status == 'ignored':
            result['files'].append(_record(entry, 'ignored', reason))
            continue
        name = posixpath.basename(entry['path'])
        observations = _observations(name, entry['stat'])
        record = _record(entry, 'sourced', 'sourced', order=len(result['session_parts']) + 1,
                         observations=observations)
        result['files'].append(record)
        if not result['session_aborts']:
            result['session_parts'].append({'name': name, 'path': entry['path'], 'order': record['order'],
                                            'sha256': entry['stat']['sha256'], 'observations': observations})
        sourced[name] = entry['stat']

    texts: list[str] = []
    option_text_ok = True
    total = 0

    def add_text(entry: dict[str, Any]) -> None:
        nonlocal option_text_ok, total
        text = entry['stat']['text']
        if text is None:
            option_text_ok = False
            _gap(gaps, 'option_text_missing', entry['path'], 'The option text was not supplied.')
            return
        if len(text) > MAX_OPTION_TEXT or total + len(text) > MAX_TOTAL_OPTION_TEXT:
            option_text_ok = False
            _gap(gaps, 'option_text_too_large', entry['path'], 'The option text is over the limit and is not read.')
            return
        if '\x00' in text:
            option_text_ok = False
            _gap(gaps, 'option_text_binary', entry['path'], 'grep treats text with NUL bytes as binary.')
            return
        if '\\' in text:
            option_text_ok = False
            _gap(gaps, 'option_text_escape', entry['path'],
                 'The sh echo in has_option interprets backslash escapes, which this contract does not emulate.')
            return
        if not entry['stat']['mode'] & 0o004:
            option_text_ok = False
            _gap(gaps, 'option_text_missing', entry['path'],
                 'Not readable by other accounts, so the options differ between users.')
            return
        total += len(text)
        texts.append(text)

    if options_file is None and not options_file_absent:
        option_text_ok = False
        _gap(gaps, 'options_not_observed', OPTIONS_FILE, 'Neither the options file nor its absence was supplied.')
    elif options_file is not None:
        status, reason = _listed(options_file)
        if status == 'unresolved':
            option_text_ok = False
            _gap(gaps, 'metadata_missing', OPTIONS_FILE, 'Type, mode, owner or size is missing for the options file.')
        elif status == 'listed':
            result['files'].append(_record(options_file, 'read', 'option_file'))
            add_text(options_file)
        else:
            result['files'].append(_record(options_file, 'ignored', reason))
    for _key, entry in sorted(option_entries, key=lambda pair: pair[0]):
        status, reason = _listed(entry)
        if status == 'unresolved':
            option_text_ok = False
            _gap(gaps, 'metadata_missing', entry['path'], 'Type, mode, owner or size is missing for this file.')
            result['files'].append(_record(entry, 'unresolved', 'unresolved'))
        elif status == 'ignored':
            result['files'].append(_record(entry, 'ignored', reason))
        else:
            result['files'].append(_record(entry, 'read', 'option_file'))
            add_text(entry)

    options: dict[str, bool | None] = {}
    combined = ''.join(texts)
    for option in KNOWN_OPTIONS:
        options[option] = has_option(combined, option) if option_text_ok else None
    result['options'] = options

    wrapper_ok = not any(g['code'] in ('xsession_not_observed', 'xsession_unverified') for g in gaps)
    listing_ok = states.get(SESSION_DIR) == 'listed' and not any(
        g['code'] in ('metadata_missing', 'too_many_files', 'input_malformed', 'gaps_truncated') for g in gaps)

    def reference(name: str) -> str:
        """Return ``yes`` (listed and identical), ``absent`` (not listed) or ``unknown``."""
        if not listing_ok:
            return 'unknown'
        stat = sourced.get(name)
        if stat is None:
            return 'absent'
        return 'yes' if stat['sha256'] == REFERENCE_PARTS[name] else 'unknown'

    def hook(path: str, status: str, detail: str, **extra: Any) -> None:
        result['user_hooks'].append({'path': path, 'status': status, 'detail': detail, **extra})

    if result['session_aborts']:
        detail = 'Xsession aborts because /etc/X11/Xsession.d does not exist.'
        for path in ('~/.xsessionrc', '~/.xsession', '~/.Xsession'):
            hook(path, 'not_run', detail)
    elif not wrapper_ok:
        for path in ('~/.xsessionrc', '~/.xsession', '~/.Xsession'):
            hook(path, 'undetermined', 'The /etc/X11/Xsession wrapper is not verified.')
    else:
        rc = reference('40x11-common_xsessionrc')
        if rc == 'yes':
            hook('~/.xsessionrc', 'sourced', 'Sourced into the X session when it exists and is readable.')
        elif rc == 'absent':
            hook('~/.xsessionrc', 'not_by_reference',
                 'The reference part that sources it is not listed; other parts are not interpreted.')
        else:
            hook('~/.xsessionrc', 'undetermined', 'The part that sources it is modified, unhashed or not listed.')
        startup = reference('50x11-common_determine-startup')
        args = reference('20x11-common_process-args')
        allow = options['allow-user-xsession']
        for path in ('~/.xsession', '~/.Xsession'):
            if startup == 'absent':
                hook(path, 'not_by_reference',
                     'The reference part that runs it is not listed; other parts are not interpreted.')
            elif startup != 'yes' or args == 'unknown':
                hook(path, 'undetermined', 'The parts that choose the session program are modified, unhashed '
                                           'or not listed.')
            elif allow is None:
                hook(path, 'undetermined', 'allow-user-xsession could not be determined.')
            elif not allow:
                hook(path, 'disabled', 'allow-user-xsession is not set.')
            else:
                hook(path, 'runs_for_default_session',
                     'The first of ~/.xsession and ~/.Xsession that exists runs as the session program when the '
                     'display manager passes no session program; it is executed when executable, otherwise run '
                     'with $SHELL.')

    result['determined'] = not any(g['code'] in BLOCKING for g in gaps)
    return result
