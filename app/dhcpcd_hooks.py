"""Pure dhcpcd hook contract (roadmap F slice, #1363).

Takes captured, read-only metadata for dhcpcd's hook locations and says which
files Debian's and Ubuntu's ``dhcpcd-run-hooks`` *sources* as root on every
dhcpcd event, in which order, and why every other entry is not used. It never
reads a hook's contents.

Semantics follow the hook loop at the end of ``dhcpcd-run-hooks`` from the
``dhcpcd-base`` packages listed in ``REFERENCES``. The loop is identical in all
of them except for the compiled-in hook directory:

* The script sources ``/etc/dhcpcd.enter-hook``, then every entry that the
  ``<hookdir>/*`` glob expands to, then ``/etc/dhcpcd.exit-hook``.
* ``/bin/sh`` is dash, which sorts glob results with ``strcmp``, so the order is
  byte order. ``*`` does not match names that start with ``.``.
* A path that ends with ``~`` is skipped.
* For each word of ``$skip_hooks`` (dhcpcd sets it from the ``nohook`` options
  that apply to the interface, after turning commas into spaces), a path is skipped when it ends with
  ``/<word>``, ``/NN-<word>`` or ``/NN-<word>.sh``, where ``NN`` is two digits.
  The word is compared literally, but ``$skip_hooks`` is expanded unquoted, so
  a word that contains a glob character first goes through pathname expansion.
  That is relative to dhcpcd's working directory and is reported as a blocking
  gap.
* A remaining path is sourced with ``.`` when ``[ -f "$hook" ]`` holds, which
  means a regular file after following symlinks. The executable bit, owner and
  mode do not matter, and the hook runs as root inside the script's shell.

The contract performs no I/O, never runs a command and never authorizes a
response action. A missing or unrecognized ``dhcpcd-run-hooks`` hash, an
unobserved or unreadable hook directory, an unobserved enter or exit hook, an
unobserved symlink target, malformed or duplicate input, a glob in ``nohook``
and over-limit input are blocking gaps, and are never reported as covered.
When the ``nohook`` words are not supplied, the result assumes none: it can
then only over-report. No record is labelled safe, and ``origin`` is always
``not_assessed``.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
# SHA-256 of the packaged dhcpcd-run-hooks -> the hook directory compiled into it.
REFERENCES = {
    '00014efd2b2044d95c3d7452df23e291bbb40b75734f8ebb268e3cef70f290e8': {
        'packages': ('dhcpcd-base 10.0.6-1ubuntu3.2', 'dhcpcd-base 10.1.0-8'),
        'script': '/usr/lib/dhcpcd/dhcpcd-run-hooks',
        'hook_dir': '/usr/lib/dhcpcd/dhcpcd-hooks',
    },
    '56b4d366ccc7713f96f106c253792ec94d599a90f718c4d1e54d0268cebd5cb5': {
        'packages': ('dhcpcd-base 10.5.2-6',),
        'script': '/usr/libexec/dhcpcd-run-hooks',
        'hook_dir': '/usr/libexec/dhcpcd-hooks',
    },
}
ENTER_HOOK = '/etc/dhcpcd.enter-hook'
EXIT_HOOK = '/etc/dhcpcd.exit-hook'
MAX_FILES = 1024
MAX_PATH = 4096
MAX_GAPS = 64
MAX_NOHOOK = 256
FILE_TYPES = ('file', 'symlink', 'directory', 'other')
TARGET_TYPES = ('file', 'directory', 'other')
DIR_STATES = ('listed', 'absent', 'unreadable')
WHEN = 'Sourced as root by dhcpcd-run-hooks on every dhcpcd event (lease, carrier, routing and stop changes).'
BLOCKING = frozenset({
    'input_malformed', 'too_many_files', 'duplicate_path', 'metadata_missing', 'symlink_target_unobserved',
    'script_not_observed', 'script_not_reference', 'directory_not_observed', 'directory_unreadable',
    'hook_not_observed', 'nohook_glob', 'gaps_truncated',
})
UNOBSERVED = (
    'Whether dhcpcd is the DHCP client in use, and on which interfaces.',
    'A replacement script set by the dhcpcd.conf "script" option.',
    'Which nohook options apply to each interface, unless nohook words were supplied.',
    'The contents of each sourced hook and anything it sources or runs in turn.',
)
NOT_A_VERDICT = ('This records which files dhcpcd-run-hooks would source. It is not a safety verdict and '
                 'authorizes no response action.')
REASONS = {
    'sourced': 'A regular file after following symlinks, so dhcpcd-run-hooks sources it as root.',
    'backup_name': 'The path ends with "~", which dhcpcd-run-hooks skips.',
    'skipped_by_nohook': 'A nohook word matches this name, so dhcpcd-run-hooks skips it.',
    'hidden_name': 'The name starts with ".", which the hook glob does not match.',
    'not_regular': 'Not a regular file after following symlinks, so [ -f ] fails.',
    'unresolvable_symlink': 'The symlink cannot be resolved, so [ -f ] fails.',
    'absent': 'The file does not exist.',
    'nested_entry': 'Inside a subdirectory of the hook directory, which the glob does not descend into.',
    'not_a_hook_location': 'Not one of the locations dhcpcd-run-hooks sources.',
    'unresolved': 'Required metadata is missing, so the outcome cannot be determined.',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_GLOB = re.compile(r'[*?\[]')


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


def _valid_path(path: Any) -> bool:
    return (isinstance(path, str) and 1 < len(path) <= MAX_PATH and path.startswith('/')
            and not _CONTROL.search(path) and posixpath.normpath(path) == path and not path.startswith('//'))


def skip_words(nohook: Any, gaps: list[dict[str, Any]]) -> list[str] | None:
    """Return the ``$skip_hooks`` words, split as the unquoted expansion does with the default IFS."""
    if nohook is None:
        return None
    if not isinstance(nohook, (list, tuple)) or len(nohook) > MAX_NOHOOK or not all(
            isinstance(value, str) and '\x00' not in value and len(value) <= MAX_PATH for value in nohook):
        _gap(gaps, 'input_malformed', detail='nohook must be a bounded list of strings.')
        return []
    # dhcpcd turns every comma in a nohook value into a space before it sets skip_hooks
    # (if-options.c, case 'C': "Commas to spaces for shell").
    words = [word for value in nohook for word in re.split(r'[ \t\n]+', value.replace(',', ' ')) if word]
    for word in words:
        if _GLOB.search(word):
            _gap(gaps, 'nohook_glob', detail=f'The nohook word {word!r} contains a glob character, so the unquoted '
                                             '$skip_hooks expansion depends on files in dhcpcd\'s working directory.')
    return words


def skipped_by(path: str, words: list[str] | None) -> str | None:
    """Return the nohook word whose case pattern matches ``path``, if any."""
    for word in words or ():
        if path.endswith('/' + word):
            return word
        for suffix in (f'-{word}', f'-{word}.sh'):
            head = path[:-len(suffix)] if path.endswith(suffix) else None
            if head is not None and len(head) >= 3 and head[-3] == '/' and head[-2:].isascii() \
                    and head[-2:].isdigit():
                return word
    return None


def _normalize(item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_path(item.get('path')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', detail='A file observation has no valid absolute path or type.')
        return None
    entry: dict[str, Any] = {'path': item['path'], 'type': item['type']}
    if item['type'] != 'symlink':
        entry['effective'] = item['type']
        return entry
    link = item.get('link_target')
    if isinstance(link, str) and link and len(link) <= MAX_PATH and '\x00' not in link:
        entry['link_target'] = link
    if 'target' not in item:
        entry['effective'] = None
    elif item['target'] is None:
        entry['effective'] = 'unresolvable'
    elif isinstance(item['target'], dict) and item['target'].get('type') in TARGET_TYPES:
        entry['effective'] = item['target']['type']
    else:
        entry['effective'] = None
    return entry


def _record(entry: dict[str, Any], status: str, reason: str, **extra: Any) -> dict[str, Any]:
    record = {'path': entry['path'], 'type': entry['type'], 'status': status, 'reason_code': reason,
              'reason': REASONS[reason]}
    if entry.get('link_target') is not None:
        record['link_target'] = entry['link_target']
    record.update(extra)
    return record


def _outcome(entry: dict[str, Any], words: list[str] | None, gaps: list[dict[str, Any]]) -> tuple[str, str, dict]:
    path = entry['path']
    if path.endswith('~'):
        return 'ignored', 'backup_name', {}
    word = skipped_by(path, words)
    if word is not None:
        return 'ignored', 'skipped_by_nohook', {'nohook_word': word}
    effective = entry['effective']
    if effective is None:
        code = 'symlink_target_unobserved' if entry['type'] == 'symlink' else 'metadata_missing'
        _gap(gaps, code, path, 'Required metadata for this entry was not supplied or is malformed.')
        return 'unresolved', 'unresolved', {}
    if effective == 'unresolvable':
        return 'ignored', 'unresolvable_symlink', {}
    if effective != 'file':
        return 'ignored', 'not_regular', {}
    return 'sourced', 'sourced', {}


def evaluate(files: Any, *, script_sha256: Any = None, hook_dir_state: Any = None, absent: Any = (),
             nohook: Any = None) -> dict[str, Any]:
    """Resolve which files dhcpcd-run-hooks sources from supplied metadata.

    ``files`` lists ``/etc/dhcpcd.enter-hook``, ``/etc/dhcpcd.exit-hook`` and the entries of the
    hook directory, each a mapping with ``path`` (absolute, normalized) and ``type`` (``file``,
    ``symlink``, ``directory`` or ``other``, from ``lstat``). A symlink also carries ``target``:
    ``{'type': ...}`` from ``stat``, or ``None`` when ``stat`` fails. ``link_target`` is optional
    and only echoed. ``script_sha256`` is the SHA-256 of the host's ``dhcpcd-run-hooks``; it
    selects the hook directory. ``hook_dir_state`` is ``listed``, ``absent`` or ``unreadable``.
    ``absent`` names the enter and exit hooks confirmed not to exist. ``nohook`` is the list of
    raw ``nohook`` option values that apply, or ``None`` when they were not observed. Commas in a
    value separate words, as dhcpcd turns them into spaces.
    """
    gaps: list[dict[str, Any]] = []
    reference = None
    if script_sha256 is None:
        _gap(gaps, 'script_not_observed', detail='The dhcpcd-run-hooks SHA-256 was not supplied.')
    elif not (isinstance(script_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', script_sha256)):
        _gap(gaps, 'input_malformed', detail='The dhcpcd-run-hooks SHA-256 must be 64 lowercase hex characters.')
    elif script_sha256 not in REFERENCES:
        _gap(gaps, 'script_not_reference',
             detail='This dhcpcd-run-hooks is not a reviewed package version, so its hook directory and loop are '
                    'unknown.')
    else:
        reference = REFERENCES[script_sha256]
    hook_dir = reference['hook_dir'] if reference else None
    words = skip_words(nohook, gaps)
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION,
        'reference': ({'script_sha256': script_sha256, 'packages': list(reference['packages']),
                       'script': reference['script'], 'hook_dir': hook_dir} if reference else None),
        'run_as': 'root', 'when': WHEN, 'hooks': [], 'files': [],
        'nohook_words': words, 'nohook_observed': words is not None,
        'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    if hook_dir is not None:
        if hook_dir_state is None:
            _gap(gaps, 'directory_not_observed', hook_dir, 'No listing result was supplied for the hook directory.')
        elif hook_dir_state not in DIR_STATES:
            _gap(gaps, 'input_malformed', hook_dir, 'The hook directory state is not recognized.')
        elif hook_dir_state == 'unreadable':
            _gap(gaps, 'directory_unreadable', hook_dir, 'The hook directory exists but could not be listed.')
    if not isinstance(absent, (list, tuple, set, frozenset)) or not all(
            path in (ENTER_HOOK, EXIT_HOOK) for path in absent):
        _gap(gaps, 'input_malformed', detail='absent may only name the enter and exit hooks.')
        absent = ()
    if not isinstance(files, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='File observations must be a list.')
        files = ()
    if len(files) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'Only the first {MAX_FILES} file observations are assessed.')
        files = files[:MAX_FILES]

    seen: set[str] = set()
    single: dict[str, dict[str, Any]] = {}
    listed: list[tuple[bytes, dict[str, Any]]] = []
    records: list[dict[str, Any]] = []
    for item in files:
        entry = _normalize(item, gaps)
        if entry is None:
            continue
        path = entry['path']
        if path in seen:
            _gap(gaps, 'duplicate_path', path, 'The path was supplied more than once; the first is used.')
            continue
        seen.add(path)
        parent = posixpath.dirname(path)
        if path in (ENTER_HOOK, EXIT_HOOK):
            if path in absent:
                _gap(gaps, 'input_malformed', path, 'The hook was reported both present and absent.')
            status, reason, extra = _outcome(entry, words, gaps)
            record = _record(entry, status, reason, **extra)
            if status == 'sourced':
                single[path] = record
        elif hook_dir is not None and parent == hook_dir:
            name = posixpath.basename(path)
            if hook_dir_state == 'absent':
                _gap(gaps, 'input_malformed', path, 'A file was supplied for a hook directory reported absent.')
            if name.startswith('.'):
                record = _record(entry, 'ignored', 'hidden_name')
            else:
                status, reason, extra = _outcome(entry, words, gaps)
                record = _record(entry, status, reason, **extra)
                if status == 'sourced':
                    listed.append((name.encode('utf-8', 'surrogateescape'), record))
        elif hook_dir is not None and path.startswith(hook_dir + '/'):
            record = _record(entry, 'ignored', 'nested_entry')
        else:
            record = _record(entry, 'ignored', 'not_a_hook_location')
        records.append(record)
    for path in (ENTER_HOOK, EXIT_HOOK):
        if path in absent and path not in seen:
            records.append({'path': path, 'type': None, 'status': 'ignored', 'reason_code': 'absent',
                            'reason': REASONS['absent']})
        elif path not in seen:
            _gap(gaps, 'hook_not_observed', path, 'Neither metadata nor confirmed absence was supplied.')

    ordered = [('enter_hook', single[ENTER_HOOK])] if ENTER_HOOK in single else []
    ordered += [('hook_dir', record) for _, record in sorted(listed, key=lambda pair: pair[0])]
    ordered += [('exit_hook', single[EXIT_HOOK])] if EXIT_HOOK in single else []
    for index, (source, record) in enumerate(ordered):
        record['order'] = index
        hook = {'order': index, 'path': record['path'], 'source': source}
        if record.get('link_target') is not None:
            hook['link_target'] = record['link_target']
        result['hooks'].append(hook)
    result['files'] = records
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
