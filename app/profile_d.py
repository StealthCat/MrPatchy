"""Pure /etc/profile.d login-shell contract (roadmap F slice, #1049).

Takes captured, read-only ``/etc/profile`` text and metadata for the entries of
``/etc/profile.d`` and says which files a Debian/Ubuntu login shell sources
through the base-files ``/etc/profile`` loop, in what order, as root and as
other accounts. It never reads a sourced file's contents.

Semantics were checked against Ubuntu 24.04 (base-files ``/etc/profile``,
dash 0.5.12 and bash 5.2), as root and as ``nobody``, not recalled. The default
loop is::

    if [ -d /etc/profile.d ]; then
      for i in /etc/profile.d/*.sh; do
        if [ -r $i ]; then
          . $i
        fi
      done
      unset i
    fi

* Login ``sh``/``bash``/``dash`` shells read ``/etc/profile``. It sources the
  files that match ``*.sh``. A glob never matches a leading dot. The account
  logging in sources the files, so a root login runs them as root.
* ``[ -r $i ]`` uses access(2). Root reads every existing file, even with mode
  0000. Other accounts need the read bit of their owner, group or other class.
  Symlinks are followed, and a dangling link is skipped.
* A directory named ``*.sh`` passes ``-r``. Sourcing it fails without stopping
  later files. bash prints "is a directory", and dash fails silently.
* ``$i`` is unquoted. A name containing whitespace or glob characters is
  word-split or re-globbed. A crafted name such as ``a -o b.sh`` can make the
  test true and source a different path. bash may run the loop with extglob
  enabled (Ubuntu's ``bash_completion.sh`` sets it), so ``@(…)``, ``+(…)`` and
  ``!(…)`` also re-glob. Such names are reported as ``unknown`` with a
  blocking gap.
* dash and the C locale expand the glob in byte order. bash uses the login
  locale's collation, which can differ for punctuation, case or one name that
  is a prefix of another. Such sets get a non-blocking gap.

It performs no I/O, never runs a command and never authorizes a response
action. Missing or malformed metadata, an unobserved directory, profile or
family, a modified loop, a truncated listing and over-limit input are explicit
blocking gaps and are never reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'profile': 'Debian/Ubuntu base-files /etc/profile', 'shells': 'dash 0.5.12, bash 5.2 (Ubuntu 24.04)'}
PROFILE = '/etc/profile'
PROFILE_D = '/etc/profile.d'
DEFAULT_LOOP = (
    'if [ -d /etc/profile.d ]; then',
    '  for i in /etc/profile.d/*.sh; do',
    '    if [ -r $i ]; then',
    '      . $i',
    '    fi',
    '  done',
    '  unset i',
    'fi',
)
KNOWN_FAMILIES = frozenset({'debian', 'rpm'})
MAX_ENTRIES = 1024
MAX_NAME_BYTES = 255
MAX_PROFILE_BYTES = 64 * 1024
MAX_ID = 2 ** 32 - 1
MAX_GAPS = 64
FILE_TYPES = ('file', 'directory', 'symlink', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
PROFILE_STATES = ('read', 'absent', 'unreadable')
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'duplicate_name', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'family_not_observed',
    'family_unsupported', 'family_not_modelled', 'profile_not_observed', 'profile_unreadable',
    'profile_too_large', 'profile_loop_modified', 'unquoted_expansion', 'special_file', 'gaps_truncated',
})
UNOBSERVED = (
    'File contents, and anything a sourced file runs or sources in turn, are not read.',
    'Other /etc/profile content, /etc/bash.bashrc and per-user dotfiles are not interpreted; content before the '
    'loop that exits, returns or redefines commands is not detected.',
    'Which accounts have login shells, their supplementary groups and the login locale are not observed.',
    'POSIX ACLs, security modules and the search permission of /etc/profile.d for non-root accounts are not '
    'assessed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'sourced': 'The /etc/profile loop sources this file in every login shell that may read it.',
    'name_not_matched': 'The name does not match /etc/profile.d/*.sh (it lacks the .sh suffix or starts with a '
                        'dot), so the loop ignores it.',
    'directory': 'A directory passes the -r test, but sourcing it fails; later files still run.',
    'target_missing': 'The symlink does not resolve, so the -r test fails and it is skipped.',
    'not_readable': 'No account in this class may read the file, so the -r test fails and it is skipped.',
    'depends_on_account': 'Only some non-root accounts may read the file (owner or group class), so whether '
                          'it is sourced depends on the account.',
    'unquoted_expansion': 'The unquoted $i word-splits or re-globs this name, so what the loop tests and sources '
                          'is not the file itself.',
    'special_file': 'Not a regular file or directory; sourcing it reads from a device, FIFO or socket.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
# ``*``, ``?`` and ``[`` glob by default; ``@(``, ``+(`` and ``!(`` glob once an earlier script
# (Ubuntu's bash_completion.sh, for example) enables bash extglob.
_UNSAFE = re.compile(r'[\s*?\[]|[+@!]\(')
_ORDER_SAFE = re.compile(r'[a-z0-9]+')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


def _gap(gaps: list[dict[str, Any]], code: str, name: str | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code}
    if name is not None:
        gap['path'] = f'{PROFILE_D}/{name}'
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def name_matched(name: str) -> bool:
    """Return whether the shell glob ``/etc/profile.d/*.sh`` matches this entry name."""
    return not name.startswith('.') and name.endswith('.sh')


def _sort_key(name: str) -> bytes:
    return name.encode('utf-8', 'surrogateescape')


def _valid_name(name: Any) -> bool:
    if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\x00' in name:
        return False
    try:
        return len(_sort_key(name)) <= MAX_NAME_BYTES
    except UnicodeEncodeError:
        return False


def _int(value: Any, upper: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= upper


def _stat(meta: Any) -> dict[str, Any] | None:
    """Validate one followed-stat mapping: ``type`` and, for a file, ``mode``, ``uid`` and ``gid``."""
    if not isinstance(meta, dict) or meta.get('type') not in ('file', 'directory', 'other'):
        return None
    if meta['type'] == 'file' and not (_int(meta.get('mode'), 0o7777) and _int(meta.get('uid'), MAX_ID)
                                       and _int(meta.get('gid'), MAX_ID)):
        return None
    return {'type': meta['type'], 'mode': meta.get('mode'), 'uid': meta.get('uid'), 'gid': meta.get('gid')}


def other_accounts_readable(mode: int, uid: int) -> str:
    """Return ``all``, ``none`` or ``some``: which non-root accounts pass ``access(R_OK)``.

    A non-root account is checked against exactly one class: owner when it owns the file, group
    when the file's group is one of its groups, and other otherwise. The owner class applies to a
    non-root account only when the owner is not root.
    """
    classes = [bool(mode & 0o040), bool(mode & 0o004)]
    if uid != 0:
        classes.append(bool(mode & 0o400))
    if all(classes):
        return 'all'
    if not any(classes):
        return 'none'
    return 'some'


def _assess(entry: dict[str, Any], gaps: list[dict[str, Any]]) -> tuple[str, str]:
    """Return ``(root_code, other_code)`` for one matched, normalized entry."""
    name = entry['name']
    if _UNSAFE.search(name):
        _gap(gaps, 'unquoted_expansion', name, 'The name contains whitespace, glob characters or an extglob group, which the '
                                               'unquoted $i in /etc/profile splits or expands.')
        return 'unquoted_expansion', 'unquoted_expansion'
    if entry['type'] == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', name, 'What the symlink resolves to was not supplied.')
            return 'unresolved', 'unresolved'
        if entry['target'] is None:
            return 'target_missing', 'target_missing'
        stat = entry['target']
    else:
        stat = entry
    if stat['type'] == 'directory':
        return 'directory', 'directory'
    if stat['type'] != 'file':
        _gap(gaps, 'special_file', name, 'Sourcing a device, FIFO or socket can block or read untracked input.')
        return 'special_file', 'special_file'
    readable = other_accounts_readable(stat['mode'], stat['uid'])
    other = {'all': 'sourced', 'none': 'not_readable', 'some': 'depends_on_account'}[readable]
    return 'sourced', other


def _normalize(item: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_name(item.get('name')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', detail='An entry observation has no valid name or type.')
        return None
    entry: dict[str, Any] = {'name': item['name'], 'type': item['type'], 'resolved': True}
    if item['type'] == 'symlink':
        link = item.get('link_target')
        if isinstance(link, str) and link and len(link) <= 4096 and not _CONTROL.search(link):
            entry['link_target'] = link
        if 'target' in item:
            if item['target'] is None:
                entry['target'] = None
            else:
                target = _stat(item['target'])
                if target is None:
                    entry['resolved'] = False
                else:
                    entry['target'] = target
        return entry
    if item['type'] == 'file':
        stat = _stat(item)
        if stat is None:
            entry['resolved'] = False
            return entry
        entry.update(mode=stat['mode'], uid=stat['uid'], gid=stat['gid'])
    return entry


def _directory(directory: Any, entries_supplied: bool, gaps: list[dict[str, Any]]) -> str | None:
    if directory is None:
        _gap(gaps, 'directory_not_observed', detail=f'No listing result was supplied for {PROFILE_D}.')
        return None
    state = directory.get('state') if isinstance(directory, dict) else None
    complete = directory.get('complete') if isinstance(directory, dict) else None
    if state not in DIRECTORY_STATES or (state == 'listed' and not isinstance(complete, bool)) \
            or (complete is not None and not isinstance(complete, bool)):
        _gap(gaps, 'input_malformed', detail='The directory observation is malformed.')
        return None
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', detail=f'{PROFILE_D} exists but could not be listed.')
    elif state == 'listed' and not complete:
        _gap(gaps, 'listing_incomplete', detail=f'The listing of {PROFILE_D} did not finish.')
    elif state in ('absent', 'not_directory') and entries_supplied:
        _gap(gaps, 'input_malformed', detail='Entries were supplied for a directory reported absent.')
    return state


def loop_present(text: str) -> bool:
    """Return whether ``text`` contains the default base-files loop exactly once, unindented."""
    lines = [line.rstrip() for line in text.split('\n')]
    size = len(DEFAULT_LOOP)
    hits = sum(1 for start in range(len(lines) - size + 1) if tuple(lines[start:start + size]) == DEFAULT_LOOP)
    mentions = sum(1 for line in lines if PROFILE_D in line and not line.lstrip().startswith('#'))
    return hits == 1 and mentions == 2


def _activation(family: Any, profile: Any, gaps: list[dict[str, Any]]) -> dict[str, Any]:
    if family is None:
        _gap(gaps, 'family_not_observed', detail='The OS family was not supplied, so the /etc/profile loop is unknown.')
        return {'state': 'unknown'}
    if family not in KNOWN_FAMILIES:
        _gap(gaps, 'family_unsupported', detail='Only Debian-family and RPM-family systems are recognized.')
        return {'state': 'unknown'}
    if family != 'debian':
        _gap(gaps, 'family_not_modelled', detail='The RPM-family /etc/profile loop (which also sources sh.local '
                                                 'and quotes its variable) is not modelled yet.')
        return {'state': 'unknown'}
    if profile is None:
        _gap(gaps, 'profile_not_observed', detail=f'{PROFILE} was not supplied.')
        return {'state': 'unknown'}
    state = profile.get('state') if isinstance(profile, dict) else None
    text = profile.get('text') if isinstance(profile, dict) else None
    if state not in PROFILE_STATES or (state == 'read') != isinstance(text, str):
        _gap(gaps, 'input_malformed', detail=f'The {PROFILE} observation is malformed.')
        return {'state': 'unknown'}
    if state == 'absent':
        return {'state': 'inactive', 'detail': f'{PROFILE} does not exist, so login shells source nothing from '
                                               f'{PROFILE_D} through it.'}
    if state == 'unreadable':
        _gap(gaps, 'profile_unreadable', detail=f'{PROFILE} exists but could not be read.')
        return {'state': 'unknown'}
    if len(text.encode('utf-8', 'surrogateescape')) > MAX_PROFILE_BYTES:
        _gap(gaps, 'profile_too_large', detail=f'{PROFILE} is larger than {MAX_PROFILE_BYTES} bytes.')
        return {'state': 'unknown'}
    if not loop_present(text):
        _gap(gaps, 'profile_loop_modified', detail=f'{PROFILE} does not contain the default {PROFILE_D} loop '
                                                   'exactly once, so which files it sources is not modelled.')
        return {'state': 'unknown'}
    return {'state': 'active', 'detail': f'{PROFILE} contains the default {PROFILE_D} loop.'}


def _collation_sensitive(names: list[str]) -> bool:
    stems = [name[:-3] for name in names]
    if any(not _ORDER_SAFE.fullmatch(stem) for stem in stems):
        return True
    ordered = sorted(stems)
    return any(ordered[i + 1].startswith(ordered[i]) for i in range(len(ordered) - 1))


def evaluate(entries: Any, *, family: Any = None, directory: Any = None, profile: Any = None) -> dict[str, Any]:
    """Resolve which ``/etc/profile.d`` files Debian login shells source from supplied metadata.

    ``entries`` is a list of mappings with ``name`` (one directory entry name) and ``type``
    (``file``, ``directory``, ``symlink`` or ``other`` for FIFOs, sockets and devices), as
    ``lstat`` reports it. A ``file`` carries ``mode`` (permission bits, 0–0o7777), ``uid`` and
    ``gid``. A ``symlink`` carries ``target``: what ``stat`` reports after following it (``type``,
    and ``mode``/``uid``/``gid`` for a file), or ``None`` when ``stat`` fails. ``link_target`` is
    optional and informational. ``directory`` is ``{'state', 'complete'}`` with state ``listed``,
    ``absent``, ``not_directory`` or ``unreadable``. ``profile`` is ``{'state', 'text'}`` with
    state ``read`` (and the file's text), ``absent`` or ``unreadable``. ``family`` is ``debian``
    or ``rpm``.

    ``scripts`` lists the files a root login sources, in byte order, each with ``other_accounts``
    (``sourced``, ``not_readable`` or ``depends_on_account``). They describe what the default loop
    does; consumers must read ``activation['state']`` (``active``, ``inactive`` or ``unknown``) to
    know whether this host's ``/etc/profile`` runs it.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'profile': PROFILE,
        'directory': PROFILE_D, 'loop': list(DEFAULT_LOOP), 'runs_as': 'logging-in account', 'order': 'byte',
        'activation': {}, 'entries': [], 'scripts': [], 'gaps': gaps, 'unobserved': list(UNOBSERVED),
        'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    result['activation'] = _activation(family, profile, gaps)
    if not isinstance(entries, (list, tuple)):
        _gap(gaps, 'input_malformed', detail='Entry observations must be a list.')
        entries = ()
    state = _directory(directory, bool(entries), gaps)
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', detail=f'Only the first {MAX_ENTRIES} entries are assessed.')
        entries = entries[:MAX_ENTRIES]

    seen: set[str] = set()
    records = []
    sourced = []
    for item in entries:
        entry = _normalize(item, gaps)
        if entry is None:
            continue
        name = entry['name']
        if name in seen:
            _gap(gaps, 'duplicate_name', name, 'The name was supplied more than once; the first is used.')
            continue
        seen.add(name)
        if not name_matched(name):
            root_code = other_code = 'name_not_matched'
        elif not entry['resolved']:
            _gap(gaps, 'metadata_missing', name, 'Required metadata for this entry was not supplied or is malformed.')
            root_code = other_code = 'unresolved'
        else:
            root_code, other_code = _assess(entry, gaps)
        record = {'name': name, 'path': f'{PROFILE_D}/{name}', 'type': entry['type'],
                  'root': _status(root_code), 'root_reason_code': root_code, 'root_reason': REASONS[root_code],
                  'other_accounts': _status(other_code), 'other_reason_code': other_code,
                  'other_reason': REASONS[other_code]}
        if entry.get('link_target') is not None:
            record['link_target'] = entry['link_target']
        records.append(record)
        if record['root'] == 'sourced':
            sourced.append(record)
    if state != 'listed':
        for record in records:
            if record['root'] != 'skipped' or record['other_accounts'] != 'skipped':
                record.update(root='unresolved', root_reason_code='unresolved', root_reason=REASONS['unresolved'],
                              other_accounts='unresolved', other_reason_code='unresolved',
                              other_reason=REASONS['unresolved'])
        sourced = []
    ordered = sorted(sourced, key=lambda rec: _sort_key(rec['name']))
    if len(ordered) > 1 and _collation_sensitive([rec['name'] for rec in ordered]):
        _gap(gaps, 'order_locale_dependent', detail='bash expands the glob in the login locale\'s collation, '
                                                    'which can order these names differently from byte order.')
    for index, record in enumerate(ordered):
        record['order'] = index
        script = {'order': index, 'name': record['name'], 'path': record['path'],
                  'other_accounts': record['other_accounts']}
        if 'link_target' in record:
            script['link_target'] = record['link_target']
        result['scripts'].append(script)
    result['entries'] = sorted(records, key=lambda rec: _sort_key(rec['name']))
    result['directory_state'] = state
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result


_STATUS = {'sourced': 'sourced', 'depends_on_account': 'depends_on_account', 'unresolved': 'unresolved',
           'unquoted_expansion': 'unknown', 'special_file': 'unknown', 'directory': 'error'}


def _status(code: str) -> str:
    return _STATUS.get(code, 'skipped')
