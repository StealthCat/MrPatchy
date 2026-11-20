"""Pure bash-completion compat-directory contract (roadmap F slice, #1197).

Takes the installed bash-completion upstream version, the loader path and
captured, read-only metadata for the entries of its compat directories. It says
which files the loader sources, in what order, as root and as other accounts,
and why every other entry is skipped. It never reads a sourced file's contents.

When an interactive bash shell loads ``/usr/share/bash-completion/bash_completion``
(through ``/etc/profile.d/bash_completion.sh``, ``/etc/bash.bashrc`` or a
user's ``~/.bashrc``), the loader sources every eligible compat file *as the
account that opened the shell*, root included. A dropped file needs no execute
bit. It runs at every interactive login of every such account.

Semantics were read from the upstream ``bash_completion`` script at tags 2.10,
2.11, 2.12.0, 2.13.0, 2.14.0, 2.15.0, 2.16.0 and 2.17.0, not recalled:

* **2.10–2.11** scan one directory, ``${BASH_COMPLETION_COMPAT_DIR:-/etc/bash_completion.d}``::

      for i in "$compat_dir"/*; do
          [[ ${i##*/} != @($_backup_glob|Makefile*|$_blacklist_glob) && -f $i && -r $i ]] && . "$i"
      done

  with ``_backup_glob='@(#*#|*@(~|.@(bak|orig|rej|swp|dpkg*|rpm@(orig|new|save))))'``
  and ``_blacklist_glob='@(acroread.sh)'``. The glob runs with the shell's own
  locale collation and options.
* **2.12–2.14** change ``dpkg*`` to ``@(dpkg|ucf)-*`` and replace the block list
  with ``${BASH_COMPLETION_COMPAT_IGNORE-}`` (empty by default). Unless
  ``BASH_COMPLETION_COMPAT_DIR`` is set, they also scan a second directory
  derived from the loader path: ``<prefix>/etc/bash_completion.d`` when the
  loader lives in ``<prefix>/share/bash-completion``, otherwise
  ``<loader dir>/bash_completion.d``. It is skipped when it equals
  ``/etc/bash_completion.d``. For the packaged loader this is
  ``/usr/etc/bash_completion.d``.
* **2.15–2.16** expand the glob through ``_comp_expand_glob``: ``LC_COLLATE=C``,
  ``nullglob``, no ``dotglob`` and an empty ``GLOBIGNORE``. Order is bytewise
  and hidden names never match.
* **2.17** adds ``zs-old`` to the backup suffixes.

Every expansion is quoted, so names with spaces or glob characters are sourced
as themselves. ``-f`` follows symlinks and accepts only a regular file, so
directories, devices, FIFOs, sockets and dangling links are skipped silently.
``-r`` uses access(2): root reads any regular file, and other accounts use one
owner, group or other class.

It performs no I/O, never runs a command and never authorizes a response
action. Missing or malformed metadata, an unobserved, unreadable or truncated
listing, an unsupported version, an unusable loader path and over-limit input
are explicit blocking gaps and are never reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

from .profile_d import other_accounts_readable

CONTRACT_VERSION = 1
REFERENCE = {'source': 'upstream bash-completion bash_completion script',
             'tags': '2.10, 2.11, 2.12.0, 2.13.0, 2.14.0, 2.15.0, 2.16.0, 2.17.0'}
SYSTEM_DIR = '/etc/bash_completion.d'
DEFAULT_LOADER = '/usr/share/bash-completion/bash_completion'
MAX_DIRECTORIES = 2
MAX_ENTRIES = 1024
MAX_NAME_BYTES = 255
MAX_PATH = 4096
MAX_ID = 2 ** 32 - 1
MAX_GAPS = 64
FILE_TYPES = ('file', 'directory', 'symlink', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
LOADER_STATES = ('present', 'absent')
FAMILIES = {
    # Keyed by the first upstream minor version of each family.
    '2.10': {'second_directory': False, 'legacy_backup': True, 'block_list': ('acroread.sh',),
             'c_order': False, 'zs_old': False},
    '2.12': {'second_directory': True, 'legacy_backup': False, 'block_list': (),
             'c_order': False, 'zs_old': False},
    '2.15': {'second_directory': True, 'legacy_backup': False, 'block_list': (),
             'c_order': True, 'zs_old': False},
    '2.17': {'second_directory': True, 'legacy_backup': False, 'block_list': (),
             'c_order': True, 'zs_old': True},
}
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'duplicate_name', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'loader_not_observed',
    'version_not_observed', 'version_unsupported', 'loader_path_unusable', 'gaps_truncated',
})
UNOBSERVED = (
    'File contents, and anything a sourced file runs or sources in turn, are not read.',
    'Which shells load bash-completion (/etc/profile.d/bash_completion.sh, /etc/bash.bashrc, per-user ~/.bashrc, '
    'progcomp and posix mode) and which accounts open interactive bash shells are not observed.',
    'BASH_COMPLETION_COMPAT_DIR (which replaces every scanned directory) and BASH_COMPLETION_COMPAT_IGNORE '
    '(2.12 and later) are environment overrides and are assumed unset.',
    'Per-user ~/.bash_completion, ${XDG_CONFIG_HOME:-~/.config}/bash_completion and the lazily loaded '
    'completions/ directories are outside this contract.',
    'POSIX ACLs, security modules, supplementary groups and the search permission of each directory for non-root '
    'accounts are not assessed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'sourced': 'The bash-completion loader sources this file in every interactive bash shell that loads it.',
    'hidden': 'The name starts with a dot, so the loader\'s "*" glob does not match it.',
    'backup_name': 'The name matches the loader\'s backup-file pattern, so it is skipped.',
    'makefile': 'The name starts with "Makefile", which the loader skips.',
    'block_listed': 'This bash-completion version skips this exact name (acroread.sh).',
    'not_regular': 'Not a regular file after following symlinks, so the -f test fails and it is skipped.',
    'target_missing': 'The symlink does not resolve, so the -f test fails and it is skipped.',
    'not_readable': 'No account in this class may read the file, so the -r test fails and it is skipped.',
    'depends_on_account': 'Only some non-root accounts may read the file (owner or group class), so whether '
                          'it is sourced depends on the account.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_STATUS = {'sourced': 'sourced', 'depends_on_account': 'depends_on_account', 'unresolved': 'unresolved'}
_VERSION = re.compile(r'(\d{1,4})\.(\d{1,4})(?:\.(\d{1,4}))?')
_ORDER_SAFE = re.compile(r'[a-z0-9]+')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_BACKUP_SUFFIXES = ('bak', 'orig', 'rej', 'swp', 'rpmorig', 'rpmnew', 'rpmsave')


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


def upstream_version(package_version: Any) -> str | None:
    """Return the upstream ``X.Y[.Z]`` from a dpkg/RPM version such as ``1:2.11-8`` or ``2.11-5.el9``."""
    if not isinstance(package_version, str) or len(package_version) > 128:
        return None
    text = package_version.split(':', 1)[1] if re.match(r'\d+:', package_version) else package_version
    text = text.split('-', 1)[0]
    return text if _VERSION.fullmatch(text) else None


def family(version: Any) -> str | None:
    """Return the modelled family (``2.10``, ``2.12``, ``2.15`` or ``2.17``) for an upstream version."""
    match = _VERSION.fullmatch(version) if isinstance(version, str) else None
    if not match or int(match.group(1)) != 2:
        return None
    minor = int(match.group(2))
    if minor in (10, 11):
        return '2.10'
    if 12 <= minor <= 14:
        return '2.12'
    if minor in (15, 16):
        return '2.15'
    if minor == 17:
        return '2.17'
    return None


def backup_name(name: str, version_family: str) -> bool:
    """Whether ``name`` matches the family's ``_backup_glob``/``_comp_backup_glob`` extglob."""
    rules = FAMILIES[version_family]
    if len(name) >= 2 and name.startswith('#') and name.endswith('#'):
        return True
    if name.endswith('~'):
        return True
    suffixes = _BACKUP_SUFFIXES + (('zs-old',) if rules['zs_old'] else ())
    # ``*.@(…)`` needs a dot before the suffix; ``*`` may be empty.
    if any(name.endswith('.' + suffix) for suffix in suffixes):
        return True
    if rules['legacy_backup']:
        return '.dpkg' in name          # *.dpkg*
    return '.dpkg-' in name or '.ucf-' in name   # *.@(dpkg|ucf)-*


def name_skip(name: str, version_family: str) -> str | None:
    """Return the skip code for a directory entry name, or ``None`` when the name is eligible."""
    if name.startswith('.'):
        return 'hidden'
    if backup_name(name, version_family):
        return 'backup_name'
    if name.startswith('Makefile'):
        return 'makefile'
    if name in FAMILIES[version_family]['block_list']:
        return 'block_listed'
    return None


def _loader_path_usable(path: Any) -> bool:
    if not isinstance(path, str) or not path.startswith('/') or len(path) > MAX_PATH or _CONTROL.search(path):
        return False
    parts = path.split('/')[1:]
    return bool(parts) and all(part not in ('', '.', '..') for part in parts)


def compat_directories(version_family: str, loader_path: str) -> list[str]:
    """Return the compat directories the loader scans, in order, with no environment overrides."""
    directories = [SYSTEM_DIR]
    if FAMILIES[version_family]['second_directory']:
        base = loader_path.rsplit('/', 1)[0] or '/'
        if base.endswith('/share/bash-completion'):
            second = base[:-len('/share/bash-completion')] + '/etc/bash_completion.d'
        else:
            second = base.rstrip('/') + '/bash_completion.d'
        if second != directories[0]:
            directories.append(second)
    return directories


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
    if not isinstance(meta, dict) or meta.get('type') not in ('file', 'directory', 'other'):
        return None
    if meta['type'] == 'file' and not (_int(meta.get('mode'), 0o7777) and _int(meta.get('uid'), MAX_ID)
                                       and _int(meta.get('gid'), MAX_ID)):
        return None
    return {'type': meta['type'], 'mode': meta.get('mode'), 'uid': meta.get('uid'), 'gid': meta.get('gid')}


def _normalize(item: Any, directory: str, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_name(item.get('name')) or item.get('type') not in FILE_TYPES:
        _gap(gaps, 'input_malformed', directory, 'An entry observation has no valid name or type.')
        return None
    entry: dict[str, Any] = {'name': item['name'], 'type': item['type'], 'resolved': True}
    if item['type'] == 'symlink':
        link = item.get('link_target')
        if isinstance(link, str) and link and len(link) <= MAX_PATH and not _CONTROL.search(link):
            entry['link_target'] = link
        if 'target' not in item:
            entry['unobserved_target'] = True
        elif item['target'] is None:
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


def _assess(entry: dict[str, Any], path: str, gaps: list[dict[str, Any]]) -> tuple[str, str]:
    """Return ``(root_code, other_code)`` for one name-eligible, normalized entry."""
    if not entry['resolved']:
        _gap(gaps, 'metadata_missing', path, 'Required metadata for this entry was not supplied or is malformed.')
        return 'unresolved', 'unresolved'
    if entry['type'] == 'symlink':
        if entry.get('unobserved_target'):
            _gap(gaps, 'symlink_target_unobserved', path, 'What the symlink resolves to was not supplied.')
            return 'unresolved', 'unresolved'
        if entry['target'] is None:
            return 'target_missing', 'target_missing'
        stat = entry['target']
    else:
        stat = entry
    if stat['type'] != 'file':
        return 'not_regular', 'not_regular'
    readable = other_accounts_readable(stat['mode'], stat['uid'])
    return 'sourced', {'all': 'sourced', 'none': 'not_readable', 'some': 'depends_on_account'}[readable]


def _listing(path: str, observation: Any, gaps: list[dict[str, Any]]) -> tuple[str | None, list[Any]]:
    if observation is None:
        _gap(gaps, 'directory_not_observed', path, f'No listing result was supplied for {path}.')
        return None, []
    state = observation.get('state') if isinstance(observation, dict) else None
    complete = observation.get('complete') if isinstance(observation, dict) else None
    entries = observation.get('entries', []) if isinstance(observation, dict) else None
    if state not in DIRECTORY_STATES or (state == 'listed' and not isinstance(complete, bool)) \
            or (complete is not None and not isinstance(complete, bool)) or not isinstance(entries, (list, tuple)):
        _gap(gaps, 'input_malformed', path, 'The directory observation is malformed.')
        return None, []
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', path, f'{path} exists but could not be listed.')
    elif state == 'listed' and not complete:
        _gap(gaps, 'listing_incomplete', path, f'The listing of {path} did not finish.')
    elif state in ('absent', 'not_directory') and entries:
        _gap(gaps, 'input_malformed', path, 'Entries were supplied for a directory reported absent.')
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', path, f'Only the first {MAX_ENTRIES} entries are assessed.')
        entries = entries[:MAX_ENTRIES]
    return state, list(entries)


def _activation(loader: Any, gaps: list[dict[str, Any]]) -> tuple[dict[str, Any], str | None, str | None]:
    """Return ``(activation, family, loader path)`` from the loader observation."""
    if loader is None:
        _gap(gaps, 'loader_not_observed', detail='Whether bash-completion is installed was not supplied.')
        return {'state': 'unknown'}, None, None
    state = loader.get('state') if isinstance(loader, dict) else None
    if state not in LOADER_STATES:
        _gap(gaps, 'input_malformed', detail='The bash-completion loader observation is malformed.')
        return {'state': 'unknown'}, None, None
    if state == 'absent':
        return ({'state': 'inactive', 'detail': 'bash-completion is not installed, so no compat directory is '
                                                'sourced through it.'}, None, None)
    path = loader.get('path', DEFAULT_LOADER)
    if not _loader_path_usable(path):
        _gap(gaps, 'loader_path_unusable', detail='The loader path must be absolute and normalized, so the '
                                                  'directories it scans are not determined.')
        return {'state': 'unknown'}, None, None
    version = loader.get('version')
    if version is None:
        _gap(gaps, 'version_not_observed', detail='The bash-completion version was not supplied.')
        return {'state': 'unknown'}, None, path
    version_family = family(version)
    if version_family is None:
        _gap(gaps, 'version_unsupported', detail='Only bash-completion 2.10 to 2.17 are modelled.')
        return {'state': 'unknown'}, None, path
    return ({'state': 'active', 'version': version, 'family': version_family, 'loader': path,
             'detail': f'bash-completion {version} sources compat files from {path} in interactive bash shells.'},
            version_family, path)


def evaluate(*, loader: Any = None, directories: Any = None) -> dict[str, Any]:
    """Resolve which compat files the bash-completion loader sources from supplied metadata.

    ``loader`` is ``{'state': 'present'|'absent', 'version': '2.11', 'path': '/usr/share/…'}``;
    ``path`` defaults to ``/usr/share/bash-completion/bash_completion`` and ``version`` is the
    upstream version (see ``upstream_version``). ``directories`` maps each scanned directory path
    (see ``compat_directories``) to ``{'state', 'complete', 'entries'}``: state ``listed``,
    ``absent``, ``not_directory`` or ``unreadable``, and entries shaped as in
    ``profile_d.evaluate`` (``name``, ``type`` and ``mode``/``uid``/``gid`` or a followed
    ``target`` for symlinks).

    ``scripts`` lists, in source order, the files a root shell sources, each with
    ``other_accounts`` (``sourced``, ``skipped`` or ``depends_on_account``); each entry's
    ``other_reason_code`` says why.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE),
        'runs_as': 'account opening an interactive bash shell that loads bash-completion',
        'activation': {}, 'directories': [], 'entries': [], 'scripts': [], 'gaps': gaps,
        'unobserved': list(UNOBSERVED), 'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    activation, version_family, path = _activation(loader, gaps)
    result['activation'] = activation
    if activation['state'] == 'inactive' or version_family is None or path is None:
        result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
        return result
    rules = FAMILIES[version_family]
    if directories is None:
        directories = {}
    if not isinstance(directories, dict):
        _gap(gaps, 'input_malformed', detail='Directory observations must be a mapping of path to listing.')
        directories = {}
    scanned = compat_directories(version_family, path)
    order = 0
    for directory in scanned:
        state, entries = _listing(directory, directories.get(directory), gaps)
        result['directories'].append({'path': directory, 'state': state or 'unobserved'})
        seen: set[str] = set()
        records = []
        for item in entries:
            entry = _normalize(item, directory, gaps)
            if entry is None:
                continue
            name = entry['name']
            entry_path = f'{directory}/{name}'
            if name in seen:
                _gap(gaps, 'duplicate_name', entry_path, 'The name was supplied more than once; the first is used.')
                continue
            seen.add(name)
            skip = name_skip(name, version_family)
            if skip == 'hidden' and not rules['c_order']:
                _gap(gaps, 'hidden_name_dotglob', entry_path, 'This version expands the glob with the shell\'s own '
                                                              'options, so a shell with dotglob set also sources '
                                                              'hidden names.')
            root_code, other_code = (skip, skip) if skip else _assess(entry, entry_path, gaps)
            if state != 'listed':
                root_code = other_code = 'unresolved'
            record = {'directory': directory, 'name': name, 'path': entry_path, 'type': entry['type'],
                      'root': _STATUS.get(root_code, 'skipped'), 'root_reason_code': root_code,
                      'root_reason': REASONS[root_code], 'other_accounts': _STATUS.get(other_code, 'skipped'),
                      'other_reason_code': other_code, 'other_reason': REASONS[other_code]}
            if entry.get('link_target') is not None:
                record['link_target'] = entry['link_target']
            records.append(record)
        records.sort(key=lambda rec: _sort_key(rec['name']))
        sourced = [rec for rec in records if rec['root'] == 'sourced']
        if not rules['c_order'] and len(sourced) > 1 and any(
                not _ORDER_SAFE.fullmatch(rec['name']) for rec in sourced):
            _gap(gaps, 'order_locale_dependent', directory, 'This version expands the glob in the shell\'s locale '
                                                            'collation, which can order these names differently '
                                                            'from byte order.')
        for record in sourced:
            record['order'] = order
            script = {'order': order, 'directory': directory, 'name': record['name'], 'path': record['path'],
                      'other_accounts': record['other_accounts']}
            if 'link_target' in record:
                script['link_target'] = record['link_target']
            result['scripts'].append(script)
            order += 1
        result['entries'].extend(records)
    for extra in sorted(key for key in directories if key not in scanned):
        if isinstance(extra, str) and len(extra) <= MAX_PATH and not _CONTROL.search(extra):
            _gap(gaps, 'directory_not_scanned', extra, 'This bash-completion version does not scan this directory.')
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
