"""Pure polkit ``rules.d`` load-order contract (roadmap F slice, #1411).

Takes captured, read-only metadata for polkit's two rules directories and says
which ``.rules`` JavaScript files polkitd loads and evaluates, in which order,
and why every other entry is not loaded. It never reads or parses a rule file.

polkit rules decide which privileged actions (systemd unit control, package
installation, udisks mounts, and so on) an unprivileged user may perform
without authenticating, and ``polkit.spawn()`` runs commands as the polkitd
user. A planted rule therefore persists across reboots and is consulted on
every authorization check.

Semantics were read in the polkit sources for 0.120, 121, 122, 123, 124 and 125,
in both the mozjs (``polkitbackendjsauthority.cpp``) and duktape
(``polkitbackendduktapeauthority.c``) backends, plus
``polkit_backend_common_rules_file_name_cmp`` and ``init.js``. They agree on
every rule below:

* polkitd reads exactly two compiled-in directories, in this order:
  ``PACKAGE_SYSCONF_DIR/polkit-1/rules.d`` and
  ``PACKAGE_DATA_DIR/polkit-1/rules.d``. That is ``/etc/polkit-1/rules.d`` and
  ``/usr/share/polkit-1/rules.d`` on Debian, Ubuntu, Fedora and RHEL. There is
  no option or configuration file that changes them.
* A directory that cannot be opened is logged and skipped. The daemon reads it
  as the polkitd user (``User=polkitd`` in ``polkit.service``), not as root.
* ``g_dir_read_name`` returns every entry except ``.`` and ``..``. Only names
  ending in ``.rules`` are kept. Hidden names and backup names are **not**
  skipped, and the entry type is not checked before the file is opened.
* There is **no shadowing**. A file with the same name in both directories is
  loaded twice. All kept paths are sorted by basename with ``strcmp``, and
  equal basenames are ordered by full path, so the ``/etc`` copy comes first.
* Each file is compiled and evaluated in that order. A file that cannot be
  opened or read, does not compile or throws while evaluating is skipped, and
  later files still load.
* ``polkit.addRule`` appends to one list, so rules from earlier files are
  consulted first, and the first rule that returns a result decides.

The contract performs no I/O, never runs a command and never authorizes a
response action. Missing or malformed metadata, an unobserved directory or
version, an unsupported version, file types whose open behavior is not
modelled, and over-limit input are explicit blocking gaps. None of them is ever
reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE_VERSIONS = ('0.120', '121', '122', '123', '124', '125')
MIN_VERSION = 120
MAX_VERSION = 125
JS_BACKEND_VERSION = 106
SUFFIX = '.rules'
DIRECTORIES = ('/etc/polkit-1/rules.d', '/usr/share/polkit-1/rules.d')
MAX_ENTRIES = 1024
MAX_NAME_BYTES = 255
MAX_PATH = 4096
MAX_GAPS = 64
MAX_GIDS = 64
ENTRY_TYPES = ('file', 'directory', 'symlink', 'char_device', 'fifo', 'socket', 'other')
TARGET_TYPES = ('file', 'directory', 'char_device', 'fifo', 'socket', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'duplicate_name', 'metadata_missing', 'symlink_target_unobserved',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'version_not_observed',
    'version_unsupported', 'legacy_pkla_backend', 'reader_identity_unobserved', 'acl_not_modelled',
    'open_behavior_unmodelled', 'gaps_truncated',
})
UNOBSERVED = (
    'Rule contents are not read: what each rule grants, and any polkit.spawn() command, are not assessed.',
    'Whether a file compiles and evaluates without error is not assessed; a failing file is skipped by polkitd.',
    'For a symlinked rules file, search permission on the directories along the link target is not assessed.',
    'Legacy .pkla local-authority files and other authorization backends are not assessed.',
    'A locally rebuilt polkit with different sysconf or data directories is not detected.',
    'Mandatory access control (SELinux, AppArmor) that could stop polkitd reading a file is not assessed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'loaded': 'polkitd reads this file, then compiles and evaluates it in the listed order.',
    'loaded_if_target_reachable': 'polkitd follows this symlink and loads the target, provided it can search '
                                  'every directory along the target path.',
    'not_rules_suffix': 'Only names ending in .rules are loaded.',
    'unresolvable': 'The symlink cannot be resolved, so opening it fails and polkitd skips it.',
    'directory': 'A directory named *.rules cannot be read as a script, so polkitd logs an error and skips it.',
    'empty_device': 'This resolves to a character device such as /dev/null, which reads as an empty script and '
                    'adds no rules.',
    'not_readable': 'The polkitd user cannot read this file, so polkitd logs an error and skips it.',
    'directory_not_readable': 'The polkitd user cannot list this directory, so polkitd skips every file in it.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
OBSERVATIONS = {
    'not_root_owned': 'The rules file is owned by a non-root user, who can change which privileged actions are '
                      'authorized.',
    'group_or_world_writable': 'The rules file is writable by group or other users.',
    'loaded_twice': 'A file with the same name exists in both rules directories. polkit has no shadowing, so '
                    'both are loaded, the /etc copy first.',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_VERSION = re.compile(r'(0\.)?(\d{1,4})(?:$|[^0-9])')


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


def _bytes(text: str) -> bytes:
    return text.encode('utf-8', 'surrogateescape')


def _valid_name(name: Any) -> bool:
    if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\x00' in name:
        return False
    try:
        return len(_bytes(name)) <= MAX_NAME_BYTES
    except UnicodeEncodeError:
        return False


def _int(value: Any, upper: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= upper


def _owner(meta: Any) -> dict[str, Any] | None:
    """Return ``mode``/``uid``/``gid``/``acl`` from a stat mapping, or ``None`` when malformed."""
    if not isinstance(meta, dict):
        return None
    if not (_int(meta.get('mode'), 0o7777) and _int(meta.get('uid'), 2 ** 32) and _int(meta.get('gid'), 2 ** 32)):
        return None
    acl = meta.get('acl', False)
    if not isinstance(acl, bool):
        return None
    return {'mode': meta['mode'], 'uid': meta['uid'], 'gid': meta['gid'], 'acl': acl}


def parse_version(value: Any) -> int | None:
    """Return polkit's release number: ``124`` for ``'124-2ubuntu1'``, ``120`` for ``'0.120'``."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value if 0 < value < 10000 else None
    if isinstance(value, str) and len(value) <= 128:
        match = _VERSION.match(value.strip())
        if match:
            return int(match.group(2))
    return None


def _identity(polkitd_uid: Any, polkitd_gids: Any, gaps: list[dict[str, Any]]) -> tuple[int, frozenset[int]] | None:
    if polkitd_uid is None and polkitd_gids is None:
        _gap(gaps, 'reader_identity_unobserved',
             detail='The polkitd user and groups were not supplied, so which files polkitd can read is unknown.')
        return None
    if not _int(polkitd_uid, 2 ** 32) or not isinstance(polkitd_gids, (list, tuple)) or not polkitd_gids \
            or len(polkitd_gids) > MAX_GIDS or not all(_int(gid, 2 ** 32) for gid in polkitd_gids):
        _gap(gaps, 'input_malformed',
             detail='polkitd_uid must be an integer and polkitd_gids a non-empty list of integer group IDs.')
        return None
    return polkitd_uid, frozenset(polkitd_gids)


def _access(meta: dict[str, Any], bits: int, identity: tuple[int, frozenset[int]] | None) -> bool | None:
    """Return whether the polkitd user has all ``bits`` (``r=4``, ``x=1``) on ``meta`` by mode, or ``None``.

    polkitd runs without CAP_DAC_OVERRIDE, so classic owner/group/other rules apply. A file
    with a POSIX ACL is never decided here.
    """
    if meta['acl']:
        return None
    mode = meta['mode']
    if identity is None:
        # Bits granted to "other" apply to every non-owner, non-group reader. Without an identity
        # the answer is only certain when owner, group and other all grant the bits.
        return True if all(mode >> shift & bits == bits for shift in (0, 3, 6)) else None
    uid, gids = identity
    if uid == 0:
        return True
    if meta['uid'] == uid:
        shift = 6
    elif meta['gid'] in gids:
        shift = 3
    else:
        shift = 0
    return mode >> shift & bits == bits


def _directory(observation: Any, path: str, identity: tuple[int, frozenset[int]] | None,
               gaps: list[dict[str, Any]]) -> tuple[str | None, bool | None, list[Any]]:
    """Return ``(state, polkitd_can_list, entries)`` for one rules directory observation."""
    if observation is None:
        _gap(gaps, 'directory_not_observed', path, f'No listing result was supplied for {path}.')
        return None, None, []
    if not isinstance(observation, dict):
        _gap(gaps, 'input_malformed', path, 'The directory observation is malformed.')
        return None, None, []
    state = observation.get('state')
    complete = observation.get('complete')
    entries = observation.get('entries', [])
    if state not in DIRECTORY_STATES or not isinstance(entries, (list, tuple)) \
            or (state == 'listed' and not isinstance(complete, bool)) \
            or (complete is not None and not isinstance(complete, bool)):
        _gap(gaps, 'input_malformed', path, 'The directory observation is malformed.')
        return None, None, []
    if state in ('absent', 'not_directory'):
        if entries:
            _gap(gaps, 'input_malformed', path, 'Entries were supplied for a directory reported absent.')
        return state, False, []
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', path, f'{path} exists but could not be listed.')
        return state, None, list(entries)
    if not complete:
        _gap(gaps, 'listing_incomplete', path, f'The listing of {path} did not finish.')
    meta = _owner(observation)
    if meta is None:
        _gap(gaps, 'metadata_missing', path, 'The directory mode, uid and gid were not supplied or are malformed.')
        return state, None, list(entries)
    if meta['acl']:
        _gap(gaps, 'acl_not_modelled', path, 'The directory has a POSIX ACL, which this contract does not model.')
    return state, _access(meta, 0o5, identity), list(entries)


def _normalize(item: Any, gaps: list[dict[str, Any]], directory: str) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not _valid_name(item.get('name')) or item.get('type') not in ENTRY_TYPES:
        _gap(gaps, 'input_malformed', directory, 'An entry observation has no valid name or type.')
        return None
    entry: dict[str, Any] = {'name': item['name'], 'type': item['type'], 'resolved': True}
    if item['type'] == 'symlink':
        text = item.get('link_target')
        if isinstance(text, str) and text and len(text) <= MAX_PATH and not _CONTROL.search(text):
            entry['link_target'] = text
        if 'target' in item:
            target = item['target']
            if target is None:
                entry['target'] = None
            elif isinstance(target, dict) and target.get('type') in TARGET_TYPES:
                stat = _owner(target) if target['type'] == 'file' else {'acl': False}
                if stat is None:
                    entry['resolved'] = False
                else:
                    entry['target'] = {'type': target['type'], **stat}
            else:
                entry['resolved'] = False
    elif item['type'] == 'file':
        stat = _owner(item)
        if stat is None:
            entry['resolved'] = False
        else:
            entry.update(stat)
    return entry


def _assess(entry: dict[str, Any], path: str, identity: tuple[int, frozenset[int]] | None,
            gaps: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None]:
    """Return the reason code for one ``*.rules`` entry and the stat of the file polkitd would read."""
    if entry['type'] == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', path, 'What the symlink resolves to was not supplied.')
            return 'unresolved', None
        if entry['target'] is None:
            return 'unresolvable', None
        stat = entry['target']
    else:
        stat = entry
    kind = stat['type']
    if kind == 'directory':
        return 'directory', None
    if kind == 'char_device':
        if entry['type'] == 'symlink' and entry.get('link_target') == '/dev/null':
            return 'empty_device', None
        _gap(gaps, 'open_behavior_unmodelled', path,
             'polkitd would read this character device as a script; what it returns is not modelled.')
        return 'unresolved', None
    if kind != 'file':
        _gap(gaps, 'open_behavior_unmodelled', path,
             f'polkitd would try to open this {kind} as a script (a FIFO can block the daemon); the outcome '
             'is not modelled.')
        return 'unresolved', None
    if stat['acl']:
        _gap(gaps, 'acl_not_modelled', path, 'The file has a POSIX ACL, which this contract does not model.')
        return 'unresolved', None
    readable = _access(stat, 0o4, identity)
    if readable is None:
        return 'unresolved', None
    if not readable:
        return 'not_readable', None
    return ('loaded_if_target_reachable' if entry['type'] == 'symlink' else 'loaded'), stat


def _scan(path: str, observation: Any, identity: tuple[int, frozenset[int]] | None,
          gaps: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    state, can_list, entries = _directory(observation, path, identity, gaps)
    summary: dict[str, Any] = {'path': path, 'state': state, 'polkitd_can_list': can_list}
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', path, f'Only the first {MAX_ENTRIES} entries are assessed.')
        entries = entries[:MAX_ENTRIES]
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    for item in entries:
        entry = _normalize(item, gaps, path)
        if entry is None:
            continue
        name = entry['name']
        entry_path = f'{path}/{name}'
        if name in seen:
            _gap(gaps, 'duplicate_name', entry_path, 'The name was supplied more than once; the first is used.')
            continue
        seen.add(name)
        stat = None
        if not name.endswith(SUFFIX):
            code = 'not_rules_suffix'
        elif state != 'listed' or can_list is None:
            code = 'unresolved'
        elif can_list is False:
            code = 'directory_not_readable'
        elif not entry['resolved']:
            _gap(gaps, 'metadata_missing', entry_path,
                 'Required metadata for this entry was not supplied or is malformed.')
            code = 'unresolved'
        else:
            code, stat = _assess(entry, entry_path, identity, gaps)
        status = {'loaded': 'loaded', 'loaded_if_target_reachable': 'conditional',
                  'unresolved': 'unresolved'}.get(code, 'skipped')
        record: dict[str, Any] = {'name': name, 'path': entry_path, 'directory': path, 'type': entry['type'],
                                  'status': status, 'reason_code': code, 'reason': REASONS[code],
                                  'observations': []}
        if 'link_target' in entry:
            record['link_target'] = entry['link_target']
        if stat is not None:
            if stat['uid'] != 0:
                record['observations'].append({'code': 'not_root_owned', 'uid': stat['uid'],
                                               'detail': OBSERVATIONS['not_root_owned']})
            if stat['mode'] & 0o022:
                record['observations'].append({'code': 'group_or_world_writable', 'mode': f'{stat["mode"]:04o}',
                                               'detail': OBSERVATIONS['group_or_world_writable']})
        records.append(record)
    records.sort(key=lambda rec: _bytes(rec['name']))
    return summary, records


def evaluate(*, polkit_version: Any = None, polkitd_uid: Any = None, polkitd_gids: Any = None,
             etc_rules: Any = None, share_rules: Any = None) -> dict[str, Any]:
    """Resolve which polkit ``.rules`` files polkitd loads, and in which order, from supplied metadata.

    ``polkit_version`` is the installed polkit version (``124``, ``'124-2ubuntu1'`` or ``'0.120-3'``).
    ``polkitd_uid`` and ``polkitd_gids`` are the numeric identity polkitd runs as (the ``polkitd``
    account and all of its groups).

    ``etc_rules`` and ``share_rules`` describe ``/etc/polkit-1/rules.d`` and
    ``/usr/share/polkit-1/rules.d`` as ``{'state', 'complete', 'mode', 'uid', 'gid', 'entries'}``:

    * ``state`` is ``listed``, ``absent``, ``not_directory`` or ``unreadable``. A listed directory
      carries its own ``mode``, ``uid`` and ``gid``, and optionally ``acl: True`` when it has a
      POSIX ACL.
    * Each entry carries ``name`` and ``type`` as ``lstat`` reports it: ``file``, ``directory``,
      ``symlink``, ``char_device``, ``fifo``, ``socket`` or ``other``.
    * A ``file`` carries ``mode`` (0–0o7777), ``uid`` and ``gid``, and optionally ``acl``.
    * A ``symlink`` carries ``target``, which is what ``stat`` reports after following it (same
      fields, with a ``type`` other than ``symlink``), or ``None`` when ``stat`` fails.
      ``link_target`` (the raw link text) is optional.

    ``load_order`` lists the files polkitd evaluates, earliest (highest precedence) first. Each
    loads only if it compiles and evaluates without error.
    """
    gaps: list[dict[str, Any]] = []
    version = None
    if polkit_version is None:
        _gap(gaps, 'version_not_observed', detail='The polkit version was not supplied.')
    else:
        version = parse_version(polkit_version)
        if version is None:
            _gap(gaps, 'input_malformed', detail='The polkit version is malformed.')
        elif version < JS_BACKEND_VERSION:
            _gap(gaps, 'legacy_pkla_backend',
                 detail=f'polkit 0.{version} uses the .pkla local-authority backend, which this contract does not '
                        'model; rules.d files are not read by that version.')
        elif not MIN_VERSION <= version <= MAX_VERSION:
            _gap(gaps, 'version_unsupported',
                 detail=f'polkit {version} is outside the read range 0.{MIN_VERSION}–{MAX_VERSION}.')
    identity = _identity(polkitd_uid, polkitd_gids, gaps)
    directories = []
    records: list[dict[str, Any]] = []
    for path, observation in zip(DIRECTORIES, (etc_rules, share_rules)):
        summary, entries = _scan(path, observation, identity, gaps)
        directories.append(summary)
        records.extend(entries)
    loading = [rec for rec in records if rec['status'] in ('loaded', 'conditional')]
    loading.sort(key=lambda rec: (_bytes(rec['name']), _bytes(rec['path'])))
    names = [rec['name'] for rec in loading]
    load_order = []
    for index, record in enumerate(loading):
        record['load_order'] = index
        if names.count(record['name']) > 1:
            record['observations'].append({'code': 'loaded_twice', 'detail': OBSERVATIONS['loaded_twice']})
        item: dict[str, Any] = {'load_order': index, 'name': record['name'], 'path': record['path'],
                                'status': record['status'],
                                'observations': [obs['code'] for obs in record['observations']]}
        if 'link_target' in record:
            item['link_target'] = record['link_target']
        load_order.append(item)
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference_versions': list(REFERENCE_VERSIONS),
        'polkit_version': version, 'runs_as': 'polkitd', 'directories': directories,
        'load_order': load_order, 'entries': records,
        'precedence': 'Earlier files are consulted first; the first rule that returns a result decides.',
        'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
