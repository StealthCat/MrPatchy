"""Pure fish startup-file contract (roadmap F slice, #1415).

Takes one fish invocation's options, the build's data, sysconf and extra vendor
directories, the ``HOME``/``XDG_*`` environment it starts with, and supplied
directory listings and file observations. It says which ``conf.d`` snippets and
``config.fish`` files the session sources, in which order, and why every other
candidate is skipped or masked. It never reads a file's contents.

Semantics were read in the fish 3.7.0 and 3.7.1 sources (``share/config.fish``,
``src/fish.cpp``, ``src/path.cpp``, ``src/expand.cpp`` and ``src/util.cpp``, which
are identical where it matters) and checked against the Ubuntu fish 3.7.0 package
by a differential over random trees:

* ``read_init`` sources ``<data>/config.fish``, then ``<sysconf>/config.fish``, then
  ``<user config dir>/config.fish``. Each runs only when ``access(R_OK)`` succeeds;
  a readable directory passes that check and ``source`` then fails. ``-N``
  (``--no-config``) and ``-n`` (``--no-execute``) skip all of them. In 3.7 a
  missing data ``config.fish`` does not stop the later two.
* The data ``config.fish`` ends by looping over
  ``$__fish_config_dir/conf.d/*.fish``, ``$__fish_sysconf_dir/conf.d/*.fish`` and
  ``$__fish_vendor_confdirs/*.fish``, in that order (user, then admin, then vendor).
  The first file with each basename wins. The basename is recorded before
  ``test -f $file -a -r $file``, so a directory, a dangling symlink or an
  unreadable file still masks every later file of that name without being sourced.
* The vendor directories are ``<user data dir>/vendor_conf.d``, then each
  ``XDG_DATA_DIRS`` component with one trailing slash removed (only after a
  non-slash) plus ``/fish/vendor_conf.d``, or ``<data>/vendor_conf.d`` when
  ``XDG_DATA_DIRS`` is unset, then the build's extra confdir unless it is already
  listed. An empty component, or an empty ``XDG_DATA_DIRS``, becomes
  ``/fish/vendor_conf.d``. ``FISH_UNIT_TESTS_RUNNING`` (any value) removes them all.
* The user config dir is ``$XDG_CONFIG_HOME/fish`` when that is set and non-empty,
  else ``$HOME/.config/fish``; the user data dir uses ``XDG_DATA_HOME`` and
  ``~/.local/share/fish`` the same way. fish creates them when missing.
* ``*.fish`` matches names ending in ``.fish`` (case-sensitive) that do not start
  with ``.``, whatever their type. Each directory's matches are sorted with
  ``wcsfilecmp_glob``: numeric runs compare as numbers after leading zeros, spaces
  after a number are skipped, other characters compare case-insensitively, and
  logically equal names fall back to code-point order.

It performs no I/O, never runs a command and never authorizes a response action.
Unsupported versions, unobserved environment or listings, relative directories,
incomplete listings, names whose order is not modelled, directories fish would
have to create and over-limit input are explicit blocking gaps, and the result is
never reported complete with any of them.
"""
from __future__ import annotations

import functools
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'shell': 'fish 3.7.0 (Ubuntu package) and the fish 3.7.0/3.7.1 sources'}
SUPPORTED_VERSIONS = ('3.7',)
PATH_MAX = 4096
NAME_MAX = 255
MAX_ENTRIES = 4096
MAX_DIRECTORIES = 64
MAX_DATA_DIRS = 32
MAX_OPTIONS = 64
MAX_GAPS = 32
ENTRY_TYPES = ('file', 'directory', 'dangling', 'other')
FILE_TYPES = ('absent', 'file', 'directory', 'other')
ENV_KEYS = ('HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_DATA_DIRS', 'FISH_UNIT_TESTS_RUNNING')
NO_CONFIG_OPTIONS = frozenset({'-N', '--no-config', '-n', '--no-execute'})
# Options that do not change which startup files are sourced in fish 3.7.
NEUTRAL_OPTIONS = frozenset({
    '-i', '--interactive', '-l', '--login', '-c', '--command', '-C', '--init-command', '-P', '--private',
    '-p', '--profile', '-d', '--debug', '-o', '--debug-output', '-f', '--features',
})
BLOCKING = frozenset({
    'input_malformed', 'version_not_observed', 'version_unsupported', 'options_unverified',
    'environment_not_observed', 'paths_not_observed', 'directory_relative', 'directory_not_observed',
    'directory_would_be_created', 'directory_unset', 'listing_not_observed', 'listing_incomplete', 'file_not_observed',
    'order_not_modelled', 'gaps_truncated',
})
UNOBSERVED = (
    ('File contents are not read. A snippet or config.fish can source other files, change variables, define '
     'event handlers, exec or exit; that is not followed here.'),
    ('Ordering assumes towlower maps ASCII letters as in the C and UTF-8 locales; a Turkish locale, where I '
     'lowers to a dotless i, is not modelled.'),
    'Functions and completions autoloaded later from fish_function_path and fish_complete_path are not covered.',
    'Universal variables (fish_variables) and fish_user_paths are not read.',
    'Search permission on parent directories, POSIX ACLs and security modules are not assessed.',
    'The passwd shell and which programs start fish are not observed.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'sources': 'fish sources this file.',
    'masked': 'An earlier conf.d entry has the same basename, so fish skips this one.',
    'skipped_not_regular': 'Not a regular file (a directory, dangling symlink or special file). It is not sourced, '
                           'but it still masks later files with the same basename.',
    'skipped_unreadable': 'fish cannot read this file. It is not sourced, but it still masks later files with the '
                          'same basename.',
    'absent': 'No file by this name exists; fish skips it silently.',
    'source_fails': 'access(R_OK) succeeds but this is not a regular file, so source reports an error.',
    'not_run': 'fish runs no configuration with -N/--no-config or -n/--no-execute.',
    'no_user_dir': 'Neither XDG_CONFIG_HOME nor HOME is set to a non-empty value, so there is no user config dir.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, detail: str = '') -> None:
    if any(g['code'] == code and g.get('path') == path for g in gaps):
        return
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


def _path(value: Any) -> bool:
    return isinstance(value, str) and len(value) < PATH_MAX and not _CONTROL.search(value)


def _abs(value: Any) -> bool:
    return _path(value) and value.startswith('/')


def _digit(ch: str) -> bool:
    return '0' <= ch <= '9'


def _leading_digits(a: str, i: int, b: str, j: int) -> tuple[int, int, int]:
    while i < len(a) and a[i] == '0':
        i += 1
    while j < len(b) and b[j] == '0':
        j += 1
    ret = 0
    while True:
        ad = i < len(a) and _digit(a[i])
        bd = j < len(b) and _digit(b[j])
        if ad and bd:
            if ret == 0 and a[i] != b[j]:
                ret = 1 if a[i] > b[j] else -1
        else:
            if ad:
                ret = 1
            if bd:
                ret = -1
            break
        i += 1
        j += 1
    while i < len(a) and a[i] == ' ':
        i += 1
    while j < len(b) and b[j] == ' ':
        j += 1
    return ret, i, j


def glob_compare(a: str, b: str) -> int:
    """fish 3.7 ``wcsfilecmp_glob`` for ASCII names without control characters."""
    i = j = 0
    ret = 0
    while i < len(a) and j < len(b):
        if _digit(a[i]) and _digit(b[j]):
            ret, i, j = _leading_digits(a, i, b, j)
            if ret or i == len(a) or j == len(b):
                break
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        al, bl = a[i].lower(), b[j].lower()
        if al != bl:
            ret = -1 if al < bl else 1
            break
        i += 1
        j += 1
    if ret:
        return ret
    if i == len(a):
        if j == len(b):
            return (a > b) - (a < b)
        return -1
    return 1


def glob_matches(name: str) -> bool:
    """Whether ``*.fish`` matches a directory entry name."""
    return name.endswith('.fish') and not name.startswith('.')


def _strip_slash(value: str) -> str:
    # string replace -r '([^/])/$' '$1'
    if len(value) >= 2 and value.endswith('/') and value[-2] != '/':
        return value[:-1]
    return value


def _base_dir(env: dict[str, Any], xdg: str, home_suffix: str) -> str | None:
    if env.get(xdg):
        return env[xdg] + '/fish'
    if env.get('HOME'):
        return env['HOME'] + home_suffix
    return None


def _environment(env: Any, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(env, dict):
        _gap(gaps, 'environment_not_observed', detail='HOME and the XDG variables decide where user files live.')
        return None
    missing = [k for k in ENV_KEYS if k not in env]
    if missing:
        _gap(gaps, 'environment_not_observed', detail='Each of these must be supplied as a string or None for '
                                                      f'unset: {", ".join(missing)}.')
        return None
    if not all(env[k] is None or _path(env[k]) for k in ENV_KEYS):
        _gap(gaps, 'input_malformed', detail='Environment values must be strings without control characters, or '
                                             'None.')
        return None
    return {k: env[k] for k in ENV_KEYS}


def _vendor_dirs(env: dict[str, Any], data_dir: str, extra: str | None, user_data: str | None,
                 gaps: list[dict[str, Any]]) -> list[str]:
    if env['FISH_UNIT_TESTS_RUNNING'] is not None:
        return []
    if env['XDG_DATA_DIRS'] is None:
        xdg = [data_dir]
    else:
        parts = env['XDG_DATA_DIRS'].split(':')
        if len(parts) > MAX_DATA_DIRS:
            _gap(gaps, 'input_malformed', detail=f'XDG_DATA_DIRS has more than {MAX_DATA_DIRS} components.')
            parts = parts[:MAX_DATA_DIRS]
        xdg = [_strip_slash(p) + '/fish' for p in parts]
    dirs = ([user_data + '/vendor_conf.d'] if user_data is not None else []) + [d + '/vendor_conf.d' for d in xdg]
    if extra is not None and extra not in dirs:
        dirs.append(extra)
    return dirs


def _options(options: Any, gaps: list[dict[str, Any]]) -> bool | None:
    """Return whether configuration runs, or None when options are malformed."""
    if not isinstance(options, list) or len(options) > MAX_OPTIONS \
            or not all(isinstance(o, str) and _path(o) for o in options):
        _gap(gaps, 'input_malformed', detail='options must be a list of option names.')
        return None
    runs = True
    for option in options:
        if option in NO_CONFIG_OPTIONS:
            runs = False
        elif option not in NEUTRAL_OPTIONS:
            _gap(gaps, 'options_unverified', detail=f'Option {option!r} is not modelled; it may stop fish '
                                                    'before configuration runs.')
    return runs


def _file(path: str, files: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    item = files.get(path)
    if item is None:
        _gap(gaps, 'file_not_observed', path, 'No followed stat observation was supplied for this path.')
        return None
    if not isinstance(item, dict) or item.get('type') not in FILE_TYPES \
            or (item['type'] != 'absent' and not isinstance(item.get('readable'), bool)):
        _gap(gaps, 'input_malformed', path, 'A file observation needs a type and, when present, readable '
                                            '(access R_OK as the session user).')
        return None
    return item


def _observed(item: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for key in ('uid', 'mode'):
        value = item.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2 ** 32:
            out[key] = value
    return out


def _encoded_length(name: str) -> int:
    """Return the filesystem byte length of ``name``, or 0 if it has no byte form.

    Only lone surrogates U+DC80-U+DCFF are ``surrogateescape`` byte escapes. JSON
    can still decode other lone surrogates (e.g. ``"\\ud800"``), which no
    filename can contain, so they are reported as malformed instead of raising.
    """
    try:
        return len(name.encode('utf-8', 'surrogateescape'))
    except UnicodeEncodeError:
        return 0


def _listing(directory: str, listings: dict[str, Any], gaps: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    item = listings.get(directory)
    if item is None:
        _gap(gaps, 'listing_not_observed', directory, 'No listing was supplied for this conf.d directory.')
        return None
    if not isinstance(item, dict) or item.get('type') not in ('absent', 'unlistable', 'directory'):
        _gap(gaps, 'input_malformed', directory, 'A listing needs type absent, unlistable or directory.')
        return None
    if item['type'] != 'directory':
        return []
    entries = item.get('entries')
    if item.get('complete') is not True:
        _gap(gaps, 'listing_incomplete', directory, 'The listing is not marked complete.')
        return None
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _gap(gaps, 'input_malformed', directory, f'entries must be a list of at most {MAX_ENTRIES} items.')
        return None
    matched: list[dict[str, Any]] = []
    names = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get('name'), str) \
                or not 0 < _encoded_length(entry['name']) <= NAME_MAX \
                or '/' in entry['name'] or _CONTROL.search(entry['name']) or entry['name'] in names \
                or entry.get('type') not in ENTRY_TYPES \
                or (entry['type'] == 'file' and not isinstance(entry.get('readable'), bool)):
            _gap(gaps, 'input_malformed', directory, 'Each entry needs a unique name without "/" or control '
                                                     'characters, a type, and readable for files.')
            return None
        names.add(entry['name'])
        if glob_matches(entry['name']):
            matched.append(entry)
    if len(matched) > 1 and any(not e['name'].isascii() for e in matched):
        _gap(gaps, 'order_not_modelled', directory, 'Non-ASCII names sort by locale-dependent towlower and '
                                                    'byte encoding, which is not modelled.')
        return None
    return sorted(matched, key=functools.cmp_to_key(lambda x, y: glob_compare(x['name'], y['name'])))


def evaluate(payload: Any) -> dict[str, Any]:
    """Resolve which fish startup files run, in order, for one invocation.

    ``payload`` keys: ``version`` (``major.minor[.patch]``), ``options`` (option
    names), ``paths`` (``data_dir``, ``sysconf_dir`` and ``extra_confdir``, the
    build's ``__extra_confdir`` or ``None`` when it has no ``__fish_build_paths.fish``),
    ``environment`` (each of ``HOME``, ``XDG_CONFIG_HOME``, ``XDG_DATA_HOME``,
    ``XDG_DATA_DIRS`` and ``FISH_UNIT_TESTS_RUNNING`` as a string or ``None``),
    ``listings`` keyed by conf.d directory (``{'type': absent|unlistable}`` or
    ``{'type': 'directory', 'complete': True, 'entries': [{'name', 'type':
    file|directory|dangling|other, 'readable', 'uid', 'mode'}]}``, types after
    following symlinks, readable as the session user) and ``files`` keyed by
    ``config.fish`` path (``{'type': absent|file|directory|other, 'readable'}``).
    ``listings`` also needs the user config and user data dirs themselves, which
    fish creates when they are missing.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'shell': 'fish',
                              'config_runs': None, 'directories': None, 'sequence': [], 'runs': [], 'gaps': gaps,
                              'complete': False, 'origin': 'not_assessed', 'unobserved': list(UNOBSERVED),
                              'note': NOT_A_VERDICT}
    if not isinstance(payload, dict):
        _gap(gaps, 'input_malformed', detail='The payload must be an object.')
        return _finish(result)
    version = payload.get('version')
    if version is None:
        _gap(gaps, 'version_not_observed', detail='fish versions differ in glob order and startup handling.')
    elif not isinstance(version, str) or '.'.join(version.split('.')[:2]) not in SUPPORTED_VERSIONS:
        _gap(gaps, 'version_unsupported', detail='Only fish 3.7 is modelled. fish 4.x sorts a number after '
                                                 'skipped spaces differently and refuses all configuration '
                                                 'when the data config.fish is unreadable.')
    config_runs = _options(payload.get('options', []), gaps)
    result['config_runs'] = config_runs
    paths = payload.get('paths')
    if not isinstance(paths, dict) or not _abs(paths.get('data_dir')) or not _abs(paths.get('sysconf_dir')) \
            or 'extra_confdir' not in paths or not (paths['extra_confdir'] is None or _abs(paths['extra_confdir'])):
        _gap(gaps, 'paths_not_observed', detail='The build\'s absolute data_dir and sysconf_dir and its '
                                                'extra_confdir (or None) are required.')
        paths = None
    env = _environment(payload.get('environment'), gaps)
    files = payload.get('files')
    listings = payload.get('listings')
    if not isinstance(files, dict) or not isinstance(listings, dict) or len(listings) > MAX_DIRECTORIES:
        _gap(gaps, 'input_malformed', detail=f'files and listings must be objects; listings has at most '
                                             f'{MAX_DIRECTORIES} directories.')
        return _finish(result)
    if config_runs is False:
        result['sequence'].append({'phase': 'all', 'path': None, 'decision': 'not_run', 'reason': REASONS['not_run']})
        return _finish(result)
    if paths is None or env is None or config_runs is None:
        return _finish(result)
    config_dir = _base_dir(env, 'XDG_CONFIG_HOME', '/.config/fish')
    user_data = _base_dir(env, 'XDG_DATA_HOME', '/.local/share/fish')
    for base, name in ((config_dir, 'XDG_CONFIG_HOME'), (user_data, 'XDG_DATA_HOME')):
        if base is None:
            _gap(gaps, 'directory_unset', detail=f'Neither {name} nor HOME is non-empty; how fish then sets its '
                                                 'directory variables is not modelled.')
            continue
        if not base.startswith('/'):
            _gap(gaps, 'directory_relative', base, 'A relative directory resolves against the unobserved working '
                                                   'directory.')
            return _finish(result)
        observed = listings.get(base)
        if observed is None:
            _gap(gaps, 'directory_not_observed', base, 'fish creates this directory when it is missing; whether '
                                                       'it exists was not supplied.')
        elif not isinstance(observed, dict) or observed.get('type') != 'directory':
            _gap(gaps, 'directory_would_be_created', base, 'fish would create this directory, or fail to, which '
                                                           'is not modelled.')
    vendor = _vendor_dirs(env, paths['data_dir'], paths['extra_confdir'], user_data, gaps)
    conf_dirs = ([config_dir + '/conf.d'] if config_dir is not None else []) \
        + [paths['sysconf_dir'] + '/conf.d'] + vendor
    result['directories'] = {'config': config_dir, 'user_data': user_data, 'conf_d': conf_dirs}
    data_config = _config_entry('data', paths['data_dir'], files, gaps)
    result['sequence'].append(data_config)
    if data_config['decision'] in ('sources', 'unresolved'):
        _conf_d(result, conf_dirs, listings, gaps, data_config['decision'])
    result['sequence'].append(_config_entry('sysconf', paths['sysconf_dir'], files, gaps))
    if config_dir is None:
        result['sequence'].append({'phase': 'user', 'path': None, 'decision': 'no_user_dir',
                                   'reason': REASONS['no_user_dir']})
    else:
        result['sequence'].append(_config_entry('user', config_dir, files, gaps))
    for entry in result['sequence']:
        if entry['decision'] == 'sources':
            result['runs'].append({'phase': entry['phase'], 'path': entry['path'], **entry.get('observed', {})})
    return _finish(result)


def _config_entry(phase: str, directory: str, files: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    path = directory + '/config.fish'
    entry: dict[str, Any] = {'phase': phase, 'path': path}
    item = _file(path, files, gaps)
    if item is None:
        entry['decision'] = 'unresolved'
    elif item['type'] == 'absent' or not item['readable']:
        entry['decision'] = 'absent' if item['type'] == 'absent' else 'skipped_unreadable'
    else:
        entry['decision'] = 'sources' if item['type'] == 'file' else 'source_fails'
        entry['observed'] = _observed(item)
    entry['reason'] = REASONS[entry['decision']]
    return entry


def _conf_d(result: dict[str, Any], conf_dirs: list[str], listings: dict[str, Any], gaps: list[dict[str, Any]],
            data_decision: str) -> None:
    first: dict[str, str] = {}
    unresolved = data_decision != 'sources'
    for directory in conf_dirs:
        matched = _listing(directory, listings, gaps)
        if matched is None:
            # Later masking depends on names this listing would contribute.
            unresolved = True
            result['sequence'].append({'phase': 'conf.d', 'path': directory + '/*.fish', 'decision': 'unresolved',
                                       'reason': REASONS['unresolved']})
            continue
        for item in matched:
            path = f'{directory}/{item["name"]}'
            entry: dict[str, Any] = {'phase': 'conf.d', 'path': path, 'basename': item['name']}
            if unresolved:
                entry['decision'] = 'unresolved'
            elif item['name'] in first:
                entry['decision'] = 'masked'
                entry['masked_by'] = first[item['name']]
            elif item['type'] != 'file':
                entry['decision'] = 'skipped_not_regular'
            elif not item['readable']:
                entry['decision'] = 'skipped_unreadable'
            else:
                entry['decision'] = 'sources'
                entry['observed'] = _observed(item)
            first.setdefault(item['name'], path)
            entry['reason'] = REASONS[entry['decision']]
            result['sequence'].append(entry)


def _finish(result: dict[str, Any]) -> dict[str, Any]:
    result['complete'] = not any(g['code'] in BLOCKING for g in result['gaps']) and bool(result['sequence']) \
        and all(e['decision'] != 'unresolved' for e in result['sequence'])
    return result
