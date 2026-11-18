"""Pure Python ``site`` startup-hook contract (roadmap F slice, #1144).

Every CPython start without ``-S`` imports :mod:`site`, including root services.
``site`` executes every ``.pth`` line in each processed site directory that starts
with ``import `` or ``import\\t``. It then imports ``sitecustomize``, and
``usercustomize`` when the user site is enabled. This module takes captured,
read-only observations of those directories and the ``.pth`` bytes. It says
which directories ``site`` processes and in what order, which ``.pth`` files it
reads, which lines it executes as code and which it appends to ``sys.path``, and
which observed ``sitecustomize``/``usercustomize`` an import would find first.

Semantics follow Debian CPython 3.11, 3.12 and 3.13 ``Lib/site.py`` (``main``,
``addusersitepackages``, ``getsitepackages``, ``addsitepackages``, ``addsitedir``
and ``addpackage``):

* The user site ``~/.local/lib/python3.X/site-packages`` is processed first, and
  only when the user site is enabled and the path is a directory. The system site
  directories follow, each only when it is a directory:
  ``/usr/local/lib/python3.X/dist-packages``, ``/usr/lib/python3/dist-packages``
  and ``/usr/lib/python3.X/dist-packages``.
* In a directory, only names that end in ``.pth`` (case-sensitive) are read, in
  ``sorted()`` (code point) order. ``open`` follows symlinks, and a directory, a
  dangling symlink or an unreadable file is skipped silently. Names that start
  with ``.`` are skipped only by interpreters that carry gh-113659 (upstream
  3.11.8, 3.12.2 and every 3.13). Debian bookworm's 3.11.2 packages still read
  them, and the observation does not carry the patch level, so on 3.11 and 3.12
  a dot-named ``.pth`` file is ``undetermined`` with a
  ``pth_hidden_name_patch_dependent`` gap and never reported as skipped.
* 3.11 and 3.12 read the file in the locale encoding with universal newlines
  (``\\n``, ``\\r`` and ``\\r\\n``). 3.13 decodes UTF-8 with an optional BOM (and
  falls back to the locale) and splits with ``str.splitlines()``, which also
  splits on form feed, vertical tab and other separators.
* A line starting with ``#`` and a line that is blank after ``strip()`` are
  skipped. A line starting with ``import `` or ``import\\t`` at column 0 is passed
  to ``exec``, so everything after ``;`` runs too. Every other line is
  ``rstrip``-ped, joined to the site directory, normalized and appended to
  ``sys.path`` when it exists and is not already there. The first line that
  raises stops the rest of that file, so every later line is reported as
  ``after_code``.
* Directories added by ``.pth`` path lines are not scanned for further ``.pth``
  files.

It performs no I/O, never runs, imports or decodes code beyond the text it is
given, and never authorizes a response action. Every input that is unknown,
malformed, truncated or over a cap, or whose meaning depends on something that
was not observed (the locale for non-ASCII bytes, an unverified interpreter
version, family or ABI, a zip or namespace candidate), becomes an explicit gap
and never yields a covered result. ``origin`` is always ``not_assessed``: a
result never labels a hook safe.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
FAMILIES = ('debian',)
VERSIONS = ('3.11', '3.12', '3.13')
# Versions whose dot-named .pth handling depends on an unobserved patch level:
# gh-113659 (skip names starting with '.') first shipped in 3.11.8 and 3.12.2.
HIDDEN_PTH_PATCH_DEPENDENT = ('3.11', '3.12')
DIR_STATES = ('present', 'absent', 'unknown')
DIR_KINDS = ('directory', 'other')
ENTRY_KINDS = ('regular', 'directory', 'dangling', 'other')
MODULES = ('sitecustomize', 'usercustomize')
MAX_DIRECTORIES = 256
MAX_ENTRIES = 4096
MAX_ACCOUNTS = 4096
MAX_PTH_BYTES = 1 << 20
MAX_LINES = 10000
MAX_TEXT = 4096
MAX_PATH = 4096
MAX_GAPS = 256
UNOBSERVED = (
    'the script directory or current directory and PYTHONPATH, which precede every site directory in sys.path',
    'interpreter options -S, -s and -I and PYTHONNOUSERSITE; a setuid or setgid start also disables the user site',
    'HOME and PYTHONUSERBASE overrides of the user base; the passwd home is assumed',
    'virtual environments, other interpreters and other Python versions installed on the host',
    'what executed .pth code and customize modules do, including changes to sys.path that affect later imports',
)
_USER = re.compile(r'[A-Za-z0-9_.][A-Za-z0-9_.@-]{0,255}\$?')
_SHA256 = re.compile(r'[0-9a-f]{64}')
_UNIVERSAL_NEWLINES = re.compile(r'\r\n|\r|\n')


class Invalid(ValueError):
    """An observation that cannot be interpreted safely."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps[-1] = {'code': 'gaps_truncated'}


def _abs(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith('/') or len(value) > MAX_PATH or '\0' in value:
        raise Invalid('invalid absolute path')
    return value


def system_site_dirs(version: str) -> tuple[str, ...]:
    """Debian ``getsitepackages()`` for prefix ``/usr`` (platlibdir ``lib``)."""
    return (f'/usr/local/lib/python{version}/dist-packages', '/usr/lib/python3/dist-packages',
            f'/usr/lib/python{version}/dist-packages')


def user_site_dir(home: str, version: str) -> str:
    return posixpath.join(home, '.local', 'lib', f'python{version}', 'site-packages')


def stdlib_path(version: str) -> tuple[str, ...]:
    """The ``sys.path`` entries that precede the site directories, after the
    unobserved script directory and ``PYTHONPATH``."""
    nodot = version.replace('.', '')
    return (f'/usr/lib/python{nodot}.zip', f'/usr/lib/python{version}', f'/usr/lib/python{version}/lib-dynload')


def _entry(value: Any) -> dict[str, Any]:
    allowed = {'name', 'kind', 'content_b64', 'sha256', 'has_init', 'link_target', 'truncated'}
    if not isinstance(value, dict) or not {'name', 'kind'} <= set(value) or not set(value) <= allowed:
        raise Invalid('invalid directory entry')
    name = value['name']
    if not isinstance(name, str) or not name or name in ('.', '..') or '/' in name or '\0' in name \
            or len(name) > 255:
        raise Invalid('invalid entry name')
    kind = value['kind']
    if kind not in ENTRY_KINDS:
        raise Invalid('invalid entry kind')
    content = None
    if 'content_b64' in value:
        if kind != 'regular' or not isinstance(value['content_b64'], str):
            raise Invalid('content supplied for an entry that is not a regular file')
        try:
            content = base64.b64decode(value['content_b64'], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise Invalid('invalid base64 content') from exc
    sha = value.get('sha256')
    if sha is not None and (not isinstance(sha, str) or not _SHA256.fullmatch(sha) or kind != 'regular'):
        raise Invalid('invalid entry hash')
    if content is not None:
        actual = hashlib.sha256(content).hexdigest()
        if sha is not None and sha != actual:
            raise Invalid('content does not match its hash')
        sha = actual
    has_init = value.get('has_init')
    if has_init is not None and (type(has_init) is not bool or kind != 'directory'):
        raise Invalid('invalid has_init')
    truncated = value.get('truncated', False)
    if type(truncated) is not bool or (truncated and content is None):
        raise Invalid('invalid truncated flag')
    target = value.get('link_target')
    if target is not None and (not isinstance(target, str) or len(target) > MAX_PATH or '\0' in target):
        raise Invalid('invalid link target')
    return {'name': name, 'kind': kind, 'content': content, 'sha256': sha, 'has_init': has_init,
            'link_target': target, 'truncated': truncated}


def _directory(path: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or 'state' not in value \
            or not set(value) <= {'state', 'kind', 'complete', 'entries'}:
        raise Invalid('invalid directory observation')
    state = value['state']
    if state not in DIR_STATES:
        raise Invalid('invalid directory state')
    kind = value.get('kind', 'directory' if state == 'present' else None)
    if (state == 'present') != (kind is not None) or (kind is not None and kind not in DIR_KINDS):
        raise Invalid('invalid directory kind')
    entries = value.get('entries', [])
    complete = value.get('complete', state == 'absent')
    if type(complete) is not bool or not isinstance(entries, list):
        raise Invalid('invalid directory listing')
    if (state != 'present' or kind != 'directory') and entries:
        raise Invalid('entries supplied for a path that is not a present directory')
    if len(entries) > MAX_ENTRIES:
        raise Invalid('directory entries over cap')
    parsed: dict[str, dict[str, Any]] = {}
    for raw in entries:
        item = _entry(raw)
        if item['name'] in parsed:
            raise Invalid('duplicate entry name')
        parsed[item['name']] = item
    return {'path': path, 'state': state, 'kind': kind, 'complete': complete, 'entries': parsed}


def _decode(content: bytes, version: str) -> tuple[list[str] | None, str | None]:
    """Return the lines ``addpackage`` iterates, or a gap code."""
    if version == '3.13':
        try:
            text = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            return None, 'pth_not_utf8_locale_fallback'
        return text.splitlines(), None
    if not content.isascii():
        return None, 'pth_non_ascii_locale_dependent'
    text = content.decode('ascii')
    # TextIOWrapper(newline=None) yields lines ending in '\n' after translating
    # '\r\n' and '\r'; the trailing newline does not change any decision below.
    return _UNIVERSAL_NEWLINES.split(text) if text else [], None


def _pth_lines(sitedir: str, entry: dict[str, Any], version: str, gaps: list[dict[str, Any]],
               path: str) -> tuple[str, list[dict[str, Any]]]:
    if entry['content'] is None:
        _gap(gaps, 'pth_content_not_observed', path=path)
        return 'unread', []
    if entry['truncated'] or len(entry['content']) > MAX_PTH_BYTES:
        _gap(gaps, 'pth_content_truncated', path=path, limit=MAX_PTH_BYTES)
        return 'undetermined', []
    lines, error = _decode(entry['content'], version)
    if error:
        _gap(gaps, error, path=path, python_version=version)
        return 'undetermined', []
    if len(lines) > MAX_LINES:
        _gap(gaps, 'pth_lines_over_cap', path=path, limit=MAX_LINES)
        return 'undetermined', []
    out: list[dict[str, Any]] = []
    after_code = False
    for number, line in enumerate(lines, 1):
        if line.startswith('#') or line.strip() == '':
            continue
        text = line[:MAX_TEXT]
        record: dict[str, Any] = {'number': number, 'after_code': after_code,
                                  'text_truncated': len(line) > MAX_TEXT}
        if line.startswith(('import ', 'import\t')):
            record.update(kind='code', text=text)
            after_code = True
        else:
            stripped = line.rstrip()
            record.update(kind='path', text=stripped[:MAX_TEXT],
                          path=posixpath.normpath(posixpath.join(sitedir, stripped)), exists=None,
                          already_in_sys_path=False)
        out.append(record)
    return 'read', out


def _process_sitedir(directory: dict[str, Any], version: str, gaps: list[dict[str, Any]]) -> dict[str, Any]:
    path = directory['path']
    result: dict[str, Any] = {'path': path, 'state': directory['state'], 'processed': None, 'pth_files': [],
                              'origin': 'not_assessed'}
    if directory['state'] == 'unknown':
        _gap(gaps, 'site_dir_not_observed', path=path)
        return result
    if directory['state'] == 'absent' or directory['kind'] != 'directory':
        result['processed'] = False
        return result
    result['processed'] = True
    if not directory['complete']:
        _gap(gaps, 'site_dir_listing_incomplete', path=path)
    hidden_uncertain = version in HIDDEN_PTH_PATCH_DEPENDENT
    for name in sorted(n for n in directory['entries']
                       if n.endswith('.pth') and (hidden_uncertain or not n.startswith('.'))):
        entry = directory['entries'][name]
        full = posixpath.join(path, name)
        record: dict[str, Any] = {'name': name, 'path': full, 'sha256': entry['sha256'],
                                  'link_target': entry['link_target'], 'lines': []}
        if name.startswith('.'):
            # Read by pre-gh-113659 builds such as Debian bookworm's 3.11.2,
            # skipped by later ones; the interpreter patch level is not observed.
            record['status'] = 'undetermined'
            _gap(gaps, 'pth_hidden_name_patch_dependent', path=full, python_version=version)
        elif entry['kind'] == 'regular':
            record['status'], record['lines'] = _pth_lines(path, entry, version, gaps, full)
        elif entry['kind'] == 'other':
            record['status'] = 'undetermined'
            _gap(gaps, 'pth_special_file', path=full)
        else:
            record['status'] = f'skipped_{entry["kind"]}'
        result['pth_files'].append(record)
    return result


def _lookup(directories: dict[str, dict[str, Any]], path: str) -> dict[str, Any]:
    return directories.get(path) or {'path': path, 'state': 'unknown', 'kind': None, 'complete': False,
                                     'entries': {}}


def _search_dir(module: str, directory: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """``FileFinder`` lookup of ``module`` in one ``sys.path`` directory.

    Returns ``('miss'|'hit'|'namespace'|'uncertain', detail)``. A package beats an
    extension, which beats source, which beats sourceless bytecode."""
    path = directory['path']
    if directory['state'] == 'absent':
        return 'miss', None
    if directory['state'] == 'unknown':
        return 'uncertain', {'path': path, 'reason': 'directory_not_observed'}
    if directory['kind'] != 'directory':
        return 'uncertain', {'path': path, 'reason': 'path_entry_not_a_directory'}
    entries = directory['entries']
    package = entries.get(module)
    if package and package['kind'] == 'directory':
        if package['has_init'] is None:
            return 'uncertain', {'path': posixpath.join(path, module), 'reason': 'package_init_not_observed'}
        if package['has_init']:
            return 'hit', {'path': posixpath.join(path, module), 'form': 'package', 'sha256': None}
    for name, entry in entries.items():
        if entry['kind'] in ('regular', 'other', 'dangling') and name.startswith(module + '.') \
                and name.endswith('.so'):
            if entry['kind'] != 'dangling':
                return 'uncertain', {'path': posixpath.join(path, name), 'reason': 'extension_module_candidate'}
    for suffix, form in (('.py', 'source'), ('.pyc', 'bytecode')):
        entry = entries.get(module + suffix)
        if entry and entry['kind'] == 'regular':
            return 'hit', {'path': posixpath.join(path, module + suffix), 'form': form,
                           'sha256': entry['sha256'], 'link_target': entry['link_target']}
        if entry and entry['kind'] == 'other':
            return 'uncertain', {'path': posixpath.join(path, module + suffix), 'reason': 'special_file_candidate'}
    if not directory['complete']:
        return 'uncertain', {'path': path, 'reason': 'directory_listing_incomplete'}
    if package and package['kind'] == 'directory':
        return 'namespace', {'path': posixpath.join(path, module)}
    return 'miss', None


def _resolve_module(module: str, search: list[dict[str, Any]], code_ran: bool) -> dict[str, Any]:
    namespaces = []
    for directory in search:
        if directory['path'].endswith('.zip') and directory['state'] == 'present':
            return {'module': module, 'outcome': 'uncertain', 'path': directory['path'],
                    'reason': 'zip_path_entry_not_inspected'}
        outcome, detail = _search_dir(module, directory)
        if outcome == 'hit':
            reasons = ['pth_code_may_change_sys_path'] if code_ran else []
            return {'module': module, 'outcome': 'imported', **detail, 'origin': 'not_assessed', 'reasons': reasons}
        if outcome == 'uncertain':
            return {'module': module, 'outcome': 'uncertain', **detail}
        if outcome == 'namespace':
            namespaces.append(detail['path'])
    if namespaces:
        return {'module': module, 'outcome': 'uncertain', 'path': namespaces[0], 'reason': 'namespace_package_only'}
    return {'module': module, 'outcome': 'none', 'path': None,
            'reasons': ['pth_code_may_change_sys_path'] if code_ran else []}


def _sys_path(directories: dict[str, dict[str, Any]], processed: list[dict[str, Any]],
              version: str, gaps: list[dict[str, Any]], context: str, report: set[str]) -> list[dict[str, Any]]:
    """The observed ``sys.path`` after ``site`` ran, as directory observations.

    Path-line gaps are reported only for the site directories in ``report``."""
    order: list[str] = list(stdlib_path(version))
    known = set(order)
    for sitedir in processed:
        if not sitedir['processed']:
            continue
        if sitedir['path'] not in known:
            order.append(sitedir['path'])
            known.add(sitedir['path'])
        for pth in sitedir['pth_files']:
            for line in pth['lines']:
                if line['kind'] != 'path':
                    continue
                state = _lookup(directories, line['path'])['state']
                line['exists'] = None if state == 'unknown' else state == 'present'
                if line['path'] in known:
                    line['already_in_sys_path'] = True
                    continue
                if state == 'unknown' and sitedir['path'] in report:
                    _gap(gaps, 'pth_path_not_observed', path=line['path'], context=context)
                if state != 'absent':
                    order.append(line['path'])
                    known.add(line['path'])
    return [_lookup(directories, p) for p in order]


def _code_ran(processed: list[dict[str, Any]]) -> bool:
    return any(line['kind'] == 'code' for d in processed for f in d['pth_files'] for line in f['lines'])


def _executed(processed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{'path': f['path'], 'number': line['number'], 'text': line['text'], 'after_code': line['after_code']}
            for d in processed if d['processed'] for f in d['pth_files'] for line in f['lines']
            if line['kind'] == 'code']


def resolve(observation: Any) -> dict[str, Any]:
    """Resolve which Python ``site`` startup hooks run.

    ``observation`` is ``{'family': 'debian', 'python_version': '3.12', 'directories': {path: dir},
    'accounts': [{'user', 'home'}]}``. A directory is ``{'state': 'present'|'absent'|'unknown',
    'kind': 'directory'|'other', 'complete': bool, 'entries': [entry]}``; an entry is ``{'name',
    'kind': 'regular'|'directory'|'dangling'|'other'`` (after following symlinks), ``'content_b64',
    'sha256', 'has_init', 'link_target', 'truncated'}``. Directories needed by the contract
    and missing from ``directories`` are unknown.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'complete': False, 'family': None,
                              'python_version': None, 'system': None, 'accounts': [],
                              'unobserved': list(UNOBSERVED), 'gaps': gaps}
    try:
        if not isinstance(observation, dict) \
                or not set(observation) <= {'family', 'python_version', 'directories', 'accounts'}:
            raise Invalid('invalid observation')
        family = observation.get('family')
        version = observation.get('python_version')
        raw_dirs = observation.get('directories', {})
        accounts = observation.get('accounts', [])
        if not isinstance(raw_dirs, dict) or not isinstance(accounts, list):
            raise Invalid('directories must be a mapping and accounts a list')
        if len(raw_dirs) > MAX_DIRECTORIES:
            raise Invalid('directories over cap')
        directories = {}
        for path, value in raw_dirs.items():
            path = _abs(path)
            if posixpath.normpath(path) != path:
                raise Invalid('directory path is not normalized')
            directories[path] = _directory(path, value)
    except Invalid as exc:
        _gap(gaps, 'invalid_observation', detail=str(exc))
        return result
    result['family'] = family
    result['python_version'] = version
    if family not in FAMILIES:
        _gap(gaps, 'family_not_supported', family=family if isinstance(family, str) else None)
        return result
    if version not in VERSIONS:
        _gap(gaps, 'python_version_not_supported', python_version=version if isinstance(version, str) else None)
        return result
    system = [_process_sitedir(_lookup(directories, p), version, gaps) for p in system_site_dirs(version)]
    no_user_path = _sys_path(directories, system, version, gaps, 'user_site_disabled',
                             set(system_site_dirs(version)))
    result['system'] = {
        'site_dirs': system,
        'executed_code': _executed(system),
        'user_site_disabled': {'sitecustomize': _resolve_module('sitecustomize', no_user_path, _code_ran(system))},
    }
    if len(accounts) > MAX_ACCOUNTS:
        _gap(gaps, 'accounts_over_cap', limit=MAX_ACCOUNTS)
        accounts = accounts[:MAX_ACCOUNTS]
    seen: set[str] = set()
    for index, raw in enumerate(accounts):
        try:
            if not isinstance(raw, dict) or set(raw) != {'user', 'home'}:
                raise Invalid('invalid account observation')
            if not isinstance(raw['user'], str) or not _USER.fullmatch(raw['user']):
                raise Invalid('invalid user name')
            home = _abs(raw['home'])
            if raw['user'] in seen:
                raise Invalid('duplicate user')
        except Invalid as exc:
            _gap(gaps, 'invalid_account', index=index, detail=str(exc))
            continue
        seen.add(raw['user'])
        account_gaps: list[dict[str, Any]] = []
        user_dir = _process_sitedir(_lookup(directories, posixpath.normpath(user_site_dir(home, version))),
                                    version, account_gaps)
        processed = [user_dir] + [dict(d, pth_files=[dict(f, lines=[dict(x) for x in f['lines']])
                                                     for f in d['pth_files']]) for d in system]
        search = _sys_path(directories, processed, version, account_gaps, raw['user'], {user_dir['path']})
        code_ran = _code_ran(processed)
        result['accounts'].append({
            'user': raw['user'], 'home': home, 'user_site': user_dir,
            'executed_code': _executed([user_dir]) + result['system']['executed_code'],
            'sitecustomize': _resolve_module('sitecustomize', search, code_ran),
            'usercustomize': _resolve_module('usercustomize', search, code_ran),
            'gaps': account_gaps,
        })
        for gap in account_gaps:
            _gap(gaps, gap['code'], user=raw['user'], **{k: v for k, v in gap.items() if k != 'code'})
    for resolution in [result['system']['user_site_disabled']['sitecustomize']] + [
            a[m] for a in result['accounts'] for m in MODULES]:
        if resolution['outcome'] == 'uncertain':
            _gap(gaps, 'customize_module_unresolved', module=resolution['module'], path=resolution['path'],
                 reason=resolution['reason'])
    result['complete'] = not gaps
    return result
