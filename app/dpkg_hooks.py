"""Pure dpkg configuration contract (roadmap F slice, #970).

Takes captured, read-only observations of ``/etc/dpkg/dpkg.cfg.d`` entries and
``/etc/dpkg/dpkg.cfg`` and returns the options that make dpkg run commands or
change what it checks:

- ``commands``: ``pre-invoke`` and ``post-invoke`` (run through ``sh -c`` before
  and after every package-changing dpkg action, normally as root) and
  ``status-logger`` (a ``sh -c`` command fed dpkg's status output). Every
  occurrence runs: invoke hooks one after another in the order read, status
  loggers side by side. An empty value is reported as ``empty``.
- ``relocations``: ``root``, ``admindir`` and ``instdir``, which move the
  installation root or the package database. Every occurrence is listed in the
  order read; dpkg uses the last one.
- ``behavior_changes``: ``force``/``refuse``/``no-force`` items, ``no-debsig``,
  ``ignore-depends``, ``no-act``/``dry-run``/``simulate``, ``no-triggers`` and
  ``path-exclude``/``path-include``.

Other recognized options are counted in ``other_options`` and not evaluated.

File eligibility, order and line syntax follow dpkg 1.22.6 and were compared
with that binary:

- A ``dpkg.cfg.d`` name is read when it does not start with ``.`` and consists
  of ``[A-Za-z0-9_-]``. Files are read in byte order, then ``dpkg.cfg``. A
  dangling link is skipped silently.
- Trailing whitespace is removed from a line. An empty line or one starting
  with ``#`` is skipped; leading whitespace is not allowed.
- The option name is the leading run of ``[A-Za-z0-9-]``. The next character,
  whatever it is, ends the name; one following ``=`` and leading whitespace are
  skipped, and a value starting with ``"`` or ``'`` must end with the same
  quote, which is removed. Names are case-sensitive long option names.
- ``force-<things>``, ``refuse-<things>`` and ``no-force-<things>`` are accepted
  without a value; ``force=<things>`` and ``force <things>`` are equivalent.
- dpkg refuses to run at all on an unknown option, a missing or unexpected
  value, unbalanced quotes, an unknown force item, an invalid ``verify-format``,
  ``ignore-depends``, ``abort-after``, ``status-fd`` or ``debug`` value, or an
  action option (such as ``configure``) in a configuration file.

It performs no I/O, runs nothing and never authorizes a response action.
Fail-closed rules:

- A line dpkg would reject is a ``config_error`` gap and makes the result
  ``undetermined``. Later lines and files are still parsed so their commands
  stay visible.
- A line longer than dpkg's 1022-byte buffer (dpkg splits it), a NUL byte, a
  non-ASCII character directly after an option name, an unreadable, oversized
  or uncollected file, a non-regular entry and over-cap input are gaps that
  make the result ``undetermined``.
- ``~/.dpkg.cfg`` of the invoking user (read last) and the options and
  environment of a particular dpkg run (for example APT's ``DPkg::Options``)
  cannot be observed and are always disclosed. dpkg sorts ``dpkg.cfg.d`` with
  the invoking locale's collation; byte order is reported and the assumption
  is disclosed when more than one file is read.
- The option table is dpkg 1.22.6's. An option another dpkg version accepts is
  reported as a ``config_error``; the result is never a safety verdict.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
PARTS_DIR = '/etc/dpkg/dpkg.cfg.d'
MAIN_FILE = '/etc/dpkg/dpkg.cfg'
MAX_FILES = 512
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 1022  # dpkg reads lines with fgets() into a 1024-byte buffer
MAX_NAME = 255
MAX_ENTRIES = 512
MAX_GAPS = 256
NOT_A_VERDICT = ('This lists dpkg configuration that runs commands or changes checks. '
                 'It is not a safety verdict and authorizes no response action.')

_FILE_NAME = re.compile(r'[A-Za-z0-9_-]+')
_OPTION_NAME = re.compile(r'[A-Za-z0-9-]*')
_SPACE = ' \t\n\v\f\r'

COMMAND_OPTIONS = ('pre-invoke', 'post-invoke', 'status-logger')
RELOCATION_OPTIONS = ('root', 'admindir', 'instdir')
# Options that take a value / take none, from dpkg 1.22.6.
VALUE_OPTIONS = frozenset((*COMMAND_OPTIONS, *RELOCATION_OPTIONS, 'abort-after', 'debug', 'force', 'refuse',
                           'no-force', 'ignore-depends', 'log', 'path-exclude', 'path-include', 'status-fd',
                           'verify-format'))
FLAG_OPTIONS = frozenset(('auto-deconfigure', 'dry-run', 'no-act', 'no-also-select', 'no-debsig', 'no-pager',
                          'no-triggers', 'pending', 'recursive', 'robot', 'selected-only', 'simulate',
                          'skip-same-version', 'triggers'))
ACTION_OPTIONS = frozenset((
    'add-architecture', 'audit', 'build', 'clear-avail', 'clear-selections', 'compare-versions', 'configure',
    'contents', 'control', 'ctrl-tarfile', 'extract', 'field', 'forget-old-unavail', 'fsys-tarfile',
    'get-selections', 'help', 'info', 'install', 'list', 'listfiles', 'merge-avail', 'predep-package',
    'print-architecture', 'print-avail', 'print-foreign-architectures', 'purge', 'record-avail', 'remove',
    'remove-architecture', 'search', 'set-selections', 'status', 'triggers-only', 'unpack', 'update-avail',
    'validate-archname', 'validate-pkgname', 'validate-trigname', 'validate-version', 'verify', 'version',
    'vextract', 'yet-to-unpack'))
# Options accepted as ``<name>-<value>`` with no separate value. ``assert-<feature>`` is an action.
PREFIX_OPTIONS = ('force', 'refuse', 'no-force', 'assert')
FORCE_THINGS = frozenset((
    'all', 'security-mac', 'downgrade', 'configure-any', 'hold', 'not-root', 'bad-path', 'bad-verify',
    'bad-version', 'statoverride-add', 'statoverride-remove', 'overwrite', 'overwrite-diverted', 'overwrite-dir',
    'unsafe-io', 'script-chrootless', 'confnew', 'confold', 'confdef', 'confmiss', 'confask', 'architecture',
    'breaks', 'conflicts', 'depends', 'depends-version', 'remove-reinstreq', 'remove-protected',
    'remove-essential'))
_PACKAGE_SPEC = re.compile(r'[A-Za-z0-9][A-Za-z0-9+._-]*(:[A-Za-z0-9][A-Za-z0-9-]*)?')
# Values dpkg validates while reading the option; anything else makes dpkg fail. These are
# deliberately narrower than dpkg where dpkg's own rule is loose (it also accepts ``0x10`` and rejects ``08`` as bad octal).
_VALUE_RULES = {
    'verify-format': lambda v: v == 'rpm',
    'abort-after': lambda v: re.fullmatch(r'0|[1-9][0-9]{0,8}', v) is not None,
    'status-fd': lambda v: re.fullmatch(r'0|[1-9][0-9]{0,8}', v) is not None,
    'debug': lambda v: re.fullmatch(r'[0-7]{1,9}', v) is not None,
    'ignore-depends': lambda v: v == '' or all(_PACKAGE_SPEC.fullmatch(item) for item in v.split(',')),
}
_BEHAVIOR_KIND = {'no-debsig': 'no_debsig', 'ignore-depends': 'ignore_depends', 'no-act': 'no_act',
                  'dry-run': 'no_act', 'simulate': 'no_act', 'no-triggers': 'no_triggers',
                  'path-exclude': 'path_filter', 'path-include': 'path_filter'}


def _gap(code: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {'code': code, 'detail': detail, **extra}


def eligibility(name: str) -> dict[str, Any]:
    """Whether dpkg reads a ``dpkg.cfg.d`` entry with this name."""
    if name.startswith('.'):
        return {'read': False, 'reason': 'hidden'}
    if not _FILE_NAME.fullmatch(name):
        return {'read': False, 'reason': 'invalid_name'}
    return {'read': True, 'reason': None}


def parse_line(line: str) -> dict[str, Any] | None:
    """Parse one physical line (without its newline) the way dpkg does.

    Returns ``None`` for a skipped line, ``{'error': code, 'detail': text}`` for
    a line dpkg rejects or this contract does not interpret, or
    ``{'option': name, 'value': text | None}`` for an accepted option. Prefix
    forms are normalized: ``force-all`` yields option ``force``, value ``all``.
    """
    if '\x00' in line:
        return {'error': 'nul_byte', 'detail': 'The line contains a NUL byte, which this contract does not interpret.'}
    if len(line.encode('utf-8', 'surrogatepass')) > MAX_LINE_BYTES:
        return {'error': 'line_too_long', 'detail': f'dpkg splits a line longer than {MAX_LINE_BYTES} bytes.'}
    line = line.rstrip(_SPACE)
    if not line or line[0] == '#':
        return None
    name = _OPTION_NAME.match(line).group()
    value: str | None = None
    if len(name) < len(line):
        if ord(line[len(name)]) > 127:
            return {'error': 'non_ascii_separator',
                    'detail': 'A non-ASCII character follows the option name; dpkg splits it mid-character.'}
        value = line[len(name) + 1:]
        value = value.removeprefix('=').lstrip(_SPACE)
        if value[:1] in ('"', "'"):
            if value[-1] != value[0]:
                return {'error': 'config_error', 'detail': f'unbalanced quotes in {name!r}'}
            value = value[1:-1]
    option = name
    if name not in VALUE_OPTIONS and name not in FLAG_OPTIONS and name not in ACTION_OPTIONS:
        prefix = next((p for p in PREFIX_OPTIONS if value is None and name.startswith(p + '-')), None)
        if prefix is None:
            return {'error': 'config_error', 'detail': f'unknown option {name[:64]!r}'}
        option, value = prefix, name[len(prefix) + 1:]
    if option == 'assert' or option in ACTION_OPTIONS:
        if value is not None and option != 'assert':
            return {'error': 'config_error', 'detail': f'{option!r} does not take a value'}
        return {'error': 'config_error',
                'detail': f'{name[:64]!r} is an action; dpkg refuses a run that also names an action'}
    if option in FLAG_OPTIONS:
        if value is not None:
            return {'error': 'config_error', 'detail': f'{option!r} does not take a value'}
        return {'option': option, 'value': None}
    if value is None:
        return {'error': 'config_error', 'detail': f'{option!r} needs a value'}
    if option in ('force', 'refuse', 'no-force'):
        for thing in value.split(','):
            if thing == 'help':
                return {'error': 'config_error', 'detail': 'the force item "help" makes dpkg print help and exit'}
            if thing not in FORCE_THINGS:
                return {'error': 'config_error', 'detail': f'unknown force/refuse option {thing[:64]!r}'}
    if option in _VALUE_RULES and not _VALUE_RULES[option](value):
        return {'error': 'config_error', 'detail': f'invalid value for {option!r}'}
    return {'option': option, 'value': value}


def _content(entry: Any) -> tuple[str | None, str | None]:
    """Return (text, problem) for a captured file observation."""
    content = entry.get('content') if isinstance(entry, dict) else None
    if not isinstance(content, str):
        return None, 'unreadable'
    if len(content.encode('utf-8', 'surrogatepass')) > MAX_FILE_BYTES:
        return None, 'too_large'
    return content, None


def resolve(parts: Any, main: Any = None) -> dict[str, Any]:
    """Resolve dpkg configuration options from captured observations.

    ``parts`` is the list of ``/etc/dpkg/dpkg.cfg.d`` entries, each a dict with
    ``name``, ``type`` (``file`` for a regular file or a link to one,
    ``missing`` for a dangling link, otherwise anything else) and ``content``
    (text, or ``None`` when unreadable). ``None`` means the directory was not
    collected. ``main`` describes ``/etc/dpkg/dpkg.cfg`` as
    ``{'present': bool, 'content': text|None}``; ``None`` means it was not
    collected.
    """
    gaps: list[dict[str, Any]] = [
        _gap('user_config_unobserved',
             'dpkg reads .dpkg.cfg in the invoking user\'s home directory last; it is not observed.'),
        _gap('invocation_unobserved',
             'Options and environment of a particular dpkg run, such as APT\'s DPkg::Options, are not observed.'),
    ]
    undetermined = False
    files: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    relocations: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    other = 0
    total = 0
    entries = 0
    over_cap = False

    def add_gap(code: str, detail: str, **extra: Any) -> None:
        nonlocal undetermined
        undetermined = True
        if len(gaps) < MAX_GAPS:
            gaps.append(_gap(code, detail, **extra))
        elif gaps[-1]['code'] != 'gap_limit':
            gaps.append(_gap('gap_limit', 'Further coverage gaps were omitted.'))

    def read(path: str, text: str) -> str:
        nonlocal other, entries, over_cap
        state = 'parsed'
        lines = text.split('\n')
        if lines and lines[-1] == '':
            lines.pop()
        for number, line in enumerate(lines, 1):
            parsed = parse_line(line)
            if parsed is None:
                continue
            if 'error' in parsed:
                state = 'error'
                add_gap(parsed['error'], 'dpkg rejects this line or this contract does not interpret it.',
                        path=path, line=number, reason=parsed['detail'])
                continue
            option, value = parsed['option'], parsed['value']
            source = {'option': option, 'path': path, 'line': number}
            if option in COMMAND_OPTIONS:
                target, item = commands, {**source, 'command': value, 'empty': not value.strip(_SPACE)}
            elif option in RELOCATION_OPTIONS:
                target, item = relocations, {**source, 'value': value}
            elif option in ('force', 'refuse', 'no-force'):
                target, item = changes, {**source, 'kind': 'force' if option == 'force' else 'refuse',
                                         'things': value.split(',')}
            elif option in _BEHAVIOR_KIND:
                target, item = changes, {**source, 'kind': _BEHAVIOR_KIND[option], 'value': value}
            else:
                other += 1
                continue
            if entries >= MAX_ENTRIES:
                over_cap = True
                continue
            entries += 1
            target.append(item)
        return state

    def load(path: str, entry: Any) -> None:
        nonlocal total
        text, problem = _content(entry)
        if text is not None and total + len(text) > MAX_TOTAL_BYTES:
            text, problem = None, 'total_limit'
        if text is None:
            files.append({'path': path, 'state': problem})
            add_gap('file_' + problem, 'dpkg reads this file, but its contents were not available to the contract.',
                    path=path)
            return
        total += len(text)
        files.append({'path': path, 'state': read(path, text)})

    if parts is None:
        add_gap('parts_not_collected', f'{PARTS_DIR} was not collected.')
    elif not isinstance(parts, list):
        add_gap('invalid_observation', f'The {PARTS_DIR} observation is malformed.')
    else:
        if len(parts) > MAX_FILES:
            add_gap('file_limit', f'Only the first {MAX_FILES} entries were evaluated.')
        candidates = []
        for entry in parts[:MAX_FILES]:
            name = entry.get('name') if isinstance(entry, dict) else None
            if (not isinstance(name, str) or not name or len(name) > MAX_NAME or '/' in name
                    or name in ('.', '..') or any(ord(c) < 32 or ord(c) == 127 for c in name)):
                add_gap('invalid_entry', 'An entry with an invalid name was not evaluated.')
                continue
            candidates.append((name.encode('utf-8', 'surrogatepass'), name, entry))
        read_count = 0
        for _, name, entry in sorted(candidates, key=lambda item: item[0]):
            path = f'{PARTS_DIR}/{name}'
            verdict = eligibility(name)
            if not verdict['read']:
                files.append({'path': path, 'state': 'ignored', 'reason': verdict['reason']})
                continue
            kind = entry.get('type')
            if kind == 'missing':
                files.append({'path': path, 'state': 'ignored', 'reason': 'dangling_link'})
                continue
            if kind != 'file':
                files.append({'path': path, 'state': 'not_regular_file'})
                add_gap('not_regular_file',
                        'dpkg opens this entry as a configuration file; a directory there makes dpkg fail.', path=path)
                continue
            read_count += 1
            load(path, entry)
        if read_count > 1 and len(gaps) < MAX_GAPS:
            # Disclosed only: the set of options is unchanged, so this does not make the result undetermined.
            gaps.append(_gap('collation_order_assumed',
                             f'dpkg sorts {PARTS_DIR} with the invoking locale\'s collation; byte order is reported.'))
    if main is None:
        add_gap('main_not_collected', f'{MAIN_FILE} was not collected.')
    elif not isinstance(main, dict) or not isinstance(main.get('present'), bool):
        add_gap('invalid_observation', f'The {MAIN_FILE} observation is malformed.')
    elif main['present']:
        load(MAIN_FILE, main)
    if over_cap:
        add_gap('entry_limit', f'Only the first {MAX_ENTRIES} reported options are listed.')
    return {
        'contract_version': CONTRACT_VERSION,
        # The two always-present disclosure gaps do not affect the default-environment result.
        'dpkg_behavior': 'undetermined' if undetermined else 'determined',
        'files': files,
        'commands': commands,
        'relocations': relocations,
        'behavior_changes': changes,
        'other_options': other,
        'gaps': gaps,
        'not_a_verdict': NOT_A_VERDICT,
    }
