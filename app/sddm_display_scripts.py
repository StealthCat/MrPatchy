"""Pure SDDM display-script contract (roadmap F slice, #1421).

Takes the files SDDM loads its configuration from, the observed ``sddm.service``
``ExecStart`` and the installation state, and says which commands the ``sddm``
daemon runs as root when it starts and stops each X11 display: the
``[X11] DisplayCommand`` setup script, the ``[X11] DisplayStopCommand`` stop script
and the X server itself. It never runs anything and never reads a script's contents.

Semantics come from sddm 0.20.0 source and the Ubuntu 24.04 package
``sddm 0.20.0-2ubuntu4.2`` (built with Qt 5), not from recollection:

* ``sddm.service`` runs ``/usr/bin/sddm`` as root. ``ConfigBase::load``
  (``src/common/ConfigReader.cpp``) reads every file listed in
  ``/usr/lib/sddm/sddm.conf.d``, then every file listed in ``/etc/sddm.conf.d``, then
  ``/etc/sddm.conf``; a later file overrides an earlier one. Each directory is listed
  with ``QDir::Files | QDir::NoDotAndDotDot`` and ``QDir::LocaleAware`` sorting: any
  name is loaded, not only ``*.conf``; hidden (dot) names, directories, broken
  symlinks and special files are skipped; symlinks to files are followed. A file
  that cannot be opened is skipped silently.
* ``loadInternal`` reads with ``readLine``, decodes UTF-8, trims Qt whitespace and
  cuts the line at the first ``#`` anywhere. A line containing ``=`` is an
  assignment (checked before section headers); otherwise ``[name]`` starts a
  section. Each file starts in the implicit ``General`` section. ``XDisplay`` is an
  alias of ``X11``. Keys and section names match case-sensitively. String values are
  trimmed; an empty value is kept, not replaced by the default.
* ``Display::defaultDisplayServerType`` lower-cases ``General.DisplayServer``.
  ``x11-user`` and ``wayland`` select other display servers; any other value falls
  back to ``x11``.
* In ``x11`` mode ``XorgDisplayServer`` runs, as root:
  ``ServerPath`` with ``ServerArguments`` split on spaces only, then
  ``-background none -seat SEAT vtN -auth FILE -noreset -displayfd FD``;
  ``DisplayCommand`` (``QProcess::splitCommand``) after the server starts, waiting
  30 s; and ``DisplayStopCommand`` (``splitCommand``) after it stops, waiting 5 s.
  The scripts get ``PATH`` from ``[Users] DefaultPath``. ``takeFirst()`` on an empty
  split is undefined. ``QProcess`` resolves a program name without ``/`` through the
  daemon's own ``PATH``.
* Ubuntu builds with ``SESSION_COMMAND=/etc/sddm/Xsession``, ``DefaultPath`` patched
  to ``/bin:/usr/bin`` and the packaged ``Xsetup``/``Xstop`` patched to run
  ``/sbin/prime-offload``/``/sbin/prime-switch`` when present.

It performs no I/O and never authorizes a response action. Unobserved family,
installation state, service command, listings, files or metadata; unreadable
files; NUL bytes or invalid UTF-8; over-limit input; locale-dependent ordering
between files that disagree; empty commands; ``PATH``-searched or relative
programs; and the ``x11-user``/``wayland`` modes are blocking gaps.
"""
from __future__ import annotations

import unicodedata
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'sddm': 'sddm 0.20.0 src/common/ConfigReader.cpp, src/common/Configuration.h, '
            'src/daemon/XorgDisplayServer.cpp, src/daemon/Display.cpp',
    'package': 'Ubuntu 24.04 sddm 0.20.0-2ubuntu4.2 debian/rules, debian/patches, sddm.service (Qt 5 build)',
}
RUNS_AS = 'root'
SYSTEM_CONFIG_DIR = '/usr/lib/sddm/sddm.conf.d'
CONFIG_DIR = '/etc/sddm.conf.d'
CONFIG_FILE = '/etc/sddm.conf'
LOAD_ORDER = (SYSTEM_CONFIG_DIR, CONFIG_DIR, CONFIG_FILE)
DEFAULT_EXEC_START = ('/usr/bin/sddm',)
APPLICABLE_FAMILIES = frozenset({'debian'})
IMPLICIT_SECTION = 'General'
SECTION_ALIASES = {'XDisplay': 'X11', 'WaylandDisplay': 'Wayland'}
# (section, key) -> compiled default in the Ubuntu build.
DEFAULTS = {
    ('General', 'DisplayServer'): 'x11',
    ('X11', 'ServerPath'): '/usr/bin/X',
    ('X11', 'ServerArguments'): '-nolisten tcp',
    ('X11', 'DisplayCommand'): '/usr/share/sddm/scripts/Xsetup',
    ('X11', 'DisplayStopCommand'): '/usr/share/sddm/scripts/Xstop',
    ('Users', 'DefaultPath'): '/bin:/usr/bin',
}
DISPLAY_SERVERS = ('x11', 'x11-user', 'wayland')
SERVER_TRAILING_ARGS = ('-background', 'none', '-seat', '<seat>', 'vt<N>', '-auth', '<auth-file>', '-noreset',
                        '-displayfd', '<fd>')
DIRECTORY_STATES = ('listed', 'absent', 'unreadable', 'not_directory')
FILE_STATES = ('read', 'absent', 'unreadable')
ENTRY_TYPES = ('file', 'directory', 'symlink', 'other')
MAX_FILE_CHARS = 1 << 20
MAX_ENTRIES = 1024
MAX_GAPS = 64
BLOCKING = frozenset({
    'input_malformed', 'family_not_observed', 'family_unsupported', 'implementation_not_observed',
    'exec_start_not_observed', 'nondefault_exec_start', 'directory_not_observed', 'directory_unreadable',
    'listing_incomplete', 'too_many_entries', 'metadata_missing', 'symlink_target_unobserved',
    'config_not_observed', 'config_unreadable', 'config_too_large', 'config_nul', 'config_invalid_utf8',
    'order_ambiguous', 'display_server_not_modeled', 'empty_command', 'program_path_search',
    'relative_program', 'gaps_truncated',
})
UNOBSERVED = (
    'Script and program contents are not read. The packaged Xsetup and Xstop also run /sbin/prime-offload and '
    '/sbin/prime-switch when present; that is not assessed.',
    'Whether sddm is enabled as the display manager, and whether a display actually starts, is not checked; '
    'commands are reported as they run when it does.',
    'User session commands ([X11]/[Wayland] SessionCommand), the Wayland greeter compositor and the legacy '
    'UPower HaltCommand/RebootCommand path are not covered.',
    'QDir::LocaleAware ordering depends on the daemon locale; files in one directory are listed in code-point '
    'order and a disagreement between them is reported as a gap rather than resolved.',
)
NOT_A_VERDICT = 'Configuration and file metadata only. This is not a safety verdict and origin is not assessed.'
_TRACKED = frozenset(DEFAULTS)


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


def _qt_space(ch: str) -> bool:
    """QChar::isSpace: U+0009..U+000D, U+0020, U+0085 and the Unicode separator categories."""
    code = ord(ch)
    if code == 0x20 or 0x09 <= code <= 0x0D or code == 0x85:
        return True
    return code > 127 and unicodedata.category(ch) in ('Zs', 'Zl', 'Zp')


def qt_trimmed(text: str) -> str:
    start, end = 0, len(text)
    while start < end and _qt_space(text[start]):
        start += 1
    while end > start and _qt_space(text[end - 1]):
        end -= 1
    return text[start:end]


def split_command(command: str) -> list[str]:
    """QProcess::splitCommand: whitespace-separated, double quotes group, three quotes are one literal quote."""
    args: list[str] = []
    tmp = ''
    quote_count = 0
    in_quote = False
    for ch in command:
        if ch == '"':
            quote_count += 1
            if quote_count == 3:
                quote_count = 0
                tmp += ch
            continue
        if quote_count:
            if quote_count == 1:
                in_quote = not in_quote
            quote_count = 0
        if not in_quote and _qt_space(ch):
            if tmp:
                args.append(tmp)
                tmp = ''
        else:
            tmp += ch
    if tmp:
        args.append(tmp)
    return args


def parse_file(text: str) -> dict[tuple[str, str], tuple[str, int]]:
    """Return the last value and 1-based line of every tracked (section, key) one file assigns."""
    found: dict[tuple[str, str], tuple[str, int]] = {}
    section = IMPLICIT_SECTION
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    for number, line in enumerate(lines, 1):
        ref = qt_trimmed(line)
        hash_at = ref.find('#')
        if hash_at >= 0:
            ref = qt_trimmed(ref[:hash_at])
        section = SECTION_ALIASES.get(section, section)
        sep = ref.find('=')
        if sep >= 0:
            key = (section, qt_trimmed(ref[:sep]))
            if key in _TRACKED:
                found[key] = (qt_trimmed(ref[sep + 1:]), number)
        elif ref.startswith('[') and ref.endswith(']'):
            section = ref[1:-1]
    return found


def _resolve_target(entry: dict[str, Any], path: str, gaps: list[dict[str, Any]]) -> str | None:
    """Return the effective type QDir sees, or None when metadata is missing."""
    kind = entry.get('type')
    if kind not in ENTRY_TYPES:
        _gap(gaps, 'metadata_missing', path, 'Entry type is missing or malformed.')
        return None
    if kind != 'symlink':
        return kind
    if 'target' not in entry:
        _gap(gaps, 'symlink_target_unobserved', path)
        return None
    target = entry['target']
    if target is None:
        return 'broken'
    if not isinstance(target, dict) or target.get('type') not in ('file', 'directory', 'other'):
        _gap(gaps, 'metadata_missing', path, 'Symlink target type is missing or malformed.')
        return None
    return target['type']


def _file_text(obs: Any, path: str, gaps: list[dict[str, Any]]) -> str | None:
    """Validate one observed file; None when it is not loaded or cannot be modeled."""
    if not isinstance(obs, dict) or obs.get('state') not in FILE_STATES:
        _gap(gaps, 'input_malformed', path, 'Malformed file observation.')
        return None
    if obs['state'] == 'absent':
        return None
    if obs['state'] == 'unreadable':
        # sddm reads as root; a file the collector could not read may still be loaded.
        _gap(gaps, 'config_unreadable', path)
        return None
    text = obs.get('text')
    if not isinstance(text, str):
        _gap(gaps, 'input_malformed', path, 'File text is missing.')
        return None
    if len(text) > MAX_FILE_CHARS:
        _gap(gaps, 'config_too_large', path)
        return None
    if '\0' in text:
        _gap(gaps, 'config_nul', path, 'Qt 5 QString::fromUtf8 stops at a NUL byte; such lines are not modeled.')
        return None
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        _gap(gaps, 'config_invalid_utf8', path, 'Invalid UTF-8 is replaced by Qt; such text is not modeled.')
        return None
    return text


def _directory(path: str, listing: Any, gaps: list[dict[str, Any]], loaded: list[dict[str, Any]]) -> list[str]:
    """Return loaded file paths of one config directory in code-point order."""
    record: dict[str, Any] = {'path': path, 'kind': 'directory', 'state': 'not_observed', 'files': []}
    loaded.append(record)
    if listing is None:
        _gap(gaps, 'directory_not_observed', path)
        return []
    if not isinstance(listing, dict) or listing.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', path, 'Malformed directory observation.')
        return []
    record['state'] = listing['state']
    if listing['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', path)
        return []
    if listing['state'] != 'listed':
        return []
    if listing.get('truncated'):
        _gap(gaps, 'listing_incomplete', path)
    entries = listing.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries' if isinstance(entries, list) else 'input_malformed', path)
        return []
    names: set[str] = set()
    out: list[tuple[str, dict[str, Any]]] = []
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or '/' in name or '\0' in name or name in names \
                or name in ('.', '..'):
            _gap(gaps, 'input_malformed', path, 'An entry has a missing, invalid or duplicate name.')
            continue
        names.add(name)
        out.append((name, entry))
    files = []
    for name, entry in sorted(out, key=lambda item: item[0]):
        full = f'{path}/{name}'
        if name.startswith('.'):
            record['files'].append({'path': full, 'loaded': False, 'reason': 'hidden'})
            continue
        kind = _resolve_target(entry, full, gaps)
        if kind is None:
            record['files'].append({'path': full, 'loaded': None, 'reason': 'unresolved'})
            continue
        if kind != 'file':
            record['files'].append({'path': full, 'loaded': False, 'reason': f'not_a_file:{kind}'})
            continue
        record['files'].append({'path': full, 'loaded': True})
        files.append(full)
    return files


def _command(name: str, value: str, source: dict[str, Any] | None, gaps: list[dict[str, Any]], *,
             split: str) -> dict[str, Any]:
    """Describe one command; ``split`` is ``qprocess`` (splitCommand) or ``none`` (setProgram)."""
    argv = split_command(value) if split == 'qprocess' else ([value] if value else [])
    item: dict[str, Any] = {'setting': name, 'value': value, 'source': source, 'argv': tuple(argv),
                            'program': argv[0] if argv else None,
                            'packaged_default': source is None}
    label = f'[X11] {name.split(".", 1)[1]}'
    if not argv:
        _gap(gaps, 'empty_command', None, f'{label} is empty, so what sddm does is not determined.')
    elif '/' not in argv[0]:
        _gap(gaps, 'program_path_search', None,
             f'{label} names "{argv[0]}" without a path; QProcess resolves it through the sddm daemon PATH.')
    elif not argv[0].startswith('/'):
        _gap(gaps, 'relative_program', None, f'{label} names a relative program path.')
    return item


def assess(sources: Any = None, *, exec_start: Any = None, family: Any = None,
           sddm_installed: Any = None) -> dict[str, Any]:
    """Resolve which display commands sddm runs as root.

    ``sources`` maps ``/usr/lib/sddm/sddm.conf.d`` and ``/etc/sddm.conf.d`` to listings
    ``{'state': 'listed'|'absent'|'unreadable'|'not_directory', 'truncated': bool, 'entries': [{'name',
    'type': 'file'|'directory'|'symlink'|'other', 'target': {'type'}|None}]}``, and every loaded file path,
    including ``/etc/sddm.conf``, to ``{'state': 'read'|'absent'|'unreadable', 'text': str}``.
    ``exec_start`` is the effective ``sddm.service`` ``ExecStart`` argv.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'runs_as': RUNS_AS,
        'applicability': 'unknown', 'load_order': LOAD_ORDER, 'loaded': [], 'settings': {},
        'display_server': None, 'commands': [], 'script_environment': None, 'gaps': gaps,
        'origin': 'not_assessed', 'not_a_verdict': NOT_A_VERDICT, 'unobserved': UNOBSERVED,
    }
    if family is None:
        _gap(gaps, 'family_not_observed')
    elif family not in APPLICABLE_FAMILIES:
        _gap(gaps, 'family_unsupported')
    if sddm_installed is False:
        result['applicability'] = 'not_applicable'
    elif sddm_installed is not True:
        _gap(gaps, 'implementation_not_observed', None, 'Whether sddm is installed is unknown.')
    elif family in APPLICABLE_FAMILIES:
        result['applicability'] = 'applicable'

    if exec_start is None:
        _gap(gaps, 'exec_start_not_observed', None, 'The effective sddm.service ExecStart was not observed.')
    elif not isinstance(exec_start, (list, tuple)) or not all(isinstance(a, str) for a in exec_start):
        _gap(gaps, 'input_malformed', None, 'Malformed ExecStart.')
    elif tuple(exec_start) != DEFAULT_EXEC_START:
        _gap(gaps, 'nondefault_exec_start', None,
             'sddm is started with a binary or arguments other than /usr/bin/sddm.')

    if sources is None:
        sources = {}
    if not isinstance(sources, dict):
        _gap(gaps, 'input_malformed', None, 'Malformed sources.')
        sources = {}

    # Group the files in load order: each directory is one group, the main file another.
    groups: list[list[str]] = []
    for path in (SYSTEM_CONFIG_DIR, CONFIG_DIR):
        groups.append(_directory(path, sources.get(path), gaps, result['loaded']))
    groups.append([CONFIG_FILE])

    parsed: dict[str, dict[tuple[str, str], tuple[str, int]]] = {}
    for group in groups:
        for path in group:
            obs = sources.get(path)
            if path == CONFIG_FILE:
                state = obs.get('state') if isinstance(obs, dict) and obs.get('state') in FILE_STATES else None
                result['loaded'].append({'path': path, 'kind': 'file', 'state': state or 'not_observed'})
            if obs is None:
                _gap(gaps, 'config_not_observed', path)
                continue
            text = _file_text(obs, path, gaps)
            if text is not None:
                parsed[path] = parse_file(text)

    settings: dict[tuple[str, str], dict[str, Any]] = {}
    for key in DEFAULTS:
        value: str | None = DEFAULTS[key]
        source: dict[str, Any] | None = None
        # Only the last group that sets the key decides it; earlier groups are overridden whatever their order.
        deciding = [setters for setters in (
            [(p, parsed[p][key]) for p in group if p in parsed and key in parsed[p]] for group in groups) if setters]
        for setters in deciding[-1:]:
            if len({v for _, (v, _) in setters}) > 1:
                value, source = None, {'paths': [p for p, _ in setters]}
                _gap(gaps, 'order_ambiguous', None,
                     f'Files in one directory set [{key[0]}] {key[1]} to different values; which wins depends on '
                     'locale-aware ordering.')
            else:
                path, (val, line) = setters[-1]
                value, source = val, {'path': path, 'line': line}
        settings[key] = {'value': value, 'source': source}
    result['settings'] = {f'{s}.{k}': v for (s, k), v in settings.items()}

    mode_setting = settings[('General', 'DisplayServer')]
    if mode_setting['value'] is None:
        return _finish(result, gaps)
    mode = mode_setting['value'].lower()
    effective = mode if mode in DISPLAY_SERVERS else 'x11'
    result['display_server'] = {'value': mode_setting['value'], 'effective': effective,
                                'fallback': mode not in DISPLAY_SERVERS}
    if effective != 'x11':
        _gap(gaps, 'display_server_not_modeled', None,
             f'In {effective} mode the display scripts run through sddm-helper for the greeter and session '
             'users; that path is not modeled.')
        return _finish(result, gaps)

    commands = result['commands']
    for setting, stage, split, waits in (
            ('X11.ServerPath', 'display_server', 'space', None),
            ('X11.DisplayCommand', 'after_server_start', 'qprocess', 30),
            ('X11.DisplayStopCommand', 'after_server_stop', 'qprocess', 5)):
        section, key = setting.split('.', 1)
        entry = settings[(section, key)]
        if entry['value'] is None:
            commands.append({'setting': setting, 'stage': stage, 'value': None, 'argv': None, 'program': None,
                             'source': entry['source'], 'runs': None})
            continue
        if setting == 'X11.ServerPath':
            # setProgram(ServerPath) takes the whole value as the program; ServerArguments splits on ' ' only.
            args_entry = settings[('X11', 'ServerArguments')]
            item = _command(setting, entry['value'], entry['source'], gaps, split='none')
            if args_entry['value'] is None:
                item['argv'] = None
            elif item['program'] is not None:
                item['argv'] = item['argv'] + tuple(a for a in args_entry['value'].split(' ') if a) \
                    + SERVER_TRAILING_ARGS
            item['arguments_source'] = args_entry['source']
            item['packaged_default'] = entry['source'] is None and args_entry['source'] is None
        else:
            item = _command(setting, entry['value'], entry['source'], gaps, split=split)
        item['stage'] = stage
        item['runs'] = True if item['program'] else None
        if waits is not None:
            item['timeout_seconds'] = waits
        commands.append(item)

    path_setting = settings[('Users', 'DefaultPath')]
    result['script_environment'] = {
        'PATH': path_setting['value'], 'PATH_source': path_setting['source'], 'HOME': '/', 'SHELL': '/bin/sh',
        'set': ('DISPLAY', 'HOME', 'PATH', 'SHELL', 'XAUTHORITY (setup only)', 'XCURSOR_THEME (setup only)',
                'XCURSOR_SIZE (setup only, when set)'),
    }
    return _finish(result, gaps)


def _finish(result: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
