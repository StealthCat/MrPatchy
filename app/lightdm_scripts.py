"""Pure LightDM seat-script contract (roadmap F slice, #1301).

LightDM runs five seat scripts as root, with a cleared environment:

- ``display-setup-script`` after the X server starts, before the greeter;
- ``display-stopped-script`` after the display server stops;
- ``greeter-setup-script`` before each greeter session;
- ``session-setup-script`` before each user session, with ``USER``/``HOME``;
- ``session-cleanup-script`` after each user session ends.

The command string is passed to ``g_shell_parse_argv`` and run with
``execvp``. This module turns captured configuration text and captured
directory listings into the effective command for each script on each assumed
seat name. It performs no I/O, never runs LightDM or a script and never
authorizes a response action.

The rules follow LightDM 1.30.0 (Ubuntu 24.04 ``lightdm_1.30.0-0ubuntu14``)
``common/configuration.c``, ``src/lightdm.c`` and ``src/seat.c``:

- ``config_load_from_standard_locations`` loads ``lightdm/lightdm.conf.d`` under
  each XDG system data directory and then each XDG system config directory,
  each list in reverse order so earlier directories win. It then loads
  ``/etc/lightdm/lightdm.conf.d`` and finally ``/etc/lightdm/lightdm.conf``.
  Only names ending in ``.conf`` are read, sorted with ``strcmp``.
- Each file is parsed by GLib's ``GKeyFile``. A drop-in it refuses is skipped
  whole. A main file it refuses stops LightDM, so nothing runs. A missing main
  file is allowed.
- ``[SeatDefaults]`` keys are moved into ``[Seat:*]``. Later files override
  earlier values for the same group and key.
- A seat takes ``[Seat:*]`` first, then every other ``[Seat:<glob>]`` whose
  glob matches its name (``g_pattern_match_simple``), in group order. Each key
  is read with ``g_key_file_get_string``. An invalid value (bad escape, invalid
  UTF-8) reads as NULL and unsets the script.

Fail-closed rules: an unobserved file or directory listing, invalid UTF-8, NUL
bytes and over-limit input mark the result incomplete. ``origin`` is always
``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import hashlib
import posixpath
from collections.abc import Iterable, Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('1.30.0',)
CONFIG_DIR = '/etc/lightdm'
MAIN_PATH = CONFIG_DIR + '/lightdm.conf'
# GLib defaults when XDG_DATA_DIRS / XDG_CONFIG_DIRS are unset.
DEFAULT_DATA_DIRS = ('/usr/local/share', '/usr/share')
DEFAULT_CONFIG_DIRS = ('/etc/xdg',)
DEFAULT_SEATS = ('seat0',)
SCRIPT_KEYS = (
    ('display-setup-script', 'after the display server starts, before the greeter'),
    ('display-stopped-script', 'after the display server stops'),
    ('greeter-setup-script', 'before each greeter session'),
    ('session-setup-script', 'before each user session'),
    ('session-cleanup-script', 'after each user session ends'),
)
MAX_TEXT = 262144
MAX_FILES = 256
MAX_GAPS = 64

BLOCKING = frozenset({
    'file_not_observed', 'directory_not_observed', 'over_limit', 'invalid_utf8', 'binary', 'files_over_limit',
    'gaps_truncated', 'relative_path',
})

NOT_OBSERVED = (
    'Whether LightDM is installed, enabled and running, and whether it was started with --config.',
    ('The XDG_DATA_DIRS and XDG_CONFIG_DIRS of the LightDM service; the GLib defaults are assumed unless '
     'other directories are passed.'),
    ('Which seats exist. Seat names come from logind; without logind, and for XDMCP and VNC seats, only '
     '[Seat:*] applies.'),
    'Whether a script path exists, is executable, or what it does.',
    'How g_shell_parse_argv splits the command; an empty or unparsable command fails to start.',
)

_SPACE = ' \t\n\f\r'  # g_ascii_isspace: no vertical tab


class KeyFileError(ValueError):
    """GKeyFile would refuse this file."""


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'path': None, 'detail': '', 'blocking': True}
        return
    gaps.append({'code': code, 'path': path, 'detail': detail[:240], 'blocking': code in BLOCKING})


def _is_group_name(name: str) -> bool:
    return bool(name) and not any(c in '[]' or ord(c) < 32 or ord(c) == 127 for c in name)


def _is_key_name(key: str) -> bool:
    q = 0
    while q < len(key) and key[q] not in '=[]':
        q += 1
    if q == 0 or key[0] == ' ' or key[q - 1] == ' ':
        return False
    if q < len(key) and key[q] == '[':
        q += 1
        while q < len(key) and (key[q].isascii() and key[q].isalnum() or key[q] in '-_.@'):
            q += 1
        if q >= len(key) or key[q] != ']':
            return False
        q += 1
    return q == len(key)


def parse_keyfile(text: str) -> list[tuple[str, dict[str, str]]]:
    """Parse like ``g_key_file_load_from_data`` (GLib 2.80) and return groups in order with raw values.

    The caller has already refused NUL bytes and invalid UTF-8. Raises :class:`KeyFileError` where
    GLib refuses the file. Translated ``key[locale]`` entries are validated and then left out.
    """
    groups: list[tuple[str, dict[str, str]]] = []
    index: dict[str, int] = {}
    current: dict[str, str] | None = None
    first_group: str | None = None
    current_name: str | None = None
    lines = text.split('\n')
    for number, line in enumerate(lines, 1):
        if number < len(lines) and line.endswith('\r'):
            line = line[:-1]
        stripped = line.lstrip(_SPACE)
        if not stripped or stripped[0] == '#':
            continue
        if stripped[0] == '[':
            close = stripped.find(']')
            if close != -1 and not stripped[close + 1:].strip(' \t'):
                name = stripped[1:stripped.rfind(']')]
                if not _is_group_name(name):
                    raise KeyFileError(f'line {number}: invalid group name')
                if name not in index:
                    index[name] = len(groups)
                    groups.append((name, {}))
                current = groups[index[name]][1]
                current_name = name
                if first_group is None:
                    first_group = name
                continue
        equals = stripped.find('=')
        if equals <= 0:
            raise KeyFileError(f'line {number}: not a key-value pair, group, or comment')
        if current is None:
            raise KeyFileError('key file does not start with a group')
        key = stripped[:equals].rstrip(_SPACE)
        if not _is_key_name(key):
            raise KeyFileError(f'line {number}: invalid key name')
        value = stripped[equals + 1:].lstrip(_SPACE)
        if current_name == first_group and key == 'Encoding' and value.lower() != 'utf-8':
            raise KeyFileError(f'line {number}: unsupported encoding')
        if key.endswith(']'):
            # A translated key is kept only for locales of LightDM's environment; it never names a script.
            continue
        current.pop(key, None)
        current[key] = value
    return groups


def unescape(value: str) -> str | None:
    """``g_key_file_get_string``: the unescaped value, or None where GLib reports an error."""
    out: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c != '\\':
            out.append(c)
            i += 1
            continue
        if i + 1 >= len(value):
            return None
        nxt = value[i + 1]
        mapped = {'s': ' ', 'n': '\n', 't': '\t', 'r': '\r', '\\': '\\'}.get(nxt)
        if mapped is None:
            return None
        out.append(mapped)
        i += 2
    return ''.join(out)


def _match_simple(pattern: str, name: str) -> bool:
    """``g_pattern_match_simple``: ``*`` matches any run and ``?`` any one character; nothing else is special."""
    p, n, star, mark = 0, 0, -1, 0
    while n < len(name):
        if p < len(pattern) and (pattern[p] == '?' or pattern[p] == name[n]):
            p += 1
            n += 1
        elif p < len(pattern) and pattern[p] == '*':
            star, mark = p, n
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            n = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == '*':
        p += 1
    return p == len(pattern)


def _decode(path: str, raw: Any, gaps: list[dict[str, Any]]) -> str | None:
    if raw is None:
        _gap(gaps, 'file_not_observed', path)
        return None
    if isinstance(raw, str):
        try:
            raw = raw.encode('utf-8')
        except UnicodeEncodeError:
            _gap(gaps, 'invalid_utf8', path)
            return None
    if len(raw) > MAX_TEXT:
        _gap(gaps, 'over_limit', path)
        return None
    if b'\0' in raw:
        _gap(gaps, 'binary', path)
        return None
    try:
        return bytes(raw).decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8', path)
        return None


def config_paths(listings: Mapping[str, Iterable[str] | None], data_dirs: Iterable[str] = DEFAULT_DATA_DIRS,
                 config_dirs: Iterable[str] = DEFAULT_CONFIG_DIRS,
                 gaps: list[dict[str, Any]] | None = None) -> list[tuple[str, bool]]:
    """The ``(path, is_main)`` load order. ``listings`` maps each conf.d directory to its entry names."""
    gaps = gaps if gaps is not None else []
    dirs = [posixpath.join(d, 'lightdm', 'lightdm.conf.d') for d in reversed(list(data_dirs))]
    dirs += [posixpath.join(d, 'lightdm', 'lightdm.conf.d') for d in reversed(list(config_dirs))]
    dirs.append(CONFIG_DIR + '/lightdm.conf.d')
    out: list[tuple[str, bool]] = []
    for directory in dirs:
        if not directory.startswith('/'):
            _gap(gaps, 'relative_path', directory)
            continue
        names = listings.get(directory)
        if names is None:
            _gap(gaps, 'directory_not_observed', directory)
            continue
        ordered = sorted((n for n in names if n.endswith('.conf')), key=lambda n: n.encode('utf-8', 'surrogateescape'))
        out += [(directory + '/' + n, False) for n in ordered]
    out.append((MAIN_PATH, True))
    return out


def _result(status: str, gaps: list, seats: list, files_read: list, detail: str = '') -> dict[str, Any]:
    return {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS), 'main_path': MAIN_PATH,
        'status': status, 'detail': detail[:240], 'complete': not any(g['blocking'] for g in gaps),
        'origin': 'not_assessed', 'runs_as': 'root', 'files_read': files_read, 'seats': seats, 'gaps': gaps,
        'not_observed': list(NOT_OBSERVED),
    }


def evaluate(*, files: Mapping[str, Any], listings: Mapping[str, Iterable[str] | None],
             data_dirs: Iterable[str] = DEFAULT_DATA_DIRS, config_dirs: Iterable[str] = DEFAULT_CONFIG_DIRS,
             seat_names: Iterable[str] = DEFAULT_SEATS, main_missing: bool = False) -> dict[str, Any]:
    """Resolve the scripts LightDM runs as root for each seat name.

    ``files`` maps each path to its captured bytes or text, or None when it could not be read.
    ``main_missing`` records that ``/etc/lightdm/lightdm.conf`` was observed to be absent.
    """
    gaps: list[dict[str, Any]] = []
    order = config_paths(listings, data_dirs, config_dirs, gaps)
    if len(order) > MAX_FILES:
        _gap(gaps, 'files_over_limit', None, f'{len(order)} files')
        order = order[:MAX_FILES - 1] + [order[-1]]
    merged: list[tuple[str, dict[str, tuple[str, str]]]] = []
    merged_index: dict[str, int] = {}
    files_read: list[str] = []
    for path, is_main in order:
        if is_main and main_missing:
            continue
        if path not in files:
            _gap(gaps, 'file_not_observed', path)
            continue
        text = _decode(path, files[path], gaps)
        if text is None:
            continue
        try:
            groups = parse_keyfile(text)
        except KeyFileError as exc:
            if is_main:
                return _result('config_error', gaps, [], files_read + [path], f'{path}: {exc}')
            _gap(gaps, 'file_refused', path, str(exc))
            continue
        files_read.append(path)
        for name, values in groups:
            group = 'Seat:*' if name == 'SeatDefaults' else name
            if group not in merged_index:
                merged_index[group] = len(merged)
                merged.append((group, {}))
            target = merged[merged_index[group]][1]
            for key, value in values.items():
                target.pop(key, None)
                target[key] = (value, path)
    seats = []
    for seat in seat_names:
        sections = ['Seat:*'] + [g for g, _ in merged if g.startswith('Seat:') and g != 'Seat:*'
                                 and _match_simple(g[len('Seat:'):], seat)]
        properties: dict[str, tuple[str | None, str, str]] = {}
        for section in sections:
            if section not in merged_index:
                continue
            for key, (raw, source) in merged[merged_index[section]][1].items():
                properties[key] = (unescape(raw), source, section)
        scripts = []
        for key, when in SCRIPT_KEYS:
            if key not in properties:
                continue
            command, source, section = properties[key]
            if command is None:
                scripts.append({'key': key, 'when': when, 'runs': False, 'command': None, 'command_sha256': None,
                                'source': source, 'section': section, 'reason': 'invalid value reads as unset'})
                continue
            scripts.append({
                'key': key, 'when': when, 'runs': True, 'command': command,
                'command_sha256': hashlib.sha256(command.encode('utf-8')).hexdigest(),
                'source': source, 'section': section, 'runs_as': 'root',
                'empty': not command.strip(_SPACE),
            })
        seats.append({'seat': seat, 'sections': [s for s in sections if s in merged_index], 'scripts': scripts})
    return _result('loads', gaps, seats, files_read)
