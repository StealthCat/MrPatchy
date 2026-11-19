"""Pure systemd-tmpfiles contract for lines that write kernel exec hooks or startup files (roadmap F slice, #1097).

``systemd-tmpfiles-setup.service`` applies ``tmpfiles.d`` at every boot as
root. A line such as ``w /proc/sys/kernel/core_pattern - - - - |/tmp/x`` sets a
program that the kernel itself later executes, which bypasses ``sysctl.d``
(#1088). A line such as ``f /etc/cron.d/job …``, ``L /etc/ld.so.preload - - - -
/x`` or ``C /etc/systemd/system/x.service`` creates a startup file. This module
turns captured, read-only ``tmpfiles.d`` text into those effective lines. It
performs no I/O, never runs ``systemd-tmpfiles``, never writes a file and never
authorizes a response action.

Rules, checked by running the compiled ``systemd-tmpfiles`` 255
(255.4-1ubuntu8.18) with ``--root`` on fixture trees:

- Only ``*.conf`` names in ``/etc``, ``/run``, ``/usr/local/lib`` and
  ``/usr/lib`` ``tmpfiles.d`` are read. A name in a higher-priority directory
  replaces the same name in a lower one, a symlink to ``/dev/null`` masks it,
  and files are read in name order.
- Lines are stripped. Empty lines and ``#`` lines are skipped and there are no
  continuation lines. The first six fields are split on whitespace with
  quoting and C escapes removed. The rest of the line, after leading
  whitespace, is the argument, and ``-`` means none. Quotes in the argument
  are kept, ``%%`` becomes ``%``, and C escapes are decoded. Any other
  specifier makes the line host-dependent.
- The type letter may be followed by ``+`` (replace or append), ``!`` (boot
  only, which the boot service passes), ``-`` (ignore failures), ``=``,
  ``~`` (the argument is base64) and ``^`` (the argument names a credential).
  Any other modifier rejects the line in v255. Newer releases accept more, so
  on a writing line that is a blocking gap.
- Relative paths, ``w`` without an argument, invalid base64, repeated
  modifiers, an invalid mode (octal above ``07777`` after ``~``/``:``) or age,
  and syntax errors reject the line before the duplicate check, so a rejected
  line never takes a path's slot. A user or group other than ``-``, ``root``
  or a plain id resolves through the host's NSS, an age form not checked
  against the binary may be rejected, and a ``C`` line is skipped when its copy
  source is missing. Such lines are conditional: a write they shadow, or a
  kernel setting they write, is a blocking ``line_validity_unresolved`` gap.
- ``f``/``w``/``L``/``C`` arguments are unescaped first and then expanded, so
  ``\x25H`` is the host name. Base64 arguments are not expanded. Repeated and trailing slashes are simplified, and a path
  with a ``..`` component is refused when applied.
- The first line for a path wins over a later conflicting one ("Duplicate
  line"). Of ``f``/``L``/``C``/``d``/``D``/``v``/``q``/``Q``/``p``/``c``/``b``,
  only the first is kept unless the argument and mode, user, group and age
  fields are identical. A ``w`` line and a
  ``w``, ``x``, ``X``, ``r`` or ``R`` line for the same path conflict, so the
  later one is dropped, except that ``w+`` lines after a ``w+`` all apply and
  lines with identical fields and argument all apply. A ``w`` and an ``f`` for
  the same path both apply.
- tmpfiles keeps two maps keyed by the path text. Glob-capable types
  (``w``, ``e``, ``x``, ``X``, ``r``, ``R``, ``z``, ``Z``, ``t``, ``T``, ``h``,
  ``H``, ``a``, ``A``) go in the second. The first map is applied first, then
  the second, each in the order its paths first appeared. So every ``f``/``L``/
  ``C`` runs before every ``w``, and among ``w`` lines a path or pattern that
  first appeared later is written later. Among the writing types only ``w``
  expands glob characters.
- ``w`` writes only to an existing file. ``f`` writes only when it creates the
  file, ``f+`` truncates and writes. ``L``/``C`` act only when the path is
  absent, and ``L+``/``C+`` replace it. Kernel files always exist, so only
  ``w``, ``w+`` and ``f+`` change a kernel setting.

Fail-closed rules: unreadable, over-limit, invalid UTF-8 or NUL input,
unfollowed symlinks, unresolved specifiers and credentials on relevant lines,
and unparsed writing lines are blocking gaps. They are never reported as
covered. Nothing is labelled safe and ``origin`` is always ``not_assessed``.
"""
from __future__ import annotations

import base64
import binascii
import fnmatch
import hashlib
import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'package': 'systemd', 'version': '255.4-1ubuntu8.18', 'binary': 'systemd-tmpfiles',
             'service': 'systemd-tmpfiles-setup.service (--create --remove --boot --exclude-prefix=/dev)'}
MAX_FILES = 512
MAX_TEXT = 262144
MAX_LINES = 20000
MAX_SHOWN = 512
MAX_GAPS = 64

TMPFILES_DIRS = ('/etc/tmpfiles.d', '/run/tmpfiles.d', '/usr/local/lib/tmpfiles.d', '/usr/lib/tmpfiles.d')
SPLIT_USR_DIR = '/lib/tmpfiles.d'

KERNEL_TARGETS = {
    '/proc/sys/kernel/core_pattern': 'core_pattern',
    '/proc/sys/kernel/modprobe': 'modprobe',
    '/proc/sys/kernel/hotplug': 'uevent_helper',
    '/sys/kernel/uevent_helper': 'uevent_helper',
    '/proc/sys/kernel/poweroff_cmd': 'poweroff_cmd',
    '/proc/sys/fs/binfmt_misc/register': 'binfmt_register',
}
KERNEL_HOOKS = {
    'core_pattern': {'kind': 'core_pattern', 'trigger': 'every core dump, when the value starts with "|"'},
    'modprobe': {'kind': 'program', 'trigger': 'every kernel module autoload request'},
    'uevent_helper': {'kind': 'program', 'trigger': 'every uevent (CONFIG_UEVENT_HELPER kernels)'},
    'poweroff_cmd': {'kind': 'command', 'trigger': 'orderly poweroff'},
    'binfmt_register': {'kind': 'binfmt_register',
                        'trigger': 'execution of programs matching the registered binfmt_misc rule'},
}
# Startup and persistence locations that tmpfiles.d could create or replace. This
# list is not exhaustive; ``UNOBSERVED`` says so.
STARTUP_FILES = frozenset({
    '/etc/crontab', '/etc/anacrontab', '/etc/ld.so.preload', '/etc/ld.so.conf', '/etc/rc.local', '/etc/profile',
    '/etc/bash.bashrc', '/etc/environment', '/etc/ssh/sshrc', '/etc/sudoers', '/etc/inittab', '/etc/sysctl.conf',
    '/etc/modules', '/root/.bashrc', '/root/.profile', '/root/.bash_profile',
})
STARTUP_DIRS = frozenset({
    '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly',
    '/var/spool/cron', '/etc/systemd/system', '/run/systemd/system', '/etc/systemd/user', '/run/systemd/user',
    '/usr/lib/systemd/system', '/lib/systemd/system', '/etc/systemd/system-generators',
    '/run/systemd/system-generators', '/usr/local/lib/systemd/system-generators', '/etc/init.d', '/etc/rcS.d',
    '/etc/rc0.d', '/etc/rc1.d', '/etc/rc2.d', '/etc/rc3.d', '/etc/rc4.d', '/etc/rc5.d', '/etc/rc6.d',
    '/etc/profile.d', '/etc/ld.so.conf.d', '/etc/udev/rules.d', '/run/udev/rules.d', '/etc/modprobe.d',
    '/run/modprobe.d', '/etc/modules-load.d', '/run/modules-load.d', '/etc/sysctl.d', '/run/sysctl.d',
    '/etc/tmpfiles.d', '/run/tmpfiles.d', '/etc/binfmt.d', '/run/binfmt.d', '/etc/xdg/autostart', '/etc/pam.d',
    '/etc/sudoers.d', '/etc/update-motd.d', '/etc/NetworkManager/dispatcher.d', '/etc/network/if-up.d',
    '/etc/network/if-pre-up.d', '/etc/network/if-down.d', '/etc/network/if-post-down.d',
    '/etc/dhcp/dhclient-enter-hooks.d', '/etc/dhcp/dhclient-exit-hooks.d', '/etc/apt/apt.conf.d',
    '/etc/logrotate.d', '/etc/acpi/events', '/etc/ppp/ip-up.d', '/etc/ppp/ip-down.d', '/etc/kernel/postinst.d',
    '/etc/kernel/postrm.d', '/etc/X11/Xsession.d', '/root/.ssh', '/root/.config/autostart',
})
WRITING = frozenset('fwLC')
OWNERSHIP = frozenset('fLCdDvqQpcb')
WRITE_BLOCKERS = frozenset('wexXrR')
KNOWN_TYPES = frozenset('fFwdDevqQpLcbCxXrRzZtThHaA')
GLOB_TYPES = frozenset('wexXrRzZtThHaA')
KNOWN_MODIFIERS = frozenset('+!-=~^')
BLOCKING = frozenset({
    'input_malformed', 'too_many_files', 'duplicate_path', 'file_unreadable', 'symlink_not_followed',
    'text_over_limit', 'invalid_utf8', 'nul_byte', 'too_many_lines', 'path_specifier_unresolved',
    'argument_specifier_unresolved', 'credential_unobserved', 'modifier_unsupported', 'line_unparsed',
    'line_validity_unresolved', 'gaps_truncated',
})
UNOBSERVED = (
    'Per-user tmpfiles (systemd-tmpfiles --user and user-tmpfiles.d) are not modelled.',
    'The live value in /proc/sys and /sys, and whether a write failed or was truncated by the kernel, are not '
    'observed. A later sysctl.d (systemd-sysctl), runtime write or sysctl -w can replace a value.',
    'Credential contents ("^" lines) and the /usr/share/factory copy sources are not observed.',
    'Whether the target file already exists is not observed, so "only if absent" and "only if present" '
    'lines are reported with that condition.',
    'The startup-location list is not exhaustive. Removal, ownership, mode and ACL lines are not assessed.',
)
NOT_A_VERDICT = 'Parsed configuration only. This is not a safety verdict and origin is not assessed.'

_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
_EOL = re.compile(r'\r\n|\r|\n')
_WS = ' \t\n\r'
_GLOB = frozenset('*?[')
_MODE = re.compile(r'[~:]*([0-7]+)')
_AGE_UNITS = ('usec', 'us', '\u00b5s', '\u03bcs', 'msec', 'ms', 'seconds', 'second', 'sec', 's', 'minutes',
              'minute', 'min', 'months', 'month', 'M', 'm', 'hours', 'hour', 'hr', 'h', 'days', 'day', 'd',
              'weeks', 'week', 'w', 'years', 'year', 'y')
_AGE_NUM = r'(?:\d{1,9}(?:\.\d{1,9})?|\.\d{1,9})'
_AGE_UNIT = '(?:%s)' % '|'.join(re.escape(u) for u in _AGE_UNITS)
_AGE = re.compile(f'(?:{_AGE_NUM}{_AGE_UNIT})*{_AGE_NUM}{_AGE_UNIT}?')
_AGE_BY = re.compile(r'[abcmABCM]+')
_ID = re.compile(r'0|[1-9][0-9]{0,9}')
_SIMPLE_ESCAPES = {'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v', '\\': '\\',
                   '"': '"', "'": "'", 's': ' '}


class _Unparsed(ValueError):
    pass


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, line: int | None = None,
         detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code}
    if path is not None:
        gap['path'] = path
    if line is not None:
        gap['line'] = line
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unescape_at(text: str, i: int) -> tuple[str, int]:
    """Decode the C escape whose backslash is at ``text[i]``. Returns the text and the next index."""
    if i + 1 >= len(text):
        raise _Unparsed('trailing backslash')
    c = text[i + 1]
    if c in _SIMPLE_ESCAPES:
        return _SIMPLE_ESCAPES[c], i + 2
    for prefix, digits, base in (('x', 2, 16), ('u', 4, 16), ('U', 8, 16)):
        if c == prefix:
            chunk = text[i + 2:i + 2 + digits]
            if len(chunk) != digits or not all(ch in '0123456789abcdefABCDEF' for ch in chunk):
                raise _Unparsed('bad escape')
            value = int(chunk, base)
            if value == 0 or value > 0x10FFFF:
                raise _Unparsed('bad escape')
            return chr(value), i + 2 + digits
    if c in '01234567':
        chunk = text[i + 1:i + 4]
        if len(chunk) != 3 or not all(ch in '01234567' for ch in chunk) or int(chunk, 8) in (0,) or int(chunk, 8) > 255:
            raise _Unparsed('bad escape')
        return chr(int(chunk, 8)), i + 4
    raise _Unparsed('bad escape')


def cunescape(text: str) -> str:
    out, i = [], 0
    while i < len(text):
        if text[i] == '\\':
            piece, i = _unescape_at(text, i)
            out.append(piece)
        else:
            out.append(text[i])
            i += 1
    return ''.join(out)


def split_fields(line: str, count: int = 6) -> tuple[list[str], str]:
    """Split up to ``count`` unquoted, unescaped words, returning them and the raw remainder."""
    words: list[str] = []
    i, n = 0, len(line)
    while len(words) < count:
        while i < n and line[i] in _WS:
            i += 1
        if i >= n:
            break
        word: list[str] = []
        quote = None
        while i < n:
            ch = line[i]
            if quote:
                if ch == quote:
                    quote, i = None, i + 1
                elif ch == '\\':
                    piece, i = _unescape_at(line, i)
                    word.append(piece)
                else:
                    word.append(ch)
                    i += 1
            elif ch in _WS:
                break
            elif ch in '"\'':
                quote, i = ch, i + 1
            elif ch == '\\':
                piece, i = _unescape_at(line, i)
                word.append(piece)
            else:
                word.append(ch)
                i += 1
        if quote:
            raise _Unparsed('unterminated quote')
        words.append(''.join(word))
    while i < n and line[i] in _WS:
        i += 1
    return words, line[i:]


def _specifiers(text: str) -> tuple[str, bool]:
    """Expand ``%%``. Returns the text and whether another specifier is present."""
    out, i, other = [], 0, False
    while i < len(text):
        if text[i] == '%' and i + 1 < len(text) and text[i + 1] == '%':
            out.append('%')
            i += 2
        else:
            if text[i] == '%':
                other = True
            out.append(text[i])
            i += 1
    return ''.join(out), other


def simplify_path(path: str) -> str:
    """systemd ``path_simplify``: collapse repeated slashes, drop ``.`` components and a trailing slash."""
    parts = [p for p in path.split('/') if p not in ('', '.')]
    return '/' + '/'.join(parts)


def _glob_component(pattern: str, name: str) -> bool:
    if name.startswith('.') and not pattern.startswith('.'):
        return False
    return fnmatch.fnmatchcase(name, pattern)


def glob_matches(pattern: str, path: str) -> bool:
    """glob(3) matching without ``GLOB_PERIOD``: ``*`` never crosses ``/``."""
    pat, parts = pattern.strip('/').split('/'), path.strip('/').split('/')
    return len(pat) == len(parts) and all(_glob_component(p, q) for p, q in zip(pat, parts))


def startup_location(path: str, glob: bool) -> str | None:
    """Return the startup location the path (or glob) writes, replaces or may reach."""
    for location in sorted(STARTUP_FILES | STARTUP_DIRS):
        is_dir = location in STARTUP_DIRS
        if glob:
            pat, loc = path.strip('/').split('/'), location.strip('/').split('/')
            if len(pat) >= len(loc) and all(_glob_component(p, q) for p, q in zip(pat, loc)):
                if len(pat) == len(loc) or is_dir:
                    return location
            continue
        if path == location or (is_dir and path.startswith(location + '/')) or location.startswith(path + '/'):
            return location
    return None


def mode_valid(field: str) -> bool:
    """v255 ``parse_mode`` after the ``~``/``:`` prefixes: octal, at most 07777, no sign."""
    match = _MODE.fullmatch(field)
    return bool(match) and int(match.group(1), 8) <= 0o7777


def age_status(field: str) -> str:
    """Classify an age field as ``valid``, ``invalid`` or ``uncertain`` (v255 ``parse_sec`` with prefixes).

    Only forms checked against the reference binary are classed; anything else is ``uncertain`` so a line
    that systemd might reject never silently takes a path's slot.
    """
    text = field[1:] if field.startswith('~') else field
    if ':' in text:
        by, text = text.split(':', 1)
        if not _AGE_BY.fullmatch(by):
            return 'invalid'
    if text == 'infinity' or _AGE.fullmatch(text):
        return 'valid'
    if text == '' or text.startswith(('-', '~')) or not any(ch.isdigit() for ch in text):
        return 'invalid'
    return 'uncertain'


def owner_resolved(field: str) -> bool:
    """Whether a user or group field resolves without the host's NSS (``-``, ``root`` or a plain id)."""
    if field in ('', '-', 'root'):
        return True
    return bool(_ID.fullmatch(field)) and int(field) < 4294967295 and int(field) != 65535


def _decode(path: str, text: Any, gaps: list[dict[str, Any]]) -> str | None:
    if isinstance(text, bytes):
        if len(text) > MAX_TEXT:
            _gap(gaps, 'text_over_limit', path)
            return None
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            _gap(gaps, 'invalid_utf8', path)
            return None
    if not isinstance(text, str):
        _gap(gaps, 'file_unreadable', path)
        return None
    if len(text) > MAX_TEXT:
        _gap(gaps, 'text_over_limit', path)
        return None
    if '\x00' in text:
        _gap(gaps, 'nul_byte', path)
        return None
    return text


def _effective_files(files: Any, gaps: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    try:
        supplied = list(files)
    except TypeError:
        _gap(gaps, 'input_malformed', detail='files must be an iterable of mappings.')
        return [], []
    if len(supplied) > MAX_FILES:
        _gap(gaps, 'too_many_files', detail=f'More than {MAX_FILES} files were supplied; none were parsed.')
        return [], []
    records: list[dict[str, Any]] = []
    items: dict[str, dict[str, Any]] = {}
    by_name: dict[str, list[tuple[int, dict[str, Any], dict[str, Any]]]] = {}
    for item in supplied:
        path = item.get('path') if isinstance(item, dict) else None
        if (not isinstance(path, str) or not path.startswith('/') or len(path) > 4096 or _CONTROL.search(path)
                or posixpath.normpath(path) != path):
            _gap(gaps, 'input_malformed', detail='A file entry has no normalized absolute path.')
            continue
        if path in items:
            _gap(gaps, 'duplicate_path', path)
            continue
        items[path] = item
        directory, name = posixpath.split(path)
        record: dict[str, Any] = {'path': path, 'name': name, 'directory': directory}
        records.append(record)
        kind = item.get('type', 'file')
        if directory == SPLIT_USR_DIR:
            record.update(status='ignored', reason='split_usr_alias')
        elif directory not in TMPFILES_DIRS:
            record.update(status='ignored', reason='outside_known_directories')
        elif name.startswith('.'):
            record.update(status='ignored', reason='hidden')
        elif not name.endswith('.conf'):
            record.update(status='ignored', reason='not_conf_suffix')
        elif kind not in ('file', 'symlink'):
            record.update(status='ignored', reason='not_regular_file')
        else:
            by_name.setdefault(name, []).append((TMPFILES_DIRS.index(directory), record, item))
    effective: list[tuple[str, str]] = []
    for name in sorted(by_name, key=lambda n: n.encode('utf-8', 'surrogatepass')):
        candidates = sorted(by_name[name], key=lambda entry: entry[0])
        _, winner, item = candidates[0]
        for _, record, _ in candidates[1:]:
            record.update(status='overridden', overridden_by=winner['path'])
        source, text = winner['path'], item.get('text')
        if item.get('type', 'file') == 'symlink' and text is None:
            target = item.get('link_target')
            target = (posixpath.normpath(posixpath.join(winner['directory'], target))
                      if isinstance(target, str) and target and len(target) <= 4096 else None)
            if target == '/dev/null':
                winner.update(status='masked', reason='symlink_to_dev_null')
                continue
            linked = items.get(target) if target else None
            if linked is None or linked.get('type', 'file') != 'file':
                winner.update(status='unreadable', reason='symlink_not_followed')
                _gap(gaps, 'symlink_not_followed', winner['path'],
                     detail='The link target was not read; lower-priority files of this name stay overridden.')
                continue
            winner.update(link_target=target)
            source, text = target, linked.get('text')
        decoded = _decode(source, text, gaps)
        if decoded is None:
            winner.update(status='unreadable', reason=gaps[-1]['code'])
            continue
        winner.update(status='effective', sha256=_sha(decoded.encode('utf-8')))
        effective.append((winner['path'], decoded))
    return records, effective


def _argument(data: bytes | None) -> dict[str, Any] | None:
    if data is None:
        return None
    shown = data[:MAX_SHOWN].decode('utf-8', 'replace')
    return {'text': shown, 'length': len(data), 'truncated': len(data) > MAX_SHOWN, 'sha256': _sha(data)}


def _parse_line(source: str, number: int, line: str, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Parse one stripped, non-comment line. Returns an item or ``None`` when systemd rejects it."""
    raw_type = line.split(None, 1)[0]
    base = raw_type[0]
    writing = base in WRITING
    try:
        words, rest = split_fields(line)
    except _Unparsed as exc:
        if writing:
            _gap(gaps, 'line_unparsed', source, number, f'The line could not be split ({exc}).')
        return None
    if len(words) < 2 or base not in KNOWN_TYPES:
        return None
    action, path = words[0], words[1]
    modifiers = action[1:]
    if any(m not in KNOWN_MODIFIERS for m in modifiers) or len(set(modifiers)) != len(modifiers):
        if writing:
            _gap(gaps, 'modifier_unsupported', source, number,
                 f'systemd 255 rejects modifiers {modifiers!r}; newer releases may accept them.')
        return None
    fields = list(words[2:6]) + ['-'] * (6 - len(words))
    mode, user, group, age = fields[:4]
    if (mode not in ('', '-') and not mode_valid(mode)) or (age not in ('', '-') and age_status(age) == 'invalid'):
        return None  # systemd logs "Invalid mode" or "Invalid age" and the line never takes the path's slot
    conditional = []
    if not owner_resolved(user) or not owner_resolved(group):
        conditional.append('owner_unresolved')
    if age not in ('', '-') and age_status(age) == 'uncertain':
        conditional.append('age_unmodelled')
    if base == 'C':
        conditional.append('copy_source_unobserved')
    path, path_other = _specifiers(path)
    if not path.startswith('/'):
        return None
    path = simplify_path(path)
    item: dict[str, Any] = {
        'source': source, 'line': number, 'type': base, 'modifiers': modifiers, 'path': path,
        'plus': '+' in modifiers, 'boot_only': '!' in modifiers, 'ignore_errors': '-' in modifiers,
        'glob': base in GLOB_TYPES and any(ch in _GLOB for ch in path),
        'fields': tuple(words[2:6]), 'argument': None, 'argument_other_specifier': False,
        'credential': '^' in modifiers, 'path_specifier_unresolved': path_other,
        'conditional': tuple(conditional),
    }
    if '..' in path.split('/'):
        item['refused'] = 'path_not_normalized'
    argument = None if rest in ('', '-') else rest
    if argument is not None and base in WRITING:
        try:
            unescaped = cunescape(argument)
        except _Unparsed as exc:
            # systemd rejects the line too, but an escape this parser does not model must not hide a write.
            _gap(gaps, 'line_unparsed', source, number, f'The argument could not be unescaped ({exc}).')
            return None
        # v255 specifier_expansion_from_arg unescapes first and then expands specifiers, so "\x25H" is
        # the host name. Base64 ("~") arguments are not expanded.
        text, other = (unescaped, False) if '~' in modifiers else _specifiers(unescaped)
        data = text.encode('utf-8', 'surrogatepass')
        if '~' in modifiers:
            try:
                data = base64.b64decode(''.join(text.split()).encode('ascii'), validate=True)
            except (binascii.Error, ValueError, UnicodeEncodeError):
                return None
        item['argument'], item['argument_other_specifier'] = data, other
    if base == 'w' and argument is None:
        return None
    if base in 'cb' and argument is None:
        return None
    return item


def _identical(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return (a['fields'], a['argument']) == (b['fields'], b['argument'])


def _blocker(existing: list[dict[str, Any]], item: dict[str, Any]) -> dict[str, Any] | None:
    """Return the earlier item for the same path that makes systemd drop ``item``, or ``None``."""
    for old in existing:
        if _identical(old, item):
            continue
        if item['type'] in OWNERSHIP and old['type'] in OWNERSHIP:
            return old
        if ('w' in (item['type'], old['type']) and item['type'] in WRITE_BLOCKERS
                and old['type'] in WRITE_BLOCKERS):
            if not (old['type'] == item['type'] == 'w' and old['plus'] and item['plus']):
                return old
    return None


def _program(kind: str, value: str) -> tuple[bool, str | None]:
    if kind == 'core_pattern':
        if not value.startswith('|'):
            return False, None
        parts = value[1:].split()
        return bool(parts), parts[0] if parts else None
    if kind == 'binfmt_register':
        if len(value) < 2:
            return False, None
        fields = value[1:].split(value[0])
        interpreter = fields[5] if len(fields) > 5 else ''
        return bool(interpreter), interpreter or None
    parts = value.split()
    return bool(parts), parts[0] if parts else None


def _public(item: dict[str, Any]) -> dict[str, Any]:
    out = {key: item[key] for key in ('source', 'line', 'type', 'modifiers', 'path', 'glob', 'boot_only',
                                      'ignore_errors')}
    out['argument'] = _argument(item['argument'])
    if item['credential']:
        out['credential'] = True
    if item['conditional']:
        out['conditional'] = list(item['conditional'])
    return out


def _when(item: dict[str, Any]) -> str:
    if item['type'] == 'w':
        return 'append_if_present' if item['plus'] else 'write_if_present'
    return 'replace' if item['plus'] else 'if_absent'


def resolve(files: Any) -> dict[str, Any]:
    """Resolve captured ``tmpfiles.d`` files.

    ``files`` is an iterable of mappings with ``path``, optional ``type``
    (``file``/``symlink``/``directory``/``other``), ``text`` (str or bytes;
    ``None`` when unreadable) and, for symlinks, ``link_target``.
    """
    gaps: list[dict[str, Any]] = []
    records, effective = _effective_files(files, gaps)
    exact: dict[str, list[dict[str, Any]]] = {}
    globs: dict[str, list[dict[str, Any]]] = {}
    rejected = duplicates = 0
    budget = MAX_LINES
    for source, text in effective:
        for number, raw in enumerate(_EOL.split(text), 1):
            line = raw.strip(_WS)
            if not line or line.startswith('#'):
                continue
            budget -= 1
            if budget < 0:
                _gap(gaps, 'too_many_lines', source, number, f'Only the first {MAX_LINES} lines were parsed.')
                break
            item = _parse_line(source, number, line, gaps)
            if item is None:
                rejected += 1
                continue
            table = globs if item['type'] in GLOB_TYPES else exact
            existing = table.setdefault(item['path'], [])
            blocker = _blocker(existing, item)
            if blocker is not None:
                duplicates += 1
                if blocker['conditional'] and item['type'] in WRITING:
                    _gap(gaps, 'line_validity_unresolved', item['source'], item['line'],
                         f'This line is dropped as a duplicate of {blocker["source"]}:{blocker["line"]}, but '
                         f'systemd rejects that line when {"/".join(blocker["conditional"])} fails on the host, '
                         'and then this line applies.')
                continue
            existing.append(item)
        if budget < 0:
            break
    ordered: list[dict[str, Any]] = []
    for table in (exact, globs):  # tmpfiles applies the non-glob-type map first
        for path_items in table.values():
            ordered.extend(path_items)
    hooks: dict[str, dict[str, Any]] = {
        key: {'kind': spec['kind'], 'trigger': spec['trigger'],
              'paths': sorted(p for p, k in KERNEL_TARGETS.items() if k == key), 'writers': [], 'other_lines': []}
        for key, spec in KERNEL_HOOKS.items()}
    startup: list[dict[str, Any]] = []
    for item in ordered:
        if item['type'] not in WRITING:
            continue
        if item['path_specifier_unresolved']:
            _gap(gaps, 'path_specifier_unresolved', item['source'], item['line'],
                 'The path uses a host-dependent specifier, so its target is not determined.')
            continue
        if item.get('refused'):
            continue
        targets = ([p for p in KERNEL_TARGETS if glob_matches(item['path'], p)] if item['glob']
                   else [item['path']] if item['path'] in KERNEL_TARGETS else [])
        for target in targets:
            public = _public(item)
            public['target'] = target
            writes = item['type'] == 'w' or (item['type'] == 'f' and item['plus'])
            hook = hooks[KERNEL_TARGETS[target]]
            if not writes:
                public['reason'] = ('f writes only when it creates the file, and kernel files exist'
                                    if item['type'] == 'f' else 'Kernel files cannot be linked or copied over.')
                hook['other_lines'].append(public)
                continue
            if item['credential']:
                _gap(gaps, 'credential_unobserved', item['source'], item['line'],
                     'The value comes from a credential that is not observed.')
            if item['argument_other_specifier']:
                _gap(gaps, 'argument_specifier_unresolved', item['source'], item['line'],
                     'The value uses a host-dependent specifier.')
            if item['conditional']:
                _gap(gaps, 'line_validity_unresolved', item['source'], item['line'],
                     f'systemd rejects this line when {"/".join(item["conditional"])} fails on the host, '
                     'so whether it writes the setting is not determined.')
            hook['writers'].append(public)
        location = startup_location(item['path'], item['glob'])
        if location is not None:
            public = _public(item)
            public.update(location=location, when=_when(item))
            if item['credential']:
                _gap(gaps, 'credential_unobserved', item['source'], item['line'],
                     'The content comes from a credential that is not observed.')
            startup.append(public)
    for key, hook in hooks.items():
        last = hook['writers'][-1] if hook['writers'] else None
        hook['last_writer'] = last
        if len(hook['writers']) > 1:
            _gap(gaps, 'multiple_writers', detail=f'{key}: {len(hook["writers"])} lines write this setting; '
                                                  'each write replaces the value, so the last one applies.')
        if last is None or last.get('credential'):
            hook['runs_program'], hook['program'] = None, None
        else:
            value = last['argument']['text'] if last['argument'] else ''
            hook['runs_program'], hook['program'] = _program(hook['kind'], value)
            if last['argument'] and last['argument']['truncated']:
                hook['runs_program'] = hook['runs_program'] or None
    return {
        'contract_version': CONTRACT_VERSION,
        'reference': dict(REFERENCE),
        'complete': not any(g['code'] in BLOCKING for g in gaps),
        'gaps': gaps,
        'files': records,
        'kernel_hooks': hooks,
        'startup_writes': startup,
        'lines_rejected': rejected,
        'lines_duplicate': duplicates,
        'unobserved': list(UNOBSERVED),
        'not_a_verdict': NOT_A_VERDICT,
        'origin': 'not_assessed',
    }
