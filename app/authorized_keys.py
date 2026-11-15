"""Pure OpenSSH ``authorized_keys`` options contract (roadmap F slice, #895).

Takes captured, read-only observations of ``authorized_keys`` files (bounded
text per file) and returns typed per-line records saying whether sshd would
accept the line, which key it authorizes (by ``SHA256:`` fingerprint, never raw
key material), the forced ``command`` it would run at login and the effective
restrictions that apply to the session.

Semantics follow sshd(8) *AUTHORIZED_KEYS FILE FORMAT* and OpenSSH's option
parser (``auth-options.c``):

* Blank lines and lines whose first non-blank character is ``#`` are ignored.
  A line is ``[options] keytype base64 [comment]``. As in sshd, the key type is
  tried first; otherwise the options token runs to the first whitespace outside
  double quotes and the key follows it.
* Options are comma separated and case-insensitive. Values are double quoted;
  ``\\"`` inside quotes is a literal quote and every other backslash is kept.
  An unknown option, a missing quote, a second ``command``/``principals`` or a
  malformed ``expiry-time``/``tunnel`` makes sshd reject the whole line, so the
  record is ``invalid`` with the reason.
* Options apply in order. ``restrict`` removes pty, port, agent, X11 forwarding
  and user rc; a later ``pty``, ``port-forwarding``, ``agent-forwarding``,
  ``X11-forwarding`` or ``user-rc`` re-enables that permission.
* ``command`` is run by sshd through the account's shell (``$SHELL -c``), so it
  is reported verbatim and no argv is guessed.
* sshd uses the first line that parses and matches the presented key. A later
  line for the same key is ``shadowed``; when the earlier line carries a
  ``from=`` restriction the later line may still apply to other sources and is
  reported as ``conditional`` precedence instead, as it is when the earlier
  line's expiry or ``permitopen``/``permitlisten`` syntax is uncertain.

It performs no I/O, never runs a command and never authorizes a response
action. Anything it cannot resolve exactly (unreadable, oversized or over-cap
input, an unknown key type, expiry without a timezone close to the observation
time, ``environment=`` whose effect depends on ``PermitUserEnvironment``,
unvalidated ``permitopen``/``permitlisten`` syntax) is an
explicit coverage gap and is never reported as covered.
"""
from __future__ import annotations

import base64
import binascii
import calendar
import hashlib
import re
import struct
from datetime import datetime
from typing import Any, Iterable

CONTRACT_VERSION = 1
MAX_FILES = 64
MAX_FILE_BYTES = 256 * 1024
MAX_LINES = 4096
MAX_LINE_CHARS = 16 * 1024
MAX_OPTIONS = 64
MAX_VALUE_CHARS = 4096
MAX_COMMENT_CHARS = 256
# Local-time expiry is interpreted in the server's zone, which is not observed.
# Real zone offsets span UTC-12 to UTC+14.
_LOCAL_EXPIRY_MARGIN_SECONDS = 14 * 3600

KEY_TYPES = frozenset({
    'ssh-rsa', 'ssh-dss', 'ssh-ed25519', 'ssh-xmss@openssh.com',
    'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
    'sk-ecdsa-sha2-nistp256@openssh.com', 'sk-ssh-ed25519@openssh.com',
    'ssh-rsa-cert-v01@openssh.com', 'ssh-dss-cert-v01@openssh.com',
    'ssh-ed25519-cert-v01@openssh.com', 'ssh-xmss-cert-v01@openssh.com',
    'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
    'ecdsa-sha2-nistp521-cert-v01@openssh.com',
    'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com',
})

PERMISSIONS = ('pty', 'port_forwarding', 'agent_forwarding', 'x11_forwarding', 'user_rc')
# Flag option -> (permission, value). ``restrict`` is handled separately.
_FLAGS = {
    'pty': ('pty', True), 'no-pty': ('pty', False),
    'port-forwarding': ('port_forwarding', True), 'no-port-forwarding': ('port_forwarding', False),
    'agent-forwarding': ('agent_forwarding', True), 'no-agent-forwarding': ('agent_forwarding', False),
    'x11-forwarding': ('x11_forwarding', True), 'no-x11-forwarding': ('x11_forwarding', False),
    'user-rc': ('user_rc', True), 'no-user-rc': ('user_rc', False),
}
_MARKERS = {'cert-authority': 'cert_authority', 'no-touch-required': 'no_touch_required',
            'verify-required': 'verify_required'}
# sshd's ``opt_flag(name, allow_negate=1)`` accepts both spellings of these
# FIDO flags; the last one on the line wins.
_NEGATABLE_MARKERS = {'touch-required': ('no_touch_required', False),
                      'no-touch-required': ('no_touch_required', True),
                      'verify-required': ('verify_required', True),
                      'no-verify-required': ('verify_required', False)}
# OpenSSH ``SSH_TUNID_MAX`` is ``0x7fffffff - 2``.
_TUNNEL_ID_MAX = 0x7fffffff - 2
_SINGLE_VALUES = ('command', 'principals')
_LIST_VALUES = ('environment', 'from', 'permitopen', 'permitlisten')
_VALUE_OPTIONS = frozenset(_SINGLE_VALUES + _LIST_VALUES + ('expiry-time', 'tunnel'))
_OPTION_NAME_RE = re.compile(r'[A-Za-z0-9-]+')
_EXPIRY_RE = re.compile(r'^(\d{8})(\d{4}(\d{2})?)?(Z)?$')
_ENV_NAME_RE = re.compile(r'^[A-Za-z0-9_]+=')
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')


class _Reject(Exception):
    """sshd would refuse this line; ``reason`` is the operator-facing cause."""

    def __init__(self, kind: str, reason: str) -> None:
        super().__init__(reason)
        self.kind = kind
        self.reason = reason


def _gap(kind: str, detail: str, **extra: Any) -> dict[str, Any]:
    gap = {'kind': kind, 'detail': detail}
    gap.update({k: v for k, v in extra.items() if v is not None})
    return gap


def _skip_options(line: str) -> int:
    """Index just past the options token, mirroring ``sshkey_advance_past_options``."""
    quoted = False
    i = 0
    while i < len(line) and (quoted or line[i] not in ' \t'):
        if line[i] == '\\' and i + 1 < len(line) and line[i + 1] == '"':
            i += 1
        elif line[i] == '"':
            quoted = not quoted
        i += 1
    if quoted:
        raise _Reject('unbalanced_quotes', 'Options have an unterminated double quote.')
    return i


def _dequote(text: str, pos: int, name: str) -> tuple[str, int]:
    """OpenSSH ``opt_dequote``: ``\\"`` is a quote, other backslashes are literal."""
    if pos >= len(text) or text[pos] != '"':
        raise _Reject('missing_quote', f'Option "{name}" needs a double-quoted value.')
    pos += 1
    out: list[str] = []
    while pos < len(text) and text[pos] != '"':
        if text[pos] == '\\' and pos + 1 < len(text) and text[pos + 1] == '"':
            pos += 1
        out.append(text[pos])
        pos += 1
    if pos >= len(text):
        raise _Reject('missing_quote', f'Option "{name}" has no closing double quote.')
    value = ''.join(out)
    if len(value) > MAX_VALUE_CHARS:
        raise _Reject('over_cap', f'Option "{name}" exceeds {MAX_VALUE_CHARS} characters.')
    return value, pos + 1


def _parse_expiry(value: str) -> dict[str, Any]:
    # sshd accepts YYYYMMDD, YYYYMMDDHHMM or YYYYMMDDHHMMSS, optionally with Z.
    match = _EXPIRY_RE.match(value)
    if not match:
        raise _Reject('invalid_expiry', 'expiry-time must be YYYYMMDD[HHMM[SS]][Z].')
    digits = match.group(1) + (match.group(2) or '0000')
    if len(digits) == 12:
        digits += '00'
    try:
        moment = datetime.strptime(digits, '%Y%m%d%H%M%S')
    except ValueError:
        raise _Reject('invalid_expiry', 'expiry-time is not a valid calendar time.') from None
    return {'value': value, 'utc': bool(match.group(4)), 'epoch': calendar.timegm(moment.timetuple())}


def _parse_options(text: str) -> dict[str, Any]:
    perms = dict.fromkeys(PERMISSIONS, True)
    opts: dict[str, Any] = {'order': [], 'command': None, 'principals': None, 'tunnel': None,
                            'expiry': None, **{k: [] for k in _LIST_VALUES},
                            **dict.fromkeys(_MARKERS.values(), False), 'restrict': False}
    pos = 0
    while pos < len(text):
        match = _OPTION_NAME_RE.match(text, pos)
        if not match:
            raise _Reject('bad_option_syntax', f'Unexpected character {text[pos]!r} in options.')
        name = match.group(0).lower()
        pos = match.end()
        if len(opts['order']) >= MAX_OPTIONS:
            raise _Reject('over_cap', f'More than {MAX_OPTIONS} options on one line.')
        opts['order'].append(name)
        if name in _VALUE_OPTIONS:
            if pos >= len(text) or text[pos] != '=':
                raise _Reject('missing_value', f'Option "{name}" needs ="value".')
            value, pos = _dequote(text, pos + 1, name)
            if name in _SINGLE_VALUES:
                if opts[name] is not None:
                    raise _Reject('duplicate_option', f'sshd refuses more than one "{name}" option.')
                opts[name] = value
            elif name == 'expiry-time':
                expiry = _parse_expiry(value)
                if opts['expiry'] is None or expiry['epoch'] < opts['expiry']['epoch']:
                    opts['expiry'] = expiry  # sshd keeps the earliest expiry.
            elif name == 'tunnel':
                # ``a2tun`` compares "any" case-insensitively.
                if not (value.lower() == 'any' or (value.isdigit() and int(value) <= _TUNNEL_ID_MAX)):
                    raise _Reject('invalid_tunnel', 'tunnel must be a device number or "any".')
                opts['tunnel'] = value
            else:
                if name == 'environment' and not _ENV_NAME_RE.match(value):
                    raise _Reject('invalid_environment', 'environment must be NAME=value.')
                opts[name].append(value)
        elif name == 'restrict':
            opts['restrict'] = True
            perms.update(dict.fromkeys(PERMISSIONS, False))
        elif name in _FLAGS:
            perm, allowed = _FLAGS[name]
            perms[perm] = allowed
        elif name in _NEGATABLE_MARKERS:
            marker, enabled = _NEGATABLE_MARKERS[name]
            opts[marker] = enabled
        elif name in _MARKERS:
            opts[_MARKERS[name]] = True
        else:
            raise _Reject('unknown_option', f'sshd does not recognise option "{name}".')
        if pos < len(text):
            if text[pos] != ',':
                raise _Reject('bad_option_syntax', 'Options must be separated by commas.')
            pos += 1
            if pos == len(text):
                raise _Reject('bad_option_syntax', 'Options end with a trailing comma.')
    opts['permissions'] = perms
    return opts


def _key_identity(key_type: str, blob_text: str) -> dict[str, Any]:
    if not _BASE64_RE.match(blob_text):
        raise _Reject('bad_key', 'Key data is not base64.')
    try:
        blob = base64.b64decode(blob_text, validate=True)
    except (binascii.Error, ValueError):
        raise _Reject('bad_key', 'Key data is not valid base64.') from None
    if len(blob) < 4:
        raise _Reject('bad_key', 'Key data is truncated.')
    (size,) = struct.unpack('>I', blob[:4])
    embedded = blob[4:4 + size]
    if size > len(blob) - 4 or embedded != key_type.encode():
        raise _Reject('key_type_mismatch', 'Encoded key type does not match the declared key type.')
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    return {'fingerprint': 'SHA256:' + digest, 'key_blob_bytes': len(blob)}


def _split_key(rest: str) -> tuple[str, str, str]:
    parts = rest.split(None, 2)
    if len(parts) < 2:
        raise _Reject('bad_key', 'No key data after the key type.')
    return parts[0], parts[1], parts[2] if len(parts) == 3 else ''


def parse_line(line: str, *, now: float | None = None) -> dict[str, Any]:
    """Assess one non-comment ``authorized_keys`` line."""
    record: dict[str, Any] = {'status': 'invalid', 'key_type': None, 'fingerprint': None, 'comment': None,
                              'options': None, 'command': None, 'gaps': []}
    try:
        if len(line) > MAX_LINE_CHARS:
            raise _Reject('over_cap', f'Line exceeds {MAX_LINE_CHARS} characters.')
        first = line.split(None, 1)[0]
        if first in KEY_TYPES:
            options_text, rest = '', line
        else:
            end = _skip_options(line)
            options_text, rest = line[:end], line[end:].lstrip(' \t')
            if not rest:
                raise _Reject('bad_key', 'No key after the options.')
        key_type, blob_text, comment = _split_key(rest)
        if key_type not in KEY_TYPES:
            record['status'] = 'unknown'
            record['key_type'] = key_type[:64]
            record['gaps'].append(_gap('unknown_key_type', 'Key type is not one this contract recognises.'))
            return record
        record['key_type'] = key_type
        record.update(_key_identity(key_type, blob_text))
        record['comment'] = comment[:MAX_COMMENT_CHARS] or None
        if len(comment) > MAX_COMMENT_CHARS:
            record['gaps'].append(_gap('comment_truncated', f'Comment shortened to {MAX_COMMENT_CHARS} characters.'))
        opts = _parse_options(options_text)
    except _Reject as reject:
        record['reason'] = reject.reason
        record['reject_kind'] = reject.kind
        return record
    record['options'] = opts['order']
    record['command'] = opts['command']
    record['command_runs_via'] = 'account_shell_-c' if opts['command'] is not None else None
    record['permissions'] = opts['permissions']
    record['restrict'] = opts['restrict']
    for key in ('principals', 'tunnel', *_LIST_VALUES, *_MARKERS.values()):
        record[key.replace('-', '_')] = opts[key]
    expiry = opts['expiry']
    record['expiry_time'] = expiry and expiry['value']
    record['status'] = 'accepted'
    if opts['environment']:
        record['gaps'].append(_gap('environment_requires_sshd_config',
                                   'environment= only applies when sshd PermitUserEnvironment allows it.'))
    if opts['permitopen'] or opts['permitlisten']:
        record['gaps'].append(_gap('forwarding_spec_unvalidated',
                                   'permitopen/permitlisten host:port syntax is not validated here; sshd '
                                   'refuses the line if a value is malformed.'))
    if expiry and now is not None:
        delta = now - expiry['epoch']
        if expiry['utc'] or abs(delta) > _LOCAL_EXPIRY_MARGIN_SECONDS:
            if delta >= 0:
                record['status'] = 'expired'
        else:
            record['gaps'].append(_gap('expiry_timezone_unknown',
                                       'Local-time expiry is within a day of the observation and the '
                                       'server timezone is not observed.'))
    elif expiry:
        record['gaps'].append(_gap('expiry_unevaluated', 'No observation time was supplied for expiry.'))
    return record


def _expiry_uncertain(record: dict[str, Any]) -> bool:
    return any(gap['kind'] in ('expiry_timezone_unknown', 'expiry_unevaluated') for gap in record['gaps'])


def _forwarding_spec_uncertain(record: dict[str, Any]) -> bool:
    # sshd refuses the whole line (and keeps reading) when a permitopen or
    # permitlisten value is malformed, so such a line may not shadow at all.
    return any(gap['kind'] == 'forwarding_spec_unvalidated' for gap in record['gaps'])


def parse_text(text: str, *, now: float | None = None) -> dict[str, Any]:
    """Assess every line of one ``authorized_keys`` file's text."""
    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    first_valid: dict[tuple[str, bool], dict[str, Any]] = {}
    lines = text.split('\n')
    for number, raw in enumerate(lines, 1):
        line = raw.rstrip('\r').lstrip(' \t')
        if not line or line.startswith('#'):
            continue
        if len(entries) >= MAX_LINES:
            gaps.append(_gap('over_cap', f'Stopped after {MAX_LINES} key lines.', line=number))
            break
        record = parse_line(line, now=now)
        record['line'] = number
        fingerprint = record['fingerprint']
        # sshd skips a matching line whose options fail (expired, from=
        # mismatch) and keeps reading, so only accepted lines can shadow.
        # A cert-authority line only matches certificates signed by that CA,
        # so the CA role and the raw-key role have separate precedence.
        if record['status'] == 'accepted' and fingerprint:
            role = (fingerprint, bool(record.get('cert_authority')))
            earlier = first_valid.get(role)
            if earlier is None:
                first_valid[role] = record
                record['precedence'] = 'first'
            elif earlier['from'] or _expiry_uncertain(earlier) or _forwarding_spec_uncertain(earlier):
                record['precedence'] = 'conditional'
                record['shadowed_by_line'] = earlier['line']
                if earlier['from']:
                    record['gaps'].append(_gap('precedence_depends_on_source',
                                               'An earlier line for this key applies only to some sources (from=).',
                                               line=earlier['line']))
                if _expiry_uncertain(earlier):
                    record['gaps'].append(_gap('precedence_depends_on_expiry',
                                               'An earlier line for this key may already have expired.',
                                               line=earlier['line']))
                if _forwarding_spec_uncertain(earlier):
                    record['gaps'].append(_gap('precedence_depends_on_forwarding_spec',
                                               'An earlier line for this key has unvalidated permitopen/'
                                               'permitlisten values; sshd skips it if one is malformed.',
                                               line=earlier['line']))
            else:
                record['precedence'] = 'shadowed'
                record['shadowed_by_line'] = earlier['line']
                record['status'] = 'shadowed'
        entries.append(record)
    return {'entries': entries, 'gaps': gaps}


def assess(observations: Iterable[dict[str, Any]], *, now: float | None = None) -> dict[str, Any]:
    """Assess captured files.

    Each observation is ``{'path': str, 'account': str|None, 'text': str}`` or,
    when the file could not be read, ``{'path', 'account', 'error': str}``.
    ``truncated: True`` marks text cut at collection. ``now`` is the observation
    time (POSIX seconds) used for ``expiry-time``.
    """
    files: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for index, observation in enumerate(observations):
        if index >= MAX_FILES:
            gaps.append(_gap('over_cap', f'Stopped after {MAX_FILES} files.'))
            break
        path = str(observation.get('path') or '')[:4096]
        account = observation.get('account')
        record: dict[str, Any] = {'path': path, 'account': account, 'status': 'unknown', 'entries': [], 'gaps': []}
        text = observation.get('text')
        if observation.get('error') or not isinstance(text, str):
            record['gaps'].append(_gap('unreadable', str(observation.get('error') or 'No file text captured.')[:512]))
        elif len(text.encode('utf-8', 'surrogateescape')) > MAX_FILE_BYTES or observation.get('truncated'):
            record['gaps'].append(_gap('oversized', f'File exceeds {MAX_FILE_BYTES} bytes or was truncated.'))
        else:
            parsed = parse_text(text, now=now)
            record.update(status='assessed', entries=parsed['entries'])
            record['gaps'].extend(parsed['gaps'])
        files.append(record)
    entries = [entry for item in files for entry in item['entries']]
    summary = {
        'files': len(files),
        'unassessed_files': sum(1 for item in files if item['status'] != 'assessed'),
        'keys': len(entries),
        'accepted': sum(1 for e in entries if e['status'] == 'accepted'),
        'forced_commands': sum(1 for e in entries if e['status'] == 'accepted' and e['command'] is not None),
        'invalid': sum(1 for e in entries if e['status'] == 'invalid'),
        'expired': sum(1 for e in entries if e['status'] == 'expired'),
        'shadowed': sum(1 for e in entries if e['status'] == 'shadowed'),
        'unknown': sum(1 for e in entries if e['status'] == 'unknown'),
    }
    return {'contract_version': CONTRACT_VERSION, 'files': files, 'gaps': gaps, 'summary': summary}
