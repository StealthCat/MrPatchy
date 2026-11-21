"""Pure keepalived script-line contract, first increment (roadmap F slice, #1307).

keepalived runs administrator-configured programs on VRRP state changes, health
checks, LVS events and at startup and shutdown, as root or as a configured
script user. This increment ports, from keepalived 2.2.8 (Ubuntu 24.04
``keepalived_2.2.8-1build2``), the parts that decide *what argv and user a
single script keyword line yields*:

- ``read_line`` and ``decomment`` in ``lib/parser.c``: physical lines are read
  with ``fgets`` into a 1024-byte buffer, trailing ``\\n``/``\\r`` removed,
  comments starting at an unquoted ``!`` or ``#`` removed (``\\!``/``\\#``
  outside double quotes are kept as literal characters), and leading and
  trailing blanks stripped. The first unquoted ``{`` or ``}`` on a line splits
  the line so that every brace ends up on a line of its own.
- ``alloc_strvec_r``: keyword tokenizing, where only double quotes group.
- ``alloc_strvec_quoted_escaped`` and ``notify_script_init`` /
  ``set_script_params_array`` in ``lib/notify.c``: the raw keyword line is
  re-split honouring single and double quotes and backslash escapes; the
  second word is the script, which is split again the same way to form the
  argv; the third and fourth words name the user and group.

Preprocessing that rewrites lines in ways this increment does not model makes
the result incomplete rather than wrong: ``include`` lines, ``$NAME=``
definitions and ``$`` parameter references that a standard definition could
replace (``$_PWD``, ``$_INSTANCE``, ``$_RANDOM``, ``$_HASH``, ``$_BANG``),
``~SEQ``/``~LST`` expansion, ``@``/``@^`` conditional lines when the
``config_id`` was not observed, trailing-backslash continuations and physical
lines too long for keepalived's buffer.

The block walk that assigns these lines to ``global_defs``, ``vrrp_script``,
``vrrp_instance``, ``vrrp_sync_group``, ``virtual_server``, ``real_server``
and ``MISC_CHECK`` blocks, and the resulting per-program inventory, are the
next increment. This module performs no I/O, runs nothing and authorizes
nothing; ``origin`` is always ``not_assessed``.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('2.2.8',)
MAXBUF = 1024
MAX_TEXT = 262144
MAX_GAPS = 64
DEFAULT_SCRIPT_USER = 'keepalived_script'

_WHITE = b' \t\f\n\r\v'
_STD_DEFINITIONS = (b'_PWD', b'_INSTANCE', b'_RANDOM', b'_HASH', b'_BANG')

BLOCKING = frozenset({
    'over_limit', 'binary', 'invalid_utf8', 'line_over_buffer', 'include', 'definition',
    'parameter_expansion', 'sequence', 'conditional_unresolved', 'continuation', 'unterminated_quote',
    'gaps_truncated',
})


def _gap(gaps: list[dict[str, Any]], code: str, line_no: int | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'line': line_no, 'detail': detail[:240], 'blocking': code in BLOCKING})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'line': None, 'detail': 'Further gaps were not recorded.',
                     'blocking': True})


def decomment(line: bytes) -> tuple[bytes, bool]:
    """Port of ``decomment``. Returns the line and whether a quote was left unterminated."""
    buf = bytearray(line.lstrip(b' \t'))
    quote = False
    cont = False
    skip = None
    i = 0
    while i < len(buf):
        c = buf[i]
        if c not in b'!#"\\':
            i += 1
            continue
        if c == 0x22:  # '"'
            if skip is None:
                quote = not quote
            i += 1
            continue
        if c == 0x5c:  # '\\'
            if i + 1 < len(buf):
                if not quote and buf[i + 1] in b'#!':
                    del buf[i]
                    i += 1
                else:
                    i += 2
                continue
            del buf[i:]
            cont = True
            break
        if not quote and skip is None:
            skip = i
        i += 1
    if skip is not None:
        del buf[skip:]
    out = bytes(buf).rstrip(b' \t')
    if cont:
        out += b'\\'
    return out, quote


def split_words(line: bytes) -> list[bytes]:
    """Port of ``alloc_strvec_r``: whitespace split, a leading ``"`` groups up to the next ``"``.

    An unmatched quote is reported by keepalived and ends tokenizing, keeping the earlier words.
    """
    words: list[bytes] = []
    i, n = 0, len(line)
    while True:
        while i < n and line[i] in _WHITE:
            i += 1
        if i >= n:
            break
        if line[i] == 0x22:
            end = line.find(b'"', i + 1)
            if end < 0:
                break
            words.append(line[i + 1:end])
            i = end + 1
        else:
            start = i
            while i < n and line[i] not in _WHITE and line[i] != 0x22:
                i += 1
            words.append(line[start:i])
    return words


def _isxdigit(c: int) -> bool:
    return 0x30 <= c <= 0x39 or 0x41 <= c <= 0x46 or 0x61 <= c <= 0x66


_SIMPLE_ESCAPES = {ord('a'): 7, ord('b'): 8, ord('E'): 0x1b, ord('f'): 12, ord('n'): 10, ord('r'): 13,
                   ord('t'): 9, ord('v'): 11}


def split_quoted_escaped(src: bytes) -> list[bytes] | None:
    """Port of ``alloc_strvec_quoted_escaped``. ``None`` where keepalived returns NULL."""
    words: list[bytes] = []
    i, n = 0, len(src)
    quote = 0
    while i < n:
        while i < n and src[i] in _WHITE:
            i += 1
        if i >= n:
            break
        out = bytearray()
        while i < n:
            if quote == 0x22:
                stops = b'"\\'
            elif quote == 0x27:
                stops = b"'\\"
            else:
                stops = _WHITE + b'\'"\\'
            j = i
            while j < n and src[j] not in stops:
                j += 1
            if j >= n:
                if quote:
                    return None
                out += src[i:]
                i = n
                break
            out += src[i:j]
            i = j
            c = src[i]
            if c == 0x5c:
                i += 1
                if i >= n:
                    return None
                e = src[i]
                if e == ord('x') and i + 1 < n and _isxdigit(src[i + 1]):
                    val = 0
                    i += 1
                    while i < n and _isxdigit(src[i]):
                        val = ((val << 4) | int(chr(src[i]), 16)) & 0xff
                        i += 1
                elif e == ord('c') and i + 1 < n:
                    val = src[i + 1] & 0x1f
                    i += 2
                elif 0x30 <= e <= 0x37:
                    val = e - 0x30
                    i += 1
                    for _ in range(2):
                        if i < n and 0x30 <= src[i] <= 0x37:
                            val = ((val << 3) + src[i] - 0x30) & 0xff
                            i += 1
                else:
                    val = _SIMPLE_ESCAPES.get(e, e)
                    i += 1
                out.append(val)
                continue
            if quote:
                quote = 0
                i += 1
                continue
            if c in (0x22, 0x27):
                quote = c
                i += 1
                continue
            break
        # STRNDUP stops at an embedded NUL produced by an escape.
        nul = out.find(0)
        words.append(bytes(out if nul < 0 else out[:nul]))
    return words or None


def _brace_split(buf: bytes) -> list[bytes]:
    """The ``{``/``}`` residue split at the end of ``read_line``, applied until no residue remains."""
    lines = []
    while buf:
        p = 0
        if buf[0] not in b'{}':
            p = -1
            k = 0
            while True:
                k = _find_any(buf, b'{}"', k)
                if k < 0:
                    break
                if buf[k] != 0x22:
                    p = k
                    break
                close = buf.find(b'"', k + 1)
                if close < 0:
                    break
                k = close + 1
        residue = b''
        if p >= 0:
            if p == 0:
                skip = 1
                while skip < len(buf) and buf[skip] in b' \t':
                    skip += 1
            else:
                skip = 0
            if p + skip < len(buf):
                residue = buf[p + skip:].rstrip(b' \t')
                buf = buf[:p + skip]
        buf = buf.rstrip(b' \t')
        if buf:
            lines.append(buf)
        buf = residue
    return lines


def _find_any(buf: bytes, chars: bytes, start: int) -> int:
    for k in range(start, len(buf)):
        if buf[k] in chars:
            return k
    return -1


def _is_include(buf: bytes) -> bool:
    if not buf.startswith(b'include') or len(buf) == 7:
        return False
    if buf[7:8].isspace():
        return True
    return len(buf) > 8 and buf[8:9].isspace() and buf[7:8] in (b'r', b'm', b'w', b'b', b'a')


def _could_expand(buf: bytes) -> bool:
    """Whether ``replace_param`` could change the line when only the standard definitions exist."""
    k = buf.find(b'$')
    while 0 <= k < len(buf) - 1:
        rest = buf[k + 1:]
        if rest.startswith(b'{'):
            rest = rest[1:]
        if any(rest.startswith(name) for name in _STD_DEFINITIONS):
            return True
        k = buf.find(b'$', k + 1)
    return False


def logical_lines(text: Any, *, config_id: str | None = None) -> dict[str, Any]:
    """Turn captured configuration text into the lines keepalived's keyword parser sees.

    ``config_id`` is keepalived's ``-i``/``--config-id`` value, or, when none was given, the host name up to
    its first ``.``; ``None`` when it was not observed.
    """
    gaps: list[dict[str, Any]] = []
    data = text.encode('utf-8', 'surrogatepass') if isinstance(text, str) else bytes(text)
    if len(data) > MAX_TEXT:
        _gap(gaps, 'over_limit')
        return _lines_result([], gaps)
    if b'\0' in data:
        _gap(gaps, 'binary')
        return _lines_result([], gaps)
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        _gap(gaps, 'invalid_utf8')
        return _lines_result([], gaps)
    cid = config_id.encode('utf-8') if config_id is not None else None
    out: list[dict[str, Any]] = []
    for line_no, raw in enumerate(data.split(b'\n'), 1):
        if len(raw) > MAXBUF - 1:
            # fgets would split the physical line into separately parsed pieces.
            _gap(gaps, 'line_over_buffer', line_no)
            continue
        raw = raw.rstrip(b'\r\n')
        if not raw:
            continue
        buf, open_quote = decomment(raw)
        if open_quote:
            _gap(gaps, 'unterminated_quote', line_no)
        if not buf:
            continue
        if buf.endswith(b'\\'):
            _gap(gaps, 'continuation', line_no)
            continue
        if buf[:1] == b'@':
            if cid is None:
                _gap(gaps, 'conditional_unresolved', line_no)
                continue
            rev = buf[1:2] == b'^'
            ofs = 2 if rev else 1
            ws = _find_any(buf, b' \t', ofs)
            if ws < 0:
                continue
            if (buf[ofs:ws] != cid) != rev:
                continue
            buf = buf[ws:].lstrip(b' \t')
        if buf[:1] == b'$':
            _gap(gaps, 'definition', line_no)
            continue
        if buf.startswith((b'~SEQ', b'~LST')):
            _gap(gaps, 'sequence', line_no)
            continue
        if buf[:1] != b'~' and _could_expand(buf):
            _gap(gaps, 'parameter_expansion', line_no)
            continue
        if _is_include(buf):
            _gap(gaps, 'include', line_no)
            continue
        for piece in _brace_split(buf):
            out.append({'line': line_no, 'text': piece})
    return _lines_result(out, gaps)


def _lines_result(lines: list, gaps: list) -> dict[str, Any]:
    return {'lines': lines, 'gaps': gaps, 'complete': not any(g['blocking'] for g in gaps)}


def script_line(line: bytes, *, user_offset: int = 2) -> dict[str, Any]:
    """Port of ``notify_script_init``: the argv and configured user/group a script keyword line yields.

    ``status`` is ``ok`` or ``ignored`` (keepalived logs and drops the script). ``user`` is ``None`` when
    the line names none, which means the default script user: ``script_user`` from ``global_defs`` when set,
    otherwise ``keepalived_script`` when that account exists, otherwise root.
    """
    words = split_quoted_escaped(line)
    if not words:
        return {'status': 'ignored', 'reason': 'unparsable_line', 'argv': None, 'user': None, 'group': None}
    argv = split_quoted_escaped(words[1]) if len(words) >= 2 else None
    if not argv:
        return {'status': 'ignored', 'reason': 'no_script', 'argv': None, 'user': None, 'group': None}
    user = words[user_offset] if len(words) > user_offset else None
    group = words[user_offset + 1] if len(words) > user_offset + 1 else None
    return {'status': 'ok', 'reason': None, 'argv': [_text(a) for a in argv],
            'user': _text(user) if user is not None else None,
            'group': _text(group) if group is not None else None}


def _text(value: bytes) -> str:
    return value.decode('utf-8', 'surrogateescape')
