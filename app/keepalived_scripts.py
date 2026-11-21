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

Increment 2 adds ``vrrp_programs``: an emulation of ``process_stream`` and
``alloc_value_block`` as the VRRP child process runs them, with the 2.2.8
keyword tables for ``vrrp_instance``, ``vrrp_sync_group`` and ``vrrp_script``
(every build-conditional keyword is present in the Ubuntu binary). It reports
each notify and ``vrrp_script`` program with its argv, its configured or
default user and its source block. Structure keepalived would report as a
configuration error (unknown keywords, unexpected or missing braces,
unbalanced or unterminated blocks) is a blocking gap, because a ``}`` that
binds to the wrong level silently moves later scripts.

Increment 3 models ``global_defs`` (``core/global_parser.c``) in the two
processes that run its scripts. The parent alone runs ``startup_script`` and
``shutdown_script`` (``startup_shutdown_script`` returns early in children),
and the parent parses every other root block as inactive, so its default-user
lookups come from ``global_defs`` only. The VRRP child runs
``notify_fifo_script`` and ``vrrp_notify_fifo_script`` when the matching
``notify_fifo``/``vrrp_notify_fifo`` is named (``fifo_open``), with the FIFO
path appended as the last argument; a ``vrrp_notify_fifo`` that names the
global FIFO is dropped with its script (``init_global_data``). The VRRP child
starts only when the configuration has ``vrrp_instance`` or ``static_*`` roots
(``have_vrrp_config``) unless keepalived runs with ``--all``. Default-user
failure is sticky (``default_user_fail``): a later ``script_user`` does not
undo it. ``lvs_notify_fifo_script`` runs in the checker process and, with the
checker's ``virtual_server`` scripts, stays a blocking gap.

This module performs no I/O, runs nothing and authorizes nothing; ``origin``
is always ``not_assessed``.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 3
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
    'gaps_truncated', 'unknown_keyword', 'unexpected_brace', 'missing_brace', 'unbalanced_brace',
    'unterminated_block', 'unmodelled_nested_block', 'unnamed_block', 'unparsable_script',
    'checker_not_modelled', 'default_user_unobserved', 'missing_user', 'vrrp_process_start_unobserved',
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



# --- Increment 2: the VRRP process block walk -------------------------------------------------------

# lib/notify.c set_vrrp_notify_script extra_params: ``notify`` gets type, name, state and priority appended.
_NOTIFY_EXTRA = {'notify': 4}
_VRRP_NOTIFY = ('notify_backup', 'notify_master', 'notify_fault', 'notify_stop', 'notify')
_INSTANCE_NOTIFY = _VRRP_NOTIFY + ('notify_deleted', 'notify_master_rx_lower_pri')
_TRACK_VALUE = ('track_interface', 'track_script', 'track_file', 'track_process', 'track_bfd')

# vrrp/vrrp_parser.c init_vrrp_keywords, keepalived 2.2.8.
SYNC_GROUP_KEYWORDS = {
    **{k: 'value' for k in ('group',) + _TRACK_VALUE},
    **{k: 'script' for k in _VRRP_NOTIFY},
    **{k: 'plain' for k in ('smtp_alert', 'global_tracking', 'sync_group_tracking_weight',
                            'notify_priority_changes')},
}
INSTANCE_KEYWORDS = {
    **{k: 'value' for k in ('unicast_peer', 'virtual_ipaddress', 'virtual_ipaddress_excluded', 'virtual_routes',
                            'virtual_rules') + _TRACK_VALUE},
    **{k: 'script' for k in _INSTANCE_NOTIFY},
    'authentication': 'auth',
    **{k: 'plain' for k in (
        'use_vmac', 'use_vmac_addr', 'vmac_xmit_base', 'use_ipvlan', 'unicast_fault_no_peer', 'check_unicast_src',
        'old_unicast_checksum', 'native_ipv6', 'state', 'interface', 'vrf', 'dont_track_primary', 'mcast_src_ip',
        'unicast_src_ip', 'mcast_dst_ip', 'track_src_ip', 'virtual_router_id', 'unicast_ttl', 'version',
        'priority', 'advert_int', 'no_virtual_ipaddress', 'promote_secondaries', 'linkbeat_use_polling',
        'v3_checksum_as_v2', 'accept', 'no_accept', 'skip_check_adv_addr', 'strict_mode', 'preempt', 'nopreempt',
        'preempt_delay', 'debug', 'smtp_alert', 'notify_priority_changes', 'lvs_sync_daemon_interface',
        'garp_master_delay', 'garp_master_refresh', 'garp_master_repeat', 'garp_master_refresh_repeat',
        'garp_lower_prio_delay', 'garp_lower_prio_repeat', 'down_timer_adverts', 'timer_expired_backup',
        'garp_extra_if', 'vmac_garp_intvl', 'lower_prio_no_advert', 'higher_prio_send_advert',
        'kernel_rx_buf_size')},
}
AUTH_KEYWORDS = {'auth_type': 'plain', 'auth_pass': 'plain'}
SCRIPT_KEYWORDS = {'script': 'vscript', 'user': 'vuser',
                   **{k: 'plain' for k in ('interval', 'timeout', 'weight', 'rise', 'fall', 'init_fail')}}

# Root keywords every process installs (core/global_parser.c, vrrp/vrrp_parser.c, check/check_parser.c,
# bfd/bfd_parser.c, trackers/track_file.c). In the VRRP process the checker roots are inactive and skipped.
ROOT_KEYWORDS = {
    'vrrp_instance': 'instance', 'vrrp_sync_group': 'sync_group', 'vrrp_script': 'vscript_block',
    'global_defs': 'global_defs',
    **{k: 'value' for k in ('static_ipaddress', 'static_routes', 'static_rules', 'linkbeat_interfaces',
                            'interface_up_down_delays')},
    **{k: 'opaque' for k in ('track_group', 'garp_group', 'vrrp_track_process', 'track_file', 'vrrp_track_file',
                             'bfd_instance')},
    **{k: 'inactive' for k in ('virtual_server', 'virtual_server_group', 'SSL')},
    **{k: 'plain' for k in ('linkbeat_use_polling', 'net_namespace', 'net_namespace_ipvs', 'namespace_with_ipsets',
                            'use_pid_dir', 'instance', 'child_wait_time')},
}
# global_defs FIFO keywords (notify_fifo / notify_fifo_script handlers) by FIFO type.
FIFO_KEYWORDS = {'notify_fifo': 'global', 'vrrp_notify_fifo': 'vrrp', 'lvs_notify_fifo': 'lvs'}
FIFO_SCRIPT_KEYWORDS = {k + '_script': v for k, v in FIFO_KEYWORDS.items()}
PARENT_SCRIPT_KEYWORDS = ('startup_script', 'shutdown_script')
# Root keywords whose handler sets global_data->have_vrrp_config, even with a NULL strvec when inactive.
VRRP_CONFIG_ROOTS = ('vrrp_instance', 'static_ipaddress', 'static_routes', 'static_rules')
_BOB, _EOB = b'{', b'}'


class _Walk:
    def __init__(self, lines: list[dict[str, Any]], gaps: list, keepalived_script_exists: bool | None,
                 process: str = 'vrrp'):
        self.lines, self.pos, self.gaps = lines, 0, gaps
        self.process = process  # 'vrrp' (the VRRP child) or 'parent'
        self.have_vrrp_config = False
        self.fifo_names: dict[str, str] = {}
        self.fifo_scripts: dict[str, dict[str, Any]] = {}
        self.parent_scripts: set = set()
        self.programs: list[dict[str, Any]] = []
        self.ks_exists = keepalived_script_exists
        self.skip = 0  # keepalived's skip_sublevel
        self.default: dict[str, Any] | None = None  # cached get_default_script_user result
        self.script_user: tuple[str, str | None] | None = None
        self.security = False
        self.names: dict[str, set] = {'instance': set(), 'sync_group': set()}

    def next(self):
        while self.pos < len(self.lines):
            item = self.lines[self.pos]
            self.pos += 1
            words = split_words(item['text'])
            if words:
                return item, words
        return None, None

    # get_default_script_user / set_default_script_user in lib/notify.c
    def default_user(self, line_no: int) -> dict[str, Any]:
        if self.default is None:
            if self.script_user is not None:
                self.default = {'user': self.script_user[0], 'group': self.script_user[1], 'via': 'script_user'}
            elif self.ks_exists is None:
                _gap(self.gaps, 'default_user_unobserved', line_no,
                     'Whether the keepalived_script account exists was not observed.')
                self.default = {'user': None, 'group': None, 'via': 'unobserved'}
            elif self.ks_exists:
                self.default = {'user': DEFAULT_SCRIPT_USER, 'group': None, 'via': 'keepalived_script'}
            elif self.security:
                self.default = {'user': None, 'group': None, 'via': 'refused'}
            else:
                self.default = {'user': 'root', 'group': None, 'via': 'daemon_user'}
        return self.default

    def record(self, block: dict, keyword: str, parsed: dict, line_no: int, extra: int = 0) -> dict | None:
        if parsed['status'] != 'ok':
            return None
        entry = self.entry(block['kind'], block['name'], keyword, line_no, parsed['argv'], extra)
        entry.update(user=parsed['user'], group=parsed['group'])
        if parsed['user'] is None:
            self.apply_default(entry, line_no)
        self.programs.append(entry)
        return entry

    def entry(self, block: str, name: str | None, keyword: str, line_no: int, argv: list, extra: int) -> dict:
        return {'process': self.process, 'block': block, 'name': name, 'keyword': keyword, 'line': line_no,
                'argv': argv, 'runtime_extra_args': extra, 'user': None, 'group': None,
                'user_source': 'configured', 'runs': True, 'not_run_reason': None, 'origin': 'not_assessed'}

    def apply_default(self, entry: dict, line_no: int) -> None:
        d = self.default_user(line_no)
        entry.update(user=d['user'], group=d['group'], user_source='default:' + d['via'])
        if d['via'] == 'refused':
            # keepalived drops the script: no keepalived_script account and script security enabled.
            entry.update(runs=False, not_run_reason='default_user_refused')

    def skip_block(self, need_bob: bool) -> None:
        self.skip = -1 if need_bob else 1

    # process_stream(keywords_vec, need_bob)
    def stream(self, table: dict | None, need_bob: bool, level: int, block: dict | None) -> bool:
        while True:
            item, words = self.next()
            if item is None:
                if level > 0:
                    _gap(self.gaps, 'unterminated_block', None, 'The configuration ended inside a block.')
                return False
            line_no, first = item['line'], words[0]
            if self.skip == -1:
                if first == _BOB:
                    self.skip, need_bob = 1, False
                    continue
                self.skip = 0
            if self.skip:
                for w in words:
                    if w == _BOB:
                        self.skip += 1
                    elif w == _EOB:
                        self.skip -= 1
                        if self.skip == 0:
                            break
                if w == _EOB and self.skip == 0 and level > 0:
                    return True
                continue
            if need_bob:
                need_bob = False
                if first == _BOB and level > 0:
                    continue
                _gap(self.gaps, 'missing_brace', line_no, 'A block keyword was not followed by "{".')
            elif first == _BOB:
                _gap(self.gaps, 'unexpected_brace', line_no, 'keepalived ignores this "{", so its "}" closes the '
                     'enclosing block.')
                continue
            if first == _EOB:
                if level > 0:
                    return False
                _gap(self.gaps, 'unbalanced_brace', line_no, 'A "}" has no open block.')
                continue
            self.keyword(table, words, item, level, block)

    def keyword(self, table: dict | None, words: list, item: dict, level: int, block: dict | None) -> None:
        line_no, name = item['line'], words[0].decode('utf-8', 'surrogateescape')
        kind = table.get(name) if table is not None else None
        if kind is None:
            _gap(self.gaps, 'unknown_keyword', line_no, f'keepalived 2.2.8 has no {name!r} keyword here.')
            return
        if level == 0 and name in VRRP_CONFIG_ROOTS:
            self.have_vrrp_config = True
        if level == 0 and self.process == 'parent' and kind != 'global_defs':
            # global_init_keywords installs every non-global root inactive: skip_sublevel, no handler work.
            self.skip_block(words[-1] != _BOB or len(words) == 1)
            if kind != 'plain':
                self.stream(None, words[-1] != _BOB or len(words) == 1, level + 1, None)
            return
        if kind == 'plain':
            return
        if kind == 'value':
            self.value_block(words, line_no)
            return
        if kind == 'script':
            seen = block['seen']
            if name in seen:
                return  # "notify script already specified - ignoring"
            parsed = script_line(item['text'])
            entry = self.record(block, name, parsed, line_no, _NOTIFY_EXTRA.get(name, 0))
            if entry is None:
                _gap(self.gaps, 'unparsable_script', line_no, 'keepalived logs and ignores this script.')
            elif entry['runs']:
                seen.add(name)  # a dropped script leaves the slot free for a later line
            return
        if kind == 'vscript':
            parsed = script_line(item['text'])
            if parsed['status'] == 'ok':
                block['script'] = (parsed['argv'], line_no)
            else:
                _gap(self.gaps, 'unparsable_script', line_no, 'keepalived keeps the earlier script, if any.')
            return
        if kind == 'vuser':
            if len(words) < 2:
                _gap(self.gaps, 'missing_user', line_no, 'keepalived drops a vrrp_script whose user is invalid.')
                block['user_error'] = True
                return
            block['user'] = (_text(words[1]), _text(words[2]) if len(words) > 2 else None)
            block['user_error'] = False
            return
        bob_needed = self.strip_bob(words)
        if kind == 'auth':
            self.stream(AUTH_KEYWORDS, bob_needed, level + 1, block)
        elif kind == 'inactive':
            self.skip_block(bob_needed)
            _gap(self.gaps, 'checker_not_modelled', line_no, f'{name} scripts run in the checker process, '
                 'which this contract does not model yet.')
            self.stream(None, bob_needed, level + 1, None)
        elif kind in ('instance', 'sync_group'):
            self.named_block(kind, words, item, bob_needed, level)
        elif kind == 'vscript_block':
            self.vscript_block(words, item, bob_needed, level)
        else:
            self.opaque_block(name, bob_needed, level)

    @staticmethod
    def strip_bob(words: list) -> bool:
        if words[-1] == _BOB and len(words) > 1:
            words.pop()
            return False
        return True

    def named_block(self, kind: str, words: list, item: dict, bob_needed: bool, level: int) -> None:
        table = INSTANCE_KEYWORDS if kind == 'instance' else SYNC_GROUP_KEYWORDS
        block = {'kind': 'vrrp_instance' if kind == 'instance' else 'vrrp_sync_group', 'name': None, 'seen': set()}
        if len(words) != 2:
            _gap(self.gaps, 'unnamed_block', item['line'], f'keepalived skips a {block["kind"]} without one name.')
            self.skip_block(True)
        else:
            block['name'] = _text(words[1])
            if block['name'] in self.names[kind]:
                self.skip_block(True)  # "already defined": skipped, not an error that hides programs
            self.names[kind].add(block['name'])
        self.stream(table, bob_needed, level + 1, block)

    def vscript_block(self, words: list, item: dict, bob_needed: bool, level: int) -> None:
        if len(words) < 2:
            _gap(self.gaps, 'unnamed_block', item['line'], 'A vrrp_script has no name.')
            self.skip_block(True)
            self.stream(None, bob_needed, level + 1, None)
            return
        block = {'kind': 'vrrp_script', 'name': _text(words[1]), 'script': None, 'user': None, 'user_error': False}
        if self.stream(SCRIPT_KEYWORDS, bob_needed, level + 1, block):
            return
        # vrrp_vscript_end_handler
        if block['script'] is None or block['user_error']:
            return
        argv, line_no = block['script']
        entry = self.entry('vrrp_script', block['name'], 'script', line_no, argv, 0)
        if block['user'] is not None:
            entry['user'], entry['group'] = block['user']
        else:
            self.apply_default(entry, line_no)
        self.programs.append(entry)

    def opaque_block(self, name: str, bob_needed: bool, level: int) -> None:
        """Known roots whose keywords run no program: walked for structure, and global_defs for the script user."""
        while True:
            item, words = self.next()
            if item is None:
                _gap(self.gaps, 'unterminated_block', None, f'The configuration ended inside {name}.')
                return
            first = words[0]
            if bob_needed:
                bob_needed = False
                if first == _BOB:
                    continue
                _gap(self.gaps, 'missing_brace', item['line'], f'{name} was not followed by "{{".')
            if first == _EOB:
                return
            if first == _BOB:
                _gap(self.gaps, 'unmodelled_nested_block', item['line'], f'A nested block in {name} is not modelled.')
                self.skip = 1
                self.stream(None, False, level + 2, None)
                continue
            if name != 'global_defs':
                continue
            self.global_keyword(_text(first), words, item)

    def global_keyword(self, key: str, words: list, item: dict) -> None:
        line_no = item['line']
        if key == 'notification_email':
            self.value_block(words, line_no)
        elif key == 'script_user' and len(words) >= 2:
            # set_default_script_user: later default lookups use it; earlier ones keep their result. A failed
            # default lookup is sticky (default_user_fail), so a later script_user cannot revive defaults.
            if self.default is None or self.default['via'] != 'refused':
                self.script_user = (_text(words[1]), _text(words[2]) if len(words) > 2 else None)
                self.default = None
        elif key == 'enable_script_security':
            self.security = True
        elif key in FIFO_KEYWORDS and len(words) >= 2:
            fifo = FIFO_KEYWORDS[key]
            if fifo in self.fifo_names:
                return  # "notify_fifo already specified - ignoring"
            if len(words) == 2 and self.default_user(line_no)['via'] == 'refused':
                return  # "Failed to set default user for fifo - ignoring"
            self.fifo_names[fifo] = _text(words[1])
        elif key in FIFO_SCRIPT_KEYWORDS and len(words) >= 2:
            fifo = FIFO_SCRIPT_KEYWORDS[key]
            if fifo in self.fifo_scripts:
                return  # "notify_fifo_script already specified - ignoring"
            if fifo == 'lvs' and self.process == 'vrrp':
                _gap(self.gaps, 'checker_not_modelled', line_no, 'lvs_notify_fifo_script runs in the checker '
                     'process, which this contract does not model yet.')
            entry = self.global_script(key, item, 1)
            if entry is not None and entry['runs']:
                entry['fifo_type'] = fifo
                self.fifo_scripts[fifo] = entry
        elif key in PARENT_SCRIPT_KEYWORDS and self.process == 'parent' and len(words) >= 2:
            if key in self.parent_scripts:
                return  # "startup script already specified"
            entry = self.global_script(key, item, 0)
            if entry is not None and entry['runs']:
                self.parent_scripts.add(key)
                self.programs.append(entry)

    def global_script(self, key: str, item: dict, extra: int) -> dict | None:
        """notify_script_init for a global_defs script; the default-user lookup happens here in every process."""
        parsed = script_line(item['text'])
        if parsed['status'] != 'ok':
            _gap(self.gaps, 'unparsable_script', item['line'], f'keepalived logs and ignores this {key}.')
            return None
        entry = self.entry('global_defs', None, key, item['line'], parsed['argv'], extra)
        entry.update(user=parsed['user'], group=parsed['group'])
        if parsed['user'] is None:
            self.apply_default(entry, item['line'])
        return entry

    def finish_fifos(self) -> None:
        """init_global_data and fifo_open for the VRRP child: which FIFO scripts it starts."""
        names = self.fifo_names
        if names.get('vrrp') is not None and names.get('vrrp') == names.get('global'):
            # "notify FIFO has been specified for global and vrrp FIFO - ignoring vrrp FIFO"
            names.pop('vrrp')
            self.fifo_scripts.pop('vrrp', None)
        for fifo in ('global', 'vrrp'):
            entry = self.fifo_scripts.get(fifo)
            if entry is None:
                continue
            entry['fifo'] = names.get(fifo)
            if entry['fifo'] is None:
                entry.update(runs=False, not_run_reason='no_fifo')
            self.programs.append(entry)

    def value_block(self, words: list, line_no: int) -> None:
        """alloc_value_block: lines up to the first line ending in "}" are values, never keywords."""
        need_bob = True
        if len(words) > 1 and words[1] == _BOB:
            need_bob = False
            if len(words) > 2 and words[-1] == _EOB:
                return
        while True:
            item, vec = self.next()
            if item is None:
                _gap(self.gaps, 'unterminated_block', line_no, 'The configuration ended inside a value block.')
                return
            if need_bob:
                need_bob = False
                if vec[0] == _BOB:
                    if len(vec) == 1:
                        continue
                    vec = vec[1:]
                else:
                    _gap(self.gaps, 'missing_brace', item['line'], 'A value block was not opened with "{".')
            if vec[-1] == _EOB:
                return


def _readable(gaps: list) -> bool:
    return not any(g['code'] in ('over_limit', 'binary', 'invalid_utf8') for g in gaps)


def _vrrp_walk(pre: dict, keepalived_script_exists: bool | None, run_all_children: bool | None) -> tuple:
    gaps = list(pre['gaps'])
    walk = _Walk(pre['lines'], gaps, keepalived_script_exists)
    starts: bool | None = False
    if _readable(gaps):
        walk.stream(ROOT_KEYWORDS, False, 0, None)
        walk.finish_fifos()
        starts = True if walk.have_vrrp_config or run_all_children else (None if run_all_children is None else False)
        if starts is not True and walk.programs:
            for entry in walk.programs:
                if entry['runs']:
                    entry.update(runs=starts, not_run_reason='vrrp_process_not_started')
            if starts is None:
                _gap(gaps, 'vrrp_process_start_unobserved', None, 'No vrrp_instance or static_* block starts the '
                     'VRRP process; whether keepalived runs with --all was not observed.')
    return walk, gaps, starts


def vrrp_programs(text: Any, *, config_id: str | None = None, keepalived_script_exists: bool | None = None,
                  run_all_children: bool | None = None) -> dict[str, Any]:
    """Programs the keepalived 2.2.8 VRRP process runs, from one captured, include-free ``keepalived.conf``.

    ``keepalived_script_exists`` says whether that account exists on the host (``None`` when not observed);
    it decides the default script user when ``global_defs`` sets no ``script_user``. ``run_all_children`` is
    whether keepalived was started with ``--all`` (``None`` when not observed); it matters only when the
    configuration has no VRRP configuration of its own.
    """
    pre = logical_lines(text, config_id=config_id)
    walk, gaps, starts = _vrrp_walk(pre, keepalived_script_exists, run_all_children)
    return {'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
            'vrrp_process_starts': starts, 'programs': walk.programs, 'gaps': gaps,
            'complete': not any(g['blocking'] for g in gaps), 'origin': 'not_assessed'}


def keepalived_programs(text: Any, *, config_id: str | None = None, keepalived_script_exists: bool | None = None,
                        run_all_children: bool | None = None) -> dict[str, Any]:
    """Programs the keepalived 2.2.8 parent and VRRP processes run; each entry names its ``process``.

    The parent's ``startup_script`` and ``shutdown_script`` come first. Each process resolves default script
    users on its own, so the parent's defaults depend only on ``global_defs`` order.
    """
    pre = logical_lines(text, config_id=config_id)
    walk, gaps, starts = _vrrp_walk(pre, keepalived_script_exists, run_all_children)
    parent_programs: list = []
    if _readable(gaps):
        parent_gaps: list = []
        parent = _Walk(pre['lines'], parent_gaps, keepalived_script_exists, process='parent')
        parent.stream(ROOT_KEYWORDS, False, 0, None)
        parent_programs = parent.programs
        seen = {(g['code'], g['line']) for g in gaps}
        for g in parent_gaps:  # structure gaps repeat the VRRP walk's; keep only the parent's own
            if (g['code'], g['line']) not in seen:
                _gap(gaps, g['code'], g['line'], g['detail'])
    return {'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
            'vrrp_process_starts': starts, 'programs': parent_programs + walk.programs, 'gaps': gaps,
            'complete': not any(g['blocking'] for g in gaps), 'origin': 'not_assessed'}
