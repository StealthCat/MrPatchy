"""Pure LVM2 program contract (roadmap F slice, #1599).

Takes captured, read-only observations of the LVM configuration cascade in
``/etc/lvm`` and says which programs and plugin libraries the configuration
makes LVM run as root:

* ``global/thin_check_executable``, ``cache_check_executable`` and the dump,
  repair, ``vdo_format`` and ``fsadm`` executables. ``lvm`` commands run them
  when thin or cache pools activate, deactivate, are repaired or dumped, when
  VDO volumes are created and on ``lvresize -r``. Activation proceeds only if a
  check exits 0.
* ``global/lvmlockctl_kill_command``. ``lvmlockctl --kill`` runs it with the
  VG name appended when a shared VG loses its locks.
* ``dmeventd/executable``, the root monitoring daemon LVM starts.
* ``dmeventd/{mirror,raid,snapshot,thin,vdo}_library``. ``dmeventd`` loads
  these into its own root process with ``dlopen()``.
* ``dmeventd/thin_command`` and ``vdo_command``. The thin and VDO plugins run
  them at each 5% fill step above 50%.

Semantics follow lvm2 2.03.16 (Ubuntu 24.04 package ``2.03.16-3ubuntu3.2``):

* ``device_mapper/libdm-config.c`` tokenizer and grammar. ``#`` starts a
  comment and C ``isspace`` separates tokens. ``"..."`` strings unescape only
  ``\\"`` and ``\\\\``, ``'...'`` strings are raw, and after ``=``, ``[`` or ``,``
  a run of non-space, non-``#=\\{\\}`` characters is a bare string. A section or
  key name may be a ``/`` path, which creates or reuses nested sections. A
  repeated section merges into the first. A repeated value is replaced by the
  later one, the opposite of LVM's own "Ignoring duplicate" warning text. A
  parse error makes every LVM command fail, so nothing below runs.
* ``lib/commands/toolcontext.c`` cascade. It reads ``lvm.conf``, then
  ``lvmlocal.conf``, then ``lvm_<tag>.conf`` for each host tag in tag order.
  The tag list grows while loading, and a missing file is skipped. Tags come
  from each file's ``tags`` section: ``hosttags = 1`` adds the hostname, and
  every subsection is a tag. A tag subsection with a ``host_list`` applies only
  on a listed host, and a ``host_filter`` is an error. Tags keep first
  appearance order, so a later tag's file wins.
* ``merge_config_tree()`` with ``CONFIG_MERGE_TYPE_TAGS``. Files merge in load
  order and a later value replaces an earlier one. A top-level section whose
  ``tags`` value names no active host tag is skipped. Subsections of a section
  already present are ignored.
* ``daemons/dmeventd/plugins/thin/dmeventd_thin.c``. A command starting
  ``lvm `` runs inside dmeventd as an lvm command with ``vg/lv`` appended. A
  command starting ``/`` is ``execvp()``'d with the *whole value* as
  ``argv[0]`` and ``vg/lv`` as ``argv[1]``, so a value with spaces names a
  program path containing spaces. Anything else fails monitoring registration.

Effective values come from the merged tree. Only the first value of an array
is read. A value of the wrong type, or an
empty value where LVM forbids one, falls back to the build default after a
warning, as the runtime lookup ``_find_config_str()`` does. ``lvmconfig``
prints the raw value in those cases, but LVM does not use it. These settings are not profilable, so
``/etc/lvm/profile`` cannot change them. Program existence and executable bits
are not verified. The contract performs no I/O, never runs a command and never
authorizes a response action. Unobserved or unreadable files, NUL bytes,
invalid UTF-8, unterminated strings, parse errors and over-limit input become
explicit gaps, and a result with any gap is not ``complete``.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('lvm2 2.03.16 (Ubuntu 24.04 lvm2 2.03.16-3ubuntu3.2)',)
SYSTEM_DIR = '/etc/lvm'
MAX_TEXT = 1 << 20
MAX_GAPS = 256
MAX_TAGS = 64
MAX_DEPTH = 64
FILE_STATES = ('absent', 'regular', 'unreadable', 'not_regular', 'unknown')
RUN_AS = 'root'

# path: (build default, empty allowed, kind, runner, when)
SETTINGS: dict[str, tuple[str, bool, str, str, str]] = {
    'global/thin_check_executable': (
        '/usr/sbin/thin_check', True, 'executable', 'lvm',
        'thin_pool_activation_and_deactivation_gate'),
    'global/thin_dump_executable': ('/usr/sbin/thin_dump', True, 'executable', 'lvm',
                                    'thin_pool_metadata_dump'),
    'global/thin_repair_executable': ('/usr/sbin/thin_repair', True, 'executable', 'lvm',
                                      'thin_pool_repair'),
    'global/cache_check_executable': (
        '/usr/sbin/cache_check', True, 'executable', 'lvm',
        'cache_activation_and_deactivation_gate'),
    'global/cache_dump_executable': ('/usr/sbin/cache_dump', True, 'executable', 'lvm',
                                     'cache_metadata_dump'),
    'global/cache_repair_executable': ('/usr/sbin/cache_repair', True, 'executable', 'lvm',
                                       'cache_repair'),
    'global/vdo_format_executable': ('/usr/bin/vdoformat', True, 'executable', 'lvm',
                                     'vdo_volume_creation'),
    'global/fsadm_executable': ('/usr/sbin/fsadm', False, 'executable', 'lvm',
                                'lvresize_resizefs'),
    'global/lvmlockctl_kill_command': ('', True, 'command', 'lvmlockctl',
                                       'shared_vg_lost_locks_vg_name_appended'),
    'dmeventd/executable': ('/usr/sbin/dmeventd', False, 'executable', 'lvm',
                            'monitoring_daemon_start'),
    'dmeventd/mirror_library': ('libdevmapper-event-lvm2mirror.so', False, 'library',
                                'dmeventd', 'mirror_monitoring_dlopen'),
    'dmeventd/raid_library': ('libdevmapper-event-lvm2raid.so', False, 'library',
                              'dmeventd', 'raid_monitoring_dlopen'),
    'dmeventd/snapshot_library': ('libdevmapper-event-lvm2snapshot.so', False, 'library',
                                  'dmeventd', 'snapshot_monitoring_dlopen'),
    'dmeventd/thin_library': ('libdevmapper-event-lvm2thin.so', False, 'library',
                              'dmeventd', 'thin_monitoring_dlopen'),
    'dmeventd/vdo_library': ('libdevmapper-event-lvm2vdo.so', False, 'library',
                             'dmeventd', 'vdo_monitoring_dlopen'),
    'dmeventd/thin_command': ('lvm lvextend --use-policies', False, 'event_command',
                              'dmeventd', 'thin_pool_fill_above_50_percent_each_5_percent'),
    'dmeventd/vdo_command': ('lvm lvextend --use-policies', False, 'event_command',
                             'dmeventd', 'vdo_pool_fill_above_50_percent_each_5_percent'),
}

NOT_MODELLED = (
    'lvm_command_line_config_and_LVM_SYSTEM_DIR',
    'initramfs_copy_of_lvm_conf',
    'global_library_dir_library_resolution',
    'program_existence_and_executable_bits',
    'which_lvs_are_thin_cache_vdo_or_monitored',
    'lvmlockctl_kill_command_shell_or_argv_execution',
)

_SPACE = ' \t\n\v\f\r'
_TAG_RE = re.compile(r'[A-Za-z0-9._+-]+')


class _ParseError(Exception):
    def __init__(self, reason: str, line: int):
        super().__init__(reason)
        self.reason = reason
        self.line = line


class _Node:
    __slots__ = ('key', 'value', 'children')

    def __init__(self, key: str):
        self.key = key
        self.value: list[tuple[str, Any]] | None = None
        self.children: list[_Node] = []

    def find(self, key: str) -> '_Node | None':
        for child in self.children:
            if child.key == key:
                return child
        return None


def _unescape(text: str) -> str:
    # dm_unescape_double_quotes(): drop the backslash before '"' or '\\' only.
    out = []
    i = 0
    while i < len(text):
        if text[i] == '\\' and i + 1 < len(text) and text[i + 1] in '"\\':
            i += 1
        out.append(text[i])
        i += 1
    return ''.join(out)


def _tokens(text: str):
    """Yield (kind, raw, line) like libdm-config ``_get_token``."""
    pos = 0
    line = 1
    end = len(text)
    prev = None
    while True:
        while pos < end:
            ch = text[pos]
            if ch == '#':
                while pos < end and text[pos] != '\n':
                    pos += 1
            elif ch in _SPACE:
                if ch == '\n':
                    line += 1
                pos += 1
            else:
                break
        if pos >= end:
            yield ('eof', '', line)
            return
        values = prev in ('eq', 'array_b', 'comma')
        start = pos
        ch = text[pos]
        simple = {'{': 'section_b', '}': 'section_e', '[': 'array_b', ']': 'array_e',
                  ',': 'comma', '=': 'eq'}
        if ch in simple:
            kind = simple[ch]
            pos += 1
        elif ch in '"\'':
            kind = 'escaped' if ch == '"' else 'string'
            pos += 1
            while pos < end and text[pos] != ch:
                if ch == '"' and text[pos] == '\\' and pos + 1 < end:
                    pos += 1
                pos += 1
            if pos >= end:
                raise _ParseError('unterminated_string', line)
            pos += 1
        elif values and (ch.isdigit() or ch in '.+-') and ch.isascii():
            kind = 'float' if ch == '.' else 'int'
            pos += 1
            while pos < end:
                c = text[pos]
                if not (c.isascii() and c.isdigit()):
                    if c == '.' and kind != 'float':
                        kind = 'float'
                        pos += 1
                        continue
                    break
                pos += 1
        else:
            kind = 'bare' if values else 'identifier'
            while pos < end and text[pos] not in _SPACE and text[pos] not in '#={}':
                pos += 1
        raw = text[start:pos]
        yield (kind, raw, line)
        line += raw.count('\n')
        prev = kind


def _find_or_make(parent: _Node, path: str) -> _Node:
    while True:
        path = path.lstrip('/')
        cut = path.find('/')
        seg = path if cut < 0 else path[:cut]
        node = parent.find(seg)
        if node is None:
            node = _Node(seg)
            # _make_node() prepends and _config_reverse() restores file order.
            parent.children.append(node)
        if cut < 0:
            return node
        parent = node
        path = path[cut:]


def parse(text: str) -> _Node:
    """Parse one LVM configuration file into a tree; raise ``_ParseError``."""
    tokens = _tokens(text)
    tok = [next(tokens)]

    def advance() -> None:
        tok[0] = next(tokens)

    def expect(kind: str) -> None:
        if tok[0][0] != kind:
            raise _ParseError('unexpected_token', tok[0][2])
        advance()

    def scalar() -> tuple[str, Any]:
        kind, raw, line = tok[0]
        if kind == 'int':
            body = raw.lstrip('+-')
            try:
                value: Any = int(raw, 0) if body[:1] != '0' or len(body) == 1 else int(raw, 8)
            except ValueError:
                value = 0  # strtoll() of a bare sign
            advance()
            return ('int', value)
        if kind == 'float':
            advance()
            return ('float', raw)
        if kind in ('string', 'escaped'):
            advance()
            body = raw[1:-1]
            return ('string', _unescape(body) if kind == 'escaped' else body)
        if kind == 'bare':
            advance()
            return ('string', raw)
        raise _ParseError('expected_value', line)

    def section(parent: _Node, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise _ParseError('nesting_limit', tok[0][2])
        kind, raw, line = tok[0]
        if kind == 'escaped':
            key = _unescape(raw[1:-1])
        elif kind == 'string':
            key = raw[1:-1]
        elif kind == 'identifier':
            key = raw
        else:
            raise _ParseError('unexpected_token', line)
        advance()
        if not key:
            raise _ParseError('empty_section_identifier', line)
        node = _find_or_make(parent, key)
        if tok[0][0] == 'section_b':
            advance()
            while tok[0][0] != 'section_e':
                section(node, depth + 1)
            advance()
            return
        expect('eq')
        if tok[0][0] == 'array_b':
            advance()
            values: list[tuple[str, Any]] = []
            while tok[0][0] != 'array_e':
                values.append(scalar())
                if tok[0][0] == 'comma':
                    advance()
            advance()
            node.value = values or [('empty_array', None)]
        else:
            node.value = [scalar()]

    root = _Node('<root>')
    while tok[0][0] != 'eof':
        section(root, 0)
    return root


def _truthy(kind: str, value: Any) -> bool:
    # dm_config_find_bool(): a non-zero int, or y/yes/on/true in any case.
    if kind == 'int':
        return bool(value)
    if kind == 'string':
        return value.lower() in ('y', 'yes', 'on', 'true')
    return False


def _strings(value: list[tuple[str, Any]] | None) -> list[str]:
    return [v for t, v in value or [] if t == 'string']


def assess(files: list[dict[str, Any]] | None, *, hostname: str | None = None,
           system_dir: str = SYSTEM_DIR) -> dict[str, Any]:
    """Return the programs and libraries one LVM configuration cascade runs.

    ``files`` holds records ``{'path', 'state', 'text'}`` for ``lvm.conf``,
    ``lvmlocal.conf`` and any ``lvm_<tag>.conf``. ``state`` is one of
    ``FILE_STATES``. ``text`` is required for ``regular`` files, unless the
    record carries ``parse_error`` (``{'reason', 'line'}``) for a file an agent
    already parsed with these rules and rejected. ``hostname`` is
    the node name LVM sees from ``uname(2)``. It is needed only to evaluate
    ``hosttags`` and ``host_list``.
    """
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
        'system_dir': system_dir, 'complete': True, 'lvm_starts': True, 'run_as': RUN_AS,
        'files': [], 'tags': [], 'settings': [], 'warnings': [], 'gaps': [],
        'not_modelled': list(NOT_MODELLED), 'origin': 'not_assessed',
    }
    gaps: list[dict[str, Any]] = result['gaps']

    def gap(reason: str, **detail: Any) -> None:
        result['complete'] = False
        if len(gaps) < MAX_GAPS:
            gaps.append({'reason': reason, **detail})
        elif len(gaps) == MAX_GAPS:
            gaps.append({'reason': 'gap_limit_reached', 'limit': MAX_GAPS})

    records: dict[str, dict[str, Any]] = {}
    for record in files or []:
        if isinstance(record, dict) and isinstance(record.get('path'), str):
            records.setdefault(record['path'], record)

    tags: list[str] = []
    state = {'hosttags': False}
    loaded: list[tuple[str, _Node]] = []

    def load(path: str) -> _Node | None:
        record = records.get(path)
        entry: dict[str, Any] = {'path': path}
        result['files'].append(entry)
        file_state = record.get('state') if record else 'unknown'
        if file_state not in FILE_STATES:
            file_state = 'unknown'
        entry['state'] = file_state
        if file_state == 'absent':
            return None
        if file_state != 'regular':
            gap('file_' + file_state, path=path)
            return None
        reported = record.get('parse_error')
        if isinstance(reported, dict):
            # The agent parsed the hashed bytes with this module's rules and kept only the error.
            reason = str(reported.get('reason'))[:80]
            if reason in ('nul_byte', 'invalid_utf8'):
                gap(reason, path=path)
                return None
            line = reported.get('line') if type(reported.get('line')) is int else None
            entry['parse_error'] = {'reason': reason, 'line': line}
            result['lvm_starts'] = False
            gap('parse_error_lvm_commands_fail', path=path, line=line, detail=reason)
            return None
        text = record.get('text')
        if isinstance(text, bytes):
            if len(text) > MAX_TEXT:
                gap('file_too_large', path=path, limit=MAX_TEXT)
                return None
            try:
                text = text.decode('utf-8')
            except UnicodeDecodeError:
                gap('invalid_utf8', path=path)
                return None
        if not isinstance(text, str):
            gap('file_text_missing', path=path)
            return None
        if len(text) > MAX_TEXT:
            gap('file_too_large', path=path, limit=MAX_TEXT)
            return None
        if '\x00' in text:
            gap('nul_byte', path=path)
            return None
        try:
            tree = parse(text)
        except _ParseError as exc:
            entry['parse_error'] = {'reason': exc.reason, 'line': exc.line}
            result['lvm_starts'] = False
            gap('parse_error_lvm_commands_fail', path=path, line=exc.line, detail=exc.reason)
            return None
        entry['parsed'] = True
        loaded.append((path, tree))
        return tree

    def add_tag(tag: str, source: str) -> None:
        if tag in tags:
            return
        if len(tags) >= MAX_TAGS:
            gap('tag_limit_reached', limit=MAX_TAGS)
            return
        tags.append(tag)
        result['tags'].append({'tag': tag, 'source': source})

    def init_tags(tree: _Node, path: str) -> None:
        section = tree.find('tags')
        if section is None or not section.children:
            return
        hosttags = section.find('hosttags')
        if not state['hosttags'] and hosttags is not None and hosttags.value:
            kind, value = hosttags.value[0]
            if _truthy(kind, value):
                if hostname is None:
                    gap('hostname_unknown_for_hosttags', path=path)
                else:
                    add_tag(hostname, path)
                state['hosttags'] = True
        for child in section.children:
            if child.value is not None:
                continue
            tag = child.key[1:] if child.key.startswith('@') else child.key
            if not _TAG_RE.fullmatch(tag) or tag.startswith('-') or tag in ('.', '..'):
                result['lvm_starts'] = False
                gap('invalid_tag_lvm_commands_fail', path=path, tag=child.key[:80])
                continue
            passes = True
            for sub in child.children:
                if sub.value is None:
                    continue
                if sub.key == 'host_list':
                    passes = False
                    if sub.value[0][0] == 'empty_array':
                        continue
                    # _check_host_filters walks the values in order: a
                    # matching string passes at once, and only a non-string
                    # reached before any match fails the command.
                    outcome = None
                    for kind, value in sub.value:
                        if kind != 'string':
                            outcome = 'invalid'
                            break
                        if hostname is None:
                            outcome = 'unknown'
                            break
                        if value == hostname:
                            outcome = 'match'
                            break
                    if outcome == 'invalid':
                        result['lvm_starts'] = False
                        gap('invalid_host_list_lvm_commands_fail', path=path, tag=tag)
                        return
                    if outcome == 'unknown':
                        gap('hostname_unknown_for_host_list', path=path, tag=tag)
                        passes = False
                        break
                    if outcome == 'match':
                        passes = True
                        break
                if sub.key == 'host_filter':
                    result['lvm_starts'] = False
                    gap('host_filter_unsupported_lvm_commands_fail', path=path, tag=tag)
                    return
            if passes:
                add_tag(tag, path)

    base = system_dir.rstrip('/') or ''
    main_tree = load(base + '/lvm.conf')
    if main_tree is not None:
        init_tags(main_tree, base + '/lvm.conf')
    local_tree = load(base + '/lvmlocal.conf')
    if local_tree is not None:
        init_tags(local_tree, base + '/lvmlocal.conf')
    index = 0
    while index < len(tags):
        path = f'{base}/lvm_{tags[index]}.conf'
        tree = load(path)
        if tree is not None:
            init_tags(tree, path)
        index += 1

    # merge_config_tree(CONFIG_MERGE_TYPE_TAGS), keyed by top-level section.
    merged: dict[str, dict[str, tuple[list[tuple[str, Any]], str]]] = {}
    for path, tree in loaded:
        for section in tree.children:
            if section.key == 'tags':
                continue
            filt = section.find('tags')
            if filt is not None:
                wanted = [s[1:] if s.startswith('@') else s for s in _strings(filt.value)]
                if not any(w and w in tags for w in wanted):
                    continue
            target = merged.setdefault(section.key, {})
            for child in section.children:
                if child.key == 'tags':
                    continue
                if child.value is None:
                    continue  # subsections hold none of the settings below
                target[child.key] = (child.value, path)

    for setting, (default, allow_empty, kind, runner, when) in SETTINGS.items():
        section_key, key = setting.split('/')
        found = merged.get(section_key, {}).get(key)
        entry: dict[str, Any] = {'setting': setting, 'kind': kind, 'runner': runner,
                                 'when': when, 'run_as': RUN_AS, 'build_default': default}
        value = default
        source = 'build_default'
        if found is not None:
            raw, path = found
            entry['configured_in'] = path
            # _find_config_str() reads only the first value of an array.
            if len(raw) > 1 and raw[0][0] == 'string':
                result['warnings'].append({'reason': 'array_first_value_used',
                                           'setting': setting, 'path': path})
            if raw[0][0] != 'string':
                result['warnings'].append({'reason': 'invalid_type_default_used',
                                           'setting': setting, 'path': path})
            elif raw[0][1] == '' and not allow_empty:
                result['warnings'].append({'reason': 'empty_not_allowed_default_used',
                                           'setting': setting, 'path': path})
            else:
                value = raw[0][1]
                source = path
        entry['value'] = value
        entry['source'] = source
        entry['changed_from_default'] = value != default
        entry['disabled'] = value == ''
        if kind == 'event_command':
            if value.startswith('lvm '):
                entry['mode'] = 'internal_lvm_command'
                entry['argv'] = ['lvm', *value[4:].split(), '<vg>/<lv>']
            elif value.startswith('/'):
                entry['mode'] = 'external_program'
                entry['argv'] = [value, '<vg>/<lv>']
                entry['program'] = value
                if any(c in _SPACE for c in value):
                    result['warnings'].append({'reason': 'whole_value_is_program_path',
                                               'setting': setting})
            else:
                entry['mode'] = 'invalid_monitoring_fails'
        elif kind == 'command' and value:
            entry['program'] = value.split()[0] if value.split() else value
            entry['argv'] = [*value.split(), '<vg>']
        elif kind == 'executable' and value:
            entry['program'] = value
        elif kind == 'library':
            entry['library'] = value
            entry['path_resolution'] = 'absolute' if value.startswith('/') else 'dlopen_search'
        result['settings'].append(entry)

    if not result['lvm_starts']:
        for entry in result['settings']:
            entry['runs_only_if_config_loads'] = True
    return result
