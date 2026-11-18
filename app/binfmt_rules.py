"""Pure systemd-binfmt registration contract (roadmap F slice, #1081).

Takes captured, read-only metadata and text for ``binfmt.d/*.conf`` files and
says which binfmt_misc handlers ``systemd-binfmt`` registers at boot. For each
handler it reports which program executions it intercepts, which interpreter
then runs, and whose credentials that interpreter receives. A binfmt_misc
handler is a persistence and interception point: its interpreter runs on every
matching ``execve`` by any user.

Semantics come from systemd v255 (``src/binfmt/binfmt.c``,
``src/basic/conf-files.c``, ``src/basic/fileio.c``, ``src/basic/path-util.c``)
and Linux v6.8 (``fs/binfmt_misc.c``). They were read from those sources, not
recalled:

* Files come from ``/etc/binfmt.d``, ``/run/binfmt.d``, ``/usr/local/lib/binfmt.d``
  and ``/usr/lib/binfmt.d``, in that precedence. A basename ending in ``.conf`` that
  is not hidden or a backup name (``hidden_or_backup_file``) is taken from the
  first directory holding it. ``conf_files_list_strv`` is called with no flags, so
  nothing is stat-ed: a directory, dangling symlink or empty file still claims
  the name and shadows lower directories. Files run in ``strcmp`` order of
  basename.
* An empty file or a symlink to ``/dev/null`` therefore masks the name, because
  it yields no lines. A dangling symlink is silently skipped (``ENOENT`` is
  ignored). A directory fails to read and contributes nothing.
* Before applying files, ``systemd-binfmt`` flushes every existing handler
  (``-1`` to ``status``).
* Lines end at ``\\n``, ``\\r`` or NUL and are stripped of spaces, tabs and line
  ends. Empty lines and lines starting with ``#`` or ``;`` are skipped.
* For each other line the rule name is the text after the first character up to
  the next occurrence of that character. A name that is not a valid file name,
  or is ``register`` or ``status``, is refused without touching the kernel.
  Otherwise any handler with that name is deleted first, and then the line plus
  a newline is written to ``register``. A later rule with the same name
  therefore replaces an earlier one, and if the later rule is rejected neither
  remains.
* The kernel parser (``create_entry``) accepts
  ``:name:type:offset:magic:mask:interpreter:flags`` with any first-character
  delimiter, a register length of 11–1920 bytes, type ``M`` (magic) or ``E``
  (extension), ``\\xHH`` escapes in magic and mask, equal decoded magic and mask
  lengths, and ``offset + size <= 256``. For ``E`` rules the offset and mask
  fields are skipped unparsed. Flags are any run of ``P``, ``O``, ``C`` and
  ``F``, optionally followed by the newline, and nothing else may follow.
  ``C`` implies ``O``. With ``F`` the interpreter is opened at registration and
  registration fails if it cannot be opened.
* New handlers are added at the head of the handler list, so the most recently
  registered handler is consulted first. binfmt_misc itself is placed ahead of
  the native ELF and ``#!`` script loaders (``insert_binfmt``), so a handler whose
  magic matches the ELF header or ``#!`` intercepts native executables and
  scripts.

It performs no I/O, never runs a command and never authorizes a response
action. Missing or malformed metadata, unobserved directories, incomplete
listings or file text, special files and over-limit input are explicit
blocking gaps and are never reported as covered.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'systemd': 'v255 src/binfmt/binfmt.c, src/basic/conf-files.c', 'linux': 'v6.8 fs/binfmt_misc.c'}
DIRECTORIES = ('/etc/binfmt.d', '/run/binfmt.d', '/usr/local/lib/binfmt.d', '/usr/lib/binfmt.d')
SUFFIX = '.conf'
REGISTER = '/proc/sys/fs/binfmt_misc/register'
RUNS_AS = 'root'
MAX_REGISTER_LENGTH = 1920
BINPRM_BUF_SIZE = 256
INT_MAX = 2**31 - 1
NAME_MAX = 255
MAX_ENTRIES = 1024
MAX_CONTENT_CHARS = 65536
MAX_RULES = 512
MAX_GAPS = 64
FILE_TYPES = ('file', 'directory', 'symlink', 'other')
TARGET_TYPES = ('file', 'directory', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
FLAG_MEANINGS = {
    'P': 'preserve_argv0',
    'O': 'open_binary',
    'C': 'credentials_from_binary',
    'F': 'interpreter_opened_at_registration',
}
_BACKUP_SUFFIXES = frozenset({
    'rpmnew', 'rpmsave', 'rpmorig', 'dpkg-old', 'dpkg-new', 'dpkg-tmp', 'dpkg-dist', 'dpkg-bak', 'dpkg-backup',
    'dpkg-remove', 'ucf-new', 'ucf-old', 'ucf-dist', 'swp', 'bak', 'old', 'new',
})
_EOL = re.compile(r'[\n\r\x00]')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_HEX = frozenset(b'0123456789abcdefABCDEF')
_DECIMAL = re.compile(rb'-?[0-9]+|\+[0-9]+')
ELF_MAGIC = b'\x7fELF'
SHEBANG = b'#!'
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'too_many_rules', 'duplicate_name', 'metadata_missing',
    'content_not_observed', 'content_incomplete', 'content_too_large', 'special_file', 'directory_not_observed',
    'directory_unreadable', 'listing_incomplete', 'gaps_truncated',
})
UNOBSERVED = (
    'Whether systemd-binfmt.service runs at boot (it can be masked) and whether binfmt_misc is mounted '
    'read-write are not resolved here.',
    'Handlers registered later by other tools (for example Debian binfmt-support update-binfmts from '
    '/usr/share/binfmts and /var/lib/binfmts, or container runtimes) and the live '
    '/proc/sys/fs/binfmt_misc state are not read.',
    'Interpreter files, their contents and whether they exist are not read; an F-flag handler registers only '
    'if its interpreter opens at boot.',
    'Per-namespace binfmt_misc instances (Linux 6.7+ user namespaces) are not assessed.',
)
NOT_A_VERDICT = 'Configuration metadata only. This is not a safety verdict and origin is not assessed.'

FILE_REASONS = {
    'applied': 'systemd-binfmt reads this file and writes each rule line to the kernel.',
    'masked': 'The file is empty (for example a symlink to /dev/null), so it contributes no rules and masks the '
              'name in lower-precedence directories.',
    'overridden': 'A file with the same name in a higher-precedence directory is used instead.',
    'dangling_symlink': 'The symlink target does not exist; systemd-binfmt ignores it, and the name is still '
                        'masked in lower-precedence directories.',
    'directory': 'A directory with this name cannot be read as a file; it contributes no rules and still '
                 'masks the name in lower-precedence directories.',
    'name_ignored': 'The name does not end in .conf, or is a hidden or backup name, so it is not read.',
    'unresolved': 'Required metadata or text was not supplied, so what this file registers is not determined.',
}
RULE_REASONS = {
    'registered': 'The kernel accepts this rule and the handler is registered.',
    'registered_if_interpreter_opens': 'The kernel accepts this rule; with the F flag it registers only if the '
                                       'interpreter can be opened when systemd-binfmt runs.',
    'replaced': 'A later rule with the same name deleted this handler.',
    'name_refused': 'systemd-binfmt refuses the rule name (not a valid file name, or register/status), so '
                    'nothing is written.',
    'kernel_rejected': 'The kernel rejects this registration string, so no handler is added.',
}


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


def _bytes(text: str) -> bytes:
    return text.encode('utf-8', 'surrogateescape')


def _text(raw: bytes) -> str:
    return raw.decode('utf-8', 'surrogateescape')


def name_considered(name: str) -> bool:
    """Return whether ``conf_files_list_strv`` lists this entry name for binfmt.d."""
    if not name.endswith(SUFFIX):
        return False
    if name.startswith('.') or name in ('lost+found', 'aquota.user', 'aquota.group') or name.endswith('~'):
        return False
    dot = name.rfind('.')
    return dot < 0 or name[dot + 1:] not in _BACKUP_SUFFIXES


def rule_lines(content: str) -> list[tuple[int, str]]:
    """Return ``(line_number, stripped_text)`` for the lines ``apply_file`` writes to the kernel.

    Line numbers count every EOL character, so they are positional, not systemd's own count when
    ``\\r\\n`` pairs are present.
    """
    result = []
    for number, line in enumerate(_EOL.split(content), start=1):
        text = line.strip(' \t\n\r')
        if text and text[0] not in '#;':
            result.append((number, text))
    return result


def systemd_rule_name(rule: str) -> tuple[str, bool]:
    """Return the rule name systemd-binfmt derives and whether it accepts it."""
    delimiter = rule[0]
    rest = rule[1:]
    end = rest.find(delimiter)
    name = rest if end < 0 else rest[:end]
    valid = (name not in ('', '.', '..') and '/' not in name and len(_bytes(name)) <= NAME_MAX
             and name not in ('register', 'status'))
    return name, valid


def _scanarg(buf: bytes, pos: int, delim: int) -> int | None:
    """Mirror ``scanarg``: return the index after the closing delimiter, or None on a bad escape."""
    while True:
        if pos >= len(buf):
            return None
        c = buf[pos]
        pos += 1
        if c == delim:
            return pos
        if c == 0x5c and pos < len(buf) and buf[pos] == 0x78:
            pos += 1
            if pos + 1 >= len(buf) or buf[pos] not in _HEX or buf[pos + 1] not in _HEX:
                return None
            pos += 2


def _unescape_hex(raw: bytes) -> bytes:
    """Mirror ``string_unescape_inplace(..., UNESCAPE_HEX)`` after ``scanarg`` validated every ``\\x``."""
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == 0x5c and i + 1 < len(raw) and raw[i + 1] == 0x78 and i + 2 < len(raw) and raw[i + 2] in _HEX:
            digits = raw[i + 2:i + 3]
            i += 3
            if i < len(raw) and raw[i] in _HEX:
                digits += raw[i:i + 1]
                i += 1
            out.append(int(digits, 16))
            continue
        out.append(raw[i])
        i += 1
    return bytes(out)


def _kstrtoint(raw: bytes) -> int | None:
    if not _DECIMAL.fullmatch(raw):
        return None
    value = int(raw)
    return value if -INT_MAX - 1 <= value <= INT_MAX else None


def kernel_parse(rule: str) -> tuple[dict[str, Any] | None, str]:
    """Mirror Linux ``create_entry`` for ``rule`` plus the newline systemd appends.

    Returns ``(handler, '')`` when accepted, or ``(None, reason)`` when the kernel returns ``EINVAL``.
    """
    data = _bytes(rule) + b'\n'
    count = len(data)
    if count < 11 or count > MAX_REGISTER_LENGTH:
        return None, f'The registration string must be 11–{MAX_REGISTER_LENGTH} bytes including the newline.'
    delim = data[0]
    buf = data + bytes([delim]) * 8
    pos = 1
    end = buf.index(delim, pos)
    name = buf[pos:end]
    pos = end + 1
    if name in (b'', b'.', b'..') or b'/' in name:
        return None, 'The handler name is empty, "." or "..", or contains "/".'
    kind = chr(buf[pos])
    pos += 1
    if kind not in ('E', 'M'):
        return None, 'The type must be M (magic) or E (extension).'
    if buf[pos] != delim:
        return None, 'The type field must be a single character.'
    pos += 1
    handler: dict[str, Any] = {'name': _text(name), 'type': 'magic' if kind == 'M' else 'extension'}
    if kind == 'M':
        end = buf.index(delim, pos)
        offset = 0
        if end != pos:
            parsed = _kstrtoint(buf[pos:end])
            if parsed is None or parsed < 0:
                return None, 'The offset is not a non-negative decimal integer.'
            offset = parsed
        pos = end + 1
        after = _scanarg(buf, pos, delim)
        if after is None:
            return None, 'The magic contains a \\x escape without two hex digits.'
        magic_raw = buf[pos:after - 1]
        if not magic_raw:
            return None, 'The magic is empty.'
        pos = after
        after = _scanarg(buf, pos, delim)
        if after is None:
            return None, 'The mask contains a \\x escape without two hex digits.'
        mask_raw = buf[pos:after - 1]
        pos = after
        magic = _unescape_hex(magic_raw)
        mask = _unescape_hex(mask_raw) if mask_raw else None
        if mask is not None and len(mask) != len(magic):
            return None, 'The decoded mask length differs from the decoded magic length.'
        if len(magic) > BINPRM_BUF_SIZE or BINPRM_BUF_SIZE - len(magic) < offset:
            return None, f'The offset plus magic length exceeds the {BINPRM_BUF_SIZE}-byte header the kernel reads.'
        handler.update(offset=offset, magic_hex=magic.hex(), mask_hex=None if mask is None else mask.hex())
        handler['_magic'], handler['_mask'] = magic, mask
    else:
        pos = buf.index(delim, pos) + 1
        end = buf.index(delim, pos)
        extension = buf[pos:end]
        pos = end + 1
        if not extension or b'/' in extension:
            return None, 'The extension is empty or contains "/".'
        handler['extension'] = _text(extension)
        pos = buf.index(delim, pos) + 1
    end = buf.index(delim, pos)
    interpreter = buf[pos:end]
    pos = end + 1
    if not interpreter:
        return None, 'The interpreter is empty.'
    handler['interpreter'] = _text(interpreter)
    flags = ''
    while pos < len(buf) and chr(buf[pos]) in FLAG_MEANINGS:
        flags += chr(buf[pos])
        pos += 1
    if pos < len(buf) and buf[pos] == 0x0a:
        pos += 1
    if pos != count:
        return None, 'Unexpected text follows the flags field (only P, O, C and F are flags).'
    handler['flags'] = ''.join(sorted(set(flags), key='POCF'.index))
    return handler, ''


def _matches_prefix(magic: bytes, mask: bytes | None, offset: int, prefix: bytes) -> bool:
    """Return whether every file whose header starts with ``prefix`` satisfies the magic and mask.

    Bytes beyond the prefix must be fully masked out, so a rule that also requires an ELF class or
    machine byte (as qemu-user rules do) does not count as matching every ELF executable.
    """
    for j, byte in enumerate(magic):
        k = offset + j
        bits = 0xff if mask is None else mask[j]
        if k >= len(prefix):
            if bits:
                return False
        elif (byte ^ prefix[k]) & bits:
            return False
    return True


def _attributes(handler: dict[str, Any]) -> dict[str, Any]:
    flags = handler['flags']
    attrs: dict[str, Any] = {
        'credentials_from_binary': 'C' in flags,
        'open_binary': 'O' in flags or 'C' in flags,
        'preserve_argv0': 'P' in flags,
        'interpreter_opened_at_registration': 'F' in flags,
        'interpreter_relative': not handler['interpreter'].startswith('/'),
    }
    if handler['type'] == 'magic':
        magic, mask, offset = handler['_magic'], handler['_mask'], handler['offset']
        attrs['matches_elf_header'] = _matches_prefix(magic, mask, offset, ELF_MAGIC)
        attrs['matches_shebang'] = _matches_prefix(magic, mask, offset, SHEBANG)
        attrs['matches_any_content'] = mask is not None and not any(mask)
    else:
        attrs.update(matches_elf_header=False, matches_shebang=False, matches_any_content=False)
    return attrs


def _target(meta: Any) -> dict[str, Any] | None:
    if not isinstance(meta, dict) or meta.get('type') not in TARGET_TYPES:
        return None
    return {'type': meta['type']}


def _normalize(item: Any, directory: str, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    name = item.get('name') if isinstance(item, dict) else None
    if not (isinstance(name, str) and name not in ('', '.', '..') and '/' not in name and '\x00' not in name
            and item.get('type') in FILE_TYPES):
        _gap(gaps, 'input_malformed', directory, 'An entry observation has no valid name or type.')
        return None
    try:
        if len(_bytes(name)) > NAME_MAX:
            raise UnicodeEncodeError('utf-8', name, 0, 1, 'too long')
    except UnicodeEncodeError:
        _gap(gaps, 'input_malformed', directory, 'An entry name is too long or not encodable.')
        return None
    entry: dict[str, Any] = {'name': name, 'type': item['type'], 'path': f'{directory}/{name}', 'resolved': True}
    if item['type'] == 'symlink':
        link = item.get('link_target')
        if isinstance(link, str) and link and len(link) <= 4096 and not _CONTROL.search(link):
            entry['link_target'] = link
        if 'target' not in item:
            entry['resolved'] = False
        elif item['target'] is None:
            entry['target'] = None
        else:
            entry['target'] = _target(item['target'])
            entry['resolved'] = entry['target'] is not None
    for key in ('content', 'content_complete'):
        if key in item:
            entry[key] = item[key]
    return entry


def _directory(meta: Any, path: str, gaps: list[dict[str, Any]]) -> tuple[str | None, list[Any]]:
    if meta is None:
        _gap(gaps, 'directory_not_observed', path, f'No listing result was supplied for {path}.')
        return None, []
    state = meta.get('state') if isinstance(meta, dict) else None
    complete = meta.get('complete') if isinstance(meta, dict) else None
    entries = meta.get('entries', []) if isinstance(meta, dict) else None
    if state not in DIRECTORY_STATES or not isinstance(entries, (list, tuple)) \
            or (state == 'listed' and not isinstance(complete, bool)) \
            or (complete is not None and not isinstance(complete, bool)) \
            or (state != 'listed' and entries):
        _gap(gaps, 'input_malformed', path, 'The directory observation is malformed.')
        return None, []
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', path, f'{path} exists but could not be listed.')
    elif state == 'listed' and not complete:
        _gap(gaps, 'listing_incomplete', path, f'The listing of {path} did not finish.')
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', path, f'Only the first {MAX_ENTRIES} entries are assessed.')
        entries = list(entries[:MAX_ENTRIES])
    return state, list(entries)


def _read(entry: dict[str, Any], gaps: list[dict[str, Any]]) -> tuple[str, str | None]:
    """Return ``(reason_code, content)`` for a listed file that wins its name."""
    path = entry['path']
    if not entry['resolved']:
        _gap(gaps, 'metadata_missing', path, 'What this entry resolves to was not supplied or is malformed.')
        return 'unresolved', None
    kind = entry['type']
    if kind == 'symlink':
        if entry['target'] is None:
            return 'dangling_symlink', None
        kind = entry['target']['type']
    if kind == 'directory':
        return 'directory', None
    content = entry.get('content')
    if content is None:
        if kind == 'other':
            _gap(gaps, 'special_file', path, 'A FIFO, socket or device file here is opened by systemd-binfmt; '
                                             'what it yields (or whether the read blocks) was not observed.')
        else:
            _gap(gaps, 'content_not_observed', path, 'The file text was not supplied.')
        return 'unresolved', None
    if not isinstance(content, str) or not isinstance(entry.get('content_complete'), bool):
        _gap(gaps, 'input_malformed', path, 'File text must be a string with a content_complete flag.')
        return 'unresolved', None
    if len(content) > MAX_CONTENT_CHARS:
        _gap(gaps, 'content_too_large', path, f'Only files up to {MAX_CONTENT_CHARS} characters are assessed.')
        return 'unresolved', None
    if not entry['content_complete']:
        _gap(gaps, 'content_incomplete', path, 'The file text was truncated or only partly read.')
        return 'unresolved', None
    if not rule_lines(content):
        return ('masked' if content == '' else 'applied'), content
    return 'applied', content


def evaluate(directories: Any) -> dict[str, Any]:
    """Resolve which binfmt_misc handlers systemd-binfmt registers from supplied metadata.

    ``directories`` maps each of :data:`DIRECTORIES` to ``{'state', 'complete', 'entries'}``, with
    ``state`` ``listed``, ``absent``, ``not_directory`` or ``unreadable`` (as ``chase_and_opendir``
    sees it, so a symlinked directory is followed). Each entry has ``name`` and ``type`` (``file``,
    ``directory``, ``symlink`` or ``other``) as ``lstat`` reports it. A ``symlink`` carries ``target``:
    ``{'type'}`` after following it, or ``None`` when it dangles. A readable file, or a symlink to one
    or to a device, carries ``content`` (the decoded text) and ``content_complete``. A symlink to
    ``/dev/null`` is ``target={'type': 'other'}`` with ``content=''``.

    ``handlers`` lists the registered handlers in the order the kernel consults them (most recently
    registered first). They are what systemd-binfmt leaves registered when it runs; see ``unobserved``.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'directories': list(DIRECTORIES),
        'register': REGISTER, 'runs_as': RUNS_AS, 'flushes_existing': True, 'files': [], 'rules': [],
        'handlers': [], 'gaps': gaps, 'unobserved': list(UNOBSERVED), 'origin': 'not_assessed',
        'note': NOT_A_VERDICT,
    }
    if not isinstance(directories, dict):
        _gap(gaps, 'input_malformed', detail='Directory observations must be a mapping.')
        directories = {}
    winners: dict[str, dict[str, Any]] = {}
    files: list[dict[str, Any]] = []
    states: dict[str, str | None] = {}
    for path in DIRECTORIES:
        state, entries = _directory(directories.get(path), path, gaps)
        states[path] = state
        seen: set[str] = set()
        for item in entries:
            entry = _normalize(item, path, gaps)
            if entry is None:
                continue
            if entry['name'] in seen:
                _gap(gaps, 'duplicate_name', entry['path'], 'The name was supplied more than once; the first is used.')
                continue
            seen.add(entry['name'])
            record = {'path': entry['path'], 'directory': path, 'name': entry['name'], 'type': entry['type']}
            if 'link_target' in entry:
                record['link_target'] = entry['link_target']
            if not name_considered(entry['name']):
                record.update(status='ignored', reason_code='name_ignored')
            elif entry['name'] in winners:
                record.update(status='ignored', reason_code='overridden',
                              overridden_by=winners[entry['name']]['record']['path'])
            else:
                winners[entry['name']] = {'entry': entry, 'record': record}
            files.append(record)
    for item in sorted(winners.values(), key=lambda w: _bytes(w['entry']['name'])):
        entry, record = item['entry'], item['record']
        code, content = _read(entry, gaps)
        status = {'applied': 'applied', 'unresolved': 'unresolved'}.get(code, 'no_rules')
        record.update(status=status, reason_code=code)
        item['content'] = content
    for record in files:
        record['reason'] = FILE_REASONS[record['reason_code']]

    rules: list[dict[str, Any]] = []
    registered: dict[str, dict[str, Any]] = {}
    sequence = 0
    for item in sorted(winners.values(), key=lambda w: _bytes(w['entry']['name'])):
        if item['record']['status'] != 'applied':
            continue
        for line, text in rule_lines(item['content']):
            if len(rules) >= MAX_RULES:
                _gap(gaps, 'too_many_rules', detail=f'Only the first {MAX_RULES} rule lines are assessed.')
                break
            name, valid = systemd_rule_name(text)
            rule: dict[str, Any] = {'file': item['record']['path'], 'line': line, 'text': text, 'name': name}
            rules.append(rule)
            if not valid:
                rule.update(status='name_refused')
                continue
            previous = registered.pop(name, None)
            if previous is not None:
                previous.update(status='replaced', replaced_by={'file': rule['file'], 'line': line})
            handler, why = kernel_parse(text)
            if handler is None:
                rule.update(status='kernel_rejected', rejection=why)
                continue
            sequence += 1
            attrs = _attributes(handler)
            for key in ('_magic', '_mask'):
                handler.pop(key, None)
            handler.update(attributes=attrs, registration=sequence)
            rule.update(status='registered_if_interpreter_opens' if attrs['interpreter_opened_at_registration']
                        else 'registered', handler=handler)
            registered[name] = rule
        else:
            continue
        break
    for rule in rules:
        rule['reason'] = RULE_REASONS[rule['status']]
    blocked = any(gap['code'] in BLOCKING for gap in gaps)
    for rule in sorted(registered.values(), key=lambda r: -r['handler']['registration']):
        result['handlers'].append({
            'name': rule['name'], 'file': rule['file'], 'line': rule['line'], **{
                k: v for k, v in rule['handler'].items() if k not in ('name', 'registration')},
            'conditional': rule['status'] == 'registered_if_interpreter_opens',
        })
    for index, handler in enumerate(result['handlers']):
        handler['match_order'] = index
    result['files'] = sorted(files, key=lambda r: (DIRECTORIES.index(r['directory']), _bytes(r['name'])))
    result['rules'] = rules
    result['directory_states'] = states
    result['complete'] = not blocked
    return result
