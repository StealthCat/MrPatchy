"""Pure auditd dispatcher-plugin contract (roadmap F slice, #1217).

Takes observations of ``/etc/audit/auditd.conf``, the effective plugin
directory and the plugin programs. It reports which programs auditd's built-in
event dispatcher forks and ``execve``s as root every time auditd starts or
reconfigures, with which arguments, and why every other plugin file does not
start anything. It never runs anything and never reads a program's contents.

The semantics come from the audit-userspace source at tag ``v3.1.2`` (Ubuntu
24.04 ships ``auditd`` 1:3.1.2), not from recollection. The files used are
``audisp/audispd.c``, ``audisp/audispd-pconfig.c``, ``src/auditd-config.c``,
``src/auditd.c`` and ``common/strsplit.c``:

* ``auditd`` calls ``init_dispatcher`` at startup. ``load_plugin_conf`` reads
  ``plugin_dir``, which defaults to ``/etc/audit/plugins.d`` and is replaced by
  the last ``plugin_dir`` line in ``auditd.conf``. Entries are taken in
  ``readdir`` order. Names starting with ``.`` or containing more than one
  ``.`` are skipped. A ``.conf`` suffix is *not* required.
* ``load_pconfig`` follows symlinks. It rejects the whole file unless it is a
  regular file owned by uid 0 that is not world-writable.
* Lines are read with ``fgets`` into a 160-byte buffer. A line that is 159
  bytes or longer without its newline is skipped. A final line without a
  newline is skipped too, and so is any line holding a NUL byte together with
  the line after it.
* Lines are split on spaces only, so a tab is part of a word. A first word
  starting with ``#`` is a comment. ``name = value [option]`` is required.
  Words after the option are silently dropped. A missing ``=`` or value, an
  unknown keyword (``strcasecmp``), an option on a keyword other than
  ``args``, or an invalid value rejects the whole file.
* ``active`` is ``yes``/``no`` and defaults to no. ``direction`` is ``out``.
  ``type`` is ``always``, and ``builtin`` is accepted as an obsolete alias.
  ``format`` is ``binary``/``string``. For ``path``, ``builtin_*`` means
  ``/sbin/audisp-af_unix``; otherwise glibc ``dirname(path)`` must be at
  least four bytes long. ``args = A [B]`` sets ``argv[1..2]``. For every
  keyword the last line wins.
* For an active plugin, ``sanity_check`` ``stat``s the path, following
  symlinks. The target must exist, be a regular file owned by uid 0, and have
  every bit of ``0750`` set. Otherwise the file is rejected.
* ``safe_exec`` forks and ``execve(path, [path, args...], NULL)``: no shell,
  no ``PATH`` search and an empty environment. stdin is the event socket. The
  program runs as root, and the dispatcher restarts it if it exits.

It performs no I/O and never authorizes a response action. Unobserved or
unreadable inputs, malformed input and over-limit input are blocking gaps.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'package': 'auditd',
    'version': '1:3.1.2 (Ubuntu 24.04)',
    'source': 'audit-userspace v3.1.2: audisp/audispd.c, audisp/audispd-pconfig.c, src/auditd-config.c',
}
RUNS_AS = 'root'
AUDITD_CONF = '/etc/audit/auditd.conf'
DEFAULT_PLUGIN_DIR = '/etc/audit/plugins.d'
BUILTIN_PATH = '/sbin/audisp-af_unix'
LINE_BUFFER = 160
KEYWORDS = ('active', 'direction', 'path', 'type', 'args', 'format')
VALUES = {
    'active': ('yes', 'no'),
    'direction': ('out',),
    'type': ('builtin', 'always'),
    'format': ('binary', 'string'),
}
REQUIRED_MODE_BITS = 0o750
STATES = ('file', 'directory', 'absent', 'unreadable', 'other')
MAX_BYTES = 65536
MAX_DIR_ENTRIES = 512
MAX_GAPS = 64
BLOCKING = frozenset({
    'input_malformed', 'path_not_observed', 'path_unreadable', 'path_other_type', 'entry_unreadable',
    'entry_other_type', 'program_not_observed', 'program_unreadable', 'too_large', 'too_many_entries',
    'gaps_truncated',
})
UNOBSERVED = (
    'Whether auditd is installed, enabled and running is not observed.',
    ('Keywords in auditd.conf other than plugin_dir are not validated. An invalid auditd.conf stops auditd '
     'from starting, so that case could only start fewer plugins than reported.'),
    'Plugin start order follows readdir order, which is not observed. Plugins are listed by name.',
    'Program contents are not read. Ownership and mode are taken from the observed stat of the target.',
)
NOT_A_VERDICT = 'Configuration metadata only. This is not a safety verdict and origin is not assessed.'


def _gap(gaps: list[dict[str, Any]], code: str, detail: str, path: str | None = None) -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code, 'detail': detail}
    if path is not None:
        gap['path'] = path
    gaps.append(gap)


def _bytes(text: str) -> bytes:
    return text.encode('utf-8', 'surrogateescape')


def _str(data: bytes) -> str:
    return data.decode('utf-8', 'surrogateescape')


def read_lines(data: bytes) -> tuple[list[tuple[int, bytes]], list[dict[str, Any]]]:
    """Port of get_line with a 160-byte fgets buffer.

    Returns the (physical line, content) pairs that are processed and the
    physical lines that are skipped.
    """
    lines: list[tuple[int, bytes]] = []
    skipped: list[dict[str, Any]] = []
    pos = 0
    physical = 1
    too_long = False
    at_line_start = True
    limit = LINE_BUFFER - 1
    while pos < len(data):
        newline = data.find(b'\n', pos, pos + limit)
        chunk = data[pos:newline + 1] if newline != -1 else data[pos:pos + limit]
        pos += len(chunk)
        visible = chunk.split(b'\0', 1)[0]  # strchr stops at the first NUL.
        if b'\n' in visible:
            if not too_long:
                lines.append((physical, visible[:visible.index(b'\n')]))
            elif at_line_start:
                skipped.append({'line': physical, 'reason': 'Swallowed: the previous line hid its newline '
                                'behind a NUL byte.'})
            too_long = False
        elif too_long and at_line_start:
            skipped.append({'line': physical, 'reason': 'Swallowed: the previous line hid its newline '
                            'behind a NUL byte.'})
        elif not too_long:
            too_long = True
            if pos >= len(data) and b'\0' not in chunk and len(chunk) < limit:
                reason = 'The last line has no newline, so get_line never returns it.'
            elif b'\0' in chunk:
                reason = 'A NUL byte hides the newline, so the line is skipped as too long.'
            else:
                reason = f'Line is {limit} bytes or longer and is skipped as too long.'
            skipped.append({'line': physical, 'reason': reason})
        physical += chunk.count(b'\n')
        at_line_start = chunk.endswith(b'\n')
    return lines, skipped


def split_line(line: bytes) -> tuple[int, list[bytes]]:
    """Port of nv_split: (rc, [name, value, option]) with words split on spaces only."""
    words = [word for word in line.split(b' ') if word]
    if not words or words[0].startswith(b'#'):
        return 0, []
    name = words[0]
    if len(words) < 2:
        return 1, [name]
    if words[1] != b'=':
        return 2, [name]
    if len(words) < 3:
        return 1, [name]
    return (1 if len(words) > 4 else 0), [name, *words[2:4]]


def glibc_dirname(path: bytes) -> bytes:
    """Port of glibc misc/dirname.c (libgen ``dirname``)."""
    last = path.rfind(b'/')
    if last > 0 and last == len(path) - 1:
        run = last
        while run > 0 and path[run - 1:run] == b'/':
            run -= 1
        if run > 0:
            last = path.rfind(b'/', 0, run)
    if last == -1:
        return b'.'
    run = last
    while run > 0 and path[run - 1:run] == b'/':
        run -= 1
    if run == 0:
        return path[:2] if last == 1 else path[:1]
    return path[:run]


def _ascii_lower(data: bytes) -> bytes:
    return data.lower()  # bytes.lower only folds ASCII, as strcasecmp does in the C locale.


def parse_plugin(text: str) -> dict[str, Any]:
    """Port of load_pconfig's line loop (before sanity_check) for one file's text."""
    config: dict[str, Any] = {'active': 'no', 'direction': None, 'path': None, 'type': 'always', 'args': [],
                              'format': 'string'}
    lines, skipped = read_lines(_bytes(text))
    notes: list[dict[str, Any]] = [{**item, 'effect': 'skipped'} for item in skipped]
    for line_no, line in lines:
        rc, words = split_line(line)
        if not words:
            continue
        if len(words) < 2:
            reason = 'Missing "=" sign.' if rc == 2 else 'Wrong number of words.'
            return {'valid': False, 'reason': f'Line {line_no}: {reason} auditd rejects the file.', 'notes': notes}
        name, value = _str(words[0]), words[1]
        option = words[2] if len(words) > 2 else None
        if rc == 1:
            notes.append({'line': line_no, 'effect': 'words_dropped',
                          'reason': 'Words after the option are ignored.'})
        keyword = _ascii_lower(words[0])
        if _str(keyword) not in KEYWORDS:
            return {'valid': False, 'reason': f'Line {line_no}: unknown keyword "{name[:64]}".', 'notes': notes}
        key = _str(keyword)
        if key != 'args' and option is not None:
            return {'valid': False, 'reason': f'Line {line_no}: "{name[:64]}" does not take an option.',
                    'notes': notes}
        if key in VALUES:
            chosen = _str(_ascii_lower(value))
            if chosen not in VALUES[key]:
                return {'valid': False, 'reason': f'Line {line_no}: invalid {key} value.', 'notes': notes}
            if key == 'type' and chosen == 'builtin':
                notes.append({'line': line_no, 'effect': 'obsolete', 'reason': 'type = builtin is run as always.'})
                chosen = 'always'
            config[key] = chosen
        elif key == 'path':
            if _ascii_lower(value).startswith(b'builtin_'):
                notes.append({'line': line_no, 'effect': 'obsolete',
                              'reason': f'builtin_ paths are replaced by {BUILTIN_PATH}.'})
                config['path'] = BUILTIN_PATH
            elif len(glibc_dirname(value)) < 4:
                return {'valid': False, 'reason': f'Line {line_no}: the directory name of path is too short.',
                        'notes': notes}
            else:
                config['path'] = _str(value)
        else:  # args
            config['args'] = [_str(value)] + ([_str(option)] if option is not None else [])
    return {'valid': True, 'config': config, 'notes': notes}


def plugin_dir_from_conf(text: str) -> tuple[str, int | None]:
    """The plugin_dir auditd uses: the last plugin_dir line, with a trailing slash added."""
    plugin_dir, source = DEFAULT_PLUGIN_DIR, None
    lines, _ = read_lines(_bytes(text))
    for line_no, line in lines:
        _, words = split_line(line)
        if len(words) >= 2 and _ascii_lower(words[0]) == b'plugin_dir':
            plugin_dir, source = _str(words[1]), line_no
    return plugin_dir, source


def _dir_key(path: str) -> str:
    stripped = path.rstrip('/')
    return stripped or '/'


def _entry_path(directory: str, name: str) -> str:
    return f'{directory.rstrip("/")}/{name}'


def _plugin_dir(observations: dict[str, Any], gaps: list[dict[str, Any]]) -> tuple[str | None, int | None]:
    if AUDITD_CONF not in observations:
        _gap(gaps, 'path_not_observed', 'auditd reads plugin_dir from this file; it was not observed.', AUDITD_CONF)
        return None, None
    conf = observations[AUDITD_CONF]
    state = conf.get('state') if isinstance(conf, dict) else None
    if state == 'absent':
        return DEFAULT_PLUGIN_DIR, None
    if state == 'file' and isinstance(conf.get('text'), str):
        if len(_bytes(conf['text'])) > MAX_BYTES:
            _gap(gaps, 'too_large', f'Larger than {MAX_BYTES} bytes; not evaluated.', AUDITD_CONF)
            return None, None
        return plugin_dir_from_conf(conf['text'])
    if state == 'unreadable':
        _gap(gaps, 'path_unreadable', 'auditd (as root) reads this file, but its content was not observed.',
             AUDITD_CONF)
    elif state in ('directory', 'other'):
        _gap(gaps, 'path_other_type', 'Not a regular file; auditd behavior was not evaluated.', AUDITD_CONF)
    else:
        _gap(gaps, 'input_malformed', 'A file observation needs a state and its text.', AUDITD_CONF)
    return None, None


def _sanity(path: str, programs: dict[str, Any], gaps: list[dict[str, Any]]) -> tuple[bool | None, str]:
    if path not in programs:
        _gap(gaps, 'program_not_observed', 'auditd stats this program before starting it; it was not observed.',
             path)
        return None, 'Program metadata not observed.'
    obs = programs[path]
    state = obs.get('state') if isinstance(obs, dict) else None
    if state == 'absent':
        return False, 'auditd cannot stat the program, so it rejects the plugin.'
    if state == 'unreadable':
        _gap(gaps, 'program_unreadable', 'The program could not be stat-ed by the collector.', path)
        return None, 'Program metadata unreadable.'
    if state in ('directory', 'other'):
        return False, 'The program is not a regular file, so auditd rejects the plugin.'
    uid, mode = (obs.get('uid'), obs.get('mode')) if state == 'file' else (None, None)
    if not isinstance(uid, int) or isinstance(uid, bool) or not isinstance(mode, int) or isinstance(mode, bool):
        _gap(gaps, 'input_malformed', 'A program observation needs a state, uid and mode.', path)
        return None, 'Program metadata malformed.'
    if uid != 0:
        return False, 'The program is not owned by root, so auditd rejects the plugin.'
    if mode & REQUIRED_MODE_BITS != REQUIRED_MODE_BITS:
        return False, 'The program lacks one of the 0750 permission bits, so auditd rejects the plugin.'
    return True, ''


def _assess_entry(path: str, name: str, obs: Any, programs: dict[str, Any],
                  gaps: list[dict[str, Any]]) -> dict[str, Any]:
    item: dict[str, Any] = {'file': path, 'name': name, 'starts': False}
    if name.startswith('.') or name.count('.') > 1:
        return {**item, 'status': 'skipped_name',
                'reason': 'Names starting with "." or with more than one "." are skipped.'}
    state = obs.get('state') if isinstance(obs, dict) else None
    if state not in STATES:
        _gap(gaps, 'input_malformed', f'State must be one of {", ".join(STATES)}.', path)
        return {**item, 'status': 'unknown', 'starts': None}
    if state == 'absent':
        return {**item, 'status': 'skipped', 'reason': 'Vanished before open; auditd skips it.'}
    if state == 'unreadable':
        _gap(gaps, 'entry_unreadable', 'auditd (as root) reads this file, but it was not observed.', path)
        return {**item, 'status': 'unknown', 'starts': None}
    if state == 'other':
        _gap(gaps, 'entry_other_type', 'Not a regular file or directory. Opening a FIFO or device can block '
             'auditd, so the outcome was not evaluated.', path)
        return {**item, 'status': 'unknown', 'starts': None}
    if state == 'directory':
        return {**item, 'status': 'rejected', 'reason': 'Not a regular file.'}
    uid, mode, text = obs.get('uid'), obs.get('mode'), obs.get('text')
    if (not isinstance(uid, int) or isinstance(uid, bool) or not isinstance(mode, int) or isinstance(mode, bool)
            or not isinstance(text, str)):
        _gap(gaps, 'input_malformed', 'A plugin file observation needs uid, mode and text.', path)
        return {**item, 'status': 'unknown', 'starts': None}
    if len(_bytes(text)) > MAX_BYTES:
        _gap(gaps, 'too_large', f'Larger than {MAX_BYTES} bytes; not evaluated.', path)
        return {**item, 'status': 'unknown', 'starts': None}
    if uid != 0:
        return {**item, 'status': 'rejected', 'reason': 'Not owned by root.'}
    if mode & 0o002:
        return {**item, 'status': 'rejected', 'reason': 'World-writable.'}
    parsed = parse_plugin(text)
    item['line_notes'] = parsed['notes']
    if not parsed['valid']:
        return {**item, 'status': 'rejected', 'reason': parsed['reason']}
    config = parsed['config']
    item['configuration'] = config
    if config['active'] != 'yes':
        return {**item, 'status': 'inactive', 'reason': 'active is not yes.'}
    if config['path'] is None:
        return {**item, 'status': 'rejected', 'reason': 'Active but no path is given.'}
    ok, reason = _sanity(config['path'], programs, gaps)
    if ok is None:
        return {**item, 'status': 'unknown', 'starts': None, 'reason': reason}
    if not ok:
        return {**item, 'status': 'rejected', 'reason': reason}
    program = config['path']
    return {**item, 'status': 'starts', 'starts': True, 'command': {
        'program': program,
        'argv': [program, *config['args']],
        'runs_as': RUNS_AS,
        'shell': False,
        'path_search': False,
        'environment': 'empty',
        'stdin': f'audit event stream ({config["format"]} format)',
        'absolute': program.startswith('/'),
        'note': ('Executed directly with execve and restarted when it exits.' if program.startswith('/') else
                 'A relative path resolves against the auditd working directory (/).'),
    }}


def assess(observations: Any = None) -> dict[str, Any]:
    """Resolve which plugin programs auditd starts as root.

    ``observations`` maps:

    * ``/etc/audit/auditd.conf`` to ``{'state': 'file', 'text': ...}`` or ``{'state': 'absent'}``;
    * the effective plugin directory (no trailing slash) to
      ``{'state': 'directory', 'entries': {name: {'state': 'file', 'uid': 0, 'mode': 0o640, 'text': ...}}}``,
      with each entry's metadata taken from the symlink target;
    * ``'programs'`` to ``{path: {'state': 'file', 'uid': 0, 'mode': 0o750}}``, stat-ed through symlinks.
    """
    gaps: list[dict[str, Any]] = []
    plugins: list[dict[str, Any]] = []
    plugin_dir: str | None = None
    source_line: int | None = None
    if not isinstance(observations, dict):
        _gap(gaps, 'input_malformed', 'Observations must be a mapping.')
    else:
        plugin_dir, source_line = _plugin_dir(observations, gaps)
        programs = observations.get('programs', {})
        if not isinstance(programs, dict):
            _gap(gaps, 'input_malformed', 'programs must be a mapping of path to stat observation.')
            programs = {}
        if plugin_dir is not None:
            key = _dir_key(plugin_dir)
            directory = observations.get(key)
            state = directory.get('state') if isinstance(directory, dict) else None
            if key not in observations:
                _gap(gaps, 'path_not_observed', 'auditd reads this plugin directory; it was not observed.', key)
            elif state == 'absent':
                pass  # opendir fails: no plugins.
            elif state == 'unreadable':
                _gap(gaps, 'path_unreadable', 'auditd (as root) lists this directory, but it was not observed.', key)
            elif state in ('file', 'other'):
                pass  # opendir fails with ENOTDIR: no plugins.
            elif state == 'directory' and isinstance(directory.get('entries'), dict):
                entries = directory['entries']
                if len(entries) > MAX_DIR_ENTRIES:
                    _gap(gaps, 'too_many_entries', f'More than {MAX_DIR_ENTRIES} entries; none were evaluated.', key)
                else:
                    for name in sorted(entries, key=lambda n: _bytes(n) if isinstance(n, str) else b''):
                        if not isinstance(name, str) or not name or '/' in name:
                            _gap(gaps, 'input_malformed', 'Entry names must be non-empty strings without "/".', key)
                            continue
                        plugins.append(_assess_entry(_entry_path(key, name), name, entries[name], programs, gaps))
            else:
                _gap(gaps, 'input_malformed', 'A directory observation needs a state and an entries mapping.', key)
    blocking = sorted({gap['code'] for gap in gaps if gap['code'] in BLOCKING})
    complete = not blocking
    started = [plugin['command'] for plugin in plugins if plugin.get('starts') is True]
    return {
        'contract_version': CONTRACT_VERSION,
        'reference': dict(REFERENCE),
        'plugin_dir': {'path': plugin_dir, 'source': (
            None if plugin_dir is None else
            {'path': AUDITD_CONF, 'line': source_line} if source_line is not None else 'default')},
        'plugins': plugins if complete else [],
        'started_programs': started if complete else None,
        'trigger': 'auditd start and every reconfigure (SIGHUP); exited plugins are restarted.',
        'complete': complete,
        'blocking_gaps': blocking,
        'gaps': gaps,
        'unobserved': list(UNOBSERVED),
        'origin': 'not_assessed',
        'not_a_verdict': NOT_A_VERDICT,
        'authorizes_response': False,
    }
