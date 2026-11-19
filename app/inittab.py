"""Pure sysvinit inittab contract (roadmap F slice, #1110).

On a host whose PID 1 is sysvinit's ``init``, every ``/etc/inittab`` entry that
``read_inittab()`` accepts runs as root at boot, on entering a runlevel, on
respawn or on a power or keyboard event. This module turns captured
``/etc/inittab`` text, plus a few observed facts about the host, into the
entries init loads and how ``spawn()`` would start each one. It performs no
I/O, never runs init, a shell or an entry, and never authorizes a response.

The rules follow ``src/init.c`` and ``src/init.h`` in sysvinit 3.14 and 3.15,
whose ``read_inittab()`` and ``spawn()`` are identical:

- Lines are read with ``fgets`` into a 256-byte buffer. A line that does not
  end in a newline within 255 bytes is skipped as "possibly too long", and so
  is a final line without a newline. Leading spaces and tabs are skipped, and
  blank lines and lines starting with ``#`` are ignored. Both checks run
  before the too-long check.
- Fields are split with ``strsep`` as ``id:runlevels:action:process``; the
  process is everything after the third colon, colons included. A line is
  rejected for a missing or empty id, a missing runlevels or process field, a
  missing or empty action, an id over 4 bytes, runlevels over 11, a process
  over 256 (unreachable behind the 255-byte line buffer) or an action over 32. An action is matched case-insensitively; an
  unknown action, or an id that repeats an accepted entry (other than ``~~``),
  rejects the line.
- Empty runlevels become ``0123456789`` (``S0123456789`` for power and
  ctrl-alt-del actions). ``sysinit`` gets the boot pseudo-level ``#``, and
  ``boot``/``bootwait`` get ``*``. A lowercase ``s`` is kept as written, so it
  does not select single-user mode.
- When no accepted entry's runlevels contain ``S``, init appends
  ``~~:S:wait:/sbin/sulogin``.
- ``initdefault`` uses the highest runlevel character of the first such entry,
  uppercased; one outside ``0-9S``, or no entry, makes init prompt on the
  console. Non-ASCII runlevel bytes leave the default unresolved with a
  blocking gap, because x86_64 (signed ``char``) and arm (unsigned ``char``)
  init pick differently.
- ``spawn()`` drops one leading ``+`` (which also stops utmp/wtmp records).
  When ``/etc/initscript`` is readable and the runlevel is not ``S``, it runs
  ``/bin/sh /etc/initscript <id> <runlevels> <action> <process>``, minus a
  leading ``@``. Otherwise, a process containing any of
  ``~`!$^&*()=|\\{}[];"'<>?`` and not starting with ``@`` runs as
  ``/bin/sh -c <process>``. Any other process, minus a leading ``@``, is split
  at spaces and tabs, stops at ``#``, keeps at most 14 words and is passed
  straight to ``execvp``.

Fail-closed rules: unobserved text, an unobserved ``/etc/inittab.d`` or
``/etc/initscript``, ``.tab`` files in ``/etc/inittab.d`` (not modelled
here), invalid UTF-8, NUL bytes and over-limit input mark the result
incomplete. ``origin`` is always ``not_assessed`` and no result is a safety
verdict.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('3.14', '3.15')
INITTAB = '/etc/inittab'
INITTABD = '/etc/inittab.d'
INITSCRIPT = '/etc/initscript'
SHELL = '/bin/sh'
SULOGIN = '/sbin/sulogin'
SHELL_CHARS = '~`!$^&*()=|\\{}[];"\'<>?'
FGETS_MAX = 255
ID_MAX = 4
RUNLEVELS_MAX = 11
PROCESS_MAX = 256
ACTION_MAX = 32
MAX_ARGS = 14
MAX_TEXT = 65536
MAX_ENTRIES = 512
MAX_GAPS = 64

ACTIONS = ('respawn', 'wait', 'once', 'boot', 'bootwait', 'powerfail', 'powerfailnow', 'powerwait',
           'powerokwait', 'ctrlaltdel', 'off', 'ondemand', 'initdefault', 'sysinit', 'kbrequest')
POWER_ACTIONS = frozenset({'powerwait', 'powerfail', 'powerokwait', 'powerfailnow', 'ctrlaltdel'})
# inittab(5): when init starts each action, and whether init waits for it.
TRIGGERS = {
    'sysinit': ('boot, before boot and bootwait entries', True),
    'boot': ('boot', False),
    'bootwait': ('boot', True),
    'once': ('entering a listed runlevel', False),
    'wait': ('entering a listed runlevel', True),
    'respawn': ('entering a listed runlevel, and again whenever it exits', False),
    'ondemand': ('telinit a, b or c for a listed level, and again whenever it exits', False),
    'powerwait': ('power failure signalled to init', True),
    'powerfail': ('power failure signalled to init', False),
    'powerfailnow': ('init told the UPS battery is almost empty', True),
    'powerokwait': ('init told power has been restored', True),
    'ctrlaltdel': ('Ctrl-Alt-Del pressed on the console', True),
    'kbrequest': ('the console KeyboardSignal key combination', True),
    'off': (None, False),
    'initdefault': (None, False),
}
BLOCKING = frozenset({'text_not_observed', 'over_limit', 'invalid_utf8', 'binary', 'entries_over_limit',
                      'inittab_d_not_observed', 'inittab_d_not_modelled', 'initscript_not_observed',
                      'gaps_truncated', 'default_runlevel_char_signedness'})
NOT_OBSERVED = (
    'Whether PID 1 is sysvinit init; systemd ignores /etc/inittab, and BusyBox init uses a different format.',
    'The current and default runlevel actually in use, so which runlevel entries are running now.',
    'The contents of programs or scripts an entry runs.',
    'Whether respawn entries are currently disabled for respawning too fast (10 starts in 120 seconds).',
    ('How much of a shell-mode process init copies: spawn() strncpy()s it into a buffer whose length it measures '
     'with strlen() on uninitialised memory, so shell_text is the text init intends to run and may be truncated at '
     'spawn time.'),
)


def _gap(gaps: list[dict[str, Any]], code: str, line: int | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'line': line, 'detail': detail[:240], 'blocking': code in BLOCKING})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'line': None, 'detail': 'Further gaps were not recorded.',
                     'blocking': True})


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()


def _lines(data: bytes) -> list[tuple[bytes, bool]]:
    """Return what successive ``fgets(buf, 256, fp)`` + ``get_void`` calls see, with a too-long flag."""
    lines: list[tuple[bytes, bool]] = []
    start = 0
    while start < len(data):
        newline = data.find(b'\n', start, start + FGETS_MAX)
        if newline >= 0:
            lines.append((data[start:newline + 1], False))
            start = newline + 1
            continue
        chunk = data[start:start + FGETS_MAX]
        # get_void() discards the rest of the physical line.
        rest = data.find(b'\n', start + len(chunk))
        start = len(data) if rest < 0 else rest + 1
        lines.append((chunk, True))
    return lines


def effective_runlevels(action: str, runlevels: str) -> str:
    """Return the runlevel string init stores for an accepted entry."""
    if action == 'sysinit':
        return '#'
    if action in ('boot', 'bootwait'):
        return '*'
    if runlevels:
        return runlevels
    return 'S0123456789' if action in POWER_ACTIONS else '0123456789'


def command(process: str, *, initscript: bool = False) -> dict[str, Any]:
    """Describe how ``spawn()`` starts ``process`` (outside runlevel S when ``initscript`` is set)."""
    utmp = not process.startswith('+')
    proc = process[1:] if not utmp else process
    result: dict[str, Any] = {'utmp_records': utmp, 'sha256': _sha(process), 'mode': None, 'argv': None,
                              'shell_text': None, 'words_dropped': 0}
    if initscript:
        if proc.startswith('@'):
            proc = proc[1:]
        result.update(mode='initscript', argv=[SHELL, INITSCRIPT, '<id>', '<runlevels>', '<action>', proc])
        return result
    if proc[:1] != '@' and any(ch in SHELL_CHARS for ch in proc):
        result.update(mode='shell', argv=[SHELL, '-c', proc], shell_text=proc)
        return result
    if proc.startswith('@'):
        proc = proc[1:]
    # The word loop fills args[1..14]; a word cut by '#' ends the command, and a '#' that starts a
    # word still adds an empty argument.
    words: list[str] = []
    position = 0
    while len(words) < MAX_ARGS:
        while position < len(proc) and proc[position] in ' \t':
            position += 1
        if position >= len(proc):
            break
        end = position
        while end < len(proc) and proc[end] not in ' \t#':
            end += 1
        words.append(proc[position:end])
        if end >= len(proc) or proc[end] == '#':
            position = len(proc)
            break
        position = end + 1
    result['words_dropped'] = len(proc[position:].split('#', 1)[0].split())
    result.update(mode='exec', argv=words)
    return result


def _reject(line: str) -> tuple[str | None, list[str] | None]:
    """Emulate the strsep field split and syntax checks; return ``(error, fields)``."""
    parts = line.split(':', 3)
    fields: list[str | None] = [*parts, *([None] * (4 - len(parts)))]
    ident, runlevels, action, process = fields
    process = process[:-1] if process is not None and process.endswith('\n') else process
    if process is not None and '\n' in process:
        process = process.split('\n', 1)[0]
    error = None
    if not ident:
        error = 'missing id field'
    if runlevels is None:
        error = 'missing runlevel field'
    if process is None:
        error = 'missing process field'
    if not action:
        error = 'missing action field'
    if ident and len(ident.encode('utf-8', 'surrogatepass')) > ID_MAX:
        error = f'id field too long (max {ID_MAX} characters)'
    if runlevels and len(runlevels.encode('utf-8', 'surrogatepass')) > RUNLEVELS_MAX:
        error = f'rlevel field too long (max {RUNLEVELS_MAX} characters)'
    if process and len(process.encode('utf-8', 'surrogatepass')) > PROCESS_MAX:
        error = f'process field too long (max {PROCESS_MAX} characters)'
    if action and len(action.encode('utf-8', 'surrogatepass')) > ACTION_MAX:
        error = 'action field too long'
    if error:
        return error, None
    return None, [ident or '', runlevels or '', action or '', process or '']


def evaluate(text: str | bytes | None, *, state: str = 'present', inittab_d: Any = None,
             initscript: str | None = None) -> dict[str, Any]:
    """Resolve the entries sysvinit loads from ``/etc/inittab`` and how each one runs.

    ``state`` is ``'present'`` (``text`` is the captured file) or ``'absent'``. ``inittab_d`` is
    ``{'state': 'absent' | 'listed' | 'unreadable', 'names': [...]}`` for ``/etc/inittab.d``.
    ``initscript`` is ``'absent'`` or ``'readable'`` for ``/etc/initscript``. ``None`` means not observed.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'format': 'sysvinit_inittab', 'source_versions': list(SOURCE_VERSIONS),
        'path': INITTAB, 'complete': False, 'sha256': None, 'entries': [], 'rejected': [],
        'implicit_sulogin': None, 'default_runlevel': None, 'default_runlevel_prompt': None,
        'execution': {'user': 'root', 'shell': SHELL, 'shell_chars': SHELL_CHARS, 'max_exec_words': MAX_ARGS,
                      'initscript': INITSCRIPT, 'initscript_readable': None},
        'origin': 'not_assessed', 'gaps': gaps, 'not_observed': list(NOT_OBSERVED),
    }
    if initscript not in ('absent', 'readable'):
        _gap(gaps, 'initscript_not_observed', None, f'Whether {INITSCRIPT} is readable was not observed; when it '
             'is, every entry outside runlevel S runs through it.')
    else:
        result['execution']['initscript_readable'] = initscript == 'readable'
    if not isinstance(inittab_d, Mapping) or inittab_d.get('state') not in ('absent', 'listed', 'unreadable'):
        _gap(gaps, 'inittab_d_not_observed', None, f'No listing of {INITTABD} was supplied; init also loads '
             '*.tab files from it.')
    elif inittab_d['state'] == 'unreadable':
        _gap(gaps, 'inittab_d_not_observed', None, f'{INITTABD} could not be listed.')
    elif inittab_d['state'] == 'listed':
        tabs = [n for n in inittab_d.get('names') or [] if isinstance(n, str) and len(n) >= 5 and n.endswith('.tab')]
        if tabs:
            _gap(gaps, 'inittab_d_not_modelled', None, f'{len(tabs)} *.tab file(s) in {INITTABD} also load '
                 'entries; this contract does not resolve them yet.')
    if state == 'absent':
        lines: list[tuple[bytes, bool]] = []
    elif text is None:
        _gap(gaps, 'text_not_observed', None, f'{INITTAB} was not captured.')
        return _finish(result, gaps)
    else:
        data = text.encode('utf-8', 'surrogatepass') if isinstance(text, str) else text
        if not isinstance(data, bytes) or len(data) > MAX_TEXT:
            _gap(gaps, 'over_limit', None, f'More than {MAX_TEXT} bytes.')
            return _finish(result, gaps)
        if b'\x00' in data:
            _gap(gaps, 'binary', None, 'The file contains NUL bytes.')
            return _finish(result, gaps)
        try:
            data.decode('utf-8')
        except UnicodeDecodeError:
            _gap(gaps, 'invalid_utf8', None, 'The file is not valid UTF-8.')
            return _finish(result, gaps)
        result['sha256'] = hashlib.sha256(data).hexdigest()
        lines = _lines(data)
    entries: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for number, (raw, too_long) in enumerate(lines, 1):
        stripped = raw.lstrip(b' \t')
        if stripped[:1] in (b'#', b'\n'):
            continue
        if len(entries) + len(rejected) >= MAX_ENTRIES:
            _gap(gaps, 'entries_over_limit', number, f'More than {MAX_ENTRIES} entry lines.')
            return _finish(result, gaps)
        if too_long:
            rejected.append({'line': number, 'reason': 'too_long_or_unterminated',
                             'detail': 'No newline within 255 bytes, or a final line without a newline.'})
            continue
        line = stripped.decode('utf-8')
        error, fields = _reject(line)
        if error:
            rejected.append({'line': number, 'reason': 'syntax', 'detail': error})
            continue
        ident, runlevels, action_text, process = fields
        action = action_text.lower() if action_text.isascii() else action_text
        if action not in ACTIONS:
            rejected.append({'line': number, 'reason': 'unknown_action', 'detail': action_text[:ACTION_MAX]})
            continue
        if ident != '~~' and any(e['id'] == ident for e in entries):
            rejected.append({'line': number, 'reason': 'duplicate_id', 'detail': ident})
            continue
        entries.append(_entry(number, ident, runlevels, action, process, result['execution']['initscript_readable']))
    has_single_user = any('S' in e['runlevels'] for e in entries)
    result['implicit_sulogin'] = not has_single_user
    if not has_single_user:
        entries.append(_entry(None, '~~', 'S', 'wait', SULOGIN, False, implicit=True))
    result['entries'] = entries
    result['rejected'] = rejected
    default = next((e for e in entries if e['action'] == 'initdefault'), None)
    if default and not default['runlevels'].isascii():
        # get_init_default() keeps the highest plain ``char``: signed on x86_64, so bytes >= 0x80 never win, but
        # unsigned on arm/aarch64, where they do. The host architecture is not observed, so do not guess.
        _gap(gaps, 'default_runlevel_char_signedness', default['line'],
             'The initdefault runlevels contain non-ASCII bytes; which runlevel init picks depends on whether the '
             'host C char type is signed (x86_64) or unsigned (arm), which was not observed.')
        result.update(default_runlevel=None, default_runlevel_prompt=None)
        return _finish(result, gaps)
    level = max(default['runlevels']) if default and default['runlevels'] else ''
    level = level.upper()
    if level and level in '0123456789S':
        result.update(default_runlevel=level, default_runlevel_prompt=False)
    else:
        result.update(default_runlevel=None, default_runlevel_prompt=True)
    return _finish(result, gaps)


def _entry(line: int | None, ident: str, runlevels: str, action: str, process: str, initscript: bool | None,
           *, implicit: bool = False) -> dict[str, Any]:
    effective = effective_runlevels(action, runlevels)
    trigger, waits = TRIGGERS[action]
    runs = action not in ('off', 'initdefault')
    entry: dict[str, Any] = {
        'line': line, 'implicit': implicit, 'id': ident, 'runlevels_written': runlevels, 'runlevels': effective,
        'action': action, 'runs': runs, 'trigger': trigger, 'init_waits': waits, 'user': 'root',
        'process': process, 'command': None, 'command_single_user': None, 'notes': [], 'origin': 'not_assessed',
    }
    if 's' in runlevels and action not in ('sysinit', 'boot', 'bootwait'):
        entry['notes'].append('lowercase_s_is_not_single_user')
    if runs and not process.strip(' \t'):
        entry['notes'].append('empty_process')
    if runs:
        # /etc/initscript is not used in runlevel S.
        entry['command_single_user'] = command(process)
        entry['command'] = command(process, initscript=True) if initscript else command(process)
    return entry


def _finish(result: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    result['complete'] = not any(g['blocking'] for g in gaps)
    return result
