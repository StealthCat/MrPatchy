"""Pure smartd warning-command contract (roadmap F slice, #1207).

Takes the captured text of ``/etc/smartd.conf`` and the observed smartd daemon
options. It reports which commands smartd runs when it warns about a disk, as
which user, and for which configuration entries. It never reads hook contents,
runs a command or authorizes a response action.

The semantics come from smartmontools 7.4: ``ParseConfigFile``,
``ParseConfigLine``, ``ParseToken`` and ``MailWarning`` in ``smartd.cpp`` at tag
``RELEASE_7_4``. They also come from the Ubuntu 24.04 ``smartmontools``
7.4-2build1 package files ``smartd_warning.sh``, ``smartd-runner`` and the
default ``smartd.conf``:

* Lines longer than 256 bytes (counting the newline) are rejected. ``#`` starts a
  comment anywhere on a line. A line whose last non-blank character is ``\\``
  continues onto the next line, and the joined line may be at most 1023 bytes.
  Tokens are split on space, tab and newline only.
* ``DEFAULT`` resets the defaults and sets new ones. Each later entry starts
  from a copy of them. ``DEVICESCAN`` ends parsing, so later lines are never
  read. Every directive must be ``-`` plus one character. An unknown directive,
  a missing argument, ``-M`` options without ``-m``, or ``-m <nomailer>``
  without ``-M exec`` is a syntax error. smartd then refuses the whole file and
  runs nothing from it.
* For every warning on an entry with ``-m`` or ``-M exec``, smartd runs
  ``popen("<warning script> 2>&1")`` through ``/bin/sh``. The warning script
  defaults to ``/usr/share/smartmontools/smartd_warning.sh``. smartd runs it as
  root unless ``-u/--warn-as-user`` is set, and ``-w/--warnexec`` replaces it.
* ``smartd_warning.sh`` splits the ``-m`` addresses on commas and blanks. If any
  address starts with ``@``, it runs ``/etc/smartmontools/smartd_warning.d/NAME``
  for each ``@NAME``, or every executable regular file there for ``@ALL``, and
  exits without mailing when no plain address is left. Otherwise it ``exec``s
  the ``-M exec`` path, or ``mail``, with ``-s SUBJECT ADDRESS...``. With no
  address (``<nomailer>``), it ``exec``s the ``-M exec`` path with no arguments.
  ``PATH`` is ``/usr/local/bin:/usr/bin:/bin``.
* Debian's default ``-M exec /usr/share/smartmontools/smartd-runner`` runs
  ``run-parts --report --lsbsysinit`` over ``/etc/smartmontools/run.d`` as the
  same user.

Missing or malformed input, unobserved daemon options and a config smartd
would reject are explicit blocking gaps. Entries after a syntax error are never
reported. No record is labelled safe, and ``origin`` is always ``not_assessed``.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'package': 'smartmontools',
    'version': '7.4-2build1 (Ubuntu 24.04)',
    'source': 'smartd.cpp at RELEASE_7_4',
}
CONFIG_PATH = '/etc/smartd.conf'
DEFAULT_WARNING_SCRIPT = '/usr/share/smartmontools/smartd_warning.sh'
PLUGIN_DIR = '/etc/smartmontools/smartd_warning.d'
SMARTD_RUNNER = '/usr/share/smartmontools/smartd-runner'
RUNNER_DIR = '/etc/smartmontools/run.d'
WARNING_PATH = '/usr/local/bin:/usr/bin:/bin'
MAX_LINE = 256
MAX_CONTINUED = 1023
MAX_BYTES = 262144
MAX_ENTRIES = 512
MAX_GAPS = 64
SCAN = 'DEVICESCAN'

# Directives that take one argument (ParseToken); -M is handled separately.
_WITH_ARG = frozenset('CUTdFlonSsmiIrRWvPec')
_NO_ARG = frozenset('Hftpua')
_FREQUENCIES = ('once', 'always', 'daily', 'diminishing')
_DELIMS = re.compile(r'[ \t\n]+')
_USER = re.compile(r'[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}(?::[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63})?|\d{1,10}(?::\d{1,10})?')

BLOCKING = frozenset({
    'input_malformed', 'config_not_observed', 'config_unreadable', 'config_too_large', 'config_rejected',
    'daemon_options_not_observed', 'too_many_entries', 'gaps_truncated',
})
UNOBSERVED = (
    'Arguments of non-mail directives (for example -d, -s, -n) are not validated. An invalid one makes smartd '
    'reject the file, so this contract can over-report commands, never under-report them.',
    'The /etc/smartmontools/smartd_warning.d and /etc/smartmontools/run.d listings are not evaluated here.',
    'Which devices exist, whether smartd is installed and running, and when warnings fire are not observed.',
    'The contents of the warning script, plugins, -M exec program and run.d hooks are not read.',
    'A replacement smartd.conf given with -c is not observed.',
)
NOT_A_VERDICT = 'Configuration text only. This is not a safety verdict and origin is not assessed.'


def _gap(gaps: list[dict[str, Any]], code: str, detail: str, line: int | None = None) -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code, 'detail': detail}
    if line is not None:
        gap['line'] = line
    gaps.append(gap)


def _fresh() -> dict[str, Any]:
    return {'address': '', 'exec': '', 'frequency': None, 'test': False}


class _Reject(Exception):
    def __init__(self, line: int, detail: str) -> None:
        super().__init__(detail)
        self.line = line
        self.detail = detail


def _parse_line(text: str, line: int, defaults: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Mirror ParseConfigLine. Returns (kind, entry) where kind is skip, default, entry or scan."""
    tokens = [token for token in _DELIMS.split(text) if token]
    if not tokens or tokens[0].startswith('#'):
        return 'skip', None
    name = tokens[0]
    if name == 'DEFAULT':
        cfg = _fresh()
        kind = 'default'
    else:
        cfg = dict(defaults)
        kind = 'scan' if name == SCAN else 'entry'
    index = 1
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token.startswith('#'):
            continue
        if token[0] != '-' or len(token) != 2:
            raise _Reject(line, f'Unknown directive {token!r}; smartd rejects the file.')
        sym = token[1]
        if sym in _NO_ARG:
            continue
        if sym not in _WITH_ARG and sym != 'M':
            raise _Reject(line, f'Unknown directive {token!r}; smartd rejects the file.')
        if index >= len(tokens):
            raise _Reject(line, f'Missing argument to {token}; smartd rejects the file.')
        arg = tokens[index]
        index += 1
        if sym == 'm':
            cfg['address'] = arg
        elif sym == 'M':
            if arg in _FREQUENCIES:
                cfg['frequency'] = arg
            elif arg == 'test':
                cfg['test'] = True
            elif arg == 'exec':
                if index >= len(tokens):
                    raise _Reject(line, '-M exec must be followed by an executable path; smartd rejects the file.')
                cfg['exec'] = tokens[index]
                index += 1
            else:
                raise _Reject(line, f'Invalid argument to -M: {arg!r}; smartd rejects the file.')
    if kind == 'default':
        return kind, cfg
    if not cfg['address'] and (cfg['exec'] or cfg['frequency'] is not None or cfg['test']):
        raise _Reject(line, '-M directives need an -m ADDRESS directive; smartd rejects the file.')
    if cfg['address'] == '<nomailer>':
        if not cfg['exec']:
            raise _Reject(line, '-m <nomailer> needs -M exec; smartd rejects the file.')
        cfg['address'] = ''
    cfg['name'] = name
    cfg['line'] = line
    return kind, cfg


def parse_config(text: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Mirror ParseConfigFile. Returns (entries, rejection) where rejection is set on a syntax error."""
    entries: list[dict[str, Any]] = []
    defaults = _fresh()
    full = ''
    physical = 0
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
        trailing_newline = True
    else:
        trailing_newline = False
    try:
        for position, raw in enumerate(lines):
            physical += 1
            has_newline = position < len(lines) - 1 or trailing_newline
            line = raw + ('\n' if has_newline else '')
            if len(line.encode('utf-8', 'surrogateescape')) > MAX_LINE:
                raise _Reject(physical, f'Line is more than {MAX_LINE} bytes; smartd rejects the file.')
            if '#' in line:
                line = line[:line.index('#')]
            if len(full.encode('utf-8', 'surrogateescape')) + len(line.encode('utf-8', 'surrogateescape')) > \
                    MAX_CONTINUED:
                raise _Reject(physical, f'Continued line is more than {MAX_CONTINUED} bytes; smartd rejects the file.')
            slash = line.rfind('\\')
            if slash >= 0 and not line[slash + 1:].strip(' \t\n'):
                full += line[:slash] + ' ' + line[slash + 1:]
                continue
            full += line
            kind, cfg = _parse_line(full, physical, defaults)
            full = ''
            if kind == 'default':
                defaults = cfg  # type: ignore[assignment]
            elif cfg is not None:
                cfg['devicescan'] = kind == 'scan'
                entries.append(cfg)
                if kind == 'scan':
                    return entries, None
        if full:
            kind, cfg = _parse_line(full, physical, defaults)
            if kind in ('entry', 'scan') and cfg is not None:
                cfg['devicescan'] = kind == 'scan'
                entries.append(cfg)
    except _Reject as rejection:
        return [], {'line': rejection.line, 'detail': rejection.detail}
    return entries, None


def _commands(entry: dict[str, Any], script: str, custom: bool, user: str) -> list[dict[str, Any]]:
    address, program = entry['address'], entry['exec']
    if not address and not program:
        return []
    commands = [{'step': 'warning_script', 'command': f'{script} 2>&1', 'via': '/bin/sh -c', 'user': user}]
    if custom:
        return commands
    tokens = [token for token in re.split(r'[\s,]+', address) if token]
    plugins = [token[1:] for token in tokens if token.startswith('@') and len(token) > 1]
    plain = [token for token in tokens if not (token.startswith('@') and len(token) > 1)]
    for name in plugins:
        target = f'{PLUGIN_DIR}/*' if name == 'ALL' else f'{PLUGIN_DIR}/{name}'
        commands.append({'step': 'plugin', 'command': target, 'stdin': '/dev/null', 'user': user,
                         'all_plugins': name == 'ALL'})
    if plugins and not plain:
        return commands
    mailer = program or 'mail'
    step: dict[str, Any] = {'step': 'mailer', 'command': mailer, 'user': user,
                            'resolved_via_path': '/' not in mailer, 'path': WARNING_PATH}
    if plain:
        step['arguments'] = ['-s', '<subject>', *plain]
        step['stdin'] = 'warning message'
    else:
        step['arguments'] = []
        step['stdin'] = '/dev/null'
    commands.append(step)
    if mailer == SMARTD_RUNNER:
        commands.append({'step': 'run_parts', 'command': f'run-parts --report --lsbsysinit -- {RUNNER_DIR}',
                         'user': user, 'arguments': ['<message file>', *(step['arguments'] + ['', '', ''])[:3]]})
    return commands


def evaluate(config_text: Any = None, *, config_state: Any = None, daemon_options: Any = None) -> dict[str, Any]:
    """Resolve which commands smartd runs on disk warnings from smartd.conf text and daemon options.

    ``config_state`` is ``present``, ``absent`` or ``unreadable`` for ``/etc/smartd.conf``.
    ``config_text`` is its text when present. ``daemon_options`` is ``None`` when the smartd command
    line was not observed. Otherwise it is a mapping with optional ``warnexec`` (the ``-w`` value) and
    ``warn_as_user`` (the ``-u`` value), where a missing or ``None`` value means the option is not set.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'config_path': CONFIG_PATH,
        'accepted': None, 'entries': [], 'gaps': gaps, 'unobserved': list(UNOBSERVED),
        'origin': 'not_assessed', 'note': NOT_A_VERDICT,
    }
    script, custom, user = DEFAULT_WARNING_SCRIPT, False, 'root'
    if daemon_options is None:
        _gap(gaps, 'daemon_options_not_observed',
             'The smartd -w/--warnexec and -u/--warn-as-user options were not observed, so the warning command '
             'and its user are assumed to be the defaults.')
    elif not isinstance(daemon_options, dict) or set(daemon_options) - {'warnexec', 'warn_as_user'}:
        _gap(gaps, 'input_malformed', 'Daemon options must be a mapping with warnexec and warn_as_user only.')
    else:
        warnexec, as_user = daemon_options.get('warnexec'), daemon_options.get('warn_as_user')
        if warnexec is not None:
            if not isinstance(warnexec, str) or not warnexec or len(warnexec) > 255 or '\x00' in warnexec:
                _gap(gaps, 'input_malformed', 'The -w/--warnexec value is malformed.')
            else:
                script, custom = warnexec, warnexec != DEFAULT_WARNING_SCRIPT
        if as_user is not None:
            if as_user == 'restricted':
                _gap(gaps, 'input_malformed', '--warn-as-user=restricted applies only to Windows.')
            elif not isinstance(as_user, str) or not _USER.fullmatch(as_user):
                _gap(gaps, 'input_malformed', 'The -u/--warn-as-user value is malformed.')
            elif as_user not in ('-', '0', '0:0', 'root', 'root:root'):
                user = as_user
    if custom:
        _gap(gaps, 'custom_warning_script',
             'smartd runs a replacement warning command; plugin and mailer steps after it are not modelled.')

    if config_state == 'absent':
        result['accepted'] = True
        result['entries'] = [{'name': SCAN, 'line': 0, 'devicescan': True, 'implicit': True, 'address': '',
                              'exec': '', 'frequency': None, 'test': False, 'commands': []}]
    elif config_state == 'unreadable':
        _gap(gaps, 'config_unreadable', 'smartd.conf exists but could not be read; smartd would not start.')
    elif config_state != 'present':
        _gap(gaps, 'config_not_observed', 'The state of /etc/smartd.conf was not supplied.')
    elif not isinstance(config_text, str) or '\x00' in config_text:
        _gap(gaps, 'input_malformed', 'The smartd.conf text must be a string without NUL bytes.')
    elif len(config_text.encode('utf-8', 'surrogateescape')) > MAX_BYTES:
        _gap(gaps, 'config_too_large', f'smartd.conf is larger than {MAX_BYTES} bytes and was not assessed.')
    else:
        entries, rejection = parse_config(config_text)
        if rejection is not None:
            result['accepted'] = False
            result['rejection'] = rejection
            _gap(gaps, 'config_rejected', rejection['detail'], rejection['line'])
        else:
            result['accepted'] = True
            if len(entries) > MAX_ENTRIES:
                _gap(gaps, 'too_many_entries', f'Only the first {MAX_ENTRIES} entries are reported.')
                entries = entries[:MAX_ENTRIES]
            for entry in entries:
                entry['commands'] = _commands(entry, script, custom, user)
                entry['runs_at_startup'] = bool(entry['test'] and entry['commands'])
                entry['uses_smartd_runner'] = entry['exec'] == SMARTD_RUNNER
                result['entries'].append(entry)
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
