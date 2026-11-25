"""Pure NUT upsmon command contract (roadmap F slice, #1247).

Network UPS Tools' ``upsmon`` is started at boot as root. It runs two
administrator-configured commands through ``system()``, which is ``/bin/sh -c``:

- ``SHUTDOWNCMD`` when a power-fail shutdown starts. It runs as root, either in
  the privileged parent of the default split-process mode or in the single
  root process under ``-p``.
- ``NOTIFYCMD "<message>"`` for every notify event whose effective flags
  include ``EXEC``. It runs in a forked child of the monitoring process, which
  is ``RUN_AS_USER`` in split mode and root under ``-p``. ``IGNORE`` makes
  ``notify()`` return before anything runs.

This module turns captured ``upsmon.conf`` text, the observed ``upsmon`` argv
words and the observed ``NUT_CONFPATH`` value into those commands. It performs
no I/O, never runs upsmon or a shell, never looks up an account and never
authorizes a response action.

Semantics follow NUT v2.8.1 (Ubuntu 24.04 ``nut-client``) ``clients/upsmon.c``
and ``common/parseconf.c``:

- **Tokenizer.** ``#`` starts a comment outside quotes. ``\\`` takes the next
  byte literally, and a backslash-newline continues the line. ``"..."`` makes
  one word and may span physical lines. A ``#`` inside quotes is a parse error:
  that logical line is dropped and parsing resumes after the ``#`` as a new
  line. A bare ``=`` is always a word of its own. ``addchar`` discards bytes
  below 0x20 or above 0x7f, but such a byte can still start an empty word.
  Words keep their first 512 bytes, and a line keeps its first 32 words. At end
  of file a line with no completed word is dropped.
- **Directives.** Directive names are exact-case. A directive with too few
  words is an invalid directive and is ignored. ``SHUTDOWNCMD``, ``NOTIFYCMD``
  and ``RUN_AS_USER`` take the second word, and the last one wins.
  ``NOTIFYMSG``/``NOTIFYFLAG`` match the event name case-insensitively.
  ``NOTIFYFLAG`` splits the flags on ``+`` with exact-case names and replaces
  the event's earlier flags. An unknown flag is ignored, and an unknown event
  leaves every flag unchanged. The default flags are ``SYSLOG+WALL``.
- **Account.** ``-u`` replaces the built-in default user, and a
  ``RUN_AS_USER`` in the file replaces both, because the file is read after
  the options. ``-p`` disables the split and runs everything as root.
- **Message.** The message template is a ``printf`` format given the UPS
  system name, truncated to 511 bytes and placed between double quotes in the
  shell command. Quote, ``$``, backquote and backslash characters in it remain
  active for the shell.

Fail-closed rules: an unobserved config, argv or environment, NUL bytes, text
that is not UTF-8, over-limit input, an argv that makes upsmon exit instead of
monitoring, and a config path that differs from the one upsmon reads make the
result incomplete. ``MONITOR`` and ``CERTIDENT`` passwords and the text of
unrelated directives are never copied into the result. A message template whose
``printf`` conversions are not modeled leaves that event ``unresolved``.
``origin`` is always ``not_assessed``, and no result is a safety verdict.
Startup-fatal conditions in ``MONITOR`` and ``MINSUPPLIES`` are not modeled, so
the contract can over-report commands for a daemon that exits, but it does not
under-report.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('2.8.1',)
DEFAULT_CONFPATH = '/etc/nut'
CONFIG_NAME = 'upsmon.conf'
SHELL = '/bin/sh'
# parseconf.h: PCONF_DEFAULT_ARG_LIMIT and PCONF_DEFAULT_WORDLEN_LIMIT.
ARG_LIMIT = 32
WORDLEN_LIMIT = 512
# do_notify formats into char msg[SMALLBUF]; SMALLBUF is 512.
MESSAGE_MAX = 511
MAX_TEXT = 262144
MAX_ARGV = 64
MAX_ARGV_WORD = 4096
MAX_LINE_NOTES = 256

# upsmon.h notifylist[], in table order, with the stock messages.
NOTIFY_EVENTS = (
    ('ONLINE', 'UPS %s on line power'),
    ('ONBATT', 'UPS %s on battery'),
    ('LOWBATT', 'UPS %s battery is low'),
    ('FSD', 'UPS %s: forced shutdown in progress'),
    ('COMMOK', 'Communications with UPS %s established'),
    ('COMMBAD', 'Communications with UPS %s lost'),
    ('SHUTDOWN', 'Auto logout and shutdown proceeding'),
    ('REPLBATT', 'UPS %s battery needs to be replaced'),
    ('NOCOMM', 'UPS %s is unavailable'),
    ('NOPARENT', 'upsmon parent process died - shutdown impossible'),
    ('CAL', 'UPS %s: calibration in progress'),
    ('OFF', 'UPS %s: administratively OFF or asleep'),
    ('NOTOFF', 'UPS %s: no longer administratively OFF or asleep'),
    ('BYPASS', 'UPS %s: on bypass (powered, not protecting)'),
    ('NOTBYPASS', 'UPS %s: no longer on bypass'),
)
FLAG_NAMES = ('IGNORE', 'SYSLOG', 'WALL', 'EXEC')
DEFAULT_FLAGS = frozenset({'SYSLOG', 'WALL'})
SHELL_ACTIVE_IN_DOUBLE_QUOTES = frozenset('"$`\\')

# getopt(argc, argv, "+DFBhic:P:f:pu:VK46")
OPTIONS_WITH_ARGUMENT = frozenset('cPfu')
OPTIONS_FLAG = frozenset('DFBpK46')
# -h prints help, -V prints the version, -i and unknown options print usage;
# -c sends a command to a running upsmon; -K only checks POWERDOWNFLAG.
EXITING_OPTIONS = frozenset('hViK')
EXITING_WITH_ARGUMENT = frozenset('c')

# Directive -> minimum number of words parse_conf_arg needs to accept it.
KNOWN_DIRECTIVES = {
    'SHUTDOWNCMD': 2, 'SHUTDOWNEXIT': 2, 'POWERDOWNFLAG': 2, 'NOTIFYCMD': 2,
    'POLLFREQ': 2, 'POLLFREQALERT': 2, 'POLLFAIL_LOG_THROTTLE_MAX': 2,
    'OFFDURATION': 2, 'HOSTSYNC': 2, 'DEADTIME': 2, 'MINSUPPLIES': 2,
    'RBWARNTIME': 2, 'NOCOMMWARNTIME': 2, 'FINALDELAY': 2, 'RUN_AS_USER': 2,
    'CERTPATH': 2, 'CERTVERIFY': 2, 'FORCESSL': 2,
    'NOTIFYMSG': 3, 'NOTIFYFLAG': 3, 'CERTIDENT': 3,
    'CERTHOST': 5, 'MONITOR': 5,
}
EXACT_CASE_EXCEPTIONS = {'DEBUG_MIN': 2}  # compared with strcasecmp

BLOCKING = frozenset({
    'config_not_observed', 'config_invalid', 'config_nul', 'config_too_large',
    'argv_not_observed', 'argv_invalid', 'argv_too_large', 'argv_exits',
    'environment_not_observed', 'config_path_mismatch', 'default_user_invalid',
})

# parseconf.c states.
_FINDWORDSTART, _FINDEOL, _QUOTECOLLECT, _QC_LITERAL, _COLLECT, _COLLECTLITERAL = range(6)
_ENDOFLINE, _PARSEERR = 'eol', 'err'


def _isspace(ch: int) -> bool:
    return ch in (0x20, 0x09, 0x0a, 0x0b, 0x0c, 0x0d)


class _Pconf:
    """Byte-for-byte model of pconf_file_next over a whole file."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.word = bytearray()
        self.args: list[bytes] = []
        self.linenum = 0

    def _addchar(self, ch: int) -> None:
        if ch < 0x20 or ch > 0x7f:
            return
        if len(self.word) >= WORDLEN_LIMIT:
            return
        self.word.append(ch)

    def _endofword(self) -> None:
        if len(self.args) < ARG_LIMIT:
            self.args.append(bytes(self.word))
        self.word.clear()

    def _findwordstart(self, ch: int):
        if ch == 10:
            return _ENDOFLINE
        if ch == 0x23:  # '#'
            return _FINDEOL
        if _isspace(ch):
            return _FINDWORDSTART
        if ch == 0x5c:  # '\\'
            return _COLLECTLITERAL
        if ch == 0x22:  # '"'
            return _QUOTECOLLECT
        self._addchar(ch)
        if ch == 0x3d:  # '='
            self._endofword()
            return _FINDWORDSTART
        return _COLLECT

    def _step(self, state, ch: int):
        if state == _FINDWORDSTART:
            return self._findwordstart(ch)
        if state == _FINDEOL:
            return _ENDOFLINE if ch == 10 else _FINDEOL
        if state == _QUOTECOLLECT:
            if ch == 0x23:
                self._endofword()
                return _PARSEERR
            if ch == 0x22:
                self._endofword()
                return _FINDWORDSTART
            if ch == 0x5c:
                return _QC_LITERAL
            self._addchar(ch)
            return _QUOTECOLLECT
        if state == _QC_LITERAL:
            if ch != 10:
                self._addchar(ch)
            return _QUOTECOLLECT
        if state == _COLLECT:
            if ch == 0x23:
                self._endofword()
                return _FINDEOL
            if ch == 10:
                self._endofword()
                return _ENDOFLINE
            if _isspace(ch):
                self._endofword()
                return _FINDWORDSTART
            if ch == 0x3d:
                self._endofword()
                self._findwordstart(ch)
                return _FINDWORDSTART
            if ch == 0x5c:
                return _COLLECTLITERAL
            self._addchar(ch)
            return _COLLECT
        # _COLLECTLITERAL
        if ch != 10:
            self._addchar(ch)
        return _COLLECT

    def next(self):
        """Return ``(linenum, args, parse_error)`` or ``None`` at end of file."""
        self.linenum += 1
        self.args = []
        state = _FINDWORDSTART
        while self.pos < len(self.data):
            ch = self.data[self.pos]
            self.pos += 1
            state = self._step(state, ch)
            if state == _PARSEERR:
                return self.linenum, self.args, True
            if state == _ENDOFLINE:
                return self.linenum, self.args, False
        if self.args:
            if self.word:
                self._endofword()
            return self.linenum, self.args, False
        return None


def tokenize(text: str) -> list[tuple[int, list[str], bool]]:
    """Return every logical line upsmon's parser reads, as ASCII words."""
    parser = _Pconf(text.encode('utf-8'))
    lines = []
    while (item := parser.next()) is not None:
        linenum, args, error = item
        lines.append((linenum, [a.decode('ascii') for a in args], error))
    return lines


def parse_argv(words: Sequence[str]) -> dict[str, Any]:
    """Model getopt("+DFBhic:P:f:pu:VK46") for the daemon's argv words."""
    split, user, config, exits = True, None, None, []
    i = 0
    while i < len(words):
        word = words[i]
        if word == '--':
            break
        if not word.startswith('-') or word == '-':
            break  # '+' in optstring: stop at the first operand
        j = 1
        while j < len(word):
            opt = word[j]
            if opt in OPTIONS_WITH_ARGUMENT:
                if j + 1 < len(word):
                    value = word[j + 1:]
                elif i + 1 < len(words):
                    i += 1
                    value = words[i]
                else:
                    exits.append('missing_argument')
                    break
                if opt in EXITING_WITH_ARGUMENT:
                    exits.append('command_mode')
                elif opt == 'u':
                    user = value
                elif opt == 'f':
                    config = value
                break
            if opt in EXITING_OPTIONS:
                exits.append('exits_option')
            elif opt == 'p':
                split = False
            elif opt not in OPTIONS_FLAG:
                exits.append('unknown_option')
            j += 1
        i += 1
    return {'split': split, 'user': user, 'config': config, 'exits': exits}


def _message_analysis(template: str) -> dict[str, Any]:
    """Classify a printf template given one ``char *`` argument."""
    conversions, i = [], 0
    while i < len(template):
        if template[i] == '%':
            nxt = template[i + 1:i + 2]
            if nxt == '%':
                i += 2
                continue
            conversions.append(nxt)
            i += 2
            continue
        i += 1
    modeled = conversions in ([], ['s'])
    return {
        'template_sha256': hashlib.sha256(template.encode('ascii')).hexdigest(),
        'template_bytes': len(template),
        'includes_ups_name': conversions == ['s'],
        'format_modeled': modeled,
        'shell_active': any(c in SHELL_ACTIVE_IN_DOUBLE_QUOTES for c in template),
        'may_truncate': (not modeled) or conversions == ['s'] or len(template) > MESSAGE_MAX,
    }


def _gap(gaps: list, code: str) -> None:
    if code not in gaps:
        gaps.append(code)


def assess(config_text: str | None, argv: Sequence[str] | None,
           environment: Mapping[str, str] | None, config_path: str | None,
           default_user: str = 'nut') -> dict[str, Any]:
    """Return which commands upsmon runs, as whom and on which events.

    ``argv`` is the daemon's argument words after the program name, as systemd
    or the init script passes them. ``environment`` is the daemon environment;
    only ``NUT_CONFPATH`` is read from it. ``config_path`` is the path the
    captured text came from. ``default_user`` is the build's ``RUN_AS_USER``
    (``nut`` for the Debian and Ubuntu packages).
    """
    gaps: list[str] = []
    notes: list[dict[str, Any]] = []

    opts = {'split': True, 'user': None, 'config': None, 'exits': []}
    if argv is None:
        _gap(gaps, 'argv_not_observed')
    elif (not isinstance(argv, (list, tuple)) or len(argv) > MAX_ARGV
          or not all(isinstance(w, str) and '\x00' not in w and len(w) <= MAX_ARGV_WORD for w in argv)):
        _gap(gaps, 'argv_too_large' if isinstance(argv, (list, tuple)) and len(argv) > MAX_ARGV else 'argv_invalid')
    else:
        opts = parse_argv(list(argv))
        if opts['exits']:
            _gap(gaps, 'argv_exits')

    expected_path = None
    if environment is None:
        _gap(gaps, 'environment_not_observed')
    elif not isinstance(environment, Mapping):
        _gap(gaps, 'environment_not_observed')
    else:
        confdir = environment.get('NUT_CONFPATH')
        if confdir is None:
            confdir = DEFAULT_CONFPATH
        if opts['config'] is not None:
            expected_path = opts['config']
        elif argv is not None and 'argv_exits' not in gaps:
            # common.c confpath() plus upsmon's "%s/upsmon.conf".
            expected_path = f'{confdir}/{CONFIG_NAME}'
    if expected_path is not None and config_path != expected_path:
        _gap(gaps, 'config_path_mismatch')

    if not isinstance(default_user, str) or not default_user or '\x00' in default_user:
        _gap(gaps, 'default_user_invalid')
        default_user = ''

    lines: list[tuple[int, list[str], bool]] = []
    if config_text is None:
        _gap(gaps, 'config_not_observed')
    elif not isinstance(config_text, str):
        _gap(gaps, 'config_invalid')
    elif len(config_text) > MAX_TEXT:
        _gap(gaps, 'config_too_large')
    else:
        if '\x00' in config_text:
            _gap(gaps, 'config_nul')
        try:
            lines = tokenize(config_text)
        except UnicodeEncodeError:
            _gap(gaps, 'config_invalid')
            lines = []

    shutdown = notify = run_as = None
    messages = {name: None for name, _ in NOTIFY_EVENTS}
    flags = {name: set(DEFAULT_FLAGS) for name, _ in NOTIFY_EVENTS}
    flag_lines: dict[str, int] = {}
    by_upper = {name.upper(): name for name, _ in NOTIFY_EVENTS}

    def note(linenum: int, status: str, directive: str | None = None) -> None:
        if len(notes) < MAX_LINE_NOTES:
            entry = {'line': linenum, 'status': status}
            if directive is not None:
                entry['directive'] = directive
            notes.append(entry)
        else:
            _gap(gaps, 'line_notes_truncated')

    for linenum, args, error in lines:
        if error:
            note(linenum, 'parse_error')
            continue
        if not args:
            continue
        name = args[0]
        known = KNOWN_DIRECTIVES.get(name)
        if known is None and name.upper() in EXACT_CASE_EXCEPTIONS:
            known = EXACT_CASE_EXCEPTIONS[name.upper()]
        if known is None or len(args) < known:
            # Text is never copied: an unknown first word may be a secret.
            note(linenum, 'invalid_directive',
                 name if known is not None else None)
            continue
        if name == 'SHUTDOWNCMD':
            shutdown = (linenum, args[1])
        elif name == 'NOTIFYCMD':
            notify = (linenum, args[1])
        elif name == 'RUN_AS_USER':
            run_as = (linenum, args[1])
        elif name == 'NOTIFYMSG':
            event = by_upper.get(args[1].upper())
            if event is None:
                note(linenum, 'unknown_notify_event', name)
            else:
                messages[event] = args[2]
        elif name == 'NOTIFYFLAG':
            event = by_upper.get(args[1].upper())
            if event is None:
                note(linenum, 'unknown_notify_event', name)
                continue
            new = set()
            for part in args[2].split('+'):
                if part in FLAG_NAMES:
                    new.add(part)
                else:
                    note(linenum, 'unknown_notify_flag', name)
            flags[event] = new
            flag_lines[event] = linenum

    if run_as is not None:
        user, user_source, user_line = run_as[1], 'config', run_as[0]
    elif opts['user'] is not None:
        user, user_source, user_line = opts['user'], 'argv', None
    else:
        user, user_source, user_line = default_user, 'default', None
    split = opts['split']
    notify_user = user if split else 'root'

    events = []
    for name, stock in NOTIFY_EVENTS:
        effective = flags[name]
        template = messages[name] if messages[name] is not None else stock
        runs = 'EXEC' in effective and 'IGNORE' not in effective and notify is not None
        entry = {
            'event': name,
            'flags': sorted(effective),
            'flags_line': flag_lines.get(name),
            'runs_notifycmd': runs,
            'message_source': 'config' if messages[name] is not None else 'stock',
            'message': _message_analysis(template),
            'status': 'runs' if runs else 'not_run',
        }
        if runs and not entry['message']['format_modeled']:
            entry['status'] = 'unresolved'
        events.append(entry)

    commands = []
    if shutdown is not None:
        commands.append({'kind': 'SHUTDOWNCMD', 'command': shutdown[1], 'line': shutdown[0],
                         'shell': SHELL, 'user': 'root',
                         'process': 'privileged_parent' if split else 'single_root_process',
                         'trigger': 'power_fail_shutdown'})
    run_events = [e['event'] for e in events if e['status'] in ('runs', 'unresolved')]
    if notify is not None and run_events:
        commands.append({'kind': 'NOTIFYCMD', 'command': notify[1], 'line': notify[0],
                         'shell': SHELL, 'argv_form': 'command "<message>"',
                         'user': notify_user,
                         'process': 'unprivileged_child' if split else 'single_root_process',
                         'trigger': 'notify_events', 'events': run_events,
                         'environment': ['UPSNAME', 'NOTIFYTYPE']})

    complete = not any(g in BLOCKING for g in gaps) and not any(e['status'] == 'unresolved' for e in events)
    result = {
        'contract_version': CONTRACT_VERSION,
        'source_versions': list(SOURCE_VERSIONS),
        'complete': complete,
        'gaps': gaps,
        'config_path': config_path,
        'expected_config_path': expected_path,
        'mode': 'split' if split else 'single_root',
        'run_as_user': {'name': user, 'source': user_source, 'line': user_line,
                        'applies_to': 'monitoring_and_notify' if split else 'none',
                        'account_resolution': 'not_assessed'},
        'shutdown_configured': shutdown is not None,
        'notify_configured': notify is not None,
        'commands': commands,
        'events': events,
        'line_notes': notes,
        'origin': 'not_assessed',
        'verdict': None,
    }
    result['fingerprint'] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return result
