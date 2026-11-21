"""Pure apcupsd event-script contract (roadmap F slice, #1243).

Takes ``/etc/apcupsd/apcupsd.conf`` text, the observed ``apcupsd.service``
``ExecStart`` and entry metadata for ``/etc/apcupsd``, and says which programs
apcupsd runs as root on UPS power events, with which arguments, and where
coverage is missing. It never runs anything and never reads a script's contents.

Semantics come from apcupsd 3.14.14 source and the Ubuntu 24.04 package
``3.14.14-3.1build2``, not from recollection:

* ``apcupsd.service`` runs ``/sbin/apcupsd`` as root (``Type=forking``), which
  reads ``/etc/apcupsd/apcupsd.conf`` (``--sysconfdir=/etc/apcupsd``). A missing
  config file, an unknown keyword or a bad value aborts startup.
* ``check_for_config`` reads the file with ``fgets`` into a 256-byte buffer, so
  an overlong line is split every 255 bytes and each piece is parsed as its own
  line. ``ParseConfig`` skips leading whitespace, ignores empty lines and lines
  starting with ``#``, upper-cases the keyword up to the first whitespace and
  looks it up exactly. ``match_str`` stores the rest after the separating
  whitespace, cut at the first ``#`` anywhere and with trailing whitespace
  removed. A later ``SCRIPTDIR`` replaces an earlier one; the default is
  ``/etc/apcupsd``.
* ``execute_command`` (``src/lib/apcexec.c``) formats ``SCRIPTDIR`` +
  ``/apccontrol`` into a 256-byte buffer and ``execv``s it with
  ``EVENT UPSNAME CONNECTED POWERED``. The daemon has already ``chdir("/")``, so a
  relative ``SCRIPTDIR`` resolves from ``/``. The 19 events are ``ups_event[]``
  in ``src/action.c``.
* The packaged ``/etc/apcupsd/apccontrol`` runs under ``/usr/bin/sh``, hardcodes
  ``SCRIPTDIR=/etc/apcupsd`` whatever the config says, sources
  ``/etc/apcupsd/config`` with ``.`` when ``[ -f ]`` holds, then runs
  ``/etc/apcupsd/EVENT`` with ``UPSNAME CONNECTED POWERED`` when
  ``[ -f p -a -x p ]`` holds (symlinks followed; for root any execute bit
  passes; ``access`` refuses a noexec mount). Exit status 99 skips the built-in
  action, which for ``doshutdown``/``doreboot`` is ``/sbin/shutdown``.
* ``/lib/systemd/system-shutdown/apcupsd_shutdown`` runs
  ``/etc/apcupsd/apccontrol killpower`` at final shutdown when the ``powerfail``
  flag file exists, so ``/etc/apcupsd/killpower`` can run there too.

It performs no I/O and never authorizes a response action. Unobserved family,
installation state, config, service command or metadata, malformed or
over-limit input, unobserved mount flags of an executable event script, a
non-default ``SCRIPTDIR``, an unverified ``apccontrol`` and a sourced
``/etc/apcupsd/config`` are blocking gaps.
"""
from __future__ import annotations

from typing import Any

from app.ifupdown_hooks import _stat_ok

CONTRACT_VERSION = 1
REFERENCE = {
    'apcupsd': 'apcupsd 3.14.14 src/lib/apcconfig.c, src/lib/apcexec.c, src/action.c, src/apcupsd.c',
    'package': 'Ubuntu 24.04 apcupsd 3.14.14-3.1build2 /etc/apcupsd/apccontrol, apcupsd.service, '
               '/lib/systemd/system-shutdown/apcupsd_shutdown',
}
RUNS_AS = 'root'
CONFIG_PATH = '/etc/apcupsd/apcupsd.conf'
DEFAULT_SCRIPTDIR = '/etc/apcupsd'
PACKAGED_APCCONTROL = '/etc/apcupsd/apccontrol'
SOURCED_CONFIG = '/etc/apcupsd/config'
DEFAULT_EXEC_START = ('/sbin/apcupsd',)
SHUTDOWN_HOOK = '/lib/systemd/system-shutdown/apcupsd_shutdown'
EVENT_ARGUMENTS = ('UPSNAME', 'CONNECTED', 'POWERED')
# ups_event[] in src/action.c, in table order.
DAEMON_EVENTS = ('powerout', 'onbattery', 'failing', 'timeout', 'loadlimit', 'runlimit', 'doshutdown',
                 'mainsback', 'annoyme', 'emergency', 'changeme', 'remotedown', 'commfailure', 'commok',
                 'startselftest', 'endselftest', 'offbattery', 'battdetach', 'battattach')
SHUTDOWN_EVENTS = ('killpower',)
EVENTS = DAEMON_EVENTS + SHUTDOWN_EVENTS
APPLICABLE_FAMILIES = frozenset({'debian'})
DIRECTORY_STATES = ('listed', 'absent', 'unreadable', 'not_directory')
CONFIG_STATES = ('read', 'absent', 'unreadable')
FGETS_CHUNK = 255   # fgets(line, MAXSTRING=256, ...) returns at most 255 bytes.
COMMAND_BUFFER = 255  # asnprintf(apccontrol, MAXSTRING=256, "%s%s", ...)
MAX_CONFIG_BYTES = 1 << 20
MAX_ENTRIES = 1024
MAX_GAPS = 64
_C_SPACE = b' \t\n\v\f\r'
BLOCKING = frozenset({
    'input_malformed', 'family_not_observed', 'family_unsupported', 'implementation_not_observed',
    'config_not_observed', 'config_unreadable', 'config_too_large', 'exec_start_not_observed',
    'nondefault_exec_start', 'nondefault_scriptdir', 'relative_scriptdir', 'apccontrol_path_truncated',
    'apccontrol_unverified', 'apccontrol_config_sourced', 'config_file_not_observed',
    'directory_not_observed', 'directory_unreadable', 'listing_incomplete', 'too_many_entries',
    'metadata_missing', 'symlink_target_unobserved', 'mount_flags_unobserved', 'gaps_truncated',
})
UNOBSERVED = (
    'Script contents are not read, so what an event script does is not assessed.',
    'Whether apcupsd actually starts (an unknown keyword or bad value aborts it) is not checked; scripts are '
    'reported as they would run if it does.',
    'Which events fire depends on the UPS, the cable and other settings, and is not predicted.',
    'Whether the powerfail flag exists at shutdown, and so whether killpower runs, is not observed.',
)
NOT_A_VERDICT = 'Configuration and file metadata only. This is not a safety verdict and origin is not assessed.'
REASONS = {
    'runs': 'The packaged apccontrol runs this file as root with UPSNAME CONNECTED POWERED; exit status 99 skips '
            'the built-in action.',
    'absent': 'No such entry, so only the built-in action runs.',
    'directory': '[ -f ] fails for a directory, so it does not run.',
    'not_executable': 'The file has no execute bit, so [ -x ] fails and it does not run.',
    'noexec_mount': 'The file is on a noexec mount, so the kernel refuses to execute it.',
    'stat_failed': 'The entry cannot be followed (for example a dangling symlink), so [ -f ] fails.',
    'not_plain_file': 'Not a regular file, so [ -f ] fails and it does not run.',
    'unresolved': 'Required metadata, such as a symlink target or the noexec mount flag, was not supplied, so '
                  'the outcome is not determined.',
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


def _fgets_lines(data: bytes) -> list[bytes]:
    """Split like repeated fgets(buf, 256, f): at most 255 bytes, stopping after a newline."""
    out = []
    pos = 0
    while pos < len(data):
        end = data.find(b'\n', pos, pos + FGETS_CHUNK)
        end = pos + FGETS_CHUNK if end < 0 else end + 1
        out.append(data[pos:end])
        pos = end
    return out


def scriptdir_from_config(text: str) -> tuple[str, int | None]:
    """Return the effective SCRIPTDIR and the 1-based fgets line that set it (None for the default)."""
    data = text.encode('utf-8', 'surrogateescape')
    value, line_no = DEFAULT_SCRIPTDIR.encode(), None
    for number, chunk in enumerate(_fgets_lines(data), 1):
        line = chunk.split(b'\0', 1)[0]  # C string functions stop at NUL.
        key = line.lstrip(_C_SPACE)
        if not key or key[:1] == b'#':
            continue
        end = 0
        while end < len(key) and key[end] not in _C_SPACE:
            end += 1
        # toupper() in the C locale changes only ASCII a-z.
        if bytes(c - 32 if 97 <= c <= 122 else c for c in key[:end]) != b'SCRIPTDIR':
            continue
        raw = key[end:].lstrip(_C_SPACE).split(b'#', 1)[0].rstrip(_C_SPACE)
        value, line_no = raw, number
    return value.decode('utf-8', 'surrogateescape'), line_no


def _event_outcome(entry: Any, path: str, gaps: list[dict[str, Any]]) -> str:
    if entry.get('type') == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', path)
            return 'unresolved'
        if entry['target'] is None:
            return 'stat_failed'
        stat = _stat_ok(entry['target'])
    else:
        stat = _stat_ok(entry)
    if stat is None:
        _gap(gaps, 'metadata_missing', path, 'Type, mode or mount flag metadata is missing or malformed.')
        return 'unresolved'
    if stat['type'] == 'directory':
        return 'directory'
    if stat['type'] == 'other':
        return 'not_plain_file'
    if not stat['mode'] & 0o111:
        return 'not_executable'
    if stat.get('noexec'):
        return 'noexec_mount'
    if stat.get('noexec') is None:
        # access(X_OK) behind [ -x ] fails on a noexec mount, so without the flag the outcome is unknown.
        _gap(gaps, 'mount_flags_unobserved', path, 'The noexec flag was not observed, so whether it runs is '
             'not determined.')
        return 'unresolved'
    return 'runs'


def _is_regular(entry: Any, path: str, gaps: list[dict[str, Any]]) -> bool | None:
    """[ -f path ]: True, False, or None when metadata is missing."""
    if entry.get('type') == 'symlink':
        if 'target' not in entry:
            _gap(gaps, 'symlink_target_unobserved', path)
            return None
        if entry['target'] is None:
            return False
        entry = entry['target']
    stat = _stat_ok(entry)
    if stat is None:
        _gap(gaps, 'metadata_missing', path, 'Type metadata is missing or malformed.')
        return None
    return stat['type'] == 'file'


def assess(config: Any = None, directory: Any = None, *, exec_start: Any = None, family: Any = None,
           apcupsd_installed: Any = None, apccontrol_verified: Any = None) -> dict[str, Any]:
    """Resolve which programs apcupsd runs as root on UPS events.

    ``config`` is ``{'state': 'read', 'text': str}`` for ``/etc/apcupsd/apcupsd.conf`` or a ``state`` of
    ``absent`` or ``unreadable``. ``directory`` is the ``/etc/apcupsd`` listing:
    ``{'state': 'listed', 'truncated': bool, 'entries': [{'name', 'type': 'file'|'directory'|'other'|'symlink',
    'mode', 'noexec', 'target'}]}`` or a ``state`` of ``absent``, ``unreadable`` or ``not_directory``.
    ``exec_start`` is the effective ``apcupsd.service`` ``ExecStart`` argv. ``apccontrol_verified`` is True only
    when ``/etc/apcupsd/apccontrol`` is authenticated as the unchanged packaged file.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'runs_as': RUNS_AS,
        'applicability': 'unknown', 'config_path': CONFIG_PATH, 'config_state': 'not_observed',
        'scriptdir': None, 'scriptdir_line': None, 'daemon_program': None,
        'event_arguments': EVENT_ARGUMENTS, 'daemon_events': DAEMON_EVENTS,
        'shutdown_program': {'hook': SHUTDOWN_HOOK, 'command': (PACKAGED_APCCONTROL, 'killpower'),
                             'condition': 'the powerfail flag file exists at final shutdown'},
        'sourced_config': {'path': SOURCED_CONFIG, 'state': 'not_observed'},
        'event_scripts': [], 'gaps': gaps, 'origin': 'not_assessed', 'not_a_verdict': NOT_A_VERDICT,
        'unobserved': UNOBSERVED,
    }
    if family is None:
        _gap(gaps, 'family_not_observed')
    elif family not in APPLICABLE_FAMILIES:
        _gap(gaps, 'family_unsupported')
    if apcupsd_installed is False:
        result['applicability'] = 'not_applicable'
    elif apcupsd_installed is not True:
        _gap(gaps, 'implementation_not_observed', None, 'Whether apcupsd is installed is unknown.')
    elif family in APPLICABLE_FAMILIES:
        result['applicability'] = 'applicable'

    if exec_start is None:
        _gap(gaps, 'exec_start_not_observed', None, 'The effective apcupsd.service ExecStart was not observed.')
    elif not isinstance(exec_start, (list, tuple)) or not all(isinstance(a, str) for a in exec_start):
        _gap(gaps, 'input_malformed', None, 'Malformed ExecStart.')
    elif tuple(exec_start) != DEFAULT_EXEC_START:
        _gap(gaps, 'nondefault_exec_start', None,
             'apcupsd is started with arguments or a binary other than /sbin/apcupsd, which may change the '
             'config file or behavior.')

    _config(config, result, gaps)
    if apccontrol_verified is not True:
        _gap(gaps, 'apccontrol_unverified', PACKAGED_APCCONTROL,
             'Not authenticated as the unchanged packaged file, so which scripts it runs is not known.')
    _directory(directory, result, gaps)
    result['complete'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result


def _config(config: Any, result: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    if config is None:
        _gap(gaps, 'config_not_observed', CONFIG_PATH)
        return
    if not isinstance(config, dict) or config.get('state') not in CONFIG_STATES:
        _gap(gaps, 'input_malformed', CONFIG_PATH, 'Malformed config observation.')
        return
    result['config_state'] = config['state']
    if config['state'] == 'unreadable':
        _gap(gaps, 'config_unreadable', CONFIG_PATH)
        return
    if config['state'] == 'absent':
        # check_for_config() aborts when the file cannot be opened: the daemon runs no events.
        result['daemon_program'] = {'path': None, 'starts': False,
                                    'reason': 'apcupsd aborts at startup without its config file.'}
        return
    text = config.get('text')
    if not isinstance(text, str):
        _gap(gaps, 'input_malformed', CONFIG_PATH, 'Config text is missing.')
        return
    if len(text.encode('utf-8', 'surrogateescape')) > MAX_CONFIG_BYTES:
        _gap(gaps, 'config_too_large', CONFIG_PATH)
        return
    scriptdir, line_no = scriptdir_from_config(text)
    result['scriptdir'], result['scriptdir_line'] = scriptdir, line_no
    raw = (scriptdir + '/apccontrol').encode('utf-8', 'surrogateescape')
    program = raw[:COMMAND_BUFFER].decode('utf-8', 'surrogateescape')
    resolved = program if program.startswith('/') else '/' + program
    result['daemon_program'] = {'path': resolved, 'starts': True, 'argv': (program, 'EVENT') + EVENT_ARGUMENTS}
    if len(raw) > COMMAND_BUFFER:
        _gap(gaps, 'apccontrol_path_truncated', resolved,
             'SCRIPTDIR is so long that apcupsd truncates the program path to 255 bytes.')
    if not scriptdir.startswith('/'):
        _gap(gaps, 'relative_scriptdir', resolved, 'A relative SCRIPTDIR resolves from / after apcupsd daemonizes.')
    if resolved != PACKAGED_APCCONTROL:
        _gap(gaps, 'nondefault_scriptdir', resolved,
             'apcupsd runs this program as root on every UPS event instead of the packaged apccontrol.')


def _directory(listing: Any, result: dict[str, Any], gaps: list[dict[str, Any]]) -> None:
    scripts = result['event_scripts']
    if listing is None:
        _gap(gaps, 'directory_not_observed', DEFAULT_SCRIPTDIR)
        return
    if not isinstance(listing, dict) or listing.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', DEFAULT_SCRIPTDIR, 'Malformed directory metadata.')
        return
    if listing['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', DEFAULT_SCRIPTDIR)
        return
    entries: dict[str, Any] = {}
    complete_listing = listing['state'] != 'listed' or not listing.get('truncated')
    if listing['state'] == 'listed':
        if listing.get('truncated'):
            _gap(gaps, 'listing_incomplete', DEFAULT_SCRIPTDIR)
        raw = listing.get('entries')
        if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
            _gap(gaps, 'too_many_entries' if isinstance(raw, list) else 'input_malformed', DEFAULT_SCRIPTDIR)
            return
        for entry in raw:
            name = entry.get('name') if isinstance(entry, dict) else None
            if not isinstance(name, str) or not name or '/' in name or name in entries or name in ('.', '..') \
                    or '\0' in name:
                _gap(gaps, 'input_malformed', DEFAULT_SCRIPTDIR, 'An entry has a missing, invalid or duplicate name.')
                continue
            entries[name] = entry

    sourced = result['sourced_config']
    entry = entries.get('config')
    if entry is None:
        if complete_listing:
            sourced['state'] = 'absent'
        else:
            _gap(gaps, 'config_file_not_observed', SOURCED_CONFIG)
    else:
        regular = _is_regular(entry, SOURCED_CONFIG, gaps)
        sourced['state'] = {True: 'sourced', False: 'not_regular', None: 'unresolved'}[regular]
        if regular:
            _gap(gaps, 'apccontrol_config_sourced', SOURCED_CONFIG,
                 'apccontrol sources this file as root shell code, which can run commands or change SCRIPTDIR.')

    for event in EVENTS:
        path = f'{DEFAULT_SCRIPTDIR}/{event}'
        entry = entries.get(event)
        if entry is None:
            if not complete_listing:
                outcome = 'unresolved'
            else:
                outcome = 'absent'
        else:
            outcome = _event_outcome(entry, path, gaps)
        scripts.append({'event': event, 'path': path, 'trigger': 'shutdown' if event in SHUTDOWN_EVENTS else 'daemon',
                        'outcome': outcome, 'reason': REASONS[outcome]})
