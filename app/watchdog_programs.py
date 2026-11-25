"""Pure watchdog daemon program contract (roadmap F slice, #1369).

Takes ``/etc/watchdog.conf`` text, the ``watchdog_options`` value from
``/etc/default/watchdog`` and entry metadata for the effective test directory,
and says which programs the ``watchdog`` daemon runs as root on every check
interval, with which argv, and where coverage is missing. It never runs
anything and never reads a program's contents.

Semantics come from watchdog 5.16 source and the Ubuntu/Debian package
``5.16-2`` (``debian/rules`` passes ``--with-configfile=/etc/watchdog.conf``;
``TESTBIN_PATH`` keeps its ``/etc/watchdog.d`` default; the only Debian patch
touches verbose logging in ``run-as-child.c``):

* ``watchdog.service`` runs ``/bin/sh -c '[ $run_watchdog != 1 ] || exec
  /usr/sbin/watchdog $watchdog_options'`` as root. ``-c``/``--config-file``
  replaces the config path; any option this contract does not model is a gap.
* ``read_config`` (``src/configfile.c``) reads each line with ``getline``. C
  string functions stop at a NUL byte. ``str_start``/``trim_white``
  (``src/read-conf.c``) treat only space, tab, CR, LF and backspace as white
  space. A line whose first non-white character is ``#`` or NUL is skipped; a
  line with no ``=`` is ignored; otherwise the key is everything before the
  first ``=`` and the value everything after it, both trimmed. There are no
  inline comments, quotes or escapes, and keys match exactly (``strcmp``).
* ``test-binary`` appends to the test list as a V0 program with argv
  ``[path]``; a blank value is ignored. ``repair-binary`` and
  ``test-directory`` take the last assignment, and a blank value resets them to
  none.
* After the file, ``add_test_binaries`` lists ``test-directory`` with
  ``readdir`` (unsorted) and appends each entry whose ``stat`` (following
  symlinks) shows a regular file with owner read and execute bits, whose name
  does not start with ``.`` and whose ``dir/name`` fits ``PATH_MAX`` (4096
  bytes including NUL). These are V1 programs: argv ``[path, "test"]``, and on
  failure ``[path, "repair", "<errcode>", path]``.
* ``interval`` is read with ``atoi`` when the value starts with a digit, ``+`` or
  ``-``; a final value ``<= 0`` is fatal, so the daemon exits and runs nothing.
  A config file that cannot be opened is also fatal.
* ``repair`` (``src/watchdog.c``) runs the repair binary for every failing V0
  test and every built-in check (load, memory, temperature, file, pidfile,
  interface, ping) as ``[repair, "<errcode>", "<object>"]``. The daemon has
  already ``chdir("/")`` unless ``-F`` is given, so relative paths are a gap.

It performs no I/O and never authorizes a response action.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'watchdog': 'watchdog 5.16 src/configfile.c, src/read-conf.c, src/test_binary.c, src/watchdog.c, '
                'src/run-as-child.c',
    'package': 'Debian/Ubuntu watchdog 5.16-2 debian/rules, debian/watchdog.service',
}
RUNS_AS = 'root'
CONFIG_PATH = '/etc/watchdog.conf'
DEFAULT_TEST_DIRECTORY = '/etc/watchdog.d'
PATH_MAX = 4096
MAX_CONFIG_BYTES = 1 << 20
MAX_ENTRIES = 1024
MAX_GAPS = 64
_WHITE = b' \t\r\n\b'
_NUMBER_START = b'0123456789+-'
# getopt_long flags that take no argument and do not change which programs run.
_FLAG_LETTERS = frozenset('Ffsqvb')
_LONG_FLAGS = frozenset({'--foreground', '--force', '--sync', '--no-action', '--verbose', '--softboot'})
CONFIG_STATES = ('read', 'absent', 'unreadable')
DIRECTORY_STATES = ('listed', 'absent', 'unreadable', 'not_directory')
ENTRY_TYPES = ('file', 'directory', 'other', 'stat_failed')
BLOCKING = frozenset({
    'input_malformed', 'options_not_observed', 'options_unverified', 'config_not_observed',
    'config_unreadable', 'config_too_large', 'directory_not_observed', 'directory_unreadable',
    'listing_incomplete', 'too_many_entries', 'relative_program_path', 'relative_test_directory',
    'gaps_truncated',
})
UNOBSERVED = (
    'Program contents are not read, so what a test or repair program does is not assessed.',
    'Whether the daemon is enabled is not checked; programs are reported as they would run if it starts.',
    'The readdir order of test-directory programs is filesystem dependent and is not predicted.',
    'Whether a repair program actually runs depends on which checks fail at run time.',
)
NOT_A_VERDICT = 'Configuration and file metadata only. This is not a safety verdict and origin is not assessed.'
SKIP_REASONS = {
    'hidden': 'Names starting with "." are skipped.',
    'path_too_long': 'dir/name does not fit PATH_MAX, so snprintf truncation makes it skip the entry.',
    'not_regular': 'stat() does not show a regular file, so it is not added.',
    'stat_failed': 'stat() fails (for example a dangling symlink), so it is not added.',
    'not_owner_executable': 'The owner execute bit is not set, so it is not added.',
    'not_owner_readable': 'The owner read bit is not set, so it is not added.',
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


def _decode(raw: bytes) -> str:
    return raw.decode('utf-8', 'surrogateescape')


def _atoi(value: bytes) -> int:
    """glibc atoi: strtol (saturating at the long range) truncated to a 32-bit int."""
    pos, sign = 0, 1
    if value[:1] in (b'+', b'-'):
        sign = -1 if value[:1] == b'-' else 1
        pos = 1
    digits = b''
    while pos < len(value) and value[pos:pos + 1].isdigit():
        digits += value[pos:pos + 1]
        pos += 1
    number = sign * int(digits) if digits else 0
    number = max(-(1 << 63), min((1 << 63) - 1, number))
    number &= 0xFFFFFFFF
    return number - (1 << 32) if number & 0x80000000 else number


def parse_config(text: str) -> dict[str, Any]:
    """Return the test-binary list, repair-binary, test-directory and interval as read_config leaves them."""
    data = text.encode('utf-8', 'surrogateescape')
    tests: list[dict[str, Any]] = []
    repair: dict[str, Any] | None = None
    test_dir: dict[str, Any] | None = {'path': DEFAULT_TEST_DIRECTORY, 'line': None}
    interval = 1
    lines = data.split(b'\n')
    if lines and lines[-1] == b'':
        lines.pop()
    for number, raw in enumerate(lines, 1):
        line = raw.split(b'\0', 1)[0]
        arg = line.lstrip(_WHITE)
        if not arg or arg[:1] == b'#':
            continue
        if b'=' not in arg:
            continue
        key, value = arg.split(b'=', 1)
        key = key.rstrip(_WHITE)
        value = value.lstrip(_WHITE).rstrip(_WHITE)
        if key == b'test-binary':
            if value:
                tests.append({'path': _decode(value), 'line': number})
        elif key == b'repair-binary':
            repair = {'path': _decode(value), 'line': number} if value else None
        elif key == b'test-directory':
            test_dir = {'path': _decode(value), 'line': number} if value else None
        elif key == b'interval' and value[:1] and value[:1] in _NUMBER_START:
            interval = _atoi(value)
    return {'test_binaries': tests, 'repair_binary': repair, 'test_directory': test_dir, 'interval': interval}


def _options_ok(options: str) -> bool:
    for token in options.split():
        if token in _LONG_FLAGS:
            continue
        if token.startswith('-') and not token.startswith('--') and len(token) > 1 \
                and all(ch in _FLAG_LETTERS for ch in token[1:]):
            continue
        return False
    return True


def _directory_programs(path: str, listing: Any, gaps: list[dict[str, Any]]) -> tuple[list, list, str]:
    if listing is None:
        _gap(gaps, 'directory_not_observed', path)
        return [], [], 'not_observed'
    if not isinstance(listing, dict) or listing.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', path, 'Malformed test-directory metadata.')
        return [], [], 'not_observed'
    state = listing['state']
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', path)
    if state != 'listed':
        return [], [], state
    entries = listing.get('entries')
    if not isinstance(entries, list):
        _gap(gaps, 'input_malformed', path, 'Malformed test-directory entries.')
        return [], [], state
    if listing.get('complete') is not True:
        _gap(gaps, 'listing_incomplete', path)
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', path)
        entries = entries[:MAX_ENTRIES]
    programs, skipped = [], []
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        kind = entry.get('type') if isinstance(entry, dict) else None
        mode = entry.get('mode') if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or '/' in name or name in ('.', '..') or kind not in ENTRY_TYPES \
                or (kind == 'file' and not (isinstance(mode, int) and not isinstance(mode, bool)
                                            and 0 <= mode <= 0o7777)):
            _gap(gaps, 'input_malformed', path, 'Malformed test-directory entry.')
            continue
        full = f'{path}/{name}'
        reason = None
        if len(full.encode('utf-8', 'surrogateescape')) >= PATH_MAX:
            reason = 'path_too_long'
        elif kind == 'stat_failed':
            reason = 'stat_failed'
        elif kind != 'file':
            reason = 'not_regular'
        elif name.startswith('.'):
            reason = 'hidden'
        elif not mode & 0o100:
            reason = 'not_owner_executable'
        elif not mode & 0o400:
            reason = 'not_owner_readable'
        if reason:
            skipped.append({'name': name, 'reason': reason, 'detail': SKIP_REASONS[reason]})
            continue
        programs.append({'path': full, 'source': 'test-directory', 'version': 1, 'line': None,
                         'argv': [full, 'test'], 'repair_argv': [full, 'repair', '<errcode>', full]})
    return programs, skipped, state


def evaluate(config: Any, watchdog_options: Any, directories: Any = None) -> dict[str, Any]:
    """Report which programs watchdog runs as root.

    ``config`` is ``{'state': 'read'|'absent'|'unreadable', 'text': str}`` for ``/etc/watchdog.conf``.
    ``watchdog_options`` is the effective ``watchdog_options`` string, or None when not observed.
    ``directories`` maps a directory path to ``{'state', 'complete', 'entries': [{'name', 'type', 'mode'}]}``,
    where ``type`` is the result of ``stat`` following symlinks.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'runs_as': RUNS_AS,
        'config_path': CONFIG_PATH, 'starts': None, 'test_directory': None, 'directory_state': None,
        'test_programs': [], 'skipped_entries': [], 'repair_binary': None, 'directory_order': 'undetermined',
        'complete': False, 'gaps': gaps, 'unobserved': list(UNOBSERVED), 'not_a_verdict': NOT_A_VERDICT,
    }
    if watchdog_options is None:
        _gap(gaps, 'options_not_observed', detail='watchdog_options was not observed; -c could change the config.')
    elif not isinstance(watchdog_options, str):
        _gap(gaps, 'input_malformed', detail='watchdog_options must be a string.')
    elif not _options_ok(watchdog_options):
        _gap(gaps, 'options_unverified', detail='watchdog_options contains an option this contract does not model.')
    if not isinstance(config, dict) or config.get('state') not in CONFIG_STATES:
        _gap(gaps, 'config_not_observed', CONFIG_PATH)
        return _finish(result)
    if config['state'] == 'unreadable':
        _gap(gaps, 'config_unreadable', CONFIG_PATH)
        return _finish(result)
    if config['state'] == 'absent':
        result['starts'] = False  # fopen fails, fatal_error exits.
        return _finish(result)
    text = config.get('text')
    if not isinstance(text, str):
        _gap(gaps, 'input_malformed', CONFIG_PATH, 'Config text must be a string.')
        return _finish(result)
    if len(text.encode('utf-8', 'surrogateescape')) > MAX_CONFIG_BYTES:
        _gap(gaps, 'config_too_large', CONFIG_PATH)
        return _finish(result)
    parsed = parse_config(text)
    programs = [{'path': t['path'], 'source': 'test-binary', 'version': 0, 'line': t['line'],
                 'argv': [t['path']], 'repair_argv': None} for t in parsed['test_binaries']]
    test_dir = parsed['test_directory']
    if test_dir is not None:
        result['test_directory'] = test_dir
        path = test_dir['path']
        if not path.startswith('/'):
            _gap(gaps, 'relative_test_directory', path, 'Resolved against the working directory at startup.')
        else:
            listing = directories.get(path) if isinstance(directories, dict) else None
            found, skipped, state = _directory_programs(path, listing, gaps)
            programs.extend(found)
            result['skipped_entries'] = skipped
            result['directory_state'] = state
    if parsed['interval'] <= 0:
        result['starts'] = False  # fatal_error after add_test_binaries.
        return _finish(result)
    result['starts'] = True
    repair = parsed['repair_binary']
    if repair is not None:
        result['repair_binary'] = {'path': repair['path'], 'line': repair['line'],
                                   'argv': [repair['path'], '<errcode>', '<object>']}
        for item in programs:
            if item['version'] == 0:
                item['repair_argv'] = [repair['path'], '<errcode>', item['path']]
    for item in programs + ([result['repair_binary']] if result['repair_binary'] else []):
        if not item['path'].startswith('/'):
            _gap(gaps, 'relative_program_path', item['path'],
                 'Resolved against / after daemonizing, or the start directory with -F.')
    result['test_programs'] = programs
    return _finish(result)


def _finish(result: dict[str, Any]) -> dict[str, Any]:
    result['complete'] = not any(g['code'] in BLOCKING for g in result['gaps'])
    if result['starts'] is False:
        result['test_programs'], result['repair_binary'] = [], None
    return result
