"""Pure kdump crash-capture hook contract (roadmap F slice, #1538).

Takes the captured text of ``/etc/kdump.conf`` and read-only metadata for the
entries of ``/etc/kdump/pre.d``, ``/etc/kdump/post.d`` and
``/etc/kdump/emergency.d``. It says which programs the kdump capture
environment runs as root after a kernel crash, in which order, with which
arguments, and what each failure does. It also says when ``kdumpctl`` refuses
the configuration, so no capture kernel is loaded and nothing runs. It never
reads a hook's contents.

Semantics were read in kdump-utils at upstream ``7bf4714`` (``kdumpctl``,
``mkdumprd``, ``kdump-lib-initramfs.sh``, ``dracut/99kdumpbase/kdump.sh`` and
``dracut/99kdumpbase/module-setup.sh``):

* Configuration lines matching ``^\\s*#`` or ``^\\s*$`` are dropped. Each other
  line is split by ``read -r opt val``. A ``#`` anywhere in the value cuts it,
  together with trailing whitespace. A value that starts and ends with ``"``
  loses one quote at each end.
* ``kdumpctl`` refuses to start on an unknown or deprecated option, an empty
  value, a repeated option or more than one dump target. A refused
  configuration loads no capture kernel, so no hook runs.
* ``kdump_pre``, ``kdump_post`` and ``kdump_emergency`` are executed as one
  quoted word (``"$KDUMP_PRE"``). A value with whitespace names a file whose
  path contains that whitespace. It does not pass arguments. ``mkdumprd``
  installs the word-split value, so the intended program is present but the
  call still fails.
* The capture script runs, in order: ``kdump_pre``, then every ``pre.d``
  entry, the dump, every ``post.d`` entry with the dump status as its only
  argument, then ``kdump_post`` with that status. This is the reverse of what
  the kdump.conf manual says for ``kdump_pre`` and ``pre.d``. When the capture
  service fails, the error handler (``kdump.sh --error-handler``, started via
  ``kdump-emergency.service``) runs every ``emergency.d`` entry, then
  ``kdump_emergency``, before the failure action, whatever that action is.
* A non-zero ``kdump_pre`` exit skips the dump and runs the final action
  (reboot by default). Every other hook failure is only logged.
* Hook directory entries come from the glob ``<dir>/*``, so names starting
  with ``.`` are never included. Only entries that pass ``[[ -x ]]`` (an
  execute bit, with symlinks followed) are installed into the capture
  initramfs. The glob order is assumed to be byte order, because the capture
  shell's collation is not observed.
* ``core_collector`` runs its value word-split; its first word is the program.
  The default is ``makedumpfile``. ``extra_bins`` are installed but never run
  by kdump itself.

The contract performs no I/O, never runs a command and never authorizes a
response action. A missing or malformed configuration or listing, and
over-limit input, are explicit blocking gaps. None of them is ever reported as
covered.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
REFERENCE = 'kdump-utils 7bf4714'
RUNS_AS = 'root'
CONFIG_PATH = '/etc/kdump.conf'
HOOK_DIRS = {'pre': '/etc/kdump/pre.d', 'post': '/etc/kdump/post.d', 'emergency': '/etc/kdump/emergency.d'}
DEFAULT_CORE_COLLECTOR = 'makedumpfile'
MAX_CONFIG_BYTES = 65536
MAX_LINES = 2048
MAX_ENTRIES = 512
MAX_NAME_BYTES = 255
MAX_GAPS = 64
DUMP_TARGETS = frozenset({'raw', 'ext2', 'ext3', 'ext4', 'minix', 'btrfs', 'xfs', 'nfs', 'ssh', 'virtiofs'})
ACCEPTED = frozenset({
    'path', 'core_collector', 'kdump_post', 'kdump_pre', 'kdump_emergency', 'extra_bins', 'extra_modules',
    'failure_action', 'final_action', 'force_rebuild', 'force_no_rebuild', 'fence_kdump_args',
    'fence_kdump_nodes', 'auto_reset_crashkernel', 'sshkey', 'default', 'dracut_args',
}) | DUMP_TARGETS
DEPRECATED = frozenset({'net', 'options', 'link_delay', 'disk_timeout', 'debug_mem_level', 'blacklist'})
ENTRY_TYPES = ('file', 'directory', 'other', 'dangling')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
BLOCKING = frozenset({
    'input_malformed', 'config_not_observed', 'config_too_large', 'directory_not_observed', 'directory_unreadable',
    'too_many_entries', 'duplicate_name', 'metadata_missing', 'gaps_truncated',
})
UNOBSERVED = (
    'Hook contents, interpreters and anything a hook runs are not read.',
    'The capture initramfs is built when kdumpctl starts; files changed later are used only after a rebuild, so '
    'the loaded image may still hold older hooks.',
    'Other kdumpctl checks (crashkernel reservation, dump target reachability, ssh keys, failure and final action '
    'values) are not assessed, so an accepted configuration may still fail to load.',
    'The capture shell\'s glob collation is not observed; byte order is assumed.',
    'Who can write the configuration, the hook directories or the hook files is not assessed.',
)
NOT_A_VERDICT = 'Configuration and file metadata only. This is not a safety verdict and origin is not assessed.'
REFUSALS = {
    'unknown_option': 'kdumpctl rejects an unknown option and refuses to start.',
    'deprecated_option': 'kdumpctl rejects a deprecated option and refuses to start.',
    'empty_value': 'kdumpctl rejects an option with an empty value and refuses to start.',
    'duplicate_option': 'kdumpctl rejects a repeated option and refuses to start.',
    'multiple_targets': 'kdumpctl rejects more than one dump target and refuses to start.',
}
OBSERVATIONS = {
    'value_has_whitespace': 'The value is executed as one word, so this names a path containing whitespace and '
                            'arguments are not passed; the call fails.',
    'pre_failure_skips_dump': 'A non-zero kdump_pre exit (including a failed call) skips the vmcore dump and runs '
                              'the final action.',
    'relative_path': 'The value is not an absolute path, so it is looked up through PATH in the capture '
                     'environment.',
    'runs_on_capture_failure': 'Emergency hooks run only when the capture service fails, before the failure '
                               'action.',
}
_SPACE = ' \t\n\r\v\f'


def _gap(gaps: list[dict[str, Any]], code: str, detail: str = '', path: str | None = None) -> None:
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


def _nbytes(text: str) -> int:
    return len(text.encode('utf-8', 'surrogateescape'))


def parse_config(text: str) -> list[tuple[int, str, str]]:
    """Return ``(line_number, option, value)`` as ``kdump_read_conf`` then ``read -r`` produce them."""
    result = []
    for number, line in enumerate(text.split('\n'), 1):
        stripped = line.lstrip(_SPACE)
        if not stripped.strip(_SPACE) or stripped.startswith('#'):
            continue
        # ``read -r`` with the default IFS splits on spaces and tabs and trims them.
        body = line.strip(' \t')
        cut = min((i for i in (body.find(' '), body.find('\t')) if i >= 0), default=len(body))
        opt, val = body[:cut], body[cut:].lstrip(' \t')
        if '#' in val:
            val = val.split('#', 1)[0].rstrip(_SPACE)
        if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        # The parsed line is printed and read again, which trims the value once more.
        val = val.strip(' \t')
        result.append((number, opt, val))
    return result


def _hook_value(value: str) -> dict[str, Any]:
    observations = []
    if any(char in value for char in ' \t'):
        observations.append('value_has_whitespace')
    if not value.startswith('/'):
        observations.append('relative_path')
    return {'program': value, 'observations': observations}


def _directory(stage: str, listing: Any, gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    path = HOOK_DIRS[stage]
    if not isinstance(listing, dict) or listing.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'directory_not_observed', 'The hook directory listing was not supplied.', path)
        return []
    state = listing['state']
    if state in ('absent', 'not_directory'):
        return []
    if state == 'unreadable':
        _gap(gaps, 'directory_unreadable', 'The hook directory exists but could not be listed.', path)
        return []
    entries = listing.get('entries')
    if not isinstance(entries, list):
        _gap(gaps, 'input_malformed', 'The listing entries are not a list.', path)
        return []
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', f'More than {MAX_ENTRIES} entries.', path)
        return []
    seen: set[str] = set()
    out = []
    for entry in entries:
        name = entry.get('name') if isinstance(entry, dict) else None
        if (not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\x00' in name
                or _nbytes(name) > MAX_NAME_BYTES):
            _gap(gaps, 'input_malformed', 'An entry has no valid name.', path)
            continue
        if name in seen:
            _gap(gaps, 'duplicate_name', f'{name!r} is listed twice.', path)
            continue
        seen.add(name)
        full = f'{path}/{name}'
        if name.startswith('.'):
            out.append({'name': name, 'path': full, 'runs': False, 'reason': 'hidden'})
            continue
        kind, mode = entry.get('type'), entry.get('mode')
        if kind not in ENTRY_TYPES:
            _gap(gaps, 'metadata_missing', 'The entry type was not supplied.', full)
            out.append({'name': name, 'path': full, 'runs': None, 'reason': 'unresolved'})
            continue
        if kind == 'dangling':
            out.append({'name': name, 'path': full, 'runs': False, 'reason': 'unresolvable'})
            continue
        if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o7777:
            _gap(gaps, 'metadata_missing', 'The entry mode was not supplied.', full)
            out.append({'name': name, 'path': full, 'runs': None, 'reason': 'unresolved'})
            continue
        if not mode & 0o111:
            out.append({'name': name, 'path': full, 'runs': False, 'reason': 'not_executable'})
        elif kind != 'file':
            # ``[[ -x ]]`` passes, but executing a directory or device fails in the capture shell.
            out.append({'name': name, 'path': full, 'runs': False, 'reason': 'not_regular'})
        else:
            out.append({'name': name, 'path': full, 'runs': True, 'reason': 'installed'})
    out.sort(key=lambda item: item['name'].encode('utf-8', 'surrogateescape'))
    return out


def assess(config_text: Any, directories: Any) -> dict[str, Any]:
    """Return the crash-time run plan for one host's kdump configuration and hook directories."""
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'runs_as': RUNS_AS,
        'config_path': CONFIG_PATH, 'not_a_verdict': NOT_A_VERDICT, 'unobserved': list(UNOBSERVED),
        'refusals': [], 'starts': None, 'sequence': [], 'directory_entries': {}, 'installed_not_run': [],
        'gaps': gaps, 'covered': False,
    }
    if not isinstance(config_text, str):
        _gap(gaps, 'config_not_observed', 'The kdump.conf text was not supplied.', CONFIG_PATH)
        return result
    if '\x00' in config_text or _nbytes(config_text) > MAX_CONFIG_BYTES or config_text.count('\n') >= MAX_LINES:
        _gap(gaps, 'config_too_large', 'The configuration is over the size limit or contains NUL bytes.',
             CONFIG_PATH)
        return result
    if not isinstance(directories, dict):
        directories = {}
    options: dict[str, str] = {}
    targets = 0
    for number, opt, val in parse_config(config_text):
        if opt in DEPRECATED:
            code = 'deprecated_option'
        elif opt not in ACCEPTED:
            code = 'unknown_option'
        elif not val:
            code = 'empty_value'
        else:
            code = None
            key = 'failure_action' if opt == 'default' else opt
            if opt in DUMP_TARGETS or (opt == 'dracut_args' and '--mount' in val):
                targets += 1
                if targets > 1:
                    code = 'multiple_targets'
            if code is None and key in options and opt not in DUMP_TARGETS:
                code = 'duplicate_option'
            if code is None:
                options[key] = val
        if code:
            result['refusals'].append({'line': number, 'option': opt, 'code': code, 'reason': REFUSALS[code]})
    listings = {stage: _directory(stage, directories.get(stage), gaps) for stage in HOOK_DIRS}
    result['directory_entries'] = listings
    if result['refusals']:
        result['starts'] = False
        result['covered'] = not any(gap['code'] in BLOCKING for gap in gaps)
        return result
    result['starts'] = True
    sequence = result['sequence']

    def add(stage: str, source: str, program: str, args: list[str], on_failure: str,
            observations: list[str] | None = None) -> None:
        sequence.append({'stage': stage, 'source': source, 'program': program, 'args': args,
                         'on_failure': on_failure, 'observations': observations or []})

    if 'kdump_pre' in options:
        hook = _hook_value(options['kdump_pre'])
        add('pre', 'kdump_pre', hook['program'], [], 'skip_dump_and_run_final_action',
            hook['observations'] + ['pre_failure_skips_dump'])
    for item in listings['pre']:
        if item['runs'] is not False:
            add('pre', 'pre.d', item['path'], [], 'warn', [] if item['runs'] else ['unresolved'])
    collector = options.get('core_collector', DEFAULT_CORE_COLLECTOR).split()
    add('dump', 'core_collector', collector[0], collector[1:], 'dump_failed')
    for item in listings['post']:
        if item['runs'] is not False:
            add('post', 'post.d', item['path'], ['<dump status>'], 'warn', [] if item['runs'] else ['unresolved'])
    if 'kdump_post' in options:
        hook = _hook_value(options['kdump_post'])
        add('post', 'kdump_post', hook['program'], ['<dump status>'], 'warn', hook['observations'])
    for item in listings['emergency']:
        if item['runs'] is not False:
            add('emergency', 'emergency.d', item['path'], [], 'warn',
                ['runs_on_capture_failure'] + ([] if item['runs'] else ['unresolved']))
    if 'kdump_emergency' in options:
        hook = _hook_value(options['kdump_emergency'])
        add('emergency', 'kdump_emergency', hook['program'], [], 'warn',
            hook['observations'] + ['runs_on_capture_failure'])
    if 'extra_bins' in options:
        result['installed_not_run'] = options['extra_bins'].split()
    result['covered'] = not any(gap['code'] in BLOCKING for gap in gaps)
    return result
