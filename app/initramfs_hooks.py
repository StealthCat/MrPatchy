"""Pure initramfs-tools build-hook contract (roadmap F slice, #1074).

Takes captured, read-only metadata for the two ``mkinitramfs`` hook directories
and says which hook executables run as root on every initramfs build, with what
arguments and environment, which are gated by an ``OPTION=`` variable, why the
others are skipped, and which coverage gaps remain. A build happens on every
``update-initramfs`` run, including the one ``/etc/kernel/postinst.d/initramfs-tools``
starts after each kernel package install and the ones initramfs-tools package
triggers start, so a hook is a root persistence point that fires on routine
patching. It never reads a hook's contents.

Semantics come from ``initramfs-tools-core 0.142ubuntu25.8`` (Ubuntu 24.04):
``mkinitramfs`` and ``hook-functions`` (``set_initlist``, ``get_prereq_pairs``,
``call_scripts``, ``run_scripts``, ``run_scripts_optional``). They were read
from the shipped files, not recalled:

* ``mkinitramfs`` calls ``run_scripts_optional /usr/share/initramfs-tools/hooks``
  (with ``STAGE_KERNEL_MODULE_COPYING=1`` exported), then
  ``run_scripts_optional /etc/initramfs-tools/hooks``. The two directories are
  independent passes: a same-named hook in ``/etc`` does not replace the
  packaged one, and both run. A missing directory is skipped.
* ``set_initlist`` iterates the shell glob ``"$dir"/*``, so names starting with a
  dot are never seen. A name matching ``*[![:alnum:]._-]*`` is ignored. A
  directory (``test -d`` follows symlinks) is ignored. An entry ``test -x``
  rejects (no execute bit, a ``noexec`` mount, or a dangling symlink) is
  ignored. An entry ``sh -n`` rejects is ignored.
* ``get_prereq_pairs`` then executes every listed hook as root with the single
  argument ``prereqs`` and feeds the output to ``tsort``. This happens before,
  and regardless of, any ``OPTION=`` gate. The run order is that ``tsort``
  output and is not established from metadata.
* ``call_scripts`` runs each ``tsort`` name that is a regular file (``test -f``)
  in the directory, as root and with no arguments. Because the names come from
  hook output, a regular file that ``set_initlist`` ignored still runs when
  another hook names it as a prerequisite. With the optional flag set (always,
  for both passes) a hook whose ``OPTION=`` value names a variable runs only
  when that variable is non-empty and not ``n``. ``sed '/^OPTION=/!d;$d;...'``
  drops an ``OPTION=`` line that is the file's last line.
* A non-zero hook exit aborts the build, so later hooks do not run.

It performs no I/O, never runs a command and never authorizes a response
action. Missing or malformed metadata, an unobserved directory or family, a
truncated listing and over-limit input are blocking gaps and are never reported
as covered. Boot-time ``scripts/`` that run inside the initramfs, dracut and
the ``mkinitramfs -d`` alternative configuration directory are out of scope and
reported as such.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'initramfs_tools': 'initramfs-tools-core 0.142ubuntu25.8 (mkinitramfs, hook-functions)'}
PACKAGE_DIR = '/usr/share/initramfs-tools/hooks'
LOCAL_DIR = '/etc/initramfs-tools/hooks'
HOOK_DIRS = (PACKAGE_DIR, LOCAL_DIR)
RUNS_AS = 'root'
PREREQS_ARG = 'prereqs'
APPLICABLE_FAMILIES = frozenset({'debian'})
KNOWN_FAMILIES = frozenset({'debian', 'rpm'})
EXPORTED_ENV = ('MODULESDIR', 'version', 'CONFDIR', 'DESTDIR', 'DPKG_ARCH', 'verbose', 'MODULES', 'BUSYBOX',
                'RESUME', 'FSTYPE')
PASS_ENV = {PACKAGE_DIR: ('STAGE_KERNEL_MODULE_COPYING=1',), LOCAL_DIR: ()}
MAX_ENTRIES = 1024
MAX_NAME_BYTES = 255
MAX_OPTION_LINES = 16
MAX_OPTION_BYTES = 256
MAX_CONFIG = 256
MAX_GAPS = 64
ENTRY_TYPES = ('file', 'directory', 'symlink', 'other')
TARGET_TYPES = ('file', 'directory', 'other')
DIRECTORY_STATES = ('listed', 'absent', 'not_directory', 'unreadable')
BLOCKING = frozenset({
    'input_malformed', 'too_many_entries', 'duplicate_name', 'metadata_missing', 'directory_not_observed',
    'directory_unreadable', 'listing_incomplete', 'family_not_observed', 'family_unsupported',
    'generator_not_observed', 'gaps_truncated', 'glob_literal_entry',
})
OUT_OF_SCOPE = (
    ('Boot-time scripts under /usr/share/initramfs-tools/scripts and /etc/initramfs-tools/scripts, which are copied '
     'into the initramfs and run inside it at boot, are not resolved here.'),
    'dracut and other initramfs generators are not covered.',
    'A build started with mkinitramfs -d <confdir> reads hooks from that directory instead of /etc/initramfs-tools.',
)
UNOBSERVED = (
    'Hook contents, interpreters, prerequisite output and anything a hook runs are not read or executed.',
    ('Prerequisite names are hook output: a name with a path (such as ../x) would make call_scripts execute a file '
     'outside the hook directory. That cannot be resolved from metadata.'),
    'Whether sh -n accepts a hook is taken from the caller.',
    'Variable values for OPTION= gates come from the caller (initramfs.conf, conf.d and the build environment).',
    'A locally modified mkinitramfs or hook-functions is not detected.',
)
NOT_A_VERDICT = 'File metadata only. This is not a safety verdict and origin is not assessed.'

REASONS = {
    'runs': 'mkinitramfs runs this hook as root with no arguments on every initramfs build.',
    'gated_off': 'The OPTION= variable is empty or "n", so the build call is skipped. The hook still ran with '
                 '"prereqs" while the order was computed.',
    'gate_unknown': 'Runs only when its OPTION= variable is non-empty and not "n"; that value was not supplied. '
                    'The hook always runs with "prereqs".',
    'gate_invalid': 'The OPTION= value is not a usable shell variable name, so the gate does not evaluate '
                    'cleanly; whether the build call happens is not determined.',
    'hidden': 'The "$dir"/* glob does not match names starting with a dot.',
    'name_rejected': 'set_initlist ignores names with characters other than letters, digits, ".", "_" and "-".',
    'directory': 'Directories are ignored.',
    'not_executable': 'test -x fails (no execute bit), so set_initlist ignores it.',
    'noexec_mount': 'The file is on a noexec mount, so test -x fails and set_initlist ignores it.',
    'dangling_symlink': 'The symlink target does not exist, so test -x fails and set_initlist ignores it.',
    'bad_syntax': 'sh -n rejects it, so set_initlist ignores it.',
    'unresolved': 'Required metadata was not supplied, so the outcome is not determined.',
}
_NAME_REJECT = re.compile(r'[^A-Za-z0-9._-]')
_SHELL_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
_TRAILING_SPACE = re.compile(r'[ \t\n\r\f\v]*$')


def _gap(gaps: list[dict[str, Any]], code: str, path: str | None = None, detail: str = '') -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'blocking': True,
                        'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code, 'blocking': code in BLOCKING}
    if path is not None:
        gap['path'] = path
    if detail:
        gap['detail'] = detail
    gaps.append(gap)


def name_listed(name: str) -> bool | None:
    """Return whether ``set_initlist`` keeps this name. ``None`` when the name has
    non-ASCII characters, whose ``[:alnum:]`` membership depends on the build locale."""
    if name.startswith('.'):
        return False
    if not name.isascii():
        stripped = ''.join(c for c in name if c.isascii())
        return False if _NAME_REJECT.search(stripped) else None
    return not _NAME_REJECT.search(name)


def option_value(option_lines: list[str], last_line_is_option: bool) -> str | None:
    """Mirror ``sed '/^OPTION=/!d;$d;s/^OPTION=//;s/[[:space:]]*$//'``.

    ``option_lines`` are the file's lines starting with ``OPTION=`` in order. The
    ``$d`` command deletes the file's last line, so when that line is an
    ``OPTION=`` line it is dropped. Returns ``None`` when no line remains."""
    lines = list(option_lines[:-1] if last_line_is_option and option_lines else option_lines)
    values = [_TRAILING_SPACE.sub('', line[len('OPTION='):], count=1) for line in lines]
    return '\n'.join(values) if values else None


def _mode(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0o7777


def _valid_name(name: Any) -> bool:
    if not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\x00' in name:
        return False
    try:
        return len(name.encode('utf-8', 'surrogateescape')) <= MAX_NAME_BYTES
    except UnicodeEncodeError:
        return False


def _optional_bool(value: Any) -> bool:
    return value is None or isinstance(value, bool)


def _target(meta: Any) -> dict[str, Any] | None:
    if not isinstance(meta, dict) or meta.get('type') not in TARGET_TYPES or not _optional_bool(meta.get('noexec')):
        return None
    if meta['type'] == 'file' and not _mode(meta.get('mode')):
        return None
    return {'type': meta['type'], 'mode': meta.get('mode'), 'noexec': meta.get('noexec')}


def _option(entry: dict[str, Any]) -> tuple[bool, str | None]:
    lines = entry.get('option_lines', [])
    last = entry.get('last_line_is_option', False)
    if (not isinstance(lines, list) or len(lines) > MAX_OPTION_LINES or not isinstance(last, bool)
            or any(not isinstance(x, str) or not x.startswith('OPTION=') or '\n' in x
                   or len(x.encode('utf-8', 'surrogateescape')) > MAX_OPTION_BYTES for x in lines)):
        return False, None
    return True, option_value(lines, last)


def _effective(entry: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Return (kind, followed metadata). kind is file, directory, other, dangling or bad."""
    kind = entry['type']
    if kind == 'symlink':
        if 'target' not in entry:
            return 'bad', None
        if entry['target'] is None:
            return 'dangling', None
        target = _target(entry['target'])
        return ('bad', None) if target is None else (target['type'], target)
    meta = _target({'type': kind, 'mode': entry.get('mode'), 'noexec': entry.get('noexec')})
    return ('bad', None) if meta is None else (kind, meta)


def _gate(option: str | None, config: dict[str, str] | None) -> tuple[str, dict[str, Any] | None]:
    if option is None or option == '':
        return 'runs', None
    info: dict[str, Any] = {'variable': option}
    if '\n' in option or not _SHELL_NAME.fullmatch(option):
        return 'gate_invalid', info
    if config is None or option not in config:
        info['value'] = None
        return 'gate_unknown', info
    value = config[option]
    info['value'] = value
    return ('runs' if value not in ('', 'n') else 'gated_off'), info


def _assess(path: str, entry: dict[str, Any], dir_noexec: bool | None, config: dict[str, str] | None,
            gaps: list[dict[str, Any]]) -> dict[str, Any]:
    name = entry['name']
    result: dict[str, Any] = {'name': name, 'path': path, 'option': None, 'invocations': [],
                              'runs_if_named_as_prereq': False}
    listed = name_listed(name)
    if name.startswith('.'):
        result['reason'] = 'hidden'
    elif listed is None:
        result['reason'] = 'unresolved'
        _gap(gaps, 'locale_dependent_name', path,
             'Non-ASCII names are kept or ignored depending on the build locale\'s [:alnum:] class.')
    elif not listed:
        result['reason'] = 'name_rejected'
    if 'reason' in result:
        kind, _meta = _effective(entry)
        result['runs_if_named_as_prereq'] = kind == 'file'
        return result
    kind, meta = _effective(entry)
    if kind == 'bad':
        result['reason'] = 'unresolved'
        _gap(gaps, 'metadata_missing', path, 'Type, mode or symlink target metadata is missing or malformed.')
        return result
    if kind == 'directory':
        result['reason'] = 'directory'
        return result
    if kind == 'dangling':
        result['reason'] = 'dangling_symlink'
        return result
    if kind == 'other':
        result['reason'] = 'unresolved'
        _gap(gaps, 'special_file', path, 'Not a regular file or directory; how test -x and sh -n treat it is not '
                                         'resolved here.')
        return result
    noexec = meta.get('noexec') if meta.get('noexec') is not None else dir_noexec
    if not meta['mode'] & 0o111:
        result['reason'] = 'not_executable'
        result['runs_if_named_as_prereq'] = True
        return result
    if noexec is None:
        result['reason'] = 'unresolved'
        _gap(gaps, 'mount_not_observed', path, 'Whether the file is on a noexec mount was not supplied.')
        return result
    if noexec:
        result['reason'] = 'noexec_mount'
        result['runs_if_named_as_prereq'] = True
        return result
    syntax = entry.get('shell_syntax_ok')
    if syntax is False:
        result['reason'] = 'bad_syntax'
        result['runs_if_named_as_prereq'] = True
        return result
    if syntax is not True:
        result['reason'] = 'unresolved'
        _gap(gaps, 'syntax_not_observed', path, 'Whether sh -n accepts this hook was not supplied.')
        return result
    ok, option = _option(entry)
    if not ok:
        result['reason'] = 'unresolved'
        _gap(gaps, 'input_malformed', path, 'option_lines must be a short list of OPTION= lines.')
        return result
    reason, info = _gate(option, config)
    result['reason'] = reason
    result['option'] = info
    result['invocations'].append([path, PREREQS_ARG])
    if reason != 'gated_off':
        result['invocations'].append([path])
    return result


def _directory(path: str, observed: Any, config: dict[str, str] | None,
               gaps: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {'directory': path, 'state': None, 'environment': list(PASS_ENV[path]), 'entries': []}
    if observed is None:
        _gap(gaps, 'directory_not_observed', path)
        return out
    if not isinstance(observed, dict) or observed.get('state') not in DIRECTORY_STATES:
        _gap(gaps, 'input_malformed', path, 'Directory state must be one of ' + ', '.join(DIRECTORY_STATES) + '.')
        return out
    out['state'] = observed['state']
    if observed['state'] in ('absent', 'not_directory'):
        return out
    if observed['state'] == 'unreadable':
        _gap(gaps, 'directory_unreadable', path)
        return out
    entries = observed.get('entries')
    dir_noexec = observed.get('noexec')
    if not isinstance(entries, list) or not _optional_bool(dir_noexec):
        _gap(gaps, 'input_malformed', path, 'A listed directory needs an entries list.')
        return out
    if observed.get('complete') is not True:
        _gap(gaps, 'listing_incomplete', path)
    if len(entries) > MAX_ENTRIES:
        _gap(gaps, 'too_many_entries', path, f'Only the first {MAX_ENTRIES} entries are assessed.')
        entries = entries[:MAX_ENTRIES]
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not _valid_name(entry.get('name')) or entry.get('type') not in ENTRY_TYPES:
            _gap(gaps, 'input_malformed', path, 'An entry needs a plain name and a type.')
            continue
        if entry['name'] in seen:
            _gap(gaps, 'duplicate_name', f"{path}/{entry['name']}")
            continue
        seen.add(entry['name'])
        out['entries'].append(_assess(f"{path}/{entry['name']}", entry, dir_noexec, config, gaps))
    out['entries'].sort(key=lambda e: e['name'].encode('utf-8', 'surrogateescape'))
    if '*' in seen:
        # set_initlist's empty-directory check ([ "$si_x" = "$initdir/*" ] && return) also matches a real entry
        # named "*", so listing stops there. Where "*" falls in the glob depends on the build locale.
        _gap(gaps, 'glob_literal_entry', f'{path}/*',
             'An entry literally named "*" makes set_initlist stop listing this directory when the glob reaches '
             'it, so later hooks never run. Glob order depends on the build locale; in the C locale no hook in '
             'this pass runs.')
        for entry in out['entries']:
            if entry['invocations']:
                entry['reason'] = 'unresolved'
                entry['invocations'] = []
    if any(e['runs_if_named_as_prereq'] for e in out['entries']):
        _gap(gaps, 'excluded_file_may_run_as_prereq', path,
             'call_scripts executes any regular file another hook names as a prerequisite, including files '
             'set_initlist ignored. One that is executable runs as root; one without an execute bit or on a '
             'noexec mount fails to execute and aborts the build. Prerequisite output is not observed.')
    return out


def _config(value: Any, gaps: list[dict[str, Any]]) -> dict[str, str] | None:
    if value is None:
        return None
    if (not isinstance(value, dict) or len(value) > MAX_CONFIG
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items())):
        _gap(gaps, 'input_malformed', None, 'config must map variable names to string values.')
        return None
    return dict(value)


def evaluate(observation: Any) -> dict[str, Any]:
    """Resolve which initramfs-tools build hooks run as root, from captured metadata.

    ``observation`` keys: ``family`` (``debian``/``rpm``), ``initramfs_tools``
    (whether ``mkinitramfs`` from initramfs-tools is the installed generator),
    ``directories`` (hook directory path -> ``{state, complete, noexec, entries}``)
    and optional ``config`` (variable -> value as the build would see it). Each
    entry has ``name``, ``type`` (file/directory/symlink/other), ``mode``,
    optional ``noexec``, ``target`` for a symlink (followed metadata, or ``None``
    when dangling), ``shell_syntax_ok`` and ``option_lines`` /
    ``last_line_is_option``.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'runs_as': RUNS_AS,
        'trigger': 'Every initramfs build: update-initramfs, kernel package installs and initramfs-tools triggers.',
        'exported_environment': list(EXPORTED_ENV), 'applicable': None, 'passes': [], 'runs': [],
        'conditional': [], 'prereq_invocations': [],
        'order': {'established': False,
                  'rule': 'Packaged hooks run before local hooks. Within each pass the order is tsort of every '
                          'listed hook\'s "prereqs" output, which is not observed.'},
        'failure_aborts_build': True, 'reasons': dict(REASONS), 'out_of_scope': list(OUT_OF_SCOPE),
        'unobserved': list(UNOBSERVED), 'not_a_verdict': NOT_A_VERDICT, 'action_authorized': False,
    }
    if not isinstance(observation, dict):
        _gap(gaps, 'input_malformed', None, 'The observation must be a mapping.')
        return _finish(result, gaps)
    family = observation.get('family')
    if family is None:
        _gap(gaps, 'family_not_observed')
        return _finish(result, gaps)
    if family not in KNOWN_FAMILIES:
        _gap(gaps, 'family_unsupported', None, f'Unknown platform family {family!r}.')
        return _finish(result, gaps)
    if family not in APPLICABLE_FAMILIES:
        result['applicable'] = False
        _gap(gaps, 'generator_not_covered', None, 'RPM families build the initramfs with dracut, whose modules '
                                                   'this contract does not cover.')
        return _finish(result, gaps)
    tools = observation.get('initramfs_tools')
    if tools is None:
        _gap(gaps, 'generator_not_observed', None, 'Whether initramfs-tools is the installed generator was not '
                                                    'supplied.')
        return _finish(result, gaps)
    if not isinstance(tools, bool):
        _gap(gaps, 'input_malformed', None, 'initramfs_tools must be true, false or absent.')
        return _finish(result, gaps)
    result['applicable'] = tools
    if not tools:
        _gap(gaps, 'generator_not_covered', None, 'initramfs-tools is not installed; another generator such as '
                                                   'dracut is not covered.')
        return _finish(result, gaps)
    directories = observation.get('directories')
    if not isinstance(directories, dict):
        _gap(gaps, 'input_malformed', None, 'directories must map each hook directory to its observation.')
        return _finish(result, gaps)
    config = _config(observation.get('config'), gaps)
    for path in HOOK_DIRS:
        listed = _directory(path, directories.get(path), config, gaps)
        result['passes'].append(listed)
        for entry in listed['entries']:
            if entry['invocations']:
                result['prereq_invocations'].append(entry['invocations'][0])
            if entry['reason'] == 'runs':
                result['runs'].append(entry['path'])
            elif entry['reason'] in ('gate_unknown', 'gate_invalid'):
                result['conditional'].append(entry['path'])
    return _finish(result, gaps)


def _finish(result: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    result['gaps'] = gaps
    result['complete'] = not any(g['blocking'] for g in gaps) and not any(
        e['reason'] == 'unresolved' for p in result['passes'] for e in p['entries'])
    result['covered'] = result['complete'] and result['applicable'] is True and all(
        p['state'] is not None for p in result['passes'])
    return result
