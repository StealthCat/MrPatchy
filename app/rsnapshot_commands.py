"""Pure rsnapshot command contract (roadmap F slice, #1530).

Takes captured, read-only observations of ``/etc/rsnapshot.conf`` and the files
it names with ``include_conf``, and says which programs ``rsnapshot`` runs:
``cmd_preexec`` and ``cmd_postexec`` hooks, ``backup_script`` and ``backup_exec``
commands, backtick ``include_conf`` commands, and the program paths set by
``cmd_rsync``, ``cmd_ssh``, ``cmd_cp``, ``cmd_rm``, ``cmd_logger``, ``cmd_du``,
``cmd_rsnapshot_diff`` and ``linux_lvm_cmd_*``. Every command runs as the user
that invokes ``rsnapshot``. The Debian/Ubuntu package's ``/etc/cron.d/rsnapshot``
runs it as root.

Semantics follow ``rsnapshot`` 1.4.5 (Ubuntu 24.04 package ``1.4.5-2``) with
Perl 5.38. The rules are:

* ``parse_config_file()`` reads the whole file, then walks it line by line. It
  stops early at a line that is false in Perl, which is only a last line of
  exactly ``0`` with no newline. ``chomp`` removes one trailing ``\\n``.
* A line starting with ``#`` is a comment. A line with no non-space character
  is blank. Both are skipped.
* Each following line matching ``^[\\t ]+\\S`` is a continuation. It is trimmed
  and joined to the line with one tab. This happens even when the continuation
  starts with ``#``.
* The line is split at runs of tabs into at most four fields: directive and up
  to three values. A line with no tab is an error. Spaces never separate
  fields.
* An error (``config_err``) marks the configuration as rejected and parsing
  continues. After parsing, a rejected configuration makes ``rsnapshot`` exit
  before any backup, so no hook or backup command runs. Commands that run
  *during* parsing (backtick ``include_conf``) still run.
* ``include_conf <path>`` parses a readable regular file in place.
  ``include_conf `<command>``` runs ``<command>`` through Perl's pipe open
  during parsing, at every invocation, including ``configtest``, and parses its
  output as configuration. The command's first word must be an absolute path to
  an executable file. There is no cycle check: a cyclic include recurses until
  ``open`` fails, which aborts ``rsnapshot``.
* ``cmd_preexec`` and ``cmd_postexec`` keep only the first value field: any
  further tab-separated text is silently dropped. The last valid assignment
  wins. They run through Perl ``system()`` from ``$HOME``. Pre-exec runs before
  the lowest-interval backup (or before ``rsnapshot sync`` when ``sync_first``
  is ``1``). A non-zero exit of either aborts ``rsnapshot``.
* ``backup_script <command> <dest>`` runs ``<command>`` through ``system()`` from
  ``<snapshot_root>/tmp/`` on each lowest-interval backup. A non-zero exit rolls
  that destination back. ``snapshot_root`` must be set earlier.
* ``backup_exec <command> [optional|required]`` runs ``<command>`` through
  ``system()`` from ``$HOME`` in configuration order with the backups. Its path
  is not checked. A non-zero exit aborts ``rsnapshot`` only when ``required``.
* Program paths drop trailing whitespace, must be absolute and are run with a
  fixed argument list, never through a shell. ``linux_lvm_cmd_*`` values may
  carry arguments, split at spaces. Paths from the last valid assignment win.
* Perl ``system()`` and pipe ``open`` with one string run ``/bin/sh -c`` when the
  string (after leading whitespace) starts with ``. `` or ``exec ``, has a
  leading ``NAME=`` word, or contains any of ``$&*(){}[]'";\\|?<>~`` or a
  newline that is not the last character. Otherwise Perl splits the string at
  whitespace and calls ``execvp`` itself.

The contract never under-reports execution. Superseded assignments are listed
with ``effective`` false. Program existence and executable bits, which
``rsnapshot`` checks at parse time, are not verified, so a configuration this
contract accepts could still be rejected on the host. It performs no I/O,
never runs a command and never authorizes a response action. File states that
are not observed or not modelled, NUL bytes and over-limit input become
explicit gaps, and a result with any gap is not ``complete``.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('rsnapshot 1.4.5 (Ubuntu 24.04 rsnapshot 1.4.5-2)', 'perl 5.38.2')
MAX_TEXT = 1 << 20
MAX_GAPS = 256
MAX_INCLUDE_DEPTH = 16
DEFAULT_CONFIG = '/etc/rsnapshot.conf'
FILE_STATES = ('absent', 'regular', 'unreadable', 'not_regular', 'unknown')
RUN_AS = 'invoking_user'

PROGRAM_KEYS = {
    # key: (default when absent, used for)
    'cmd_rsync': (None, 'every_backup_point_copy'),
    'cmd_ssh': (None, 'remote_ssh_backup_points_via_rsync_rsh'),
    'cmd_cp': ('perl_native_copy', 'hard_link_rotation'),
    'cmd_rm': ('perl_native_rm_rf', 'snapshot_deletion'),
    'cmd_logger': ('no_syslog', 'syslog_messages'),
    'cmd_du': ('du_from_PATH', 'rsnapshot_du_command'),
    'cmd_rsnapshot_diff': ('rsnapshot-diff_from_PATH', 'rsnapshot_diff_command'),
}
LVM_KEYS = ('linux_lvm_cmd_lvcreate', 'linux_lvm_cmd_lvremove',
            'linux_lvm_cmd_mount', 'linux_lvm_cmd_umount')
_OTHER_KEYS = frozenset({
    'config_version', 'snapshot_root', 'no_create_root', 'interval', 'retain', 'backup',
    'link_dest', 'sync_first', 'verbose', 'loglevel', 'logfile', 'lockfile',
    'stop_on_stale_lockfile', 'rsync_short_args', 'rsync_long_args', 'ssh_args', 'du_args',
    'one_fs', 'include', 'exclude', 'include_file', 'exclude_file', 'use_lazy_deletes',
    'rsync_numtries', 'linux_lvm_snapshotsize', 'linux_lvm_snapshotname',
    'linux_lvm_vgpath', 'linux_lvm_mountpath',
})
NOT_MODELLED = (
    'which_user_and_schedule_invoke_rsnapshot',
    'alternate_config_files_given_with_-c',
    'program_existence_and_executable_bits',
    'non_command_directive_value_validation',
    'validate_config_file_checks',
    'per_backup_point_option_parsing',
    'contents_of_the_commands_run',
)

_PERL_SPACE = ' \t\n\r\f\v'
_PERL_SHELL_META = set('$&*(){}[]\'";\\|?<>~`\n')
_CONTINUATION = re.compile(r'^[\t ]+\S')
_NO_SPACE = re.compile(r'\S')
_WORD = re.compile(r'[A-Za-z0-9_]*')
_BACKTICK = re.compile(r'^`(.*)`$')
_SSH_PATH = re.compile(r'^(.*?@)?.*?:[~.]?/.*$')


def perl_uses_shell(command: str) -> bool:
    """Whether Perl's one-string ``system``/pipe ``open`` runs ``/bin/sh -c``."""
    s = command.lstrip(_PERL_SPACE)
    if len(s) > 1 and s[0] == '.' and s[1] in _PERL_SPACE:
        return True
    if s.startswith('exec') and len(s) > 4 and s[4] in _PERL_SPACE:
        return True
    word = _WORD.match(s)
    if word and s[word.end():word.end() + 1] == '=':
        return True
    for i, ch in enumerate(s):
        if ch in _PERL_SHELL_META:
            return not (ch == '\n' and i == len(s) - 1)
    return False


def perl_argv(command: str) -> list[str]:
    """The argv Perl ``execvp``s when it does not use the shell."""
    return [part for part in re.split('[' + re.escape(_PERL_SPACE) + ']+', command) if part]


def _script_word(command: str) -> str:
    # Perl split(/\s+/, ...): a leading separator yields a leading empty field.
    return re.split(r'\s+', command)[0]


def _traversal(path: str) -> bool:
    return '/..' in path or '../' in path


def _abs_path(path: str) -> bool:
    return path.startswith('/') and not _traversal(path)


def _lines(text: str) -> list[str]:
    parts = text.split('\n')
    lines = [p + '\n' for p in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def assess_config(files: list[dict[str, Any]] | None, *, config_path: str = DEFAULT_CONFIG
                  ) -> dict[str, Any]:
    """Return the commands and programs one rsnapshot configuration makes it run.

    ``files`` holds records ``{'path', 'state', 'text'}`` for the main
    configuration and any ``include_conf`` files. ``state`` is one of
    ``FILE_STATES``. ``text`` is required for ``regular`` files.
    """
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS),
        'config_path': config_path, 'complete': True, 'rejected_by_parser': False,
        'run_as': RUN_AS, 'files': [], 'commands': [], 'programs': [],
        'config_errors': [], 'warnings': [], 'gaps': [], 'not_modelled': list(NOT_MODELLED),
        'origin': 'not_assessed',
    }
    gaps: list[dict[str, Any]] = result['gaps']
    records: dict[str, dict[str, Any]] = {}
    for record in files or []:
        if isinstance(record, dict) and isinstance(record.get('path'), str):
            records.setdefault(record['path'], record)

    def gap(reason: str, **detail: Any) -> None:
        result['complete'] = False
        if len(gaps) < MAX_GAPS:
            gaps.append({'reason': reason, **detail})
        elif len(gaps) == MAX_GAPS:
            gaps.append({'reason': 'gap_limit_reached', 'limit': MAX_GAPS})

    def config_err(file_path: str, line: int, reason: str, **detail: Any) -> None:
        result['rejected_by_parser'] = True
        result['config_errors'].append({'file': file_path, 'line': line, 'reason': reason,
                                        **detail})

    commands: list[dict[str, Any]] = result['commands']
    programs: dict[str, dict[str, Any]] = {}
    hooks: dict[str, dict[str, Any]] = {}
    state: dict[str, Any] = {'snapshot_root': False, 'cmd_ssh': False, 'ssh_backups': 0,
                             'lvm_backups': 0, 'aborted': False}

    def command_entry(kind: str, command: str, path: str, line: int, **extra: Any) -> dict[str, Any]:
        shell = perl_uses_shell(command)
        entry = {
            'kind': kind, 'command': command, 'executable': _script_word(command),
            'via_shell': shell, 'argv': ['/bin/sh', '-c', command] if shell else perl_argv(command),
            'run_as': RUN_AS, 'file': path, 'line': line, 'origin': 'not_assessed',
        }
        entry.update(extra)
        commands.append(entry)
        return entry

    def parse(path: str, depth: int, chain: tuple[str, ...], included_from: dict | None) -> None:
        if state['aborted']:
            return
        record = records.get(path)
        file_info: dict[str, Any] = {'path': path, 'included_from': included_from}
        result['files'].append(file_info)
        if record is None:
            file_info['state'] = 'not_observed'
            gap('file_not_observed', path=path)
            return
        file_state = record.get('state')
        file_info['state'] = file_state
        if file_state not in FILE_STATES:
            gap('file_state_not_modelled', path=path, state=file_state)
            return
        if file_state == 'unknown':
            gap('file_state_unknown', path=path)
            return
        if file_state != 'regular':
            if included_from is None:
                # main config missing or unreadable: exit_no_config_file()
                state['aborted'] = True
                config_err(path, 0, 'config_file_not_readable', state=file_state)
            else:
                config_err(included_from['file'], included_from['line'],
                           'include_conf_file_not_readable', path=path, state=file_state)
            return
        text = record.get('text')
        if not isinstance(text, str):
            gap('file_text_missing', path=path)
            return
        if len(text.encode('utf-8', 'surrogateescape')) > MAX_TEXT:
            gap('file_too_large', path=path, limit=MAX_TEXT)
            return
        if '\0' in text:
            gap('nul_byte', path=path)
            return
        parse_lines(path, _lines(text), depth, chain)

    def parse_lines(path: str, configs: list[str], depth: int, chain: tuple[str, ...]) -> None:
        i = 0
        while i < len(configs) and configs[i] and configs[i] != '0':
            if state['aborted']:
                return
            raw = configs[i]
            line = raw.removesuffix('\n')
            i += 1
            line_no = i
            if line.startswith('#') or not _NO_SPACE.search(line):
                continue
            while i < len(configs) and _CONTINUATION.match(configs[i]):
                line = line + '\t' + configs[i].strip(_PERL_SPACE)
                i += 1
            fields = re.split(r'\t+', line, maxsplit=3)
            var = fields[0]
            value = fields[1] if len(fields) > 1 else None
            value2 = fields[2] if len(fields) > 2 else None
            if value is None:
                reason = 'spaces_instead_of_tabs' if re.search(r'\s', line) else 'missing_value'
                config_err(path, line_no, reason, text=line[:120])
                continue
            for v in (value, value2, fields[3] if len(fields) > 3 else None):
                if v is not None and v.startswith(' '):
                    result['warnings'].append({'file': path, 'line': line_no,
                                               'reason': 'space_after_tab'})
            handle(path, line_no, var, value, value2, fields[3:] if len(fields) > 3 else [],
                   depth, chain)

    def handle(path: str, line_no: int, var: str, value: str, value2: str | None,
               rest: list[str], depth: int, chain: tuple[str, ...]) -> None:
        where = {'file': path, 'line': line_no}
        if var == 'include_conf':
            m = _BACKTICK.match(value)
            target = records.get(value)
            # rsnapshot tries "-f && -r" on the literal value first, then the backtick form.
            if m is None or (target is not None and target.get('state') == 'regular'):
                if value in chain:
                    # No cycle check: recursion holds every handle open until open() fails.
                    state['aborted'] = True
                    config_err(path, line_no, 'include_conf_cycle_aborts', path=value)
                    return
                if depth + 1 > MAX_INCLUDE_DEPTH:
                    gap('include_depth_limit', path=value, limit=MAX_INCLUDE_DEPTH)
                    return
                parse(value, depth + 1, chain + (value,), where)
                return
            inner = m.group(1)
            if not _abs_path(_script_word(inner)):
                config_err(path, line_no, 'include_conf_script_not_valid', command=inner)
                return
            command_entry('include_conf_command', inner, path, line_no,
                          when='every_invocation_while_parsing_config_including_configtest',
                          cwd='invocation_directory', on_failure='output_parsed_as_config',
                          effective=True, requires_executable=_script_word(inner))
            gap('include_conf_command_output_not_modelled', file=path, line=line_no,
                command=inner)
            return
        if var in ('cmd_preexec', 'cmd_postexec'):
            script = _script_word(value)
            if not _abs_path(script):
                config_err(path, line_no, 'hook_script_not_absolute', key=var, script=script)
                return
            previous = hooks.get(var)
            if previous is not None:
                previous['effective'] = False
            dropped = [v for v in [value2, *rest] if v is not None]
            when = ('before_lowest_interval_backup_or_sync' if var == 'cmd_preexec'
                    else 'after_lowest_interval_backup_or_sync')
            hooks[var] = command_entry(
                var, value, path, line_no, when=when, cwd='$HOME',
                on_failure='aborts_rsnapshot', effective=True, requires_executable=script,
                dropped_fields=dropped)
            return
        if var == 'backup_script':
            if not state['snapshot_root']:
                config_err(path, line_no, 'snapshot_root_not_yet_defined')
                return
            if value2 is None:
                config_err(path, line_no, 'backup_script_without_destination')
                return
            if value2.startswith('/') or _traversal(value2):
                config_err(path, line_no, 'backup_script_destination_not_relative', dest=value2)
                return
            script = _script_word(value)
            if not _abs_path(script):
                config_err(path, line_no, 'backup_script_not_absolute', script=script)
                return
            command_entry('backup_script', value, path, line_no, destination=value2,
                          when='each_lowest_interval_backup_or_sync',
                          cwd='<snapshot_root>/tmp/', on_failure='rolls_back_destination',
                          effective=True, requires_executable=script)
            return
        if var == 'backup_exec':
            importance = value2 if value2 is not None else 'optional'
            if importance not in ('optional', 'required'):
                config_err(path, line_no, 'backup_exec_importance_invalid', importance=importance)
                return
            command_entry('backup_exec', value, path, line_no, importance=importance,
                          when='each_lowest_interval_backup_or_sync_in_config_order',
                          cwd='$HOME',
                          on_failure='aborts_rsnapshot' if importance == 'required' else 'warning',
                          effective=True, path_checked=False)
            return
        if var in PROGRAM_KEYS or var in LVM_KEYS:
            lvm = var in LVM_KEYS
            program = _script_word(value) if lvm else value.rstrip(_PERL_SPACE)
            if not _abs_path(program):
                config_err(path, line_no, 'program_path_not_absolute', key=var, path=program)
                return
            if var == 'cmd_ssh':
                state['cmd_ssh'] = True
            previous = programs.get(var)
            if previous is not None:
                previous['effective'] = False
                result['programs'].append(dict(previous))
            programs[var] = {
                'key': var, 'path': program,
                'argv_prefix': value.split() if lvm else [program], 'via_shell': False,
                'configured': True, 'effective': True, 'run_as': RUN_AS,
                'used_for': PROGRAM_KEYS[var][1] if not lvm else 'lvm_snapshot_backup_points',
                **where,
            }
            return
        if var == 'snapshot_root':
            if not _abs_path(value):
                config_err(path, line_no, 'snapshot_root_not_absolute')
                return
            state['snapshot_root'] = True
            return
        if var == 'backup':
            src = value
            if value2 is None:
                config_err(path, line_no, 'backup_without_destination')
                return
            if '://' not in src and _SSH_PATH.match(src) and not re.search(r'^\s|\s$', src):
                if not state['cmd_ssh']:
                    config_err(path, line_no, 'ssh_backup_without_cmd_ssh', source=src)
                    return
                state['ssh_backups'] += 1
            elif src.startswith('lvm://'):
                state['lvm_backups'] += 1
            return
        if var in _OTHER_KEYS:
            return
        config_err(path, line_no, 'unknown_directive', directive=var[:80])

    parse(config_path, 0, (config_path,), None)

    if not state['aborted']:
        for key, (default, used_for) in PROGRAM_KEYS.items():
            if key not in programs:
                result['programs'].append({'key': key, 'path': None, 'configured': False,
                                           'effective': True, 'default': default,
                                           'used_for': used_for})
        result['programs'].extend(programs[k] for k in programs)
        if 'cmd_rsync' not in programs:
            config_err(config_path, 0, 'cmd_rsync_required')
        result['ssh_backup_points'] = state['ssh_backups']
        result['lvm_backup_points'] = state['lvm_backups']
    result['programs'].sort(key=lambda p: (p['key'], not p.get('effective', True)))
    if result['rejected_by_parser']:
        for entry in commands:
            if entry['kind'] != 'include_conf_command':
                entry['runs_only_if_config_accepted'] = True
        result['backup_commands_run'] = False
    else:
        result['backup_commands_run'] = 'if_host_checks_pass'
    return result
