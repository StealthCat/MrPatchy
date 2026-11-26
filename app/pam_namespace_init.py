"""Pure pam_namespace init-script contract (roadmap F slice, #1564).

``pam_namespace.so`` polyinstantiates directories when a PAM session opens.
For each configured directory it runs an init script as root:
``/etc/security/namespace.init``, or the per-directory ``iscript=`` program.
The script runs with an empty environment and waits for every session that
reaches the directory. A planted ``iscript=`` or an edited ``namespace.init``
therefore runs as root on login, and neither cron, systemd nor the PAM-stack
contract (#967) shows it. This module turns captured, read-only
``namespace.conf`` and ``namespace.d`` text, plus the observed state of the
scripts, into the programs that run, with their argv and order. It performs no
I/O, never runs a script, never opens a PAM session and never authorizes a
response action.

Rules this module follows were read from ``modules/pam_namespace`` in
Linux-PAM 1.7.1 (``pam_namespace.c``, ``argv_parse.c``). They were checked
natively against Ubuntu 24.04 ``libpam-modules 1.5.3-5ubuntu5.7``, which syncs
the module to 1.7 with the CVE-2025-6020 fixes, through a ctypes
``pam_open_session`` driver. The ``1.5`` model applies the source differences
of Linux-PAM 1.5.3 (four script arguments, a ``/`` polydir is invalid, and
only one trailing slash is removed). It has not been checked natively.

- ``namespace.conf`` is read first. It must open, even when ``namespace.d``
  has files; otherwise every session fails. Then ``namespace.d/*.conf`` is
  read in ``strcmp`` basename order. ``glob()`` skips hidden names.
- Each line: leading ``isspace`` is skipped, the first ``#`` ends the line
  even inside quotes, then ``argv_parse`` splits the line. Whitespace
  separates words, ``"`` toggles quoting (no escapes inside), and outside
  quotes ``\\n`` ``\\t`` ``\\b`` are escapes and ``\\x`` is ``x``. The fields
  are ``polydir instance_prefix method [uids]``; extra fields are ignored.
- ``$HOME`` and ``$USER`` are expanded wherever they start, by prefix, so
  ``$USERz`` is the user name followed by ``z``. Trailing slashes are removed.
- The method is the first ``:``-separated token (empty tokens are skipped),
  matched case-sensitively against ``user context level tmpdir tmpfs``. A
  method with no token (only ``:`` or an empty quoted string) makes libpam call
  ``strcmp(NULL, ...)``; the session process crashed natively. Later tokens are
  flags matched by **prefix**: ``createfoo`` is ``create`` and ``noinitx`` is
  ``noinit``. Unknown flags are ignored. ``iscript=<path>`` sets the script,
  relative to ``/etc/security/namespace.d/``. The last non-empty value wins,
  and ``iscript=`` or ``iscriptX`` keep the earlier or default script.
- A line is invalid when a field is missing, the polydir is empty, the method
  is unknown, a path is at least ``PATH_MAX`` bytes, the polydir (or, except
  for ``tmpfs``, the instance prefix) is not absolute, or either contains
  ``..``. An invalid line fails every session unless the PAM stack passes
  ``ignore_config_error``, which skips it.
- ``uids`` lists override users. They are not polyinstantiated, or are the
  only ones that are when the list starts with ``~``. Unknown names are logged
  and dropped.
- Per directory, unless ``noinit`` is set, libpam runs the script only if it
  exists. If it exists but is not executable, the session fails at that
  directory, after the earlier directories' scripts have already run. The
  argv is ``script polydir instance newdir user`` plus, in 1.7,
  ``polydir_safe instance_safe``. The instance is the literal ``tmpfs`` for the
  ``tmpfs`` method, with ``newdir`` ``1``. A non-zero exit status is ignored;
  death by a signal fails the session.

Fail-closed rules: unobserved files, listings or script states, NUL bytes,
over-limit input, a vendor directory, an unknown model, a method without a
name and ``create`` owners or groups (resolved through the account database)
are gaps. A result with any gap is not ``complete``. ``origin`` is always
``not_assessed``.
"""
from __future__ import annotations

from typing import Any

CONTRACT_VERSION = 1
MAX_TEXT = 1 << 20
MAX_FILES = 512
MAX_GAPS = 256
PATH_MAX = 4096

CONF = '/etc/security/namespace.conf'
CONF_D = '/etc/security/namespace.d/'
DEFAULT_SCRIPT = '/etc/security/namespace.init'
MODELS = ('1.7', '1.5')
FILE_STATES = ('absent', 'regular', 'unreadable', 'not_regular', 'unknown')
LISTING_STATES = ('listed', 'absent', 'unreadable', 'unknown')
SCRIPT_STATES = ('absent', 'executable', 'not_executable', 'unknown')
METHODS = ('user', 'context', 'level', 'tmpdir', 'tmpfs')
FLAGS = ('create', 'noinit', 'iscript', 'shared', 'mntopts')
NOT_MODELLED = (
    'which_pam_services_load_pam_namespace',
    'runtime_override_user_matching_uid_and_ruid',
    'selinux_context_and_level_instances',
    'polydir_and_instance_runtime_failures',
    'contents_of_the_scripts_run',
)

_ISSPACE = ' \t\n\v\f\r'
_ESCAPES = {'n': '\n', 't': '\t', 'b': '\b'}


class Invalid(ValueError):
    """Raised for observations that do not have the documented shape."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})


def _bytes(value: str) -> int:
    return len(value.encode('utf-8', 'surrogateescape'))


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise Invalid(f'{name}.text must be a string for a regular file')
    if len(value) > MAX_TEXT:
        raise Invalid(f'{name}.text exceeds {MAX_TEXT} characters')
    try:
        value.encode('utf-8', 'surrogateescape')
    except UnicodeEncodeError as error:
        raise Invalid(f'{name}.text is not a surrogateescape decoding of file bytes') from error
    return value


def _file(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {'state': 'unknown', 'text': None}
    if not isinstance(value, dict) or set(value) - {'state', 'text'}:
        raise Invalid(f'{name} must be an object with state and optional text')
    state = value.get('state')
    if state not in FILE_STATES:
        raise Invalid(f'{name}.state must be one of {FILE_STATES}')
    text = value.get('text')
    if state == 'regular':
        text = _text(text, name)
    elif text is not None:
        raise Invalid(f'{name}.text is only allowed for a regular file')
    return {'state': state, 'text': text}


def argv_parse(line: str) -> list[str]:
    """Split a line as ``argv_parse.c`` does."""
    words: list[str] = []
    word: list[str] | None = None
    quoted = False
    index = 0
    while index < len(line):
        char = line[index]
        index += 1
        if word is None:
            if char in _ISSPACE:
                continue
            word = []
        if quoted:
            if char == '"':
                quoted = False
            else:
                word.append(char)
            continue
        if char in _ISSPACE:
            words.append(''.join(word))
            word = None
            continue
        if char == '"':
            quoted = True
            continue
        if char == '\\' and index < len(line):
            char = _ESCAPES.get(line[index], line[index])
            index += 1
        word.append(char)
    if word is not None:
        words.append(''.join(word))
    return words


def _expansions(value: str) -> list[str]:
    found: list[str] = []
    index = value.find('$')
    while index >= 0:
        for name in ('HOME', 'USER'):
            if value.startswith(name, index + 1) and '$' + name not in found:
                found.append('$' + name)
        index = value.find('$', index + 1)
    return found


def _strip_slashes(value: str, model: str) -> str:
    if model == '1.5':
        return value[:-1] if value.endswith('/') else value
    while len(value) > 1 and value.endswith('/'):
        value = value[:-1]
    return value


def _absolute(value: str) -> bool:
    # $HOME expands to the account's home directory, which pam_namespace looks up and which
    # is absolute on any working system; $USER never starts with '/'.
    return value.startswith('/') or value.startswith('$HOME')


def _method(text: str) -> tuple[str | None, dict[str, Any], str | None]:
    tokens = [token for token in text.split(':') if token]
    flags: dict[str, Any] = {'set': [], 'iscript': None, 'create': None}
    if not tokens:
        return None, flags, 'method_without_name_crashes'
    if tokens[0] not in METHODS:
        return None, flags, 'unknown_method'
    for token in tokens[1:]:
        for name in FLAGS:
            if not token.startswith(name):
                continue
            if name not in flags['set']:
                flags['set'].append(name)
            rest = token[len(name):]
            if name == 'iscript' and rest.startswith('=') and len(rest) > 1:
                value = rest[1:]
                flags['iscript'] = value if value.startswith('/') else CONF_D + value
            if name == 'create' and rest.startswith('='):
                flags['create'] = rest[1:]
    return tokens[0], flags, None


def _create_accounts(value: str | None) -> list[str]:
    if not value:
        return []
    parts = value.split(',', 2)
    return [part for part in parts[1:] if part]


def _line(path: str, number: int, raw: str, model: str,
          gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    line = raw.lstrip(_ISSPACE)
    line = line.split('#', 1)[0].split('\n', 1)[0]
    if not line:
        return None
    words = argv_parse(line)
    entry: dict[str, Any] = {'path': path, 'line': number, 'fields': words[:4], 'error': None}
    if len(words) < 3:
        entry['error'] = ('missing_polydir', 'missing_instance_prefix', 'missing_method')[len(words)]
        return entry
    polydir = _strip_slashes(words[0], model)
    prefix = words[1]
    if not polydir:
        # 1.5 removes one trailing slash, so '/' becomes '' and is rejected there.
        entry['error'] = 'invalid_polydir'
        return entry
    method, flags, error = _method(words[2])
    if error:
        entry['error'] = error
        if error == 'method_without_name_crashes':
            _gap(gaps, 'method_without_name_crashes', path=path, line=number)
        return entry
    if any(_bytes(value) >= PATH_MAX for value in (polydir, prefix)):
        entry['error'] = 'path_too_long'
        return entry
    if not _absolute(polydir) or (method != 'tmpfs' and not _absolute(prefix)):
        entry['error'] = 'path_not_absolute'
        return entry
    if '..' in polydir or '..' in prefix:
        entry['error'] = 'path_contains_dotdot'
        return entry
    accounts = _create_accounts(flags['create']) if 'create' in flags['set'] else []
    if accounts:
        _gap(gaps, 'create_account_unchecked', path=path, line=number, accounts=accounts)
    uids = words[3] if len(words) > 3 else None
    applies: dict[str, Any] = {'mode': 'all_users', 'users': []}
    if uids is not None:
        exclusive = uids.startswith('~')
        names = (uids[1:] if exclusive else uids).split(',')
        applies = {'mode': 'only_listed' if exclusive else 'all_except_listed', 'users': names}
    entry.update({
        'polydir': polydir,
        'instance_prefix': prefix,
        'method': method,
        'flags': flags['set'],
        'iscript': flags['iscript'],
        'create_accounts': accounts,
        'expansions': _expansions(words[0] + '\0' + prefix),
        'applies_to': applies,
    })
    return entry


def _instance(entry: dict[str, Any]) -> str:
    method = entry['method']
    if method == 'tmpfs':
        return 'tmpfs'
    suffix = {'user': '<user_or_hash>', 'tmpdir': '<random6>'}.get(method, '<selinux_instance>')
    return entry['instance_prefix'] + suffix


def _scripts(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise Invalid('scripts must be an object')
    out: dict[str, str] = {}
    for path, state in value.items():
        if not isinstance(path, str) or not path.startswith('/'):
            raise Invalid('scripts keys must be absolute paths')
        if state not in SCRIPT_STATES:
            raise Invalid(f'scripts[{path!r}] must be one of {SCRIPT_STATES}')
        out[path] = state
    return out


def _listing(value: Any) -> tuple[str, list[tuple[str, dict[str, Any]]]]:
    if value is None:
        return 'unknown', []
    if not isinstance(value, dict) or set(value) - {'state', 'entries'}:
        raise Invalid('namespace_d must be an object with state and optional entries')
    state = value.get('state')
    if state not in LISTING_STATES:
        raise Invalid(f'namespace_d.state must be one of {LISTING_STATES}')
    entries = value.get('entries') or {}
    if state != 'listed' and entries:
        raise Invalid('namespace_d.entries is only allowed for a listed directory')
    if not isinstance(entries, dict) or len(entries) > MAX_FILES:
        raise Invalid(f'namespace_d.entries must be an object of at most {MAX_FILES} files')
    files: list[tuple[str, dict[str, Any]]] = []
    for name in entries:
        if not isinstance(name, str) or not name or '/' in name:
            raise Invalid('namespace_d.entries keys must be base names')
    names = sorted((name for name in entries if name.endswith('.conf') and not name.startswith('.')),
                   key=lambda item: item.encode('utf-8', 'surrogateescape'))
    for name in names:
        files.append((CONF_D + name, _file(entries[name], f'namespace_d.entries[{name!r}]')))
    return state, files


def resolve(observation: Any) -> dict[str, Any]:
    """Return the init scripts pam_namespace runs as root for each polyinstantiated directory."""
    if not isinstance(observation, dict):
        raise Invalid('observation must be an object')
    allowed = {'model', 'namespace_conf', 'namespace_d', 'scripts', 'module_args', 'vendor_dir'}
    unknown = set(observation) - allowed
    if unknown:
        raise Invalid(f'unknown observation keys: {sorted(unknown)}')
    gaps: list[dict[str, Any]] = []
    model = observation.get('model')
    if model not in MODELS:
        _gap(gaps, 'version_unverified', model=model)
        model = '1.7'
    if observation.get('vendor_dir') is not None:
        _gap(gaps, 'vendor_dir_not_modelled', vendor_dir=observation.get('vendor_dir'))
    args = observation.get('module_args')
    if args is not None and (not isinstance(args, list) or not all(isinstance(a, str) for a in args)):
        raise Invalid('module_args must be a list of strings')
    scripts = _scripts(observation.get('scripts'))

    conf = _file(observation.get('namespace_conf'), 'namespace_conf')
    listing_state, d_files = _listing(observation.get('namespace_d'))
    sources: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    fatal: dict[str, Any] | None = None

    def read(path: str, observed: dict[str, Any]) -> None:
        nonlocal fatal
        state = observed['state']
        sources.append({'path': path, 'state': state})
        if state == 'unknown':
            _gap(gaps, 'file_unobserved', path=path)
            return
        if state == 'not_regular':
            _gap(gaps, 'file_not_modelled', path=path)
            return
        if state in ('absent', 'unreadable'):
            if fatal is None:
                fatal = {'path': path, 'reason': 'cannot_open'}
            return
        text = observed['text']
        if '\0' in text:
            _gap(gaps, 'nul_byte', path=path)
            return
        # getline() splits on '\n' only.
        lines = text.split('\n')
        if lines and lines[-1] == '':
            lines.pop()
        for number, raw in enumerate(lines, 1):
            entry = _line(path, number, raw, model, gaps)
            if entry is None:
                continue
            (invalid if entry['error'] else entries).append(entry)

    read(CONF, conf)
    if listing_state == 'unknown':
        _gap(gaps, 'listing_unobserved', path=CONF_D)
    elif listing_state == 'unreadable':
        _gap(gaps, 'listing_not_modelled', path=CONF_D)
    for path, observed in d_files:
        read(path, observed)

    ignore = None if args is None else 'ignore_config_error' in args
    unmount_only = bool(args) and 'unmnt_only' in args
    if fatal is not None or unmount_only or (invalid and ignore is False):
        runs: bool | None = False
    elif invalid and ignore is None:
        runs = None
    else:
        runs = True
    commands: list[dict[str, Any]] = []
    stops_at: dict[str, Any] | None = None
    for entry in entries:
        script = entry['iscript'] or DEFAULT_SCRIPT
        state = scripts.get(script, 'unknown')
        if 'noinit' in entry['flags']:
            effect = 'noinit'
        elif state == 'unknown':
            effect = 'script_unobserved'
            _gap(gaps, 'script_unobserved', path=script)
        elif state == 'absent':
            effect = 'script_absent_nothing_runs'
        elif state == 'not_executable':
            effect = 'session_fails_here'
        else:
            effect = 'runs_as_root'
        entry['script'] = script
        entry['script_state'] = state
        entry['effect'] = effect
        if effect == 'session_fails_here' and stops_at is None:
            stops_at = {'path': entry['path'], 'line': entry['line']}
        if effect != 'runs_as_root':
            continue
        argv = [script, entry['polydir'], _instance(entry),
                '1' if entry['method'] == 'tmpfs' else '<newdir:0|1>', '<user>']
        if model == '1.7':
            argv += ['<polydir_safe:0|1>', '0' if entry['method'] == 'tmpfs' else '<instance_safe:0|1>']
        commands.append({
            'path': entry['path'],
            'line': entry['line'],
            'script': script,
            'per_directory_iscript': entry['iscript'] is not None,
            'argv': argv,
            'environment': {},
            'runs_as': 'root',
            'waits': True,
            'exit_status_ignored': True,
            'applies_to': entry['applies_to'],
            'after_failure_point': stops_at is not None,
            'reachable': False if stops_at is not None else runs,
            'origin': 'not_assessed',
        })
    if fatal is not None or (invalid and ignore is False):
        outcome = 'every_session_fails'
    elif invalid and ignore is None:
        outcome = 'depends_on_ignore_config_error'
    else:
        outcome = 'ok'
    return {
        'contract_version': CONTRACT_VERSION,
        'model': model,
        'complete': not gaps,
        'sources': sources,
        'directories': entries,
        'invalid_lines': invalid,
        'config_outcome': outcome,
        'config_fatal': fatal,
        'unmount_only': unmount_only,
        'session_stops_at': stops_at,
        'commands': commands,
        'reachable_commands': sum(1 for item in commands if item['reachable'] is True),
        'gaps': gaps,
        'not_modelled': list(NOT_MODELLED),
        'authorizes_response': False,
    }
