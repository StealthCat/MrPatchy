"""Pure TuneD profile contract (roadmap F slice, #1237).

Takes captured, read-only TuneD state and says which executables the TuneD
daemon (``/usr/sbin/tuned``, running as root) starts for the active profile,
with which arguments and in which order, and where coverage is missing. TuneD
is installed and enabled by default on RHEL-family servers and is packaged for
Debian and Ubuntu. It never runs anything and never reads a script's contents.

Semantics come from the TuneD 2.21.0 source as packaged in Ubuntu 24.04
(``tuned_2.21.0-1ubuntu2``): ``profiles/locator.py``, ``loader.py``,
``merger.py``, ``profile.py``, ``unit.py`` and ``variables.py``,
``plugins/base.py``, ``plugin_script.py``, ``units/manager.py``,
``daemon/daemon.py`` and ``utils/commands.py``, not from recollection:

* At start and on every reload, the daemon reads ``/etc/tuned/active_profile``
  and ``/etc/tuned/profile_mode`` (each ``.strip()``-ed). A mode other than
  empty, ``auto`` or ``manual`` refuses to load any profile. With no mode
  file, a non-empty active profile means manual mode. In auto mode the daemon
  replaces the active profile with the recommended one (``recommend.d``),
  which this contract does not model, so it is a blocking gap.
* ``/etc/tuned/post_loaded_profile`` (stripped) is appended as one extra name.
  Whitespace inside it refuses the whole load.
* Every requested name must be a *known* profile: a directory entry of
  ``/usr/lib/tuned`` or ``/etc/tuned`` whose ``<dir>/<name>/tuned.conf`` is a
  regular file (symlinks followed). Otherwise nothing loads. Names that do not
  match ``^[a-zA-Z0-9_.-]+$`` are then silently dropped.
* A profile name resolves to ``<dir>/basename(name)/tuned.conf``, trying
  ``/etc/tuned`` before ``/usr/lib/tuned``, so a custom profile shadows a stock
  one. A file already loaded is skipped, and the search falls through to the
  next directory. ``include=`` in ``[main]`` is split on ``,`` or ``;`` and
  loaded first, depth first. A ``-name`` include is optional; any other missing
  include refuses the whole load. Each file is parsed by Python
  ``configparser`` with ``=`` as the only delimiter, ``#`` inline comments,
  ``strict=False`` and case-sensitive option names. A parse error refuses the
  whole load.
* ``${i:PROFILE_DIR}`` (not preceded by ``\\``) becomes the file's directory.
  A ``script=`` option in any section becomes a one-element list holding
  ``normpath(join(profile_dir, value))``.
* Profiles are merged in load order. ``[main]`` options are updated. A unit
  with ``replace=true``, or one not seen before, replaces the earlier unit.
  Otherwise ``type``, ``enabled`` and ``devices`` are overwritten, the
  regexes and ``script_pre``/``script_post`` are overwritten when set,
  ``drop=`` removes earlier options, and options are updated. For a unit named
  ``script`` that already has scripts, the result is the earlier list followed
  by the merged list. When the later unit sets no ``script``, that repeats the
  earlier scripts, so they run twice; this is TuneD's behavior and is kept.
* Units with ``enabled`` not in ``True``/``true``/``1`` are skipped. Units with
  ``cpuinfo_regex`` or ``uname_regex`` only run when the regex matches the
  host, which is reported as a condition. Units are ordered by ``int(priority)``
  (default ``default_instance_priority``, normally 0), stable on profile
  order. ``units/manager.py`` checks each enabled unit in profile order:
  ``cpuinfo_regex`` (``re.search``), then ``uname_regex``, then
  ``int(priority)``. An uncompilable regex or a non-integer priority raises
  before any unit is created, so nothing is applied. When the raising check
  is only reached if an earlier regex of the same unit matches the host, the
  outcome depends on the host and is a blocking gap; a regex containing
  ``$`` is expanded by TuneD first and is never treated as uncompilable.
* A ``type=script`` unit runs each listed path as root with ``start`` when the
  profile is applied, ``verify`` on ``tuned-adm verify`` and ``stop`` in
  reverse order on unload, with ``cwd`` set to the script's directory and the
  daemon environment plus profile variables. Ownership and permissions are not
  checked. A missing or non-executable path only logs an error.
* Any unit's ``script_pre`` and ``script_post`` run as root around that
  unit's tuning, once per assigned device, with ``apply``/``verify``/
  ``unapply`` and the device name. A relative path never runs. Whether any
  device is assigned depends on the plugin and the hardware, so these runs are
  conditional.
* ``${f:exec:...}`` in an expanded value runs that command as root while the
  profile is loaded or applied. ``[variables]`` values are expanded as soon as
  the profile loads. ``Variables.expand`` substitutes ``${NAME}`` statically
  first and then runs functions, innermost first, so ``exec`` can be assembled
  from a variable or another function's result. The contract substitutes
  variables textually, leaving every function call in place, and then reads
  each ``{f:`` name: ``exec`` is a blocking ``function_exec`` gap, and a name
  that is not a literal word is a blocking ``function_expansion_not_modeled``
  gap. So is any ``${`` that is neither a plain ``${NAME}`` reference nor a
  literal ``${f:<name>`` call, because TuneD re-splits that outer call after a
  nested result is spliced in (``${${f:strip:f\\:exec\\:cmd}}`` runs ``cmd``).
  The daemon keeps one variable store for its lifetime, so a reference to a
  name the profile does not define may resolve to a value left by an earlier
  profile; that is a blocking ``variable_undefined`` gap. A variable or
  function in an include and a ``[variables] include=`` file are blocking gaps.
  ``${i:PROFILE_DIR}`` is substituted with ``re.sub``, which treats a backslash
  in the directory as a template escape, so that case is a blocking gap too.
  Script paths are never expanded by TuneD beyond ``${i:PROFILE_DIR}``, so they
  are reported literally.

It performs no I/O and never authorizes a response action. Unobserved family,
installation state, files or listings, malformed input and over-limit input are
blocking gaps.
"""
from __future__ import annotations

import configparser
import posixpath
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'tuned': 'TuneD 2.21.0 (tuned_2.21.0-1ubuntu2) profiles/{locator,loader,merger,profile,unit,variables}.py, '
             'plugins/{base,plugin_script}.py, units/manager.py, daemon/daemon.py, utils/commands.py',
}
RUNS_AS = 'root'
DAEMON = '/usr/sbin/tuned'
LOAD_DIRECTORIES = ('/usr/lib/tuned', '/etc/tuned')
ACTIVE_PROFILE_FILE = '/etc/tuned/active_profile'
PROFILE_MODE_FILE = '/etc/tuned/profile_mode'
POST_LOADED_PROFILE_FILE = '/etc/tuned/post_loaded_profile'
SCRIPT_ARGUMENTS = {'apply': ('start',), 'verify': ('verify',), 'unapply': ('stop',)}
DEVICE_SCRIPT_ARGUMENTS = {'apply': ('apply', 'DEVICE'), 'verify': ('verify', 'DEVICE'),
                           'unapply': ('unapply', 'DEVICE')}
EVENTS = ('tuned.service start at boot', 'tuned-adm profile / tuned reload (SIGHUP)',
          'tuned-adm verify (verify), profile switch or tuned stop (stop/unapply)')
APPLICABLE_FAMILIES = frozenset({'debian', 'rpm'})
MAX_FILES = 512
MAX_TEXT = 256 * 1024
MAX_LISTING = 4096
MAX_DEPTH = 32
MAX_GAPS = 64
BLOCKING = frozenset({
    'family_unobserved', 'installation_unobserved', 'input_invalid', 'input_over_limit',
    'state_file_unobserved', 'state_file_unreadable', 'recommended_profile_not_modeled',
    'listing_unobserved', 'path_unobserved', 'file_unreadable', 'include_expansion_not_modeled',
    'function_exec', 'variables_file_not_modeled',
    'include_depth_exceeded', 'apply_refusal_conditional', 'function_expansion_not_modeled',
    'variable_undefined', 'profile_dir_escape_not_modeled',
})

_SAFE_NAME = re.compile(r'^[a-zA-Z0-9_.-]+$')
_PROFILE_DIR = re.compile(r'(?<!\\)\$\{i:PROFILE_DIR\}')
_INCLUDE_SPLIT = re.compile(r'\s*[,;]\s*')
_DROP_SPLIT = re.compile(r'\b\s*[,;]\s*')
_VAR_REF = re.compile(r'(?<!\\)\$\{(\w+)\}')
_VAR_UNESCAPE = re.compile(r'\\(\$\{\w+\})')
_FUNC_OPEN = re.compile(r'\{f:')
_FUNC_NAME = re.compile(r'\w+(?=[:}])')
_CALL_OPEN = re.compile(r'\$\{')
_READABLE_OPEN = re.compile(r'\w+\}|f:\w+[:}]')
_VAR_NAME = re.compile(r'\w+$')
_TRUE = ('True', 'true', '1')


class _Abort(Exception):
    """The daemon would refuse to load any profile."""

    def __init__(self, reason: str, detail: str = ''):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class _Incomplete(Exception):
    """A fact the resolution needs was not observed or is not modelled."""


class _Unit:
    __slots__ = ('name', 'type', 'enabled', 'replace', 'drop', 'devices', 'cpuinfo_regex',
                 'uname_regex', 'script_pre', 'script_post', 'options', 'source')

    def __init__(self, name: str, config: dict, source: str):
        self.name = name
        self.source = source
        self.type = config.pop('type', name)
        self.enabled = config.pop('enabled', True) in (True, *_TRUE, 1)
        self.replace = config.pop('replace', False) in (True, *_TRUE, 1)
        drop = config.pop('drop', None)
        self.drop = _DROP_SPLIT.split(str(drop)) if drop is not None else None
        self.devices = config.pop('devices', '*')
        config.pop('devices_udev_regex', None)
        self.cpuinfo_regex = config.pop('cpuinfo_regex', None)
        self.uname_regex = config.pop('uname_regex', None)
        self.script_pre = config.pop('script_pre', None)
        self.script_post = config.pop('script_post', None)
        self.options = dict(config)


class _Profile:
    def __init__(self, config: dict, source: str):
        self.options = dict(config.get('main', {}))
        self.units: dict[str, _Unit] = {}
        for name, section in config.items():
            if name != 'main':
                self.units[name] = _Unit(name, dict(section), source)


def _merge(a: _Profile, b: _Profile) -> _Profile:
    a.options.update(b.options)
    for name, unit in list(b.units.items()):
        if unit.replace or name not in a.units:
            a.units[name] = unit
            continue
        target = a.units[name]
        target.type = unit.type
        target.enabled = unit.enabled
        target.devices = unit.devices
        for attr in ('cpuinfo_regex', 'uname_regex', 'script_pre', 'script_post'):
            if getattr(unit, attr) is not None:
                setattr(target, attr, getattr(unit, attr))
        if unit.drop is not None:
            for option in unit.drop:
                target.options.pop(option, None)
            unit.drop = None
        if name == 'script' and target.options.get('script') is not None:
            scripts = target.options['script']
            target.options.update(unit.options)
            target.options['script'] = scripts + target.options['script']
        else:
            target.options.update(unit.options)
        target.source = unit.source
    return a


def _text_state(raw: Any, path: str) -> str | None:
    """Return stripped file text, '' when absent, or raise for an unusable fact."""
    if raw is None:
        raise _Incomplete(('state_file_unobserved', path))
    if not isinstance(raw, dict) or raw.get('state') not in ('absent', 'present', 'unreadable'):
        raise _Incomplete(('input_invalid', path))
    if raw['state'] == 'absent':
        return ''
    if raw['state'] == 'unreadable':
        # commands.get_active_profile raises for any error other than ENOENT.
        raise _Abort('state_file_unreadable', path)
    text = raw.get('text')
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        raise _Incomplete(('input_invalid', path))
    return text.strip()


class _Resolver:
    def __init__(self, files: dict, listings: dict):
        self.files = files
        self.listings = listings
        self.loaded: list[str] = []

    def file(self, path: str) -> dict:
        entry = self.files.get(path)
        if entry is None:
            raise _Incomplete(('path_unobserved', path))
        if not isinstance(entry, dict) or entry.get('type') not in ('file', 'other', 'absent'):
            raise _Incomplete(('input_invalid', path))
        return entry

    def isfile(self, path: str) -> bool:
        return self.file(path)['type'] == 'file'

    def known(self, name: str) -> bool:
        for directory in LOAD_DIRECTORIES:
            listing = self.listings.get(directory)
            if listing is None:
                raise _Incomplete(('listing_unobserved', directory))
            if name in listing and self.isfile(posixpath.normpath(posixpath.join(directory, name, 'tuned.conf'))):
                return True
        return False

    def locate(self, name: str) -> str | None:
        ret = None
        conditional = name[:1] == '-'
        if conditional:
            name = name[1:]
        for directory in reversed(LOAD_DIRECTORIES):
            path = posixpath.normpath(posixpath.join(directory, posixpath.basename(name), 'tuned.conf'))
            if path in self.loaded:
                ret = ''
                continue
            if self.isfile(path):
                return path
        if conditional and ret is None:
            ret = ''
        return ret

    def parse(self, path: str) -> dict:
        entry = self.file(path)
        text = entry.get('text')
        if entry.get('readable') is False:
            raise _Incomplete(('file_unreadable', path))
        if not isinstance(text, str) or len(text) > MAX_TEXT:
            raise _Incomplete(('input_invalid', path))
        parser = configparser.ConfigParser(delimiters=('=',), inline_comment_prefixes=('#',), strict=False)
        parser.optionxform = str  # type: ignore[assignment,method-assign]
        try:
            parser.read_string(text, path)
        except configparser.Error as exc:
            raise _Abort('profile_parse_error', f'{path}: {type(exc).__name__}') from None
        directory = posixpath.dirname(path)
        config: dict[str, dict] = {}
        for section in parser.sections():
            values: dict[str, Any] = {}
            for option in parser.options(section):
                value = parser.get(section, option, raw=True)
                if '\\' in directory and _PROFILE_DIR.search(value):
                    # TuneD passes the directory to re.sub as a replacement template.
                    raise _Incomplete(('profile_dir_escape_not_modeled', path))
                values[option] = _PROFILE_DIR.sub(lambda _m: directory, value)
            if values.get('script') is not None:
                values['script'] = [posixpath.normpath(posixpath.join(directory, values['script']))]
            config[section] = values
        return config

    def load(self, names: list[str], profiles: list[_Profile], depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            raise _Incomplete(('include_depth_exceeded', ''))
        for name in names:
            path = self.locate(name)
            if path == '':
                continue
            if path is None:
                raise _Abort('profile_not_found', name)
            if len(self.loaded) >= MAX_FILES:
                raise _Incomplete(('input_over_limit', 'files'))
            self.loaded.append(path)
            profile = _Profile(self.parse(path), path)
            if 'include' in profile.options:
                include = profile.options.pop('include')
                if '$' in include:
                    raise _Incomplete(('include_expansion_not_modeled', path))
                self.load(_INCLUDE_SPLIT.split(include), profiles, depth + 1)
            profiles.append(profile)


def _regex_compiles(pattern: Any) -> bool:
    """Whether TuneD's ``re.search`` accepts ``pattern``; ``$`` values are expanded first, so assume yes."""
    if not isinstance(pattern, str) or '$' in pattern:
        return True
    try:
        re.compile(pattern, re.MULTILINE)
    except (re.error, RecursionError, OverflowError):
        return False
    return True


def _expand_static(text: str, defined: dict[str, str], undefined: list[str]) -> str:
    """Textual ``Variables.expand_static``: one pass over defined names, then unescape.

    Function calls are left in place, so the result holds every character a
    function result could contribute; unescaped names not defined here are
    collected because the daemon's variable store outlives a single load.
    """
    undefined.extend(name for name in _VAR_REF.findall(text) if name not in defined)
    text = _VAR_REF.sub(lambda m: defined.get(m.group(1), m.group(0)), text)
    return _VAR_UNESCAPE.sub(r'\1', text)


def _function_calls(text: str) -> tuple[bool, bool]:
    """Return (calls exec, has a function name the contract cannot read literally)."""
    calls_exec = opaque = False
    for match in _FUNC_OPEN.finditer(text):
        name = _FUNC_NAME.match(text, match.end())
        if name is None:
            opaque = True
        elif name.group(0) == 'exec':
            calls_exec = True
    # TuneD pushes a frame at every "${" and re-splits it after inner results are
    # spliced in, so an opening that is neither a plain variable reference nor a
    # literal "f:<name>" call can be completed into any call, exec included.
    for match in _CALL_OPEN.finditer(text):
        if _READABLE_OPEN.match(text, match.end()) is None:
            opaque = True
    return calls_exec, opaque


def _strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return [value] if isinstance(value, str) else []


def _base(family: Any, installed: Any) -> dict:
    return {
        'contract_version': CONTRACT_VERSION, 'reference': REFERENCE, 'runs_as': RUNS_AS, 'daemon': DAEMON,
        'events': EVENTS, 'family': family, 'installed': installed, 'mode': None, 'requested_profiles': [],
        'status': None, 'detail': None, 'loaded_files': [], 'invocations': [], 'function_exec': [],
        'gaps': [], 'complete': False,
    }


def _gap(result: dict, kind: str, path: str = '') -> None:
    if len(result['gaps']) < MAX_GAPS:
        result['gaps'].append({'kind': kind, 'path': path, 'blocking': kind in BLOCKING})


def evaluate(capture: Any, *, default_instance_priority: int = 0) -> dict:
    """Resolve which executables tuned runs as root for the captured profile state.

    ``capture`` keys: ``family`` (``debian``/``rpm``), ``installed`` (bool),
    ``active_profile``/``profile_mode``/``post_loaded_profile``
    (``{'state': 'absent'|'present'|'unreadable', 'text': str}``),
    ``listings`` (``{'/usr/lib/tuned': [names], '/etc/tuned': [names]}``) and
    ``files`` (``{path: {'type': 'file'|'other'|'absent', 'text': str}}``) for
    every ``tuned.conf`` path the resolution asks about.
    """
    if not isinstance(capture, dict):
        result = _base(None, None)
        result['status'] = 'incomplete'
        _gap(result, 'input_invalid')
        return result
    family, installed = capture.get('family'), capture.get('installed')
    result = _base(family, installed)
    if family is None:
        result['status'] = 'incomplete'
        _gap(result, 'family_unobserved')
        return result
    if family not in APPLICABLE_FAMILIES:
        result['status'] = 'not_applicable'
        result['complete'] = True
        return result
    if installed is None:
        result['status'] = 'incomplete'
        _gap(result, 'installation_unobserved')
        return result
    if installed is not True:
        result['status'] = 'not_installed'
        result['complete'] = True
        return result
    files, listings = capture.get('files', {}), capture.get('listings', {})
    if (not isinstance(files, dict) or not isinstance(listings, dict) or len(files) > MAX_FILES
            or any(not isinstance(v, list) or len(v) > MAX_LISTING or not all(isinstance(n, str) for n in v)
                   for v in listings.values())):
        result['status'] = 'incomplete'
        _gap(result, 'input_invalid' if isinstance(files, dict) and isinstance(listings, dict)
             and len(files) <= MAX_FILES else 'input_over_limit')
        return result
    resolver = _Resolver(files, {k: frozenset(v) for k, v in listings.items()})
    try:
        _resolve(capture, resolver, result, default_instance_priority)
    except _Abort as exc:
        result['status'] = 'load_refused'
        result['detail'] = {'reason': exc.reason, 'subject': exc.detail}
        result['invocations'] = []
        result['function_exec'] = []
        result['complete'] = True
    except _Incomplete as exc:
        kind, path = exc.args[0]
        result['status'] = 'incomplete'
        result['invocations'] = []
        _gap(result, kind, path)
    result['loaded_files'] = list(resolver.loaded)
    if any(g['blocking'] for g in result['gaps']):
        result['complete'] = False
    return result


def _resolve(capture: dict, resolver: _Resolver, result: dict, default_priority: int) -> None:
    active = _text_state(capture.get('active_profile'), ACTIVE_PROFILE_FILE)
    mode = _text_state(capture.get('profile_mode'), PROFILE_MODE_FILE)
    if mode not in ('', 'auto', 'manual'):
        raise _Abort('profile_mode_invalid', PROFILE_MODE_FILE)
    post_loaded = _text_state(capture.get('post_loaded_profile'), POST_LOADED_PROFILE_FILE)
    manual = (mode == 'manual') if mode else bool(active)
    result['mode'] = 'manual' if manual else 'auto'
    if not manual:
        raise _Incomplete(('recommended_profile_not_modeled', '/usr/lib/tuned/recommend.d'))
    if post_loaded and len(post_loaded.split()) > 1:
        raise _Abort('post_loaded_profile_invalid', POST_LOADED_PROFILE_FILE)
    names = (active or '').split() + ([post_loaded] if post_loaded else [])
    result['requested_profiles'] = names
    if not names:
        result['status'] = 'no_profile'
        result['complete'] = True
        return
    for name in names:
        if not resolver.known(name):
            raise _Abort('profile_not_found', name)
    names = [name for name in names if _SAFE_NAME.match(name)]
    if not names:
        raise _Abort('profile_name_invalid', '')
    profiles: list[_Profile] = []
    resolver.load(names, profiles)
    final = profiles[0]
    for profile in profiles[1:]:
        final = _merge(final, profile)
    variables = final.units.pop('variables', None)
    if variables is not None:
        for key, value in variables.options.items():
            if key == 'include':
                raise _Incomplete(('variables_file_not_modeled', str(value)))
    defined: dict[str, str] = {}
    undefined: list[str] = []
    opaque: str | None = None
    expanded: list[tuple[str, str]] = []
    for key, value in (variables.options.items() if variables else ()):
        if not _VAR_NAME.match(str(key)) or not isinstance(value, str):
            continue
        defined[key] = _expand_static(value, defined, undefined)
        expanded.append(('variables', defined[key]))
    for unit in final.units.values():
        values = [*unit.options.values(), unit.script_pre, unit.script_post, unit.devices,
                  unit.cpuinfo_regex, unit.uname_regex]
        for value in values:
            for text in _strings(value):
                expanded.append((unit.name, _expand_static(text, defined, undefined)))
    for unit_name, text in expanded:
        calls_exec, unreadable = _function_calls(text)
        if calls_exec:
            result['function_exec'].append({'unit': unit_name, 'value': text[:512]})
        if unreadable and opaque is None:
            opaque = unit_name
    if result['function_exec']:
        raise _Incomplete(('function_exec', result['function_exec'][0]['unit']))
    if opaque is not None:
        raise _Incomplete(('function_expansion_not_modeled', opaque))
    if undefined:
        raise _Incomplete(('variable_undefined', undefined[0]))
    ordered = []
    definite_refusal: tuple[str, str] | None = None
    conditional_refusal: str | None = None
    for unit in final.units.values():
        if not unit.enabled:
            continue
        host_dependent = False
        failure = None
        for attr in ('cpuinfo_regex', 'uname_regex'):
            pattern = getattr(unit, attr)
            if pattern is None:
                continue
            if not _regex_compiles(pattern):
                failure = 'regex_invalid'
                break
            host_dependent = True
        raw = unit.options.get('priority', default_priority)
        priority = 0
        if failure is None:
            try:
                priority = int(raw)
            except (TypeError, ValueError):
                failure = 'priority_invalid'
        if failure is not None:
            if host_dependent:
                conditional_refusal = conditional_refusal or unit.name
            elif definite_refusal is None:
                definite_refusal = (failure, unit.name)
            continue
        ordered.append((priority, unit))
    if definite_refusal is not None:
        raise _Abort(*definite_refusal)
    if conditional_refusal is not None:
        raise _Incomplete(('apply_refusal_conditional', conditional_refusal))
    ordered.sort(key=lambda item: item[0])
    invocations = []
    for priority, unit in ordered:
        conditions = []
        if unit.cpuinfo_regex is not None:
            conditions.append('cpuinfo_regex matches /proc/cpuinfo')
        if unit.uname_regex is not None:
            conditions.append('uname_regex matches the kernel identity')
        def device_script(phase: str, path: str) -> None:
            invocations.append({
                'unit': unit.name, 'type': unit.type, 'kind': phase, 'path': path, 'priority': priority,
                'runs': path.startswith('/'), 'cwd': posixpath.dirname(path),
                'arguments': DEVICE_SCRIPT_ARGUMENTS,
                'conditions': conditions + [f'the {unit.type} plugin is supported and assigns at least one device'],
                'reason': None if path.startswith('/') else 'relative_path_never_runs',
            })
        if unit.script_pre is not None:
            device_script('script_pre', unit.script_pre)
        if unit.type == 'script':
            for path in unit.options.get('script') or []:
                invocations.append({
                    'unit': unit.name, 'type': unit.type, 'kind': 'script', 'path': path, 'priority': priority,
                    'runs': True, 'cwd': posixpath.dirname(path), 'arguments': SCRIPT_ARGUMENTS,
                    'conditions': list(conditions), 'reason': None,
                })
        if unit.script_post is not None:
            device_script('script_post', unit.script_post)
    result['invocations'] = invocations
    result['status'] = 'resolved'
    result['complete'] = True
