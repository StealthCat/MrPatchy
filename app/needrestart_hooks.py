"""Pure needrestart hook contract (roadmap F slice, #1148).

Ubuntu installs ``needrestart`` by default. ``/etc/apt/apt.conf.d/99needrestart``
adds a ``DPkg::Post-Invoke`` command that runs ``/usr/lib/needrestart/apt-pinvoke
-m u`` as root after every APT package transaction. When dpkg unpacked something
and did not fail, ``apt-pinvoke`` execs ``/usr/sbin/needrestart -m u``.

This module takes captured, read-only observations and says which root code that
run can execute. The rules are pinned to the Ubuntu ``needrestart
3.6-7ubuntu4.x`` source (``usr/sbin/needrestart``, ``NeedRestart/Utils.pm``, the
shipped ``needrestart.conf``, ``notify.d/README.needrestart`` and
``apt-pinvoke``):

* ``/etc/needrestart/needrestart.conf`` is read whole and passed to Perl
  ``eval``. The shipped file ends with a loop that ``eval``s every
  ``sort </etc/needrestart/conf.d/*.conf>`` when that directory exists. The
  glob skips dot-hidden names and matches any file kind. ``sort`` compares the
  path bytes. These files are arbitrary root Perl code and need no execute bit.
  A directory matched by the glob reads as nothing and is a no-op.
* ``hook.d``: for each candidate process, every ``nsort <hook_d/*>`` entry is
  passed to ``exec`` with no execute-bit check, so a non-executable entry fails
  silently. The loop stops at the first hook that identifies the service.
* ``restart.d``: ``<restart_d>/<service>`` is run instead of ``systemctl
  restart`` when ``-x`` is true for it. Under ``-m u`` (APT) with neither
  ``restart`` nor ``ui`` configured, the restart mode is automatic.
* ``notify.d``: for each user session with outdated binaries, while
  ``sendnotify`` is true, every ``nsort <notify_d/*>`` entry that is ``-x``
  and whose path does not end in ``~`` or ``.dpkg-<suffix>`` runs, as root,
  until one exits 0. ``-x`` is also true for a searchable directory, and its
  ``exec`` then fails.

``nsort`` is Sort::Naturally. This contract does not reimplement it. It reports
an order only when a simple natural order and the byte order agree for names
made of ``[a-z0-9._-]``. Any other set is listed with an ``order_unresolved``
gap.

Perl is never evaluated. ``needrestart.conf`` is understood only when its
SHA-256 matches the shipped file. A ``conf.d`` file is understood only when every
statement is a comment or ``$nrconf{key} = <number or quoted literal>;``.
Anything else, or any assignment to ``hook_d``, ``notify_d`` or ``restart_d``,
is a gap: Perl code can change the directories, the modes and the conf.d loop
itself. Every input that is unknown, malformed or over a cap becomes an explicit
coverage gap and never yields a covered result.

It performs no I/O, never runs a command and never authorizes a response action.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
MAX_ENTRIES = 1024
MAX_NAME = 255
MAX_TEXT = 1 << 20
MAX_GAPS = 256

CONF = '/etc/needrestart/needrestart.conf'
CONF_D = '/etc/needrestart/conf.d'
HOOK_D = '/etc/needrestart/hook.d'
NOTIFY_D = '/etc/needrestart/notify.d'
RESTART_D = '/etc/needrestart/restart.d'
APT_CONF = '/etc/apt/apt.conf.d/99needrestart'
APT_PINVOKE = '/usr/lib/needrestart/apt-pinvoke'

# SHA-256 of the files shipped by needrestart 3.6-7ubuntu4.6 (Ubuntu 24.04).
SHIPPED_SHA256 = {
    CONF: 'baacdd683222532d35770efbf7cd83360fc33a4c49ef010787628f0da778f7ee',
    APT_CONF: 'd453d945957bf2fb33a26cb74eacd38244291919715a1bb1d6179d0290c95c52',
    APT_PINVOKE: 'ee34cc66a524a871515f2aaf23e558f1f29382c499fd3918136f2371820df0ca',
}
SUPPORTED_VERSION = re.compile(r'3\.6-7ubuntu4(?:\.[0-9]+)*')

FILE_STATES = ('present', 'absent', 'unknown')
DIR_STATES = ('listed', 'absent', 'unknown')
KINDS = ('regular', 'directory', 'other', 'unknown')
DIRECTORY_KEYS = ('hook_d', 'notify_d', 'restart_d')
TRACKED_KEYS = ('restart', 'ui', 'sendnotify')

_SHA256 = re.compile(r'[0-9a-f]{64}')
_NAME = re.compile(r'[^/\x00]{1,255}')
_SIMPLE_NAME = re.compile(r'[a-z0-9._-]+')
_NOTIFY_SKIP = re.compile(r'(~|\.dpkg-[^.]+)\Z')
_COMMENT = re.compile(r'\s*(#.*)?')
_ASSIGN = re.compile(
    r"\s*\$nrconf\{\s*(?:'(?P<q1>\w+)'|\"(?P<q2>\w+)\"|(?P<bare>\w+))\s*\}\s*=\s*"
    r"(?P<value>-?[0-9]+|'[^'\\\n]*'|\"[^\"\\$@\n]*\"|q\([^()\\\n]*\))\s*;\s*(#.*)?"
)


class Invalid(ValueError):
    """An observation that cannot be interpreted safely."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps[-1] = {'code': 'gaps_truncated'}


def _file(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Invalid(f'{name} must be an object')
    state = value.get('state')
    if state not in FILE_STATES:
        raise Invalid(f'{name}.state is invalid')
    digest = value.get('sha256')
    if digest is not None and (not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
        raise Invalid(f'{name}.sha256 is invalid')
    text = value.get('text')
    if text is not None and (not isinstance(text, str) or len(text) > MAX_TEXT):
        raise Invalid(f'{name}.text is invalid')
    return {'state': state, 'sha256': digest if state == 'present' else None,
            'text': text if state == 'present' else None}


def _directory(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Invalid(f'{name} must be an object')
    state = value.get('state')
    if state not in DIR_STATES:
        raise Invalid(f'{name}.state is invalid')
    raw = value.get('entries', [])
    if state != 'listed':
        return {'state': state, 'entries': [], 'complete': False}
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
        raise Invalid(f'{name}.entries is invalid')
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise Invalid(f'{name} entry must be an object')
        entry_name = item.get('name')
        if not isinstance(entry_name, str) or not _NAME.fullmatch(entry_name) or entry_name in ('.', '..'):
            raise Invalid(f'{name} entry name is invalid')
        if entry_name in seen:
            raise Invalid(f'{name} entry {entry_name!r} is duplicated')
        seen.add(entry_name)
        kind = item.get('kind', 'unknown')
        if kind not in KINDS:
            raise Invalid(f'{name} entry kind is invalid')
        executable = item.get('executable')
        if executable is not None and not isinstance(executable, bool):
            raise Invalid(f'{name} entry executable is invalid')
        text = item.get('text')
        if text is not None and (not isinstance(text, str) or len(text) > MAX_TEXT):
            raise Invalid(f'{name} entry text is invalid')
        entries.append({'name': entry_name, 'kind': kind, 'executable': executable, 'text': text})
    complete = value.get('complete', True)
    if not isinstance(complete, bool):
        raise Invalid(f'{name}.complete is invalid')
    return {'state': state, 'entries': entries, 'complete': complete}


def _literal(value: str) -> Any:
    if value[0] in '\'"':
        return value[1:-1]
    if value.startswith('q('):
        return value[2:-1]
    return int(value)


def _parse_simple(text: str) -> list[tuple[str, Any]] | None:
    """Return the assignments of a simple conf.d file, or None for other Perl."""
    assignments: list[tuple[str, Any]] = []
    for line in text.splitlines():
        if _COMMENT.fullmatch(line):
            continue
        match = _ASSIGN.fullmatch(line)
        if not match:
            return None
        key = match.group('q1') or match.group('q2') or match.group('bare')
        assignments.append((key, _literal(match.group('value'))))
    return assignments


def _byte_key(name: str) -> bytes:
    return name.encode('utf-8', 'surrogateescape')


def _natural_key(name: str) -> tuple:
    return tuple((0, int(part), len(part)) if part.isdigit() else (1, part)
                 for part in re.findall(r'[0-9]+|[^0-9]+', name))


def _natural_order(names: list[str]) -> tuple[list[str], bool]:
    by_bytes = sorted(names, key=_byte_key)
    if not all(_SIMPLE_NAME.fullmatch(name) for name in names):
        return by_bytes, False
    natural = sorted(names, key=_natural_key)
    return natural, natural == by_bytes


def _glob(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Perl's csh glob of "<dir>/*" never matches dot-hidden names.
    return [entry for entry in entries if not entry['name'].startswith('.')]


def _hook_programs(directory: dict[str, Any], base: str, kind: str,
                   gaps: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {'path': base, 'state': directory['state'], 'order_exact': False, 'programs': []}
    if directory['state'] == 'unknown':
        _gap(gaps, 'directory_unknown', path=base)
        return result
    if directory['state'] == 'absent':
        result['order_exact'] = True
        return result
    if not directory['complete']:
        _gap(gaps, 'directory_incomplete', path=base)
    entries = directory['entries'] if kind == 'restart' else _glob(directory['entries'])
    programs: list[dict[str, Any]] = []
    for entry in sorted(entries, key=lambda e: _byte_key(e['name'])):
        path = f"{base}/{entry['name']}"
        if kind == 'notify' and _NOTIFY_SKIP.search(path):
            runs, reason = False, 'skipped_backup_or_dpkg_name'
        elif entry['kind'] == 'other':
            runs, reason = None, 'special_file'
            _gap(gaps, 'entry_special_file', path=path)
        elif entry['kind'] == 'unknown' or (entry['kind'] == 'regular' and entry['executable'] is None):
            runs, reason = None, 'unknown'
            _gap(gaps, 'entry_unknown', path=path)
        elif entry['kind'] == 'directory':
            runs, reason = False, 'directory_exec_fails'
        elif not entry['executable']:
            runs = False
            reason = 'not_executable_exec_fails' if kind == 'hook' else 'not_executable_skipped'
        else:
            runs, reason = True, 'executable'
        program = {'name': entry['name'], 'path': path, 'runs': runs, 'reason': reason}
        if kind == 'restart':
            # restart.d is not globbed: needrestart tests "<restart_d>/<service>".
            program['replaces_restart_of'] = entry['name']
        programs.append(program)
    exact = True
    if kind != 'restart':
        # Only entries that can run take part in the nsort order that matters.
        candidates = [p['name'] for p in programs if p['runs'] is not False]
        ordered, exact = _natural_order(candidates)
        if not exact:
            _gap(gaps, 'order_unresolved', path=base)
        position = {name: index for index, name in enumerate(ordered, 1)}
        for program in programs:
            program['order'] = position.get(program['name']) if exact else None
        programs.sort(key=lambda p: (p['order'] is None, p['order'] or 0, _byte_key(p['name'])))
    result['order_exact'] = exact
    result['programs'] = programs
    return result


def resolve(observation: Any) -> dict[str, Any]:
    """Resolve the root code a needrestart run after APT can execute."""
    if not isinstance(observation, dict):
        raise Invalid('observation must be an object')
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION,
        'mechanism': 'needrestart',
        'origin': 'not_assessed',
        'applicable': False,
        'covered': False,
        'runs_as': 'root',
        'trigger': None,
        'perl_config': [],
        'restart_mode_under_apt': None,
        'sendnotify': None,
        'hook_d': None,
        'restart_d': None,
        'notify_d': None,
        'gaps': gaps,
        'unobserved': [
            'manual needrestart runs and their -c, -r and -m options',
            'NEEDRESTART_MODE, NEEDRESTART_UI and NEEDRESTART_SUSPEND in the APT environment',
            'which processes use outdated binaries, so whether hooks actually run',
            'Perl syntax or runtime errors that abort needrestart before its hooks',
            'what the evaluated Perl and the hook programs do',
        ],
    }
    family = observation.get('family')
    if family not in ('debian', 'rpm', 'unknown'):
        raise Invalid('family is invalid')
    package = observation.get('package')
    if not isinstance(package, dict) or package.get('state') not in ('installed', 'absent', 'unknown'):
        raise Invalid('package is invalid')
    version = package.get('version')
    if family != 'debian':
        _gap(gaps, 'unsupported_family', family=family)
        return result
    if package['state'] == 'absent':
        result['applicable'] = False
        result['covered'] = True
        return result
    if package['state'] == 'unknown':
        _gap(gaps, 'package_unknown')
        return result
    if not isinstance(version, str) or not SUPPORTED_VERSION.fullmatch(version):
        _gap(gaps, 'unsupported_version', version=version if isinstance(version, str) else None)
        return result
    result['applicable'] = True

    apt_conf = _file(observation.get('apt_conf'), 'apt_conf')
    pinvoke = _file(observation.get('apt_pinvoke'), 'apt_pinvoke')
    conf = _file(observation.get('config'), 'config')
    conf_d = _directory(observation.get('conf_d'), 'conf_d')
    hook_d = _directory(observation.get('hook_d'), 'hook_d')
    notify_d = _directory(observation.get('notify_d'), 'notify_d')
    restart_d = _directory(observation.get('restart_d'), 'restart_d')

    trigger = {'apt_post_invoke': None, 'apt_conf': apt_conf['state'], 'apt_pinvoke': pinvoke['state']}
    if apt_conf['state'] == 'absent' or pinvoke['state'] == 'absent':
        trigger['apt_post_invoke'] = False
    elif apt_conf['state'] == 'unknown' or pinvoke['state'] == 'unknown':
        _gap(gaps, 'trigger_unknown')
    elif (apt_conf['sha256'] != SHIPPED_SHA256[APT_CONF]
          or pinvoke['sha256'] != SHIPPED_SHA256[APT_PINVOKE]):
        _gap(gaps, 'trigger_modified')
    else:
        trigger['apt_post_invoke'] = True
    result['trigger'] = trigger

    settings: dict[str, Any] = {}
    directories_known = True
    loop_known = False
    if conf['state'] == 'present':
        result['perl_config'].append({'path': CONF, 'order': 1, 'evaluated': True, 'understood': None})
        if conf['sha256'] == SHIPPED_SHA256[CONF]:
            result['perl_config'][0]['understood'] = True
            loop_known = True
        else:
            result['perl_config'][0]['understood'] = False
            _gap(gaps, 'config_modified', path=CONF)
            directories_known = False
    elif conf['state'] == 'absent':
        # needrestart dies ("Could not read config file") before any hook runs.
        result['trigger']['needrestart_aborts'] = 'config_missing'
        result['covered'] = not gaps
        return result
    else:
        _gap(gaps, 'config_unknown', path=CONF)
        directories_known = False

    # Even when the main file is modified, report the conf.d files the shipped
    # loop would evaluate; whether they run is then unresolved.
    if conf_d['state'] == 'unknown':
        _gap(gaps, 'directory_unknown', path=CONF_D)
    elif conf_d['state'] == 'listed':
        if not conf_d['complete']:
            _gap(gaps, 'directory_incomplete', path=CONF_D)
        matched = [e for e in _glob(conf_d['entries']) if e['name'].endswith('.conf')]
        for entry in sorted(matched, key=lambda e: _byte_key(e['name'])):
            path = f'{CONF_D}/{entry["name"]}'
            record: dict[str, Any] = {'path': path, 'order': len(result['perl_config']) + 1,
                                      'evaluated': True if loop_known else None, 'understood': None}
            result['perl_config'].append(record)
            if entry['kind'] == 'directory':
                record.update(evaluated=False, understood=True, reason='directory_reads_nothing')
                continue
            if entry['kind'] != 'regular' or entry['text'] is None:
                _gap(gaps, 'config_unread', path=path)
                directories_known = False
                continue
            assignments = _parse_simple(entry['text'])
            if assignments is None:
                record['understood'] = False
                _gap(gaps, 'config_unrecognized_code', path=path)
                directories_known = False
                continue
            record['understood'] = True
            for key, value in assignments:
                if key in DIRECTORY_KEYS:
                    _gap(gaps, 'directory_overridden', path=path, key=key)
                    directories_known = False
                settings[key] = value

    if directories_known:
        if hook_d['state'] == 'absent':
            # needrestart dies when hook_d is not a directory, before any hook.
            result['trigger']['needrestart_aborts'] = 'hook_directory_missing'
            result['covered'] = not gaps
            return result
        mode = str(settings['restart']) if 'restart' in settings else None
        if mode is None:
            result['restart_mode_under_apt'] = 'interactive' if 'ui' in settings else 'automatic'
        elif mode in ('a', 'i', 'l'):
            result['restart_mode_under_apt'] = {'a': 'automatic', 'i': 'interactive', 'l': 'list_only'}[mode]
        else:
            _gap(gaps, 'restart_mode_invalid', value=mode)
        sendnotify = settings.get('sendnotify', 1)
        result['sendnotify'] = sendnotify not in (0, '', '0')
        result['hook_d'] = _hook_programs(hook_d, HOOK_D, 'hook', gaps)
        result['restart_d'] = _hook_programs(restart_d, RESTART_D, 'restart', gaps)
        result['notify_d'] = _hook_programs(notify_d, NOTIFY_D, 'notify', gaps)
    result['covered'] = not gaps
    return result
