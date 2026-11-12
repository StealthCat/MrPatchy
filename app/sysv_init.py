"""Pure SysV init script, runlevel link and rc.local parsing contract (roadmap F slice, #717).

Turns captured, read-only text of ``/etc/init.d`` scripts, a captured listing of
``/etc/rcN.d`` entries and the text of ``/etc/rc.local`` into typed, bounded
records. It performs no I/O, never runs a script, ``update-rc.d``,
``chkconfig`` or ``service``, never sources a script and never authorizes a
response action.

Fail-closed rules:

- Over-limit text, invalid UTF-8, NUL bytes and input the documented layouts do
  not allow become explicit gaps. Over-cap input yields no partial records.
- Init script bodies are never returned. Records carry the LSB header fields
  needed to understand when a service starts plus the full-text SHA-256.
- ``rc.local`` command lines are returned bounded with a SHA-256 of each full
  logical line; environment values are not interpreted.
- No record is labelled a package default or "safe". ``origin`` is always
  ``not_assessed``; provenance needs separate authenticated package evidence.
- Disagreement between LSB ``Default-Start`` and installed links, links without
  a captured script and start/stop links for one service in one runlevel are
  reported as observations, never as verdicts.

LSB headers follow the Linux Standard Base "Init Script Comment Conventions":
one ``### BEGIN INIT INFO`` ... ``### END INIT INFO`` block of ``# Keyword:
value`` lines, with ``Description`` continuation lines starting ``#`` followed
by a tab or at least two spaces. Runlevel links follow ``[SK]NNname`` in
``/etc/rc[0-6S].d`` (Debian) or ``/etc/rc.d/rc[0-6].d`` (RPM layouts).
"""
from __future__ import annotations

import hashlib
import posixpath
import re
from collections.abc import Iterable
from typing import Any

CONTRACT_VERSION = 1
MAX_TEXT = 262144
MAX_LINES = 8192
MAX_LINKS = 2048
MAX_SCRIPTS = 1024
MAX_COMMANDS = 512
MAX_COMMAND = 4096
MAX_FIELD = 512
MAX_GAPS = 64

RUNLEVELS = ('S', '0', '1', '2', '3', '4', '5', '6')
INIT_DIRS = ('/etc/init.d', '/etc/rc.d/init.d')
LIST_FIELDS = ('Provides', 'Required-Start', 'Required-Stop', 'Should-Start', 'Should-Stop',
               'X-Start-Before', 'X-Stop-After')
RUNLEVEL_FIELDS = ('Default-Start', 'Default-Stop')
TEXT_FIELDS = ('Short-Description', 'Description')
KNOWN_FIELDS = LIST_FIELDS + RUNLEVEL_FIELDS + TEXT_FIELDS
# Non-script files distributions ship in init and runlevel directories.
IGNORED_NAMES = frozenset({'README', '.depend.boot', '.depend.start', '.depend.stop', '.legacy-bootordering'})

_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._+@-]{0,127}')
_RC_DIR = re.compile(r'/etc/(?:rc\.d/)?rc([0-6S])\.d')
_LINK = re.compile(r'([SK])([0-9]{2})(.+)')
_FIELD = re.compile(r'#\s?([A-Za-z][A-Za-z0-9-]{0,63}):(.*)')
_CONTINUATION = re.compile(r'#(?:\t| {2,})(.*)')
_EXIT = re.compile(r'exit(?:\s+[0-9]+)?\s*(?:;\s*)?(?:#.*)?')


def _gap(gaps: list[dict[str, Any]], code: str, line: int | None = None, detail: str = '') -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'line': line, 'detail': detail[:200]})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'line': None, 'detail': 'Further gaps were not recorded.'})


def _decode(text: str | bytes, gaps: list[dict[str, Any]]) -> str | None:
    if isinstance(text, bytes):
        if len(text) > MAX_TEXT:
            _gap(gaps, 'over_limit', None, f'More than {MAX_TEXT} bytes.')
            return None
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            _gap(gaps, 'invalid_utf8', None, 'Text is not valid UTF-8.')
            return None
    if not isinstance(text, str):
        _gap(gaps, 'unreadable', None, 'No text was captured.')
        return None
    if len(text.encode('utf-8')) > MAX_TEXT:
        _gap(gaps, 'over_limit', None, f'More than {MAX_TEXT} bytes.')
        return None
    if '\x00' in text:
        _gap(gaps, 'binary', None, 'Text contains NUL bytes.')
        return None
    return text


def _lines(text: str | bytes, gaps: list[dict[str, Any]]) -> tuple[str | None, list[str] | None]:
    decoded = _decode(text, gaps)
    if decoded is None:
        return None, None
    lines = decoded.split('\n')
    if len(lines) > MAX_LINES:
        _gap(gaps, 'over_limit', None, f'More than {MAX_LINES} lines.')
        return None, None
    return decoded, lines


def _executable(mode: int | None) -> bool | None:
    return None if mode is None else bool(int(mode) & 0o111)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _runlevels(value: str) -> tuple[list[str], list[str]]:
    levels: list[str] = []
    invalid: list[str] = []
    for token in value.split():
        token = 'S' if token == 's' else token
        if token in RUNLEVELS:
            if token not in levels:
                levels.append(token)
        else:
            invalid.append(token[:16])
    return sorted(levels, key=RUNLEVELS.index), invalid


def _lsb(lines: list[str], gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    begins = [i for i, line in enumerate(lines) if line.strip() == '### BEGIN INIT INFO']
    if not begins:
        _gap(gaps, 'missing_lsb_header', None, 'No "### BEGIN INIT INFO" block.')
        return None
    if len(begins) > 1:
        _gap(gaps, 'duplicate_lsb_header', begins[1] + 1, 'More than one LSB block; only the first was read.')
    start = begins[0]
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() == '### END INIT INFO'), None)
    if end is None:
        _gap(gaps, 'unterminated_lsb_header', start + 1, 'The LSB block has no "### END INIT INFO".')
        return None
    fields: dict[str, Any] = {}
    extensions: list[str] = []
    last: str | None = None
    for index in range(start + 1, end):
        line = lines[index].rstrip('\r')
        number = index + 1
        match = _FIELD.fullmatch(line)
        continuation = _CONTINUATION.fullmatch(line)
        if continuation and last == 'Description' and not (match and match.group(1) in KNOWN_FIELDS):
            fields['Description'] = (fields['Description'] + ' ' + continuation.group(1).strip()).strip()[:MAX_FIELD]
            continue
        if not match:
            if line.strip() not in ('', '#'):
                _gap(gaps, 'malformed_lsb_line', number, 'Expected "# Keyword: value".')
            last = None
            continue
        key, value = match.group(1), match.group(2).strip()
        last = key
        if key not in KNOWN_FIELDS:
            if key.startswith('X-'):
                if key not in extensions and len(extensions) < 32:
                    extensions.append(key)
            else:
                _gap(gaps, 'unknown_lsb_field', number, f'{key[:64]} is not an LSB keyword.')
            continue
        if key in fields:
            _gap(gaps, 'duplicate_lsb_field', number, f'{key} repeated; the first value was kept.')
            continue
        if key in RUNLEVEL_FIELDS:
            levels, invalid = _runlevels(value)
            if invalid:
                _gap(gaps, 'invalid_runlevel', number, f'{key} lists unsupported runlevels: {", ".join(invalid)}.')
            fields[key] = levels
        elif key in LIST_FIELDS:
            fields[key] = [token[:128] for token in value.split()][:64]
        else:
            fields[key] = value[:MAX_FIELD]
    if 'Provides' not in fields:
        _gap(gaps, 'missing_provides', start + 1, 'The LSB block has no Provides keyword.')
    overlap = sorted(set(fields.get('Default-Start', [])) & set(fields.get('Default-Stop', [])), key=RUNLEVELS.index)
    if overlap:
        _gap(gaps, 'start_stop_overlap', None, f'Default-Start and Default-Stop both list {", ".join(overlap)}.')
    return {
        'provides': fields.get('Provides', []), 'required_start': fields.get('Required-Start', []),
        'required_stop': fields.get('Required-Stop', []), 'should_start': fields.get('Should-Start', []),
        'should_stop': fields.get('Should-Stop', []), 'start_before': fields.get('X-Start-Before', []),
        'stop_after': fields.get('X-Stop-After', []), 'default_start': fields.get('Default-Start'),
        'default_stop': fields.get('Default-Stop'), 'short_description': fields.get('Short-Description'),
        'description': fields.get('Description'), 'extension_fields': extensions,
        'block_lines': [start + 1, end + 1],
    }


def parse_init_script(name: str, text: str | bytes, mode: int | None = None) -> dict[str, Any]:
    """Parse one ``/etc/init.d`` script's interpreter and LSB header."""
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'format': 'init_script', 'state': 'parsed',
                              'name': str(name)[:128], 'interpreter': None, 'executable': _executable(mode),
                              'sha256': None, 'size': None, 'lsb': None, 'origin': 'not_assessed', 'gaps': gaps}
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        _gap(gaps, 'invalid_name', None, 'Script name is not a plain init script file name.')
        result['state'] = 'unavailable'
        return result
    decoded, lines = _lines(text, gaps)
    if lines is None:
        result['state'] = 'unavailable'
        return result
    result['sha256'] = _sha(decoded)
    result['size'] = len(decoded.encode('utf-8'))
    if lines[0].startswith('#!'):
        result['interpreter'] = lines[0][2:].strip()[:256] or None
    if result['interpreter'] is None:
        _gap(gaps, 'missing_shebang', 1, 'No "#!" interpreter line; the script cannot be executed directly.')
    if result['executable'] is False:
        _gap(gaps, 'not_executable', None, 'The captured mode has no execute bit; init and runlevel links will not run it.')
    result['lsb'] = _lsb(lines, gaps)
    if gaps:
        result['state'] = 'partial'
    return result


def _link_target(directory: str, target: str) -> tuple[str, str | None]:
    resolved = posixpath.normpath(target if target.startswith('/') else posixpath.join(directory, target))
    parent, base = posixpath.split(resolved)
    return resolved, base if parent in INIT_DIRS else None


def parse_rc_links(entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Parse captured runlevel directory entries.

    Each entry is ``{'dir': '/etc/rc2.d', 'name': 'S01ssh', 'target': '../init.d/ssh'}``;
    ``target`` is ``None`` for a regular file rather than a symbolic link.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'format': 'rc_links', 'state': 'parsed',
                              'links': [], 'gaps': gaps}
    entries = list(entries) if entries is not None else []
    if len(entries) > MAX_LINKS:
        _gap(gaps, 'over_limit', None, f'More than {MAX_LINKS} runlevel entries.')
        result['state'] = 'unavailable'
        return result
    for entry in entries:
        directory = str(entry.get('dir') or '').rstrip('/')
        name = str(entry.get('name') or '')
        target = entry.get('target')
        place = f'{directory}/{name}'[:200]
        level = _RC_DIR.fullmatch(directory)
        if not level:
            _gap(gaps, 'unrecognized_directory', None, f'{directory[:120]} is not a runlevel directory.')
            continue
        if name in IGNORED_NAMES:
            continue
        match = _LINK.fullmatch(name)
        if not match or not _NAME.fullmatch(match.group(3)):
            _gap(gaps, 'unrecognized_link_name', None, f'{place} does not follow [SK]NNname.')
            continue
        link = {'runlevel': level.group(1), 'action': 'start' if match.group(1) == 'S' else 'stop',
                'order': int(match.group(2)), 'name': name, 'link_service': match.group(3), 'path': place,
                'symlink': target is not None, 'target': None, 'service': None, 'origin': 'not_assessed'}
        if target is None:
            _gap(gaps, 'not_symlink', None, f'{place} is a regular file, not a link to an init script.')
        else:
            if not isinstance(target, str) or not target or '\x00' in target or len(target) > 4096:
                _gap(gaps, 'invalid_target', None, f'{place} has an unreadable link target.')
                continue
            resolved, service = _link_target(directory, target)
            link['target'] = resolved
            link['service'] = service
            if service is None:
                _gap(gaps, 'target_outside_init_dir', None, f'{place} points outside the init script directory.')
            elif service != link['link_service']:
                _gap(gaps, 'name_target_mismatch', None, f'{place} name differs from its target script {service[:64]}.')
        result['links'].append(link)
    result['links'].sort(key=lambda r: (RUNLEVELS.index(r['runlevel']), r['action'] == 'start', r['order'], r['name']))
    if gaps:
        result['state'] = 'partial'
    return result


def effective_services(scripts: Iterable[dict[str, Any]], links: dict[str, Any]) -> dict[str, Any]:
    """Combine parsed scripts and runlevel links into per-service enablement observations."""
    gaps: list[dict[str, Any]] = []
    scripts = list(scripts) if scripts is not None else []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'format': 'sysv_services', 'state': 'parsed',
                              'services': [], 'orphan_links': [], 'gaps': gaps}
    if len(scripts) > MAX_SCRIPTS:
        _gap(gaps, 'over_limit', None, f'More than {MAX_SCRIPTS} init scripts.')
        result['state'] = 'unavailable'
        return result
    if links.get('state') == 'unavailable':
        _gap(gaps, 'links_unavailable', None, 'Runlevel links were not captured; enablement is unknown.')
    by_name = {s['name']: s for s in scripts if s.get('state') != 'unavailable'}
    for script in scripts:
        if script['name'] not in by_name:
            _gap(gaps, 'script_unavailable', None, f'{script["name"][:64]} could not be parsed.')
    grouped: dict[str, list[dict[str, Any]]] = {}
    for link in links.get('links', []):
        service = link.get('service')
        if service is None or service not in by_name:
            result['orphan_links'].append({'path': link['path'], 'target': link['target'], 'service': service})
            continue
        grouped.setdefault(service, []).append(link)
    if result['orphan_links']:
        _gap(gaps, 'orphan_links', None, f'{len(result["orphan_links"])} runlevel links name no captured init script.')
    for name in sorted(by_name):
        script = by_name[name]
        own = grouped.get(name, [])
        start = sorted({l['runlevel'] for l in own if l['action'] == 'start'}, key=RUNLEVELS.index)
        stop = sorted({l['runlevel'] for l in own if l['action'] == 'stop'}, key=RUNLEVELS.index)
        conflicts = sorted(set(start) & set(stop), key=RUNLEVELS.index)
        lsb = script.get('lsb') or {}
        default_start = lsb.get('default_start')
        observations: list[str] = []
        if conflicts:
            observations.append('start_and_stop_links_in_same_runlevel')
        if links.get('state') != 'unavailable' and default_start is not None and set(default_start) != set(start):
            observations.append('links_differ_from_lsb_default_start')
        if script.get('executable') is False and start:
            observations.append('start_links_to_non_executable_script')
        result['services'].append({
            'name': name, 'sha256': script.get('sha256'),
            'enabled': None if links.get('state') == 'unavailable' else bool(start),
            'start_runlevels': start, 'stop_runlevels': stop, 'conflicting_runlevels': conflicts,
            'start_orders': {l['runlevel']: l['order'] for l in own if l['action'] == 'start'},
            'lsb_default_start': default_start, 'lsb_default_stop': lsb.get('default_stop'),
            'observations': observations, 'origin': 'not_assessed',
        })
    if gaps or links.get('gaps'):
        result['state'] = 'partial'
    return result


def parse_rc_local(text: str | bytes, mode: int | None = None) -> dict[str, Any]:
    """Parse ``/etc/rc.local`` into bounded logical command lines."""
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'format': 'rc_local', 'state': 'parsed',
                              'interpreter': None, 'executable': _executable(mode), 'sha256': None,
                              'commands': [], 'unreachable_commands': 0, 'exit_line': None,
                              'origin': 'not_assessed', 'gaps': gaps}
    decoded, lines = _lines(text, gaps)
    if lines is None:
        result['state'] = 'unavailable'
        return result
    result['sha256'] = _sha(decoded)
    if lines[0].startswith('#!'):
        result['interpreter'] = lines[0][2:].strip()[:256] or None
    if result['interpreter'] is None:
        _gap(gaps, 'missing_shebang', 1, 'No "#!" interpreter line; boot-time execution may fail.')
    if result['executable'] is False:
        _gap(gaps, 'not_executable', None, 'The captured mode has no execute bit; systemd\'s rc-local '
             'compatibility unit and SysV rc only run an executable /etc/rc.local.')
    commands: list[dict[str, Any]] = []
    pending: list[str] = []
    pending_line = 0
    complex_seen = False
    indented = False
    for index, raw in enumerate(lines[1:] if result['interpreter'] else lines, 2 if result['interpreter'] else 1):
        line = raw.rstrip('\r')
        if not pending:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            pending_line = index
            indented = line[:1] in (' ', '\t')
        if line.endswith('\\'):
            pending.append(line[:-1])
            continue
        pending.append(line)
        logical = '\n'.join(pending).strip()
        pending = []
        if result['exit_line'] is not None:
            result['unreachable_commands'] += 1
            continue
        if not indented and _EXIT.fullmatch(logical):
            result['exit_line'] = pending_line
            continue
        if '<<' in logical and not complex_seen:
            complex_seen = True
            _gap(gaps, 'heredoc_not_interpreted', pending_line, 'Heredoc bodies are reported as separate lines.')
        if len(commands) >= MAX_COMMANDS:
            _gap(gaps, 'over_limit', pending_line, f'More than {MAX_COMMANDS} commands.')
            result.update(state='unavailable', commands=[], unreachable_commands=0, exit_line=None)
            return result
        commands.append({'line': pending_line, 'command': logical[:MAX_COMMAND],
                         'command_truncated': len(logical) > MAX_COMMAND, 'command_sha256': _sha(logical),
                         'background': logical.rstrip().endswith('&') and not logical.rstrip().endswith('&&')})
    if pending:
        _gap(gaps, 'unterminated_continuation', pending_line, 'The file ends inside a "\\" line continuation.')
    if result['unreachable_commands']:
        _gap(gaps, 'unreachable_after_exit', result['exit_line'],
             f'{result["unreachable_commands"]} command line(s) follow the top-level exit and never run.')
    result['commands'] = commands
    if gaps:
        result['state'] = 'partial'
    return result
