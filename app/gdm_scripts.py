"""Pure GDM display-manager script contract (roadmap F slice, #1405).

Takes captured, read-only observations of GDM's script directories and says
which ``Init``, ``PostLogin``, ``PreSession`` and ``PostSession`` script gdm
runs as root, for which display or remote host, and whether its failure blocks
the login.

Semantics follow GDM 46.2 ``common/gdm-common.c`` ``gdm_run_script()`` with
glib 2.80:

* For a phase directory ``<GDMCONFDIR>/<Phase>`` GDM tries, in order,
  ``g_build_filename(dir, display_name)``, then ``<dir>/<remote host>`` (only
  when a remote host name is set and not empty), then ``<dir>/Default``. The
  first candidate for which ``g_file_test`` reports both ``IS_REGULAR`` and
  ``IS_EXECUTABLE`` runs and the later ones are skipped. Both tests use
  ``stat()``, so symlinks are followed and a dangling symlink counts as absent.
  GDM runs as root, and glib then treats a file as executable when any of its
  user, group or other execute bits is set.
* ``g_build_filename`` ignores an absent or empty element, so a session with no
  X11 display name (a Wayland session) tries the phase path itself first. When
  that path is an executable regular file instead of a directory, it runs.
* The chosen path is reparsed with ``g_shell_parse_argv`` and spawned without a
  shell. When ``execve`` fails with ``ENOEXEC`` (no ``#!`` line and not a binary)
  glib runs ``/bin/sh <path>`` instead.
* ``PostLogin`` and ``PreSession`` run as root in the session worker, after
  authentication and before the user session starts. A script that fails or
  exits non-zero aborts the login. ``PostSession`` runs as root after the user
  session exits, and its result is ignored. The greeter and other program
  sessions run none of the three. The remote host is passed only for
  non-local (XDMCP) displays.
* ``Init`` runs as root, with ``USER`` ``gdm``, when the daemon itself starts an
  Xorg server, which happens only for ``legacy-xorg`` and XDMCP displays. Its
  remote host is always unset and its result is ignored. User-display-server
  sessions (the default on current distributions) never run it.

``GDMCONFDIR`` is a build setting: ``/etc/gdm3`` on Debian and Ubuntu,
``/etc/gdm`` upstream and on Fedora. The caller supplies it.

It performs no I/O, never runs a command and never authorizes a response
action. Every input that is unknown, malformed or over a cap, and every path
that ``g_shell_parse_argv`` would change or that leaves the phase directory
(a display name or host containing ``/``), becomes an explicit coverage gap
and never yields a covered result.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
MAX_PATH = 4096
MAX_NAMES = 1024
MAX_GAPS = 256

PHASES = ('Init', 'PostLogin', 'PreSession', 'PostSession')
DEFAULT_NAME = 'Default'
SHELL_FALLBACK = '/bin/sh'
INIT_USER = 'gdm'
FILE_STATES = ('present', 'absent', 'unknown')
FILE_KINDS = ('regular', 'directory', 'other')
_PHASE = {
    'Init': {'runs_as': 'root', 'env_user': INIT_USER, 'when': 'gdm_started_xorg_server_ready',
             'applies_to': 'legacy_xorg_and_xdmcp_displays', 'failure_aborts_login': False,
             'remote_host_used': False},
    'PostLogin': {'runs_as': 'root', 'env_user': 'session_user', 'when': 'after_authentication_before_session',
                  'applies_to': 'user_sessions', 'failure_aborts_login': True, 'remote_host_used': True},
    'PreSession': {'runs_as': 'root', 'env_user': 'session_user', 'when': 'before_user_session_starts',
                   'applies_to': 'user_sessions', 'failure_aborts_login': True, 'remote_host_used': True},
    'PostSession': {'runs_as': 'root', 'env_user': 'session_user', 'when': 'after_user_session_exits',
                    'applies_to': 'user_sessions', 'failure_aborts_login': False, 'remote_host_used': True},
}
_SHA256 = re.compile(r'[0-9a-f]{64}')
# g_shell_parse_argv() splits on blanks, removes quotes and backslashes and
# drops '#' comments. A path made only of these characters is one literal word.
_SHELL_LITERAL = re.compile(r'[A-Za-z0-9_./+,:@%=-]+')


class Invalid(ValueError):
    """An observation that cannot be interpreted safely."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps[-1] = {'code': 'gaps_truncated'}


def _confdir(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith('/') or len(value) > MAX_PATH or '\0' in value:
        raise Invalid('invalid GDMCONFDIR')
    value = value.rstrip('/') or '/'
    if '//' in value:
        raise Invalid('invalid GDMCONFDIR')
    return value


def _join(directory: str, name: str | None) -> str:
    # g_build_filename() ignores an absent or empty element.
    if not name:
        return directory
    return f'{directory.rstrip("/")}/{name}'


def _file(value: Any) -> dict[str, Any]:
    if value is None:
        return {'state': 'unknown', 'kind': None, 'executable': None, 'sha256': None}
    if not isinstance(value, dict) or 'state' not in value \
            or not set(value) <= {'state', 'kind', 'executable', 'sha256'}:
        raise Invalid('invalid file observation')
    state, kind, executable, sha = value['state'], value.get('kind'), value.get('executable'), value.get('sha256')
    if state not in FILE_STATES:
        raise Invalid('invalid file state')
    if state != 'present' and (kind is not None or executable is not None or sha is not None):
        raise Invalid('details supplied for a file that is not present')
    if kind is not None and kind not in FILE_KINDS:
        raise Invalid('invalid file kind')
    if executable is not None and type(executable) is not bool:
        raise Invalid('invalid executable flag')
    if sha is not None and (not isinstance(sha, str) or not _SHA256.fullmatch(sha) or kind != 'regular'):
        raise Invalid('invalid file hash')
    return {'state': state, 'kind': kind, 'executable': executable, 'sha256': sha}


def _qualifies(obs: dict[str, Any]) -> bool | None:
    """Return GDM's regular-and-executable test, or None when it is unknown."""
    if obs['state'] == 'unknown':
        return None
    if obs['state'] == 'absent':
        return False
    if obs['kind'] is None:
        return None
    if obs['kind'] != 'regular':
        return False
    return obs['executable']


def _inert_reason(obs: dict[str, Any]) -> str:
    if obs['state'] == 'absent':
        return 'absent_or_dangling'
    if obs['kind'] != 'regular':
        return 'not_regular_file'
    return 'no_execute_bit'


def _parse(observation: Any) -> tuple[str, dict[str, dict[str, Any]], dict[str, list[str] | None]]:
    if not isinstance(observation, dict) or 'confdir' not in observation \
            or not set(observation) <= {'confdir', 'paths', 'listings'}:
        raise Invalid('invalid observation')
    confdir = _confdir(observation['confdir'])
    raw_paths = observation.get('paths', {})
    raw_listings = observation.get('listings', {})
    if not isinstance(raw_paths, dict) or not isinstance(raw_listings, dict):
        raise Invalid('paths and listings must be mappings')
    paths: dict[str, dict[str, Any]] = {}
    for path, value in raw_paths.items():
        if not isinstance(path, str) or not path.startswith('/') or len(path) > MAX_PATH or '\0' in path:
            raise Invalid('invalid observed path')
        paths[path] = _file(value)
    listings: dict[str, list[str] | None] = {}
    for path, names in raw_listings.items():
        if not isinstance(path, str) or not path.startswith('/'):
            raise Invalid('invalid listing path')
        if names is None:
            listings[path] = None
            continue
        # Validate every entry before detecting duplicates: set() raises TypeError on an object or array.
        if not isinstance(names, list) or any(
                not isinstance(n, str) or not n or '/' in n or '\0' in n or n in ('.', '..') for n in names) \
                or len(set(names)) != len(names):
            raise Invalid('invalid directory listing')
        listings[path] = names
    return confdir, paths, listings


def _candidate(path: str, selector: str, name: str | None, paths: dict[str, dict[str, Any]],
               gaps: list[dict[str, Any]]) -> dict[str, Any]:
    obs = paths.get(path, _file(None))
    qualifies = _qualifies(obs)
    entry = {'path': path, 'name': name, 'selector': selector, 'qualifies': qualifies, 'sha256': obs['sha256']}
    if qualifies is None:
        _gap(gaps, 'candidate_not_observed', path=path)
    elif not qualifies:
        entry['skipped_because'] = _inert_reason(obs)
    return entry


def _command(path: str, gaps: list[dict[str, Any]]) -> list[str] | None:
    if not _SHELL_LITERAL.fullmatch(path):
        _gap(gaps, 'script_path_reparsed_by_shell_parse_argv', path=path)
        return None
    return [path]


def select(observation: Any, phase: str, display_name: str | None = None,
           remote_host: str | None = None) -> dict[str, Any]:
    """Return the script GDM runs for one phase, display name and remote host.

    ``observation`` is ``{'confdir': '/etc/gdm3', 'paths': {path: file}, 'listings': {dir: [names]}}``.
    A file is ``{'state': 'present'|'absent'|'unknown', 'kind': 'regular'|'directory'|'other',
    'executable': bool, 'sha256': hex}`` as seen by ``stat()`` (symlinks followed);
    ``executable`` means any execute bit is set. An unlisted path is unknown.
    ``display_name`` is the X11 display (``':0'``), or None/empty for a Wayland session.
    ``remote_host`` is the XDMCP host; it is ignored for ``Init``.
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'complete': False, 'phase': phase,
                              'outcome': 'undetermined', 'script': None, 'argv': None, 'candidates': [],
                              'gaps': gaps}
    try:
        if phase not in PHASES:
            raise Invalid('unknown phase')
        confdir, paths, _ = _parse(observation)
        for label, value in (('display_name', display_name), ('remote_host', remote_host)):
            if value is not None and (not isinstance(value, str) or '\0' in value or len(value) > MAX_PATH):
                raise Invalid(f'invalid {label}')
    except Invalid as exc:
        _gap(gaps, 'invalid_observation', detail=str(exc))
        return result
    meta = _PHASE[phase]
    result.update({k: meta[k] for k in ('runs_as', 'env_user', 'when', 'applies_to', 'failure_aborts_login')})
    result['enoexec_fallback'] = SHELL_FALLBACK
    directory = _join(confdir, phase)
    host = remote_host if meta['remote_host_used'] else None
    order = [('display_name' if display_name else 'empty_display_name', display_name or None)]
    if host:
        order.append(('remote_host', host))
    order.append(('default', DEFAULT_NAME))
    for selector, name in order:
        if name is not None and '/' in name:
            _gap(gaps, 'name_leaves_phase_directory', selector=selector, name=name)
            return result
        entry = _candidate(_join(directory, name), selector, name, paths, gaps)
        result['candidates'].append(entry)
        if entry['qualifies'] is None:
            return result
        if entry['qualifies']:
            argv = _command(entry['path'], gaps)
            result.update({'outcome': 'runs', 'script': entry['path'], 'selector': selector,
                           'sha256': entry['sha256'], 'argv': argv})
            if argv is None:
                result['outcome'] = 'undetermined'
            result['complete'] = not gaps
            return result
    result.update({'outcome': 'none', 'complete': not gaps})
    return result


def evaluate(observation: Any) -> dict[str, Any]:
    """List, per phase, every script GDM could run and the display or host that selects it.

    A directory listing is needed for each phase directory, because display and
    host-specific names are open-ended. ``Default`` runs whenever no more specific
    candidate qualifies; a name starting with ``:`` (or ``host:N``) matches an X11
    display name; any other name matches a remote XDMCP host (never for ``Init``).
    """
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {'contract_version': CONTRACT_VERSION, 'complete': False, 'confdir': None,
                              'phases': [], 'gaps': gaps}
    try:
        confdir, paths, listings = _parse(observation)
    except Invalid as exc:
        _gap(gaps, 'invalid_observation', detail=str(exc))
        return result
    result['confdir'] = confdir
    for phase in PHASES:
        meta = _PHASE[phase]
        directory = _join(confdir, phase)
        phase_gaps: list[dict[str, Any]] = []
        entry: dict[str, Any] = {'phase': phase, 'directory': directory, 'enoexec_fallback': SHELL_FALLBACK,
                                 **{k: meta[k] for k in ('runs_as', 'env_user', 'when', 'applies_to',
                                                         'failure_aborts_login')},
                                 'scripts': [], 'inert': [], 'gaps': phase_gaps}
        dir_obs = paths.get(directory, _file(None))
        if dir_obs['state'] == 'unknown' or (dir_obs['state'] == 'present' and dir_obs['kind'] is None):
            _gap(phase_gaps, 'phase_path_not_observed', path=directory)
        elif dir_obs['state'] == 'present' and dir_obs['kind'] == 'regular':
            # With no display name the phase path itself is the first candidate.
            self_entry = _candidate(directory, 'empty_display_name', None, paths, phase_gaps)
            if self_entry['qualifies']:
                self_entry['argv'] = _command(directory, phase_gaps)
                self_entry['runs_for'] = 'sessions_without_x11_display_name'
                entry['scripts'].append(self_entry)
            elif self_entry['qualifies'] is False:
                entry['inert'].append(self_entry)
        elif dir_obs['state'] == 'present' and dir_obs['kind'] == 'directory':
            names = listings.get(directory)
            if names is None:
                _gap(phase_gaps, 'directory_listing_not_observed', path=directory)
                names = []
            if len(names) > MAX_NAMES:
                _gap(phase_gaps, 'directory_listing_over_cap', path=directory, limit=MAX_NAMES)
                names = names[:MAX_NAMES]
            for name in sorted(names):
                if name == DEFAULT_NAME:
                    selector, runs_for = 'default', 'when_no_display_or_host_script_qualifies'
                elif ':' in name:
                    # An IPv6 literal remote host also contains ':'.
                    selector = 'display_name'
                    runs_for = ('x11_display_or_ipv6_remote_host_with_this_name' if meta['remote_host_used']
                                else 'x11_display_with_this_name')
                elif meta['remote_host_used']:
                    selector, runs_for = 'remote_host', 'remote_xdmcp_display_from_this_host'
                else:
                    selector, runs_for = 'unused_name', None
                candidate = _candidate(_join(directory, name), selector, name, paths, phase_gaps)
                if candidate['qualifies'] and runs_for:
                    candidate['argv'] = _command(candidate['path'], phase_gaps)
                    candidate['runs_for'] = runs_for
                    entry['scripts'].append(candidate)
                elif candidate['qualifies'] is not None:
                    if candidate['qualifies']:
                        candidate['skipped_because'] = 'name_never_selected'
                    entry['inert'].append(candidate)
        # An absent phase path, or one that is neither a directory nor a regular
        # file, never yields a qualifying candidate.
        result['phases'].append(entry)
        for gap in phase_gaps:
            _gap(gaps, gap['code'], phase=phase, **{k: v for k, v in gap.items() if k != 'code'})
    result['complete'] = not gaps
    return result
