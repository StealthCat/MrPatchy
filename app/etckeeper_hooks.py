"""Pure etckeeper hook contract (roadmap F slice, #1517).

etckeeper keeps ``/etc`` in version control. Its Debian/Ubuntu package runs its
own hook directories as root from three triggers:

* ``/etc/apt/apt.conf.d/05etckeeper`` adds ``DPkg::Pre-Invoke`` and
  ``DPkg::Post-Invoke`` commands, so every dpkg run from APT starts
  ``etckeeper pre-install`` and ``etckeeper post-install`` while
  ``/usr/bin/etckeeper`` is executable.
* ``/etc/cron.daily/etckeeper`` sources ``etckeeper.conf`` and, unless
  ``AVOID_DAILY_AUTOCOMMITS`` is ``"1"``, runs ``/etc/etckeeper/daily``.
* ``etckeeper.timer`` starts ``etckeeper.service``, whose ``ExecStart`` is
  ``/etc/etckeeper/daily``. That path does not read
  ``AVOID_DAILY_AUTOCOMMITS``.

``/etc/etckeeper/daily`` runs ``etckeeper unclean`` and, when that succeeds,
``etckeeper commit``. Some shipped hook scripts call further etckeeper
commands, listed in ``SHIPPED_INVOCATIONS``.

The rules are pinned to Ubuntu ``etckeeper 1.18.20-2`` (``/usr/bin/etckeeper``,
the shipped hooks, cron job and units):

* ``etckeeper.conf`` is sourced by ``/bin/sh`` as root before the hook
  directory is chosen. It is root shell code and can redirect
  ``ETCKEEPER_CONF_DIR`` or ``ETCKEEPER_DIR``.
* ``etckeeper <command>`` exits before running anything when
  ``<conf dir>/<command>.d`` is not a directory, or when no VCS is configured or
  detected.
* With Perl present, ``lsscripts`` selects ``glob "$dir/*"`` entries whose name
  matches ``[-a-zA-Z0-9]+``, that are not directories and that are ``-x``.
  ``glob`` skips dot names. Under ``LANG=C`` File::Glob sorts case-folded names
  first and breaks ties by bytes. Without Perl, the ``/bin/sh`` fallback uses
  the same selection and dash's byte order.
* Every script runs as ``"$script" "$@"`` under ``set -e``, so a failing script
  stops the remaining scripts of that command and the command itself.

This module never evaluates shell. ``etckeeper.conf`` is understood only when
its SHA-256 matches the shipped file or every line is blank, a comment or a
literal ``NAME=value`` assignment. A script's nested invocations are known only
for unchanged shipped scripts. ``git commit`` and ``git push`` in shipped
``commit.d`` scripts run VCS hooks, which this contract does not resolve.
Every input that is unknown, malformed or over a cap becomes an explicit gap
and never yields a covered result.

It performs no I/O, never runs a command and never authorizes a response action.
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
SUPPORTED_VERSION = '1.18.20-2'
MAX_ENTRIES = 1024
MAX_TEXT = 1 << 20
MAX_GAPS = 256

PROGRAM = '/usr/bin/etckeeper'
CONF_DIR = '/etc/etckeeper'
CONF = '/etc/etckeeper/etckeeper.conf'
APT_CONF = '/etc/apt/apt.conf.d/05etckeeper'
CRON_DAILY = '/etc/cron.daily/etckeeper'
DAILY = '/etc/etckeeper/daily'
SERVICE = '/usr/lib/systemd/system/etckeeper.service'
TIMER = '/usr/lib/systemd/system/etckeeper.timer'

# SHA-256 of the files shipped by etckeeper 1.18.20-2 (Ubuntu 24.04).
SHIPPED_FILES = {
    PROGRAM: 'a71a2ae8832c843b372752684866225acf39ea95a44dbb473d050d0f251f8d9a',
    APT_CONF: '2fd68c2109eb267d2f24b59e6bff2a8d3430aa665d000e82aeec1d33be68d263',
    CRON_DAILY: 'f07e4d562cda373aabc4097c54d90701cc0671360234b366161fc3f7ed149734',
    DAILY: 'b59e796876ef5403cabcf882fd3e2c5ff74897987c92b2466061c70f3d9a391b',
    CONF: '9166324888fd3eccc5d5f13cd3a111c669abc047bca030c435ebd7c8ede8626e',
    SERVICE: '2942714e2d41939dd55af64b298561cffe9b88ac972767d0c07ea4fe31e318c9',
    TIMER: '256326aaaf5ce44a1b965e102cccd0cba433a76444ad9053428fb9f16428b8e5',
}
FILE_KEYS = {'program': PROGRAM, 'conf': CONF, 'apt_conf': APT_CONF, 'cron_daily': CRON_DAILY,
             'daily': DAILY, 'service': SERVICE, 'timer': TIMER}

# Hook scripts shipped per command directory, by SHA-256 of their content.
# commit.d/20store-metadata is a symlink to ../pre-commit.d/30store-metadata.
SHIPPED_SCRIPTS: dict[str, dict[str, str]] = {
    'commit': {
        '10vcs-test': '66376a15e184569c9265539ed00f8d6bd76b9d06ec0fbdf6384d2a8d5405964c',
        '20store-metadata': 'b781278601de89902da64860c99b63a353d3c2a47da3d22df4b62f19f25e7843',
        '30bzr-add': 'a1b8c15a3aa80470681d70406e72f79540aea43cc88db62df6a446c1f314f606',
        '30darcs-add': 'b160934ebc227832da708ee501fcbb2d4a18800c15318f5981e0c914ebefa21e',
        '30git-add': '47e984ea5b497634216f296770875ccd4e5e0a91d0adeaf71de429177fe46590',
        '30hg-addremove': '323b1720db518fb9de4227653628378c5cb7bf5d37dab653e9e533f2bc9cab78',
        '50vcs-commit': 'e615a46e175f77d47769b71ad3cdaf85c99f3d6ce65d7494748dd7b755df3a68',
        '99push': '99f88b8db8aef5e674332b9e6018fd92f93f9b21eb61e12cd979a6b8defce2e6',
    },
    'init': {
        '10restore-metadata': 'f6c7159eeee35db151af07f2d00f4c28c0411e032fe84e0c1f77c3a3bd531a5f',
        '20restore-etckeeper': 'cadec5f18f5913d1994aecff37735e16d18245a7c6f19f5212efe48d7755ca20',
        '40vcs-init': '0c870f5f408b1fe5ba228947ae333db126947b3e220451de508e233f4568ca91',
        '50vcs-ignore': '184ac1bdb5ca52b1f54f5f209fcae7193e7717e194d75852d16377c6b7910e6f',
        '50vcs-perm': 'ddda3268bd47635a4c129f72e270f646a32b68c56992a748576ef8f0968804b9',
        '50vcs-pre-commit-hook': 'c17423d7823de8b890ed0f18e0e80a2d34eb383442246ae11be16089f5eb5475',
        '60darcs-deleted-symlinks': '5c640c4f8790cf103bebd676fb4a1d11807ca72159276ec735375696ea6d7359',
        '70vcs-add': 'f52f7251a1fbb4c7f1d2ef1e3734d451e89c78dc56802e42d463c5b3192a179d',
    },
    'list-installed': {
        '50list-installed': 'f940357c36e92ead88b9f4a554f7745da3fe0ae1a914c9e24b719f00b538f7d1',
    },
    'post-install': {
        '50vcs-commit': 'fbf198d234168583f3bed6052263f7dedc7d1260bb0d70f9d641e4341bd4c518',
    },
    'pre-commit': {
        '20warn-problem-files': '05a9c581624656a56bda8b53c692958856078cbb12574b4fe150ae5ed8196d30',
        '30store-metadata': 'b781278601de89902da64860c99b63a353d3c2a47da3d22df4b62f19f25e7843',
    },
    'pre-install': {
        '10packagelist': '722e9f68ec96c6d2f47c8466d3638602d31ac92d0ef2bc9216ba10d45ad55a3a',
        '50uncommitted-changes': '945b50766fb5c5be1d7d935174f73fe2de6f86d9d446bc408151c9669cc03aad',
    },
    'unclean': {
        '50test': 'e282505c734ebeceb1a88b9e9190f7bb84683d4f3cfd35a58e125360d955311d',
    },
    'uninit': {
        '01prompt': '3e91a5eb9c4ae688429dd4b63d72e9fc28c564fb2ec227d30a87ce5e932e710e',
        '50remove-metadata': '4b84d598dd5c82d4df8e1dcf9a4a3e74306cc0fce2135c36bf20d98102235959',
        '50vcs-uninit': 'e7a4fe88d73d24427dfec48284229e7c855e561313f2d0fef236898df6343fb0',
    },
    'update-ignore': {
        '01update-ignore': '26b29dc58337f6fc6ae312ea768a806e40666d99eefc532bdbf1c46eca8eef88',
    },
    'vcs': {
        '50vcs-cmd': 'b8c8661921accb901de20055597599e7b3623bfb7959d7ddcb1ae0012c054b4a',
    },
}
COMMANDS = tuple(sorted(SHIPPED_SCRIPTS))

# etckeeper commands that unchanged shipped scripts invoke, in source order.
SHIPPED_INVOCATIONS: dict[tuple[str, str], tuple[str, ...]] = {
    ('pre-install', '10packagelist'): ('list-installed',),
    ('pre-install', '50uncommitted-changes'): ('unclean', 'commit'),
    ('post-install', '50vcs-commit'): ('unclean', 'list-installed', 'commit'),
    ('init', '50vcs-ignore'): ('update-ignore',),
}
# Unchanged shipped scripts that run the VCS, whose own hooks can run more code.
SHIPPED_VCS_HOOK_RUNNERS = {('commit', '50vcs-commit'), ('commit', '99push')}
DAILY_INVOCATIONS = ('unclean', 'commit')

FILE_STATES = ('present', 'absent', 'unknown')
DIR_STATES = ('listed', 'absent', 'unknown')
KINDS = ('regular', 'directory', 'other', 'unknown')
PERL_STATES = ('present', 'absent', 'unknown')
TIMER_STATES = ('enabled', 'disabled', 'unknown')
VCS_NAMES = ('git', 'hg', 'darcs', 'bzr')
REDIRECT_KEYS = ('ETCKEEPER_CONF_DIR', 'ETCKEEPER_DIR')
SCRIPT_PROVENANCE = ('shipped_unchanged', 'shipped_modified', 'custom', 'unverified')

_SHA256 = re.compile(r'[0-9a-f]{64}')
_NAME = re.compile(r'[^/\x00]{1,255}')
_SELECTED = re.compile(r'[-a-zA-Z0-9]+')
# Perl's "$" also matches before one trailing newline.
_SELECTED_NEWLINE = re.compile(r'[-a-zA-Z0-9]+\n')
_COMMENT = re.compile(r'[ \t]*(#.*)?')
_ASSIGN = re.compile(r'(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>"[^"\\$`]*"|\'[^\']*\'|[A-Za-z0-9_./:@%+,-]*)'
                     r'(?:[ \t]+(?:#.*)?)?')  # "#" starts a comment only at the start of a shell word


class Invalid(ValueError):
    """An observation that cannot be interpreted safely."""


def _gap(gaps: list[dict[str, Any]], code: str, **detail: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, **detail})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps[-1] = {'code': 'gaps_truncated'}


def _file(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {'state': 'unknown', 'sha256': None, 'text': None, 'executable': None}
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
    executable = value.get('executable')
    if executable is not None and not isinstance(executable, bool):
        raise Invalid(f'{name}.executable is invalid')
    present = state == 'present'
    return {'state': state, 'sha256': digest if present else None, 'text': text if present else None,
            'executable': executable if present else None}


def _directory(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {'state': 'unknown', 'entries': [], 'complete': False}
    if not isinstance(value, dict):
        raise Invalid(f'{name} must be an object')
    state = value.get('state')
    if state not in DIR_STATES:
        raise Invalid(f'{name}.state is invalid')
    if state != 'listed':
        return {'state': state, 'entries': [], 'complete': False}
    raw = value.get('entries', [])
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
        digest = item.get('sha256')
        if digest is not None and (not isinstance(digest, str) or not _SHA256.fullmatch(digest)):
            raise Invalid(f'{name} entry sha256 is invalid')
        entries.append({'name': entry_name, 'kind': kind, 'executable': executable, 'sha256': digest})
    complete = value.get('complete', True)
    if not isinstance(complete, bool):
        raise Invalid(f'{name}.complete is invalid')
    return {'state': state, 'entries': entries, 'complete': complete}


def _choice(value: Any, allowed: tuple[str, ...], name: str) -> str:
    if value is None:
        return 'unknown'
    if value not in allowed:
        raise Invalid(f'{name} is invalid')
    return value


def _parse_conf(text: str) -> dict[str, str] | None:
    """Return the literal assignments of a simple etckeeper.conf, or None for other shell."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if _COMMENT.fullmatch(line):
            continue
        match = _ASSIGN.fullmatch(line.strip(' \t'))
        if not match:
            return None
        value = match.group('value')
        if value[:1] in ('"', "'"):
            value = value[1:-1]
        values[match.group('key')] = value
    return values


def _perl_key(name: str) -> tuple[bytes, bytes]:
    raw = name.encode('utf-8', 'surrogateescape')
    return raw.lower(), raw


def _byte_key(name: str) -> bytes:
    return name.encode('utf-8', 'surrogateescape')


def _conf_state(conf: dict[str, Any], gaps: list[dict[str, Any]]) -> dict[str, Any]:
    """Interpret etckeeper.conf without evaluating it."""
    result: dict[str, Any] = {'path': CONF, 'state': conf['state'], 'sourced_as': 'root',
                              'provenance': None, 'values': {}, 'understood': False}
    if conf['state'] == 'absent':
        result['understood'] = True
        return result
    if conf['state'] == 'unknown':
        _gap(gaps, 'conf_unknown', path=CONF)
        return result
    if conf['sha256'] == SHIPPED_FILES[CONF]:
        result['provenance'] = 'shipped_unchanged'
    elif conf['sha256'] is None:
        result['provenance'] = 'unverified'
    else:
        result['provenance'] = 'modified'
    if conf['text'] is None:
        if result['provenance'] == 'shipped_unchanged':
            # The shipped file only assigns these literals.
            result['values'] = {'VCS': 'git', 'HIGHLEVEL_PACKAGE_MANAGER': 'apt',
                                'LOWLEVEL_PACKAGE_MANAGER': 'dpkg', 'PUSH_REMOTE': ''}
            result['understood'] = True
            return result
        _gap(gaps, 'conf_text_missing', path=CONF)
        return result
    values = _parse_conf(conf['text'])
    if values is None:
        _gap(gaps, 'conf_not_understood', path=CONF,
             detail='etckeeper.conf contains shell other than literal assignments and is sourced as root.')
        return result
    redirected = [key for key in REDIRECT_KEYS if key in values]
    result['values'] = values
    if redirected:
        _gap(gaps, 'conf_redirects_directory', path=CONF, keys=redirected)
        return result
    result['understood'] = True
    return result


def _file_provenance(observed: dict[str, Any], path: str) -> str:
    if observed['sha256'] is None:
        return 'unverified'
    return 'shipped_unchanged' if observed['sha256'] == SHIPPED_FILES[path] else 'modified'


def _command(command: str, directory: dict[str, Any], perl: str,
             gaps: list[dict[str, Any]]) -> dict[str, Any]:
    path = f'{CONF_DIR}/{command}.d'
    result: dict[str, Any] = {'command': command, 'directory': path, 'state': directory['state'],
                              'scripts': [], 'skipped': [], 'order_resolved': True, 'complete': False}
    if directory['state'] == 'absent':
        result['complete'] = True
        result['note'] = f'etckeeper {command} exits 1 before running any script when {path} is missing.'
        return result
    if directory['state'] == 'unknown':
        _gap(gaps, 'directory_unknown', path=path)
        return result
    complete = directory['complete']
    if not complete:
        _gap(gaps, 'directory_incomplete', path=path)
    shipped = SHIPPED_SCRIPTS.get(command, {})
    candidates: list[dict[str, Any]] = []
    for entry in directory['entries']:
        name = entry['name']
        if name.startswith('.'):
            result['skipped'].append({'name': name, 'reason': 'dot_name_not_globbed'})
            continue
        if _SELECTED_NEWLINE.fullmatch(name):
            _gap(gaps, 'name_unresolved', path=path, name=name,
                 detail='Perl selects a name with a trailing newline that the shell then splits.')
            complete = False
            continue
        if not _SELECTED.fullmatch(name):
            result['skipped'].append({'name': name, 'reason': 'name_not_selected'})
            continue
        if entry['kind'] == 'directory':
            result['skipped'].append({'name': name, 'reason': 'directory'})
            continue
        if entry['kind'] == 'unknown' or entry['executable'] is None:
            _gap(gaps, 'entry_unresolved', path=f'{path}/{name}')
            complete = False
            continue
        if not entry['executable']:
            result['skipped'].append({'name': name, 'reason': 'not_executable'})
            continue
        candidates.append(entry)
    names = [entry['name'] for entry in candidates]
    perl_order = sorted(names, key=_perl_key)
    shell_order = sorted(names, key=_byte_key)
    if perl == 'absent':
        order = shell_order
    else:
        order = perl_order
        if perl == 'unknown' and perl_order != shell_order:
            result['order_resolved'] = False
            _gap(gaps, 'order_unresolved', path=path,
                 detail='Perl and the /bin/sh fallback order these scripts differently and Perl presence is unknown.')
    by_name = {entry['name']: entry for entry in candidates}
    for position, name in enumerate(order, 1):
        entry = by_name[name]
        if entry['sha256'] is None:
            provenance = 'unverified'
        elif name in shipped:
            provenance = 'shipped_unchanged' if entry['sha256'] == shipped[name] else 'shipped_modified'
        else:
            provenance = 'custom'
        script: dict[str, Any] = {'path': f'{path}/{name}', 'name': name, 'position': position,
                                  'kind': entry['kind'], 'runs_as': 'root', 'provenance': provenance,
                                  'sha256': entry['sha256']}
        if provenance == 'shipped_unchanged':
            script['invokes'] = list(SHIPPED_INVOCATIONS.get((command, name), ()))
            script['invocations_resolved'] = True
            if (command, name) in SHIPPED_VCS_HOOK_RUNNERS:
                script['runs_vcs_hooks'] = True
                _gap(gaps, 'vcs_hooks_not_resolved', path=script['path'],
                     detail='This script runs the VCS, whose repository hooks can run more root code.')
        else:
            script['invokes'] = []
            script['invocations_resolved'] = False
            _gap(gaps, 'invocations_unresolved', path=script['path'], provenance=provenance)
        result['scripts'].append(script)
    result['complete'] = complete and result['order_resolved']
    return result


def _expand(command: str, commands: dict[str, dict[str, Any]], stack: tuple[str, ...],
            gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the ordered root scripts one etckeeper command runs, following known nesting."""
    if command in stack:
        _gap(gaps, 'invocation_cycle', commands=[*stack, command])
        return []
    resolved = commands.get(command)
    if resolved is None:
        return []
    steps: list[dict[str, Any]] = []
    for script in resolved['scripts']:
        steps.append({'command': command, 'path': script['path'], 'provenance': script['provenance'],
                      'depth': len(stack)})
        for nested in script['invokes']:
            steps.extend(_expand(nested, commands, (*stack, command), gaps))
    return steps


def evaluate(observation: Any) -> dict[str, Any]:
    """Resolve which etckeeper hook scripts run as root, from which trigger, in which order."""
    if not isinstance(observation, dict):
        raise Invalid('observation must be an object')
    gaps: list[dict[str, Any]] = []
    package = observation.get('package')
    if not isinstance(package, dict) or package.get('state') not in ('installed', 'absent', 'unknown'):
        raise Invalid('package.state is invalid')
    version = package.get('version')
    if version is not None and not isinstance(version, str):
        raise Invalid('package.version is invalid')
    files = {key: _file(observation.get(key), key) for key in FILE_KEYS}
    perl = _choice(observation.get('perl'), PERL_STATES, 'perl')
    timer_state = _choice(observation.get('timer_enabled'), TIMER_STATES, 'timer_enabled')
    raw_dirs = observation.get('directories', {})
    if not isinstance(raw_dirs, dict):
        raise Invalid('directories must be an object')
    for key in raw_dirs:
        if key not in COMMANDS:
            raise Invalid(f'directories.{key} is not an etckeeper command')
    repositories = observation.get('repositories', {})
    if not isinstance(repositories, dict) or any(key not in VCS_NAMES or value not in FILE_STATES
                                                 for key, value in repositories.items()):
        raise Invalid('repositories is invalid')

    base = {'contract_version': CONTRACT_VERSION, 'supported_version': SUPPORTED_VERSION,
            'authorizes_response': False, 'stops_on_failure': True}
    if package['state'] == 'absent' and files['program']['state'] == 'absent':
        return {**base, 'installed': False, 'covered': True, 'triggers': [], 'commands': [], 'conf': None,
                'gaps': []}
    if package['state'] == 'unknown':
        _gap(gaps, 'package_unknown')
    elif package['state'] == 'absent':
        _gap(gaps, 'program_without_package', path=PROGRAM)
    elif version != SUPPORTED_VERSION:
        _gap(gaps, 'version_unsupported', version=version, supported=SUPPORTED_VERSION)
    program = files['program']
    if program['state'] != 'present':
        _gap(gaps, 'program_unknown' if program['state'] == 'unknown' else 'program_absent', path=PROGRAM)
    elif _file_provenance(program, PROGRAM) != 'shipped_unchanged':
        _gap(gaps, 'program_not_verified', path=PROGRAM, provenance=_file_provenance(program, PROGRAM))

    conf = _conf_state(files['conf'], gaps)
    directories = {command: _directory(raw_dirs.get(command), f'directories.{command}') for command in COMMANDS}
    commands = {command: _command(command, directories[command], perl, gaps) for command in COMMANDS}

    # etckeeper exits before any hook when no VCS is configured or detected.
    configured_vcs = conf['values'].get('VCS') if conf['understood'] else None
    detected = [name for name in VCS_NAMES if repositories.get(name) == 'present']
    if detected or configured_vcs:
        vcs_state: bool | None = True
    elif conf['understood'] and all(repositories.get(name) == 'absent' for name in VCS_NAMES):
        vcs_state = False
    else:
        vcs_state = None
        _gap(gaps, 'vcs_unknown', detail='Whether etckeeper finds a VCS, and so runs any hook, is unknown.')

    # The APT hook and /etc/etckeeper/daily both run etckeeper only when [ -x /usr/bin/etckeeper ].
    if program['state'] == 'present':
        program_runs = program['executable']
        if program_runs is None:
            _gap(gaps, 'program_executable_unknown', path=PROGRAM)
    else:
        program_runs = _known(program['state'], False)
    triggers: list[dict[str, Any]] = []

    apt = files['apt_conf']
    apt_ok = _verified(apt, APT_CONF, 'apt_hook', gaps,
                       'A changed APT hook file is resolved by the apt_hooks contract, not here.')
    for trigger_id, command in (('apt_pre_invoke', 'pre-install'), ('apt_post_invoke', 'post-install')):
        triggers.append({'id': trigger_id, 'source': APT_CONF, 'when': 'every dpkg run started by APT',
                         'runs_as': 'root', 'state': _state(_all(apt_ok, program_runs, vcs_state)),
                         'commands': [command], 'steps': _expand(command, commands, (), gaps)})

    # /etc/etckeeper/daily runs only when it, /usr/bin/etckeeper and etckeeper.conf exist.
    daily_ok = _verified(files['daily'], DAILY, 'daily', gaps)
    conf_exists = _known(files['conf']['state'], files['conf']['state'] == 'present')
    daily_runs = _all(daily_ok, program_runs, conf_exists, vcs_state)
    daily_steps = [step for command in DAILY_INVOCATIONS for step in _expand(command, commands, (), gaps)]

    avoid = conf['values'].get('AVOID_DAILY_AUTOCOMMITS') if conf['understood'] else None
    not_avoided = (avoid != '1') if conf['understood'] else None
    cron_ok = _verified(files['cron_daily'], CRON_DAILY, 'cron_daily', gaps)
    cron_trigger = {'id': 'cron_daily', 'source': CRON_DAILY, 'when': 'daily run-parts', 'runs_as': 'root',
                    'state': _state(_all(cron_ok, daily_runs, not_avoided)),
                    'commands': list(DAILY_INVOCATIONS), 'steps': daily_steps,
                    'sources_conf': True, 'honours_avoid_daily_autocommits': True}
    if cron_ok is True and avoid == '1':
        cron_trigger['note'] = 'AVOID_DAILY_AUTOCOMMITS="1" stops the cron job, but it still sources etckeeper.conf.'
    triggers.append(cron_trigger)

    units_ok = _all(_verified(files['service'], SERVICE, 'service', gaps),
                    _verified(files['timer'], TIMER, 'timer', gaps))
    if units_ok is True and timer_state == 'unknown':
        _gap(gaps, 'timer_enablement_unknown', path=TIMER)
    timer_enabled = None if timer_state == 'unknown' else timer_state == 'enabled'
    timer_trigger = {'id': 'systemd_timer', 'source': TIMER, 'when': '15 min after boot, then daily',
                     'runs_as': 'root', 'state': _state(_all(units_ok, timer_enabled, daily_runs)),
                     'commands': list(DAILY_INVOCATIONS), 'steps': daily_steps,
                     'honours_avoid_daily_autocommits': False}
    if timer_trigger['state'] != 'inactive' and avoid == '1':
        timer_trigger['note'] = 'etckeeper.service runs /etc/etckeeper/daily even with AVOID_DAILY_AUTOCOMMITS="1".'
    triggers.append(timer_trigger)

    if conf['state'] == 'present' and not conf['understood']:
        _gap(gaps, 'hook_directory_unresolved',
             detail='etckeeper.conf may change ETCKEEPER_CONF_DIR, so these directories may not be the ones used.')
    return {**base, 'installed': True, 'covered': not gaps, 'conf': conf, 'vcs': {True: 'set', False: 'unset', None: 'unknown'}[vcs_state],
            'perl': perl, 'triggers': triggers, 'commands': [commands[c] for c in COMMANDS], 'gaps': gaps}


def _known(file_state: str, value: bool) -> bool | None:
    return None if file_state == 'unknown' else value


def _all(*values: bool | None) -> bool | None:
    """Three-valued AND: any False wins, then any unknown."""
    if any(value is False for value in values):
        return False
    return None if any(value is None for value in values) else True


def _state(value: bool | None) -> str:
    return {True: 'active', False: 'inactive', None: 'unknown'}[value]


def _verified(observed: dict[str, Any], path: str, code: str, gaps: list[dict[str, Any]],
              detail: str | None = None) -> bool | None:
    """True for the unchanged shipped file, False when absent, None when unknown or changed."""
    if observed['state'] == 'absent':
        return False
    if observed['state'] == 'unknown':
        _gap(gaps, f'{code}_unknown', path=path)
        return None
    provenance = _file_provenance(observed, path)
    if provenance != 'shipped_unchanged':
        extra = {'detail': detail} if detail else {}
        _gap(gaps, f'{code}_not_verified', path=path, provenance=provenance, **extra)
        return None
    return True
