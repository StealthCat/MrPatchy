"""Pure rsyncd.conf exec-command contract (roadmap F slice, #1395).

``rsync --daemon`` reads ``/etc/rsyncd.conf`` again for every client
connection. When a client opens a module that has ``early exec``,
``pre-xfer exec``, ``post-xfer exec`` or ``name converter`` set, the daemon
runs that value through ``system()`` (``/bin/sh -c``), or through
``$RSYNC_SHELL -c`` when that variable is set. The command runs as the daemon
process itself, not as the module's ``uid``/``gid`` and not inside the module
chroot. On a stock Debian or Ubuntu ``rsync.service`` the daemon is root, so
``pre-xfer exec = /tmp/x`` is a root command that runs on every connection.

This module turns captured configuration text into the commands the daemon
would run, per module. It performs no I/O, never runs rsync or a command and
never authorizes a response action.

The rules follow rsync 3.2.7 (Ubuntu 24.04 ``rsync_3.2.7.orig.tar.gz``, sha256
``4e7d9d3f6ed10878c58c5fb724a67dacf4b6aac7340b13e488fb2dc41346f2bb``),
``params.c``, ``loadparm.c``, ``daemon-parm.txt`` and ``clientserver.c``:

- ``params.c`` reads the file one byte at a time. Blank lines are skipped. A
  line whose first non-blank byte is ``#`` or ``;`` is a comment, and a
  leading ``\\`` is skipped on its own. ``[name]`` starts a section; a
  newline before ``]`` is allowed only after a trailing backslash, and an
  empty name or end of file inside the brackets rejects the configuration.
  ``name = value`` sets a parameter. Whitespace runs in names collapse to one
  space, names and values are trimmed, ``\\r`` is dropped from values, and a
  trailing backslash continues the name or value on the next line. A name
  line with no ``=`` is ignored, and so is one cut off by end of file. An
  empty name before ``=`` rejects the configuration.
- ``loadparm.c`` matches labels ignoring case and whitespace, and ignores
  names that start with ``-`` and unknown names. Parameters before the first
  section, or in a ``[global]`` section, set globals and the defaults of
  module parameters. A module copies the defaults that are current when it is
  first created. A repeated section name reuses the earlier module. A module
  parameter that was never set, in the module or in the copied defaults,
  falls back to the final global default. An empty value disables a command.
  A global parameter inside a module is ignored. A ``/`` in a module name
  rejects the configuration. The ``name`` parameter renames a module.
- String values expand ``%VAR%`` from the daemon environment when they are
  read. The environment is not observed, so such commands are flagged.
- ``clientserver.c`` applies ``daemon chroot``, then ``daemon gid`` (setgid
  only, supplementary groups kept), then ``daemon uid`` after loading the file
  and before reading the module request. For each module connection that
  passes host and authentication checks it forks ``post-xfer exec`` first
  (run after the transfer ends), then runs ``early exec`` and waits, then
  starts ``pre-xfer exec`` (its non-zero exit refuses the transfer) and
  ``name converter``, then changes to the module's ``uid``/``gid``.

A rejected configuration makes the daemon exit, so no command runs. Fail-closed
rules: an unobserved file, NUL bytes, over-limit input and ``&include`` or
``&merge`` directives mark the result incomplete. ``origin`` is always
``not_assessed`` and no result is a safety verdict.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

CONTRACT_VERSION = 1
SOURCE_VERSIONS = ('3.2.7',)
DEFAULT_PATH = '/etc/rsyncd.conf'
MAX_TEXT = 262144
MAX_MODULES = 512
MAX_GAPS = 64

# Execution order for one module connection (clientserver.c rsync_module).
KINDS = ('post-xfer exec', 'early exec', 'pre-xfer exec', 'name converter')
_WHEN = {
    'post-xfer exec': 'after_transfer',
    'early exec': 'before_request_waited',
    'pre-xfer exec': 'before_transfer_can_refuse',
    'name converter': 'during_transfer_coprocess',
}
_LOCAL_LABELS = {k.replace(' ', '').upper(): k for k in (*KINDS, 'name', 'path')}
_GLOBAL_LABELS = {k.replace(' ', '').upper(): k for k in ('daemon uid', 'daemon gid', 'daemon chroot')}
NOT_MODELLED = (
    'Whether an rsync daemon runs at all, which unit or inetd entry starts it, and its starting user.',
    ('Daemon command-line --config, --dparam and --port options, and the RSYNC_NO_XFER_EXEC, '
    'RSYNC_SHELL and %VAR% environment.'),
    'Per-connection access: hosts allow/deny, auth users, secrets and max connections.',
    ('Whether the daemon and module uid/gid names exist; an unknown module uid or gid refuses the module '
    'before any command runs, so the result can over-report.'),
    'Locale-dependent isspace() for bytes above 0x7f (the C locale is assumed).',
)

_EOF = -1
_SPACE = frozenset(b' \t\n\v\f\r')
_ENV_REF = re.compile(r'%[A-Z][^%]*%')


class _Rejected(Exception):
    pass


def _isspace(c: int) -> bool:
    return c in _SPACE


def _wi(value: str) -> str:
    """strwiEQ key: ASCII case-insensitive and whitespace-blind, as in the C locale."""
    return ''.join(ch.upper() if 'a' <= ch <= 'z' else ch for ch in value if not (ord(ch) < 128 and ord(ch) in _SPACE))


class _Buf:
    """The shared params.c ``bufr``: writes past the end extend it."""

    def __init__(self) -> None:
        self.b = bytearray()

    def __setitem__(self, i: int, v: int) -> None:
        if i >= len(self.b):
            self.b.extend(b'\0' * (i + 1 - len(self.b)))
        self.b[i] = v

    def __getitem__(self, i: int) -> int:
        return self.b[i] if i < len(self.b) else 0

    def text(self, start: int, end: int) -> str:
        raw = bytes(self.b[start:end])
        cut = raw.find(b'\0')
        return (raw if cut < 0 else raw[:cut]).decode('utf-8', 'surrogateescape')


class _Parser:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.line = 1

    def getc(self) -> int:
        if self.pos >= len(self.data):
            return _EOF
        c = self.data[self.pos]
        self.pos += 1
        if c == 10:
            self.line += 1
        return c

    def eat_whitespace(self) -> int:
        c = self.getc()
        while c != _EOF and _isspace(c) and c != 10:
            c = self.getc()
        return c

    def eat_comment(self) -> int:
        c = self.getc()
        while c != 10 and c != _EOF and c > 0:
            c = self.getc()
        return c

    @staticmethod
    def continuation(buf: _Buf, pos: int) -> int:
        pos -= 1
        while pos >= 0 and _isspace(buf[pos]):
            pos -= 1
        return pos if pos >= 0 and buf[pos] == 0x5C else -1

    def section(self, sfunc) -> bool:
        buf = _Buf()
        i = end = 0
        c = self.eat_whitespace()
        while c != _EOF and c > 0:
            if c == 0x5D:  # ]
                if end == 0:
                    return False
                if not sfunc(buf.text(0, end)):
                    return False
                self.eat_comment()
                return True
            if c == 10:
                i = self.continuation(buf, i)
                if i < 0:
                    return False
                end = i - 1 if i > 0 and buf[i - 1] == 0x20 else i
                c = self.getc()
            elif _isspace(c):
                buf[end] = 0x20
                i = end + 1
                c = self.eat_whitespace()
            else:
                buf[i] = c
                i += 1
                end = i
                c = self.getc()
        return False

    def parameter(self, pfunc, c: int) -> bool:
        buf = _Buf()
        i = end = vstart = 0
        line = self.line
        while vstart == 0:
            if c == 0x3D:  # =
                if end == 0:
                    raise _Rejected('Invalid parameter name in config file.')
                buf[end] = 0
                end += 1
                i = vstart = end
                c = self.eat_whitespace()
            elif c == 10:
                i = self.continuation(buf, i)
                if i < 0:
                    return True  # "Ignoring badly formed line"
                end = i - 1 if i > 0 and buf[i - 1] == 0x20 else i
                c = self.getc()
            elif c == 0 or c == _EOF:
                return True  # "Unexpected end-of-file"; the parameter is dropped
            elif c in (0x20, 0x09) and buf[0] == 0x26:  # directive name ends at a blank
                buf[end] = 0
                end += 1
                i = vstart = end
                c = self.eat_whitespace()
                if c == 0x3D:
                    c = self.eat_whitespace()
            elif _isspace(c):
                buf[end] = 0x20
                i = end + 1
                c = self.eat_whitespace()
            else:
                buf[i] = c
                i += 1
                end = i
                c = self.getc()
        while c != _EOF and c > 0:
            if c == 13:
                c = self.getc()
            elif c == 10:
                i = self.continuation(buf, i)
                if i < 0:
                    c = 0
                else:
                    end = i
                    while end >= 0 and _isspace(buf[end]):
                        end -= 1
                    c = self.getc()
            else:
                buf[i] = c
                i += 1
                if not _isspace(c):
                    end = i
                c = self.getc()
        return pfunc(buf.text(0, vstart), buf.text(vstart, end), line)

    def parse(self, sfunc, pfunc, directive) -> None:
        c = self.eat_whitespace()
        while c != _EOF and c > 0:
            if c == 10:
                c = self.eat_whitespace()
            elif c in (0x3B, 0x23):
                c = self.eat_comment()
            elif c == 0x5B:
                if not self.section(sfunc):
                    raise _Rejected('Section header rejected.')
                c = self.eat_whitespace()
            elif c == 0x5C:
                c = self.eat_whitespace()
            elif c == 0x26:
                self.parameter(directive, c)
                c = self.eat_whitespace()
            else:
                self.parameter(pfunc, c)
                c = self.eat_whitespace()


def _gap(gaps: list[dict[str, Any]], code: str, detail: str, **extra: Any) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'detail': detail, **extra})


def _result(path: str, status: str, gaps: list, commands: list, modules: list, daemon: dict | None,
            detail: str = '') -> dict[str, Any]:
    return {
        'contract_version': CONTRACT_VERSION, 'source_versions': list(SOURCE_VERSIONS), 'path': path,
        'status': status, 'complete': not gaps, 'detail': detail, 'modules': modules, 'commands': commands,
        'daemon': daemon, 'gaps': gaps, 'not_modelled': list(NOT_MODELLED), 'origin': 'not_assessed',
    }


def evaluate(*, text: bytes | str | None, path: str = DEFAULT_PATH) -> dict[str, Any]:
    """Return the commands an ``rsync --daemon`` using ``path`` would run.

    ``text`` is the captured file content, or None when the file state was not
    observed. Statuses: ``not_observed``, ``config_rejected`` (rsync exits, so
    nothing runs) and ``evaluated``. ``complete`` is false whenever any gap
    remains.
    """
    gaps: list[dict[str, Any]] = []
    if text is None:
        _gap(gaps, 'not_observed', 'The configuration file state was not observed.', path=path)
        return _result(path, 'not_observed', gaps, [], [], None)
    data = text.encode('utf-8', 'surrogateescape') if isinstance(text, str) else bytes(text)
    if len(data) > MAX_TEXT:
        _gap(gaps, 'over_limit', f'The file is larger than {MAX_TEXT} bytes.', path=path)
        return _result(path, 'evaluated', gaps, [], [], None)
    if b'\0' in data:
        _gap(gaps, 'nul_byte', 'The file contains a NUL byte, which rsync treats as an early end of input.',
             path=path)
        return _result(path, 'evaluated', gaps, [], [], None)

    defaults: dict[str, tuple[str, int] | None] = {k: None for k in (*KINDS, 'name', 'path')}
    globals_: dict[str, tuple[str, int] | None] = {k: None for k in _GLOBAL_LABELS.values()}
    sections: list[dict[str, Any]] = []
    state: dict[str, Any] = {'global': True, 'index': -1}

    def find(name: str) -> int:
        key = _wi(name)
        for idx in range(len(sections) - 1, -1, -1):
            current = sections[idx]['values']['name']
            if current is not None and _wi(current[0]) == key:
                return idx
        return -1

    def sfunc(name: str) -> bool:
        isglobal = _wi(name) == 'GLOBAL'
        state['global'] = isglobal
        if isglobal:
            return True
        if '/' in name:
            return False
        idx = find(name)
        if idx < 0:
            if len(sections) >= MAX_MODULES:
                raise OverflowError
            values = dict(defaults)
            values['name'] = (name, 0)
            sections.append({'values': values, 'own': set()})
            idx = len(sections) - 1
        state['index'] = idx
        return True

    def pfunc(name: str, value: str, line: int) -> bool:
        if name.startswith('-'):
            return True
        key = _wi(name)
        if key in _GLOBAL_LABELS:
            if state['global']:
                globals_[_GLOBAL_LABELS[key]] = (value, line)
            return True
        if key in _LOCAL_LABELS:
            label = _LOCAL_LABELS[key]
            if state['global']:
                defaults[label] = (value, line)
            else:
                sections[state['index']]['values'][label] = (value, line)
                sections[state['index']]['own'].add(label)
        return True

    def directive(name: str, value: str, line: int) -> bool:
        if name.lower() not in ('&include', '&merge'):
            raise _Rejected(f'Unknown directive {name!r}.')
        _gap(gaps, 'include_not_modelled',
             f'{name} {value} reads more configuration, which this contract does not follow.',
             line=line)
        return True

    parser = _Parser(data)
    try:
        parser.parse(sfunc, pfunc, directive)
    except _Rejected as exc:
        return _result(path, 'config_rejected', gaps, [], [], None,
                       f'rsync rejects this configuration near line {parser.line} ({exc}), so the daemon exits '
                       'and runs no command.')
    except OverflowError:
        _gap(gaps, 'over_limit', f'More than {MAX_MODULES} modules.', path=path)
        return _result(path, 'evaluated', gaps, [], [], None)

    def plain(item: tuple[str, int] | None) -> str | None:
        return item[0] if item is not None and item[0] != '' else None

    daemon = {
        'uid': plain(globals_['daemon uid']), 'gid': plain(globals_['daemon gid']),
        'chroot': plain(globals_['daemon chroot']),
    }
    runs_as = daemon['uid'] if daemon['uid'] is not None else 'rsync daemon starting user'
    runs_group = daemon['gid'] if daemon['gid'] is not None else 'rsync daemon starting group'
    modules: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    names = [s['values']['name'][0] if s['values']['name'] is not None else '' for s in sections]
    for idx, section in enumerate(sections):
        values = section['values']
        module = names[idx]
        path_item = values['path'] if values['path'] is not None else defaults['path']
        # lp_number() picks the last module whose name matches exactly.
        reachable = module not in names[idx + 1:]
        has_path = path_item is not None and path_item[0] != ''
        refused = None if reachable and has_path else ('shadowed_by_later_module' if not reachable else 'no_path')
        modules.append({'name': module, 'reachable': reachable, 'path': path_item[0] if has_path else None,
                        'refused': refused})
        if refused:
            continue
        for kind in KINDS:
            item = values[kind]
            if item is None:
                item = defaults[kind]
            if item is None or item[0] == '':
                continue
            command, line = item
            commands.append({
                'module': module, 'kind': kind, 'when': _WHEN[kind], 'command': command, 'line': line,
                'from_global_default': kind not in section['own'],
                'command_sha256': hashlib.sha256(command.encode('utf-8', 'surrogateescape')).hexdigest(),
                'env_expansion': bool(_ENV_REF.search(command)),
                'shell': '/bin/sh -c (or $RSYNC_SHELL -c)',
                'runs_as': runs_as, 'runs_as_group': runs_group, 'root_dir': daemon['chroot'] or '/',
                'module_uid_applies': False,
            })
    for cmd in commands:
        if cmd['env_expansion']:
            _gap(gaps, 'env_expansion', 'The command contains %VAR% references expanded from the unobserved '
                 'daemon environment.', module=cmd['module'], kind=cmd['kind'], line=cmd['line'])
    if any(v is not None and _ENV_REF.search(v) for v in daemon.values()):
        _gap(gaps, 'env_expansion', 'A daemon uid, gid or chroot value contains %VAR% references.')
    return _result(path, 'evaluated', gaps, commands, modules, daemon)
