"""Pure Docker Engine daemon.json program contract (roadmap F slice, #1521).

Takes the captured text of ``/etc/docker/daemon.json`` and reports which programs
``dockerd`` runs as root because of it:

* each ``runtimes.<name>`` entry, with its ``path`` and ``runtimeArgs`` or its
  containerd ``runtimeType`` shim, and whether it is the ``default-runtime`` that
  every container uses unless it names another runtime;
* the container init binary (``init-path``, default ``docker-init``) and whether
  ``"init": true`` makes every container start it;
* the userland proxy (``userland-proxy-path``, default ``docker-proxy``) and whether
  ``userland-proxy`` leaves it enabled;
* ``authorization-plugins`` names, which see every API request.

Behaviour was checked against a real dockerd 29.9.3 started with each case:

* The file is JSON decoded the Go way: a UTF-8 BOM and an empty file are accepted,
  a repeated key keeps its last value, and comments or trailing commas stop dockerd.
* Top-level directive names are matched exactly (``Init-Path`` is an unknown
  directive and dockerd refuses to start).
* A runtime with non-empty ``runtimeArgs`` is run through a generated wrapper,
  ``#!/bin/sh`` then ``<path> <args joined by spaces> $@``, with nothing quoted, so
  ``/bin/sh`` re-parses the path and arguments. Without arguments the path is the
  runtime binary itself.
* dockerd refuses to start when a runtime is named ``runc``, sets both or neither of
  ``path`` and ``runtimeType``, combines ``runtimeArgs`` with ``runtimeType``, or when
  ``default-runtime`` names a runtime that is not defined and is not a containerd
  shim name.

It performs no I/O, resolves no PATH lookup and never authorizes a response action.
Constructs it does not model are explicit blocking gaps, and the result is never
reported complete with any of them.
"""
from __future__ import annotations

import json
import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {'dockerd': '29.9.3'}
MAX_TEXT = 262144
MAX_RUNTIMES = 64
MAX_ARGS = 64
MAX_GAPS = 32
STOCK_RUNTIME = 'runc'
STOCK_SHIM = 'io.containerd.runc.v2'
DEFAULT_INIT = 'docker-init'
DEFAULT_PROXY = 'docker-proxy'
RUNTIME_KEYS = frozenset({'path', 'runtimeArgs', 'runtimeType', 'options'})
BLOCKING = frozenset({
    'input_malformed', 'text_too_large', 'not_an_object', 'wrong_type', 'too_many_runtimes', 'too_many_args',
    'unmodelled_runtime_key', 'reserved_shim_name', 'shell_metacharacters', 'gaps_truncated',
})
UNOBSERVED = (
    'dockerd command-line flags (--add-runtime, --default-runtime, --init-path, --userland-proxy-path and '
    'others in the service unit) are not seen; a flag that repeats a file directive stops dockerd.',
    'Relative program names are reported as written; dockerd and containerd resolve them through PATH.',
    'Whether each program exists and is executable is not checked; dockerd checks userland-proxy-path at '
    'start and fails when it is missing.',
    'Other directives are not validated; dockerd refuses to start on an unknown directive, and none of these '
    'programs then run.',
    'Rootless dockerd reads ~/.config/docker/daemon.json and runs these programs as that user, not root.',
    'Containers can still name any defined runtime with --runtime; only the default is used implicitly.',
)
NOT_A_VERDICT = 'daemon.json text only. This is not a safety verdict and origin is not assessed.'
# containerd runtime type: io.containerd.<name>.<version>, run as containerd-shim-<name>-<version>.
_SHIM = re.compile(r'^io\.containerd\.([A-Za-z0-9_-]+)\.(v[0-9]+)$')
# Characters /bin/sh treats specially in the generated wrapper's command line.
_SHELL_META = re.compile(r'[\s;&|<>()$`\\"\'*?\[\]#~=%{}!]')


class _Malformed(ValueError):
    pass


def _reject_constant(name: str):
    raise _Malformed(name)


def _decode(text: str) -> Any:
    if text.startswith('﻿'):
        text = text[1:]
    if not text.strip():
        return {}
    # Go keeps the last value of a repeated key, as dict() does; NaN/Infinity are not JSON.
    return json.loads(text, parse_constant=_reject_constant)


def _shim_binary(runtime_type: str) -> str | None:
    match = _SHIM.match(runtime_type)
    if match:
        return f'containerd-shim-{match.group(1)}-{match.group(2)}'
    return None


def analyze(text: Any) -> dict[str, Any]:
    gaps: list[dict[str, Any]] = []
    refusals: list[str] = []

    def gap(code: str, detail: str) -> None:
        if len(gaps) < MAX_GAPS:
            gaps.append({'code': code, 'detail': detail})
        elif not any(g['code'] == 'gaps_truncated' for g in gaps):
            gaps.append({'code': 'gaps_truncated', 'detail': f'more than {MAX_GAPS} gaps'})

    result: dict[str, Any] = {
        'contract_version': CONTRACT_VERSION, 'reference': dict(REFERENCE), 'run_as': 'root',
        'starts': True, 'refusals': refusals, 'default_runtime': STOCK_RUNTIME, 'programs': [],
        'authorization_plugins': [], 'gaps': gaps, 'complete': False,
        'unobserved': list(UNOBSERVED), 'not_a_verdict': NOT_A_VERDICT,
    }
    if not isinstance(text, str):
        gap('input_malformed', 'daemon.json text must be a string')
        return result
    if len(text) > MAX_TEXT:
        gap('text_too_large', f'more than {MAX_TEXT} characters')
        return result
    try:
        doc = _decode(text)
    except (ValueError, RecursionError) as exc:
        result['starts'] = False
        refusals.append(f'invalid JSON: {type(exc).__name__}')
        result['complete'] = True
        return result
    if not isinstance(doc, dict):
        gap('not_an_object', 'daemon.json is not a JSON object')
        return result

    def typed(key: str, kinds: tuple[type, ...], label: str) -> Any:
        value = doc.get(key)
        if value is None:
            return None
        if not isinstance(value, kinds) or (bool not in kinds and isinstance(value, bool)):
            gap('wrong_type', f'{key} is not {label}')
            return None
        return value

    runtimes_raw = typed('runtimes', (dict,), 'an object') or {}
    default_name = typed('default-runtime', (str,), 'a string')
    init_enabled = typed('init', (bool,), 'a boolean')
    init_path = typed('init-path', (str,), 'a string')
    proxy_enabled = typed('userland-proxy', (bool,), 'a boolean')
    proxy_path = typed('userland-proxy-path', (str,), 'a string')
    authz = typed('authorization-plugins', (list,), 'a list')

    if default_name == '':
        default_name = None
    effective_default = default_name or STOCK_RUNTIME
    result['default_runtime'] = effective_default
    programs: list[dict[str, Any]] = result['programs']

    if len(runtimes_raw) > MAX_RUNTIMES:
        gap('too_many_runtimes', f'more than {MAX_RUNTIMES} runtimes')
        runtimes_raw = {}
    defined: set[str] = set()
    for name, spec in runtimes_raw.items():
        if name == STOCK_RUNTIME:
            result['starts'] = False
            refusals.append(f"runtime name '{STOCK_RUNTIME}' is reserved")
            continue
        if name == STOCK_SHIM:
            gap('reserved_shim_name', f'runtime {name!r} shadows the stock containerd runtime; not modelled')
            continue
        if not isinstance(spec, dict):
            gap('wrong_type', f'runtime {name!r} is not an object')
            continue
        unknown = sorted(k for k in spec if k not in RUNTIME_KEYS)
        if unknown:
            gap('unmodelled_runtime_key', f'runtime {name!r} has unmodelled keys {unknown}')
            continue
        path, runtime_type, args = spec.get('path'), spec.get('runtimeType'), spec.get('runtimeArgs')
        if (path is not None and not isinstance(path, str)) or (
                runtime_type is not None and not isinstance(runtime_type, str)) or (
                args is not None and not (isinstance(args, list) and all(isinstance(a, str) for a in args))):
            gap('wrong_type', f'runtime {name!r} has a value of the wrong type')
            continue
        args = args or []
        if path and runtime_type:
            result['starts'] = False
            refusals.append(f'runtime {name}: cannot configure both path and runtimeType')
            continue
        if not path and not runtime_type:
            result['starts'] = False
            refusals.append(f'runtime {name}: either a runtimeType or a path must be configured')
            continue
        if runtime_type and args:
            result['starts'] = False
            refusals.append(f'runtime {name}: args cannot be used with a runtimeType runtime')
            continue
        if len(args) > MAX_ARGS:
            gap('too_many_args', f'runtime {name!r} has more than {MAX_ARGS} arguments')
            continue
        defined.add(name)
        entry: dict[str, Any] = {'kind': 'runtime', 'name': name, 'default': name == effective_default}
        if runtime_type:
            entry.update(kind='runtime_shim', runtime_type=runtime_type,
                         shim_binary=_shim_binary(runtime_type), argv=None, via_shell=False)
        elif args:
            line = ' '.join([path, *args])
            entry.update(path=path, runtime_args=list(args), via_shell=True,
                         shell_wrapper=f'#!/bin/sh\n{line} $@\n', argv=None)
            if _SHELL_META.search(path) or any(_SHELL_META.search(a) or not a for a in args):
                gap('shell_metacharacters',
                    f'runtime {name!r}: /bin/sh re-parses its unquoted wrapper line; argv not determined')
            else:
                entry['argv'] = [path, *args]
        else:
            entry.update(path=path, runtime_args=[], via_shell=False, argv=[path])
        programs.append(entry)

    if effective_default not in defined and effective_default not in (STOCK_RUNTIME, STOCK_SHIM):
        if effective_default in runtimes_raw:
            pass  # Its definition was refused or is a gap; that is already reported.
        elif _shim_binary(effective_default):
            programs.append({'kind': 'runtime_shim', 'name': effective_default, 'default': True,
                             'runtime_type': effective_default, 'shim_binary': _shim_binary(effective_default),
                             'argv': None, 'via_shell': False})
        else:
            result['starts'] = False
            refusals.append(f"specified default runtime '{effective_default}' does not exist")
    if effective_default in (STOCK_RUNTIME, STOCK_SHIM):
        programs.insert(0, {'kind': 'runtime', 'name': effective_default, 'default': True, 'stock': True,
                            'path': STOCK_RUNTIME, 'runtime_args': [], 'via_shell': False,
                            'argv': [STOCK_RUNTIME]})

    programs.append({'kind': 'init', 'path': init_path or DEFAULT_INIT, 'configured': bool(init_path),
                     'every_container': bool(init_enabled), 'argv': [init_path or DEFAULT_INIT]})
    proxy_on = proxy_enabled is not False
    programs.append({'kind': 'userland_proxy', 'path': proxy_path or DEFAULT_PROXY, 'configured': bool(proxy_path),
                     'enabled': proxy_on, 'argv': [proxy_path or DEFAULT_PROXY]})
    if authz:
        if all(isinstance(p, str) for p in authz):
            result['authorization_plugins'] = list(authz)
        else:
            gap('wrong_type', 'authorization-plugins entries are not all strings')

    if not result['starts']:
        result['programs'] = []
    result['complete'] = not any(g['code'] in BLOCKING for g in gaps)
    return result
