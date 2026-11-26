"""Pure DKMS root-execution contract (roadmap F slice, #1524).

Takes observations of the files ``dkms`` reads and reports:

* which files it sources with bash as root, in order;
* which ``POST_ADD``/``PRE_BUILD``/``POST_BUILD``/``PRE_INSTALL``/``POST_INSTALL``/``POST_REMOVE``
  hook programs it runs as root for each module, from which directory and with which argv;
* which ``MAKE[n]``/``CLEAN`` commands it ``eval``s as root.

It never runs anything and never reads the hook programs.

Semantics come from ``/usr/sbin/dkms`` in Ubuntu 24.04 ``dkms 3.0.11-1ubuntu13``
(``safe_source``, ``read_conf``, ``read_framework_conf``, ``run_build_script``,
``prepare_build``, ``actual_build``). They were checked against that dkms running as root:

* ``read_framework_conf`` sources ``/etc/dkms/framework.conf`` and then the
  ``/etc/dkms/framework.conf.d/*.conf`` glob. Other names are skipped. ``read_conf`` sources the module's
  ``dkms.conf`` and then ``/etc/dkms/<module>.conf``, ``<module>-<version>.conf``,
  ``<module>-<version>-<kernel>.conf`` and ``<module>-<version>-<kernel>-<arch>.conf``,
  skipping missing ones. Each file is executed with ``.`` by root, so **every line is root
  shell code**, not only the assignments dkms keeps. Even ``dkms status`` sources each built
  module's ``dkms.conf``. The kernel ``postinst.d``/``prerm.d``/``header_postinst.d``/``install.d``
  hooks run dkms on every kernel package change.
* ``safe_source`` keeps only dkms' listed variables. It echoes each array element back unquoted,
  as ``NAME[i]="${NAME[i]}"``, and sources that again. So each kept value is word-split,
  glob-expanded in dkms' working directory, joined with single spaces, and then **re-parsed in
  double quotes**. A ``$``, backtick, ``\\`` or ``"`` in a value, even one written in single
  quotes, is interpreted again, and ``$(...)`` executes. Array elements accumulate across the
  chain, and the last assignment to an element wins.
* ``run_build_script`` builds ``$dkms_tree/<module>/<version>/<dir>/<value>``. ``<dir>`` is
  ``build`` for ``PRE_BUILD``/``POST_BUILD`` (a copy of the source tree made by
  ``prepare_build``) and ``source`` otherwise. It runs the value only when ``-x`` holds for the
  text before the first space, and then calls ``exec $run`` from that directory: unquoted, word-split
  and glob-expanded, without a shell. A value starting with ``/`` stays under that directory
  (``build//x``).
* ``CLEAN`` and the ``MAKE[n]`` selected by ``MAKE_MATCH[n]`` regexes against the kernel are
  ``eval``ed as root. Without ``MAKE[0]``, dkms runs ``make -C <kernel source> M=<build dir>``.

It performs no I/O and never authorizes a response action. Anything not understood is reported
as ``unknown`` with a named gap, never as "does not run".
"""
from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = 1
REFERENCE = {
    'package': 'dkms',
    'version': '3.0.11-1ubuntu13 (Ubuntu 24.04)',
    'source': '/usr/sbin/dkms: safe_source, read_conf, read_framework_conf, run_build_script, actual_build',
}
RUNS_AS = 'root'
FRAMEWORK_FILE = '/etc/dkms/framework.conf'
FRAMEWORK_DIR = '/etc/dkms/framework.conf.d'
ETC_DKMS = '/etc/dkms'
DEFAULT_DKMS_TREE = '/var/lib/dkms'
HOOKS = (
    ('POST_ADD', 'source', 'dkms add, and autoinstall of a module that is not yet added'),
    ('PRE_BUILD', 'build', 'dkms build/install/autoinstall, before make'),
    ('POST_BUILD', 'build', 'dkms build/install/autoinstall, after a successful make'),
    ('PRE_INSTALL', 'source', 'dkms install/autoinstall; a non-zero exit aborts the install unless --force'),
    ('POST_INSTALL', 'source', 'dkms install/autoinstall, after the module is copied'),
    ('POST_REMOVE', 'source', 'dkms remove/uninstall of an installed module, including kernel removal'),
)
CONF_VARIABLES = frozenset((
    'CLEAN PACKAGE_NAME PACKAGE_VERSION POST_ADD POST_BUILD POST_INSTALL POST_REMOVE PRE_BUILD PRE_INSTALL '
    'BUILD_DEPENDS BUILD_EXCLUSIVE_ARCH BUILD_EXCLUSIVE_CONFIG BUILD_EXCLUSIVE_KERNEL BUILD_EXCLUSIVE_KERNEL_MIN '
    'BUILD_EXCLUSIVE_KERNEL_MAX build_exclude OBSOLETE_BY MAKE MAKE_MATCH PATCH PATCH_MATCH patch_array '
    'BUILT_MODULE_NAME built_module_name BUILT_MODULE_LOCATION built_module_location DEST_MODULE_NAME '
    'dest_module_name DEST_MODULE_LOCATION dest_module_location STRIP strip AUTOINSTALL NO_WEAK_MODULES '
    'SIGN_FILE MOK_SIGNING_KEY MOK_CERTIFICATE REMAKE_INITRD MODULES_CONF MODULES_CONF_OBSOLETES '
    'MODULES_CONF_ALIAS_TYPE MODULES_CONF_OBSOLETE_ONLY').split())
FRAMEWORK_VARIABLES = frozenset((
    'source_tree dkms_tree install_tree tmp_location verbose symlink_modules autoinstall_all_kernels '
    'modprobe_on_install sign_file mok_signing_key mok_certificate').split())
STATES = ('file', 'directory', 'absent', 'unreadable', 'other')
MAX_BYTES = 262144
MAX_MODULES = 256
MAX_DIR_ENTRIES = 512
MAX_GAPS = 64
MAX_UNPARSED = 16
BLOCKING = frozenset({'input_malformed', 'path_not_observed', 'path_unreadable', 'path_other_type',
                      'too_large', 'too_many_entries', 'gaps_truncated'})
UNOBSERVED = (
    'Whether dkms is installed and which kernels and headers trigger builds are not observed.',
    ('The contents, owner and permissions of hook programs are not read; the executable bit is taken '
     'from the caller.'),
    ('The make command dkms picks by MAKE_MATCH regex for a given kernel is not resolved; every candidate '
     'is listed.'),
    'Directives given with --directive on a dkms command line are not observed.',
)
NOT_A_VERDICT = 'Configuration text only. This is not a safety verdict and origin is not assessed.'

_NAME = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)(?:\[([0-9]+)\])?=')
_BARE = re.compile(r"[A-Za-z0-9_./:,+=@%^-]*")  # no ~: tilde expansion
_SHELL_SPECIAL = frozenset('$`\\"')
_GLOB = frozenset('*?[')


def _gap(gaps: list[dict[str, Any]], code: str, detail: str, path: str | None = None) -> None:
    if len(gaps) >= MAX_GAPS:
        if gaps[-1]['code'] != 'gaps_truncated':
            gaps[-1] = {'code': 'gaps_truncated', 'detail': f'Only the first {MAX_GAPS - 1} gaps are listed.'}
        return
    gap: dict[str, Any] = {'code': code, 'detail': detail}
    if path is not None:
        gap['path'] = path
    gaps.append(gap)


def _value(rest: str) -> tuple[str, str] | None:
    """Parse one shell word made only of literal parts; return (value, remainder) or None."""
    out: list[str] = []
    i = 0
    while i < len(rest) and rest[i] not in ' \t':
        c = rest[i]
        if c == "'":
            end = rest.find("'", i + 1)
            if end < 0:
                return None
            out.append(rest[i + 1:end])
            i = end + 1
        elif c == '"':
            end = rest.find('"', i + 1)
            if end < 0:
                return None
            inner = rest[i + 1:end]
            if any(ch in _SHELL_SPECIAL for ch in inner):
                return None
            out.append(inner)
            i = end + 1
        else:
            match = _BARE.match(rest, i)
            if not match or match.end() == i:
                return None
            out.append(match.group())
            i = match.end()
    return ''.join(out), rest[i:]


def parse_assignments(text: str) -> dict[str, Any]:
    """Accept only blank lines, comments and ``NAME[=|[i]=]literal`` lines.

    Anything else (commands, expansions, functions, continuations, several words) leaves the
    file not ``understood``; its effect on any variable is then unknown.
    """
    assignments: list[dict[str, Any]] = []
    unparsed: list[dict[str, Any]] = []
    for number, raw in enumerate(text.split('\n'), 1):
        line = raw.lstrip(' \t')
        if not line or line.startswith('#'):
            continue
        match = _NAME.match(line)
        parsed = _value(line[match.end():]) if match else None
        if parsed is not None:
            remainder = parsed[1].lstrip(' \t')
            if remainder and not remainder.startswith('#'):
                parsed = None
        if match is None or parsed is None or raw.endswith('\\') or match.group(1).startswith('DKMS_DIRECTIVE'):
            if len(unparsed) < MAX_UNPARSED:
                unparsed.append({'line': number, 'text': raw[:128]})
            else:
                unparsed[-1] = {'line': number, 'text': '(further lines not listed)'}
            continue
        assignments.append({'name': match.group(1), 'index': int(match.group(2) or 0),
                            'value': parsed[0], 'line': number})
    return {'understood': not unparsed, 'assignments': assignments, 'unparsed': unparsed}


def echo_back(value: str) -> dict[str, Any]:
    """What one value becomes after safe_source's unquoted echo and double-quoted re-source."""
    words = value.split()
    if any(ch in _GLOB for word in words for ch in word):
        return {'state': 'unknown', 'reason': 'glob_in_value',
                'detail': 'The value is glob-expanded in dkms\' working directory before it is kept.'}
    joined = ' '.join(words)
    if any(ch in _SHELL_SPECIAL for ch in joined):
        executes = '$(' in joined or '`' in joined
        return {'state': 'unknown', 'reason': 'reinterpreted_value', 'executes_when_sourced': executes,
                'detail': 'dkms re-parses the value in double quotes; $, `, \\ and " are interpreted again'
                          + (' and the command substitution runs as root.' if executes else '.')}
    return {'state': 'known', 'value': joined}


def _observe_file(path: str, obs: Any, gaps: list[dict[str, Any]], *, required: bool) -> str | None:
    if obs is None:
        if required:
            _gap(gaps, 'path_not_observed', 'dkms sources this path when it exists; it was not observed.', path)
        return None
    if not isinstance(obs, dict) or obs.get('state') not in STATES:
        _gap(gaps, 'input_malformed', f'State must be one of {", ".join(STATES)}.', path)
        return None
    state = obs['state']
    if state == 'absent':
        return None
    if state == 'unreadable':
        _gap(gaps, 'path_unreadable', 'dkms (as root) sources this path, but its content was not observed.', path)
        return None
    if state != 'file':
        _gap(gaps, 'path_other_type', 'Not a regular file; bash still tries to source it as root.', path)
        return None
    text = obs.get('text')
    if not isinstance(text, str):
        _gap(gaps, 'input_malformed', 'A file observation needs its text.', path)
        return None
    if len(text.encode('utf-8', 'surrogateescape')) > MAX_BYTES:
        _gap(gaps, 'too_large', f'Larger than {MAX_BYTES} bytes; not evaluated.', path)
        return None
    return text


def _framework_files(paths: dict[str, Any], gaps: list[dict[str, Any]]) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    text = _observe_file(FRAMEWORK_FILE, paths.get(FRAMEWORK_FILE), gaps, required=True)
    if text is not None:
        files.append((FRAMEWORK_FILE, text))
    directory = paths.get(FRAMEWORK_DIR)
    if directory is None:
        _gap(gaps, 'path_not_observed', 'dkms sources *.conf from this directory; it was not observed.',
             FRAMEWORK_DIR)
        return files
    if not isinstance(directory, dict) or directory.get('state') not in ('directory', 'absent'):
        _gap(gaps, 'input_malformed', 'The drop-in directory must be a directory or absent.', FRAMEWORK_DIR)
        return files
    entries = directory.get('entries') or {}
    if not isinstance(entries, dict):
        _gap(gaps, 'input_malformed', 'A directory observation needs an entries mapping.', FRAMEWORK_DIR)
        return files
    if len(entries) > MAX_DIR_ENTRIES:
        _gap(gaps, 'too_many_entries', f'More than {MAX_DIR_ENTRIES} entries; none were evaluated.', FRAMEWORK_DIR)
        return files
    names = sorted((n for n in entries if isinstance(n, str) and n.endswith('.conf') and not n.startswith('.')
                    and '/' not in n), key=lambda n: n.encode('utf-8', 'surrogateescape'))
    if len(names) > 1:
        _gap(gaps, 'order_locale_dependent', 'Glob order follows the collation locale dkms runs with; byte '
             'order is shown.', FRAMEWORK_DIR)
    for name in names:
        child = f'{FRAMEWORK_DIR}/{name}'
        text = _observe_file(child, entries[name], gaps, required=True)
        if text is not None:
            files.append((child, text))
    return files


def _merge(files: list[tuple[str, str]], wanted: frozenset[str]) -> tuple[list[dict[str, Any]], dict, bool]:
    """Source files in order; return per-file reports, kept values and whether all were understood."""
    reports: list[dict[str, Any]] = []
    values: dict[tuple[str, int], dict[str, Any]] = {}
    understood = True
    for path, text in files:
        parsed = parse_assignments(text)
        understood = understood and parsed['understood']
        kept = [a for a in parsed['assignments'] if a['name'] in wanted]
        for item in kept:
            values[(item['name'], item['index'])] = {**echo_back(item['value']), 'path': path, 'line': item['line']}
        reports.append({'path': path, 'sourced_as': RUNS_AS, 'only_literal_assignments': parsed['understood'],
                        'unparsed_lines': parsed['unparsed'], 'kept_assignments': len(kept)})
    return reports, values, understood


def _hook(name: str, where: str, when: str, values: dict, understood: bool, tree: str | None,
          module: str, version: str, executables: dict[str, Any]) -> dict[str, Any]:
    base = {'hook': name, 'directory_kind': where, 'when': when, 'runs_as': RUNS_AS, 'shell': False}
    if not understood:
        return {**base, 'state': 'unknown', 'reason': 'conf_not_understood'}
    entry = values.get((name, 0))
    if entry is None or (entry['state'] == 'known' and entry['value'] == ''):
        return {**base, 'state': 'not_configured'}
    source = {'path': entry['path'], 'line': entry['line']}
    if entry['state'] != 'known':
        return {**base, 'state': 'unknown', 'reason': entry['reason'], 'source': source}
    argv_tail = entry['value'].split(' ')
    if tree is None:
        return {**base, 'state': 'unknown', 'reason': 'dkms_tree_unknown', 'value': entry['value'],
                'source': source}
    directory = f'{tree}/{module}/{version}/{where}'
    program = f'{directory}/{argv_tail[0]}'
    executable = executables.get(program)
    state = {True: 'runs', False: 'skipped_not_executable'}.get(executable, 'unknown')
    result = {**base, 'state': state, 'directory': directory, 'program': program,
              'argv': [program, *argv_tail[1:]], 'source': source}
    if where == 'build':
        result['copied_from'] = f'{tree}/{module}/{version}/source/{argv_tail[0]}'
    if state == 'unknown':
        result['reason'] = 'executable_bit_not_observed'
    return result


def _make_commands(values: dict, understood: bool) -> dict[str, Any]:
    if not understood:
        return {'state': 'unknown', 'reason': 'conf_not_understood'}
    candidates = []
    for (name, index), entry in sorted(values.items()):
        if name != 'MAKE':
            continue
        match = values.get(('MAKE_MATCH', index))
        candidates.append({'index': index, 'eval_as': RUNS_AS, 'source': {'path': entry['path'], 'line': entry['line']},
                           **({'command': entry['value']} if entry['state'] == 'known' else
                              {'state': 'unknown', 'reason': entry['reason']}),
                           'match_regex': (match.get('value', 'unknown') if match else None)})
    clean = values.get(('CLEAN', 0))
    default_used = ('MAKE', 0) not in values or ('MAKE_MATCH', 0) in values
    return {'state': 'known', 'make_candidates': candidates,
            'default_make_possible': default_used,
            'clean': (None if clean is None else clean.get('value', 'unknown')),
            'note': 'dkms evals the selected make command and CLEAN as root shell code.'}


def assess(paths: Any = None, modules: Any = None, kernels: Any = None,
           executables: Any = None) -> dict[str, Any]:
    """Resolve what dkms runs as root.

    ``paths`` maps absolute paths to ``{'state': ..., 'text': ...}`` (``framework.conf``,
    ``framework.conf.d`` with ``entries``, ``/etc/dkms`` with ``entries`` for the override
    listing, and each module's ``dkms.conf``). ``modules`` lists ``{'module', 'version', 'conf'}``,
    with ``conf`` being the observed ``dkms.conf`` path. ``kernels`` lists ``{'kernel', 'arch'}``
    contexts. ``executables`` maps resolved hook program paths to the observed ``-x`` result.
    """
    gaps: list[dict[str, Any]] = []
    if not isinstance(paths, dict) or not isinstance(modules or [], list) or not isinstance(kernels or [], list) \
            or not isinstance(executables or {}, dict):
        _gap(gaps, 'input_malformed', 'paths and executables must be mappings; modules and kernels lists.')
        paths, modules, kernels, executables = {}, [], [], {}
    modules, kernels, executables = modules or [], kernels or [], executables or {}
    if len(modules) > MAX_MODULES:
        _gap(gaps, 'too_many_entries', f'More than {MAX_MODULES} modules; none were evaluated.')
        modules = []
    framework, fw_values, fw_understood = _merge(_framework_files(paths, gaps), FRAMEWORK_VARIABLES)
    tree_entry = fw_values.get(('dkms_tree', 0))
    tree: str | None = DEFAULT_DKMS_TREE
    if not fw_understood:
        tree = None
    elif tree_entry is not None:
        tree = tree_entry.get('value') if tree_entry['state'] == 'known' else None
        if tree is not None and (not tree.startswith('/') or ' ' in tree):
            tree = None
    sign_file = fw_values.get(('sign_file', 0))
    listing = paths.get(ETC_DKMS)
    etc_names: set[str] | None = None
    if isinstance(listing, dict) and listing.get('state') == 'directory' and isinstance(listing.get('entries'), dict):
        etc_names = {n for n in listing['entries'] if isinstance(n, str)}
    elif modules:
        _gap(gaps, 'path_not_observed', 'The /etc/dkms listing decides which per-module overrides exist.', ETC_DKMS)
    contexts = [(k.get('kernel'), k.get('arch')) for k in kernels if isinstance(k, dict)] or [(None, None)]
    results = []
    for item in modules:
        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) and item.get(k)
                                                 for k in ('module', 'version', 'conf')):
            _gap(gaps, 'input_malformed', 'Each module needs module, version and conf strings.')
            continue
        module, version, conf = item['module'], item['version'], item['conf']
        for kernel, arch in contexts:
            local: list[dict[str, Any]] = []
            chain: list[tuple[str, str]] = []
            text = _observe_file(conf, paths.get(conf), local, required=True)
            if text is not None:
                chain.append((conf, text))
            candidates = [f'{module}.conf', f'{module}-{version}.conf']
            if kernel:
                candidates.append(f'{module}-{version}-{kernel}.conf')
                if arch:
                    candidates.append(f'{module}-{version}-{kernel}-{arch}.conf')
            elif etc_names and any(n.startswith(f'{module}-{version}-') and n.endswith('.conf') for n in etc_names):
                _gap(local, 'kernel_override_unresolved', 'A kernel-specific override exists; pass kernels to '
                     'resolve it.', ETC_DKMS)
            for name in candidates:
                if etc_names is not None and name not in etc_names:
                    continue
                path = f'{ETC_DKMS}/{name}'
                text = _observe_file(path, paths.get(path), local, required=etc_names is not None)
                if text is not None:
                    chain.append((path, text))
            reports, values, understood = _merge(chain, CONF_VARIABLES)
            understood = understood and etc_names is not None and \
                not any(g['code'] in BLOCKING or g['code'] == 'kernel_override_unresolved' for g in local)
            hooks = [_hook(name, where, when, values, understood, tree, module, version, executables)
                     for name, where, when in HOOKS]
            results.append({'module': module, 'version': version, 'kernel': kernel, 'arch': arch,
                            'sourced_files': reports, 'hooks': hooks,
                            'make': _make_commands(values, understood), 'gaps': local})
            for gap in local:
                _gap(gaps, gap['code'], gap['detail'], gap.get('path'))
    blocking = sorted({g['code'] for g in gaps if g['code'] in BLOCKING})
    return {
        'contract_version': CONTRACT_VERSION,
        'reference': dict(REFERENCE),
        'framework': {'sourced_files': framework, 'dkms_tree': tree,
                      'sign_file': None if sign_file is None else sign_file.get('value', 'unknown')},
        'modules': results,
        'complete': not blocking,
        'blocking_gaps': blocking,
        'gaps': gaps,
        'unobserved': list(UNOBSERVED),
        'origin': 'not_assessed',
        'not_a_verdict': NOT_A_VERDICT,
        'authorizes_response': False,
    }
