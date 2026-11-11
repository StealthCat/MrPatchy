"""Pure systemd effective-unit resolution contract (roadmap F slice, #702).

Takes captured, read-only observations of systemd system-unit search
directories (path, entry kind, symlink target, bounded file text) and returns
typed effective-unit records: which fragment wins under search-path precedence,
which fragments it shadows, which drop-ins apply in which order, the resolved
commands/account/schedule, enablement links, masking, timer/socket/path trigger
relationships and the origin of every contributing file.

It performs no I/O, never runs ``systemctl`` or a unit, never sources a script
and never authorizes a response action. Anything it cannot resolve exactly
(an uncollected search directory, unreadable or oversized text, malformed lines,
invalid names, unresolved links, over-cap inputs, runtime state) becomes an
explicit coverage gap; it is never silently reported as covered. Package
ownership is not inferred: a ``vendor`` origin means only "found in a vendor
search directory", never "verified unchanged package default".

Precedence follows ``systemd.unit(5)`` for the system manager, highest first.
Drop-ins are applied in lexicographic file-name order across every applicable
drop-in directory; for one file name the copy in the highest-precedence search
directory wins, and within one search directory the most specific directory
(unit, then template, then longest dash prefix, then unit type) wins.

A unit's names are its canonical name plus every effective alias (a winning
fragment symlink whose target file has another unit name). systemd reads drop-in
directories for all of those names, so the canonical record and every alias
record apply the same drop-in set. For one file name within one search
directory, a canonical-name directory outranks an alias-name directory of the
same specificity. An alias whose target is not the canonical name's own winning
fragment is reported as an ``alias_target_shadowed`` gap rather than guessed.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from typing import Any, Iterable

CONTRACT_VERSION = 1
MAX_OBSERVATIONS = 4096
MAX_TEXT = 65536
MAX_VALUE = 4096
MAX_NAME = 255
MAX_LINKS_PER_UNIT = 256

# (directory, origin), highest precedence first.
SEARCH_PATHS: tuple[tuple[str, str], ...] = (
    ('/etc/systemd/system.control', 'administrator'),
    ('/run/systemd/system.control', 'runtime'),
    ('/run/systemd/transient', 'transient'),
    ('/run/systemd/generator.early', 'generated'),
    ('/etc/systemd/system', 'administrator'),
    ('/run/systemd/system', 'runtime'),
    ('/run/systemd/generator', 'generated'),
    ('/usr/local/lib/systemd/system', 'local'),
    ('/usr/lib/systemd/system', 'vendor'),
    ('/lib/systemd/system', 'vendor'),
    ('/run/systemd/generator.late', 'generated'),
)
_RANK = {root: i for i, (root, _) in enumerate(SEARCH_PATHS)}
_ORIGIN = dict(SEARCH_PATHS)
# Longest roots first so '/etc/systemd/system.control' is not read as '/etc/systemd/system'.
_ROOTS_BY_LEN = sorted(_RANK, key=len, reverse=True)
# Enablement is only meaningful from administrator/runtime directories.
_ENABLEMENT_ORIGINS = frozenset({'administrator', 'runtime', 'transient', 'generated'})

UNIT_TYPES = ('service', 'socket', 'timer', 'path', 'target', 'mount', 'automount',
              'swap', 'slice', 'scope', 'device')
_NAME_RE = re.compile(r'^([A-Za-z0-9:_.\\-]+?)(@([A-Za-z0-9:_.\\-]*))?\.(' + '|'.join(UNIT_TYPES) + r')$')
_DEP_DIRS = ('wants', 'requires', 'upholds')
LIST_KEYS = frozenset({
    'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecReload',
    'ExecCondition', 'OnCalendar', 'OnBootSec', 'OnStartupSec', 'OnActiveSec',
    'OnUnitActiveSec', 'OnUnitInactiveSec', 'WantedBy', 'RequiredBy', 'Alias',
    'ListenStream', 'ListenDatagram', 'PathExists', 'PathChanged', 'PathModified',
    'Environment', 'EnvironmentFile',
})
SCALAR_KEYS = frozenset({
    'Description', 'Type', 'User', 'Group', 'DynamicUser', 'Unit', 'Persistent',
    'RemainAfterExit', 'WorkingDirectory', 'RootDirectory',
})
LIMITATIONS = (
    'Runtime active/inactive/failed state is not collected by this contract.',
    'Per-user (systemd --user) search paths are not resolved by this contract.',
    'Package ownership and vendor-default authenticity are not verified here.',
    'Specifier expansion (%i, %n, ...) and environment substitution are not performed.',
    'Only the settings named in LIST_KEYS/SCALAR_KEYS are resolved into config.',
)


def _gap(code: str, path: str = '', detail: str = '') -> dict[str, str]:
    return {'code': code, 'path': path[:512], 'detail': detail[:256]}


def parse_name(name: Any) -> dict[str, Any] | None:
    """Return name parts or None for an invalid unit name."""
    if not isinstance(name, str) or not name or len(name) > MAX_NAME:
        return None
    m = _NAME_RE.match(name)
    if not m:
        return None
    prefix, at, instance, kind = m.group(1), m.group(2), m.group(3), m.group(4)
    return {
        'name': name, 'prefix': prefix, 'type': kind,
        'template': bool(at) and instance == '',
        'instance': instance if at and instance else None,
        'template_name': f'{prefix}@.{kind}' if at else None,
    }


def _locate(path: str) -> tuple[str, str] | None:
    for root in _ROOTS_BY_LEN:
        if path.startswith(root + '/'):
            return root, path[len(root) + 1:]
    return None


def parse_unit_text(text: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Parse one fragment/drop-in into ``{section: {key: [assignments]}}``.

    Every assignment is kept in order (including empty resets) so that the
    caller can apply systemd's list-reset semantics across files. Returns the
    parsed sections and a list of problems (malformed or overlong lines).
    """
    sections: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    current: str | None = None
    pending = ''
    for raw in text.splitlines():
        line = pending + raw.strip() if pending else raw.strip()
        pending = ''
        if line.endswith('\\'):
            pending = line[:-1].rstrip() + ' '
            continue
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if '=' not in line or current is None:
            problems.append('malformed_line')
            continue
        key, value = line.split('=', 1)
        key, value = key.strip(), value.strip()
        if not key or len(value) > MAX_VALUE:
            problems.append('overlong_value' if key else 'malformed_line')
            continue
        sections[current].setdefault(key, []).append(value)
    if pending:
        problems.append('dangling_continuation')
    return sections, problems


def _merge(layers: Iterable[dict[str, dict[str, list[str]]]]) -> dict[str, dict[str, Any]]:
    """Apply fragment then drop-ins: lists reset on empty assignment, scalars last-wins."""
    out: dict[str, dict[str, Any]] = {}
    for layer in layers:
        for section, keys in layer.items():
            dest = out.setdefault(section, {})
            for key, values in keys.items():
                if key in LIST_KEYS:
                    cur = dest.get(key, [])
                    for v in values:
                        cur = [] if v == '' else cur + [v]
                    dest[key] = cur
                elif key in SCALAR_KEYS:
                    dest[key] = values[-1] if values else None
    return out


def _dropin_dirs(parts: dict[str, Any]) -> list[str]:
    """Drop-in directory names for a unit, most specific first."""
    name, kind = parts['name'], parts['type']
    dirs = [name + '.d']
    if parts['template_name'] and parts['template_name'] != name:
        dirs.append(parts['template_name'] + '.d')
    pieces = parts['prefix'].split('-')
    for i in range(len(pieces) - 1, 0, -1):
        dirs.append('-'.join(pieces[:i]) + '-.' + kind + '.d')
    dirs.append(kind + '.d')
    return dirs


def resolve(observations: Any, collected_roots: Any = None) -> dict[str, Any]:
    """Resolve effective system units from captured observations.

    ``observations`` is a list of dicts with ``path`` and ``kind`` (``file``,
    ``symlink``, ``dir`` or ``unreadable``), plus ``target`` for symlinks and
    ``text`` (and optional ``truncated``) for files. ``collected_roots`` lists
    the search directories the collector actually enumerated; every other
    search directory is reported as an uncollected coverage gap.
    """
    gaps: list[dict[str, str]] = []
    obs = observations if isinstance(observations, list) else []
    if not isinstance(observations, list):
        gaps.append(_gap('invalid_observations'))
    if len(obs) > MAX_OBSERVATIONS:
        gaps.append(_gap('observation_cap', detail=f'{len(obs)} > {MAX_OBSERVATIONS}'))
        obs = obs[:MAX_OBSERVATIONS]
    collected = set(collected_roots) if isinstance(collected_roots, (list, tuple, set, frozenset)) else set()
    for root, _ in SEARCH_PATHS:
        if root not in collected:
            gaps.append(_gap('search_path_not_collected', root))

    fragments: dict[str, list[dict[str, Any]]] = {}
    dropins: dict[tuple[str, str], list[dict[str, Any]]] = {}  # (dir name, file name)
    links: list[dict[str, Any]] = []
    by_path: dict[str, dict[str, Any]] = {}
    external: dict[str, dict[str, Any]] = {}

    for o in obs:
        if not isinstance(o, dict):
            gaps.append(_gap('invalid_observation'))
            continue
        path = o.get('path')
        if (not isinstance(path, str) or not path.startswith('/') or '\x00' in path
                or posixpath.normpath(path) != path or len(path) > 4096):
            gaps.append(_gap('invalid_path', str(path)[:512] if isinstance(path, str) else ''))
            continue
        loc = _locate(path)
        if not loc:
            # Possible target of a linked unit (``systemctl link``); kept only as link content.
            if o.get('kind') == 'file' and isinstance(o.get('text'), str):
                external[path] = {'path': path, 'origin': 'linked', 'rank': len(SEARCH_PATHS), 'kind': 'file',
                                  'text': '' if (o.get('truncated') or len(o['text']) > MAX_TEXT) else o['text'],
                                  'incomplete': bool(o.get('truncated') or len(o['text']) > MAX_TEXT)}
            else:
                gaps.append(_gap('outside_search_path', path))
            continue
        root, rel = loc
        kind = o.get('kind')
        if kind == 'dir':
            continue
        if kind == 'unreadable':
            gaps.append(_gap('unreadable', path))
            continue
        if kind not in ('file', 'symlink'):
            gaps.append(_gap('unsupported_entry_kind', path, str(kind)[:32]))
            continue
        rec = {'path': path, 'root': root, 'origin': _ORIGIN[root], 'rank': _RANK[root], 'kind': kind}
        if kind == 'symlink':
            target = o.get('target')
            if not isinstance(target, str) or not target or '\x00' in target:
                gaps.append(_gap('unresolved_link', path))
                continue
            if not target.startswith('/'):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
            rec['target'] = target
        else:
            text = o.get('text')
            if not isinstance(text, str):
                gaps.append(_gap('unreadable', path, 'no text'))
                continue
            if o.get('truncated') or len(text) > MAX_TEXT:
                gaps.append(_gap('oversized', path))
                rec['incomplete'] = True
                text = ''
            rec['text'] = text
        by_path[path] = rec
        segs = rel.split('/')
        if len(segs) == 1:
            if parse_name(segs[0]) is None:
                gaps.append(_gap('invalid_unit_name', path))
                continue
            rec['name'] = segs[0]
            fragments.setdefault(segs[0], []).append(rec)
        elif len(segs) == 2 and segs[0].endswith('.d') and kind == 'file':
            if not segs[1].endswith('.conf'):
                continue  # systemd ignores non-.conf files in drop-in dirs
            dropins.setdefault((segs[0], segs[1]), []).append(rec)
        elif len(segs) == 2 and kind == 'symlink' and segs[0].rsplit('.', 1)[-1] in _DEP_DIRS:
            owner, dep = segs[0].rsplit('.', 1)
            if parse_name(owner) is None or parse_name(segs[1]) is None:
                gaps.append(_gap('invalid_unit_name', path))
                continue
            rec.update(owner=owner, dependency=dep, name=segs[1])
            links.append(rec)
        else:
            gaps.append(_gap('unrecognized_entry', path))

    for path, rec in external.items():
        by_path.setdefault(path, rec)
    names = set(fragments)
    for link in links:
        names.add(link['name'])
        names.add(link['owner'])

    alias_target, aliases = _alias_map(fragments, by_path)

    units: list[dict[str, Any]] = []
    unit_index: dict[str, dict[str, Any]] = {}
    referenced: set[Any] = set()
    for name in sorted(names):
        parts = parse_name(name)
        if parts is None:
            continue
        unit = _resolve_unit(name, parts, fragments, dropins, by_path, links, gaps, alias_target, aliases)
        referenced.add(unit['fragment'])
        units.append(unit)
        unit_index[name] = unit

    for path in sorted(set(external) - referenced):
        gaps.append(_gap('outside_search_path', path))

    triggers: list[dict[str, Any]] = []
    for unit in units:
        if unit['type'] not in ('timer', 'socket', 'path') or unit['template'] or unit['state'] == 'masked':
            continue
        section = {'timer': 'Timer', 'socket': 'Socket', 'path': 'Path'}[unit['type']]
        explicit = unit['config'].get(section, {}).get('Unit')
        stem = unit['name'].rsplit('.', 1)[0]
        target = explicit or f'{stem}.service'
        tgt = unit_index.get(target)
        if tgt is None and parse_name(target):
            tparts = parse_name(target)
            if tparts and tparts['instance'] and tparts['template_name'] in unit_index:
                tgt = unit_index[tparts['template_name']]
        rel = {
            'trigger': unit['name'], 'type': unit['type'], 'unit': target,
            'explicit': bool(explicit), 'unit_present': bool(tgt and tgt['fragment']),
            'unit_state': tgt['state'] if tgt else 'missing',
        }
        if unit['type'] == 'timer':
            t = unit['config'].get('Timer', {})
            rel['schedule'] = {k: t[k] for k in sorted(t) if k.startswith('On') and t[k]}
        triggers.append(rel)
        if not rel['unit_present'] or rel['unit_state'] == 'masked':
            gaps.append(_gap('trigger_target_missing' if not rel['unit_present'] else 'trigger_target_masked',
                             unit['fragment'] or '', target))
        unit['triggers_unit'] = target

    gaps.sort(key=lambda g: (g['code'], g['path'], g['detail']))
    body = {'contract_version': CONTRACT_VERSION, 'units': units, 'triggers': triggers, 'gaps': gaps}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {
        **body,
        'complete': not gaps,
        'runtime_state': 'not_collected',
        'limitations': list(LIMITATIONS),
        'digest': digest,
    }


def _effective_path(rec: dict[str, Any] | None) -> str | None:
    if rec is None:
        return None
    return rec['target'] if rec['kind'] == 'symlink' else rec['path']


def _alias_map(fragments, by_path) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Map each effective alias name to its canonical name, and canonical to aliases.

    An alias is effective only when its winning fragment is a symlink to an
    observed file whose base name is a different valid, non-template unit name.
    """
    alias_target: dict[str, str] = {}
    aliases: dict[str, set[str]] = {}
    for name, recs in fragments.items():
        winner = min(recs, key=lambda r: r['rank'])
        if winner['kind'] != 'symlink' or winner['target'] == '/dev/null':
            continue
        linked = by_path.get(winner['target'])
        if linked is None or linked.get('kind') != 'file':
            continue
        canonical = posixpath.basename(winner['target'])
        parts = parse_name(name)
        cparts = parse_name(canonical)
        if (canonical == name or parts is None or cparts is None or cparts['type'] != parts['type']
                or parts['instance'] or cparts['instance']
                or canonical == parts['template_name']):
            continue
        alias_target[name] = canonical
        aliases.setdefault(canonical, set()).add(name)
    return alias_target, aliases


def _resolve_unit(name, parts, fragments, dropins, by_path, links, gaps,
                  alias_target=None, aliases=None) -> dict[str, Any]:
    alias_target = alias_target or {}
    aliases = aliases or {}
    canonical = alias_target.get(name, name)
    all_names = [canonical] + sorted(aliases.get(canonical, set()) - {canonical})
    cands = sorted(fragments.get(name, []), key=lambda r: r['rank'])
    fragment_parts = parts
    if not cands and parts['instance']:
        cands = sorted(fragments.get(parts['template_name'], []), key=lambda r: r['rank'])
        fragment_parts = parse_name(parts['template_name']) or parts
    winner = cands[0] if cands else None
    shadowed = [{'path': c['path'], 'origin': c['origin']} for c in cands[1:]]
    state = None
    incomplete = False
    alias_of = None
    text = ''
    fragment_path = None
    origin = 'unknown'
    if winner is not None:
        origin = winner['origin']
        fragment_path = winner['path']
        if winner['kind'] == 'symlink':
            target = winner['target']
            if target == '/dev/null':
                state = 'masked'
            else:
                tbase = posixpath.basename(target)
                linked = by_path.get(target)
                if linked is not None and linked.get('kind') == 'file':
                    if tbase != name and tbase != fragment_parts['name']:
                        alias_of = tbase
                    text = linked.get('text', '')
                    incomplete = bool(linked.get('incomplete'))
                    fragment_path = target
                    origin = linked['origin']
                else:
                    gaps.append(_gap('unresolved_link', winner['path'], target))
                    incomplete = True
        else:
            text = winner.get('text', '')
            incomplete = bool(winner.get('incomplete'))
            if text.strip() == '' and not incomplete:
                state = 'masked'

    if canonical != name and state != 'masked':
        canon_cands = fragments.get(canonical, [])
        canon_winner = min(canon_cands, key=lambda r: r['rank']) if canon_cands else None
        if canon_winner is not None and _effective_path(canon_winner) != fragment_path:
            gaps.append(_gap('alias_target_shadowed', winner['path'] if winner else name,
                             _effective_path(canon_winner) or ''))
            incomplete = True

    layers = []
    problems: list[str] = []
    if text and state != 'masked':
        sec, probs = parse_unit_text(text)
        layers.append(sec)
        problems.extend(probs)

    applied: list[dict[str, str]] = []
    if state != 'masked':
        spec: dict[str, tuple[int, int, int]] = {}
        scopes: dict[str, str] = {}
        for ni, n in enumerate(all_names):
            nparts = parse_name(n)
            if nparts is None:
                continue
            for pos, d in enumerate(_dropin_dirs(nparts)):
                scope = _scope(d, nparts)
                if scope == 'unit' and n != name:
                    scope = 'alias'
                key = (_SCOPE_ORDER[scope], ni, pos)
                if d not in spec or key < spec[d]:
                    spec[d] = key
                    scopes[d] = scope
        chosen: dict[str, dict[str, Any]] = {}
        for (dname, fname), recs in dropins.items():
            if dname not in spec:
                continue
            for r in recs:
                key = (r['rank'], spec[dname])
                cur = chosen.get(fname)
                if cur is None or key < cur['_key']:
                    chosen[fname] = {**r, '_key': key, '_dir': dname}
        for fname in sorted(chosen):
            r = chosen[fname]
            if r.get('incomplete'):
                incomplete = True
            sec, probs = parse_unit_text(r.get('text', ''))
            layers.append(sec)
            problems.extend(probs)
            applied.append({'path': r['path'], 'origin': r['origin'], 'scope': scopes[r['_dir']]})
    config = _merge(layers) if state != 'masked' else {}
    if problems:
        incomplete = True
        gaps.append(_gap('malformed_configuration', fragment_path or name,
                         ','.join(sorted(set(problems)))))

    enabled_by: list[dict[str, str]] = []
    static_deps: list[dict[str, str]] = []
    for link in links:
        if link['name'] != name:
            continue
        entry = {'owner': link['owner'], 'dependency': link['dependency'], 'path': link['path'],
                 'origin': link['origin']}
        tbase = posixpath.basename(link['target'])
        if link['target'] == '/dev/null':
            entry['problem'] = 'masked_link'
        elif tbase not in (name, parts['template_name'], canonical):
            entry['problem'] = 'foreign_target'
            gaps.append(_gap('foreign_link_target', link['path'], link['target']))
        (enabled_by if link['origin'] in _ENABLEMENT_ORIGINS else static_deps).append(entry)
    if len(enabled_by) > MAX_LINKS_PER_UNIT:
        gaps.append(_gap('link_cap', name, str(len(enabled_by))))
        enabled_by = enabled_by[:MAX_LINKS_PER_UNIT]
    enabled_by.sort(key=lambda e: e['path'])
    static_deps.sort(key=lambda e: e['path'])

    if state is None:
        if winner is None:
            state = 'not_found'
            if enabled_by:
                gaps.append(_gap('dangling_enablement', enabled_by[0]['path'], name))
        elif incomplete:
            state = 'unknown'
        elif origin in ('transient', 'generated'):
            state = origin
        elif any('problem' not in e for e in enabled_by) or alias_of:
            state = 'enabled'
        elif config.get('Install') and any(config['Install'].get(k) for k in ('WantedBy', 'RequiredBy', 'Alias')):
            state = 'disabled'
        else:
            state = 'static'

    vendor_present = any(c['origin'] in ('vendor', 'local') for c in cands)
    override_origins = sorted({a['origin'] for a in applied if a['origin'] not in ('vendor', 'local')})
    if origin in ('generated', 'transient', 'runtime', 'unknown', 'linked'):
        classification = origin if origin != 'linked' else 'custom'
    elif origin in ('vendor', 'local') and not override_origins:
        classification = 'vendor_location'
    elif vendor_present:
        classification = 'vendor_overridden'
    else:
        classification = 'custom'

    svc = config.get('Service', {})
    return {
        'name': name, 'type': parts['type'], 'template': parts['template'],
        'instance': parts['instance'], 'state': state, 'origin': origin,
        'classification': classification, 'package_verified': False,
        'fragment': fragment_path, 'alias_of': alias_of, 'names': sorted(all_names),
        'shadowed': shadowed,
        'dropins': applied, 'override_origins': override_origins,
        'enabled_by': enabled_by, 'static_dependencies': static_deps,
        'exec': {k: svc[k] for k in sorted(svc) if k.startswith('Exec') and svc[k]},
        'account': {'user': svc.get('User') or ('dynamic' if svc.get('DynamicUser') in ('yes', 'true', '1') else None),
                    'group': svc.get('Group')} if parts['type'] == 'service' else None,
        'privileged_exec': any(_privileged(v) for k, vs in svc.items() if k.startswith('Exec') and vs for v in vs),
        'config': config, 'incomplete': incomplete,
    }


def _privileged(value: str) -> bool:
    """True when an Exec line's prefix ('+' or '!'/'!!') bypasses User=/sandboxing."""
    m = re.match(r'^[-@:+!|]*', value)
    prefix = m.group(0) if m else ''
    return '+' in prefix or '!' in prefix


_SCOPE_ORDER = {'unit': 0, 'alias': 0, 'template': 1, 'prefix': 2, 'type': 3}


def _scope(dname: str, parts: dict[str, Any]) -> str:
    if dname == parts['name'] + '.d':
        return 'unit'
    if parts['template_name'] and dname == parts['template_name'] + '.d':
        return 'template'
    if dname == parts['type'] + '.d':
        return 'type'
    return 'prefix'
