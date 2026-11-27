"""Startup Files evaluation of runit service directories from reported metadata (#1628, increment 3)."""
import os
import random
import stat
import time

import pytest

from app import persistence, runit_services, startup_inventory
from target import agent

SERVICE, RUNIT, SV = '/etc/service', '/etc/runit', '/etc/sv'


def entry(path, mode=0o755):
    return {'path': path, 'kind': 'regular', 'uid': 0, 'gid': 0, 'mode': mode, 'size': 4, 'mtime_ns': 1, 'sha256': 'a' * 64}


def link(path, target):
    return {'path': path, 'kind': 'symlink', 'uid': 0, 'gid': 0, 'mode': 0o777, 'size': len(target), 'mtime_ns': 1,
            'target': target}


def inventory(entries, state='collected', missing=(), scope=(SERVICE, RUNIT, SV)):
    return {'scope': list(scope), 'state': state, 'entries': entries, 'gaps': [] if state == 'collected' else ['x: y'],
            'skipped': 0 if state == 'collected' else 1, 'missing_roots': list(missing)}


def debian(*extra):
    # Ubuntu 24.04 runit 2.1.2-59ubuntu1 layout: /etc/service -> runit/runsvdir/current -> default.
    return [link(SERVICE, 'runit/runsvdir/current'), link(RUNIT + '/runsvdir/current', 'default'), entry(RUNIT + '/2'),
            link(RUNIT + '/runsvdir/default/ssh', '/etc/sv/ssh'), entry(SV + '/ssh/run'), entry(SV + '/ssh/finish', 0o644),
            entry(SV + '/ssh/log/run'), link(SV + '/ssh/supervise', '/run/runit/supervise.ssh'),
            entry(SV + '/ssh/control/u'), entry(SV + '/ssh/control/t', 0o644), entry(SV + '/ssh/control/README'),
            link(RUNIT + '/runsvdir/default/getty-5', '../../../sv/getty-5'), entry(SV + '/getty-5/run'),
            entry(SV + '/getty-5/down', 0o644), *extra]


def by_name(view):
    return {s['name']: s for s in view['services']}


def programs(service):
    return {p['path']: p for p in service['programs']}


def codes(view):
    return {g['code']: g['blocking'] for g in view['gaps']}


def test_debian_layout_resolves_links_inside_the_inventory_and_reports_programs():
    view = startup_inventory.runit_view(inventory(debian()))
    assert view['resolved_directory'] == RUNIT + '/runsvdir/default'
    services = by_name(view)
    assert set(services) == {'ssh', 'getty-5'}
    ssh = programs(services['ssh'])
    assert ssh['/etc/service/ssh/run']['outcome'] == 'runs' and ssh['/etc/service/ssh/run']['argv'] == ['./run']
    assert ssh['/etc/service/ssh/finish']['outcome'] == 'not_executable'
    assert ssh['/etc/service/ssh/log/run']['outcome'] == 'runs' and services['ssh']['has_log'] is True
    assert ssh['/etc/service/ssh/control/u']['outcome'] == 'runs' and ssh['/etc/service/ssh/control/t']['outcome'] == 'no_owner_execute'
    assert ssh['/etc/service/ssh/control/README']['outcome'] == 'never_consulted'
    assert services['ssh']['wanted_down'] is False and services['getty-5']['wanted_down'] is True
    # runsvdir is not observed, so no program is claimed to start automatically or as any account.
    assert all(p['automatic'] is None for s in view['services'] for p in s['programs'] if p['role'] in ('run', 'finish', 'log_run'))
    assert view['runs'] == 4 and view['complete'] is False and view['authorizes_response'] is False
    assert codes(view) == {'supervisor_not_observed': True, 'mount_flags_unobserved': False, 'empty_directories_not_recorded': True}


def test_links_outside_the_roots_loops_and_dangling_targets_are_not_guessed():
    view = startup_inventory.runit_view(inventory(debian(
        link(RUNIT + '/runsvdir/default/ext', '/usr/share/runit/sv/ext'),
        link(RUNIT + '/runsvdir/default/gone', '/etc/sv/gone'),
        link(RUNIT + '/runsvdir/default/loop', 'loop'),
        link(RUNIT + '/runsvdir/default/escape', '../../../../usr/../etc/sv/ssh'),
        link(RUNIT + '/runsvdir/default/.hidden', '/etc/sv/ssh'),
        entry(RUNIT + '/runsvdir/default/notes.txt', 0o644),
        link(SV + '/getty-5/finish', '/usr/lib/runit/finish'))))
    services = by_name(view)
    assert services['gone']['outcome'] == 'stat_failed' and services['.hidden']['outcome'] == 'hidden_name'
    assert services['notes.txt']['outcome'] == 'not_directory'
    for name in ('ext', 'loop', 'escape'):
        assert services[name]['outcome'] == 'unresolved' and services[name]['programs'] == []
    unobserved = {g['path'] for g in view['gaps'] if g['code'] == 'symlink_target_unobserved'}
    assert unobserved == {'/etc/service/ext', '/etc/service/loop', '/etc/service/escape'}
    # A program behind a link that leaves the roots is unresolved, never reported as running or absent.
    assert '/etc/service/getty-5/finish' not in programs(services['getty-5'])
    assert [(g['code'], g['blocking']) for g in view['gaps'] if g.get('path') == '/etc/service/getty-5/finish'] == \
        [('metadata_missing', True)]


def test_incomplete_or_missing_collections_do_not_infer_absence():
    view = startup_inventory.runit_view(inventory(debian(), state='incomplete'))
    assert codes(view)['collection_incomplete'] is True
    ssh = by_name(view)['ssh']
    # down, log/down and control letters that were not recorded are unknown, not absent.
    assert ssh['wanted_down'] is None
    assert any(g['code'] == 'metadata_missing' and g['path'] == '/etc/service/ssh/down' for g in view['gaps'])
    # Roots the agent reported missing are observed absent: runsvdir would have no directory to scan.
    missing = startup_inventory.runit_view(inventory([], missing=(SERVICE, RUNIT, SV)))
    assert missing['services'] == [] and 'scan_directory_not_observed' not in codes(missing)
    # An older agent never walked these roots, so nothing about them is inferred.
    older = startup_inventory.runit_view(inventory([entry('/etc/crontab')], scope=('/etc/crontab',)))
    assert older['services'] == [] and 'scan_directory_not_observed' in codes(older)


def test_plain_service_directory_and_directory_programs():
    rows = [entry(SERVICE + '/web/run'), entry(SERVICE + '/web/run2'), entry(SERVICE + '/web/down/marker'),
            entry(SERVICE + '/web/control/z/inner'), entry(SERVICE + '/db/run/inner')]
    view = startup_inventory.runit_view(inventory(rows))
    assert view['resolved_directory'] == SERVICE
    web, db = by_name(view)['web'], by_name(view)['db']
    assert web['wanted_down'] is True
    # control/z is not a control letter, so it is never consulted whatever its type.
    assert programs(web)['/etc/service/web/control/z']['outcome'] == 'never_consulted'
    assert programs(db)['/etc/service/db/run']['outcome'] == 'not_plain_file'
    rows = [entry(SERVICE + '/web/run'), entry(SERVICE + '/web/control/u/inner')]
    control = programs(by_name(startup_inventory.runit_view(inventory(rows)))['web'])['/etc/service/web/control/u']
    assert control['outcome'] == 'unresolved'


def test_page_attaches_the_view_once_and_keeps_text_out_of_html_contexts():
    rows = debian(entry(SV + '/<img src=x>/run'), link(RUNIT + '/runsvdir/default/<img src=x>', '/etc/sv/<img src=x>'))
    view = startup_inventory.runit_view(inventory(rows))
    assert '<img src=x>' in by_name(view)
    assert all(set(p) <= {'role', 'path', 'letter', 'argv', 'cwd', 'event', 'outcome', 'reason', 'automatic'}
               for s in view['services'] for p in s['programs'])


# Seeded differential: a real tree collected by the agent and evaluated from its report must give the same services
# and programs as the contract evaluated over os.stat metadata of the same tree. Empty directories and special files
# are outside the comparison (they are disclosed as gaps).

def real_input(etc):
    def meta(path):
        try:
            info = os.stat(path)
        except FileNotFoundError:
            return {'type': 'absent'}
        kind = 'directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'other'
        return {'type': kind, 'mode': stat.S_IMODE(info.st_mode) if kind == 'file' else 0}

    def listing(path):
        found = meta(path)
        state = {'absent': 'absent', 'file': 'not_directory', 'directory': 'listed'}[found['type']]
        return {'state': state, 'entries': sorted(os.listdir(path)) if state == 'listed' else []}

    scan = os.path.join(etc, 'service')
    items = []
    for name in sorted(os.listdir(scan)):
        base = os.path.join(scan, name)
        item = {'name': name}
        found = meta(base)
        if os.path.islink(base):
            item.update(type='symlink', target=None if found['type'] == 'absent' else {'type': found['type']})
        else:
            item['type'] = found['type']
        if found['type'] == 'directory':
            log, control = listing(base + '/log'), listing(base + '/control')
            item['service'] = {'state': 'listed', 'files': {k: meta(base + '/' + k) for k in ('run', 'finish', 'down', 'log')},
                               'log': {'state': 'listed', 'files': {k: meta(base + '/log/' + k) for k in ('run', 'down')}}
                               if log['state'] == 'listed' else None,
                               'control': {'state': control['state'], 'entries': [
                                   {'name': c, **meta(base + '/control/' + c)} for c in control['entries']]}}
        items.append(item)
    return runit_services.assess({'path': SERVICE, 'state': 'listed', 'truncated': False, 'entries': items})


def build(etc, rng):
    sv = etc / 'sv'
    default = etc / 'runit' / 'runsvdir' / 'default'
    default.mkdir(parents=True)
    (etc / 'runit' / 'runsvdir' / 'current').symlink_to('default')
    (etc / 'service').symlink_to('runit/runsvdir/current')
    (etc / 'runit' / '2').write_text('#!/bin/sh\n')
    for index in range(rng.randint(1, 6)):
        name = f's{index}'
        service = sv / name
        service.mkdir(parents=True)
        (service / 'marker').write_text('')  # never empty, so the directory is recorded
        for program in ('run', 'finish'):
            choice = rng.random()
            if choice < 0.6:
                (service / program).write_text('#!/bin/sh\n')
                (service / program).chmod(rng.choice((0o755, 0o644, 0o700, 0o600)))
            elif choice < 0.7:
                (service / program).mkdir()
                (service / program / 'inner').write_text('')
        if rng.random() < 0.3:
            (service / 'down').write_text('')
        elif rng.random() < 0.1:
            (service / 'down').symlink_to('/etc/sv/missing-target')
        if rng.random() < 0.5:
            (service / 'log').mkdir()
            (service / 'log' / 'run').write_text('#!/bin/sh\n')
            (service / 'log' / 'run').chmod(rng.choice((0o755, 0o644)))
            if rng.random() < 0.3:
                (service / 'log' / 'down').write_text('')
        if rng.random() < 0.5:
            (service / 'control').mkdir()
            for letter in rng.sample(list('udxtkpcah12z') + ['README'], rng.randint(1, 4)):
                (service / 'control' / letter).write_text('#!/bin/sh\n')
                (service / 'control' / letter).chmod(rng.choice((0o755, 0o644, 0o744)))
        target = rng.choice((f'/etc/sv/{name}', f'../../../sv/{name}'))
        (default / name).symlink_to(target)
    if rng.random() < 0.5:
        (default / 'dangling').symlink_to('/etc/sv/nowhere')
    if rng.random() < 0.5:
        (default / '.hidden').symlink_to('/etc/sv/s0')
    if rng.random() < 0.3:
        (default / 'plain').write_text('')


def rebase(report, root):
    for row in report['entries']:
        row['path'] = row['path'][len(root):]
    report['scope'] = [SERVICE, RUNIT, SV]
    report['missing_roots'] = [p[len(root):] for p in report['missing_roots']]
    return report


@pytest.mark.parametrize('seed', range(40))
def test_seeded_differential_against_real_metadata(tmp_path, monkeypatch, seed):
    rng = random.Random(seed)
    root = tmp_path / 'root'
    etc = root / 'etc'
    build(etc, rng)
    # The agent collects the tree as built-in scope. Absolute link targets name /etc, so the ground truth reads the
    # tree through a chroot-like rewrite: every absolute target is repointed inside the test root first.
    roots = tuple(str(etc / p) for p in ('service', 'runit', 'sv'))
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', roots)
    monkeypatch.setattr(agent, 'SYMLINK_RECORDED_ROOTS', (roots[0],))
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', ())
    report = agent.persistence_inventory(time.monotonic() + 10, cron_jobs=True)
    assert report['state'] == 'collected', report['gaps']
    persistence.validate(rebase(report, str(root)))
    view = startup_inventory.runit_view(report)
    for directory, _, names in os.walk(etc):
        for name in names:
            path = os.path.join(directory, name)
            if os.path.islink(path) and os.readlink(path).startswith('/'):
                target = os.readlink(path)
                os.unlink(path)
                os.symlink(str(root) + target, path)
    truth = real_input(str(etc))
    expected = {s['name']: (s['outcome'], s.get('wanted_down'), s.get('has_log'),
                            sorted((p['path'], p['outcome']) for p in s['programs'])) for s in truth['services']}
    actual = {s['name']: (s['outcome'], s.get('wanted_down'), s.get('has_log'),
                          sorted((p['path'], p['outcome']) for p in s['programs'])) for s in view['services']}
    assert actual == expected
    # Only the disclosed view-level gaps and per-program mount-flag notes remain; nothing else blocks.
    assert {g['code'] for g in view['gaps']} <= {'supervisor_not_observed', 'mount_flags_unobserved', 'empty_directories_not_recorded'}


def test_startup_route_attaches_one_view_to_the_service_row(admin):
    from app.db import Host, Session
    from app.incidents import Inspection
    report = inventory(debian())
    with Session() as s:
        s.add(Host(id='one', name='one', address='192.0.2.1', fingerprint='test'))
        s.add(Inspection(id='new', host_id='one', created=time.time() - 1, report={'persistence': report}))
        s.commit()
    data = admin.get('/api/hosts/one/security/startup-inventory').json()
    holders = [r['path'] for r in data['items'] if 'runit' in r]
    assert holders == [SERVICE]
    view = next(r for r in data['items'] if 'runit' in r)['runit']
    assert set(by_name(view)) == {'ssh', 'getty-5'} and view['authorizes_response'] is False
    # A search that hides /etc/service moves the single view to the first runit row that matches.
    data = admin.get('/api/hosts/one/security/startup-inventory', params={'q': 'getty'}).json()
    assert [r['path'] for r in data['items'] if 'runit' in r] == [RUNIT + '/runsvdir/default/getty-5']
