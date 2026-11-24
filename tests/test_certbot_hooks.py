import importlib.util
import os
import stat
import sys
import types

import pytest

from app import certbot_hooks as cb

SCRIPT = {'type': 'file', 'mode': 0o755, 'noexec': False}


def _listing(*entries, **kw):
    return dict({'state': 'listed', 'entries': list(entries)}, **kw)


def _dirs(pre=None, deploy=None, post=None):
    empty = _listing()
    return {'pre': pre or empty, 'deploy': deploy or empty, 'post': post or empty}


def _run(directories=None, **kw):
    kw.setdefault('family', 'debian')
    kw.setdefault('certbot_installed', True)
    if directories is None:
        directories = _dirs(deploy=_listing(dict(SCRIPT, name='reload-nginx')))
    return cb.assess(directories, **kw)


def _outcomes(result, phase):
    return [(s['name'], s['outcome']) for s in result['phases'][phase]['scripts']]


def _codes(result):
    return {g['code'] for g in result['gaps']}


def test_hooks_run_as_root_through_the_shell_in_sorted_order_per_phase():
    result = _run(_dirs(
        pre=_listing(dict(SCRIPT, name='stop-haproxy')),
        deploy=_listing(dict(SCRIPT, name='reload.sh'), dict(SCRIPT, name='Zed'), dict(SCRIPT, name='.hidden'),
                        dict(SCRIPT, name='000first'), dict(SCRIPT, name='app.dpkg-dist')),
        post=_listing(dict(SCRIPT, name='start-haproxy')),
    ))
    assert result['complete'] is True and result['gaps'] == []
    assert result['applicability'] == 'applicable'
    assert result['runs_as'] == 'root' and result['shell'] == ('/bin/sh', '-c', 'HOOK_PATH')
    assert result['stops_on_failure'] is False
    deploy = result['phases']['deploy']
    # Python sorted() code-point order, with no run-parts name filter: dotfiles and suffixes run.
    assert [n for n, _ in _outcomes(result, 'deploy')] == ['.hidden', '000first', 'Zed', 'app.dpkg-dist',
                                                           'reload.sh']
    assert deploy['run_order'] == [f'{cb.HOOK_DIRS["deploy"]}/{n}'
                                   for n in ('.hidden', '000first', 'Zed', 'app.dpkg-dist', 'reload.sh')]
    assert result['phases']['pre']['run_order'] == ['/etc/letsencrypt/renewal-hooks/pre/stop-haproxy']
    assert result['phases']['post']['run_order'] == ['/etc/letsencrypt/renewal-hooks/post/start-haproxy']
    assert any('RENEWED_LINEAGE' in e for e in deploy['environment'])
    assert any('FAILED_DOMAINS' in e for e in result['phases']['post']['environment'])
    assert result['phases']['pre']['environment'] == ()
    assert any('dry-run' in e for e in deploy['events'])
    assert all('renew' in e for e in result['phases']['pre']['events'] + result['phases']['post']['events'])
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['not_a_verdict']


def test_type_mode_backup_and_mount_rules():
    result = _run(_dirs(deploy=_listing(
        dict(SCRIPT, name='ok'),
        dict(SCRIPT, name='ok~'),
        {'name': 'plain', 'type': 'file', 'mode': 0o644, 'noexec': False},
        {'name': 'sub', 'type': 'directory', 'mode': 0o755},
        {'name': 'fifo', 'type': 'other'},
        dict(SCRIPT, name='nx', noexec=True),
        {'name': 'gone', 'type': 'symlink', 'target': None},
        {'name': 'link', 'type': 'symlink', 'target': dict(SCRIPT)},
        {'name': 'linkdir', 'type': 'symlink', 'target': {'type': 'directory'}},
        {'name': 'linkfifo', 'type': 'symlink', 'target': {'type': 'other'}},
    )))
    assert dict(_outcomes(result, 'deploy')) == {
        'ok': 'runs', 'ok~': 'backup_name', 'plain': 'not_executable', 'sub': 'directory',
        'fifo': 'not_plain_file', 'nx': 'noexec_mount', 'gone': 'stat_failed', 'link': 'runs',
        'linkdir': 'directory', 'linkfifo': 'not_plain_file',
    }
    assert result['phases']['deploy']['run_order'] == [f'{cb.HOOK_DIRS["deploy"]}/link',
                                                       f'{cb.HOOK_DIRS["deploy"]}/ok']
    assert result['complete'] is True
    assert all(s['reason'] == cb.REASONS[s['outcome']] for s in result['phases']['deploy']['scripts'])


def test_any_execute_bit_is_enough_for_root():
    for mode in (0o100, 0o010, 0o001, 0o4711):
        result = _run(_dirs(deploy=_listing(dict(SCRIPT, name='hook', mode=mode))))
        assert _outcomes(result, 'deploy') == [('hook', 'runs')], oct(mode)


@pytest.mark.parametrize('name', ['two words', 'a;b', 'x$(id)', 'q`id`', 'g*', 'b{1,2}', 'tab\there', 'r>out',
                                  "it's", 'nl\nx', 'bs\\x'])
def test_shell_special_names_run_as_shell_text_and_block(name):
    result = _run(_dirs(deploy=_listing(dict(SCRIPT, name=name))))
    assert _outcomes(result, 'deploy') == [(name, 'runs_as_shell_text')]
    assert result['phases']['deploy']['run_order'] == [f'{cb.HOOK_DIRS["deploy"]}/{name}']
    assert 'shell_reinterpreted' in _codes(result) and result['complete'] is False


@pytest.mark.parametrize('name', ['a-b_c.d', 'v1:2', 'a=b', 'x%y', 'a,b', 'p+q', 'm@n', 'mid~tilde', 'ñ', 'a#b',
                                  'x]y', 'bang!'])
def test_shell_neutral_names_are_plain_runs(name):
    result = _run(_dirs(deploy=_listing(dict(SCRIPT, name=name))))
    assert _outcomes(result, 'deploy') == [(name, 'runs')]
    assert result['complete'] is True


@pytest.mark.parametrize('state', ['absent', 'not_directory'])
def test_missing_or_non_directory_runs_nothing(state):
    result = _run(_dirs(deploy={'state': state}))
    assert result['phases']['deploy']['state'] == state
    assert result['phases']['deploy']['run_order'] == []
    assert result['complete'] is True
    if state == 'not_directory':
        assert 'directory_breaks_renewal' in _codes(result)
        assert 'directory_breaks_renewal' not in cb.BLOCKING


def test_applicability():
    assert _run(family='rpm')['applicability'] == 'applicable'
    assert _run(certbot_installed=False)['applicability'] == 'not_applicable'
    result = _run(family=None)
    assert result['applicability'] == 'unknown' and 'family_not_observed' in _codes(result)
    assert result['complete'] is False
    result = _run(family='arch')
    assert 'family_unsupported' in _codes(result) and result['complete'] is False
    result = _run(certbot_installed=None)
    assert result['applicability'] == 'unknown' and 'implementation_not_observed' in _codes(result)
    assert result['complete'] is False
    result = _run(certbot_installed='yes')
    assert 'implementation_not_observed' in _codes(result) and result['complete'] is False


@pytest.mark.parametrize('deploy, code', [
    (None, 'directory_not_observed'),
    ({'state': 'unreadable'}, 'directory_unreadable'),
    ({'state': 'weird'}, 'input_malformed'),
    ('listed', 'input_malformed'),
    (_listing(dict(SCRIPT, name='a'), truncated=True), 'listing_incomplete'),
    ({'state': 'listed', 'entries': 'a'}, 'input_malformed'),
    ({'state': 'listed', 'entries': [dict(SCRIPT, name=f'h{i}') for i in range(cb.MAX_ENTRIES + 1)]},
     'too_many_entries'),
    (_listing(dict(SCRIPT, name='a'), dict(SCRIPT, name='a')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='a/b')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='..')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='a\0b')), 'input_malformed'),
    (_listing('a'), 'input_malformed'),
    (_listing({'name': 'a', 'type': 'file'}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'file', 'mode': True}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'file', 'mode': 0o10000}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'file', 'mode': 0o755, 'noexec': 'no'}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'socket'}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'symlink'}), 'symlink_target_unobserved'),
    (_listing({'name': 'a', 'type': 'symlink', 'target': {'type': 'file'}}), 'metadata_missing'),
])
def test_blocking_gaps_fail_closed(deploy, code):
    directories = _dirs()
    directories['deploy'] = deploy
    result = cb.assess(directories, family='debian', certbot_installed=True)
    assert code in _codes(result)
    assert code in cb.BLOCKING
    assert result['complete'] is False


def test_unobserved_directories_and_malformed_map_block():
    result = cb.assess(None, family='debian', certbot_installed=True)
    assert [g['path'] for g in result['gaps']] == [cb.HOOK_DIRS[p] for p in cb.PHASES]
    assert result['complete'] is False
    result = cb.assess({'pre': _listing(), 'deploy': _listing()}, family='debian', certbot_installed=True)
    assert result['phases']['post']['state'] == 'not_observed' and result['complete'] is False
    result = cb.assess(['pre'], family='debian', certbot_installed=True)
    assert 'input_malformed' in _codes(result) and result['complete'] is False


def test_unresolved_entries_are_never_reported_as_running():
    result = _run(_dirs(deploy=_listing({'name': 'a', 'type': 'symlink'}, {'name': 'b', 'type': 'file'})))
    assert _outcomes(result, 'deploy') == [('a', 'unresolved'), ('b', 'unresolved')]
    assert result['phases']['deploy']['run_order'] == []


def test_unobserved_mount_flags_are_a_non_blocking_gap():
    result = _run(_dirs(deploy=_listing({'name': 'hook', 'type': 'file', 'mode': 0o755})))
    assert _outcomes(result, 'deploy') == [('hook', 'runs')]
    assert _codes(result) == {'mount_flags_unobserved'}
    assert 'mount_flags_unobserved' not in cb.BLOCKING
    assert result['complete'] is True


def test_gap_list_is_bounded():
    entries = [{'name': f'h{i:03d}', 'type': 'symlink'} for i in range(200)]
    result = _run(_dirs(deploy=_listing(*entries)))
    assert len(result['gaps']) == cb.MAX_GAPS
    assert result['gaps'][-1]['code'] == 'gaps_truncated'
    assert result['complete'] is False


def test_input_is_not_mutated_and_result_has_no_response_authority():
    directories = _dirs(deploy=_listing(dict(SCRIPT, name='b'), dict(SCRIPT, name='a')))
    snapshot = repr(directories)
    result = _run(directories)
    assert repr(directories) == snapshot
    flat = repr(result).lower()
    for word in ('quarantine', 'terminate', 'approve', 'authoriz'):
        assert word not in flat


# Differential against certbot's real hooks.py: its listing, ordering, deduplication, environment and
# /bin/sh execution code runs unchanged against temporary hook directories. Point MRPATCHY_CERTBOT_SOURCE
# at an unpacked certbot wheel (the directory containing the ``certbot`` package), or install certbot.

def _certbot_source():
    root = os.environ.get('MRPATCHY_CERTBOT_SOURCE')
    if root:
        return root if os.path.isfile(os.path.join(root, 'certbot', '_internal', 'hooks.py')) else None
    try:
        spec = importlib.util.find_spec('certbot')
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.submodule_search_locations:
        return None
    return os.path.dirname(list(spec.submodule_search_locations)[0])


_SOURCE = _certbot_source()
real = pytest.mark.skipif(not (_SOURCE and os.path.exists('/bin/sh') and os.name == 'posix'),
                          reason='needs certbot source (MRPATCHY_CERTBOT_SOURCE or an installed certbot)')


def _load(name, path, monkeypatch, package=False):
    spec = importlib.util.spec_from_file_location(
        name, path, submodule_search_locations=[os.path.dirname(path)] if package else None)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def _stub(name, monkeypatch, **attrs):
    module = types.ModuleType(name)
    module.__path__ = []
    module.__dict__.update(attrs)
    monkeypatch.setitem(sys.modules, name, module)
    return module


@pytest.fixture
def real_hooks(monkeypatch):
    """Load certbot's own hooks.py and compat modules; stub only logging/display and unused helpers."""
    for name in [m for m in sys.modules if m == 'certbot' or m.startswith('certbot.')]:
        monkeypatch.delitem(sys.modules, name)
    pkg = os.path.join(_SOURCE, 'certbot')
    _stub('certbot', monkeypatch)
    _load('certbot.errors', os.path.join(pkg, 'errors.py'), monkeypatch)
    _stub('certbot.compat', monkeypatch)
    _load('certbot.compat._path', os.path.join(pkg, 'compat', '_path.py'), monkeypatch)
    _load('certbot.compat.os', os.path.join(pkg, 'compat', 'os.py'), monkeypatch)
    filesystem = _load('certbot.compat.filesystem', os.path.join(pkg, 'compat', 'filesystem.py'), monkeypatch)
    _load('certbot.compat.misc', os.path.join(pkg, 'compat', 'misc.py'), monkeypatch)
    _stub('certbot.configuration', monkeypatch, NamespaceConfig=object)
    # Outside a snap, certbot's env_no_snap_for_external_calls() is a plain copy of os.environ.
    _stub('certbot.util', monkeypatch, env_no_snap_for_external_calls=lambda: os.environ.copy(),
          exe_exists=lambda exe: filesystem.is_executable(exe))
    _stub('certbot.plugins', monkeypatch)
    _stub('certbot.plugins.util', monkeypatch, path_surgery=lambda cmd: None)
    _stub('certbot.display', monkeypatch)
    _stub('certbot.display.ops', monkeypatch, report_executed_command=lambda *a: None)
    for key in ('RENEWED_DOMAINS', 'RENEWED_LINEAGE', 'FAILED_DOMAINS'):
        monkeypatch.delenv(key, raising=False)
    saved = dict(os.environ)
    yield _load('certbot._internal.hooks', os.path.join(pkg, '_internal', 'hooks.py'), monkeypatch)
    os.environ.clear()
    os.environ.update(saved)


def _meta(path):
    """Collect the entry metadata the contract consumes from a real directory entry."""
    name = os.path.basename(path)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.stat(path)
        except OSError:
            return {'name': name, 'type': 'symlink', 'target': None}
        return {'name': name, 'type': 'symlink', 'target': _kind(target)}
    return dict(_kind(st), name=name)


def _kind(st):
    if stat.S_ISREG(st.st_mode):
        return {'type': 'file', 'mode': stat.S_IMODE(st.st_mode), 'noexec': False}
    if stat.S_ISDIR(st.st_mode):
        return {'type': 'directory', 'mode': stat.S_IMODE(st.st_mode)}
    return {'type': 'other'}


def _hook(path, log, status=0, mode=0o700):
    with open(path, 'w') as fh:
        fh.write(f'#!/bin/sh\necho "$0|$*|${{RENEWED_DOMAINS-unset}}|${{RENEWED_LINEAGE-unset}}|'
                 f'${{FAILED_DOMAINS-unset}}" >> {log}\nexit {status}\n')
    os.chmod(path, mode)


def _populate(root, log):
    dirs = {}
    for phase in cb.PHASES:
        d = root / phase
        d.mkdir()
        dirs[phase] = d
    deploy = dirs['deploy']
    for name in ('zz-last', 'A_first', '.hidden', 'x.sh', 'pkg.dpkg-dist', 'fails', 'ñ-unicode', 'two words'):
        _hook(str(deploy / name), log, 5 if name == 'fails' else 0)
    _hook(str(deploy / 'backup~'), log)
    _hook(str(deploy / 'plain'), log, mode=0o600)
    (deploy / 'subdir').mkdir()
    os.symlink(str(deploy / 'A_first'), str(deploy / 'linked'))
    os.symlink(str(root / 'missing'), str(deploy / 'dangling'))
    os.symlink(str(deploy / 'subdir'), str(deploy / 'linkdir'))
    os.mkfifo(deploy / 'fifo')
    _hook(str(dirs['pre'] / 'stop'), log)
    _hook(str(dirs['post'] / 'start'), log)
    _hook(str(dirs['post'] / 'Again'), log)
    return dirs


def _config(dirs, **kw):
    values = dict(verb='renew', directory_hooks=True, pre_hook=None, post_hook=None, renew_hook=None,
                  deploy_hook=None, dry_run=False, run_deploy_hooks=False,
                  renewal_pre_hooks_dir=str(dirs['pre']), renewal_deploy_hooks_dir=str(dirs['deploy']),
                  renewal_post_hooks_dir=str(dirs['post']))
    values.update(kw)
    return types.SimpleNamespace(**values)


def _calls(log):
    if not log.exists():
        return []
    return [line.split('|') for line in log.read_text().splitlines()]


def _order(result, phase, dirs):
    """The contract's run order, rebased from /etc/letsencrypt onto the temporary hook directory."""
    return [str(dirs[phase]) + p[len(cb.HOOK_DIRS[phase]):] for p in result['phases'][phase]['run_order']]


def _assess(dirs):
    listing = {phase: _listing(*(_meta(str(p)) for p in dirs[phase].iterdir())) for phase in cb.PHASES}
    return cb.assess(listing, family='debian', certbot_installed=True)


@real
def test_differential_renew_runs_what_the_contract_lists(real_hooks, tmp_path):
    log = tmp_path / 'log'
    dirs = _populate(tmp_path, log)
    result = _assess(dirs)
    config = _config(dirs)

    # Two lineages are due: the pre hooks run once, before the first.
    real_hooks.pre_hook(config)
    real_hooks.pre_hook(config)
    assert _calls(log) == [[str(dirs['pre'] / 'stop'), '', 'unset', 'unset', 'unset']]
    assert [c[0] for c in _calls(log)] == _order(result, 'pre', dirs)

    log.write_text('')
    real_hooks.renew_hook(config, ['a.example', 'www.a.example'], '/etc/letsencrypt/live/a.example')
    ran = [c[0] for c in _calls(log)]
    runs = [p for p in _order(result, 'deploy', dirs) if not p.endswith('/two words')]
    # Everything the contract lists as a plain run ran, in order, and nothing else did.
    assert ran == runs
    assert [s['name'] for s in result['phases']['deploy']['scripts'] if s['outcome'] == 'runs'] == [
        '.hidden', 'A_first', 'fails', 'linked', 'pkg.dpkg-dist', 'x.sh', 'zz-last', 'ñ-unicode']
    for call in _calls(log):
        assert call[2:] == ['a.example www.a.example', '/etc/letsencrypt/live/a.example', 'unset']
    # The name with a space is handed to /bin/sh as text: /bin/sh looks for ".../two", so the file never runs.
    assert ('two words', 'runs_as_shell_text') in _outcomes(result, 'deploy')
    assert str(dirs['deploy'] / 'two words') not in ran
    assert result['complete'] is False and 'shell_reinterpreted' in _codes(result)

    # Post hooks are registered per attempted renewal and run once at the end with both domain lists.
    log.write_text('')
    real_hooks.post_hook(config, [])
    real_hooks.post_hook(config, [])
    assert _calls(log) == []
    real_hooks.run_saved_post_hooks(['a.example'], ['b.example'])
    assert [c[0] for c in _calls(log)] == _order(result, 'post', dirs) == [
        str(dirs['post'] / 'Again'), str(dirs['post'] / 'start')]
    for call in _calls(log):
        assert call[2] == 'a.example' and call[4] == 'b.example'


@real
def test_differential_other_verbs_dry_run_and_no_directory_hooks(real_hooks, tmp_path):
    log = tmp_path / 'log'
    dirs = _populate(tmp_path, log)
    plain = [p for p in _order(_assess(dirs), 'deploy', dirs) if not p.endswith('/two words')]

    # certonly renewing an existing lineage: no directory pre/post hooks, but deploy hooks run.
    config = _config(dirs, verb='certonly')
    real_hooks.pre_hook(config)
    real_hooks.post_hook(config, ['a.example'])
    assert _calls(log) == []
    real_hooks.renew_hook(config, ['a.example'], '/l')
    assert [c[0] for c in _calls(log)] == plain

    # A dry run skips deploy hooks unless --run-deploy-hooks; pre hooks still run.
    log.write_text('')
    real_hooks.renew_hook(_config(dirs, dry_run=True), ['a.example'], '/l')
    assert _calls(log) == []
    real_hooks.renew_hook(_config(dirs, dry_run=True, run_deploy_hooks=True), ['a.example'], '/l')
    assert [c[0] for c in _calls(log)] == plain
    log.write_text('')
    real_hooks.pre_hook(_config(dirs, dry_run=True))
    assert [c[0] for c in _calls(log)] == [str(dirs['pre'] / 'stop')]

    # --no-directory-hooks disables all three directories.
    log.write_text('')
    off = _config(dirs, directory_hooks=False)
    real_hooks.renew_hook(off, ['a.example'], '/l')
    real_hooks.post_hook(off, [])
    assert _calls(log) == []


@real
def test_differential_non_directory_hook_path_raises(real_hooks, tmp_path):
    log = tmp_path / 'log'
    dirs = _populate(tmp_path, log)
    bad = tmp_path / 'deploy-file'
    bad.write_text('')
    with pytest.raises(NotADirectoryError):
        real_hooks.renew_hook(_config(dirs, renewal_deploy_hooks_dir=str(bad)), ['a.example'], '/l')
    assert _calls(log) == []
    result = cb.assess(_dirs(deploy={'state': 'not_directory'}), family='debian', certbot_installed=True)
    assert result['phases']['deploy']['run_order'] == [] and 'directory_breaks_renewal' in _codes(result)


@real
def test_real_list_hooks_ordering_matches_contract(real_hooks, tmp_path):
    d = tmp_path / 'hooks'
    d.mkdir()
    names = ['b', 'B', 'a', 'A', '_x', '-y', '0', 'Z9', 'z_', '.dot', 'é', 'e', '~t', 'a.b', 'a-b']
    for name in names:
        _hook(str(d / name), tmp_path / 'log')
    listing = _listing(*(_meta(str(d / n)) for n in names))
    result = cb.assess({'pre': _listing(), 'deploy': listing, 'post': _listing()}, family='debian',
                       certbot_installed=True)
    assert real_hooks.list_hooks(str(d)) == [p.replace(cb.HOOK_DIRS['deploy'], str(d))
                                             for p in result['phases']['deploy']['run_order']]
