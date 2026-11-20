import os
import shutil
import subprocess

import pytest

from app import resolvconf_hooks as rh

SCRIPT = {'type': 'file', 'mode': 0o755, 'noexec': False}
UPD = rh.UPDATE_D
LIBC = rh.UPDATE_LIBC_D


def _listing(*entries, **kw):
    return dict({'state': 'listed', 'entries': list(entries)}, **kw)


def _run(update_d=None, update_libc_d=None, **kw):
    kw.setdefault('family', 'debian')
    kw.setdefault('resolvconf_installed', True)
    if update_d is None:
        update_d = _listing(dict(SCRIPT, name='libc'))
    if update_libc_d is None:
        update_libc_d = _listing()
    return rh.assess(update_d, update_libc_d, **kw)


def _outcomes(result, directory):
    return [(s['name'], s['outcome']) for s in result['run_parts'][directory]['scripts']]


def _codes(result):
    return {g['code'] for g in result['gaps']}


def test_update_d_scripts_run_as_root_in_byte_order_with_reasons():
    result = _run(_listing(dict(SCRIPT, name='libc'), dict(SCRIPT, name='Zed'), dict(SCRIPT, name='000first'),
                           dict(SCRIPT, name='b-c_d'), dict(SCRIPT, name='B')))
    assert result['complete'] is True
    assert result['applicability'] == 'applicable'
    assert result['runs_as'] == 'root'
    assert _outcomes(result, UPD) == [('000first', 'runs'), ('B', 'runs'), ('Zed', 'runs'), ('b-c_d', 'runs'),
                                      ('libc', 'runs')]
    update = result['run_parts'][UPD]
    assert update['command'][0] == '/bin/run-parts' and update['command'][-1] == UPD
    assert '--exit-on-error' not in update['command']
    assert all(s['reason'] == rh.REASONS['runs'] for s in update['scripts'])
    assert any('-u' in t for t in update['triggers'])
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['not_a_verdict']


def test_name_type_mode_and_mount_rules():
    result = _run(_listing(
        dict(SCRIPT, name='libc'),
        dict(SCRIPT, name='x.sh'), dict(SCRIPT, name='.hidden'), dict(SCRIPT, name='x~'),
        dict(SCRIPT, name='old.dpkg-old'),
        {'name': 'plain', 'type': 'file', 'mode': 0o644, 'noexec': False},
        {'name': 'sub', 'type': 'directory', 'mode': 0o755},
        {'name': 'fifo', 'type': 'other'},
        dict(SCRIPT, name='nx', noexec=True),
        {'name': 'gone', 'type': 'symlink', 'target': None},
        {'name': 'link', 'type': 'symlink', 'target': dict(SCRIPT)},
        {'name': 'linkdir', 'type': 'symlink', 'target': {'type': 'directory'}},
    ))
    assert dict(_outcomes(result, UPD)) == {
        'libc': 'runs', 'x.sh': 'name_rejected', '.hidden': 'name_rejected', 'x~': 'name_rejected',
        'old.dpkg-old': 'name_rejected', 'plain': 'not_executable', 'sub': 'directory', 'fifo': 'not_plain_file',
        'nx': 'noexec_mount', 'gone': 'stat_failed', 'link': 'runs', 'linkdir': 'directory',
    }
    assert result['complete'] is True


def test_any_execute_bit_is_enough_for_root():
    for mode in (0o100, 0o010, 0o001, 0o4711):
        result = _run(_listing(dict(SCRIPT, name='libc', mode=mode)))
        assert _outcomes(result, UPD) == [('libc', 'runs')], oct(mode)


def test_update_libc_d_is_conditional_on_update_d_libc():
    libc_dir = _listing(dict(SCRIPT, name='nscd'), {'name': 'off', 'type': 'file', 'mode': 0o644, 'noexec': False})
    result = _run(_listing(dict(SCRIPT, name='libc')), libc_dir)
    libc = result['run_parts'][LIBC]
    assert libc['invocation'] == 'conditional' and libc['invoked_by'] == f'{UPD}/libc'
    assert _outcomes(result, LIBC) == [('nscd', 'runs_if_libc'), ('off', 'not_executable')]
    assert libc['command'] == ('/bin/run-parts', LIBC)
    assert '--arg' not in ' '.join(libc['command'])


@pytest.mark.parametrize('update_d', [
    _listing(dict(SCRIPT, name='other')),
    _listing({'name': 'libc', 'type': 'file', 'mode': 0o644, 'noexec': False}),
    _listing(dict(SCRIPT, name='libc', noexec=True)),
    _listing({'name': 'libc', 'type': 'symlink', 'target': None}),
    {'state': 'absent'},
    {'state': 'not_directory'},
])
def test_update_libc_d_not_invoked_when_libc_does_not_run(update_d):
    result = _run(update_d, _listing(dict(SCRIPT, name='nscd')))
    assert result['run_parts'][LIBC]['invocation'] == 'not_invoked'
    assert _outcomes(result, LIBC) == [('nscd', 'not_invoked')]


def test_update_libc_d_unresolved_when_libc_or_update_d_unresolved():
    result = _run(_listing({'name': 'libc', 'type': 'symlink'}), _listing(dict(SCRIPT, name='nscd')))
    assert result['run_parts'][LIBC]['invocation'] == 'unresolved'
    assert _outcomes(result, LIBC) == [('nscd', 'unresolved')]
    assert 'symlink_target_unobserved' in _codes(result) and result['complete'] is False
    result = rh.assess(None, _listing(dict(SCRIPT, name='nscd')), family='debian', resolvconf_installed=True)
    assert result['run_parts'][LIBC]['invocation'] == 'unresolved'
    assert _outcomes(result, LIBC) == [('nscd', 'unresolved')]
    assert 'directory_not_observed' in _codes(result) and result['complete'] is False
    result = _run({'state': 'unreadable'}, _listing(dict(SCRIPT, name='nscd')))
    assert result['run_parts'][LIBC]['invocation'] == 'unresolved'
    assert 'directory_unreadable' in _codes(result) and result['complete'] is False


def test_applicability():
    assert _run(family='rpm')['applicability'] == 'not_applicable'
    assert _run(resolvconf_installed=False)['applicability'] == 'not_applicable'
    result = _run(family=None)
    assert result['applicability'] == 'unknown' and 'family_not_observed' in _codes(result)
    assert result['complete'] is False
    result = _run(family='arch')
    assert 'family_unsupported' in _codes(result) and result['complete'] is False
    result = _run(resolvconf_installed=None)
    assert 'implementation_not_observed' in _codes(result) and result['complete'] is False


@pytest.mark.parametrize('listing,code', [
    (_listing(dict(SCRIPT, name='libc'), truncated=True), 'listing_incomplete'),
    ({'state': 'listed', 'entries': 'x'}, 'input_malformed'),
    ({'state': 'weird'}, 'input_malformed'),
    ('nope', 'input_malformed'),
    (_listing(dict(SCRIPT, name='libc'), dict(SCRIPT, name='libc')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='a/b')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='..')), 'input_malformed'),
    (_listing('entry'), 'input_malformed'),
    (_listing({'name': 'libc', 'type': 'file'}), 'metadata_missing'),
    (_listing({'name': 'libc', 'type': 'file', 'mode': True}), 'metadata_missing'),
    (_listing({'name': 'libc', 'type': 'file', 'mode': 0o17777}), 'metadata_missing'),
    (_listing({'name': 'libc', 'type': 'file', 'mode': 0o755, 'noexec': 'no'}), 'metadata_missing'),
    (_listing({'name': 'libc', 'type': 'socket'}), 'metadata_missing'),
    (_listing(*[dict(SCRIPT, name=f'n{i}') for i in range(rh.MAX_ENTRIES + 1)]), 'too_many_entries'),
])
def test_fail_closed(listing, code):
    result = _run(listing)
    assert code in _codes(result)
    assert result['complete'] is False
    assert not any(s['outcome'] == 'runs' and s['name'] in ('a/b', '', '..')
                   for s in result['run_parts'][UPD]['scripts'])


def test_unobserved_mount_flags_are_non_blocking():
    result = _run(_listing({'name': 'libc', 'type': 'file', 'mode': 0o755}))
    assert _outcomes(result, UPD) == [('libc', 'runs')]
    assert 'mount_flags_unobserved' in _codes(result)
    assert result['complete'] is True


def test_gaps_are_bounded():
    entries = [{'name': f'n{i}', 'type': 'file'} for i in range(200)]
    result = _run(_listing(*entries))
    assert len(result['gaps']) == rh.MAX_GAPS
    assert result['gaps'][-1]['code'] == 'gaps_truncated'


def test_pure_and_does_not_mutate_input():
    listing = _listing(dict(SCRIPT, name='libc'), dict(SCRIPT, name='a'))
    snapshot = repr(listing)
    first = _run(listing)
    assert repr(listing) == snapshot
    assert first == _run(listing)


NAMES = ['000resolvconf', 'Zed', 'a_b-c', 'B', 'b', '_x', '-y', 'x.sh', '.hidden', 'x~', 'a.b', 'dpkg-new',
         'x.dpkg-old', 'UPPER', '9', 'with space', 'ünï']


@pytest.mark.skipif(shutil.which('run-parts') is None, reason='debianutils run-parts is not installed')
def test_matches_real_run_parts(tmp_path):
    """Differential against the real debianutils run-parts --test on real files."""
    root = tmp_path / 'update.d'
    root.mkdir()
    entries = []
    for name in NAMES:
        path = root / name
        path.write_text('#!/bin/sh\n')
        path.chmod(0o755)
        entries.append(dict(SCRIPT, name=name))
    (root / 'plain').write_text('x')
    (root / 'plain').chmod(0o644)
    entries.append({'name': 'plain', 'type': 'file', 'mode': 0o644, 'noexec': False})
    (root / 'sub').mkdir()
    entries.append({'name': 'sub', 'type': 'directory', 'mode': 0o755})
    os.symlink('/nonexistent/x', root / 'gone')
    entries.append({'name': 'gone', 'type': 'symlink', 'target': None})
    os.symlink(root / 'Zed', root / 'link')
    entries.append({'name': 'link', 'type': 'symlink', 'target': dict(SCRIPT)})
    out = subprocess.run(['run-parts', '--test', str(root)], capture_output=True, text=True, timeout=30,
                         env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, check=False)
    real = [line.rsplit('/', 1)[1] for line in out.stdout.splitlines()]
    result = _run(_listing(*entries))
    modeled = [s['name'] for s in result['run_parts'][UPD]['scripts'] if s['outcome'] == 'runs']
    if os.geteuid() == 0:
        assert modeled == real
    else:
        assert set(real) <= set(modeled)
