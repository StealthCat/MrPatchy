import glob
import os
import shutil
import stat
import subprocess

import pytest

from app import ca_certificates_hooks as ch

SCRIPT = {'type': 'file', 'mode': 0o755, 'noexec': False}
HOOKS = ch.HOOKS_DIR


def _listing(*entries, **kw):
    return dict({'state': 'listed', 'entries': list(entries)}, **kw)


def _run(hooks_dir=None, **kw):
    kw.setdefault('family', 'debian')
    kw.setdefault('ca_certificates_installed', True)
    if hooks_dir is None:
        hooks_dir = _listing(dict(SCRIPT, name='jks-keystore'))
    return ch.assess(hooks_dir, **kw)


def _outcomes(result):
    return [(s['name'], s['outcome']) for s in result['hooks']['scripts']]


def _codes(result):
    return {g['code'] for g in result['gaps']}


def test_hooks_run_as_root_in_byte_order_with_invocation_details():
    result = _run(_listing(dict(SCRIPT, name='mono-keystore'), dict(SCRIPT, name='Zed'),
                           dict(SCRIPT, name='000first'), dict(SCRIPT, name='b-c_d'), dict(SCRIPT, name='B')))
    assert result['complete'] is True and result['gaps'] == []
    assert result['applicability'] == 'applicable'
    assert result['runs_as'] == 'root'
    assert _outcomes(result) == [('000first', 'runs'), ('B', 'runs'), ('Zed', 'runs'), ('b-c_d', 'runs'),
                                 ('mono-keystore', 'runs')]
    hooks = result['hooks']
    assert hooks['run_order'] == [f'{HOOKS}/{n}' for n in ('000first', 'B', 'Zed', 'b-c_d', 'mono-keystore')]
    assert hooks['command'] == ('run-parts', '--test', '--', HOOKS)
    assert '--lsbsysinit' not in hooks['command'] and '--exit-on-error' not in hooks['command']
    assert hooks['hook_argv'] == ('HOOK', '[--fresh]')
    assert hooks['hook_stdin'][0].startswith('+') and hooks['hook_stdin'][1].startswith('-')
    assert hooks['stops_on_failure'] is False
    assert any('update-ca-certificates-fresh' in t for t in hooks['triggers'])
    assert all(s['reason'] == ch.REASONS['runs'] for s in hooks['scripts'])
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['not_a_verdict']


def test_name_type_mode_and_mount_rules():
    result = _run(_listing(
        dict(SCRIPT, name='jks-keystore'),
        dict(SCRIPT, name='x.sh'), dict(SCRIPT, name='.hidden'), dict(SCRIPT, name='x~'),
        dict(SCRIPT, name='jks-keystore.dpkg-dist'), dict(SCRIPT, name='sp ace'),
        {'name': 'plain', 'type': 'file', 'mode': 0o644, 'noexec': False},
        {'name': 'sub', 'type': 'directory', 'mode': 0o755},
        {'name': 'fifo', 'type': 'other'},
        dict(SCRIPT, name='nx', noexec=True),
        {'name': 'gone', 'type': 'symlink', 'target': None},
        {'name': 'link', 'type': 'symlink', 'target': dict(SCRIPT)},
        {'name': 'linkdir', 'type': 'symlink', 'target': {'type': 'directory'}},
    ))
    assert dict(_outcomes(result)) == {
        'jks-keystore': 'runs', 'x.sh': 'name_rejected', '.hidden': 'name_rejected', 'x~': 'name_rejected',
        'jks-keystore.dpkg-dist': 'name_rejected', 'sp ace': 'name_rejected', 'plain': 'not_executable',
        'sub': 'directory', 'fifo': 'not_plain_file', 'nx': 'noexec_mount', 'gone': 'stat_failed',
        'link': 'runs', 'linkdir': 'directory',
    }
    assert result['hooks']['run_order'] == [f'{HOOKS}/jks-keystore', f'{HOOKS}/link']
    assert result['complete'] is True


def test_any_execute_bit_is_enough_for_root():
    for mode in (0o100, 0o010, 0o001, 0o4711):
        result = _run(_listing(dict(SCRIPT, name='hook', mode=mode)))
        assert _outcomes(result) == [('hook', 'runs')], oct(mode)


@pytest.mark.parametrize('state', ['absent', 'not_directory'])
def test_missing_directory_runs_nothing_and_is_complete(state):
    result = _run({'state': state})
    assert result['hooks']['state'] == state
    assert result['hooks']['scripts'] == [] and result['hooks']['run_order'] == []
    assert result['complete'] is True


def test_applicability():
    assert _run(family='rpm')['applicability'] == 'not_applicable'
    assert _run(ca_certificates_installed=False)['applicability'] == 'not_applicable'
    result = _run(family=None)
    assert result['applicability'] == 'unknown' and 'family_not_observed' in _codes(result)
    assert result['complete'] is False
    result = _run(family='arch')
    assert 'family_unsupported' in _codes(result) and result['complete'] is False
    result = _run(ca_certificates_installed=None)
    assert result['applicability'] == 'unknown' and 'implementation_not_observed' in _codes(result)
    assert result['complete'] is False
    result = _run(ca_certificates_installed='yes')
    assert 'implementation_not_observed' in _codes(result) and result['complete'] is False


@pytest.mark.parametrize('hooks_dir, code', [
    (None, 'directory_not_observed'),
    ({'state': 'unreadable'}, 'directory_unreadable'),
    ({'state': 'weird'}, 'input_malformed'),
    ('listed', 'input_malformed'),
    (_listing(dict(SCRIPT, name='a'), truncated=True), 'listing_incomplete'),
    ({'state': 'listed', 'entries': 'a'}, 'input_malformed'),
    ({'state': 'listed', 'entries': [dict(SCRIPT, name=f'h{i}') for i in range(ch.MAX_ENTRIES + 1)]},
     'too_many_entries'),
    (_listing(dict(SCRIPT, name='a'), dict(SCRIPT, name='a')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='a/b')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='')), 'input_malformed'),
    (_listing(dict(SCRIPT, name='..')), 'input_malformed'),
    (_listing('a'), 'input_malformed'),
    (_listing({'name': 'a', 'type': 'file'}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'file', 'mode': True}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'file', 'mode': 0o10000}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'file', 'mode': 0o755, 'noexec': 'no'}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'socket'}), 'metadata_missing'),
    (_listing({'name': 'a', 'type': 'symlink'}), 'symlink_target_unobserved'),
    (_listing({'name': 'a', 'type': 'symlink', 'target': {'type': 'file'}}), 'metadata_missing'),
])
def test_blocking_gaps_fail_closed(hooks_dir, code):
    result = ch.assess(hooks_dir, family='debian', ca_certificates_installed=True)
    assert code in _codes(result)
    assert code in ch.BLOCKING
    assert result['complete'] is False


def test_unresolved_entries_are_never_reported_as_running():
    result = _run(_listing({'name': 'a', 'type': 'symlink'}, {'name': 'b', 'type': 'file'}))
    assert _outcomes(result) == [('a', 'unresolved'), ('b', 'unresolved')]
    assert result['hooks']['run_order'] == []


def test_unobserved_mount_flags_are_a_non_blocking_gap():
    result = _run(_listing({'name': 'hook', 'type': 'file', 'mode': 0o755}))
    assert _outcomes(result) == [('hook', 'runs')]
    assert _codes(result) == {'mount_flags_unobserved'}
    assert 'mount_flags_unobserved' not in ch.BLOCKING
    assert result['complete'] is True


def test_gap_list_is_bounded():
    entries = [{'name': f'h{i:03d}', 'type': 'symlink'} for i in range(200)]
    result = _run(_listing(*entries))
    assert len(result['gaps']) == ch.MAX_GAPS
    assert result['gaps'][-1]['code'] == 'gaps_truncated'
    assert result['complete'] is False


def test_input_is_not_mutated_and_result_has_no_response_authority():
    listing = _listing(dict(SCRIPT, name='b'), dict(SCRIPT, name='a'))
    snapshot = repr(listing)
    result = _run(listing)
    assert repr(listing) == snapshot
    flat = repr(result).lower()
    for word in ('quarantine', 'terminate', 'approve', 'authoriz'):
        assert word not in flat


# Differential against the real update-ca-certificates and run-parts.

_BINARY = shutil.which('update-ca-certificates')
_CERTS = sorted(glob.glob('/usr/share/ca-certificates/mozilla/*.crt'))[:2]
real = pytest.mark.skipif(not (_BINARY and shutil.which('run-parts') and shutil.which('openssl')
                               and len(_CERTS) == 2 and os.geteuid() == 0),
                          reason='needs root, update-ca-certificates, run-parts, openssl and two bundled CA certificates')


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


def _hook(path, log, status=0):
    with open(path, 'w') as fh:
        fh.write(f'#!/bin/sh\necho "== $0 [$*]" >> {log}\ncat >> {log}\nexit {status}\n')
    os.chmod(path, 0o700)


@real
@pytest.mark.parametrize('extra', [[], ['--fresh']])
def test_differential_against_real_update_ca_certificates(tmp_path, extra):
    certs, local, etc, hooks = (tmp_path / d for d in ('certs', 'local', 'etc', 'hooks'))
    for d in (certs / 'mozilla', local, etc, hooks):
        d.mkdir(parents=True)
    for cert in _CERTS:
        shutil.copy(cert, certs / 'mozilla')
    names = [os.path.basename(c) for c in _CERTS]
    conf = tmp_path / 'ca-certificates.conf'
    conf.write_text(f'mozilla/{names[0]}\n!mozilla/{names[1]}\n')
    log = tmp_path / 'log'
    # The second certificate starts linked so that this run removes it.
    removed_pem = names[1][:-4] + '.pem'
    os.symlink(str(certs / 'mozilla' / names[1]), str(etc / removed_pem))
    for name in ('zz-last', 'A_first', 'Mid-1', 'fails', 'x.sh', '.hidden', 'old~', 'pkg.dpkg-dist'):
        _hook(str(hooks / name), log, 3 if name == 'fails' else 0)
    _hook(str(hooks / 'plain'), log)
    os.chmod(hooks / 'plain', 0o600)
    (hooks / 'subdir').mkdir()
    os.symlink(str(hooks / 'Mid-1'), str(hooks / 'linked'))
    os.symlink(str(tmp_path / 'missing'), str(hooks / 'dangling'))
    os.mkfifo(hooks / 'fifo')

    run = subprocess.run(
        [_BINARY, '--certsconf', str(conf), '--certsdir', str(certs), '--localcertsdir', str(local),
         '--etccertsdir', str(etc), '--hooksdir', str(hooks), '--certbundle', 'bundle.crt', *extra],
        capture_output=True, text=True, timeout=120, env={'PATH': os.environ['PATH'], 'LC_ALL': 'C'})
    assert run.returncode == 0, run.stderr
    assert f'E: {hooks}/fails exited with code 3.' in run.stdout

    calls = []
    for line in log.read_text().splitlines():
        if line.startswith('== '):
            path, argv = line[3:].split(' [', 1)
            calls.append({'name': os.path.basename(path), 'argv': argv[:-1], 'stdin': []})
        else:
            calls[-1]['stdin'].append(line)

    listing = _listing(*(_meta(str(p)) for p in hooks.iterdir()))
    result = ch.assess(listing, family='debian', ca_certificates_installed=True)
    assert result['complete'] is True
    contract_runs = [s['name'] for s in result['hooks']['scripts'] if s['outcome'] == 'runs']
    assert [c['name'] for c in calls] == contract_runs == ['A_first', 'Mid-1', 'fails', 'linked', 'zz-last']
    expected_argv = '--fresh' if extra else ''
    added = f'+{etc}/{names[0][:-4]}.pem'
    removed = f'-{etc}/{removed_pem}'
    for call in calls:
        assert call['argv'] == expected_argv
        # Added lines come before removed lines; --fresh clears managed links first, so nothing is removed.
        assert call['stdin'] == ([added] if extra else [added, removed])

    # A second run with nothing to change still runs every hook, with empty input.
    log.write_text('')
    again = subprocess.run(
        [_BINARY, '--certsconf', str(conf), '--certsdir', str(certs), '--localcertsdir', str(local),
         '--etccertsdir', str(etc), '--hooksdir', str(hooks), '--certbundle', 'bundle.crt'],
        capture_output=True, text=True, timeout=120, env={'PATH': os.environ['PATH'], 'LC_ALL': 'C'})
    assert again.returncode == 0 and '0 added, 0 removed' in again.stdout
    assert [line[3:].split(' [')[0].rsplit('/', 1)[1] for line in log.read_text().splitlines()] == contract_runs


@real
def test_real_update_ca_certificates_skips_hooks_when_directory_is_missing(tmp_path):
    certs, etc = tmp_path / 'certs', tmp_path / 'etc'
    (certs / 'mozilla').mkdir(parents=True)
    etc.mkdir()
    shutil.copy(_CERTS[0], certs / 'mozilla')
    conf = tmp_path / 'conf'
    conf.write_text(f'mozilla/{os.path.basename(_CERTS[0])}\n')
    (tmp_path / 'hooks').write_text('not a directory\n')
    run = subprocess.run(
        [_BINARY, '--certsconf', str(conf), '--certsdir', str(certs), '--localcertsdir', str(tmp_path / 'none'),
         '--etccertsdir', str(etc), '--hooksdir', str(tmp_path / 'hooks'), '--certbundle', 'b.crt'],
        capture_output=True, text=True, timeout=120, env={'PATH': os.environ['PATH'], 'LC_ALL': 'C'})
    assert run.returncode == 0, run.stderr
    assert 'Running hooks' not in run.stdout
    result = ch.assess({'state': 'not_directory'}, family='debian', ca_certificates_installed=True)
    assert result['hooks']['run_order'] == [] and result['complete'] is True


@real
def test_real_run_parts_orders_bytewise_even_under_a_utf8_locale(tmp_path):
    hooks = tmp_path / 'hooks'
    hooks.mkdir()
    names = ['b', 'B', 'a', 'A', '_x', '-y', '0', 'Z9', 'z_']
    for name in names:
        _hook(str(hooks / name), tmp_path / 'log')
    listing = _listing(*(_meta(str(hooks / n)) for n in names))
    expected = [s['name'] for s in ch.assess(listing, family='debian', ca_certificates_installed=True)
                ['hooks']['scripts']]
    for locale in ('C', 'C.UTF-8', 'en_US.UTF-8'):
        out = subprocess.run(['run-parts', '--test', '--', str(hooks)], capture_output=True, text=True,
                             env={'PATH': os.environ['PATH'], 'LC_ALL': locale}, check=True).stdout
        assert [os.path.basename(p) for p in out.split()] == expected, locale
