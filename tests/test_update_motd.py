import os
import shutil
import subprocess

import pytest

from app import update_motd as um

LISTED = {'state': 'listed', 'complete': True, 'noexec': False}
SSHD = [{'service': 'sshd', 'args': ['motd=/run/motd.dynamic'], 'reached': 'yes'},
        {'service': 'sshd', 'args': ['noupdate'], 'reached': 'yes'}]

# Pinned from `run-parts --list --lsbsysinit` (debianutils 5.17, Ubuntu 24.04) over a seeded random
# corpus plus Debian/Ubuntu script names and backup-suffix variants. Order is run-parts' own.
LSBSYSINIT_ACCEPTED = (
    '.x.dpkg-bak', '.x.dpkg-dist', '.x.dpkg-new', '.x.dpkg-old', '.x.dpkg-tmp', '.xdpkg-old', '0', '00',
    '00-header', '1.dpkg-bak', '10-help-text', '1dpkg-old', '50-motd-news', '50-x.dpkg-bak', '50-xdpkg-old',
    '91-release-upgrade', '98-reboot-required', '9999b', '9b', '_foo-bar', '_x.dpkg-bak', '_x.dpkg-dist',
    '_x.dpkg-new', '_x.dpkg-old', '_x.dpkg-tmp', '_xdpkg-old', 'a', 'a--9a', 'a.b-c.d-e', 'a_', 'a_0',
    'a_b.dpkg-bak', 'a_bdpkg-old', 'ab', 'b', 'b-', 'ba', 'foo.-baz', 'foo..bar-baz', 'foo.bar-baz', 'x.dpkg-bak',
    'xdpkg-old', 'z', 'za0', 'zb0-', 'zz', 'zzzaz-',
)
LSBSYSINIT_REJECTED = (
    ' ', ' +', ' -', ' .', ' 0bZ', ' A', ' AbzZ', ' Z9zab', ' Z_', ' Z~-~@', ' ~', ' ~ba', ' ~z90a', '+', '+++@A',
    '+-', '+.0~A', '+A.', '+AA._0', '+_.A ', '+z-a', '+z@', '+~b', '+~z-', '-', '- b.', '-+ ~ ~', '-+@00', '-0_',
    '-9', '-@a_~', '-a9a', '-ab', '-b', '-x.dpkg-bak', '-x.dpkg-dist', '-x.dpkg-new', '-x.dpkg-old',
    '-x.dpkg-old.x', '-x.dpkg-tmp', '-x.rpmsave', '-x.sh', '-xdpkg-old', '-x~', '-~~ a', '.+A', '.-Z', '..._++',
    '.0--', '.0z', '.9+0_-', '.909', '.A._A', '.Z A', '._0', '.a+b', '.b', '.x.dpkg-old.x', '.x.rpmsave', '.x.sh',
    '.x~', '.~9  +', '0-.-', '0-_-+_', '0A', '0AaZA', '0ZA+', '0b9@_.', '0bA', '0zZz_A', '1.dpkg-dist',
    '1.dpkg-new', '1.dpkg-old', '1.dpkg-old.x', '1.dpkg-tmp', '1.rpmsave', '1.sh', '1~', '50-x.dpkg-dist',
    '50-x.dpkg-new', '50-x.dpkg-old', '50-x.dpkg-old.x', '50-x.dpkg-tmp', '50-x.rpmsave', '50-x.sh', '50-x~',
    '9+0 _', '9@.z.', '9@_b', '9Z-za', '9a@-b', '9a~b', '9bAb', '@', '@+@~', '@+z~ ', '@9', '@9@.~Z', '@@', '@bz',
    '@~@Z', 'A', 'A Z_.', 'A Za_', 'A0A_', 'AA.+ab', 'Azbz', 'A~', 'Foo-bar', 'README', 'X.dpkg-bak', 'X.dpkg-dist',
    'X.dpkg-new', 'X.dpkg-old', 'X.dpkg-old.x', 'X.dpkg-tmp', 'X.rpmsave', 'X.sh', 'Xdpkg-old', 'X~', 'Z', 'Z ',
    'Z 90~', 'Z 9~', 'Z.', 'Z.9', 'Z.@~z', 'Z.A@_', 'Z0', 'Z9', 'Za', 'Zz@9@', 'Z~', 'Z~@b ', 'Z~A', '_', '_ a9',
    '_+ ', '_.~', '_0b~', '_9', '_9 b', '_Z-bb.', '___Z', '_foo', '_x.dpkg-old.x', '_x.rpmsave', '_x.sh', '_x~',
    '_~-', '_~0z.', 'a ', 'a+z', 'a.', 'a0.', 'aA+Z', 'aZ', 'aZ00', 'a_b.dpkg-dist', 'a_b.dpkg-new', 'a_b.dpkg-old',
    'a_b.dpkg-old.x', 'a_b.dpkg-tmp', 'a_b.rpmsave', 'a_b.sh', 'a_b~', 'aa+Z_Z', 'b+ ', 'b-@', 'b-a-A_', 'b. z9@',
    'b0-a.', 'b9+ +A', 'b9_z~@', 'bZ', 'b_Z.', 'bb+Ab', 'b~@~', 'foo.bar', 'x.dpkg-dist', 'x.dpkg-new',
    'x.dpkg-old', 'x.dpkg-old.x', 'x.dpkg-tmp', 'x.rpmsave', 'x.sh', 'x~', 'z ', 'z @', 'z+0z', 'z.+.-', 'z..-',
    'z.aA.0', 'z9+~', 'z9bZa~', 'z9~', 'zZ', 'zZZaz', 'zaa+ ', '~', '~9aA', '~A0b.', '~A_Za', '~Z', '~_.@', '~za@@',
    '~~',
)


def f(name, mode=0o755, type='file'):
    return {'name': name, 'type': type, 'mode': mode}


def link(name, target=..., text='target'):
    item = {'name': name, 'type': 'symlink', 'link_target': text}
    if target is not ...:
        item['target'] = target
    return item


def run(entries, family='debian', directory=LISTED, pam_motd=SSHD):
    return um.evaluate(entries, family=family, directory=directory, pam_motd=pam_motd)


def status(result):
    return {r['name']: (r['status'], r['reason_code']) for r in result['entries']}


def codes(result):
    return [g['code'] for g in result['gaps']]


def scripts(result):
    return [s['name'] for s in result['scripts']]


def test_name_rule_matches_pinned_run_parts_corpus():
    assert [n for n in LSBSYSINIT_ACCEPTED if not um.name_considered(n)] == []
    assert [n for n in LSBSYSINIT_REJECTED if um.name_considered(n)] == []


def test_order_matches_pinned_run_parts_order():
    result = run([f(n) for n in reversed(LSBSYSINIT_ACCEPTED + LSBSYSINIT_REJECTED)])
    assert tuple(scripts(result)) == LSBSYSINIT_ACCEPTED
    assert [s['order'] for s in result['scripts']] == list(range(len(LSBSYSINIT_ACCEPTED)))
    assert result['complete'] is True


@pytest.mark.parametrize('name, considered', [
    ('50-landscape-sysinfo', True), ('91-release-upgrade', True), ('b_c', True),
    ('Upper', False), ('50-x.sh', False), ('foo.bar', False), ('x~', False), ('.hidden', False),
    ('50-x.dpkg-old', False), ('50-x.dpkg-dist', False), ('50-x.dpkg-new', False), ('50-x.dpkg-tmp', False),
    ('50-x.dpkg-bak', True), ('50-x.ucf-dist', True), ('50-x.rpmsave', False),
    # The .dpkg-* exclusion only applies to names starting with [a-z0-9-]; these still run.
    ('_x.dpkg-old', True), ('.x.dpkg-old', True),
])
def test_name_rule_examples(name, considered):
    assert um.name_considered(name) is considered


def test_ubuntu_default_scripts_run_in_byte_order_as_root():
    result = run([f('50-motd-news'), f('00-header'), f('10-help-text'), f('README', 0o644),
                  f('98-fsck-at-reboot', 0o644)])
    assert scripts(result) == ['00-header', '10-help-text', '50-motd-news']
    assert status(result)['README'] == ('skipped', 'name_rejected')
    assert status(result)['98-fsck-at-reboot'] == ('skipped', 'not_executable')
    assert result['runs_as'] == 'root'
    assert result['command'][-2:] == ['--lsbsysinit', '/etc/update-motd.d']
    assert result['command'][:2] == ['/usr/bin/env', '-i']
    assert result['activation']['state'] == 'active'
    assert result['complete'] is True and result['gaps'] == []
    assert result['origin'] == 'not_assessed'


@pytest.mark.parametrize('mode', [0o100, 0o010, 0o001, 0o4711])
def test_any_execute_bit_is_enough_for_root(mode):
    assert scripts(run([f('10-x', mode)])) == ['10-x']


def test_file_types_and_symlinks_follow_run_parts():
    result = run([
        f('10-dir', type='directory'), f('11-fifo', type='other'),
        link('20-link', {'type': 'file', 'mode': 0o755, 'noexec': False}),
        link('21-dangling', None), link('22-dirlink', {'type': 'directory'}),
        link('23-noexec-target', {'type': 'file', 'mode': 0o644, 'noexec': False}),
        link('24-devnull', {'type': 'other'}, text='/dev/null'),
    ])
    assert scripts(result) == ['20-link']
    assert result['scripts'][0]['link_target'] == 'target'
    assert status(result) == {
        '10-dir': ('skipped', 'directory'), '11-fifo': ('skipped', 'not_plain_file'),
        '20-link': ('runs', 'runs'), '21-dangling': ('skipped', 'stat_failed'),
        '22-dirlink': ('skipped', 'directory'), '23-noexec-target': ('skipped', 'not_executable'),
        '24-devnull': ('skipped', 'not_plain_file'),
    }
    assert result['complete'] is True


def test_rejected_name_is_not_inspected_further():
    result = run([link('Bad-Name'), f('x.sh', mode=None)])
    assert status(result) == {'Bad-Name': ('skipped', 'name_rejected'), 'x.sh': ('skipped', 'name_rejected')}
    assert result['complete'] is True


def test_noexec_mount_stops_scripts_and_unknown_mount_is_a_gap():
    result = run([f('10-a'), link('20-b', {'type': 'file', 'mode': 0o755, 'noexec': True})],
                 directory={'state': 'listed', 'complete': True, 'noexec': True})
    assert scripts(result) == []
    assert status(result) == {'10-a': ('skipped', 'noexec_mount'), '20-b': ('skipped', 'noexec_mount')}
    unknown = run([f('10-a'), link('20-b', {'type': 'file', 'mode': 0o755})],
                  directory={'state': 'listed', 'complete': True})
    assert scripts(unknown) == ['10-a', '20-b']
    assert codes(unknown) == ['mount_flags_not_observed']  # one gap for the listing, naming both
    assert '10-a' in unknown['gaps'][0]['detail'] and '20-b' in unknown['gaps'][0]['detail']
    assert unknown['complete'] is True  # reported as running: never under-reports what may run


def test_many_scripts_on_unobserved_mounts_do_not_exhaust_the_gap_budget():
    entries = [f(f'{index:03d}-script') for index in range(200)]
    result = run(entries, directory={'state': 'listed', 'complete': True})
    assert len(scripts(result)) == 200
    assert codes(result) == ['mount_flags_not_observed'] and 'and 195 more' in result['gaps'][0]['detail']
    assert result['complete'] is True


@pytest.mark.parametrize('pam, state', [
    (SSHD, 'active'),
    ([{'service': 'sshd', 'args': ['noupdate'], 'reached': 'yes'}], 'inactive'),
    ([{'service': 'login', 'args': [], 'reached': 'no'}], 'inactive'),
    ([], 'inactive'),
    ([{'service': 'sshd', 'args': [], 'reached': 'unknown'}], 'possible'),
    ([{'service': 'sshd', 'args': [], 'reached': 'unknown'}, {'service': 'login', 'args': [], 'reached': 'yes'}],
     'active'),
    # noupdate must be its own argument, as pam_motd compares it with strcmp.
    ([{'service': 'sshd', 'args': ['noupdate=1'], 'reached': 'yes'}], 'active'),
])
def test_activation_per_pam_service(pam, state):
    result = run([f('00-header')], pam_motd=pam)
    assert result['activation']['state'] == state
    assert scripts(result) == ['00-header']


def test_unknown_reachability_is_possible_never_active():
    result = run([f('00-header')], pam_motd=[{'service': 'sshd', 'args': [], 'reached': 'unknown'}])
    assert result['activation']['state'] == 'possible'
    assert codes(result) == ['pam_reachability_unknown']
    assert result['activation']['services'] == [
        {'service': 'sshd', 'args': [], 'reached': 'unknown', 'updates': True}]


def test_rpm_family_is_not_applicable_and_unknown_family_is_blocking():
    rpm = run([f('00-header')], family='rpm', pam_motd=None)
    assert rpm['activation']['state'] == 'not_applicable' and rpm['complete'] is True
    for family, code in ((None, 'family_not_observed'), ('arch', 'family_unsupported')):
        result = run([f('00-header')], family=family)
        assert result['activation']['state'] == 'unknown'
        assert code in codes(result) and result['complete'] is False


@pytest.mark.parametrize('pam', [None, 'sshd', [{'service': 'sshd', 'args': 'noupdate', 'reached': 'yes'}],
                                 [{'service': 'a/b', 'args': [], 'reached': 'yes'}],
                                 [{'service': 'sshd', 'args': [], 'reached': True}]])
def test_unobserved_or_malformed_pam_is_never_active_or_complete(pam):
    result = run([f('00-header')], pam_motd=pam)
    assert result['activation']['state'] == 'unknown'
    assert result['complete'] is False


def test_malformed_invocation_beside_a_reached_one_still_reports_active_but_incomplete():
    result = run([f('00-header')], pam_motd=[{'service': 'sshd', 'args': [], 'reached': 'yes'}, 'junk'])
    assert result['activation']['state'] == 'active'
    assert result['complete'] is False


@pytest.mark.parametrize('directory, code', [
    (None, 'directory_not_observed'),
    ({'state': 'unreadable'}, 'directory_unreadable'),
    ({'state': 'listed', 'complete': False}, 'listing_incomplete'),
    ({'state': 'gone'}, 'input_malformed'),
    ({'state': 'listed', 'noexec': 'no'}, 'input_malformed'),
    ({'state': 'listed', 'noexec': False}, 'input_malformed'),  # completeness not stated: not complete
    ({'state': 'listed', 'complete': 'yes', 'noexec': False}, 'input_malformed'),
    ({'state': 'unreadable', 'complete': 1}, 'input_malformed'),
])
def test_unobserved_directory_fails_closed(directory, code):
    result = run([f('00-header')], directory=directory)
    assert code in codes(result)
    assert result['complete'] is False
    if directory is None or directory.get('state') != 'listed' or 'noexec' in directory:
        assert scripts(result) == []
        assert status(result)['00-header'] == ('unresolved', 'unresolved')


def test_truncated_listing_still_reports_what_was_seen():
    result = run([f('00-header')], directory={'state': 'listed', 'complete': False})
    assert scripts(result) == ['00-header']
    assert result['complete'] is False


def test_absent_or_not_directory_runs_nothing():
    for state in ('absent', 'not_directory'):
        result = run([], directory={'state': state})
        assert scripts(result) == [] and result['complete'] is True
        assert result['directory_state'] == state
    result = run([f('00-header')], directory={'state': 'absent'})
    assert scripts(result) == [] and 'input_malformed' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('item, code', [
    ({'name': '10-a', 'type': 'file'}, 'metadata_missing'),
    ({'name': '10-a', 'type': 'file', 'mode': 0o17777}, 'metadata_missing'),
    ({'name': '10-a', 'type': 'file', 'mode': True}, 'metadata_missing'),
    (link('10-a'), 'symlink_target_unobserved'),
    (link('10-a', {'type': 'file'}), 'metadata_missing'),
    (link('10-a', {'type': 'file', 'mode': 0o755, 'noexec': 'yes'}), 'metadata_missing'),
    ({'name': 'a/b', 'type': 'file', 'mode': 0o755}, 'input_malformed'),
    ({'name': '..', 'type': 'file', 'mode': 0o755}, 'input_malformed'),
    ({'name': 'x' * 256, 'type': 'file', 'mode': 0o755}, 'input_malformed'),
    ({'name': '10-a', 'type': 'socket', 'mode': 0o755}, 'input_malformed'),
    ('10-a', 'input_malformed'),
])
def test_malformed_or_missing_entry_metadata_is_blocking(item, code):
    result = run([item, f('20-b')])
    assert code in codes(result)
    assert result['complete'] is False
    assert scripts(result) == ['20-b']
    assert '10-a' not in scripts(result)


def test_entries_must_be_a_list_and_duplicates_are_blocking():
    assert 'input_malformed' in codes(run('00-header'))
    result = run([f('10-a'), f('10-a', 0o644)])
    assert scripts(result) == ['10-a'] and 'duplicate_name' in codes(result) and result['complete'] is False


def test_over_cap_input_is_truncated_and_blocking():
    result = run([f(f'{i:05d}') for i in range(um.MAX_ENTRIES + 5)])
    assert len(result['scripts']) == um.MAX_ENTRIES
    assert 'too_many_entries' in codes(result) and result['complete'] is False
    pam = [{'service': 'sshd', 'args': [], 'reached': 'no'}] * (um.MAX_INVOCATIONS + 1)
    result = run([], pam_motd=pam)
    assert 'too_many_invocations' in codes(result) and result['activation']['state'] == 'unknown'


def test_gaps_are_bounded():
    result = run([{'name': f'{i:03d}', 'type': 'file'} for i in range(200)])
    assert len(result['gaps']) == um.MAX_GAPS
    assert result['gaps'][-1]['code'] == 'gaps_truncated'
    assert result['complete'] is False


def test_contract_is_pure_and_does_not_mutate_input():
    entries = [f('00-header'), link('10-l', {'type': 'file', 'mode': 0o755, 'noexec': False})]
    snapshot = repr(entries)
    first = run(entries)
    assert repr(entries) == snapshot
    assert run(entries) == first


@pytest.mark.skipif(shutil.which('run-parts') is None or os.geteuid() != 0,
                    reason='needs debianutils run-parts and root (execute-bit semantics are root\'s)')
def test_live_run_parts_agrees_on_names_types_and_order(tmp_path):
    version = subprocess.run(['run-parts', '--version'], capture_output=True, text=True).stdout
    if 'Debian run-parts' not in version:
        pytest.skip('not debianutils run-parts')
    entries = []
    for name in LSBSYSINIT_ACCEPTED[:20] + LSBSYSINIT_REJECTED[:20]:
        (tmp_path / name).write_text('#!/bin/sh\n')
        (tmp_path / name).chmod(0o755)
        entries.append(f(name))
    for name, mode in (('60-noexec', 0o644), ('61-otherx', 0o001)):
        (tmp_path / name).write_text('#!/bin/sh\n')
        (tmp_path / name).chmod(mode)
        entries.append(f(name, mode))
    (tmp_path / '62-dir').mkdir()
    entries.append(f('62-dir', type='directory'))
    (tmp_path / '63-link').symlink_to(tmp_path / '61-otherx')
    entries.append(link('63-link', {'type': 'file', 'mode': 0o001, 'noexec': False}))
    (tmp_path / '64-dangling').symlink_to(tmp_path / 'missing')
    entries.append(link('64-dangling', None))
    os.mkfifo(tmp_path / '65-fifo')
    entries.append(f('65-fifo', type='other'))
    out = subprocess.run(['run-parts', '--test', '--lsbsysinit', str(tmp_path)], capture_output=True,
                         env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')}).stdout.decode()
    observed = [line.rsplit('/', 1)[1] for line in out.splitlines()]
    assert scripts(run(entries)) == observed
