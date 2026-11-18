import os
import shutil
import subprocess

import pytest

from app import kernel_hooks as kh

LISTED = {'state': 'listed', 'complete': True, 'noexec': False}
ABSENT = {'state': 'absent'}

# Pinned from `LC_ALL=C run-parts --list` (debianutils 5.17, Ubuntu 24.04) over a seeded random corpus plus
# real /etc/kernel hook names and backup-suffix variants, every entry an executable regular file.
# Order is run-parts' own.
DEFAULT_ACCEPTED = (
    '-', '-0Z9', '-9', '-9a_a', '-Z', '-x', '0', '00-header', '0aZa_', '0aa', '9', '90', '99', '99-0a', '9Z9_a',
    'A', 'Foo_Bar-9', 'README', 'Z', 'Z0', 'ZZ-a-', '_', '_0a', '_ZaZ', '__0_', '_x', 'a', 'a0', 'a9', 'aZ',
    'apt-auto-removal', 'dkms', 'initramfs-tools', 'statoverride', 'unattended-upgrades', 'update-notifier',
    'xx-update-initrd-links', 'zz-runlilo', 'zz-update-grub',
)

DEFAULT_REJECTED = (
    ' ', '  9', '  a', ' +. -', ' 0a0Z', ' @9', ' @~ ~9', ' Z', ' _++', ' ~', ' ~ ', ' ~9Z', '+', '+ 0', '++',
    '+-_', '+-aZ', '+. ', '+.- 9', '+0.', '+9a@', '+@', '+@+_Z', '+@09-9', '+@~a', '+Z', '+Z@', '+_+_', '+_. ',
    '+_@.Z', '+_@@', '+_~~@', '+a', '+a-.@9', '+~', '+~_+@', '+~a00 ', '- ', '-++ -', '-- .', '-.0.9 ', '-0@.',
    '-0_@.', '-9 ', '-9a@Z', '-@', '-@+9a@', '-@_', '-Z@_', '-_@9~', '-~~00 ', '. ~_', '.+', '.+@- ', '.- +',
    '.- ~', '.-a', '.-a+', '.-aZZ', '..+ ', '.0ZZ_', '.9Z', '.9a+a', '.Z~', '.a9Z@~', '.a@ ', '.hidden', '.~+. _',
    '.~Z- _', '0+.0', '0@0~', '0@Z', '0Z+', '0_a_ ', '0a. ', '0a@ -Z', '0~a~', '0~a~a.', '50-x.ucf-dist', '9+0_Z-',
    '9+_a-', '9.', '9.9 ++', '9._', '909+', '9@09Z~', '9_- @-', '9a0-~-', '@', '@ a 0', '@++.Z', '@- -_', '@..Z',
    '@0', '@0+9', '@9', '@@@a-.', '@@~@~0', '@Z+Z', '@Z.9~.', '@Z9_@-', '@Z@+0a', '@Z~', '@_', '@_-Z', '@a. +',
    '@a@-', '@aa0', '@~ 9', '@~~9', 'Z ', 'Z-.', 'Z.', 'Z.a0@-', 'Z9 ', 'Z@', 'Z@+0', 'Z@+0-', 'ZZ ZZ9', 'ZZa~ ',
    'Z_+~0', 'Z~ 0Z', '_ 9_~', '_+', '_+.', '_+_ ', '_+a', '_0+90 ', '_9Z~', '__._', '__a ', '_~-a ', '_~9', 'a b',
    'a ~+@.', 'aZ+~Z', 'aZ@+', 'a_aa~-', 'aa+', 'aa@', 'aa_ 09', 'a~9.-~', 'dkms.dpkg-new', 'x.dpkg-dist',
    'x.dpkg-old', 'x.rpmsave', 'x.sh', 'x~', 'zz-update-grub.bak', 'zz-update-grub~', '~', '~ +-', '~ .0..',
    '~+ a+', '~-Z', '~-a+9', '~.-', '~.Z9  ', '~0.aZ9', '~0~++-', '~9', '~9-09+', '~9a', '~@_9-0', '~@~Z', '~Z.@_Z',
    '~Z0', '~ZZa', '~a.-9',
)



def f(name, mode=0o755, type='file'):
    return {'name': name, 'type': type, 'mode': mode}


def link(name, target=..., text='target'):
    item = {'name': name, 'type': 'symlink', 'link_target': text}
    if target is not ...:
        item['target'] = target
    return item


def obs(entries=(), directory=LISTED):
    return {'directory': directory, 'entries': list(entries)}


def all_absent(**overrides):
    observations = {hook: obs(directory=ABSENT) for hook in kh.HOOKS}
    observations.update(overrides)
    return observations


def run(family='debian', **overrides):
    return kh.evaluate(all_absent(**overrides), family=family)


def hook(result, name):
    return next(item for item in result['hooks'] if item['hook'] == name)


def by_name(hook_result):
    return {entry['name']: entry for entry in hook_result['entries']}


def test_name_rule_matches_pinned_run_parts_corpus():
    assert [n for n in DEFAULT_ACCEPTED if kh.name_considered(n)] == list(DEFAULT_ACCEPTED)
    assert [n for n in DEFAULT_REJECTED if kh.name_considered(n)] == []
    result = run(postinst=obs(f(n) for n in DEFAULT_ACCEPTED + DEFAULT_REJECTED))
    assert [s['name'] for s in hook(result, 'postinst')['scripts']] == list(DEFAULT_ACCEPTED)
    assert result['complete'] is True


def test_hook_invocations_match_shipped_maintainer_scripts():
    result = run()
    hooks = {item['hook']: item for item in result['hooks']}
    assert list(hooks) == ['preinst', 'postinst', 'prerm', 'postrm', 'header_postinst']
    assert hooks['postinst']['command'] == ['run-parts', '--report', '--exit-on-error', '--arg=<version>',
                                            '--arg=<image_path>', '/etc/kernel/postinst.d']
    assert hooks['header_postinst']['command'] == ['run-parts', '--report', '--exit-on-error', '--arg=<version>',
                                                   '/etc/kernel/header_postinst.d']
    assert hooks['preinst']['actions'] == ['install', 'upgrade']
    assert hooks['prerm']['actions'] == ['remove']
    assert 'upgrade' in hooks['postrm']['actions'] and 'purge' in hooks['postrm']['actions']
    assert hooks['postinst']['deferred_by_trigger'] is True
    assert hooks['postinst']['packages'] == ['linux-image-*', 'linux-modules-*']
    assert hooks['header_postinst']['packages'] == ['linux-headers-*']
    assert result['runs_as'] == 'root' and 'DEB_MAINT_PARAMS' in result['environment']
    assert all(item['run_outcome'] == 'not_invoked' and item['scripts'] == [] for item in hooks.values())
    assert result['complete'] is True and result['origin'] == 'not_assessed'


def test_ubuntu_postinst_hooks_run_in_byte_order_and_skip_other_entries():
    entries = [f('zz-update-grub'), f('initramfs-tools'), f('dkms'), f('xx-update-initrd-links'),
               f('unattended-upgrades'), f('zz-update-grub.dpkg-old'), f('README', 0o644), f('notes', 0o644),
               f('sub', type='directory'), f('Zeta')]
    item = hook(run(postinst=obs(entries)), 'postinst')
    assert [s['name'] for s in item['scripts']] == ['Zeta', 'dkms', 'initramfs-tools', 'unattended-upgrades',
                                                    'xx-update-initrd-links', 'zz-update-grub']
    assert [s['requires_earlier_success'] for s in item['scripts']] == [False] + [True] * 5
    entries = by_name(item)
    assert entries['zz-update-grub.dpkg-old']['reason_code'] == 'name_rejected'
    assert entries['README']['reason_code'] == 'not_executable'
    assert entries['sub']['reason_code'] == 'directory'
    assert item['run_outcome'] == 'runs' and item['stops_at'] is None


def test_failed_stat_stops_the_walk_and_later_scripts_are_not_reached():
    entries = [f('a'), link('m', None, '/nonexistent'), f('z'), link('zz', {'type': 'file', 'mode': 0o755}),
               f('z.sh')]
    item = hook(run(prerm=obs(entries)), 'prerm')
    status = {name: (e['status'], e['reason_code']) for name, e in by_name(item).items()}
    assert status == {'a': ('runs', 'runs'), 'm': ('skipped', 'stat_failed'), 'z': ('not_reached', 'not_reached'),
                      'zz': ('not_reached', 'not_reached'), 'z.sh': ('skipped', 'name_rejected')}
    assert item['run_outcome'] == 'stops_early' and item['stops_at'] == '/etc/kernel/prerm.d/m'
    assert [s['name'] for s in item['scripts']] == ['a']


def test_other_file_types_are_reported_but_later_scripts_still_run():
    item = hook(run(postrm=obs([f('a'), f('m', type='other'), f('z')])), 'postrm')
    assert [s['name'] for s in item['scripts']] == ['a', 'z']
    assert by_name(item)['m']['reason_code'] == 'not_plain_file'
    assert item['run_outcome'] == 'fails_after_run'


def test_symlinks_are_followed_and_noexec_is_honored():
    entries = [link('a', {'type': 'file', 'mode': 0o100}, '../x'), link('b', {'type': 'directory'}),
               link('c', {'type': 'file', 'mode': 0o755, 'noexec': True}), f('d', 0o644)]
    item = hook(run(preinst=obs(entries)), 'preinst')
    codes = {name: e['reason_code'] for name, e in by_name(item).items()}
    assert codes == {'a': 'runs', 'b': 'directory', 'c': 'noexec_mount', 'd': 'not_executable'}
    assert item['scripts'] == [{'order': 0, 'name': 'a', 'path': '/etc/kernel/preinst.d/a', 'reached': 'yes',
                                'requires_earlier_success': False, 'link_target': '../x'}]
    noexec_dir = hook(run(preinst=obs([f('x')], {'state': 'listed', 'complete': True, 'noexec': True})), 'preinst')
    assert noexec_dir['scripts'] == [] and by_name(noexec_dir)['x']['reason_code'] == 'noexec_mount'


def test_unobserved_mount_flags_report_scripts_as_running_with_one_gap():
    result = run(postinst=obs([f(f'h{i}') for i in range(7)], {'state': 'listed', 'complete': True}))
    assert len(hook(result, 'postinst')['scripts']) == 7
    gaps = [g for g in result['gaps'] if g['code'] == 'mount_flags_not_observed']
    assert len(gaps) == 1 and 'and 2 more' in gaps[0]['detail']
    assert result['complete'] is True


def test_unresolved_entry_makes_later_scripts_reach_unknown_and_blocks():
    result = run(postinst=obs([f('a'), {'name': 'b', 'type': 'file'}, link('c'), f('d')]))
    item = hook(result, 'postinst')
    entries = by_name(item)
    assert entries['b']['status'] == 'unresolved' and entries['c']['status'] == 'unresolved'
    assert [(s['name'], s['reached']) for s in item['scripts']] == [('a', 'yes'), ('d', 'unknown')]
    codes = {g['code'] for g in result['gaps']}
    assert {'metadata_missing', 'symlink_target_unobserved'} <= codes
    assert result['complete'] is False


@pytest.mark.parametrize('directory, code', [
    ({'state': 'unreadable'}, 'directory_unreadable'),
    ({'state': 'listed', 'complete': False, 'noexec': False}, 'listing_incomplete'),
    ({'state': 'listed', 'noexec': False}, 'input_malformed'),
    ({'state': 'gone'}, 'input_malformed'),
    (None, 'input_malformed'),
])
def test_bad_directory_observations_fail_closed(directory, code):
    result = run(postinst=obs([f('a')], directory))
    item = hook(result, 'postinst')
    assert code in {g['code'] for g in result['gaps']}
    assert item['run_outcome'] == 'unknown'
    # Scripts seen in a partial listing are still shown; nothing is shown outside a listed directory.
    assert [s['name'] for s in item['scripts']] == (['a'] if code == 'listing_incomplete' else [])
    assert result['complete'] is False


def test_missing_hook_observation_and_entries_for_absent_directory_fail_closed():
    observations = all_absent()
    del observations['postrm']
    observations['prerm'] = obs([f('a')], ABSENT)
    result = kh.evaluate(observations, family='debian')
    codes = [(g['code'], g.get('path')) for g in result['gaps']]
    assert ('directory_not_observed', '/etc/kernel/postrm.d') in codes
    assert ('input_malformed', '/etc/kernel/prerm.d') in codes
    assert hook(result, 'prerm')['run_outcome'] == 'unknown'
    assert result['complete'] is False


@pytest.mark.parametrize('family, applicability, complete', [
    ('rpm', 'not_applicable', True), (None, 'unknown', False), ('arch', 'unknown', False)])
def test_family_applicability(family, applicability, complete):
    result = kh.evaluate(all_absent(), family=family)
    assert result['applicability'] == applicability and result['complete'] is complete
    assert result['hooks'] == [] if family != 'debian' else True


@pytest.mark.parametrize('observations', [None, [], 'x', {'bogus': obs()}])
def test_malformed_observation_mapping_fails_closed(observations):
    result = kh.evaluate(observations, family='debian')
    assert result['complete'] is False


@pytest.mark.parametrize('entry', [
    {'name': '', 'type': 'file', 'mode': 0o755}, {'name': 'a/b', 'type': 'file', 'mode': 0o755},
    {'name': '..', 'type': 'file', 'mode': 0o755}, {'name': 'a', 'type': 'fifo'}, 'a',
    {'name': 'a', 'type': 'file', 'mode': True}, {'name': 'a', 'type': 'file', 'mode': 0o17777},
    {'name': 'x' * 256, 'type': 'file', 'mode': 0o755},
])
def test_malformed_entries_fail_closed(entry):
    result = run(postinst=obs([entry]))
    assert result['complete'] is False
    assert hook(result, 'postinst')['scripts'] == []


def test_duplicates_and_limits_fail_closed():
    duplicate = run(postinst=obs([f('a'), f('a', 0o644)]))
    assert 'duplicate_name' in {g['code'] for g in duplicate['gaps']} and duplicate['complete'] is False
    assert by_name(hook(duplicate, 'postinst'))['a']['status'] == 'runs'
    many = run(postinst=obs(f(f'n{i:05d}') for i in range(kh.MAX_ENTRIES + 3)))
    assert len(hook(many, 'postinst')['scripts']) == kh.MAX_ENTRIES
    assert 'too_many_entries' in {g['code'] for g in many['gaps']} and many['complete'] is False
    noisy = run(postinst=obs([{'name': f'bad/{i}', 'type': 'file'} for i in range(kh.MAX_GAPS + 10)]))
    assert len(noisy['gaps']) == kh.MAX_GAPS and noisy['gaps'][-1]['code'] == 'gaps_truncated'


def test_inputs_are_not_mutated_and_output_is_not_a_verdict():
    entries = [f('a'), link('b', {'type': 'file', 'mode': 0o755})]
    snapshot = repr(entries)
    result = run(postinst=obs(entries))
    assert repr(entries) == snapshot
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['note']
    assert not any(key in result for key in ('verdict', 'action', 'response'))


@pytest.mark.skipif(shutil.which('run-parts') is None or os.geteuid() != 0,
                    reason='needs debianutils run-parts and root')
def test_live_run_parts_matches_the_contract(tmp_path):
    hookdir = tmp_path / 'postinst.d'
    hookdir.mkdir()
    log = tmp_path / 'log'
    script = f'#!/bin/sh\necho "$(basename "$0") $*" >> {log}\n'
    for name, mode in (('zz-update-grub', 0o755), ('dkms', 0o755), ('Upper', 0o755), ('x.sh', 0o755),
                       ('plain', 0o644), ('exec-only', 0o100), ('m-later', 0o755)):
        (hookdir / name).write_text(script)
        (hookdir / name).chmod(mode)
    (hookdir / 'sub').mkdir()
    (tmp_path / 'target').write_text(script)
    (tmp_path / 'target').chmod(0o755)
    (hookdir / 'linked').symlink_to(tmp_path / 'target')
    entries = [f('zz-update-grub'), f('dkms'), f('Upper'), f('x.sh'), f('plain', 0o644), f('exec-only', 0o100),
               f('m-later'), f('sub', type='directory'), link('linked', {'type': 'file', 'mode': 0o755})]
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'}
    command = ['run-parts', '--report', '--exit-on-error', '--arg=6.8.0-71-generic',
               '--arg=/boot/vmlinuz-6.8.0-71-generic', str(hookdir)]
    done = subprocess.run(command, check=False, env=env, capture_output=True, text=True, timeout=30)
    assert done.returncode == 0
    ran = [line.split()[0] for line in log.read_text().splitlines()]
    item = hook(run(postinst=obs(entries)), 'postinst')
    assert 'Upper' in ran and 'exec-only' in ran and 'linked' in ran
    assert ran == [s['name'] for s in item['scripts']]

    # A dangling symlink stops the real walk exactly where the contract says.
    log.unlink()
    (hookdir / 'n-dangling').symlink_to(tmp_path / 'missing')
    done = subprocess.run(command, check=False, env=env, capture_output=True, text=True, timeout=30)
    assert done.returncode != 0 and 'failed to stat' in done.stderr
    item = hook(run(postinst=obs(entries + [link('n-dangling', None)])), 'postinst')
    assert item['run_outcome'] == 'stops_early'
    ran = [line.split()[0] for line in log.read_text().splitlines()]
    assert ran == [s['name'] for s in item['scripts']]


def test_any_execute_bit_runs_as_root():
    item = hook(run(postinst=obs([f('g', 0o010), f('o', 0o001), f('u', 0o100), f('n', 0o666)])), 'postinst')
    assert [s['name'] for s in item['scripts']] == ['g', 'o', 'u']
