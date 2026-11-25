"""Tests for the pure grub-mkconfig contract (#1136).

Expected outcomes follow util/grub-mkconfig.in and util/grub-mkconfig_lib.in in
GRUB 2.06 and 2.12, plus Debian's /etc/default/grub.d patch.
"""
from app import grub_mkconfig as gm

GRUB_D = {'path': '/etc/grub.d', 'state': 'listed'}
DEFAULT_D = {'path': '/etc/default/grub.d', 'state': 'listed'}
FILE = {'type': 'file', 'mode': 0o644}


def f(name, mode=0o755, kind='file', target=None, target_mode=None):
    entry = {'name': name, 'type': kind}
    if kind == 'symlink':
        entry.update(target_type=target, target_mode=target_mode)
    else:
        entry['mode'] = mode
    return entry


# Ubuntu 24.04 grub2-common/grub-pc /etc/grub.d listing.
UBUNTU = [f('00_header'), f('05_debian_theme'), f('10_linux'), f('10_linux_zfs'), f('20_linux_xen'),
          f('25_bli'), f('30_os-prober'), f('30_uefi-firmware'), f('35_fwupd'), f('40_custom'), f('41_custom'),
          f('README', 0o644)]


def run(entries, family='debian', default_grub=FILE, default_entries=(), grub_d=GRUB_D, default_d=DEFAULT_D):
    return gm.evaluate(family=family, grub_d=grub_d, grub_d_entries=entries, default_grub=default_grub,
                       default_d=default_d, default_d_entries=list(default_entries))


def status(result):
    return {s['name']: (s['status'], s['reason']) for s in result['scripts']}


def codes(result):
    return [g['code'] for g in result['gaps']]


def test_ubuntu_listing_runs_every_numbered_script_in_byte_order_and_skips_readme():
    result = run(UBUNTU, default_entries=[f('init-select.cfg', 0o644)])
    assert result['complete'] and not result['gaps']
    assert result['command'] == 'grub-mkconfig' and result['execution']['user'] == 'root'
    assert [r['name'] for r in result['runs']] == [
        '00_header', '05_debian_theme', '10_linux', '10_linux_zfs', '20_linux_xen', '25_bli', '30_os-prober',
        '30_uefi-firmware', '35_fwupd', '40_custom', '41_custom']
    assert status(result)['README'] == ('skipped_garbage', 'readme')
    assert result['runs'][0] == {'name': '00_header', 'path': '/etc/grub.d/00_header', 'mode': '0755',
                                 'origin': 'not_assessed'}
    assert [(s['path'], s['status']) for s in result['sourced']] == [
        ('/etc/default/grub', 'sourced'), ('/etc/default/grub.d/init-select.cfg', 'sourced')]
    assert result['order'] == {'shell': 'dash', 'basis': 'byte', 'reported': 'byte', 'certain': True}
    assert result['origin'] == 'not_assessed' and result['not_observed']


def test_editor_backups_and_package_leftovers_are_skipped_even_when_executable():
    names = ['10_linux~', '#40_custom#', '10_linux.dpkg-dist', '10_linux.dpkg-old', '40_custom.rpmnew',
             '40_custom.rpmsave', 'README.md', '10_linux.sig', '#', '40_custom#']
    result = run([f(n) for n in names])
    assert status(result) == {
        '10_linux~': ('skipped_backup', 'editor_backup'), '#40_custom#': ('skipped_backup', 'editor_autosave'),
        '10_linux.dpkg-dist': ('skipped_garbage', 'dpkg_leftover'),
        '10_linux.dpkg-old': ('skipped_garbage', 'dpkg_leftover'),
        '40_custom.rpmnew': ('skipped_garbage', 'rpm_leftover'),
        '40_custom.rpmsave': ('skipped_garbage', 'rpm_leftover'),
        'README.md': ('skipped_garbage', 'readme'), '10_linux.sig': ('skipped_garbage', 'signature'),
        # A lone '#' is not '#*#', and '40_custom#' does not start with '#': both run.
        '#': ('runs', None), '40_custom#': ('runs', None)}
    assert result['complete']


def test_any_execute_bit_runs_for_root_and_none_does_not():
    result = run([f('a', 0o700), f('b', 0o010), f('c', 0o001), f('d', 0o644), f('e', 0o4000)])
    assert status(result) == {'a': ('runs', None), 'b': ('runs', None), 'c': ('runs', None),
                              'd': ('not_executable', 'no_execute_bit'), 'e': ('not_executable', 'no_execute_bit')}


def test_symlinks_are_followed_and_non_files_skipped():
    result = run([f('15_ok', kind='symlink', target='file', target_mode=0o755),
                  f('16_dir', kind='symlink', target='directory'), f('17_gone', kind='symlink', target='missing'),
                  f('18_subdir', kind='directory'), f('19_fifo', kind='other'),
                  f('20_plain', kind='symlink', target='file', target_mode=0o644)])
    assert status(result) == {
        '15_ok': ('runs', None), '16_dir': ('skipped_non_file', 'directory'),
        '17_gone': ('skipped_non_file', 'dangling_symlink'), '18_subdir': ('skipped_non_file', 'directory'),
        '19_fifo': ('skipped_non_file', 'other'), '20_plain': ('not_executable', 'no_execute_bit')}
    assert result['complete']


def test_dot_names_never_match_the_glob():
    result = run([f('.hidden'), f('10_linux')])
    assert status(result)['.hidden'] == ('not_matched', 'dot_name')
    assert [r['name'] for r in result['runs']] == ['10_linux']


def test_unobserved_mode_type_or_target_fails_closed():
    result = run([{'name': '10_linux', 'type': 'file'}, {'name': '20_x'},
                  {'name': '30_y', 'type': 'symlink'}, f('40_custom')])
    assert status(result) == {'10_linux': ('unresolved', 'mode_not_observed'),
                              '20_x': ('unresolved', 'type_not_observed'),
                              '30_y': ('unresolved', 'target_not_observed'), '40_custom': ('runs', None)}
    assert not result['complete']
    assert set(codes(result)) == {'mode_not_observed', 'type_not_observed', 'target_not_observed'}


def test_unobserved_or_unreadable_directory_is_incomplete_not_empty():
    for listing in (None, {'path': '/etc/grub.d', 'state': 'unreadable'}, {'path': '/etc/grub', 'state': 'listed'}):
        result = run(UBUNTU, grub_d=listing)
        assert not result['complete'] and result['runs'] == []
        assert result['scripts'][0]['status'] == 'unresolved'


def test_absent_directory_runs_nothing_and_is_complete():
    result = run([], grub_d={'path': '/etc/grub.d', 'state': 'absent'})
    assert result['complete'] and result['scripts'] == [] and result['runs'] == []


def test_malformed_duplicate_and_over_limit_listings_fail_closed():
    assert 'malformed_entry' in codes(run([{'name': 'a/b', 'type': 'file', 'mode': 0o755}]))
    assert 'duplicate_entry' in codes(run([f('10_linux'), f('10_linux')]))
    result = run([f(f'{i:05d}') for i in range(gm.MAX_ENTRIES + 1)])
    assert not result['complete'] and 'entries_over_limit' in codes(result)


def test_debian_default_d_sources_only_existing_cfg_files_in_order():
    entries = [f('z.cfg', 0o644), f('a.cfg', 0o600), f('notes.txt', 0o644), f('.hidden.cfg', 0o644),
               f('gone.cfg', kind='symlink', target='missing'),
               f('link.cfg', kind='symlink', target='file', target_mode=0o644), f('dir.cfg', kind='directory')]
    result = run([], default_entries=entries)
    assert [(s['path'], s['status'], s['reason']) for s in result['sourced']] == [
        ('/etc/default/grub', 'sourced', None),
        ('/etc/default/grub.d/a.cfg', 'sourced', None),
        ('/etc/default/grub.d/dir.cfg', 'source_error', 'directory'),
        ('/etc/default/grub.d/gone.cfg', 'not_matched', 'dangling_symlink'),
        ('/etc/default/grub.d/link.cfg', 'sourced', None),
        ('/etc/default/grub.d/z.cfg', 'sourced', None)]
    # A shell error is reported but does not hide anything: the result stays complete.
    assert 'source_non_file' in codes(result) and result['complete']


def test_default_grub_needs_test_f_and_must_be_observed():
    missing = run([], default_grub={'type': 'missing'})
    assert missing['sourced'][0]['status'] == 'not_matched' and missing['complete']
    directory = run([], default_grub={'type': 'directory'})
    assert directory['sourced'][0]['status'] == 'not_matched' and directory['complete']
    unobserved = run([], default_grub=None)
    assert unobserved['sourced'][0]['status'] == 'unresolved' and not unobserved['complete']


def test_rpm_family_skips_default_d_and_flags_locale_dependent_order():
    result = gm.evaluate(family='rpm', grub_d=GRUB_D, grub_d_entries=[f('10_linux'), f('10_Linux2'), f('41_custom')],
                         default_grub=FILE, default_d=None)
    assert result['command'] == 'grub2-mkconfig'
    assert [s['path'] for s in result['sourced']] == ['/etc/default/grub']
    assert result['order']['shell'] == 'bash' and result['order']['certain'] is False
    assert 'order_locale_dependent' in codes(result) and result['complete']
    plain = gm.evaluate(family='rpm', grub_d=GRUB_D, grub_d_entries=[f('00_header'), f('10_linux'), f('40_custom')],
                        default_grub=FILE)
    assert plain['order']['certain'] and not plain['gaps']


def test_unknown_family_is_incomplete():
    result = gm.evaluate(family='arch', grub_d=GRUB_D, grub_d_entries=UBUNTU, default_grub=FILE)
    assert not result['complete'] and result['runs'] == [] and codes(result) == ['family_unknown']


def test_debian_default_d_must_be_observed():
    result = run([], default_d=None)
    assert not result['complete'] and result['sourced'][-1]['status'] == 'unresolved'


def test_order_certainty_follows_glibc_punctuation_and_case_rules():
    assert gm.order_certain(['00_header', '10_linux', '10_linux_zfs', '20_linux_xen'])
    assert not gm.order_certain(gm.byte_order(['10_linux', '10_Linux2', '10_linux3']))
    # Byte order puts 'B' before 'a'; a collating locale does not.
    assert not gm.order_certain(['B', 'a'])
    # '10-a' and '10_a' collide once punctuation is ignored.
    assert not gm.order_certain(['10-a', '10_a'])


# Copied from grub-common 2.12-1ubuntu7.3: grub_file_is_not_garbage from
# /usr/share/grub/grub-mkconfig_lib, the /etc/default sourcing from
# /usr/sbin/grub-mkconfig lines 160-169, and its script loop, lines 295-310.
# ``.`` and the script call print the path instead of reading or running it.
REFERENCE = r'''
sysconfdir="$1"; grub_mkconfig_dir="$1/grub.d"
grub_file_is_not_garbage ()
{
  if test -f "$1" ; then
    case "$1" in
      *.dpkg-*) return 1 ;; # debian dpkg
      *.rpmsave|*.rpmnew) return 1 ;;
      README*|*/README*)  return 1 ;; # documentation
      *.sig) return 1 ;; # signatures
    esac
  else
    return 1
  fi
  return 0
}
if test -f ${sysconfdir}/default/grub ; then
  echo "source ${sysconfdir}/default/grub"
fi
for x in ${sysconfdir}/default/grub.d/*.cfg ; do
  if [ -e "${x}" ]; then
    echo "source ${x}"
  fi
done
for i in "${grub_mkconfig_dir}"/* ; do
  case "$i" in
    *~) ;;
    */\#*\#) ;;
    *)
      if grub_file_is_not_garbage "$i" && test -x "$i" ; then
        echo "run $i"
      fi
    ;;
  esac
done
'''


def test_matches_the_reference_grub_mkconfig_loop_under_sh(tmp_path):
    import os
    import shutil
    import subprocess

    import pytest
    if not shutil.which('sh'):
        pytest.skip('no /bin/sh')
    root = tmp_path / 'etc'
    (root / 'grub.d').mkdir(parents=True)
    (root / 'default' / 'grub.d').mkdir(parents=True)
    (root / 'default' / 'grub').write_text('GRUB_TIMEOUT=5\n')
    # Owner execute bits only, so the result is the same as root and as an unprivileged test user.
    scripts = {'00_header': 0o755, '10_linux': 0o755, '10_linux~': 0o755, '#40_custom#': 0o755,
               '10_linux.dpkg-dist': 0o755, '40_custom.rpmnew': 0o755, 'README': 0o755, '10_linux.sig': 0o755,
               '41_custom': 0o644, '.hidden': 0o755, '#': 0o755, '50_x#': 0o755, 'Z_upper': 0o755}
    for name, mode in scripts.items():
        (root / 'grub.d' / name).write_text('#!/bin/sh\n')
        os.chmod(root / 'grub.d' / name, mode)
    (root / 'grub.d' / '20_dir').mkdir()
    os.symlink(root / 'grub.d' / '00_header', root / 'grub.d' / '15_link')
    os.symlink(root / 'nowhere', root / 'grub.d' / '16_dangling')
    for name in ('a.cfg', 'z.cfg', 'notes.txt', '.h.cfg'):
        (root / 'default' / 'grub.d' / name).write_text('X=1\n')
    os.symlink(root / 'nowhere', root / 'default' / 'grub.d' / 'gone.cfg')
    reference = subprocess.run(['sh', '-c', REFERENCE, 'sh', str(root)], capture_output=True, text=True,
                               check=True, env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'})

    def listing(directory):
        entries = []
        for name in os.listdir(directory):
            path = directory / name
            if path.is_symlink():
                target = ('missing' if not path.exists() else 'file' if path.is_file() else 'directory')
                entries.append({'name': name, 'type': 'symlink', 'target_type': target,
                                'target_mode': path.stat().st_mode & 0o7777 if target == 'file' else None})
            else:
                entries.append({'name': name, 'type': 'file' if path.is_file() else 'directory',
                                'mode': path.stat().st_mode & 0o7777})
        return entries

    result = gm.evaluate(family='debian', grub_d=GRUB_D, grub_d_entries=listing(root / 'grub.d'),
                         default_grub=FILE, default_d=DEFAULT_D, default_d_entries=listing(root / 'default' / 'grub.d'))
    expected = [line.replace(str(root), '/etc') for line in reference.stdout.splitlines()]
    actual = ([f'source {s["path"]}' for s in result['sourced'] if s['status'] == 'sourced'] +
              [f'run {r["path"]}' for r in result['runs']])
    assert actual == expected
    assert 'run /etc/grub.d/Z_upper' in expected and 'run /etc/grub.d/#' in expected
