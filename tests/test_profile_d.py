"""Tests for the pure /etc/profile.d login-shell contract (#1049)."""
from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from app import profile_d

DEFAULT_PROFILE = '''# /etc/profile: system-wide .profile file for the Bourne shell (sh(1))
# and Bourne compatible shells (bash(1), ksh(1), ash(1), ...).

if [ "${PS1-}" ]; then
  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then
    # The file bash.bashrc already sets the default PS1.
    # PS1='\\h:\\w\\$ '
    if [ -f /etc/bash.bashrc ]; then
      . /etc/bash.bashrc
    fi
  else
    if [ "$(id -u)" -eq 0 ]; then
      PS1='# '
    else
      PS1='$ '
    fi
  fi
fi

if [ -d /etc/profile.d ]; then
  for i in /etc/profile.d/*.sh; do
    if [ -r $i ]; then
      . $i
    fi
  done
  unset i
fi
'''
LISTED = {'state': 'listed', 'complete': True}
READ = {'state': 'read', 'text': DEFAULT_PROFILE}


def f(name, mode=0o644, uid=0, gid=0):
    return {'name': name, 'type': 'file', 'mode': mode, 'uid': uid, 'gid': gid}


def run(entries, **kwargs):
    kwargs.setdefault('family', 'debian')
    kwargs.setdefault('directory', LISTED)
    kwargs.setdefault('profile', READ)
    return profile_d.evaluate(entries, **kwargs)


def by_name(result):
    return {rec['name']: rec for rec in result['entries']}


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def test_default_profile_sources_matching_files_in_byte_order():
    result = run([f('z.sh'), f('a.sh'), f('m10.sh'), f('README'), f('.hidden.sh'), f('x.csh'), f('bash')])
    assert result['activation']['state'] == 'active'
    assert [s['name'] for s in result['scripts']] == ['a.sh', 'm10.sh', 'z.sh']
    assert all(s['other_accounts'] == 'sourced' for s in result['scripts'])
    assert result['complete'] is True and result['gaps'] == []
    recs = by_name(result)
    for skipped in ('README', '.hidden.sh', 'x.csh', 'bash'):
        assert recs[skipped]['root'] == 'skipped' and recs[skipped]['root_reason_code'] == 'name_not_matched'


@pytest.mark.parametrize(('name', 'matched'), [
    ('a.sh', True), ('*.sh', True), ('A.SH', False), ('a.SH', False), ('.sh', False), ('.a.sh', False),
    ('a.sh~', False), ('a.sh.dpkg-old', False), ('a.bash', False), ('01-locale-fix.sh', True), ('x.sh.sh', True),
])
def test_glob_name_rule(name, matched):
    assert profile_d.name_matched(name) is matched


def test_root_reads_mode_0000_but_other_accounts_do_not():
    recs = by_name(run([f('locked.sh', 0o000)]))
    assert recs['locked.sh']['root'] == 'sourced'
    assert recs['locked.sh']['other_accounts'] == 'skipped'
    assert recs['locked.sh']['other_reason_code'] == 'not_readable'


@pytest.mark.parametrize(('mode', 'uid', 'expected'), [
    (0o644, 0, 'all'), (0o604, 0, 'some'), (0o444, 0, 'all'), (0o640, 0, 'some'), (0o600, 0, 'none'), (0o400, 0, 'none'),
    (0o400, 1000, 'some'), (0o044, 1000, 'some'), (0o444, 1000, 'all'), (0o000, 1000, 'none'),
    (0o004, 0, 'some'),
])
def test_other_accounts_readable_uses_one_access_class(mode, uid, expected):
    assert profile_d.other_accounts_readable(mode, uid) == expected


def test_group_only_file_depends_on_account():
    result = run([f('grp.sh', 0o640, 0, 4)])
    assert result['scripts'] == [{'order': 0, 'name': 'grp.sh', 'path': '/etc/profile.d/grp.sh',
                                  'other_accounts': 'depends_on_account'}]


def test_symlinks_follow_target_and_dangling_links_are_skipped():
    entries = [
        {'name': 'ok.sh', 'type': 'symlink', 'link_target': '/usr/share/x/ok.sh',
         'target': {'type': 'file', 'mode': 0o644, 'uid': 0, 'gid': 0}},
        {'name': 'dang.sh', 'type': 'symlink', 'link_target': '/nonexistent', 'target': None},
        {'name': 'unk.sh', 'type': 'symlink'},
    ]
    result = run(entries)
    recs = by_name(result)
    assert [s['name'] for s in result['scripts']] == ['ok.sh']
    assert result['scripts'][0]['link_target'] == '/usr/share/x/ok.sh'
    assert recs['dang.sh']['root'] == 'skipped' and recs['dang.sh']['root_reason_code'] == 'target_missing'
    assert recs['unk.sh']['root'] == 'unresolved'
    assert 'symlink_target_unobserved' in codes(result) and result['complete'] is False


def test_directory_named_sh_is_a_non_fatal_error():
    result = run([{'name': 'dir.sh', 'type': 'directory'}, f('z.sh')])
    assert by_name(result)['dir.sh']['root'] == 'error'
    assert [s['name'] for s in result['scripts']] == ['z.sh']
    assert result['complete'] is True


def test_special_file_is_unknown_and_blocking():
    result = run([{'name': 'fifo.sh', 'type': 'other'}])
    assert by_name(result)['fifo.sh']['root'] == 'unknown'
    assert 'special_file' in codes(result) and result['complete'] is False and result['scripts'] == []


@pytest.mark.parametrize('name', ['a b.sh', 'a -o b.sh', 'tab\there.sh', 'x*.sh', 'q?.sh', 'br[a].sh'])
def test_unquoted_expansion_names_are_unknown_and_blocking(name):
    result = run([f(name)])
    rec = by_name(result)[name]
    assert rec['root'] == 'unknown' and rec['root_reason_code'] == 'unquoted_expansion'
    assert result['scripts'] == [] and result['complete'] is False


@pytest.mark.parametrize(('names', 'sensitive'), [
    (['a.sh', 'b.sh', 'c10.sh'], False),
    (['a.sh', 'a1.sh'], True),
    (['01-locale-fix.sh', 'bun.sh'], True),
    (['B.sh', 'a.sh'], True),
    (['x_y.sh', 'xz.sh'], True),
    (['only.sh'], False),
])
def test_locale_collation_gap_is_non_blocking(names, sensitive):
    result = run([f(name) for name in names])
    assert ('order_locale_dependent' in codes(result)) is sensitive
    assert result['complete'] is True


def test_missing_profile_is_inactive_and_modified_loop_is_unknown():
    result = run([f('a.sh')], profile={'state': 'absent'})
    assert result['activation']['state'] == 'inactive' and result['complete'] is True
    quoted = DEFAULT_PROFILE.replace('. $i', '. "$i"')
    result = run([f('a.sh')], profile={'state': 'read', 'text': quoted})
    assert result['activation']['state'] == 'unknown' and 'profile_loop_modified' in codes(result)
    assert result['complete'] is False
    extra = DEFAULT_PROFILE + '\n. /etc/profile.d/extra\n'
    assert run([], profile={'state': 'read', 'text': extra})['activation']['state'] == 'unknown'
    twice = DEFAULT_PROFILE + DEFAULT_PROFILE
    assert run([], profile={'state': 'read', 'text': twice})['activation']['state'] == 'unknown'
    commented = DEFAULT_PROFILE + '\n# see /etc/profile.d\n'
    assert run([], profile={'state': 'read', 'text': commented})['activation']['state'] == 'active'
    crlf = DEFAULT_PROFILE.replace('\n', '  \r\n')
    assert run([], profile={'state': 'read', 'text': crlf})['activation']['state'] == 'active'


@pytest.mark.parametrize(('kwargs', 'code'), [
    ({'family': None}, 'family_not_observed'),
    ({'family': 'arch'}, 'family_unsupported'),
    ({'family': 'rpm'}, 'family_not_modelled'),
    ({'profile': None}, 'profile_not_observed'),
    ({'profile': {'state': 'unreadable'}}, 'profile_unreadable'),
    ({'profile': {'state': 'read'}}, 'input_malformed'),
    ({'profile': {'state': 'absent', 'text': 'x'}}, 'input_malformed'),
    ({'profile': {'state': 'read', 'text': 'x' * (64 * 1024 + 1)}}, 'profile_too_large'),
    ({'directory': None}, 'directory_not_observed'),
    ({'directory': {'state': 'listed'}}, 'input_malformed'),
    ({'directory': {'state': 'listed', 'complete': 'yes'}}, 'input_malformed'),
    ({'directory': {'state': 'listed', 'complete': False}}, 'listing_incomplete'),
    ({'directory': {'state': 'unreadable'}}, 'directory_unreadable'),
    ({'directory': {'state': 'weird', 'complete': True}}, 'input_malformed'),
])
def test_unobserved_or_malformed_input_is_blocking(kwargs, code):
    result = run([f('a.sh')], **kwargs)
    assert code in codes(result)
    assert result['complete'] is False


def test_entries_outside_a_listed_directory_never_report_sourced():
    for state in ('unreadable', 'absent', 'not_directory'):
        result = run([f('a.sh'), f('README')], directory={'state': state})
        assert result['scripts'] == []
        recs = by_name(result)
        assert recs['a.sh']['root'] == 'unresolved' and recs['README']['root'] == 'skipped'
    assert run([], directory={'state': 'absent'})['complete'] is True


@pytest.mark.parametrize('item', [
    None, {}, {'name': 'a/b.sh', 'type': 'file'}, {'name': '', 'type': 'file'}, {'name': 'a.sh', 'type': 'x'},
    {'name': 'n' * 300 + '.sh', 'type': 'file'},
])
def test_malformed_entries_are_blocking(item):
    result = run([item, f('ok.sh')])
    assert 'input_malformed' in codes(result) and result['complete'] is False
    assert [s['name'] for s in result['scripts']] == ['ok.sh']


@pytest.mark.parametrize('item', [
    {'name': 'a.sh', 'type': 'file'},
    {'name': 'a.sh', 'type': 'file', 'mode': 0o644, 'uid': 0},
    {'name': 'a.sh', 'type': 'file', 'mode': True, 'uid': 0, 'gid': 0},
    {'name': 'a.sh', 'type': 'file', 'mode': 0o644, 'uid': -1, 'gid': 0},
    {'name': 'a.sh', 'type': 'symlink', 'target': {'type': 'file', 'mode': 0o644}},
])
def test_missing_metadata_is_unresolved(item):
    result = run([item])
    assert by_name(result)['a.sh']['root'] == 'unresolved'
    assert 'metadata_missing' in codes(result) and result['complete'] is False and result['scripts'] == []


def test_duplicates_and_limits_are_blocking():
    result = run([f('a.sh'), f('a.sh', 0o000)])
    assert 'duplicate_name' in codes(result) and result['complete'] is False
    many = [f(f'n{i:05d}.sh') for i in range(profile_d.MAX_ENTRIES + 1)]
    result = run(many)
    assert 'too_many_entries' in codes(result) and len(result['scripts']) == profile_d.MAX_ENTRIES
    result = run('not a list')
    assert 'input_malformed' in codes(result)


def test_gap_budget_truncates_and_blocks():
    result = run([f(f'a {i}.sh') for i in range(200)])
    assert len(result['gaps']) == profile_d.MAX_GAPS and result['gaps'][-1]['code'] == 'gaps_truncated'


def test_input_is_not_mutated_and_result_is_not_a_verdict():
    entries = [f('a.sh'), {'name': 'l.sh', 'type': 'symlink', 'target': {'type': 'file', 'mode': 0o644,
                                                                           'uid': 0, 'gid': 0}}]
    snapshot = repr(entries)
    result = run(entries)
    assert repr(entries) == snapshot
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['note']
    assert result['loop'] == list(profile_d.DEFAULT_LOOP)


def test_real_profile_on_this_host_matches_loop_when_debian():
    path = Path('/etc/profile')
    if not path.is_file() or not Path('/etc/debian_version').exists():
        pytest.skip('not a Debian-family host')
    text = path.read_text(errors='surrogateescape')
    if '/etc/profile.d/*.sh' not in text:
        pytest.skip('host /etc/profile is customized')
    assert profile_d.loop_present(text)


def _observe(directory: Path) -> list[dict]:
    entries = []
    for name in os.listdir(directory):
        path = directory / name
        st = path.lstat()
        if path.is_symlink():
            try:
                tst = path.stat()
            except OSError:
                target = None
            else:
                target = ({'type': 'file', 'mode': tst.st_mode & 0o7777, 'uid': tst.st_uid, 'gid': tst.st_gid}
                          if Path(path).is_file() else {'type': 'directory' if path.is_dir() else 'other'})
            entries.append({'name': name, 'type': 'symlink', 'target': target})
        elif path.is_dir():
            entries.append({'name': name, 'type': 'directory'})
        elif path.is_file():
            entries.append({'name': name, 'type': 'file', 'mode': st.st_mode & 0o7777, 'uid': st.st_uid,
                            'gid': st.st_gid})
        else:
            entries.append({'name': name, 'type': 'other'})
    return entries


@pytest.mark.skipif(not (shutil.which('dash') and hasattr(os, 'geteuid') and os.geteuid() == 0),
                    reason='needs dash and root')
def test_live_dash_matches_contract_as_root_and_nobody():
    try:
        nobody = pwd.getpwnam('nobody')
    except KeyError:
        pytest.skip('no nobody account')
    base = Path(tempfile.mkdtemp(prefix='profiled-', dir='/tmp'))
    try:
        base.chmod(0o755)
        pd = base / 'profile.d'
        pd.mkdir(mode=0o755)
        pd.chmod(0o755)
        spec = {'a.sh': 0o644, 'z.sh': 0o644, 'm.sh': 0o000, 'g.sh': 0o640, 'o.sh': 0o604, 'B.sh': 0o644,
                '_u.sh': 0o644, 'a1.sh': 0o644, 'noext': 0o644, '.hid.sh': 0o644, 'x.csh': 0o644}
        for name, mode in spec.items():
            (pd / name).write_text(f'echo "SOURCED {name}"\n')
            os.chown(pd / name, 0, 0)
            (pd / name).chmod(mode)
        (pd / 'dir.sh').mkdir()
        (pd / 'dang.sh').symlink_to('/nonexistent-profiled-target')
        (pd / 'lm.sh').symlink_to(pd / 'm.sh')
        (pd / 'la.sh').symlink_to(pd / 'a.sh')
        loop = '\n'.join(profile_d.DEFAULT_LOOP).replace(profile_d.PROFILE_D, str(pd))
        script = base / 'profile'
        script.write_text(loop + '\n')
        script.chmod(0o644)
        result = run(_observe(pd))
        assert result['complete'] is True

        def sourced(cmd):
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env={'PATH': '/usr/bin:/bin'},
                                 check=False).stdout
            return [line.split(' ', 1)[1] for line in out.splitlines() if line.startswith('SOURCED ')]

        root_actual = sourced(['dash', '-c', f'. {script}'])
        # Sourcing a symlink prints the target's echo, so compare by position against expected targets.
        expected_root = [s['name'] for s in result['scripts']]
        link_of = {'lm.sh': 'm.sh', 'la.sh': 'a.sh'}
        assert root_actual == [link_of.get(name, name) for name in expected_root]

        def demote():
            os.setgid(nobody.pw_gid)
            os.setgroups([nobody.pw_gid])
            os.setuid(nobody.pw_uid)

        out = subprocess.run(['dash', '-c', f'. {script}'], capture_output=True, text=True, timeout=30,
                             env={'PATH': '/usr/bin:/bin'}, preexec_fn=demote, check=False).stdout
        nobody_actual = [line.split(' ', 1)[1] for line in out.splitlines() if line.startswith('SOURCED ')]
        # nobody is neither the owner (root) nor in group root, so only the other class applies to it:
        # a depends_on_account file is read exactly when its other bit is set.
        modes = {name: mode for name, mode in spec.items()}
        expected_nobody = [link_of.get(s['name'], s['name']) for s in result['scripts']
                           if s['other_accounts'] == 'sourced'
                           or (s['other_accounts'] == 'depends_on_account'
                               and modes[link_of.get(s['name'], s['name'])] & 0o004)]
        assert nobody_actual == expected_nobody
        depends = [s['name'] for s in result['scripts'] if s['other_accounts'] == 'depends_on_account']
        assert depends == ['g.sh', 'o.sh']
        assert 'm.sh' in root_actual and 'm.sh' not in nobody_actual
    finally:
        shutil.rmtree(base, ignore_errors=True)
