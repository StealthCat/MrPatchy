"""Tests for the pure bash-completion compat-directory contract (#1197)."""
from __future__ import annotations

import copy
import os
import shutil
import subprocess
import tempfile

import pytest

from app import bash_completion_d as bc

# Verbatim from upstream bash_completion at the named tags.
UPSTREAM_GLOBS = {
    '2.10': ("@(#*#|*@(~|.@(bak|orig|rej|swp|dpkg*|rpm@(orig|new|save))))", '@(acroread.sh)'),
    '2.12': ("@(#*#|*@(~|.@(bak|orig|rej|swp|@(dpkg|ucf)-*|rpm@(orig|new|save))))", ''),
    '2.15': ("@(#*#|*@(~|.@(bak|orig|rej|swp|@(dpkg|ucf)-*|rpm@(orig|new|save))))", ''),
    '2.17': ("@(#*#|*@(~|.@(bak|orig|rej|swp|@(dpkg|ucf)-*|rpm@(orig|new|save)|zs-old)))", ''),
}
NAMES = ['git', 'zz', 'a b', 'x*y', '[q]', 'foo~', '#x#', '#', '##', 'f.bak', 'f.bak.sh', 'f.orig', 'f.rej',
         'f.swp', 'f.dpkg', 'f.dpkg-old', 'f.dpkg-dist', 'f.dpkgx', 'f.dpkg.sh', 'f.ucf-old', 'f.ucf', 'f.rpmnew',
         'f.rpmsave', 'f.rpmorig', 'f.rpm', 'f.zs-old', 'Makefile', 'Makefile.am', 'makefile', 'acroread.sh',
         'acroread', 'bak', 'x.BAK', 'Z', 'a-b', 'a_b', '@(x)', 'f.new', 'f.old', 'tilde~x', '~', 'f.', 'dpkg-x',
         'f.swp~', 'x.ucf-', 'x.dpkg-', 'Makefilex', 'ucf-x', 'a.dpkg-new.sh', 'zs-old', 'f.zs-oldx']
LOADER = {'state': 'present', 'version': '2.11'}


def regular(name, mode=0o644, uid=0, gid=0):
    return {'name': name, 'type': 'file', 'mode': mode, 'uid': uid, 'gid': gid}


def listed(*entries, complete=True):
    return {'state': 'listed', 'complete': complete, 'entries': list(entries)}


def absent():
    return {'state': 'absent', 'complete': None, 'entries': []}


def run(version='2.11', etc=None, usr=None, path=None):
    loader = {'state': 'present', 'version': version}
    if path is not None:
        loader['path'] = path
    directories = {'/etc/bash_completion.d': etc if etc is not None else listed()}
    if bc.FAMILIES[bc.family(version)]['second_directory']:
        directories['/usr/etc/bash_completion.d'] = usr if usr is not None else absent()
    return bc.evaluate(loader=loader, directories=directories)


def entry(result, name, directory='/etc/bash_completion.d'):
    return next(rec for rec in result['entries'] if rec['name'] == name and rec['directory'] == directory)


def codes(result):
    return [gap['code'] for gap in result['gaps']]


@pytest.mark.parametrize('version,expected', [
    ('2.10', '2.10'), ('2.11', '2.10'), ('2.12.0', '2.12'), ('2.13.0', '2.12'), ('2.14.0', '2.12'),
    ('2.15.0', '2.15'), ('2.16.0', '2.15'), ('2.17.0', '2.17'), ('2.9', None), ('2.18.0', None), ('1.3', None),
    ('3.0', None), ('2.11a', None), ('', None), (2.11, None), (None, None),
])
def test_version_families(version, expected):
    assert bc.family(version) == expected


@pytest.mark.parametrize('package,upstream', [
    ('1:2.11-8', '2.11'), ('1:2.16.0-7', '2.16.0'), ('2.11-5.el9', '2.11'), ('2.11', '2.11'),
    ('1:2.x-1', None), ('', None), (None, None), ('x' * 200, None),
])
def test_upstream_version_strips_epoch_and_revision(package, upstream):
    assert bc.upstream_version(package) == upstream


@pytest.mark.parametrize('version_family', sorted(bc.FAMILIES))
def test_name_rules_match_bash_extglob_on_verbatim_upstream_patterns(version_family):
    if not shutil.which('bash'):
        pytest.skip('bash is not installed')
    backup, block = UPSTREAM_GLOBS[version_family]
    script = ('shopt -s extglob\n_g=\'%s\'\n_b=\'%s\'\n'
              'while IFS= read -r n; do [[ $n != @($_g|Makefile*|$_b) ]] && printf "%%s\\n" "$n"; done'
              % (backup, block))
    out = subprocess.run(['bash', '--norc', '--noprofile', '-c', script], input='\n'.join(NAMES) + '\n',
                         capture_output=True, text=True, timeout=30, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    assert out.returncode in (0, 1), out.stderr
    kept = set(out.stdout.splitlines())
    assert kept == {name for name in NAMES if bc.name_skip(name, version_family) is None}


def test_version_specific_backup_rules():
    assert bc.name_skip('f.dpkgx', '2.10') == 'backup_name'
    assert bc.name_skip('f.dpkgx', '2.12') is None
    assert bc.name_skip('f.ucf-old', '2.10') is None
    assert bc.name_skip('f.ucf-old', '2.12') == 'backup_name'
    assert bc.name_skip('f.zs-old', '2.15') is None
    assert bc.name_skip('f.zs-old', '2.17') == 'backup_name'
    assert bc.name_skip('acroread.sh', '2.10') == 'block_listed'
    assert bc.name_skip('acroread.sh', '2.12') is None
    assert bc.name_skip('Makefile.am', '2.17') == 'makefile'
    assert bc.name_skip('.git', '2.17') == 'hidden'


def test_directories_per_version_and_loader_path():
    assert bc.compat_directories('2.10', bc.DEFAULT_LOADER) == ['/etc/bash_completion.d']
    for version_family in ('2.12', '2.15', '2.17'):
        assert bc.compat_directories(version_family, bc.DEFAULT_LOADER) == [
            '/etc/bash_completion.d', '/usr/etc/bash_completion.d']
    assert bc.compat_directories('2.15', '/opt/bc/share/bash-completion/bash_completion') == [
        '/etc/bash_completion.d', '/opt/bc/etc/bash_completion.d']
    assert bc.compat_directories('2.15', '/opt/bc/bash_completion') == [
        '/etc/bash_completion.d', '/opt/bc/bash_completion.d']
    # An empty prefix derives /etc/bash_completion.d itself, which is not scanned twice.
    assert bc.compat_directories('2.15', '/share/bash-completion/bash_completion') == ['/etc/bash_completion.d']


def test_legacy_loader_sources_eligible_files_in_byte_order():
    result = run('2.11', etc=listed(regular('zz'), regular('git'), regular('f.dpkg-old'), regular('Makefile'),
                                    regular('acroread.sh'), regular('.hidden'), regular('f.bak')))
    assert result['activation']['state'] == 'active'
    assert result['activation']['family'] == '2.10'
    assert [s['name'] for s in result['scripts']] == ['git', 'zz']
    assert [s['order'] for s in result['scripts']] == [0, 1]
    assert entry(result, 'f.dpkg-old')['root_reason_code'] == 'backup_name'
    assert entry(result, 'Makefile')['root_reason_code'] == 'makefile'
    assert entry(result, 'acroread.sh')['root_reason_code'] == 'block_listed'
    assert entry(result, '.hidden')['root_reason_code'] == 'hidden'
    # A hidden name only reaches a shell that set dotglob; that is disclosed, not blocking.
    assert 'hidden_name_dotglob' in codes(result)
    assert result['complete'] is True


def test_modern_loader_also_sources_the_usr_etc_directory_after_etc():
    result = run('2.16.0', etc=listed(regular('zz')), usr=listed(regular('aa'), regular('.hidden')))
    assert [(s['directory'], s['name'], s['order']) for s in result['scripts']] == [
        ('/etc/bash_completion.d', 'zz', 0), ('/usr/etc/bash_completion.d', 'aa', 1)]
    assert [d['path'] for d in result['directories']] == ['/etc/bash_completion.d', '/usr/etc/bash_completion.d']
    # 2.15 and later never match hidden names.
    assert 'hidden_name_dotglob' not in codes(result)
    assert result['complete'] is True


def test_unobserved_second_directory_is_blocking():
    result = bc.evaluate(loader={'state': 'present', 'version': '2.12.0'},
                         directories={'/etc/bash_completion.d': listed(regular('git'))})
    assert 'directory_not_observed' in codes(result)
    assert result['complete'] is False
    assert result['directories'][1] == {'path': '/usr/etc/bash_completion.d', 'state': 'unobserved'}


def test_root_reads_any_regular_file_and_other_accounts_use_one_class():
    result = run('2.15.0', etc=listed(regular('closed', 0o000), regular('group', 0o640), regular('owned', 0o600, 1000),
                                      regular('open', 0o644)))
    assert entry(result, 'closed')['root'] == 'sourced'
    assert entry(result, 'closed')['other_reason_code'] == 'not_readable'
    assert entry(result, 'group')['other_accounts'] == 'depends_on_account'
    assert entry(result, 'owned')['other_accounts'] == 'depends_on_account'
    assert entry(result, 'open')['other_accounts'] == 'sourced'
    # Byte order: closed, group, open, owned.
    assert [s['other_accounts'] for s in result['scripts']] == ['skipped', 'depends_on_account', 'sourced',
                                                                'depends_on_account']


def test_minus_f_skips_directories_special_files_and_dangling_links_without_blocking():
    target = {'type': 'file', 'mode': 0o644, 'uid': 0, 'gid': 0}
    result = run('2.15.0', etc=listed({'name': 'adir', 'type': 'directory'}, {'name': 'fifo', 'type': 'other'},
                                      {'name': 'gone', 'type': 'symlink', 'target': None, 'link_target': '/x'},
                                      {'name': 'todir', 'type': 'symlink', 'target': {'type': 'directory'}},
                                      {'name': 'link', 'type': 'symlink', 'target': target,
                                       'link_target': '/opt/tool/completion'}))
    assert entry(result, 'adir')['root_reason_code'] == 'not_regular'
    assert entry(result, 'fifo')['root_reason_code'] == 'not_regular'
    assert entry(result, 'todir')['root_reason_code'] == 'not_regular'
    assert entry(result, 'gone')['root_reason_code'] == 'target_missing'
    assert result['scripts'] == [{'order': 0, 'directory': '/etc/bash_completion.d', 'name': 'link',
                                  'path': '/etc/bash_completion.d/link', 'other_accounts': 'sourced',
                                  'link_target': '/opt/tool/completion'}]
    assert result['complete'] is True


def test_names_with_spaces_and_glob_characters_are_sourced_as_themselves():
    result = run('2.15.0', etc=listed(regular('a b'), regular('x*y'), regular('[q]')))
    assert sorted(s['name'] for s in result['scripts']) == ['[q]', 'a b', 'x*y']
    assert result['complete'] is True


@pytest.mark.parametrize('version,names,gap', [
    ('2.11', ['a-b', 'ab'], True), ('2.14.0', ['Git', 'apt'], True), ('2.11', ['apt', 'git'], False),
    ('2.15.0', ['a-b', 'Git'], False),
])
def test_locale_order_gap_only_before_2_15_and_non_blocking(version, names, gap):
    result = run(version, etc=listed(*(regular(name) for name in names)))
    assert ('order_locale_dependent' in codes(result)) is gap
    assert result['complete'] is True


def test_missing_loader_is_inactive_and_needs_no_listing():
    result = bc.evaluate(loader={'state': 'absent'})
    assert result['activation']['state'] == 'inactive'
    assert result['scripts'] == [] and result['complete'] is True


@pytest.mark.parametrize('loader,code', [
    (None, 'loader_not_observed'),
    ({'state': 'maybe'}, 'input_malformed'),
    ({'state': 'present'}, 'version_not_observed'),
    ({'state': 'present', 'version': '2.9'}, 'version_unsupported'),
    ({'state': 'present', 'version': '2.11', 'path': 'usr/share/bash-completion/bash_completion'},
     'loader_path_unusable'),
    ({'state': 'present', 'version': '2.11', 'path': '/usr/share/../share/bash-completion/bash_completion'},
     'loader_path_unusable'),
    ({'state': 'present', 'version': '2.11', 'path': '/usr//share/bash-completion/bash_completion'},
     'loader_path_unusable'),
])
def test_unusable_loader_observation_is_blocking_and_sources_nothing(loader, code):
    result = bc.evaluate(loader=loader, directories={'/etc/bash_completion.d': listed(regular('git'))})
    assert code in codes(result)
    assert result['activation']['state'] == 'unknown'
    assert result['scripts'] == [] and result['complete'] is False


@pytest.mark.parametrize('observation,code', [
    (None, 'directory_not_observed'),
    ({'state': 'unreadable', 'complete': None, 'entries': []}, 'directory_unreadable'),
    (listed(regular('git'), complete=False), 'listing_incomplete'),
    ({'state': 'listed', 'entries': []}, 'input_malformed'),
    ({'state': 'absent', 'complete': None, 'entries': [regular('git')]}, 'input_malformed'),
    ({'state': 'listed', 'complete': True, 'entries': 'git'}, 'input_malformed'),
])
def test_unobserved_or_malformed_listing_is_blocking(observation, code):
    result = bc.evaluate(loader=LOADER, directories={'/etc/bash_completion.d': observation})
    assert code in codes(result)
    assert result['complete'] is False


def test_entries_outside_a_listed_directory_never_report_sourced():
    result = bc.evaluate(loader=LOADER, directories={'/etc/bash_completion.d': {
        'state': 'unreadable', 'complete': None, 'entries': [regular('git')]}})
    assert result['scripts'] == []
    assert entry(result, 'git')['root'] == 'unresolved'


@pytest.mark.parametrize('item', [
    {'name': 'a/b', 'type': 'file', 'mode': 0o644, 'uid': 0, 'gid': 0},
    {'name': '', 'type': 'file'}, {'name': 'x', 'type': 'socket'}, 'git', {'name': 'x' * 256, 'type': 'other'},
])
def test_malformed_entries_are_blocking(item):
    result = run('2.11', etc=listed(item))
    assert 'input_malformed' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('item,code', [
    ({'name': 'git', 'type': 'file', 'mode': 0o644, 'uid': 0}, 'metadata_missing'),
    ({'name': 'git', 'type': 'file', 'mode': True, 'uid': 0, 'gid': 0}, 'metadata_missing'),
    ({'name': 'git', 'type': 'symlink', 'target': {'type': 'file', 'mode': 0o644}}, 'metadata_missing'),
    ({'name': 'git', 'type': 'symlink'}, 'symlink_target_unobserved'),
])
def test_missing_metadata_is_unresolved_and_blocking(item, code):
    result = run('2.11', etc=listed(item))
    assert code in codes(result) and result['complete'] is False
    assert entry(result, 'git')['root'] == 'unresolved'
    assert result['scripts'] == []


def test_missing_metadata_on_a_skipped_name_does_not_block():
    result = run('2.11', etc=listed({'name': 'git.bak', 'type': 'file'}))
    assert entry(result, 'git.bak')['root_reason_code'] == 'backup_name'
    assert result['complete'] is True


def test_duplicates_limits_and_gap_budget_are_blocking():
    result = run('2.11', etc=listed(regular('git'), regular('git')))
    assert 'duplicate_name' in codes(result) and result['complete'] is False
    result = run('2.11', etc=listed(*(regular(f'n{i}') for i in range(bc.MAX_ENTRIES + 1))))
    assert 'too_many_entries' in codes(result) and len(result['scripts']) == bc.MAX_ENTRIES
    result = run('2.11', etc=listed(*({'name': f'n{i}', 'type': 'symlink'} for i in range(bc.MAX_GAPS + 5))))
    assert codes(result)[-1] == 'gaps_truncated' and len(result['gaps']) == bc.MAX_GAPS
    assert result['complete'] is False


def test_unscanned_directory_is_disclosed_without_blocking():
    result = bc.evaluate(loader=LOADER, directories={'/etc/bash_completion.d': listed(),
                                                     '/usr/etc/bash_completion.d': listed(regular('git'))})
    assert 'directory_not_scanned' in codes(result)
    assert result['scripts'] == [] and result['complete'] is True


def test_input_is_not_mutated_and_result_is_not_a_verdict():
    directories = {'/etc/bash_completion.d': listed(regular('git'))}
    before = copy.deepcopy(directories)
    result = bc.evaluate(loader=LOADER, directories=directories)
    assert directories == before
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['note']
    assert result['contract_version'] == bc.CONTRACT_VERSION


def _loop(version_family):
    """The upstream compat loop body for each family, with the directory passed as $1."""
    backup, block = UPSTREAM_GLOBS[version_family]
    if bc.FAMILIES[version_family]['c_order']:
        expand = 'shopt -s nullglob; shopt -u dotglob; files=("$1"/*)'
    else:
        expand = 'files=("$1"/*)'
    return ('shopt -s extglob\n_g=\'%s\'\n_b=\'%s\'\n%s\n'
            'for i in "${files[@]}"; do [[ ${i##*/} != @($_g|Makefile*|$_b) && -f $i && -r $i ]] && '
            'printf "%%s\\n" "${i##*/}"; done' % (backup, block, expand))


@pytest.mark.skipif(not (shutil.which('bash') and hasattr(os, 'geteuid')), reason='needs bash on POSIX')
@pytest.mark.parametrize('version_family', sorted(bc.FAMILIES))
def test_live_bash_tests_match_contract(version_family):
    """Real files and real bash ``-f``/``-r`` tests agree with the contract for the current account."""
    root = tempfile.mkdtemp()
    try:
        for name in ['git', 'a b', 'f.bak', 'Makefile', 'acroread.sh', 'f.dpkgx', 'f.ucf-old', 'f.zs-old', '.hid',
                     'closed']:
            with open(os.path.join(root, name), 'w') as handle:
                handle.write('true\n')
        os.chmod(os.path.join(root, 'closed'), 0)
        os.mkdir(os.path.join(root, 'adir'))
        os.mkfifo(os.path.join(root, 'fifo'))
        os.symlink('/nonexistent/x', os.path.join(root, 'gone'))
        os.symlink(os.path.join(root, 'git'), os.path.join(root, 'link'))
        out = subprocess.run(['bash', '--norc', '--noprofile', '-c', _loop(version_family), 'bash', root],
                             capture_output=True, text=True, timeout=30, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        assert out.returncode in (0, 1), out.stderr
        entries = []
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            lst = os.lstat(path)
            if os.path.islink(path):
                try:
                    st = os.stat(path)
                    target = {'type': 'file' if os.path.isfile(path) else 'directory' if os.path.isdir(path)
                              else 'other', 'mode': st.st_mode & 0o7777, 'uid': st.st_uid, 'gid': st.st_gid}
                except FileNotFoundError:
                    target = None
                entries.append({'name': name, 'type': 'symlink', 'target': target})
            elif os.path.isdir(path):
                entries.append({'name': name, 'type': 'directory'})
            elif os.path.isfile(path):
                entries.append(regular(name, lst.st_mode & 0o7777, lst.st_uid, lst.st_gid))
            else:
                entries.append({'name': name, 'type': 'other'})
        version = {'2.10': '2.11', '2.12': '2.12.0', '2.15': '2.16.0', '2.17': '2.17.0'}[version_family]
        result = bc.evaluate(loader={'state': 'present', 'version': version},
                             directories={'/etc/bash_completion.d': listed(*entries),
                                          '/usr/etc/bash_completion.d': absent()})
        if os.geteuid() == 0:
            expected = [s['name'] for s in result['scripts']]
        else:
            # The test account owns every file, so the owner class decides; 'closed' (mode 0) is unreadable.
            expected = [s['name'] for s in result['scripts'] if s['name'] != 'closed']
        assert sorted(out.stdout.splitlines()) == sorted(expected)
        if bc.FAMILIES[version_family]['c_order']:
            assert out.stdout.splitlines() == expected
    finally:
        os.chmod(os.path.join(root, 'closed'), 0o600)
        shutil.rmtree(root)
