import pytest

from app import run_parts as rp


def entry(path, kind='regular', uid=0, mode=0o755, **extra):
    return {'path': path, 'kind': kind, 'uid': uid, 'mode': mode, **extra}


def codes(result):
    return [r['code'] for r in result['reasons']]


@pytest.mark.parametrize('directory', rp.DIRECTORIES)
@pytest.mark.parametrize('family', ['debian', 'rpm'])
def test_executable_conventional_names_are_eligible_in_every_directory(directory, family):
    for name in ('logrotate', '0anacron', 'man-db', 'apt_compat', 'A1'):
        result = rp.assess(entry(directory + '/' + name), family)
        assert result == {'state': 'eligible', 'family': family, 'reasons': []}


@pytest.mark.parametrize('name', ['backup.sh', 'job.dpkg-old', 'apt.dpkg-dist', '.hidden', 'old~', 'café', 'a b'])
def test_debian_skips_names_outside_the_traditional_namespace(name):
    result = rp.assess(entry('/etc/cron.daily/' + name), 'debian')
    assert result['state'] == 'skipped' and codes(result) == ['debian_name']
    assert 'dots' in result['reasons'][0]['detail']


@pytest.mark.parametrize('name', ['.hidden', 'job~', 'job,', 'job.rpmsave', 'job.rpmorig', 'job.rpmnew',
                                  'job.swp', 'job.cfsaved', 'job,v'])
def test_rpm_skips_hidden_and_backup_names(name):
    result = rp.assess(entry('/etc/cron.daily/' + name), 'rpm')
    assert result['state'] == 'skipped' and codes(result) == ['rpm_name']


@pytest.mark.parametrize('name', ['backup.sh', 'job.dpkg-old', 'café'])
def test_rpm_runs_dotted_names_that_debian_would_skip(name):
    assert rp.assess(entry('/etc/cron.weekly/' + name), 'rpm')['state'] == 'eligible'
    assert rp.assess(entry('/etc/cron.weekly/' + name), 'debian')['state'] == 'skipped'


@pytest.mark.parametrize('name', ['my job', 'a b c', ' lead', 'trail '])
def test_rpm_skips_names_word_split_by_cronie(name):
    # cronie expands `for i in $(echo dir/*)` and `[ -x $i ]` unquoted, so the
    # file is split into words and never runs as itself (peer review on #849).
    result = rp.assess(entry('/etc/cron.daily/' + name), 'rpm')
    assert result['state'] == 'skipped' and codes(result) == ['rpm_word_split']
    assert rp.assess(entry('/etc/cron.daily/' + name), 'debian')['state'] == 'skipped'


@pytest.mark.parametrize('name', ['a*b', 'job?', '[x]', 'a* b', 'x[1].rpmnew'])
def test_rpm_glob_names_are_unknown(name):
    # Unquoted re-expansion makes the outcome depend on sibling names.
    for mode in (0o755, 0o644):
        result = rp.assess(entry('/etc/cron.daily/' + name, mode=mode), 'rpm')
        assert result['state'] == 'unknown' and codes(result) == ['rpm_glob_expansion']


def test_rpm_word_split_combines_with_other_reasons():
    assert codes(rp.assess(entry('/etc/cron.daily/my job~', mode=0o644), 'rpm')) == [
        'rpm_name', 'rpm_word_split', 'not_executable']


@pytest.mark.parametrize('mode,state', [(0o644, 'skipped'), (0o600, 'skipped'), (0o000, 'skipped'),
                                        (0o4644, 'skipped'), (0o700, 'eligible'), (0o610, 'eligible'),
                                        (0o601, 'eligible'), (0o001, 'eligible')])
@pytest.mark.parametrize('family', ['debian', 'rpm'])
def test_root_needs_any_execute_bit(mode, state, family):
    result = rp.assess(entry('/etc/cron.hourly/job', mode=mode), family)
    assert result['state'] == state
    assert codes(result) == (['not_executable'] if state == 'skipped' else [])


def test_multiple_reasons_are_reported_in_stable_order():
    assert codes(rp.assess(entry('/etc/cron.daily/x.sh', mode=0o644), 'debian')) == ['debian_name', 'not_executable']
    assert codes(rp.assess(entry('/etc/cron.daily/x.rpmnew', mode=0o644), 'rpm')) == ['rpm_name', 'not_executable']


def test_owner_is_not_a_run_parts_rule():
    # run-parts executes non-root-owned scripts; ownership drift is a separate concern.
    assert rp.assess(entry('/etc/cron.daily/job', uid=1000, mode=0o777), 'debian')['state'] == 'eligible'


def test_nested_entries_are_never_run():
    result = rp.assess(entry('/etc/cron.daily/helpers/job'), 'debian')
    assert result['state'] == 'skipped' and codes(result) == ['nested_entry']


def test_symlinks_and_unrecorded_metadata_are_unknown_not_guessed():
    result = rp.assess(entry('/etc/cron.daily/job', kind='symlink', target='/opt/job'), 'debian')
    assert result['state'] == 'unknown' and codes(result) == ['symlink_target_not_recorded']
    for bad in (entry('/etc/cron.daily/job', kind='directory'), entry('/etc/cron.daily/job', kind=None),
                entry('/etc/cron.daily/job', uid=None), entry('/etc/cron.daily/job', mode='0755'),
                entry('/etc/cron.daily/job', mode=True), entry('/etc/cron.daily/job', uid=-1),
                entry('/etc/cron.daily/job', mode=0o17777), entry('/etc/cron.daily/job', mode=1.0)):
        result = rp.assess(bad, 'rpm')
        assert result['state'] == 'unknown' and codes(result) == ['not_regular_file'], bad


@pytest.mark.parametrize('family', [None, 'arch', '', 'DEBIAN', 1, ['debian']])
def test_unknown_family_is_unknown(family):
    result = rp.assess(entry('/etc/cron.daily/job'), family)
    assert result == {'state': 'unknown', 'family': None,
                      'reasons': [{'code': 'unknown_family', 'detail': rp.REASONS['unknown_family']}]}


class StrSub(str):
    pass


class DictSub(dict):
    pass


@pytest.mark.parametrize('path', ['/etc/cron.daily', '/etc/cron.daily/', '/etc/cron.d/job', '/etc/crontab',
                                  '/etc/cron.dailyx/job', '/etc/cron.daily//job', '/etc/cron.daily/../job',
                                  '/etc/cron.daily/./job', '/etc/cron.daily/a/../b', 'etc/cron.daily/job',
                                  '/etc/cron.daily/job\n', '/etc/cron.daily/j\x7fob', '/etc/cron.daily/' + 'a' * 5000,
                                  StrSub('/etc/cron.daily/job'), None, 7, b'/etc/cron.daily/job'])
def test_paths_outside_run_parts_directories_or_malformed_have_no_assessment(path):
    assert rp.assess(entry(path), 'debian') is None
    assert rp.applies(path) is False


def test_non_dict_entries_have_no_assessment():
    for value in (None, [], 'x', DictSub(entry('/etc/cron.daily/job'))):
        assert rp.assess(value, 'debian') is None


def test_family_mapping_never_guesses():
    assert rp.family_of({'package_manager': 'apt'}) == 'debian'
    assert rp.family_of({'package_manager': 'rpm'}) == 'rpm'
    for value in ({}, {'package_manager': 'pacman'}, {'package_manager': ['apt']}, None, 'apt'):
        assert rp.family_of(value) is None


def test_assessment_does_not_mutate_input_and_reasons_are_known():
    item = entry('/etc/cron.daily/x.sh', mode=0o644)
    snapshot = dict(item)
    result = rp.assess(item, 'debian')
    assert item == snapshot
    assert all(r['detail'] == rp.REASONS[r['code']] for r in result['reasons'])
    assert 'jobs.allow' in rp.LIMITATION and 'anacron' in rp.LIMITATION
