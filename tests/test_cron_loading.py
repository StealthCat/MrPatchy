import pytest
from app import cron_loading
from app.db import Session, Host
from app.incidents import Inspection


def entry(path, uid=0, mode=0o644, kind='regular', **extra):
    row = {'path': path, 'kind': kind, 'uid': uid, 'gid': 0, 'mode': mode, 'size': 1, 'mtime_ns': 1}
    row.update({'sha256': 'a' * 64} if kind == 'regular' else {'target': '/opt/job'})
    row.update(extra)
    return row


def codes(result):
    return [reason['code'] for reason in result['reasons']]


@pytest.mark.parametrize('path', ['/etc/crontab', '/etc/cron.d/backup', '/etc/cron.d/e2scrub_all', '/etc/cron.d/php-sessions'])
def test_debian_valid_root_files_are_eligible(path):
    result = cron_loading.assess(entry(path), 'debian')
    assert result['state'] == 'eligible' and result['reasons'] == [] and result['family'] == 'debian'


@pytest.mark.parametrize('name', ['backup.sh', 'job.dpkg-old', 'job~', '.hidden', 'with space'])
def test_debian_ignores_cron_d_names_outside_run_parts_convention(name):
    result = cron_loading.assess(entry('/etc/cron.d/' + name), 'debian')
    assert result['state'] == 'skipped' and codes(result) == ['debian_name']


def test_debian_name_rule_does_not_apply_to_etc_crontab():
    assert cron_loading.assess(entry('/etc/crontab'), 'debian')['state'] == 'eligible'


@pytest.mark.parametrize('uid,mode,expected', [
    (1000, 0o644, ['not_root_owned']),
    (0, 0o664, ['group_or_other_writable']),
    (0, 0o646, ['group_or_other_writable']),
    (33, 0o666, ['not_root_owned', 'group_or_other_writable']),
])
def test_debian_owner_and_writable_rules(uid, mode, expected):
    result = cron_loading.assess(entry('/etc/cron.d/job', uid=uid, mode=mode), 'debian')
    assert result['state'] == 'skipped' and codes(result) == expected


def test_debian_allows_executable_root_file():
    assert cron_loading.assess(entry('/etc/cron.d/job', mode=0o755), 'debian')['state'] == 'eligible'


@pytest.mark.parametrize('name', ['backup.sh', '0hourly', 'raid-check', 'sysstat'])
def test_cronie_allows_dotted_names(name):
    assert cron_loading.assess(entry('/etc/cron.d/' + name), 'rpm')['state'] == 'eligible'


@pytest.mark.parametrize('name', ['.hidden', 'job~', 'job.rpmsave', 'job.rpmorig', 'job.rpmnew'])
def test_cronie_ignored_names(name):
    result = cron_loading.assess(entry('/etc/cron.d/' + name), 'rpm')
    assert result['state'] == 'skipped' and codes(result) == ['cronie_name']


@pytest.mark.parametrize('mode', [0o644, 0o600, 0o400, 0o640, 0o604])
def test_cronie_accepted_modes(mode):
    assert cron_loading.assess(entry('/etc/crontab', mode=mode), 'rpm')['state'] == 'eligible'


@pytest.mark.parametrize('mode', [0o755, 0o664, 0o646, 0o200, 0o4644, 0o1644, 0o654])
def test_cronie_bad_file_mode(mode):
    result = cron_loading.assess(entry('/etc/cron.d/job', mode=mode), 'rpm')
    assert result['state'] == 'skipped' and codes(result) == ['cronie_mode']


def test_cronie_wrong_owner():
    result = cron_loading.assess(entry('/etc/crontab', uid=1000), 'rpm')
    assert codes(result) == ['not_root_owned']


@pytest.mark.parametrize('family', [None, '', 'alpine', 'Debian'])
def test_unknown_family_is_never_guessed(family):
    result = cron_loading.assess(entry('/etc/cron.d/bad.name', uid=1000, mode=0o777), family)
    assert result == {'state': 'unknown', 'family': None, 'reasons': [{'code': 'unknown_family', 'detail': cron_loading.REASONS['unknown_family']}]}


def test_symlink_and_malformed_metadata_are_unknown():
    assert codes(cron_loading.assess(entry('/etc/cron.d/link', kind='symlink'), 'debian')) == ['symlink_target_not_recorded']
    for bad in ({'uid': -1}, {'mode': 0o17777}, {'uid': True}, {'mode': '644'}, {'kind': 'fifo'}):
        result = cron_loading.assess({**entry('/etc/cron.d/job'), **bad}, 'rpm')
        assert result['state'] == 'unknown' and codes(result) == ['not_regular_file']


@pytest.mark.parametrize('path', ['/etc/cron.daily/backup', '/var/spool/cron/crontabs/root', '/etc/cron.d', '/etc/cron.d/', '/etc/cron.d/sub/job', '/etc/crontab.bak', None])
def test_rule_applies_only_to_system_crontab_locations(path):
    assert cron_loading.assess({**entry('/etc/cron.d/x'), 'path': path}, 'debian') is None


@pytest.mark.parametrize('inventory,family', [({'package_manager': 'apt'}, 'debian'), ({'package_manager': 'rpm'}, 'rpm'), ({}, None), (None, None), ({'package_manager': 'zypper'}, None)])
def test_family_mapping(inventory, family):
    assert cron_loading.family_of(inventory) == family


@pytest.fixture
def seeded(admin):
    entries = [entry('/etc/crontab'), entry('/etc/cron.d/backup.sh'), entry('/etc/cron.d/writable', mode=0o666),
               entry('/etc/cron.d/link', kind='symlink'), entry('/etc/cron.daily/logrotate', mode=0o755)]
    with Session() as s:
        s.add(Host(id='one', name='fixture', address='192.0.2.1', fingerprint='fixture', inventory={'package_manager': 'apt'}))
        s.add(Inspection(id='receipt', host_id='one', report={'persistence': dict(state='collected', scope=['/etc/crontab', '/etc/cron.d', '/etc/cron.daily'],
                                                                                    entries=entries, gaps=[], missing_roots=[], skipped=0)}))
        s.commit()
    return admin


def test_page_reports_loading_without_changing_receipt(seeded, monkeypatch):
    from app import ai, ssh
    monkeypatch.setattr(ai, 'request', lambda *a, **k: pytest.fail('no AI'))
    monkeypatch.setattr(ssh, 'call', lambda *a, **k: pytest.fail('no target'))
    with Session() as s:
        before = s.get(Inspection, 'receipt').report
    data = seeded.get('/api/hosts/one/security/startup-inventory').json()
    rows = {row['path']: row for row in data['items']}
    assert rows['/etc/crontab']['cron_loading']['state'] == 'eligible'
    assert codes(rows['/etc/cron.d/backup.sh']['cron_loading']) == ['debian_name']
    assert codes(rows['/etc/cron.d/writable']['cron_loading']) == ['group_or_other_writable']
    assert rows['/etc/cron.d/link']['cron_loading']['state'] == 'unknown'
    assert 'cron_loading' not in rows['/etc/cron.daily/logrotate']
    assert data['cron']['skipped_files'] == 2 and data['cron']['unknown_loading'] == 1 and data['cron']['loading_family'] == 'debian'
    assert cron_loading.LIMITATION in data['cron']['loading_limitation'] and any(cron_loading.LIMITATION in gap for gap in data['gaps'])
    with Session() as s:
        assert s.get(Inspection, 'receipt').report == before
        s.get(Host, 'one').inventory = {'package_manager': 'rpm'}
        s.commit()
    rows = {row['path']: row for row in seeded.get('/api/hosts/one/security/startup-inventory').json()['items']}
    assert rows['/etc/cron.d/backup.sh']['cron_loading']['state'] == 'eligible'
    assert codes(rows['/etc/cron.d/writable']['cron_loading']) == ['cronie_mode']
    with Session() as s:
        s.get(Host, 'one').inventory = {}
        s.commit()
    data = seeded.get('/api/hosts/one/security/startup-inventory').json()
    assert {row['cron_loading']['state'] for row in data['items'] if 'cron_loading' in row} == {'unknown'}
    assert data['cron']['skipped_files'] == 0
