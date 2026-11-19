"""Individual /etc/anacrontab jobs in the startup inventory (roadmap F slice, #1156)."""
import hashlib
import json
import time

import pytest

from app import persistence, scheduled_jobs, startup_inventory as view
from app.db import Host, Session
from app.identity import User
from app.incidents import Inspection
from target import agent

# Debian anacron 2.3 default plus local additions.
TABLE = b'''# /etc/anacrontab: configuration file for anacron
SHELL=/bin/sh
HOME=/root
LOGNAME=root
API_TOKEN=supersecretvalue
START_HOURS_RANGE=3-22
RANDOM_DELAY=45

# These replace cron's entries
1\t5\tcron.daily\trun-parts --report /etc/cron.daily
7\t10\tcron.weekly\trun-parts --report /etc/cron.weekly
@monthly\t15\tcron.monthly\trun-parts --report /etc/cron.monthly
3 20 backup.sync /usr/local/bin/sync --password hunter2 /srv
1 5 cron.daily /usr/local/bin/second-daily
'''


def test_agent_parses_jobs_settings_and_withholds_environment_values():
    tab = agent.parse_anacrontab(TABLE)
    assert tab['parsed'] and tab['environment'] == 6 and tab['unparsed'] == 0 and not tab['truncated']
    assert tab['settings'] == {'start_hours_range': {'start': 3, 'end': 22}, 'random_delay': 45}
    jobs = tab['jobs']
    assert [(j['line'], j['identifier'], j['period_days'], j['period_name'], j['delay_minutes']) for j in jobs] == [
        (10, 'cron.daily', 1, None, 5), (11, 'cron.weekly', 7, None, 10), (12, 'cron.monthly', 30, 'monthly', 15),
        (13, 'backup.sync', 3, None, 20), (14, 'cron.daily', 1, None, 5)]
    assert jobs[3]['command'] == '/usr/local/bin/sync --password [REDACTED] /srv' and jobs[3]['redacted'] and tab['redacted']
    assert jobs[4]['duplicate_of_line'] == 10 and jobs[0]['duplicate_of_line'] is None
    text = json.dumps(tab)
    assert 'hunter2' not in text and 'supersecretvalue' not in text and '/root' not in text


CORPUS = [
    TABLE,
    b'1 5 a cmd\n0 5 zero cmd\nx 5 bad cmd\n1 y bad cmd\n1 5 a/b cmd\n1 5\n@hourly 1 h cmd\n@yearly 2 y cmd\n',
    b'START_HOURS_RANGE=25-3\nRANDOM_DELAY=abc\n  PATH = /usr/bin \n@annually 0 yr  echo  hi  \n',
    b'START_HOURS_RANGE=3-22\nSTART_HOURS_RANGE=bad\n1 1 j echo\r\n',
    b'',
]


@pytest.mark.parametrize('data', CORPUS)
def test_agent_matches_the_pure_anacrontab_contract(data):
    ours = agent.parse_anacrontab(data)
    pure = scheduled_jobs.parse_anacrontab(data)
    assert [(j['line'], j['identifier'], j['period_days'], j['delay_minutes'], j['duplicate_of_line']) for j in ours['jobs']] == [
        (j['line'], j['identifier'], j['period']['days'], j['delay_minutes'], j['duplicate_of_line']) for j in pure['jobs']]
    rejected = {'malformed_line', 'invalid_period', 'invalid_delay', 'invalid_identifier'}
    assert ours['unparsed'] == sum(g['code'] in rejected for g in pure['gaps'])
    assert ours['settings']['start_hours_range'] == pure['settings'].get('START_HOURS_RANGE')
    assert ours['settings']['random_delay'] == pure['settings'].get('RANDOM_DELAY')


@pytest.mark.parametrize('data', [b'1 5 a cmd\n\x00', b'1 5 a \xff\n', b'#' * (agent.ANACRON_TEXT_LIMIT + 1)])
def test_unreadable_tables_yield_no_jobs_not_guesses(data):
    tab = agent.parse_anacrontab(data)
    assert not tab['parsed'] and tab['jobs'] == [] and tab['environment'] == 0 and tab['unparsed'] == 0
    assert scheduled_jobs.parse_anacrontab(data)['state'] == 'unavailable'


def test_jobs_and_commands_are_bounded_and_control_characters_escaped():
    many = b''.join(b'1 5 job%d echo\n' % i for i in range(agent.CRON_FILE_JOBS + 3))
    tab = agent.parse_anacrontab(many)
    assert len(tab['jobs']) == agent.CRON_FILE_JOBS and tab['truncated']
    long = agent.parse_anacrontab(b'1 5 long ' + b'x' * 600 + b'\n')['jobs'][0]
    assert len(long['command']) == agent.CRON_COMMAND_LIMIT and long['command_truncated']
    escaped = agent.parse_anacrontab(b'1 5 e\x1bid /bin/echo \x1b[31m\n')['jobs'][0]
    assert escaped['command'] == '/bin/echo \\x1b[31m' and escaped['identifier'] == 'e\\x1bid'


def table_file(tmp_path, monkeypatch, data=TABLE):
    table = tmp_path / 'anacrontab'
    table.write_bytes(data)
    monkeypatch.setattr(agent, 'PERSISTENCE_ROOTS', ())
    monkeypatch.setattr(agent, 'PERSISTENCE_FILES', (str(table),))
    monkeypatch.setattr(agent, 'ANACRONTAB', str(table))
    monkeypatch.setattr(persistence, 'ANACRONTAB', str(table))
    return table


def test_inventory_parses_exactly_the_hashed_bytes_only_when_asked(tmp_path, monkeypatch):
    table = table_file(tmp_path, monkeypatch)
    result = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=True)
    row = result['entries'][0]
    assert row['path'] == str(table) and row['sha256'] == hashlib.sha256(TABLE).hexdigest()
    assert len(row['anacron']['jobs']) == 5 and 'cron' not in row and 'at' not in row
    assert result['state'] == 'collected' and 'hunter2' not in json.dumps(result)
    persistence.validate(result)
    older = agent.persistence_inventory(time.monotonic() + 5, cron_jobs=False)
    assert 'anacron' not in older['entries'][0]


def record(**changes):
    return {**agent.parse_anacrontab(TABLE), **changes}


def job(**changes):
    return {**agent.parse_anacrontab(TABLE)['jobs'][0], **changes}


def inventory(anacron=None, sha='a' * 64, path='/etc/anacrontab', kind='regular'):
    row = dict(path=path, kind=kind, uid=0, gid=0, mode=0o644, size=1, mtime_ns=1)
    row.update(sha256=sha) if kind == 'regular' else row.update(target='/elsewhere')
    if anacron is not None:
        row['anacron'] = anacron
    return dict(state='collected', scope=['/etc/anacrontab', '/etc/cron.d'], entries=[row], gaps=[], missing_roots=[], skipped=0)


@pytest.mark.parametrize('bad', [
    record(extra=1), {k: v for k, v in record().items() if k != 'redacted'}, record(parsed='yes'), record(environment=-1),
    record(unparsed=True), record(settings={}), record(settings={'start_hours_range': {'start': 3, 'end': 25}, 'random_delay': None}),
    record(settings={'start_hours_range': None, 'random_delay': -1}), record(jobs=[job()] * 65),
    record(parsed=False, jobs=[]), record(jobs=[job(extra=1)]), record(jobs=[job(line=0)]), record(jobs=[job(), job()]),
    record(jobs=[job(period_days=0)]), record(jobs=[job(period_name='hourly')]), record(jobs=[job(period_name='weekly', period_days=1)]),
    record(jobs=[job(delay_minutes=-1)]), record(jobs=[job(identifier='a/b')]), record(jobs=[job(identifier='a b')]),
    record(jobs=[job(identifier='')]), record(jobs=[job(command='')]), record(jobs=[job(command='x' * 513)]),
    record(jobs=[job(command='a\x00b')]), record(jobs=[job(duplicate_of_line=10)]),
    record(jobs=[job(), job(line=11, identifier='other', duplicate_of_line=10)]), record(jobs=[job(redacted=1)]),
])
def test_controller_rejects_malformed_anacron_detail(bad):
    persistence.validate(inventory())
    persistence.validate(inventory(record()))
    persistence.validate(inventory(record(jobs=[job(), job(line=11, duplicate_of_line=10)])))
    with pytest.raises(ValueError):
        persistence.validate(inventory(bad))


def test_controller_rejects_anacron_detail_outside_anacrontab_or_on_a_symlink():
    with pytest.raises(ValueError):
        persistence.validate(inventory(record(), path='/etc/cron.d/anacron'))
    with pytest.raises(ValueError):
        persistence.validate(inventory(record(), kind='symlink'))


def test_unparsed_record_is_valid_only_when_empty():
    empty = agent.parse_anacrontab(b'\xff')
    persistence.validate(inventory(empty))
    with pytest.raises(ValueError):
        persistence.validate(inventory({**empty, 'unparsed': 1}))


def test_changes_and_incident_evidence_stay_metadata_only():
    before = inventory(record())
    after = inventory(record(jobs=[job(command='/bin/new-command')]), sha='b' * 64)
    changes = persistence.compare(before, after)['changes']
    assert changes[0]['fields'] == ['sha256'] and 'anacron' not in changes[0]['before'] and 'anacron' not in changes[0]['after']
    assert 'new-command' not in json.dumps(changes)
    assert persistence.compare(inventory(), inventory(record()))['changes'] == []


@pytest.fixture
def seeded(admin):
    with Session() as s:
        s.add(Host(id='one', name='fixture', address='192.0.2.1', fingerprint='fixture'))
        s.add(Inspection(id='receipt', host_id='one', report={'persistence': inventory(record())}))
        s.add(Host(id='two', name='older', address='192.0.2.2', fingerprint='older'))
        s.add(Inspection(id='older-receipt', host_id='two', report={'persistence': inventory()}))
        s.commit()
    return admin


def test_view_returns_anacron_jobs_search_coverage_and_older_agent_state(seeded, monkeypatch):
    from app import ai, ssh
    monkeypatch.setattr(ai, 'request', lambda *a, **k: pytest.fail('no AI'))
    monkeypatch.setattr(ssh, 'call', lambda *a, **k: pytest.fail('no target'))
    url = '/api/hosts/one/security/startup-inventory'
    data = seeded.get(url).json()
    row = {r['path']: r for r in data['items']}['/etc/anacrontab']
    assert row['anacron_state'] == 'parsed' and row['mechanism'] == 'anacron' and len(row['anacron']['jobs']) == 5
    catalog = [c for c in data['catalog'] if c['id'] == 'anacron'][0]
    assert catalog['observed_files'] == 1 and '5 parsed jobs' in catalog['label'] and 'not reported' not in catalog['label']
    assert [r['path'] for r in seeded.get(url, params={'q': 'backup.sync'}).json()['items']] == ['/etc/anacrontab']
    assert [r['path'] for r in seeded.get(url, params={'q': 'second-daily'}).json()['items']] == ['/etc/anacrontab']
    assert seeded.get(url, params={'q': 'hunter2'}).json()['items'] == []
    assert any('Exception for anacron' in gap for gap in data['gaps'])
    assert not any('its jobs are not parsed' in gap for gap in data['gaps'])
    older = seeded.get('/api/hosts/two/security/startup-inventory').json()
    old_row = older['items'][0]
    assert old_row['anacron_state'] == 'not_reported' and 'anacron' not in old_row
    assert 'not reported by this agent version' in [c for c in older['catalog'] if c['id'] == 'anacron'][0]['label']
    for role in ('operator', 'viewer'):
        with Session() as s:
            s.get(User, 'admin').role = role
            s.commit()
        assert seeded.get(url).status_code == 403


@pytest.mark.parametrize('entry,state', [
    ({'path': '/etc/anacrontab', 'kind': 'regular'}, 'not_reported'),
    ({'path': '/etc/anacrontab', 'kind': 'regular', 'anacron': {}}, 'parsed'),
    ({'path': '/etc/anacrontab', 'kind': 'symlink'}, None),
    ({'path': '/etc/cron.d/anacron', 'kind': 'regular'}, None),
])
def test_anacron_state_for_entries(entry, state):
    assert view.anacron_state(entry) == state
