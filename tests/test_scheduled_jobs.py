from app import scheduled_jobs as sj

DEBIAN_ANACRONTAB = """# /etc/anacrontab: configuration file for anacron

# See anacron(8) and anacrontab(5) for details.

SHELL=/bin/sh
HOME=/root
LOGNAME=root

# These replace cron's entries
1\t5\tcron.daily\trun-parts --report /etc/cron.daily
7\t10\tcron.weekly\trun-parts --report /etc/cron.weekly
@monthly\t15\tcron.monthly\trun-parts --report /etc/cron.monthly
"""

RHEL_ANACRONTAB = """SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
# the maximal random delay added to the base delay of the jobs
RANDOM_DELAY=45
# the jobs will be started during the following hours only
START_HOURS_RANGE=3-22

#period in days   delay in minutes   job-identifier   command
1\t5\tcron.daily\t\tnice run-parts /etc/cron.daily
7\t25\tcron.weekly\t\tnice run-parts /etc/cron.weekly
@monthly 45\tcron.monthly\t\tnice run-parts /etc/cron.monthly
"""


def test_debian_default_anacrontab_jobs_and_run_parts_relationships():
    r = sj.parse_anacrontab(DEBIAN_ANACRONTAB)
    assert r['state'] == 'parsed' and r['gaps'] == []
    assert r['environment_names'] == ['SHELL', 'HOME', 'LOGNAME']
    jobs = {j['identifier']: j for j in r['jobs']}
    assert set(jobs) == {'cron.daily', 'cron.weekly', 'cron.monthly'}
    assert jobs['cron.daily']['period'] == {'kind': 'days', 'name': None, 'days': 1}
    assert jobs['cron.monthly']['period'] == {'kind': 'named', 'name': 'monthly', 'days': 30}
    assert jobs['cron.weekly']['delay_minutes'] == 10
    assert jobs['cron.weekly']['run_parts_dirs'] == ['/etc/cron.weekly']
    assert jobs['cron.daily']['command'] == 'run-parts --report /etc/cron.daily'
    assert all(j['origin'] == 'not_assessed' for j in r['jobs'])
    assert len(jobs['cron.daily']['command_sha256']) == 64


def test_rhel_anacrontab_discloses_only_scheduling_settings():
    r = sj.parse_anacrontab(RHEL_ANACRONTAB.encode())
    assert r['state'] == 'parsed'
    assert r['settings'] == {'RANDOM_DELAY': 45, 'START_HOURS_RANGE': {'start': 3, 'end': 22}}
    assert 'MAILTO' in r['environment_names'] and 'PATH' in r['environment_names']
    assert [j['run_parts_dirs'] for j in r['jobs']] == [['/etc/cron.daily'], ['/etc/cron.weekly'], ['/etc/cron.monthly']]


def test_environment_values_are_withheld():
    secret = 'hunter2-token-value'
    r = sj.parse_anacrontab(f'API_TOKEN={secret}\nRANDOM_DELAY=abc\n1 5 job /usr/bin/true\n')
    assert secret not in repr(r)
    assert r['environment_names'] == ['API_TOKEN', 'RANDOM_DELAY']
    assert r['settings'] == {}
    assert r['state'] == 'partial' and r['gaps'][0]['code'] == 'invalid_setting'


def test_invalid_job_lines_are_gaps_not_guessed_jobs():
    text = ('0 5 zero /bin/true\n@hourly 5 hourly /bin/true\n1 soon delay /bin/true\n'
            '1 5 bad/ident /bin/true\n1 5 short\n1 5 good /bin/true\n')
    r = sj.parse_anacrontab(text)
    assert [j['identifier'] for j in r['jobs']] == ['good']
    assert [g['code'] for g in r['gaps']] == ['invalid_period', 'invalid_period', 'invalid_delay',
                                              'invalid_identifier', 'malformed_line']
    assert r['state'] == 'partial'


def test_duplicate_identifier_is_flagged():
    r = sj.parse_anacrontab('1 5 same /bin/a\n7 5 same /bin/b\n')
    assert [j['duplicate_of_line'] for j in r['jobs']] == [None, 1]
    assert r['gaps'][0]['code'] == 'duplicate_identifier' and r['gaps'][0]['line'] == 2


def test_run_parts_only_reports_named_absolute_directories():
    r = sj.parse_anacrontab('1 5 a run-parts relative/dir\n1 5 b /usr/bin/run-parts -v --report /opt/jobs/\n'
                            '1 5 c echo run-parts\n')
    assert [j['run_parts_dirs'] for j in r['jobs']] == [[], ['/opt/jobs'], []]


def test_long_command_is_bounded_but_hashed_in_full():
    long = '/bin/echo ' + 'x' * (sj.MAX_COMMAND + 10)
    job = sj.parse_anacrontab(f'1 5 long {long}\n')['jobs'][0]
    assert job['command_truncated'] and len(job['command']) == sj.MAX_COMMAND
    assert job['command_sha256'] == __import__('hashlib').sha256(long.encode()).hexdigest()


def test_over_limit_inputs_fail_closed_without_partial_jobs():
    big = sj.parse_anacrontab('1 5 a /bin/true\n' + '#' * sj.MAX_TEXT)
    assert big['state'] == 'unavailable' and big['jobs'] == [] and big['gaps'][0]['code'] == 'over_limit'
    many = sj.parse_anacrontab(''.join(f'1 5 j{i} /bin/true\n' for i in range(sj.MAX_JOBS + 1)))
    assert many['state'] == 'unavailable' and many['jobs'] == []
    lines = sj.parse_anacrontab('\n' * sj.MAX_LINES)
    assert lines['state'] == 'unavailable'
    assert sj.parse_anacrontab(b'\xff\xfe')['gaps'][0]['code'] == 'invalid_utf8'
    assert sj.parse_anacrontab('1 5 a /bin/true\x00')['gaps'][0]['code'] == 'binary'
    assert sj.parse_anacrontab(None)['state'] == 'unavailable'


def at_script(command_block, *, uid=1000, gid=1000, env=('PATH=/usr/bin:/bin; export PATH',)):
    return '\n'.join(['#!/bin/sh', f'# atrun uid={uid} gid={gid}', '# mail alice 0', 'umask 22', *env,
                      'cd /home/alice || {', "\t echo 'Execution directory inaccessible' >&2", '\t exit 1', '}',
                      *command_block]) + '\n'


def test_at_name_decoding_queues_and_schedule():
    assert sj.decode_at_name('a0000101a8b3c4') == {'queue': 'a', 'job_number': 1, 'scheduled_at': 0x01a8b3c4 * 60,
                                                    'running': False, 'batch': False}
    assert sj.decode_at_name('=0000201a8b3c4')['running'] is True
    assert sj.decode_at_name('B0000301a8b3c4')['batch'] is True
    for bad in ('.SEQ', 'a0000101a8b3c', 'a0000101A8B3C4', '', 'spool'):
        assert sj.decode_at_name(bad) is None


def test_at_job_plain_layout():
    secret = 's3cr3t'
    r = sj.parse_at_job('a0000101a8b3c4', at_script(['/usr/local/bin/backup --full'],
                                                     env=(f'DB_PASS={secret}; export DB_PASS', 'PATH=/bin; export PATH')),
                        owner_uid=1000)
    assert r['state'] == 'parsed' and r['gaps'] == []
    assert (r['uid'], r['gid'], r['owner_mismatch']) == (1000, 1000, False)
    assert r['environment_names'] == ['DB_PASS', 'PATH'] and secret not in repr(r)
    assert r['working_directory'] == '/home/alice'
    assert r['command'] == '/usr/local/bin/backup --full'
    assert r['queue'] == 'a' and r['job_number'] == 1 and r['origin'] == 'not_assessed'


def test_at_job_heredoc_layout():
    block = ["${SHELL:-/bin/sh} << 'marcinDELIMITER2b6b4ac8'", 'echo one', 'echo two', 'marcinDELIMITER2b6b4ac8']
    r = sj.parse_at_job('b0000201a8b3c4', at_script(block))
    assert r['state'] == 'parsed' and r['command'] == 'echo one\necho two'
    assert r['owner_mismatch'] is None


def test_at_job_owner_mismatch_is_a_gap():
    r = sj.parse_at_job('a0000101a8b3c4', at_script(['id']), owner_uid=0)
    assert r['owner_mismatch'] is True and r['state'] == 'partial'
    assert r['gaps'][0]['code'] == 'owner_mismatch' and r['command'] == 'id'


def test_at_job_unrecognized_layouts_fail_closed():
    name = 'a0000101a8b3c4'
    cases = {
        'no header': '#!/bin/sh\necho hi\n',
        'no cd': '#!/bin/sh\n# atrun uid=0 gid=0\numask 22\necho hi\n',
        'unclosed cd': '#!/bin/sh\n# atrun uid=0 gid=0\ncd / || {\n echo x\n',
        'unterminated heredoc': at_script(["${SHELL:-/bin/sh} << 'DELIM'", 'echo hi']),
        'trailing after heredoc': at_script(["${SHELL:-/bin/sh} << 'DELIM'", 'echo hi', 'DELIM', 'rm -rf /']),
    }
    for label, text in cases.items():
        r = sj.parse_at_job(name, text)
        assert r['state'] == 'unavailable', label
        assert r['command'] is None, label
        assert r['gaps'][0]['code'] == 'unrecognized_layout', label
    assert sj.parse_at_job('.SEQ', '0\n')['gaps'][0]['code'] == 'unrecognized_name'
    assert sj.parse_at_job(name, 'x' * (sj.MAX_TEXT + 1))['gaps'][0]['code'] == 'over_limit'


def test_at_job_empty_command_and_env_cap():
    r = sj.parse_at_job('a0000101a8b3c4', at_script([]))
    assert r['state'] == 'partial' and r['gaps'][0]['code'] == 'empty_command' and r['command'] is None
    env = tuple(f'V{i}=1; export V{i}' for i in range(sj.MAX_ENV + 1))
    capped = sj.parse_at_job('a0000101a8b3c4', at_script(['id'], env=env))
    assert capped['state'] == 'unavailable' and capped['environment_names'] == []


def test_non_ascii_anacron_numeric_fields_are_coverage_gaps():
    result = sj.parse_anacrontab(
        'RANDOM_DELAY=\u00b2\nSTART_HOURS_RANGE=\u0663-22\n'
        '\u00b2 5 period /bin/true\n1 \u00b2 delay /bin/true\n'
        '\u0661 5 decimal /bin/true\n1 0 good /bin/true\n'
    )
    assert result['state'] == 'partial'
    assert result['settings'] == {}
    assert [job['identifier'] for job in result['jobs']] == ['good']
    assert [gap['code'] for gap in result['gaps']] == [
        'invalid_setting', 'invalid_setting', 'invalid_period', 'invalid_delay', 'invalid_period',
    ]
