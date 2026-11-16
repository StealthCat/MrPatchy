import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools import benchmark_ai
from tools.compare_ai_benchmarks import ComparisonError, compare


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / 'tools' / 'benchmark_ai.py'
ENV = benchmark_ai.MYSQL_URL_ENV
SECRET = 'fixture-secret-never-printed'
MYSQL_URL = os.getenv('TEST_DATABASE_URL', '')
needs_mysql = pytest.mark.skipif(not MYSQL_URL.startswith('mysql'), reason='MySQL service required')


def run(*arguments, url=None, extra=None, timeout=120):
    environment = {name: value for name, value in os.environ.items()
                   if name not in (ENV, 'DATABASE_URL', 'TEST_DATABASE_URL')}
    if url is not None:
        environment[ENV] = url
    environment.update(extra or {})
    return subprocess.run([sys.executable, str(BENCHMARK), *arguments], cwd=ROOT, env=environment,
                          capture_output=True, text=True, timeout=timeout, check=False)


@pytest.mark.parametrize('url, reason', [
    (None, f'--database mysql requires {ENV}'),
    ('   ', f'--database mysql requires {ENV}'),
    (f'sqlite:///{SECRET}.db', 'must be a mysql+pymysql:// URL'),
    (f'postgresql://user:{SECRET}@127.0.0.1/bench', 'must be a mysql+pymysql:// URL'),
    (f'mysql://user:{SECRET}@127.0.0.1/bench', 'must be a mysql+pymysql:// URL'),
    (f'mysql+pymysql://user:{SECRET}@127.0.0.1', 'must name a host and a database'),
    (f'mysql+pymysql://user:{SECRET}@/bench', 'must name a host and a database'),
    (f'mysql+pymysql://user:{SECRET}@127.0.0.1:not-a-port/bench', 'is not a valid database URL'),
    (f'not a url {SECRET}', 'is not a valid database URL'),
])
def test_mysql_mode_refuses_an_unusable_target_without_echoing_it(url, reason):
    result = run('--database', 'mysql', url=url, timeout=30)
    assert result.returncode == 2 and result.stdout == ''
    assert reason in result.stderr
    assert SECRET not in result.stderr


def test_mysql_mode_reports_an_unreachable_server_by_error_class_only():
    result = run('--database', 'mysql', url=f'mysql+pymysql://user:{SECRET}@127.0.0.1:1/bench', timeout=60)
    assert result.returncode == 2 and result.stdout == ''
    assert 'cannot inspect the benchmark MySQL database (OperationalError)' in result.stderr
    assert SECRET not in result.stderr and '127.0.0.1' not in result.stderr


def test_sqlite_default_ignores_deployment_and_benchmark_database_urls():
    unreachable = f'mysql+pymysql://user:{SECRET}@127.0.0.1:1/bench'
    result = run('--runs', '2', '--provider-delay-ms', '1', '--ssh-delay-ms', '1',
                 url=unreachable, extra={'DATABASE_URL': unreachable})
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['database'] == 'sqlite' and report['database_version']
    assert report['provider_calls'] == 3 and report['errors'] == 0
    assert SECRET not in result.stdout


def test_the_target_url_is_read_only_from_the_environment():
    result = run('--database', 'mysql', '--database-url', 'mysql+pymysql://u:p@127.0.0.1/bench', timeout=30)
    assert result.returncode == 2
    assert 'unrecognized arguments' in result.stderr


def _tables(engine):
    from sqlalchemy import text
    with engine.connect() as connection:
        return sorted(row[0] for row in connection.execute(text('SHOW FULL TABLES')))


@pytest.fixture
def empty_mysql():
    """The CI database is dedicated and disposable; every `client` fixture rebuilds it."""
    from sqlalchemy import text
    from app.db import engine, init

    def clear():
        with engine.connect() as connection:
            connection.execute(text('SET FOREIGN_KEY_CHECKS=0'))
            for name, kind in list(connection.execute(text('SHOW FULL TABLES'))):
                connection.execute(text(f"DROP {'VIEW' if kind == 'VIEW' else 'TABLE'} `{name}`"))
            connection.commit()
        engine.dispose()

    clear()
    try:
        yield engine
    finally:
        clear()
        init()
        engine.dispose()


@needs_mysql
def test_mysql_mode_refuses_a_database_that_already_has_tables(empty_mysql):
    from sqlalchemy import text
    with empty_mysql.begin() as connection:
        connection.execute(text('CREATE TABLE operator_data (id INT PRIMARY KEY, note VARCHAR(20))'))
        connection.execute(text("INSERT INTO operator_data VALUES (1, 'keep me')"))
    empty_mysql.dispose()
    result = run('--database', 'mysql', '--runs', '2', url=MYSQL_URL, timeout=60)
    assert result.returncode == 2 and result.stdout == ''
    assert 'already has tables' in result.stderr and 'nothing was changed' in result.stderr
    assert _tables(empty_mysql) == ['operator_data']
    with empty_mysql.connect() as connection:
        assert connection.execute(text('SELECT note FROM operator_data')).scalar_one() == 'keep me'


@needs_mysql
def test_mysql_serial_and_parallel_reports_are_equivalent_and_leave_no_tables(empty_mysql):
    reports = []
    for concurrency in (1, 4):
        result = run('--database', 'mysql', '--runs', '4', '--concurrency', str(concurrency),
                     '--provider-delay-ms', '40', '--ssh-delay-ms', '1', '--retained-history-rows', '25',
                     url=MYSQL_URL)
        assert result.returncode == 0, result.stderr
        assert MYSQL_URL not in result.stdout and MYSQL_URL not in result.stderr
        assert _tables(empty_mysql) == []
        empty_mysql.dispose()
        reports.append(json.loads(result.stdout))
    serial, parallel = reports
    for report in reports:
        assert report['database'] == 'mysql' and report['database_version']
        assert report['runs'] == report['completed_subjects'] == 4
        assert report['provider_calls'] == 6 and report['errors'] == 0
        assert report['retained_history_rows'] == 25 and report['approved_subjects'] == 0
    assert serial['peak_provider_requests'] == 1 and parallel['peak_provider_requests'] > 1
    comparison = compare(serial, parallel)
    assert comparison['capability_equivalent'] is True
    assert comparison['baseline']['database'] == comparison['candidate']['database'] == 'mysql'
    sqlite = run('--runs', '4', '--provider-delay-ms', '40', '--ssh-delay-ms', '1', '--retained-history-rows', '25')
    assert sqlite.returncode == 0, sqlite.stderr
    sqlite_report = json.loads(sqlite.stdout)
    # The same synthetic workload reaches the provider and SSH fixtures on either backend.
    assert sqlite_report['workload_fingerprint'] == parallel['workload_fingerprint']
    with pytest.raises(ComparisonError, match='capability mismatch: database differs'):
        compare(sqlite_report, parallel)


@needs_mysql
def test_mysql_mode_cleans_up_after_a_failure_once_the_database_was_claimed(empty_mysql):
    # Rejected after the empty database was claimed: more threads than one server's slots.
    result = run('--database', 'mysql', '--same-server', '--runs', '8', '--concurrency', '8', url=MYSQL_URL, timeout=60)
    assert result.returncode == 2 and '--same-server requires --concurrency at most' in result.stderr
    assert _tables(empty_mysql) == []


@needs_mysql
def test_cleanup_removes_every_fixture_table_and_view(empty_mysql):
    from sqlalchemy import text
    scratch, version = benchmark_ai.claim_empty_mysql(benchmark_ai.mysql_target({ENV: MYSQL_URL}))
    assert version
    with empty_mysql.begin() as connection:
        connection.execute(text('CREATE TABLE parent (id INT PRIMARY KEY)'))
        connection.execute(text('CREATE TABLE `odd``name` (id INT PRIMARY KEY, parent INT, '
                                'FOREIGN KEY (parent) REFERENCES parent (id))'))
        connection.execute(text('CREATE VIEW parent_view AS SELECT id FROM parent'))
    empty_mysql.dispose()
    with pytest.raises(benchmark_ai.DatabaseRefused, match='already has tables'):
        benchmark_ai.claim_empty_mysql(benchmark_ai.mysql_target({ENV: MYSQL_URL}))
    benchmark_ai.drop_mysql_tables(scratch)
    assert _tables(empty_mysql) == []
