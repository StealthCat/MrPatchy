"""Disposable serial/parallel triage fixture; no external provider or SSH target."""
import argparse
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import re
import statistics
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from copy import deepcopy
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

MYSQL_URL_ENV = 'AI_BENCHMARK_MYSQL_URL'
FIXTURE_MODEL = 'fixture-model'
FIXTURE_PRICE_VERSION = 'synthetic-v1'
FIXTURE_CAP_USD = 10
DEFAULT_FIXTURE_RATE_PER_HOUR = 1000
MAX_FIXTURE_PACING_SECONDS = 300
PACED_MODES = ('rate', 'rate_and_daily')
PERSISTENCE_TIMING = re.compile(r'([a-z ]+): ([0-9]{1,16}\.[0-9]{3}) ms; outcome=(complete|error)')
FIXTURE_RESULT = {
    'risk': 'low', 'explanation': 'Synthetic complete assessment',
    'recommended_checks': 'None', 'requested_checks': [],
}
FIXTURE_FOLLOW_UP = {
    'identity_verified': True, 'sha256': 'a' * 64,
    'executable': {'path': '/fixture/artifact', 'verified': True},
}


class BenchmarkTimingError(ValueError):
    """The disposable workload did not retain complete timing evidence."""

class BenchmarkAssessmentError(ValueError):
    """The disposable workload did not retain its expected assessments."""



def clean_source_commit(root):
    """Return the tracked checkout's commit when Git can verify it is clean."""
    if not (root / '.git').exists():
        return None
    # Identify this checkout independent of the caller's directory or Git overrides.
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
    try:
        status = subprocess.run(
            ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
             'status', '--porcelain=v2', '--branch', '--untracked-files=no'],
            cwd=root, env=environment, check=True, capture_output=True, encoding='utf-8',
            errors='replace', timeout=5,
        ).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return None
    if any(not line.startswith('# ') for line in status):
        return None
    commit = next((line.removeprefix('# branch.oid ') for line in status
                   if line.startswith('# branch.oid ')), '')
    return commit if re.fullmatch(r'[0-9a-f]{40}(?:[0-9a-f]{24})?', commit) else None


class DatabaseRefused(Exception):
    """Fixed-text refusal; never carries the URL, credentials or driver text."""


def mysql_target(environ):
    """Return the validated disposable MySQL URL from the environment.

    The URL is read only from MYSQL_URL_ENV so its password never appears in the
    process arguments, and DATABASE_URL is deliberately ignored.
    """
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ArgumentError

    raw = environ.get(MYSQL_URL_ENV, '').strip()
    if not raw:
        raise DatabaseRefused(f'--database mysql requires {MYSQL_URL_ENV} to hold the disposable database URL')
    try:
        url = make_url(raw)
        url.port  # a malformed port raises here
    except (ArgumentError, ValueError):
        raise DatabaseRefused(f'{MYSQL_URL_ENV} is not a valid database URL') from None
    if url.drivername != 'mysql+pymysql':
        raise DatabaseRefused(f'{MYSQL_URL_ENV} must be a mysql+pymysql:// URL')
    if not url.host or not url.database:
        raise DatabaseRefused(f'{MYSQL_URL_ENV} must name a host and a database')
    return url


def _mysql_tables(connection):
    from sqlalchemy import text

    return [(name, kind) for name, kind in connection.execute(text('SHOW FULL TABLES'))]


def _mysql_lock_name(url):
    # Advisory lock names are server-wide and limited to 64 characters.
    return 'mrpatchy-ai-benchmark:' + hashlib.sha256(url.database.encode()).hexdigest()[:32]


class MySQLClaim:
    """An empty database held by one benchmark run through a MySQL advisory lock."""

    def __init__(self, engine, connection, lock_name, version):
        self.engine, self.connection, self.lock_name, self.version = engine, connection, lock_name, version
        # Only the application's own tables are dropped. The metadata is read at release
        # time because models keep registering until init() has run.
        self.fixture_tables = set()
        self.metadata = None

    def release(self):
        """Drop the fixture's own tables, report anything else, and release the lock."""
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        connection = self.connection
        try:
            # Named locks belong to the session. A replacement connection cannot
            # distinguish this run's tables from a later owner's tables.
            try:
                owns_lock = connection.execute(
                    text('SELECT IS_USED_LOCK(:name) = CONNECTION_ID()'),
                    {'name': self.lock_name},
                ).scalar_one() == 1
            except SQLAlchemyError:
                owns_lock = False
            if not owns_lock:
                raise DatabaseRefused(
                    'Benchmark MySQL lock ownership could not be verified; cleanup skipped. '
                    'Inspect the disposable database before reusing it.'
                )

            foreign = 0
            owned = self.fixture_tables | set(self.metadata.tables if self.metadata is not None else ())
            connection.execute(text('SET FOREIGN_KEY_CHECKS=0'))
            for name, kind in _mysql_tables(connection):
                if kind == 'VIEW' or name not in owned:
                    foreign += 1
                    continue
                connection.execute(text('DROP TABLE `' + name.replace('`', '``') + '`'))
            connection.execute(text('SET FOREIGN_KEY_CHECKS=1'))
            connection.execute(text('SELECT RELEASE_LOCK(:name)'), {'name': self.lock_name})
            connection.commit()
            if foreign:
                print(f'warning: left {foreign} table(s) or view(s) the benchmark did not create in the '
                      'MySQL database; it is no longer empty', file=sys.stderr)
        finally:
            try:
                connection.close()
            finally:
                self.engine.dispose()


def claim_empty_mysql(url):
    """Lock the database for this run and refuse it unless it has no tables.

    An empty schema is the tool's evidence that the target is disposable. The
    advisory lock stops two benchmark runs from sharing one database. Nothing
    is written before both checks pass.
    """
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import SQLAlchemyError

    engine = create_engine(url, pool_pre_ping=True)
    lock_name = _mysql_lock_name(url)
    try:
        connection = engine.connect()
        version = str(connection.execute(text('SELECT VERSION()')).scalar_one())[:64]
        locked = connection.execute(text('SELECT GET_LOCK(:name, 0)'), {'name': lock_name}).scalar_one() == 1
        occupied = locked and bool(_mysql_tables(connection))
        if occupied:
            connection.execute(text('SELECT RELEASE_LOCK(:name)'), {'name': lock_name})
        connection.commit()
    except SQLAlchemyError as error:
        engine.dispose()
        raise DatabaseRefused(f'cannot inspect the benchmark MySQL database ({type(error).__name__})') from None
    if not locked or occupied:
        connection.close(); engine.dispose()
        raise DatabaseRefused(
            'the benchmark MySQL database already has tables; use an empty disposable database '
            '(nothing was changed)' if occupied else
            'another benchmark run holds the benchmark MySQL database; wait for it to finish (nothing was changed)')
    return MySQLClaim(engine, connection, lock_name, version)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def workload_fingerprint(provider_requests, ssh_requests):
    """Hash the observed synthetic requests independently of dispatch order."""
    provider = []
    for request in provider_requests:
        evidence = json.loads(request['input'])
        if 'investigation' in evidence:
            evidence['investigation'].pop('collected', None)
        provider.append(canonical({**request, 'input': evidence}))

    ssh = [canonical({**request, 'checks': sorted(request['checks'])}) for request in ssh_requests]
    workload = {'version': 1, 'provider': sorted(provider), 'ssh': sorted(ssh)}
    return {'version': workload['version'], 'sha256': hashlib.sha256(canonical(workload).encode()).hexdigest()}


def collect_persisted_timings(events, expected_persistence):
    """Collect timings only after checking each fixture run's persistence evidence."""
    remaining = {stage: set(run_ids) for stage, run_ids in expected_persistence.items()}
    samples = {}
    for event in events:
        stage = event.stage.removeprefix('timing_')
        if stage in remaining:
            if event.run_id not in expected_persistence[stage]:
                raise BenchmarkTimingError(f'{stage}: unexpected timing sample')
            if event.run_id not in remaining[stage]:
                raise BenchmarkTimingError(f'{stage}: duplicate timing sample')
            message = event.message
            match = PERSISTENCE_TIMING.fullmatch(message) if isinstance(message, str) else None
            if match is None or match[1] != stage.replace('_', ' '):
                raise BenchmarkTimingError(f'{stage}: malformed timing sample')
            if match[3] != 'complete':
                raise BenchmarkTimingError(f'{stage}: failed timing sample')
            remaining[stage].remove(event.run_id)
            value = float(match[2])
        else:
            value = float(event.message.split(': ', 1)[1].split(' ms;', 1)[0])
        samples.setdefault(stage, []).append(value)
    for stage, missing in remaining.items():
        if missing:
            raise BenchmarkTimingError(f'{stage}: missing {len(missing)} timing sample(s)')
    return samples


def assessment_coverage(assessments, observations, runs, follow_up_subjects, ai, provider_requests):
    """Verify the retained result and input trail after the timed workload."""
    observations_by_subject = {row.id: row for row in observations}
    runs_by_subject = {run.subject: run for run in runs}
    seen = set()
    saved_evidence = Counter()
    policy = ai.investigation_policy()
    for assessment in assessments:
        subject = assessment.subject
        observation = observations_by_subject.get(subject)
        run = runs_by_subject.get(subject)
        if observation is None or run is None:
            raise BenchmarkAssessmentError('Assessment persistence: unexpected subject.')
        if subject in seen:
            raise BenchmarkAssessmentError('Assessment persistence: duplicate subject.')
        seen.add(subject)
        if (assessment.run_id, assessment.host_id, assessment.source, assessment.model) != (
                run.id, observation.host_id, 'ai', FIXTURE_MODEL):
            raise BenchmarkAssessmentError('Assessment persistence: run, host, source or model differs.')
        evidence = observation.evidence
        if (not isinstance(evidence, dict) or assessment.result != FIXTURE_RESULT
                or assessment.snapshot != evidence):
            raise BenchmarkAssessmentError('Assessment persistence: final result or evidence snapshot differs.')

        initial = {key: value for key, value in evidence.items() if key != 'investigation'}
        expected_inputs = [{'evidence': ai.investigation_input(initial), 'policy': policy}]
        if subject in follow_up_subjects:
            follow_up = evidence.get('investigation')
            if not isinstance(follow_up, dict) or follow_up.get('details') != FIXTURE_FOLLOW_UP:
                raise BenchmarkAssessmentError('Assessment persistence: expected follow-up evidence is missing or changed.')
            expected_inputs.append({'evidence': ai.investigation_input(evidence), 'policy': policy})
        elif 'investigation' in evidence:
            raise BenchmarkAssessmentError('Assessment persistence: unexpected follow-up evidence.')
        if assessment.inputs != expected_inputs:
            raise BenchmarkAssessmentError('Assessment persistence: retained AI input stages differ.')
        saved_evidence.update(canonical(stage['evidence']) for stage in assessment.inputs)

    if missing := observations_by_subject.keys() - seen:
        raise BenchmarkAssessmentError(f'Assessment persistence: missing {len(missing)} assessment(s).')
    sent_evidence = Counter(canonical(json.loads(request['input'])) for request in provider_requests)
    if saved_evidence != sent_evidence:
        raise BenchmarkAssessmentError('Assessment persistence: retained evidence differs from provider requests.')
    return {'subjects': len(seen), 'input_stages': sum(saved_evidence.values()),
            'follow_up_subjects': len(follow_up_subjects)}


def capped_fixture_summary(session, budget_entry, receipts, settings):
    """Require one settled reservation for each priced receipt and no extra rows."""
    expected = {receipt.id: receipt for group in receipts.values() for receipt in group}
    entries = session.query(budget_entry).all()
    if len(entries) != len(expected) or {entry.call_id for entry in entries} != expected.keys():
        raise ValueError('Capped fixture did not retain one reservation per provider receipt.')
    for entry in entries:
        receipt = expected[entry.call_id]
        if (entry.status != 'settled' or receipt.status != 'estimated'
                or entry.run_id != receipt.run_id or entry.model != FIXTURE_MODEL
                or entry.pricing_version != FIXTURE_PRICE_VERSION
                or entry.timezone != settings['ai_budget_timezone']
                or entry.actual_usd != Decimal(receipt.pricing['estimated_usd'])
                or not 0 < entry.actual_usd <= entry.reservation_usd):
            raise ValueError('Capped fixture could not verify a fully settled provider receipt.')
    return {
        'pricing_version': FIXTURE_PRICE_VERSION,
        'cap_usd': settings['ai_daily_cap_usd'],
        'timezone': settings['ai_budget_timezone'],
        'settled_calls': len(entries),
        'settled_microusd': int(sum(entry.actual_usd for entry in entries) * 1_000_000),
    }


def dispatch_paced(pool, run_one, runs, session_factory, admission_model):
    """Wait for each durable start slot while earlier investigations can finish."""
    futures = []
    wait_seconds = 0.0
    for index in range(runs):
        if futures:
            started = time.perf_counter()
            deadline = started + 45
            previous = futures[-1]
            while True:
                finished = previous.done()
                with session_factory() as session:
                    slot = session.get(admission_model, 'global')
                    next_at = slot.next_at if slot is not None and slot.admitted == index else None
                if next_at is not None:
                    time.sleep(max(0, next_at - time.time()))
                    break
                if finished or time.perf_counter() >= deadline:
                    if finished:
                        previous.result()
                    raise BenchmarkTimingError('Paced fixture did not observe the previous durable start.')
                time.sleep(0.02)
            wait_seconds += time.perf_counter() - started
        futures.append(pool.submit(run_one, time.perf_counter()))
    for future in futures:
        future.result()
    return wait_seconds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=int, default=8)
    parser.add_argument('--follow-up-runs', type=int,
                        help='number of investigations requesting follow-up evidence (default: every second run)')
    parser.add_argument('--concurrency', type=int, default=1)
    layout = parser.add_mutually_exclusive_group()
    layout.add_argument('--same-server', action='store_true',
                        help='place distinct subjects on one server using its maximum supported slots')
    layout.add_argument('--servers', type=int,
                        help='distribute subjects across this many fixture servers (default: one per run)')
    parser.add_argument('--provider-delay-ms', type=int, default=20)
    parser.add_argument('--persistence-delay-ms', type=int, default=0)
    parser.add_argument('--ssh-delay-ms', type=int, default=10,
                        help='simulated latency of a follow-up SSH evidence request (default: 10)')
    parser.add_argument('--control-mode', choices=('legacy', 'unthrottled', 'daily_cap', *PACED_MODES),
                        default='legacy', help='AI control mode for the fixture (default: legacy). '
                        'Capped modes use the real spend ledger with synthetic prices. '
                        'Paced modes wait for the real gate.')
    parser.add_argument('--rate-per-hour', type=int,
                        help='shared starts per hour in paced modes (1–1000, default: 1000)')
    parser.add_argument('--queue-age-seconds', type=int, default=2,
                        help='synthetic age of queued observations without a real wait (default: 2)')
    parser.add_argument('--retained-history-rows', type=int, default=0,
                        help='number of older completed observations to seed (default: 0)')
    parser.add_argument('--database', choices=('sqlite', 'mysql'), default='sqlite',
                        help='sqlite: temporary file (default). mysql: the EMPTY disposable database named by '
                             f'the {MYSQL_URL_ENV} environment variable; its tables are removed afterwards')
    args = parser.parse_args()
    if not 2 <= args.runs <= 20: parser.error('--runs must be between 2 and 20')
    servers = args.runs if args.servers is None else args.servers
    if args.same_server:
        servers = 1
    if not 1 <= servers <= args.runs:
        parser.error('--servers must be between 1 and --runs')
    paced = args.control_mode in PACED_MODES
    rate = DEFAULT_FIXTURE_RATE_PER_HOUR if args.rate_per_hour is None else args.rate_per_hour
    if args.rate_per_hour is not None and not paced:
        parser.error('--rate-per-hour requires --control-mode rate or rate_and_daily')
    if not 1 <= rate <= 1000:
        parser.error('--rate-per-hour must be between 1 and 1000')
    if paced and (args.runs - 1) * 3600 > MAX_FIXTURE_PACING_SECONDS * rate:
        parser.error(f'The workload requires more than {MAX_FIXTURE_PACING_SECONDS} seconds of scheduled pacing. '
                     'Reduce --runs or raise --rate-per-hour.')
    if args.follow_up_runs is not None and not 0 <= args.follow_up_runs <= args.runs:
        parser.error('--follow-up-runs must be between 0 and --runs')
    if args.follow_up_runs is None:
        follow_up_indices = range(1, args.runs, 2)
    else:
        follow_up_indices = {
            index for index in range(args.runs)
            if (index + 1) * args.follow_up_runs // args.runs > index * args.follow_up_runs // args.runs
        }
    if not 1<=args.concurrency<=8:parser.error('--concurrency must be between 1 and 8')
    if not 1<=args.provider_delay_ms<=1000:parser.error('--provider-delay-ms must be between 1 and 1000')
    if not 0<=args.persistence_delay_ms<=1000:parser.error('--persistence-delay-ms must be between 0 and 1000')
    if not 0 <= args.ssh_delay_ms <= 1000:
        parser.error('--ssh-delay-ms must be between 0 and 1000')
    if not 0 <= args.queue_age_seconds <= 86400:
        parser.error('--queue-age-seconds must be between 0 and 86400')
    if not 0 <= args.retained_history_rows <= 50_000:
        parser.error('--retained-history-rows must be between 0 and 50000')
    source_commit = clean_source_commit(SOURCE_ROOT)
    begin=ContextVar('benchmark_begin');two_stage=ContextVar('benchmark_two_stage',default=False)
    # Set before importing runtime modules; never inherit a deployment database.
    with tempfile.TemporaryDirectory(prefix='mrpatchy-ai-benchmark-') as directory, contextlib.ExitStack() as cleanup:
        database_url = 'sqlite:///'+directory+'/bench.db'; database_version = sqlite3.sqlite_version
        if args.database == 'mysql':
            try:
                target = mysql_target(os.environ)
                claim = claim_empty_mysql(target)
            except DatabaseRefused as refusal:
                parser.error(str(refusal))
            # Registered only after the lock and empty check; drops only the application's own tables.
            cleanup.callback(claim.release)
            database_version = claim.version
            database_url = target.render_as_string(hide_password=False)
        os.environ.pop(MYSQL_URL_ENV, None)
        os.environ.update(DATA_DIR=directory, DATABASE_URL=database_url, DISABLE_SCHEDULER='1')
        for name in list(os.environ):
            if name.lower().endswith('_proxy'):os.environ.pop(name)
        from sqlalchemy import insert
        from app import ai, ai_admission, ai_assessments, ai_budget, ai_policy, ai_pricing, worker, ai_runs
        from app.db import init, Session, Host, Setting, Behavior, engine, config
        from app.security import seal
        if args.database == 'mysql':
            from app.db import Base
            claim.metadata = Base.metadata
        per_server_slots = ai_policy.MAX_CONCURRENCY if servers < args.runs else None
        if per_server_slots is not None and args.concurrency > per_server_slots:
            option = '--same-server' if args.same_server else '--servers'
            parser.error(f'{option} requires --concurrency at most {per_server_slots}')
        init()
        capped = args.control_mode in ai_pricing.CAP_MODES
        if capped:
            # The benchmark uses one loopback model and never depends on public catalog dates.
            now = time.time()
            cleanup.enter_context(patch.multiple(
                ai_pricing, RATES={FIXTURE_MODEL: ('0.1', '0.01', '0.5', None)},
                VERSION=FIXTURE_PRICE_VERSION, SOURCE='Disposable loopback benchmark',
                VERIFIED_AT=now - 1, EXPIRES_AT=now + 86_400,
            ))
        requests = []
        ssh_requests = []
        connections = set()
        samples = {k: [] for k in (
            'run', 'one_stage', 'two_stage', 'provider', 'ssh_evidence', 'admission',
            'queue_age', 'executor_wait', 'receipt_persistence', 'usage_persistence',
        )}
        provider_lock = threading.Lock()
        active_provider_requests = peak_provider_requests = 0

        class Provider(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def setup(self):
                super().setup();self.connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            def log_message(self, *args): pass
            def do_POST(self):
                nonlocal active_provider_requests, peak_provider_requests
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                with provider_lock:
                    requests.append(payload)
                    connections.add(self.client_address)
                    active_provider_requests += 1
                    peak_provider_requests = max(peak_provider_requests, active_provider_requests)
                try:
                    evidence = json.loads(payload['input']); time.sleep(args.provider_delay_ms/1000)
                    result = {**FIXTURE_RESULT,
                              'requested_checks':['executable'] if evidence['two_stage'] and 'investigation' not in evidence else []}
                    response = {'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(result)}]}],
                                'usage':{'input_tokens':100,'output_tokens':20,'output_tokens_details':{'reasoning_tokens':5}}}
                    if capped:
                        response.update(model=FIXTURE_MODEL, service_tier='default')
                        response['usage']['input_tokens_details'] = {'cached_tokens': 0}
                    body = json.dumps(response).encode()
                finally:
                    with provider_lock:
                        active_provider_requests -= 1
                self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); self.wfile.flush()

        server = ThreadingHTTPServer(('127.0.0.1',0), Provider)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        ai.URL = 'http://127.0.0.1:'+str(server.server_port)+'/v1/responses'
        original = ai._request
        def measured(*a, **kw):
            started=time.perf_counter()
            try:return original(*a,**kw)
            finally:samples['provider'].append((time.perf_counter()-started)*1000)
        ai._request = measured
        def wrap_stage(name,fn,*,delay_ms=0):
            def wrapped(*a,**kw):
                started=time.perf_counter()
                try:
                    if delay_ms:time.sleep(delay_ms/1000)
                    return fn(*a,**kw)
                finally:samples[name].append((time.perf_counter()-started)*1000)
            return wrapped
        for name in ('request_started','record_usage'):
            stage='receipt_persistence' if name=='request_started' else 'usage_persistence'
            setattr(ai_runs,name,wrap_stage(stage,getattr(ai_runs,name),delay_ms=args.persistence_delay_ms))
        budget_stages = {'reserve': 'budget_reservation', 'reconcile': 'budget_reconciliation'}
        if capped:
            for name, stage in budget_stages.items():
                samples[stage] = []
                cleanup.enter_context(patch.object(ai_budget, name, wrap_stage(stage, getattr(ai_budget, name))))
        def ssh_fixture(*a, **kw):
            started=time.perf_counter(); time.sleep(args.ssh_delay_ms / 1000)
            samples['ssh_evidence'].append((time.perf_counter()-started)*1000)
            _, request = a
            ssh_requests.append(request)
            return deepcopy(FIXTURE_FOLLOW_UP)
        worker.ssh.call = ssh_fixture
        original_assess = worker._assess_behavior
        def admission(s,row,*a):
            samples['admission'].append((time.perf_counter()-begin.get())*1000)
            samples['queue_age'].append((time.time()-row.first_seen)*1000)
            two_stage.set(row.evidence['two_stage'])
            return original_assess(s,row,*a)
        worker._assess_behavior = admission
        try:
            subjects = [f'fixture-{index}' for index in range(args.runs)]
            expected_hosts = {subject: f'fixture-host-{index % servers}'
                              for index, subject in enumerate(subjects)}
            with Session() as s:
                settings = {'ai_enabled': True, 'ai_model': FIXTURE_MODEL, 'ai_hourly_limit': 100,
                            'ai_control_mode': args.control_mode}
                if capped:
                    settings.update(ai_daily_cap_usd=FIXTURE_CAP_USD, ai_budget_timezone='UTC')
                if paced:
                    settings['ai_rate_per_hour'] = rate
                s.add(Setting(key='config', value=settings))
                s.add(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
                for host_id in dict.fromkeys(expected_hosts.values()):
                    s.add(Host(id=host_id,name='Fixture only',address='192.0.2.1',fingerprint=''))
                    if per_server_slots is not None:
                        s.add(Setting(key=ai_policy.PREFIX+host_id,
                                      value={'concurrency_limit': per_server_slots}))
                if args.retained_history_rows:
                    history_time = time.time() - args.queue_age_seconds - 3600
                    s.execute(insert(Behavior), [
                        {'id': f'history-{index}', 'host_id': 'fixture-host-0', 'verdict': 'low',
                         'evidence': {}, 'first_seen': history_time, 'last_seen': history_time}
                        for index in range(args.retained_history_rows)
                    ])
                first_seen=time.time()-args.queue_age_seconds
                for index, subject in enumerate(subjects):
                    evidence = {'executable':'/fixture/artifact','sha256':'a'*64,'identity_verified':True,'two_stage':index in follow_up_indices}
                    if per_server_slots is not None:
                        evidence['uid'] = str(1000 + index)
                    s.add(Behavior(id=subject,host_id=expected_hosts[subject],first_seen=first_seen+index*.0001,
                                   evidence=evidence))
                s.commit()
            started=time.perf_counter()
            def run_one(submitted_at):
                started_at = time.perf_counter()
                samples['executor_wait'].append((started_at - submitted_at) * 1000)
                token = begin.set(started_at)
                try:
                    worker.investigate_one();duration=(time.perf_counter()-begin.get())*1000
                    samples['run'].append(duration);samples['two_stage' if two_stage.get() else 'one_stage'].append(duration)
                finally:begin.reset(token)
            with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                if paced:
                    wait_seconds = dispatch_paced(pool, run_one, args.runs, Session, ai_admission.Admission)
                else:
                    futures = [pool.submit(run_one, time.perf_counter()) for _ in range(args.runs)]
                    for future in futures:
                        future.result()
            elapsed=time.perf_counter()-started
            with Session() as s:
                rows=s.query(Behavior).filter(Behavior.id.in_(subjects)).all()
                assert len(rows)==args.runs and all(row.verdict=='low' and not row.approved for row in rows), [(r.verdict,r.analysis) for r in rows]
                retained_history_rows = s.query(Behavior).count() - len(rows)
                assert retained_history_rows == args.retained_history_rows
                completed_subjects=sum(row.verdict=='low' for row in rows)
                approved_subjects=sum(bool(row.approved) for row in rows)
                runs = s.query(ai_runs.AIRun).all()
                assert len(runs) == args.runs and all(run.state == 'complete' for run in runs)
                observed_hosts = {run.subject: run.host_id for run in runs}
                assert observed_hosts == expected_hosts
                assert sum(run.calls for run in runs) == len(requests) == args.runs + len(follow_up_indices)
                assert len(ssh_requests) == len(follow_up_indices)
                receipts = ai_runs.call_receipts(s, [run.id for run in runs])
                assert all(len(receipts[run.id]) == run.calls for run in runs)
                costs = [ai_runs.cost_summary(run, receipts[run.id]) for run in runs]
                # Report the mode the application actually applied, not only the flag.
                settings = config(s)
                control_mode = settings['ai_control_mode']
                assert control_mode == args.control_mode, control_mode
                fixture_budget = capped_fixture_summary(s, ai_budget.BudgetEntry, receipts, settings) if capped else None
                if capped:
                    for stage in budget_stages.values():
                        if len(samples[stage]) != len(requests):
                            raise BenchmarkTimingError(f'{stage}: expected one timing sample per settled provider call.')
                fixture_rate = None
                if paced:
                    if settings['ai_rate_per_hour'] != rate:
                        raise BenchmarkTimingError('The effective paced fixture rate differs from the requested rate.')
                    slot = s.get(ai_admission.Admission, 'global')
                    if slot is None or slot.admitted != len(runs):
                        raise BenchmarkTimingError('Paced fixture requires one durable start per investigation.')
                    fixture_rate = {
                        'starts_per_hour': settings['ai_rate_per_hour'],
                        'admitted_starts': slot.admitted,
                        'dispatch_wait_seconds': round(wait_seconds, 3),
                    }
                follow_up_subjects = {subjects[index] for index in follow_up_indices}
                retained_assessments = assessment_coverage(
                    s.query(ai_assessments.Assessment).all(), rows, runs, follow_up_subjects, ai, requests,
                )
                expected_persistence = {
                    'result_persistence': {run.id for run in runs},
                    'evidence_persistence': {run.id for run in runs if run.subject in follow_up_subjects},
                }
                persisted_timings = collect_persisted_timings(
                    s.query(ai_runs.AIEvent).filter(ai_runs.AIEvent.stage.like('timing_%')),
                    expected_persistence,
                )
            assert all(p['model']==FIXTURE_MODEL and p['max_output_tokens']==1600 and p['text']['format']['schema']==ai.SCHEMA for p in requests)
            def summary(values):
                if not values:
                    return {'count': 0, 'p50_ms': None, 'p95_ms': None}
                ordered=sorted(values)
                return {'count':len(values),'p50_ms':round(statistics.median(values),3),'p95_ms':round(ordered[math.ceil(.95*len(values))-1],3)}
            source_identity = (
                {'source_commit': source_commit}
                if source_commit and clean_source_commit(SOURCE_ROOT) == source_commit else {}
            )
            report = json.dumps({'fixture_only':True,**source_identity,'execution':'serial' if args.concurrency==1 else 'parallel','concurrency':args.concurrency,'provider_delay_ms':args.provider_delay_ms,'ssh_delay_ms':args.ssh_delay_ms,'persistence_delay_ms':args.persistence_delay_ms,'queue_age_seconds':args.queue_age_seconds,'runs':args.runs,'provider_calls':len(requests),
                'fixture_hosts':len(set(observed_hosts.values())),
                'single_server_slots':per_server_slots if servers == 1 else None,
                **({'shared_server_slots':per_server_slots} if 1 < servers < args.runs else {}),
                'peak_provider_requests':peak_provider_requests,
                'database':args.database, 'database_version':database_version,
                'retained_history_rows':retained_history_rows,'connections':len(connections),
                'elapsed_seconds':round(elapsed,3),'runs_per_second':round(args.runs/elapsed,3),
                'workload_fingerprint':workload_fingerprint(requests,ssh_requests),
                'persisted_assessments':retained_assessments,
                'ai_control_mode':control_mode,
                **({'fixture_budget': fixture_budget} if capped else {}),
                **({'fixture_rate': fixture_rate} if paced else {}),
                'stages':{k:summary(v) for k,v in samples.items()},
                'persisted_stages':{k:summary(v) for k,v in persisted_timings.items()},'input_tokens':sum(c['tokens']['input_tokens'] for c in costs),
                'output_tokens':sum(c['tokens']['output_tokens'] for c in costs),'completed_subjects':completed_subjects,'approved_subjects':approved_subjects,
                'errors':0,'cost_status':'unavailable: synthetic model/usage, no paid API calls','initial_fixture_queue_age_seconds':args.queue_age_seconds,
                'notes':'Loopback provider, SSH delay, queue age and the optional receipt/usage persistence delay are synthetic; no production/TLS/database speed claim. Admission includes lock/query/run creation; run includes persistence.'},indent=2)
        finally:
            if hasattr(ai,'transport'):ai.transport.close()
            server.shutdown();server.server_close();thread.join();engine.dispose()

    # ExitStack runs the MySQL cleanup before a successful report is emitted.
    print(report)


if __name__ == '__main__':
    try:
        main()
    except (DatabaseRefused, BenchmarkTimingError, BenchmarkAssessmentError) as refusal:
        sys.exit(str(refusal))
