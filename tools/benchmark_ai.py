"""Disposable serial/parallel triage fixture; no external provider or SSH target."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import socket
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def workload_fingerprint(provider_requests, ssh_requests):
    """Hash the observed synthetic requests independently of dispatch order."""
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)

    provider = []
    for request in provider_requests:
        evidence = json.loads(request['input'])
        if 'investigation' in evidence:
            evidence['investigation'].pop('collected', None)
        provider.append(canonical({**request, 'input': evidence}))

    ssh = [canonical({**request, 'checks': sorted(request['checks'])}) for request in ssh_requests]
    workload = {'version': 1, 'provider': sorted(provider), 'ssh': sorted(ssh)}
    return {'version': workload['version'], 'sha256': hashlib.sha256(canonical(workload).encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=int, default=8)
    parser.add_argument('--concurrency', type=int, default=1)
    parser.add_argument('--same-server', action='store_true',
                        help='place distinct subjects on one server using its maximum supported slots')
    parser.add_argument('--provider-delay-ms', type=int, default=20)
    parser.add_argument('--persistence-delay-ms', type=int, default=0)
    parser.add_argument('--ssh-delay-ms', type=int, default=10,
                        help='simulated latency of a follow-up SSH evidence request (default: 10)')
    parser.add_argument('--queue-age-seconds', type=int, default=2,
                        help='synthetic age of queued observations without a real wait (default: 2)')
    parser.add_argument('--retained-history-rows', type=int, default=0,
                        help='number of older completed observations to seed (default: 0)')
    args = parser.parse_args()
    if not 2 <= args.runs <= 20: parser.error('--runs must be between 2 and 20')
    if not 1<=args.concurrency<=8:parser.error('--concurrency must be between 1 and 8')
    if not 1<=args.provider_delay_ms<=1000:parser.error('--provider-delay-ms must be between 1 and 1000')
    if not 0<=args.persistence_delay_ms<=1000:parser.error('--persistence-delay-ms must be between 0 and 1000')
    if not 0 <= args.ssh_delay_ms <= 1000:
        parser.error('--ssh-delay-ms must be between 0 and 1000')
    if not 0 <= args.queue_age_seconds <= 86400:
        parser.error('--queue-age-seconds must be between 0 and 86400')
    if not 0 <= args.retained_history_rows <= 50_000:
        parser.error('--retained-history-rows must be between 0 and 50000')
    begin=ContextVar('benchmark_begin');two_stage=ContextVar('benchmark_two_stage',default=False)
    # Set before importing runtime modules; never inherit a deployment database.
    with tempfile.TemporaryDirectory(prefix='mrpatchy-ai-benchmark-') as directory:
        os.environ.update(DATA_DIR=directory, DATABASE_URL='sqlite:///'+directory+'/bench.db', DISABLE_SCHEDULER='1')
        for name in list(os.environ):
            if name.lower().endswith('_proxy'):os.environ.pop(name)
        from sqlalchemy import insert
        from app import ai, ai_policy, worker, ai_runs
        from app.db import init, Session, Host, Setting, Behavior, engine
        from app.security import seal
        single_server_slots = ai_policy.MAX_CONCURRENCY if args.same_server else None
        if single_server_slots is not None and args.concurrency > single_server_slots:
            parser.error(f'--same-server requires --concurrency at most {single_server_slots}')
        init()
        requests = []; ssh_requests = []; connections = set(); samples = {k: [] for k in ('run', 'one_stage', 'two_stage', 'provider', 'ssh_evidence', 'admission', 'queue_age', 'receipt_persistence', 'usage_persistence')}
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
                    result = {'risk':'low','explanation':'Synthetic complete assessment','recommended_checks':'None',
                              'requested_checks':['executable'] if evidence['two_stage'] and 'investigation' not in evidence else []}
                    body = json.dumps({'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(result)}]}],
                                       'usage':{'input_tokens':100,'output_tokens':20,'output_tokens_details':{'reasoning_tokens':5}}}).encode()
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
        def wrap_stage(name,fn):
            def wrapped(*a,**kw):
                started=time.perf_counter()
                try:
                    if args.persistence_delay_ms:time.sleep(args.persistence_delay_ms/1000)
                    return fn(*a,**kw)
                finally:samples[name].append((time.perf_counter()-started)*1000)
            return wrapped
        for name in ('request_started','record_usage'):
            stage='receipt_persistence' if name=='request_started' else 'usage_persistence'
            setattr(ai_runs,name,wrap_stage(stage,getattr(ai_runs,name)))
        def ssh_fixture(*a, **kw):
            started=time.perf_counter(); time.sleep(args.ssh_delay_ms / 1000)
            samples['ssh_evidence'].append((time.perf_counter()-started)*1000)
            _, request = a
            ssh_requests.append(request)
            return {'identity_verified':True,'sha256':'a'*64,'executable':{'path':'/fixture/artifact','verified':True}}
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
            expected_hosts = {subject: f'fixture-host-{0 if args.same_server else index}'
                              for index, subject in enumerate(subjects)}
            with Session() as s:
                s.add(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model','ai_hourly_limit':100}))
                s.add(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
                for host_id in dict.fromkeys(expected_hosts.values()):
                    s.add(Host(id=host_id,name='Fixture only',address='192.0.2.1',fingerprint=''))
                if single_server_slots is not None:
                    s.add(Setting(key=ai_policy.PREFIX+'fixture-host-0',
                                  value={'concurrency_limit': single_server_slots}))
                if args.retained_history_rows:
                    history_time = time.time() - args.queue_age_seconds - 3600
                    s.execute(insert(Behavior), [
                        {'id': f'history-{index}', 'host_id': 'fixture-host-0', 'verdict': 'low',
                         'evidence': {}, 'first_seen': history_time, 'last_seen': history_time}
                        for index in range(args.retained_history_rows)
                    ])
                first_seen=time.time()-args.queue_age_seconds
                for index, subject in enumerate(subjects):
                    evidence = {'executable':'/fixture/artifact','sha256':'a'*64,'identity_verified':True,'two_stage':bool(index%2)}
                    if args.same_server:
                        evidence['uid'] = str(1000 + index)
                    s.add(Behavior(id=subject,host_id=expected_hosts[subject],first_seen=first_seen+index*.0001,
                                   evidence=evidence))
                s.commit()
            started=time.perf_counter()
            def run_one(index):
                token=begin.set(time.perf_counter())
                try:
                    worker.investigate_one();duration=(time.perf_counter()-begin.get())*1000
                    samples['run'].append(duration);samples['two_stage' if two_stage.get() else 'one_stage'].append(duration)
                finally:begin.reset(token)
            with ThreadPoolExecutor(max_workers=args.concurrency) as pool:list(pool.map(run_one,range(args.runs)))
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
                assert sum(run.calls for run in runs)==len(requests)==args.runs+args.runs//2
                receipts = ai_runs.call_receipts(s, [run.id for run in runs])
                assert all(len(receipts[run.id]) == run.calls for run in runs)
                costs = [ai_runs.cost_summary(run, receipts[run.id]) for run in runs]
            persisted_timings={}
            with Session() as s:
                for event in s.query(ai_runs.AIEvent).filter(ai_runs.AIEvent.stage.like('timing_%')):
                    stage=event.stage.removeprefix('timing_')
                    persisted_timings.setdefault(stage,[]).append(float(event.message.split(': ',1)[1].split(' ms;',1)[0]))
            assert all(p['model']=='fixture-model' and p['max_output_tokens']==1600 and p['text']['format']['schema']==ai.SCHEMA for p in requests)
            def summary(values):
                ordered=sorted(values)
                return {'count':len(values),'p50_ms':round(statistics.median(values),3),'p95_ms':round(ordered[math.ceil(.95*len(values))-1],3)}
            print(json.dumps({'fixture_only':True,'execution':'serial' if args.concurrency==1 else 'parallel','concurrency':args.concurrency,'provider_delay_ms':args.provider_delay_ms,'ssh_delay_ms':args.ssh_delay_ms,'persistence_delay_ms':args.persistence_delay_ms,'queue_age_seconds':args.queue_age_seconds,'runs':args.runs,'provider_calls':len(requests),
                'fixture_hosts':len(set(observed_hosts.values())), 'single_server_slots':single_server_slots,
                'peak_provider_requests':peak_provider_requests,
                'retained_history_rows':retained_history_rows,'connections':len(connections),
                'elapsed_seconds':round(elapsed,3),'runs_per_second':round(args.runs/elapsed,3),
                'workload_fingerprint':workload_fingerprint(requests,ssh_requests),
                'stages':{k:summary(v) for k,v in samples.items()},
                'persisted_stages':{k:summary(v) for k,v in persisted_timings.items()},'input_tokens':sum(c['tokens']['input_tokens'] for c in costs),
                'output_tokens':sum(c['tokens']['output_tokens'] for c in costs),'completed_subjects':completed_subjects,'approved_subjects':approved_subjects,
                'errors':0,'cost_status':'unavailable: synthetic model/usage, no paid API calls','initial_fixture_queue_age_seconds':args.queue_age_seconds,
                'notes':'Loopback provider, SSH delay, queue age and the optional receipt/usage persistence delay are synthetic; no production/TLS/database speed claim. Admission includes lock/query/run creation; run includes persistence.'},indent=2))
        finally:
            if hasattr(ai,'transport'):ai.transport.close()
            server.shutdown();server.server_close();thread.join();engine.dispose()

if __name__ == '__main__':main()
