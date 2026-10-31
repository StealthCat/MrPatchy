"""Disposable serial/parallel triage fixture; no external provider or SSH target."""
import argparse
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=int, default=8)
    parser.add_argument('--concurrency', type=int, default=1)
    parser.add_argument('--provider-delay-ms', type=int, default=20)
    args = parser.parse_args()
    if not 2 <= args.runs <= 20: parser.error('--runs must be between 2 and 20')
    if not 1<=args.concurrency<=8:parser.error('--concurrency must be between 1 and 8')
    if not 1<=args.provider_delay_ms<=1000:parser.error('--provider-delay-ms must be between 1 and 1000')
    begin=ContextVar('benchmark_begin');two_stage=ContextVar('benchmark_two_stage',default=False)
    # Set before importing runtime modules; never inherit a deployment database.
    with tempfile.TemporaryDirectory(prefix='mrpatchy-ai-benchmark-') as directory:
        os.environ.update(DATA_DIR=directory, DATABASE_URL='sqlite:///'+directory+'/bench.db', DISABLE_SCHEDULER='1')
        for name in list(os.environ):
            if name.lower().endswith('_proxy'):os.environ.pop(name)
        from app import ai, worker, ai_runs
        from app.db import init, Session, Host, Setting, Behavior, engine
        from app.security import seal
        from app import main as web_runtime
        init()
        requests = []; connections = set(); samples = {k: [] for k in ('run', 'one_stage', 'two_stage', 'provider', 'ssh_evidence', 'admission', 'queue_age', 'receipt_persistence', 'usage_persistence')}

        class Provider(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def setup(self):
                super().setup();self.connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            def log_message(self, *args): pass
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append(payload); connections.add(self.client_address)
                evidence = json.loads(payload['input']); time.sleep(args.provider_delay_ms/1000)
                result = {'risk':'low','explanation':'Synthetic complete assessment','recommended_checks':'None',
                          'requested_checks':['executable'] if evidence['two_stage'] and 'investigation' not in evidence else []}
                body = json.dumps({'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(result)}]}],
                                   'usage':{'input_tokens':100,'output_tokens':20,'output_tokens_details':{'reasoning_tokens':5}}}).encode()
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
                try:return fn(*a,**kw)
                finally:samples[name].append((time.perf_counter()-started)*1000)
            return wrapped
        for name in ('request_started','record_usage'):
            stage='receipt_persistence' if name=='request_started' else 'usage_persistence'
            setattr(ai_runs,name,wrap_stage(stage,getattr(ai_runs,name)))
        def ssh_fixture(*a, **kw):
            started=time.perf_counter(); time.sleep(.01)
            samples['ssh_evidence'].append((time.perf_counter()-started)*1000)
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
            with Session() as s:
                s.add(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model','ai_hourly_limit':100}))
                s.add(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
                first_seen=time.time()-2
                for index in range(args.runs):
                    host_id='fixture-host-'+str(index)
                    s.add(Host(id=host_id,name='Fixture only',address='192.0.2.1',fingerprint=''))
                    s.add(Behavior(id='fixture-'+str(index),host_id=host_id,first_seen=first_seen+index*.0001,
                                   evidence={'executable':'/fixture/artifact','sha256':'a'*64,'identity_verified':True,'two_stage':bool(index%2)}))
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
                rows=list(s.query(Behavior));assert len(rows)==args.runs and all(row.verdict=='low' and not row.approved for row in rows), [(r.verdict,r.analysis) for r in rows]
                assert sum(r.calls for r in s.query(ai_runs.AIRun))==len(requests)==args.runs+args.runs//2
                costs=[ai_runs.cost_summary(r,ai_runs.call_receipts(s,[r.id])[r.id]) for r in s.query(ai_runs.AIRun)]
            persisted_timings={}
            with Session() as s:
                for event in s.query(ai_runs.AIEvent).filter(ai_runs.AIEvent.stage.like('timing_%')):
                    stage=event.stage.removeprefix('timing_')
                    persisted_timings.setdefault(stage,[]).append(float(event.message.split(': ',1)[1].split(' ms;',1)[0]))
            assert all(p['model']=='fixture-model' and p['max_output_tokens']==1600 and p['text']['format']['schema']==ai.SCHEMA for p in requests)
            def summary(values):
                ordered=sorted(values)
                return {'count':len(values),'p50_ms':round(statistics.median(values),3),'p95_ms':round(ordered[math.ceil(.95*len(values))-1],3)}
            print(json.dumps({'fixture_only':True,'execution':'serial' if args.concurrency==1 else 'parallel','concurrency':args.concurrency,'provider_delay_ms':args.provider_delay_ms,'runs':args.runs,'provider_calls':len(requests),
                'connections':len(connections),'elapsed_seconds':round(elapsed,3),'runs_per_second':round(args.runs/elapsed,3),
                'stages':{k:summary(v) for k,v in samples.items()},
                'persisted_stages':{k:summary(v) for k,v in persisted_timings.items()},'input_tokens':sum(c['tokens']['input_tokens'] for c in costs),
                'output_tokens':sum(c['tokens']['output_tokens'] for c in costs),'cost_status':'unavailable: synthetic model/usage, no paid API calls',
                'errors':0,'initial_fixture_queue_age_seconds':2,'notes':'Loopback configurable provider and 10ms SSH fixtures; no production/TLS speed claim. Each subject has an independent server. Admission includes lock/query/run creation; run includes persistence.'},indent=2))
        finally:
            if hasattr(ai,'transport'):ai.transport.close()
            server.shutdown();server.server_close();thread.join();engine.dispose()

if __name__ == '__main__':main()
