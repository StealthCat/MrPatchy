"""eBPF diagnostic lifecycle: superseded warnings are history, new failures stay current."""
import json
import os
import sys
import time
import pytest
from app import worker
from app.db import Session,Host
from target import agent,bridge
from test_review_regressions import create_host,telemetry

class StopLoop(Exception):pass

def ingest(snapshot):
    with Session() as s:
        h=s.get(Host,'review-host') or create_host(s);worker.ingest(s,h,{'telemetry':telemetry(),**snapshot})
        return h.state,[item for item in h.integrity if item['path']=='eBPF diagnostics'],h.telemetry

def snapshot(tmp_path,monkeypatch):
    monkeypatch.setattr(bridge,'ROOT',tmp_path)
    # On targets bridge imports the deployed agent module by its bare name.
    monkeypatch.setitem(sys.modules,'agent',agent)
    return {k:v for k,v in bridge.handle({'action':'snapshot'}).items() if k.startswith('ebpf')}

def wait_for(condition,timeout=10):
    deadline=time.monotonic()+timeout
    while not condition():
        if time.monotonic()>deadline:raise AssertionError('condition not reached')
        time.sleep(0.02)

def read(tmp_path,name):
    try:return json.loads((tmp_path/(name+'.json')).read_text())
    except (OSError,ValueError):return {}

def fake_bpftrace(tmp_path,script):
    bin_dir=tmp_path/'bin';bin_dir.mkdir(exist_ok=True)
    path=bin_dir/'bpftrace';path.write_text('#!'+sys.executable+'\nimport sys,time\n'+script);path.chmod(0o755)
    return str(bin_dir)

def run_loop(tmp_path,monkeypatch,on_sleep):
    """Drive the real collector loop; each sleep hands control back to the test."""
    monkeypatch.setattr(agent,'ROOT',tmp_path)
    real_sleep=time.sleep;calls=[]
    def sleep(seconds):
        calls.append(seconds)
        if seconds>=5:on_sleep(len(calls))
        else:real_sleep(seconds)
    monkeypatch.setattr(agent.time,'sleep',sleep)
    with pytest.raises(StopLoop):agent.ebpf_loop()

def configure(tmp_path,enabled):
    (tmp_path/'observability.json').write_text(json.dumps({'ebpf':enabled}))

def test_day_old_warning_with_disabled_collector_is_not_current_attention(admin):
    state,issues,stored=ingest({'ebpf-status':{'state':'disabled'},
        'ebpf-diagnostic':{'state':'warning','error':'old bpf warning','at':time.time()-86400}})
    assert state=='online' and issues==[]
    # The superseded diagnostic is retained as history rather than discarded.
    assert stored['ebpf_diagnostic']['error']=='old bpf warning'

def test_controller_lifecycle_rules(admin):
    now=time.time()
    warning=lambda **extra:{'state':'warning','error':'bpf warning','at':now-60,'instance':'a',**extra}
    # Warning predating the same run's recovery is superseded.
    assert ingest({'ebpf-status':{'state':'active','instance':'a','since':now-30,'last_event':now},
                   'ebpf-diagnostic':warning()})[0]=='online'
    # A warning emitted after recovery is a new genuine failure.
    assert ingest({'ebpf-status':{'state':'active','instance':'a','since':now-90,'last_event':now},
                   'ebpf-diagnostic':warning()})[1]
    # A later collector run supersedes an earlier run's warning, including a legacy untagged one.
    assert ingest({'ebpf-status':{'state':'starting','instance':'b','since':now},'ebpf-diagnostic':warning()})[0]=='online'
    legacy={'state':'warning','error':'bpf warning','at':now-60}
    assert ingest({'ebpf-status':{'state':'starting','instance':'b','since':now},'ebpf-diagnostic':legacy})[0]=='online'
    # The current run's own warning stays visible while it starts.
    assert ingest({'ebpf-status':{'state':'starting','instance':'a','since':now-90},'ebpf-diagnostic':warning()})[1]
    # Producer-retired history never raises attention, whatever the status.
    assert ingest({'ebpf-status':{'state':'active','instance':'a','since':now-90,'last_event':now},
                   'ebpf-diagnostic':warning(state='historical',retired_reason='recovered')})[0]=='online'
    # Older collectors and malformed diagnostics keep failing closed.
    assert ingest({'ebpf-status':{'state':'active','last_event':now},'ebpf-diagnostic':legacy})[1]
    assert ingest({'ebpf-status':{'state':'active','instance':'a','since':now},'ebpf-diagnostic':'unparsed warning'})[1]
    assert ingest({'ebpf-status':{'state':'active','instance':'a','since':now,'last_event':now},
                   'ebpf-diagnostic':warning(at='later')})[1]

def test_failure_then_recovery_then_disable_through_snapshot(admin,tmp_path,monkeypatch):
    """Real collector loop: attach warning -> first event -> late warning -> exit -> disable."""
    path=fake_bpftrace(tmp_path,
        "sys.stderr.write('attach warning\\n');sys.stderr.flush();time.sleep(0.5)\n"
        "print('{\"type\":\"printf\",\"data\":\"%d\\\\t0\\\\t/nonexistent/exe\\\\n\"}' % "+str(os.getpid())+",flush=True)\n"
        # Emit the late warning only after the collector has recorded recovery (processing time varies).
        "import json,pathlib\n"
        "status=pathlib.Path(__file__).parent.parent/'ebpf-status.json'\n"
        "for _ in range(500):\n"
        "    try:\n"
        "        if json.loads(status.read_text()).get('state')=='active':break\n"
        "    except (OSError,ValueError):pass\n"
        "    time.sleep(0.02)\n"
        "else:sys.exit(2)\n"
        "sys.stderr.write('late warning\\n');sys.stderr.flush();time.sleep(0.5);sys.exit(1)\n")
    monkeypatch.setenv('PATH',path+os.pathsep+os.environ['PATH'])
    configure(tmp_path,True)
    seen={}
    def on_sleep(count):
        if count==1:
            # The attach warning was retired by recovery; the later warning is current.
            wait_for(lambda:read(tmp_path,'ebpf-diagnostic').get('error','').startswith('late'))
            seen['run']=snapshot(tmp_path,monkeypatch)
            configure(tmp_path,False)
        else:
            seen['disabled']=snapshot(tmp_path,monkeypatch)
            raise StopLoop
    run_loop(tmp_path,monkeypatch,on_sleep)
    run=seen['run']
    assert run['ebpf-diagnostic']['state']=='warning' and run['ebpf-diagnostic']['instance']==run['ebpf-status']['instance']
    assert ingest(run)[1],'a warning after recovery must remain current'
    events=agent.pending_events()['events']
    assert events and events[0]['processes'][0]['capture']=='ebpf'
    disabled=seen['disabled']
    assert disabled['ebpf-status']['state']=='disabled'
    assert disabled['ebpf-diagnostic']['state']=='historical' and disabled['ebpf-diagnostic']['retired_reason']=='disabled'
    assert disabled['ebpf-diagnostic']['error'].startswith('late warning')
    state,issues,stored=ingest(disabled)
    assert state=='online' and issues==[] and stored['ebpf_diagnostic']['retired_reason']=='disabled'

def test_recovery_retires_the_failed_runs_warning(admin,tmp_path,monkeypatch):
    path=fake_bpftrace(tmp_path,
        "sys.stderr.write('attach warning\\n');sys.stderr.flush();time.sleep(0.5)\n"
        "print('{\"type\":\"printf\",\"data\":\"%d\\\\t0\\\\t/nonexistent/exe\\\\n\"}' % "+str(os.getpid())+",flush=True)\n"
        "time.sleep(30)\n")
    monkeypatch.setenv('PATH',path+os.pathsep+os.environ['PATH'])
    configure(tmp_path,True)
    monkeypatch.setattr(agent,'ROOT',tmp_path)
    seen={}
    def watch():
        wait_for(lambda:read(tmp_path,'ebpf-status').get('state')=='active')
        seen['active']=snapshot(tmp_path,monkeypatch);configure(tmp_path,False)
    import threading
    watcher=threading.Thread(target=watch);watcher.start()
    def on_sleep(count):
        watcher.join();raise StopLoop
    run_loop(tmp_path,monkeypatch,on_sleep)
    active=seen['active']
    assert active['ebpf-diagnostic']['state']=='historical' and active['ebpf-diagnostic']['retired_reason']=='recovered'
    assert active['ebpf-diagnostic']['retired_by']==active['ebpf-status']['instance']
    assert ingest(active)[0]=='online'

def test_restart_retires_previous_process_warning_without_hiding_new_ones(admin,tmp_path,monkeypatch):
    monkeypatch.setattr(agent,'ROOT',tmp_path)
    agent.record_ebpf_diagnostic('previous-run',b'old warning\n')
    configure(tmp_path,False)
    seen={}
    def on_sleep(count):
        seen['restarted']=snapshot(tmp_path,monkeypatch);raise StopLoop
    run_loop(tmp_path,monkeypatch,on_sleep)
    assert seen['restarted']['ebpf-diagnostic']['retired_reason']=='collector-restart'
    assert ingest(seen['restarted'])[0]=='online'
    # A new warning is current again; retiring history is idempotent.
    agent.record_ebpf_diagnostic('next-run',b'new warning\n')
    assert read(tmp_path,'ebpf-diagnostic')['state']=='warning'
    assert ingest({'ebpf-status':{'state':'starting','instance':'next-run','since':time.time()-5},
                   'ebpf-diagnostic':read(tmp_path,'ebpf-diagnostic')})[1]
    agent.retire_ebpf_diagnostic('disabled');retired=read(tmp_path,'ebpf-diagnostic')
    agent.retire_ebpf_diagnostic('collector-restart')
    assert read(tmp_path,'ebpf-diagnostic')==retired

def test_late_warning_after_slow_event_processing_stays_current(admin,tmp_path,monkeypatch):
    """Slow first-event processing must not let the late warning precede recovery."""
    real_sleep=time.sleep;original=agent.ebpf_process
    def slow(*args,**kwargs):
        result=original(*args,**kwargs);real_sleep(1.1);return result
    monkeypatch.setattr(agent,'ebpf_process',slow)
    test_failure_then_recovery_then_disable_through_snapshot(admin,tmp_path,monkeypatch)
