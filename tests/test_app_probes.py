import json
import socket
import threading
from http.server import BaseHTTPRequestHandler,HTTPServer
import pytest
from app import app_probes,worker
from app.db import Session,Host,Job,Setting
from target import bridge
from test_operations import login_as

def probe(**extra):return {'name':'web','kind':'http','port':8080,'path':'/health','reason':'Site depends on it',**extra}
def health():return {'failed_units':'','collector_active':True,'reboot_required':False}
def result(*rows):return {'results':[{'name':n,'ok':ok,'detail':'x'} for n,ok in rows]}

def test_normalize_is_strict_and_canonical():
    out=app_probes.normalize([probe(),{'name':'db','kind':'tcp','port':5432,'reason':'primary','required':False}])
    assert out[0]['expect_status']==200 and out[0]['timeout']==5 and out[1]=={'name':'db','kind':'tcp','port':5432,'timeout':5,'required':False,'reason':'primary'}
    for bad in ([probe(path='http://evil/')],[probe(path='/a b')],[probe(port=0)],[probe(port='80')],[probe(timeout=11)],[probe(kind='cmd')],
                [probe(command='id')],[probe(reason='')],[probe(name='Bad Name')],[probe(),probe()],[{'name':'t','kind':'tcp','port':1,'path':'/','reason':'r'}],
                [probe(expect_status=99)],[probe(required='yes')],[probe(name=f'p{n}') for n in range(17)],'x'):
        with pytest.raises(ValueError):app_probes.normalize(bad)

def test_request_omits_review_notes():
    assert 'reason' not in app_probes.request(app_probes.normalize([probe()]))['probes'][0]

def test_comparison_separates_new_from_pre_existing_and_distrusts_gaps():
    probes=app_probes.normalize([probe(),probe(name='api',port=9),probe(name='opt',port=10,required=False)])
    r=app_probes.comparison(probes,result(('web',True),('api',False),('opt',True)),result(('web',False),('api',False),('opt',False)))
    assert r['new_probe_failures']==['web'] and r['pre_existing_probe_failures']==['api'] and not r['passed']
    assert app_probes.comparison(probes,result(('web',True),('api',True),('opt',True)),result(('web',True),('api',True),('opt',False)))['passed']
    # missing, duplicated, truthy-but-not-boolean and absent payloads are never healthy
    ok=result(('web',True),('api',True),('opt',True))
    for after in (None,{},result(('web',True)),result(('web',True),('web',True),('api',True)),{'results':[{'name':'web','ok':1},{'name':'api','ok':True}]}):
        assert not app_probes.comparison(probes,ok,after)['passed']
    assert app_probes.comparison(probes,None,result(('web',True),('api',True)))['recovered_probes']==['web','api']

def serve(status):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status);self.end_headers();self.wfile.write(b'secret-body')
        def log_message(self,*args):pass
    server=HTTPServer(('127.0.0.1',0),H);threading.Thread(target=server.serve_forever,daemon=True).start()
    return server

def test_target_adapter_checks_loopback_only_and_hides_bodies():
    server=serve(503);closed=socket.socket();closed.bind(('127.0.0.1',0));dead=closed.getsockname()[1];closed.close()
    try:
        port=server.server_address[1]
        out=bridge.handle({'action':'app-probe','probes':[
            {'name':'up','kind':'tcp','port':port,'timeout':2},
            {'name':'bad','kind':'http','port':port,'path':'/x','expect_status':503,'timeout':2},
            {'name':'wrong','kind':'http','port':port,'path':'/x','expect_status':200,'timeout':2},
            {'name':'down','kind':'tcp','port':dead,'timeout':2}]})
    finally:server.shutdown()
    rows={r['name']:r for r in out['results']}
    assert rows['up']['ok'] and rows['bad']['ok'] and not rows['wrong']['ok'] and rows['wrong']['detail']=='status 503' and not rows['down']['ok']
    assert 'secret' not in json.dumps(out)
    for bad in ([{'name':'a','kind':'tcp','port':1,'timeout':1,'host':'10.0.0.1','extra':1}][:0]+[{'name':'A','kind':'tcp','port':1,'timeout':1}],
                [{'name':'a','kind':'http','port':1,'timeout':1,'path':'http://x/','expect_status':200}],'x',[{'name':'a','kind':'exec','port':1,'timeout':1}]):
        with pytest.raises(ValueError):bridge.handle({'action':'app-probe','probes':bad})

def seed(host_id,probes):
    with Session() as s:
        s.add(Host(id=host_id,name=host_id,address='192.0.2.1',fingerprint='test'))
        s.add(Job(id=host_id+'-job',host_id=host_id,action='patch',payload={'packages':['demo=2'],'_depends_on':[]}))
        if probes:s.add(Setting(key=app_probes.key(host_id),value={'probes':app_probes.normalize(probes)}))
        s.commit()

def run(monkeypatch,host_id,probe_samples):
    calls=[];samples=iter(probe_samples)
    def call(host,request,**kwargs):
        calls.append(request['action'])
        if request['action']=='health':return health()
        if request['action']=='app-probe':
            sample=next(samples)
            if isinstance(sample,Exception):raise sample
            return sample
        return {}
    monkeypatch.setattr(worker.ssh,'call',call);monkeypatch.setattr(worker,'save_inventory',lambda *a:None);monkeypatch.setattr(worker,'validate_patch',lambda *a:None)
    worker.execute(host_id+'-job');return calls

def test_rollout_stops_on_new_probe_failure_and_reports_pre_existing(admin,monkeypatch):
    seed('probe-new',[probe(),probe(name='api',port=9)])
    calls=run(monkeypatch,'probe-new',[result(('web',True),('api',False)),result(('web',False),('api',False))])
    assert calls==['inventory','health','app-probe','patch','inventory','health','app-probe']
    with Session() as s:
        row=s.get(Job,'probe-new-job');assert row.state=='failed'

def test_rollout_passes_with_healthy_probes_and_records_comparison(admin,monkeypatch):
    seed('probe-ok',[probe()])
    run(monkeypatch,'probe-ok',[result(('web',True)),result(('web',True))])
    with Session() as s:
        row=s.get(Job,'probe-ok-job');assert row.state=='complete' and 'application probe comparison' in row.output

def test_unavailable_baseline_blocks_before_any_package_change(admin,monkeypatch):
    seed('probe-base',[probe()])
    calls=run(monkeypatch,'probe-base',[RuntimeError('agent disconnected')])
    assert 'patch' not in calls
    with Session() as s:assert s.get(Job,'probe-base-job').state=='failed'

def test_post_probe_outage_is_unhealthy_not_ignored(admin,monkeypatch):
    seed('probe-gone',[probe()])
    run(monkeypatch,'probe-gone',[result(('web',True)),RuntimeError('timed out')])
    with Session() as s:assert s.get(Job,'probe-gone-job').state in ('failed','recovery_required')

def test_no_probes_keeps_existing_call_sequence(admin,monkeypatch):
    seed('probe-none',[])
    assert run(monkeypatch,'probe-none',[])==['inventory','health','patch','inventory','health']

def test_probe_api_roles_validation_and_audit(admin):
    with Session() as s:s.add(Host(id='api-host',name='api',address='192.0.2.1',fingerprint='test'));s.commit()
    assert admin.put('/api/operations/api-host/probes',json={'probes':[probe(command='id')]}).status_code==400
    assert admin.put('/api/operations/nope/probes',json={'probes':[]}).status_code==404
    assert admin.put('/api/operations/api-host/probes',json={'probes':[probe()]}).status_code==200
    got=admin.get('/api/operations/api-host/probes').json();assert got['probes'][0]['name']=='web' and got['reviewed_by']
    login_as(admin,'op','operator')
    assert admin.put('/api/operations/api-host/probes',json={'probes':[]}).status_code==403
    assert admin.get('/api/operations/api-host/probes').status_code==200
