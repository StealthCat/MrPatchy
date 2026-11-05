import time
from types import SimpleNamespace
import pytest
from app import os_upgrade
from app.db import Session,Host,Setting,engine

NOW=1_800_000_000.0

def host(os_text='ID=debian\nVERSION_ID="12"\n',collected=NOW-60,state='online',enabled=True,deleted_at=0,**extra):
    inv={'os':os_text,'status':'','files':{},'collected':collected,**extra}
    return SimpleNamespace(inventory=inv,state=state,enabled=enabled,deleted_at=deleted_at)

def test_debian_with_adjacent_release_is_available():
    r=os_upgrade.status(host(),NOW)
    assert (r['status'],r['distribution'],r['from_version'],r['to_version'])==('available','debian','12','13')
    assert r['checked']==NOW-60

def test_ubuntu_is_supported_but_not_asserted_as_offered():
    assert os_upgrade.status(host('ID=ubuntu\nVERSION_ID="24.04"\n'),NOW)['status']=='supported'

@pytest.mark.parametrize('os_text',['ID=debian\nVERSION_ID="13"\n','ID=fedora\nVERSION_ID="41"\n','ID=ubuntu\nVERSION_ID="23.10"\n'])
def test_no_adjacent_path_is_unsupported(os_text):
    assert os_upgrade.status(host(os_text),NOW)['status']=='unsupported'

def test_raspberry_pi_marker_blocks_alert():
    r=os_upgrade.status(host(status='Package: raspberrypi-sys-mods\n'),NOW)
    assert r['status']=='unsupported' and 'new-image' in r['message']

@pytest.mark.parametrize('kwargs,expected',[
    ({'collected':NOW-8*86400},'stale'),({'collected':0},'stale'),({'collected':NOW+86400},'stale'),
    ({'state':'offline'},'unknown'),({'state':'enrolling'},'unknown'),
    ({'enabled':False},'unknown'),({'deleted_at':5},'unknown'),({'os_text':''},'unknown')])
def test_stale_offline_disabled_or_missing_inventory_never_alerts(kwargs,expected):
    assert os_upgrade.status(host(**kwargs),NOW)['status']==expected

def test_status_clears_after_upgrade_inventory_refresh():
    h=host();assert os_upgrade.status(h,NOW)['status']=='available'
    h.inventory['os']='ID=debian\nVERSION_ID="13"\n';assert os_upgrade.status(h,NOW)['status']=='unsupported'

def test_api_exposes_one_status_to_every_role(admin,client):
    with Session() as s:
        h=Host(id='up1',name='Upgradable',address='192.0.2.50',fingerprint='fixture',state='online',last_seen=time.time(),
                   inventory={'os':'ID=debian\nVERSION_ID="12"\n','status':'','files':{},'collected':time.time()})
        s.add(h);os_upgrade.store(s,h,h.inventory);s.commit()
    row=[h for h in client.get('/api/hosts').json() if h['id']=='up1'][0]
    assert row['os_upgrade']['status']=='available' and row['os_upgrade']['to_version']=='13'
    summary=client.get('/api/hosts/up1/summary').json()['host']
    assert summary['os_upgrade']==row['os_upgrade']

def test_ui_uses_one_badge_helper_in_every_server_reference():
    from pathlib import Path
    root=Path(__file__).resolve().parent.parent/'app/static'
    assert "status==='available'" in (root/'ui.js').read_text()
    assert 'PatchyUI.upgradeBadge(h)' in (root/'app.js').read_text()
    server=(root/'server.js').read_text()
    assert 'PatchyUI.upgradeBadge(h)' in server and 'upgradeNotice' in server

@pytest.mark.parametrize('bad',[{'collected':'not-a-timestamp'},{'collected':float('nan')},{'files':None},{'files':[]},{'files':{'a':1}},{'os':{'ID':'debian','VERSION_ID':'12'}},{'status':None}])
def test_malformed_inventory_is_unknown_not_an_error(bad):
    inv={'os':'ID=debian\nVERSION_ID="12"\n','status':'','files':{},'collected':NOW-60,**bad}
    h=SimpleNamespace(inventory=inv,state='online',enabled=True,deleted_at=0)
    assert os_upgrade.status(h,NOW)['status']=='unknown'

def test_malformed_inventory_keeps_fleet_api_working(admin,client):
    from app import worker
    now=time.time()
    with Session() as s:
        for hid,bad in (('bad1',{'collected':'x'}),('bad2',{'files':None}),('bad3',{'os':{'ID':'debian'}}),('ok1',{})):
            s.add(Host(id=hid,name=hid,address='192.0.2.60',fingerprint='fixture',state='online',last_seen=now))
            s.flush();h=s.get(Host,hid)
            worker.save_inventory(s,h,{'os':'ID=debian\nVERSION_ID="12"\n','status':'','files':{},'collected':now,**bad})
        s.commit()
    r=client.get('/api/hosts');assert r.status_code==200
    rows={h['id']:h for h in r.json()}
    assert rows['ok1']['os_upgrade']['status']=='available'
    assert all(rows[i]['os_upgrade']['status']=='unknown' for i in ('bad1','bad2','bad3'))
    assert client.get('/api/hosts/bad1/summary').status_code==200


def test_fleet_status_uses_one_projection_without_loading_private_inventory(admin):
    from sqlalchemy import event,inspect
    with Session() as s:
        for index in range(20):
            h=Host(id='bounded-'+str(index),name='Bounded',address='192.0.2.1',fingerprint='test',state='online',
                inventory={'os':'ID=debian\nVERSION_ID="12"\n','status':'','files':{},'collected':time.time(),
                           'unused':'x'*100000},telemetry={'unused':'y'*100000},baseline={'unused':'z'*100000})
            s.add(h);os_upgrade.store(s,h,h.inventory)
        s.commit()
    queries=[];loaded=[]
    def sql(conn,cursor,statement,parameters,context,many):
        if 'FROM hosts' in statement:queries.append(statement)
    def load(host,context):
        loaded.append(host.id)
        assert {'inventory','telemetry','baseline'}<=inspect(host).unloaded
    event.listen(engine,'before_cursor_execute',sql);event.listen(Host,'load',load)
    try:response=admin.get('/api/hosts')
    finally:
        event.remove(engine,'before_cursor_execute',sql);event.remove(Host,'load',load)
    assert response.status_code==200 and len(loaded)==20 and len(queries)==1
    assert all(item['os_upgrade']['status']=='available' for item in response.json())
    assert all('unused' not in item for item in response.json())


def test_startup_backfill_is_idempotent_and_does_not_need_inventory_on_list(admin):
    with Session() as s:
        s.add(Host(id='legacy',name='Legacy',address='192.0.2.1',fingerprint='test',state='online',
            inventory={'os':'ID=debian\nVERSION_ID="12"\n','status':'','files':{},'collected':time.time()}))
        s.commit()
    assert admin.get('/api/hosts').json()[0]['os_upgrade']['status']=='unknown'
    with engine.begin() as connection:
        os_upgrade.backfill(connection);os_upgrade.backfill(connection)
    assert admin.get('/api/hosts').json()[0]['os_upgrade']['status']=='available'
    with Session() as s:assert s.get(Setting,os_upgrade.PREFIX+'legacy')


def test_saved_status_rechecks_freshness_and_lifecycle_without_inventory():
    saved=os_upgrade.snapshot(host().inventory)
    class NoInventory:
        state='online';enabled=True;deleted_at=0
        @property
        def inventory(self):raise AssertionError('Private inventory must not load')
    h=NoInventory()
    assert os_upgrade.status(h,NOW,saved=saved)['status']=='available'
    assert os_upgrade.status(h,NOW+8*86400,saved=saved)['status']=='stale'
    h.enabled=False
    assert os_upgrade.status(h,NOW,saved=saved)['status']=='unknown'


@pytest.mark.parametrize('collected',[10**400,-10**400,2**53+1,float('inf'),float('-inf'),True])
def test_unbounded_timestamps_are_malformed_not_overflow(collected):
    inv={'os':'ID=debian\nVERSION_ID="12"\n','status':'','files':{},'collected':collected}
    snap=os_upgrade.snapshot(inv)
    assert snap['valid'] is False and snap['collected']==0
    h=SimpleNamespace(inventory=inv,state='online',enabled=True,deleted_at=0)
    assert os_upgrade.status(h,NOW)['status']=='unknown'
    saved={'version':1,'has_os':True,'valid':True,'collected':collected,
           'detected':{'status':'available','message':'m','distribution':'debian','from_version':'12','to_version':'13'}}
    r=os_upgrade.status(h,NOW,saved=saved)
    assert r['status']=='unknown' and 'malformed' in r['message']


def test_valid_integer_and_float_timestamps_are_preserved():
    for collected in (int(NOW-60),NOW-60.5):
        assert os_upgrade.snapshot(host(collected=collected).inventory)['collected']==collected
        assert os_upgrade.status(host(collected=collected),NOW)['checked']==collected


def test_malformed_legacy_inventory_survives_backfill_and_summary(admin):
    if engine.dialect.name!='sqlite':
        pytest.skip('only SQLite JSON can hold integers beyond the float range')
    with Session() as s:
        s.add(Host(id='huge',name='Huge',address='192.0.2.2',fingerprint='test',state='online',last_seen=time.time(),
            inventory={'os':'ID=debian\nVERSION_ID=12','collected':10**400}))
        s.commit()
    with engine.begin() as connection:
        os_upgrade.backfill(connection)
    with Session() as s:
        saved=s.get(Setting,os_upgrade.PREFIX+'huge').value
    assert saved['valid'] is False and saved['collected']==0
    summary=admin.get('/api/hosts/huge/summary')
    assert summary.status_code==200 and summary.json()['host']['os_upgrade']['status']=='unknown'
    assert next(h for h in admin.get('/api/hosts').json() if h['id']=='huge')['os_upgrade']['status']=='unknown'
    with Session() as s:
        s.get(Setting,os_upgrade.PREFIX+'huge').value={**saved,'valid':True,'collected':10**400}
        s.commit()
    assert next(h for h in admin.get('/api/hosts').json() if h['id']=='huge')['os_upgrade']['status']=='unknown'
