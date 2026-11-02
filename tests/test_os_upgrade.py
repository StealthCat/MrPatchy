import time
from types import SimpleNamespace
import pytest
from app import os_upgrade
from app.db import Session,Host

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
        s.add(Host(id='up1',name='Upgradable',address='192.0.2.50',fingerprint='fixture',state='online',last_seen=time.time(),
                   inventory={'os':'ID=debian\nVERSION_ID="12"\n','status':'','files':{},'collected':time.time()}));s.commit()
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
