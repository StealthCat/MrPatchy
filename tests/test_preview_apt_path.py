import time
from app import apt
from app.db import Session,Host,Package


def test_apt_preview_simulates_with_the_stored_host_config(admin,tmp_path,monkeypatch):
    monkeypatch.setattr(apt,'DATA',tmp_path)
    with Session() as s:
        s.add(Host(id='preview-host',name='Preview',address='192.0.2.9',fingerprint='SHA256:'+'p'*43,state='online',
                   inventory={'package_manager':'apt'},last_repo=time.time()))
        s.add(Package(id='preview-host:demo',host_id='preview-host',name='demo',installed='1',candidate='2',dpkg_state='install ok installed'))
        s.commit()
    calls=[]
    monkeypatch.setattr(apt,'run',lambda cfg,args:calls.append((cfg,args)) or 'Inst demo [1] (2)')
    response=admin.post('/api/hosts/preview-host/preview',json={'packages':['demo']})
    assert response.status_code==409 and calls==[]
    cfg=tmp_path/'apt'/'preview-host'/'apt.conf';cfg.parent.mkdir(parents=True);cfg.write_text('')
    response=admin.post('/api/hosts/preview-host/preview',json={'packages':['demo']})
    assert response.status_code==200,response.text
    assert response.json()['packages']==['demo=2']
    assert calls==[(cfg,['apt-get','--simulate','--no-remove','--only-upgrade','install','--','demo=2'])]
    assert admin.post('/api/hosts/missing-host/preview',json={'packages':['demo']}).status_code==404
