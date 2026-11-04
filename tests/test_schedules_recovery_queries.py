"""GET /api/schedules loads recovery policies in one query regardless of fleet size."""
from sqlalchemy import event
from app.db import Session, Host, Setting, engine


def _count(client):
    statements=[]
    def hook(conn,cursor,statement,*args):statements.append(statement)
    event.listen(engine,'before_cursor_execute',hook)
    try:result=client.get('/api/schedules')
    finally:event.remove(engine,'before_cursor_execute',hook)
    assert result.status_code==200
    return result.json(),None,statements


def test_policies_use_constant_setting_queries(admin):
    with Session() as s:
        for n in range(30):s.add(Host(id=f'h{n}',name=f'h{n}',address='192.0.2.1',fingerprint=''))
        s.add(Setting(key='recovery:h3',value={'reboot':True}))
        s.add(Setting(key='recovery:h4',value={'rollback':True,'reboot':True}))
        s.commit()
    body,_,statements=_count(admin)
    policies=body['host_policies']
    assert len(policies)==30
    assert policies['h3']=={'reboot':True,'rollback':False}
    assert policies['h4']=={'reboot':True,'rollback':True}
    assert policies['h0']=={'reboot':False,'rollback':False}
    recovery=[q for q in statements if 'settings' in q.lower()]
    assert len(recovery)<=2, recovery
