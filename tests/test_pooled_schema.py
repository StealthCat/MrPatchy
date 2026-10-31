"""Initialization must see schema changes on previously warmed SQLite connections."""
from concurrent.futures import ThreadPoolExecutor
import threading
import pytest
from sqlalchemy import inspect,select,text
from app.db import engine,Session,Setting,Host,init


@pytest.mark.parametrize('table,column',[('packages','dpkg_state'),('hosts','enabled'),('hosts','deleted_at'),('hosts','lifecycle_revision'),('update_scores','next_at'),('jobs','next_at')])
def test_initialization_after_pooled_schema_change(admin,table,column):
    if engine.dialect.name!='sqlite':pytest.skip('SQLite per-connection schema cache regression')
    with Session() as s:
        s.add(Host(id='pooled-fixture',name='Preserved host',address='192.0.2.1',fingerprint=''));s.commit()
    barrier=threading.Barrier(4)
    def warm(_):
        with Session() as s:
            s.execute(select(Setting)).all();barrier.wait(timeout=10)
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(warm,range(4)))
        with engine.begin() as connection:
            connection.execute(text('ALTER TABLE '+table+' DROP COLUMN '+column))
        init();init()
        with engine.connect() as connection:
            assert 'dpkg_state' in {c['name'] for c in inspect(connection).get_columns('packages')}
            assert 'lifecycle_revision' in {c['name'] for c in inspect(connection).get_columns('hosts')}
            assert 'next_at' in {c['name'] for c in inspect(connection).get_columns('update_scores')}
        hosts=admin.get('/api/hosts')
        assert hosts.status_code==200 and hosts.json()[0]['name']=='Preserved host'
    finally:engine.dispose()
