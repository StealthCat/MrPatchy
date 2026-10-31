import os
import tempfile
os.environ['DATA_DIR']=tempfile.mkdtemp(prefix='mrpatchy-tests-')
os.environ['DATABASE_URL']=os.getenv('TEST_DATABASE_URL','sqlite:///'+os.environ['DATA_DIR']+'/test.db')
os.environ['ADMIN_PASSWORD']='test-password-long-enough'
os.environ['COOKIE_SECURE']='false'
os.environ['DISABLE_SCHEDULER']='1'
import pytest
from fastapi.testclient import TestClient
from app.main import app,login_attempts
from app.db import Base,engine
@pytest.fixture
def client():
    login_attempts.clear()
    Base.metadata.drop_all(engine)
    with TestClient(app) as c: yield c
@pytest.fixture
def admin(client):
    result=client.post('/api/login',json={'password':os.environ['ADMIN_PASSWORD']})
    assert result.status_code==200
    client.headers['X-CSRF-Token']=result.json()['csrf']
    return client
def pytest_collection_modifyitems(config,items):
    """Split whole test files across CI jobs: MRPATCHY_TEST_SHARD=INDEX/TOTAL (1-based).

    Files are balanced greedily by test count; every shard computes the same assignment
    from the same collection, so each file runs in exactly one shard in its original order.
    """
    spec=os.getenv('MRPATCHY_TEST_SHARD','').strip()
    if not spec:return
    try:
        index,total=(int(part) for part in spec.split('/'))
        if not 1<=index<=total:raise ValueError
    except ValueError:raise pytest.UsageError(f'MRPATCHY_TEST_SHARD must be INDEX/TOTAL with 1<=INDEX<=TOTAL, not {spec!r}')
    files={}
    for item in items:files.setdefault(item.nodeid.split('::',1)[0],[]).append(item)
    loads=[0]*total;owner={}
    for name in sorted(files,key=lambda name:(-len(files[name]),name)):
        shard=min(range(total),key=lambda n:(loads[n],n));owner[name]=shard;loads[shard]+=len(files[name])
    keep=[item for item in items if owner[item.nodeid.split('::',1)[0]]==index-1]
    config.hook.pytest_deselected(items=[item for item in items if owner[item.nodeid.split('::',1)[0]]!=index-1])
    items[:]=keep
