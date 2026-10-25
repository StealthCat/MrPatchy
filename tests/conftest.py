import os
import tempfile
os.environ['DATA_DIR']=tempfile.mkdtemp(prefix='mrpatchy-tests-')
os.environ['ADMIN_PASSWORD']='test-password-long-enough'
os.environ['COOKIE_SECURE']='false'
os.environ['DISABLE_SCHEDULER']='1'
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import Base,engine
@pytest.fixture
def client():
    Base.metadata.drop_all(engine)
    with TestClient(app) as c: yield c
@pytest.fixture
def admin(client):
    result=client.post('/api/login',json={'password':os.environ['ADMIN_PASSWORD']})
    assert result.status_code==200
    client.headers['X-CSRF-Token']=result.json()['csrf']
    return client
