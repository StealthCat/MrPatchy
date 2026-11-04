import os
import tempfile
os.environ['DATA_DIR']=tempfile.mkdtemp(prefix='mrpatchy-tests-')
os.environ['DATABASE_URL']=os.getenv('TEST_DATABASE_URL','sqlite:///'+os.environ['DATA_DIR']+'/test.db')
os.environ['ADMIN_PASSWORD']='test-password-long-enough'
os.environ['COOKIE_SECURE']='false'
os.environ['DISABLE_SCHEDULER']='1'
import sys
import types
try:
    import imghdr  # noqa: F401
except ModuleNotFoundError:
    # PGPy (test-only signing fixtures) imports imghdr, removed in Python 3.13 (PEP 594).
    # It only uses imghdr.what() to sniff photo user IDs, which the fixtures never contain.
    _imghdr=types.ModuleType('imghdr');_imghdr.what=lambda file,h=None:None
    sys.modules['imghdr']=_imghdr
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
