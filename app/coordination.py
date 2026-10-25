"""Cross-process locks. Shared local filesystem for SQLite; MySQL named locks across hosts."""
import fcntl
import hashlib
import threading
from sqlalchemy import create_engine,text
from sqlalchemy.pool import NullPool
from .db import DATA,URL
lock_engine=create_engine(URL,poolclass=NullPool)
class Lock:
    def __init__(self,name):
        self.name='mrpatchy:'+hashlib.sha256((str(lock_engine.url.database)+':'+name).encode()).hexdigest()[:48]
        self.local=threading.Lock();self.resource=None
    def acquire(self,blocking=True):
        if not self.local.acquire(blocking):return False
        resource=None
        try:
            if lock_engine.dialect.name in ('mysql','mariadb'):
                connection=resource=lock_engine.connect()
                if connection.execute(text('SELECT GET_LOCK(:name,:wait)'),{'name':self.name,'wait':3600 if blocking else 0}).scalar()!=1:
                    connection.close();self.local.release();return False
                self.resource=connection
            else:
                directory=DATA/'locks';directory.mkdir(exist_ok=True)
                stream=resource=open(directory/self.name.replace(':','-'),'a')
                try:fcntl.flock(stream,fcntl.LOCK_EX|(0 if blocking else fcntl.LOCK_NB))
                except BlockingIOError:stream.close();self.local.release();return False
                self.resource=stream
            return True
        except Exception:
            try:
                if resource is not None:resource.close()
            finally:self.local.release()
            raise
    def owned(self):
        if self.resource is None:return False
        if lock_engine.dialect.name in ('mysql','mariadb'):
            return self.resource.execute(text('SELECT IS_USED_LOCK(:name)=CONNECTION_ID()'),{'name':self.name}).scalar()==1
        return True
    def release(self):
        try:
            if lock_engine.dialect.name in ('mysql','mariadb'):
                try:self.resource.execute(text('SELECT RELEASE_LOCK(:name)'),{'name':self.name})
                finally:self.resource.close()
            else:
                try:fcntl.flock(self.resource,fcntl.LOCK_UN)
                finally:self.resource.close()
        finally:self.resource=None;self.local.release()
    def __enter__(self):
        if not self.acquire():raise RuntimeError('Could not acquire worker lock')
        return self
    def __exit__(self,*args):self.release()
