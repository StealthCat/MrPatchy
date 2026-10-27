"""Explicit acquisition of preserved bytes; never execute or serve their contents."""
import base64
import binascii
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
import stat
import time
from .db import DATA,audit
from .evidence_vault import EvidenceArchive,ArchiveObservation,EvidenceCopy
from . import ssh

MAX_BYTES=32*1024*1024


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9-]{36}',value):raise ValueError('Invalid evidence archive ID')
    return value


@contextmanager
def directory(archive_id,create=False):
    """Anchor storage in the private data directory, with no symlink traversal."""
    identifier(archive_id)
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in DATA.absolute().parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        info=os.fstat(fd)
        if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o022:raise ValueError('Controller data directory must be owned by the service user and not group/world writable')
        for part in ('evidence-archive',archive_id):
            if create:
                try:os.mkdir(part,0o700,dir_fd=fd);os.fsync(fd)
                except FileExistsError:
                    if part==archive_id:raise ValueError('Existing acquisition files require read-only reconciliation')
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            info=os.fstat(child)
            if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
                os.close(child);raise ValueError('Unsafe controller evidence directory')
            os.close(fd);fd=child
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield fd
    finally:os.close(fd)


def manifest(row):
    return {'version':1,'id':row.id,'host_id':row.host_id,'copy_id':row.copy_id,
            'snapshot':row.snapshot,'fingerprint':row.fingerprint,'actor':row.actor,
            'reason':row.reason,'approved':row.created,'expires':row.expires}


def write_json(fd,name,value):
    out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
    with os.fdopen(out,'wb') as stream:
        stream.write(json.dumps(value,sort_keys=True).encode());stream.flush();os.fsync(stream.fileno())
    os.fsync(fd)


def opened(fd,name,limit):
    source=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    try:
        info=os.fstat(source)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>limit:raise ValueError('Unsafe controller evidence file')
        return source,info
    except Exception:
        os.close(source);raise


def identity(info):
    return tuple(getattr(info,'st_'+k) for k in ('dev','ino','size','uid','gid','mode','mtime_ns','ctime_ns','nlink'))


def verify_open(fd,row):
    receipt,info=opened(fd,'receipt.json',128000)
    try:
        value=json.loads(os.read(receipt,128001))
        if identity(info)!=identity(os.fstat(receipt)) or value!=manifest(row):raise ValueError('Archive receipt changed or mismatched')
    finally:os.close(receipt)
    source,before=opened(fd,'content',MAX_BYTES)
    try:
        digest=hashlib.sha256();total=0;deadline=time.monotonic()+30
        while True:
            chunk=os.read(source,65536)
            if not chunk:break
            total+=len(chunk)
            if total>MAX_BYTES or time.monotonic()>deadline:raise ValueError('Archive verification exceeded its budget')
            digest.update(chunk)
        if identity(before)!=identity(os.fstat(source)) or identity(before)!=identity(os.stat('content',dir_fd=fd,follow_symlinks=False)) or digest.hexdigest()!=row.snapshot['sha256'] or total!=row.snapshot['identity']['size']:raise ValueError('Archive content changed or mismatched')
        return 'verified'
    finally:os.close(source)


def verify(row):
    try:
        with directory(row.id) as fd:
            try:return verify_open(fd,row)
            except FileNotFoundError:return 'incomplete'
    except FileNotFoundError:return 'not_found'
    except (ValueError,OSError,KeyError,TypeError):return 'unavailable'


def observe(s,row,state,job_id='',actor=None):
    s.add(ArchiveObservation(archive_id=row.id,host_id=row.host_id,state=state,job_id=job_id,actor=actor or row.actor))
    audit(s,'evidence archive '+state,row.host_id+' '+row.id)


def execute(s,host,job):
    row=s.get(EvidenceArchive,job.payload['archive_id'])
    if not row or row.host_id!=host.id:raise ValueError('Evidence acquisition not found')
    if job.action=='evidence-archive-status':
        state=verify(row);row.state=state;observe(s,row,state,job.id,job.payload.get('_actor'))
        return {'id':row.id,'state':state,'location':'controller'}
    copy=s.get(EvidenceCopy,row.copy_id)
    if row.state!='queued' or time.time()>=row.expires or host.fingerprint!=row.fingerprint or not copy or copy.host_id!=host.id or copy.state!='preserved' or copy.snapshot!=row.snapshot:
        if row.state=='queued':row.state='rejected'
        observe(s,row,'rejected',job.id);s.commit()
        raise ValueError('Acquisition approval expired or preserved evidence changed')
    # Commit uncertainty before any file creation or remote acquisition. Never
    # automatically reissue an interrupted request or overwrite partial files.
    row.state='uncertain';observe(s,row,'started',job.id);s.commit()
    try:
        with directory(row.id,create=True) as fd:
            write_json(fd,'intent.json',manifest(row))
            response=ssh.call(host,{'action':'evidence-export','id':row.copy_id,'snapshot':row.snapshot,'approved_until':row.expires},timeout=150)
            if time.time()>=row.expires:raise ValueError('Evidence acquisition approval expired during transfer')
            if not isinstance(response,dict) or set(response)!={'id','snapshot','content_base64'} or response['id']!=row.copy_id or response['snapshot']!=row.snapshot:raise ValueError('Evidence export does not bind approved identity')
            encoded=response['content_base64']
            if not isinstance(encoded,str) or len(encoded)>4*((MAX_BYTES+2)//3):raise ValueError('Evidence export exceeds size limit')
            try:content=base64.b64decode(encoded,validate=True)
            except (ValueError,binascii.Error):raise ValueError('Invalid evidence export encoding') from None
            if len(content)!=row.snapshot['identity']['size'] or len(content)>MAX_BYTES or hashlib.sha256(content).hexdigest()!=row.snapshot['sha256']:raise ValueError('Acquired bytes do not match approved evidence')
            out=os.open('partial',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(out,'wb') as stream:
                stream.write(content);stream.flush();os.fsync(stream.fileno())
            os.rename('partial','content',src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd)
            write_json(fd,'receipt.json',manifest(row))
            state=verify_open(fd,row)
        # Reopen the path as a second check after publishing the completed files.
        if verify(row)!=state:raise ValueError('Controller archive path changed')
        row.state=state;observe(s,row,state,job.id)
        return {'id':row.id,'state':state,'location':'controller','sha256':row.snapshot['sha256'],'bytes':len(content)}
    except Exception:
        s.rollback();row=s.get(EvidenceArchive,row.id)
        observe(s,row,'interrupted',job.id);s.commit()
        raise
