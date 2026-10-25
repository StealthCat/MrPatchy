#!/usr/bin/python3
"""Root-owned, outbound-network-free collector. No third-party dependencies."""
import base64
import glob
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import time
import sqlite3
import tempfile
from contextlib import contextmanager
import uuid
import re

ROOT = Path('/opt/drpatch')
MANAGED = ['/usr/local/lib/mrpatchy/release.py', '/usr/local/lib/mrpatchy/agent.py', '/usr/local/lib/mrpatchy/bridge.py', '/etc/systemd/system/mrpatchy-agent.service', '/etc/sudoers.d/mrpatchy', '/opt/drpatch/.ssh/authorized_keys']
def digest(path):
    return hash_artifact(path,{})
def read(path):
    return Path(path).read_text(errors='replace')
def inventory():
    files = {}
    for pattern in ['/etc/apt/sources.list', '/etc/apt/sources.list.d/*', '/etc/apt/preferences', '/etc/apt/preferences.d/*']:
        for name in glob.glob(pattern):
            p = Path(name)
            if p.is_file() and p.stat().st_size < 2_000_000: files[name] = read(name)
    keys = {}
    for pattern in ['/etc/apt/trusted.gpg', '/etc/apt/trusted.gpg.d/*', '/etc/apt/keyrings/*', '/usr/share/keyrings/*']:
        for name in glob.glob(pattern):
            p = Path(name)
            if p.is_file() and p.stat().st_size < 2_000_000:
                keys[name] = base64.b64encode(p.read_bytes()).decode()
    # Capture explicitly referenced public-key files outside the conventional directories.
    for content in files.values():
        for name in re.findall(r'/[A-Za-z0-9_./+\-]+\.(?:asc|gpg)',content):
            p=Path(name)
            if '..' not in p.parts and p.is_file() and p.stat().st_size<2_000_000:
                keys[name]=base64.b64encode(p.read_bytes()).decode()
    arch = subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip()
    foreign = subprocess.check_output(['dpkg', '--print-foreign-architectures'], text=True).split()
    return {'os': read('/etc/os-release'), 'architecture': arch, 'foreign_architectures': foreign, 'status': read('/var/lib/dpkg/status'), 'files': files, 'keys': keys, 'machine_id': read('/etc/machine-id').strip(), 'collected': time.time()}
def address(value, ipv6):
    ip, port = value.split(':')
    raw = bytes.fromhex(ip)
    if ipv6: raw = b''.join(raw[i:i+4][::-1] for i in range(0,16,4))
    else: raw = raw[::-1]
    return socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET, raw), int(port,16)
def sockets(base=Path('/proc/net')):
    result = {}; errors = []
    for proto in ['tcp','tcp6','udp','udp6']:
        try:
            for line in read(base/proto).splitlines()[1:]:
                fields = line.split()
                local, lp = address(fields[1], proto.endswith('6'))
                remote, rp = address(fields[2], proto.endswith('6'))
                result[fields[9]] = {'protocol':proto, 'local':local, 'local_port':lp, 'remote':remote, 'remote_port':rp, 'state':fields[3]}
        except FileNotFoundError: pass
        except OSError as e: errors.append({'path':str(base/proto),'error':str(e)})
    return result, errors

def collect(hash_cache):
    errors=[]; processes=[]; namespaces={};deadline=time.monotonic()+10
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            namespace=(p/'ns/net').stat().st_ino
            if namespace not in namespaces:
                net,net_errors=sockets(p/'net');namespaces[namespace]=net;errors.extend(net_errors)
            net=namespaces[namespace]
            exe = os.readlink(p/'exe')
            sha='unavailable';verified=False
            try:
                sha=hash_artifact(p/'exe',hash_cache,deadline=deadline);verified=True
            except (OSError,ValueError) as error:
                errors.append({'pid':p.name,'error':'Executable identity unverified: '+type(error).__name__})
            connections = []
            for fd in (p/'fd').iterdir():
                try:
                    link = os.readlink(fd)
                    if link.startswith('socket:[') and link[8:-1] in net: connections.append(net[link[8:-1]])
                except FileNotFoundError: pass
                except OSError as e: errors.append({'pid':p.name,'error':str(e)})
            uid = next(x.split()[2] for x in read(p/'status').splitlines() if x.startswith('Uid:'))
            processes.append({'pid':int(p.name),'executable':exe,'sha256':sha,'identity_verified':verified,'uid':uid,'network_namespace':namespace,'connections':connections,'provenance':provenance(p,hash_cache,deadline=deadline)})
        except FileNotFoundError: pass # short-lived process / kernel thread
        except (OSError, StopIteration) as e: errors.append({'pid':p.name,'error':str(e)})
    return processes, errors

def atomic(path, value):
    fd,name=tempfile.mkstemp(prefix='.'+path.name,dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o600)
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

@contextmanager
def spool_db():
    db=sqlite3.connect(ROOT/'events.db',timeout=5)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, observed REAL, payload TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER)')
    try:
        with db: yield db
    finally: db.close()

def spool(processes, observed):
    # Bounded durable batches. Overflow is explicit and persists across restarts.
    with spool_db() as db:
        payload=json.dumps({'processes':processes})
        if len(payload.encode())>2_000_000:
            db.execute("INSERT INTO counters VALUES ('dropped',1) ON CONFLICT(name) DO UPDATE SET value=value+1")
            return
        db.execute('INSERT INTO events VALUES (?,?,?)',(str(uuid.uuid4()),observed,payload))
        size=db.execute('SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM events').fetchone()[0]
        while size>48_000_000:
            row=db.execute('SELECT id,length(CAST(payload AS BLOB)) FROM events ORDER BY rowid LIMIT 1').fetchone()
            db.execute('DELETE FROM events WHERE id=?',(row[0],));size-=row[1]
            db.execute("INSERT INTO counters VALUES ('dropped',1) ON CONFLICT(name) DO UPDATE SET value=value+1")

def pending_events():
    with spool_db() as db:
        rows=db.execute('SELECT id,observed,payload FROM events ORDER BY rowid LIMIT 8').fetchall()
        dropped=db.execute("SELECT value FROM counters WHERE name='dropped'").fetchone()
        count=db.execute('SELECT count(*) FROM events').fetchone()[0]
    return {'events':[{'id':r[0],'observed':r[1],**json.loads(r[2])} for r in rows],
            'spool':{'pending':count,'dropped':dropped[0] if dropped else 0}}

def acknowledge(ids):
    if not isinstance(ids,list) or len(ids)>8 or any(not isinstance(x,str) or len(x)!=36 for x in ids):
        raise ValueError('Invalid event acknowledgement')
    with spool_db() as db: db.executemany('DELETE FROM events WHERE id=?',[(x,) for x in ids])
    return {'acknowledged':len(ids)}

def hash_artifact(path,cache,expected=None,deadline=None,metadata=None):
    # Read through one descriptor: pathname replacement cannot change the inode
    # between validation and hashing. O_NONBLOCK prevents FIFO substitution hangs.
    deadline=min(deadline if deadline is not None else float('inf'),time.monotonic()+2)
    if time.monotonic()>deadline:raise ValueError('Hash time budget exceeded')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>128*1024*1024:
            raise ValueError('Not a regular file within the 128 MiB hash limit')
        if expected and (info.st_dev,info.st_ino)!=expected:
            raise ValueError('On-disk inode differs from the running mapping')
        identity=(info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns,info.st_size)
        if identity not in cache:
            checksum=hashlib.sha256();total=0
            for chunk in iter(lambda:stream.read(1024*1024),b''):
                if time.monotonic()>deadline:raise ValueError('Hash time budget exceeded')
                total+=len(chunk)
                if total>128*1024*1024:raise ValueError('File grew beyond the hash limit')
                checksum.update(chunk)
            after=os.fstat(stream.fileno())
            if (after.st_mtime_ns,after.st_ctime_ns,after.st_size)!=(info.st_mtime_ns,info.st_ctime_ns,info.st_size):
                raise ValueError('File changed during hashing')
            cache[identity]=checksum.hexdigest()
        if metadata is not None:
            metadata.update(uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode),size=info.st_size)
        return cache[identity]


def interpreter_family(executable):
    for name,pattern in (('python',r'python(?:[0-9]+(?:\.[0-9]+)*)?'),('bash',r'bash'),
                         ('sh',r'(?:sh|dash)'),('node',r'node(?:js)?'),
                         ('ruby',r'ruby(?:[0-9]+(?:\.[0-9]+)*)?'),('perl',r'perl(?:[0-9]+(?:\.[0-9]+)*)?')):
        if re.fullmatch(pattern,executable):return name
    return None


def script_operand(executable,args):
    """Conservative interpreter parsing. Never export raw options or arguments."""
    family=interpreter_family(executable)
    if family is None:return None
    flags={'python':set('bBdEhiIOPqRsSuvVx'), 'bash':set('abefhkmnptuvxBCEHPT'),
           'sh':set('abefhkmnptuvx'), 'node':set(), 'ruby':set('dw'), 'perl':set('wW')}
    index=1
    while index<len(args):
        arg=os.fsdecode(args[index]);index+=1
        if arg=='--':
            if index<len(args) and args[index] not in (b'',b'-'):return os.fsdecode(args[index])
            break
        if arg=='-' or not arg:break
        if not arg.startswith(('-', '+')):return arg
        if family=='python' and (arg.startswith('-W') or arg.startswith('-X')):
            if len(arg)==2:
                if index>=len(args):break
                index+=1
            continue
        if family in ('bash','sh') and arg in ('--noprofile','--norc'):continue
        if family=='node' and arg in ('--no-warnings','--trace-warnings','--use-strict'):continue
        if arg.startswith('-') and len(arg)>1 and set(arg[1:])<=flags[family]:continue
        # Inline code, modules, preloads and unknown options cannot be attested
        # as one script. Do not mistake an option's value for the entry point.
        raise ValueError('Interpreter entry point or options cannot be verified')
    raise ValueError('Interpreter has no verifiable script entry point')


def provenance(proc,cache,deadline=None):
    """Mapped file identities and script files; never claim memory attestation."""
    result=[];candidates={}
    try:
        for line in read(proc/'maps').splitlines():
            fields=line.split(maxsplit=5)
            if len(fields)!=6 or 'x' not in fields[1] or not fields[5].startswith('/'):
                continue
            name=fields[5]
            major,minor=(int(x,16) for x in fields[3].split(':'))
            expected=(os.makedev(major,minor),int(fields[4]))
            candidates[('library',name,expected)]=(proc/'map_files'/fields[0],expected)
        executable=os.path.basename(os.readlink(proc/'exe'))
        try:
            raw=b''
            if interpreter_family(executable):
                with (proc/'cmdline').open('rb') as stream:raw=stream.read(65537)
            if len(raw)>65536:raise ValueError('Interpreter command line exceeds capture limit')
            operand=script_operand(executable,raw.rstrip(b'\0').split(b'\0'))
            if operand:
                absolute=os.path.normpath(operand if operand.startswith('/') else os.readlink(proc/'cwd')+'/'+operand)
                candidates[('script',absolute,None)]=(proc/'root'/absolute.lstrip('/'),None)
        except (OSError,ValueError) as error:
            result.append({'kind':'script','identity_verified':False,'error':type(error).__name__ if isinstance(error,OSError) else str(error)})
        for (kind,name,_),(path,expected) in sorted(candidates.items())[:128]:
            entry={'kind':kind,'path':name,'identity_verified':False}
            try:
                try:sha=hash_artifact(path,cache,expected,deadline=deadline)
                except (OSError,ValueError):
                    if kind!='library' or name.endswith(' (deleted)'):raise
                    # map_files may require an extra kernel capability. A pathname
                    # fallback is safe only when it still refers to the mapped inode.
                    sha=hash_artifact(proc/'root'/name.lstrip('/'),cache,expected,deadline=deadline)
                entry.update(sha256=sha,identity_verified=True,source='mapped-file' if kind=='library' else 'script-file')
            except (OSError,ValueError) as e:
                entry['error']=type(e).__name__ if isinstance(e,OSError) else str(e)[:300]
            result.append(entry)
        if len(candidates)>128:result.append({'identity_verified':False,'error':'Provenance file limit exceeded','omitted':len(candidates)-128})
    except (OSError,ValueError) as e:result.append({'identity_verified':False,'error':type(e).__name__ if isinstance(e,OSError) else str(e)[:300]})
    return result

def decode_bpf_events(pending,chunk):
    """Frame pipe reads without losing buffered events or splitting UTF-8 characters."""
    lines=(pending+chunk).split(b'\n')
    if any(len(line)>65536 for line in lines):raise ValueError('Oversized bpftrace event')
    return [json.loads(line) for line in lines[:-1] if line],lines[-1]

def ebpf_loop():
    """Optional kernel exec events. BPF attachment failures are visible, not silently ignored."""
    import shutil
    import threading
    program='tracepoint:sched:sched_process_exec { printf("%d\\t%d\\t%s\\n", pid, uid, str(args->filename)); }'
    while True:
        config_path=ROOT/'observability.json'
        config=json.loads(config_path.read_text()) if config_path.exists() else {}
        if not config.get('ebpf'):
            atomic(ROOT/'ebpf-status.json',{'state':'disabled'});time.sleep(5);continue
        if not shutil.which('bpftrace'):
            atomic(ROOT/'ebpf-status.json',{'state':'unavailable','error':'Install bpftrace and kernel BPF support'});time.sleep(30);continue
        try:
            process=subprocess.Popen(['bpftrace','-q','-f','json','-B','line','-e',program],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            def diagnostics():
                for line in process.stderr:
                    atomic(ROOT/'ebpf-diagnostic.json',{'state':'warning','error':line[-2000:].decode(errors='replace'),'at':time.time()})
            threading.Thread(target=diagnostics,daemon=True).start()
            atomic(ROOT/'ebpf-status.json',{'state':'starting'})
            import selectors
            selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
            pending=b'';ended=False
            while not ended:
                current=json.loads(config_path.read_text()) if config_path.exists() else {}
                if not current.get('ebpf'):process.terminate();break
                for key,_ in selector.select(1):
                    chunk=os.read(key.fd,65536)
                    if not chunk:ended=True;break
                    events,pending=decode_bpf_events(pending,chunk)
                    for event in events:
                        if event.get('type')!='printf':continue
                        pid,uid,filename=event['data'].rstrip('\n').split('\t',2)
                        proc=Path('/proc')/str(int(pid));sha=None
                        try:
                            if os.readlink(proc/'exe')==filename:sha=hash_artifact(proc/'exe',{})
                        except (OSError,ValueError):pass
                        # Exited processes remain events even when their executable is no longer readable.
                        spool([{'pid':int(pid),'uid':uid,'executable':filename,'sha256':sha or 'unavailable',
                                'connections':[],'capture':'ebpf','identity_verified':sha is not None}],time.time())
                        atomic(ROOT/'ebpf-status.json',{'state':'active','last_event':time.time()})
            selector.close()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            if process.returncode:atomic(ROOT/'ebpf-status.json',{'state':'unavailable','error':'bpftrace exited '+str(process.returncode)})
        except Exception as e:
            if 'process' in locals() and process.poll() is None:process.kill();process.wait()
            atomic(ROOT/'ebpf-status.json',{'state':'error','error':str(e)[:2000]})
        time.sleep(5)

def main():
    ROOT.mkdir(exist_ok=True)
    import threading
    threading.Thread(target=ebpf_loop,daemon=True).start()
    cache = {}; hashes = {}; metadata = {}; next_hash = 0; next_inventory = 0
    while True:
        started = time.monotonic()
        try:
            if started >= next_hash:
                cache = {}; hashes = {}; metadata = {}
                optional='/etc/systemd/system/mrpatchy-agent.service.d/observability.conf'
                for p in MANAGED+([optional] if Path(optional).exists() else []):
                    try:
                        hashes[p] = digest(p)
                        info=Path(p).stat()
                        metadata[p]={'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}
                    except (OSError,ValueError) as e: hashes[p] = 'ERROR: '+str(e)
                hashed_at = time.time(); next_hash = started+300
            procs, errors = collect(cache)
            spool(procs,time.time())
            atomic(ROOT/'telemetry.json', {'collected':time.time(),'hashed_at':hashed_at,'managed':hashes,'managed_metadata':metadata,'processes':procs,'errors':errors})
            if started >= next_inventory:
                atomic(ROOT/'inventory.json', inventory()); next_inventory = started+300
            (ROOT/'collector-error.json').unlink(missing_ok=True)
        except Exception as e:
            atomic(ROOT/'collector-error.json', {'error':str(e),'at':time.time()})
        time.sleep(max(0.1, 30-(time.monotonic()-started)))
if __name__ == '__main__': main()
