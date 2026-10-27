#!/usr/bin/python3
"""Root-owned, outbound-network-free collector. RPM inventory uses the system RPM bindings."""
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
MANAGED = ['/usr/local/lib/mrpatchy/rpm_support.py', '/usr/local/lib/mrpatchy/release.py', '/usr/local/lib/mrpatchy/agent.py', '/usr/local/lib/mrpatchy/bridge.py', '/etc/systemd/system/mrpatchy-agent.service', '/etc/sudoers.d/mrpatchy', '/opt/drpatch/.ssh/authorized_keys']
def digest(path):
    return hash_artifact(path,{})
def read(path):
    return Path(path).read_text(errors='replace')
def inventory():
    if not Path('/var/lib/dpkg/status').exists():
        import sys
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        try:from rpm_support import local_inventory
        except ImportError:from target.rpm_support import local_inventory
        return local_inventory()
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

SCAN_EXCLUDED = ('/proc','/sys','/dev','/run','/var/lib/mrpatchy-quarantine')
SCAN_MAX_ENTRIES = 10000
SCAN_MAX_DEPTH = 32
SIGNATURE_MAX_AGE = 7*86400


def signature_status(version, now):
    """Assess the advertised daily database build time, not vendor authenticity."""
    from datetime import datetime, timezone
    result={'state':'unknown','max_age_seconds':SIGNATURE_MAX_AGE,'checked_at':now}
    match=re.fullmatch(r'ClamAV ([^/\n]+)/([0-9]+)/[A-Za-z]{3} ([A-Za-z]{3}) +([0-9]{1,2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4})',version.strip())
    if not match:return result
    engine,revision,month,day,hour,minute,second,year=match.groups()
    try:
        month_number=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].index(month)+1
        built=datetime(int(year),month_number,int(day),int(hour),int(minute),int(second),tzinfo=timezone.utc).timestamp()
    except (ValueError,OverflowError):return result
    age=now-built
    result.update(database_version=revision,built_at=built,age_seconds=age,
                  state='future' if age < -300 else 'stale' if age>SIGNATURE_MAX_AGE else 'recent')
    return result


def scan_excluded(path):
    return any(str(path)==item or str(path).startswith(item+'/') for item in SCAN_EXCLUDED)


@contextmanager
def scan_root(path):
    """Open every ancestor with O_NOFOLLOW; never resolve a parent symlink."""
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        yield fd
    finally:os.close(fd)


def scan_entries(fd,path,report,deadline,gap,depth=0):
    # Keep directory handles while descending, with an explicit depth/entry budget.
    if depth>SCAN_MAX_DEPTH:
        gap(path,'Directory depth limit reached');return
    try:
        with os.scandir(fd) as entries:
            for entry in entries:
                report['entries_examined']+=1
                if report['entries_examined']>SCAN_MAX_ENTRIES or time.monotonic()>deadline:
                    raise TimeoutError('Traversal budget exhausted')
                child=path/entry.name
                if scan_excluded(child):
                    gap(child,'Directory excluded from scan');continue
                try:
                    info=entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child_fd=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                        try:
                            opened=os.fstat(child_fd)
                            if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):
                                gap(child,'Directory changed during traversal');continue
                            yield from scan_entries(child_fd,child,report,deadline,gap,depth+1)
                        finally:os.close(child_fd)
                    else:yield fd,path,entry.name
                except TimeoutError:raise
                except OSError:gap(child,'Entry inaccessible or changed during traversal')
    except TimeoutError:raise
    except OSError:gap(path,'Directory inaccessible')


def validate_yara_rules(rules):
    if not isinstance(rules,dict) or not isinstance(rules.get('source'),str):raise ValueError('Invalid YARA source packet')
    source=rules['source']
    if not 1<=len(source.encode())<=128*1024 or '\x00' in source or re.search(r'\b(?:include|import)\b',source,re.I):raise ValueError('YARA source must be bounded text without include/import words')
    if hashlib.sha256(source.encode()).hexdigest()!=rules.get('sha256'):raise ValueError('YARA source digest mismatch')
    issued=rules.get('issued');expires=rules.get('expires');now=time.time()
    if type(issued) not in (int,float) or type(expires) not in (int,float) or not (0<=issued<=now+300 and now<expires<=issued+30*86400):raise ValueError('YARA rule validity expired, future dated or exceeds 30 days')


def security_scan(paths,yara_rules=None):
    if yara_rules is not None:validate_yara_rules(yara_rules)
    """Bounded read-only scanning, anchored to open directories and file handles."""
    import shutil
    from contextlib import ExitStack
    if not isinstance(paths,list) or not 1<=len(paths)<=16:
        raise ValueError('Select 1–16 absolute directories')
    roots=[]
    for value in paths:
        if not isinstance(value,str) or not value.startswith('/') or value.startswith('//') or '..' in Path(value).parts or len(value)>4096:
            raise ValueError('Invalid scan directory')
        path=Path(value)
        if scan_excluded(path):raise ValueError('Scan root is in an excluded filesystem or quarantine directory')
        roots.append(path)
    report={'version':2,'started':time.time(),'roots':paths,'engine':'YARA' if yara_rules is not None else 'ClamAV','available':False,
            'scanned':0,'examined':0,'entries_examined':0,'skipped':0,'findings':[],'gaps':[], 'state':'incomplete',
            'signatures':{'state':'unknown','max_age_seconds':SIGNATURE_MAX_AGE}}
    if yara_rules is not None:report['signatures']={'state':'recent','database_version':yara_rules['sha256'],'built_at':yara_rules['issued'],'expires':yara_rules['expires'],'basis':'signed_rule_validity_not_vendor_freshness'}
    def gap(path,reason):
        report['skipped']+=1
        if len(report['gaps'])<100:report['gaps'].append(str(path)+': '+reason)
    version_text=None
    def finish():
        if version_text is not None:
            try:
                final_version=subprocess.run([engine,'--version'],capture_output=True,text=True,timeout=15,env={**os.environ,'LC_ALL':'C','TZ':'UTC'})
                if final_version.returncode:raise ValueError('Engine version check failed')
                if final_version.stdout[:500]!=version_text:
                    report['signatures']['state']='changed'
                    report['engine_version_after']=final_version.stdout[:500]
                    report['gaps'].append('Scanner/database version changed during scan; per-file signature provenance is uncertain')
            except (OSError,ValueError,subprocess.TimeoutExpired):
                report['signatures']['state']='unknown'
                report['gaps'].append('Final scanner health check failed')
        if yara_rules is not None:
            try:validate_yara_rules(yara_rules)
            except ValueError:
                report['signatures']['state']='stale'
                report['gaps'].append('YARA rule validity expired during scanning')
        report['finished']=time.time()
        if not report['gaps']:
            report['state']='completed_with_findings' if report['findings'] else 'no_detections'
        return report
    with ExitStack() as stack:
        handles=[]
        try:
            for root in roots:
                fd=stack.enter_context(scan_root(root));handles.append((root,fd))
        except OSError as error:raise ValueError('Scan roots and ancestors must be accessible real directories, without symlinks') from error
        rules_file=None
        if yara_rules is not None:
            rules_file=stack.enter_context(tempfile.TemporaryFile())
            rules_file.write(yara_rules['source'].encode());rules_file.flush()
        engine=shutil.which('yara' if yara_rules is not None else 'clamscan');report['available']=bool(engine)
        if not engine:
            report['gaps'].append(report['engine']+' is not installed; no malware scanning performed');return finish()
        try:
            version=subprocess.run([engine,'--version'],capture_output=True,text=True,timeout=15,env={**os.environ,'LC_ALL':'C','TZ':'UTC'})
            if version.returncode:raise ValueError('Engine version check failed')
            version_text=version.stdout[:500]
            if yara_rules is not None:
                try:from bridge import bounded
                except ImportError:from target.bridge import bounded
                empty=stack.enter_context(tempfile.TemporaryFile())
                os.lseek(rules_file.fileno(),0,0)
                _,errors,_=bounded([engine,'-a','10',f'/proc/self/fd/{rules_file.fileno()}',f'/proc/self/fd/{empty.fileno()}'],pass_fds=(rules_file.fileno(),empty.fileno()),timeout=15,limit=64000,return_status=True,memory_limit=512*1024*1024)
                if errors:raise ValueError('YARA rule compilation produced diagnostics')
            report['engine_version']=version_text
            report['signatures']=({'state':'recent','database_version':yara_rules['sha256'],'built_at':yara_rules['issued'],'expires':yara_rules['expires'],'basis':'signed_rule_validity_not_vendor_freshness'} if yara_rules is not None else signature_status(version.stdout[:500],time.time()))
            if report['signatures']['state']!='recent':
                report['gaps'].append('Signature freshness is '+report['signatures']['state']+'; update databases or verify scanner configuration and system clock')
        except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.TimeoutExpired):
            report['gaps'].append('Scanner health check failed');return finish()
        deadline=time.monotonic()+240
        def entries():
            for root,fd in handles:
                yield from scan_entries(fd,root,report,deadline,gap)
        iterator=entries()
        try:
            for directory_fd,directory,name in iterator:
                path=directory/name;report['examined']+=1
                if report['examined']>2000 or time.monotonic()>deadline:
                    gap(path,'Scan budget exhausted; remaining files not examined');return finish()
                fd=None
                try:
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
                    before=os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode) or before.st_size>32*1024*1024:
                        gap(path,'Not a regular file within the 32 MiB limit');continue
                    digest=hashlib.sha256();read_bytes=0
                    while True:
                        chunk=os.read(fd,1024*1024)
                        if not chunk:break
                        read_bytes+=len(chunk)
                        if read_bytes>32*1024*1024:raise ValueError('File grew beyond scan limit')
                        digest.update(chunk)
                        if time.monotonic()>deadline:raise TimeoutError()
                    os.lseek(fd,0,0)
                    if yara_rules is not None:
                        try:from bridge import bounded
                        except ImportError:from target.bridge import bounded
                        os.lseek(rules_file.fileno(),0,0)
                        output,errors,status=bounded([engine,'-a','10',f'/proc/self/fd/{rules_file.fileno()}',f'/proc/self/fd/{fd}'],pass_fds=(rules_file.fileno(),fd),timeout=min(15,max(1,deadline-time.monotonic())),limit=64000,return_status=True,memory_limit=512*1024*1024,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
                        if errors:raise ValueError('YARA diagnostics prevented complete inspection')
                        identifiers=[]
                        for line in output.splitlines():
                            match=re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]{0,127}) '+re.escape(f'/proc/self/fd/{fd}'),line)
                            if not match or len(identifiers)>=100:raise ValueError('Unexpected or excessive YARA matches')
                            identifiers.append(match[1])
                        from types import SimpleNamespace
                        result=SimpleNamespace(returncode=1 if identifiers else 0,stdout='YARA rules: '+', '.join(identifiers))
                    else:
                        result=subprocess.run([engine,'--stdout','--no-summary','--alert-exceeds-max=yes','--alert-encrypted=yes','--follow-file-symlinks=2','--max-filesize=32M','--max-scansize=64M','--max-recursion=16',f'/proc/self/fd/{fd}'],pass_fds=(fd,),capture_output=True,text=True,timeout=min(30,max(1,deadline-time.monotonic())))
                    after=os.fstat(fd)
                    with scan_root(directory) as current_dir:
                        current_info=os.fstat(current_dir);original_info=os.fstat(directory_fd)
                        if (current_info.st_dev,current_info.st_ino)!=(original_info.st_dev,original_info.st_ino):
                            gap(path,'Parent directory changed during scanning');continue
                    named=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
                    if (named.st_dev,named.st_ino)!=(before.st_dev,before.st_ino):
                        gap(path,'File path replaced during scanning');continue
                    if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                        gap(path,'File changed during scanning');continue
                    if result.returncode not in (0,1):gap(path,'Scanner failed');continue
                    if 'Heuristics.Limits.Exceeded' in result.stdout or 'Heuristics.Encrypted' in result.stdout:gap(path,'Scanner inspection limit or encrypted content prevented complete inspection')
                    report['scanned']+=1
                    if result.returncode==1:
                        report['findings'].append({'path':str(path),'sha256':digest.hexdigest(),'device':before.st_dev,'inode':before.st_ino,'size':before.st_size,'uid':before.st_uid,'mode':stat.S_IMODE(before.st_mode),'evidence':result.stdout[-2000:],**({'rule_ids':identifiers} if yara_rules is not None else {})})
                        if len(report['findings'])>=100:
                            gap(path,'Finding limit reached; scan stopped');return finish()

                except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.TimeoutExpired) as error:gap(path,type(error).__name__)
                finally:
                    if fd is not None:os.close(fd)
        except TimeoutError:gap('Traversal','Scan budget exhausted; remaining entries not examined')
        finally:iterator.close()
    return finish()


# Explicit scope only: this inventory is not a complete enumeration of persistence.
PERSISTENCE_ROOTS = ('/etc/systemd/system','/etc/cron.d','/etc/cron.daily',
                     '/etc/cron.hourly','/etc/cron.weekly','/etc/cron.monthly',
                     '/var/spool/cron','/etc/init.d','/etc/profile.d')
PERSISTENCE_FILES = ('/etc/crontab','/etc/rc.local','/etc/ld.so.preload')
PACKAGE_ID = r'[A-Za-z0-9][A-Za-z0-9+_.:-]{0,199}'


def validate_custom_paths(paths):
    if not isinstance(paths,list) or len(paths)>16:raise ValueError('Select up to 16 custom file or directory paths')
    selected=list(PERSISTENCE_ROOTS)+list(PERSISTENCE_FILES)
    for value in paths:
        if not isinstance(value,str) or not 1<len(value)<=4096 or not value.startswith('/') or value.startswith('//') or str(Path(value))!=value or '..' in Path(value).parts or any(ord(c)<32 for c in value):raise ValueError('Custom paths must be canonical absolute paths without control characters')
        if scan_excluded(Path(value)):raise ValueError('Custom path is in an excluded filesystem or quarantine directory')
        if any(value==root or value.startswith(root+'/') or root.startswith(value+'/') for root in selected):raise ValueError('Custom paths must not overlap each other or built-in startup scope')
        selected.append(value)
    return selected


def validate_inspection(packages,persistence,custom_paths=None):
    paths=[] if custom_paths is None else custom_paths
    validate_custom_paths(paths)
    if paths and persistence is not True:raise ValueError('Custom paths require the integrity inventory option')
    if not isinstance(packages,list) or len(packages)>16 or type(persistence) is not bool:
        raise ValueError('Select up to 16 packages and a persistence inventory option')
    if any(not isinstance(name,str) or not re.fullmatch(PACKAGE_ID,name) for name in packages):
        raise ValueError('Invalid package identifier; wildcards and options are not allowed')
    if len(set(packages))!=len(packages):raise ValueError('Duplicate package identifiers')
    if not packages and not persistence:raise ValueError('Select packages or persistence inventory')


def parse_package_verification(output):
    findings=[];gaps=[]
    for line in output.splitlines():
        if not line.strip():continue
        match=re.fullmatch(r'(missing|[SM5DLUGTP?.]{9})\s+(?:([c dglrmasn])\s+)?(/.*)',line)
        if not match:
            gaps.append('Unrecognized package verification output');continue
        flags,kind,path=match.groups()
        if len(path)>4096 or '..' in Path(path).parts or any(ord(c)<32 for c in path):
            gaps.append('Unrepresentable verification path');continue
        findings.append({'path':path,'checks':flags,'configuration_file':kind=='c',
                         'status':'missing' if flags=='missing' else 'metadata_or_content_changed'})
        if len(findings)>=200:
            gaps.append('Verification finding limit reached');break
    return findings,gaps[:20]


def persistence_inventory(deadline,custom_paths=None):
    paths=[] if custom_paths is None else custom_paths
    scope=validate_custom_paths(paths)
    report={'scope':scope,'entries':[],'entries_examined':0,
            'skipped':0,'gaps':[],'missing_roots':[],'state':'incomplete'}
    def gap(path,reason):
        report['skipped']+=1
        if len(report['gaps'])<50:report['gaps'].append(str(path)+': '+reason)
    def capture(directory_fd,directory,name):
        path=directory/name;fd=None
        if len(report['entries'])>=256 or time.monotonic()>deadline:
            raise TimeoutError('Persistence inventory budget exhausted')
        try:
            before=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
            row={'path':str(path),'uid':before.st_uid,'gid':before.st_gid,
                 'mode':stat.S_IMODE(before.st_mode),'size':before.st_size,'mtime_ns':before.st_mtime_ns}
            if stat.S_ISLNK(before.st_mode):
                row.update(kind='symlink',target=os.readlink(name,dir_fd=directory_fd)[:4096])
            elif stat.S_ISREG(before.st_mode):
                if before.st_size>1024*1024:gap(path,'File exceeds 1 MiB inventory limit');return
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
                opened=os.fstat(fd)
                if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):raise ValueError('File replaced')
                digest=hashlib.sha256();total=0
                while True:
                    chunk=os.read(fd,65536)
                    if not chunk:break
                    total+=len(chunk)
                    if total>1024*1024 or time.monotonic()>deadline:raise TimeoutError('Hash budget exhausted')
                    digest.update(chunk)
                row.update(kind='regular',sha256=digest.hexdigest())
                after=os.fstat(fd)
                if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                    raise ValueError('File changed')
            else:gap(path,'Non-regular entry excluded');return
            after=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
            if (before.st_dev,before.st_ino,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_ctime_ns):
                raise ValueError('Entry changed')
            with scan_root(directory) as current:
                now=os.fstat(current);old=os.fstat(directory_fd)
                if (now.st_dev,now.st_ino)!=(old.st_dev,old.st_ino):raise ValueError('Directory changed')
            report['entries'].append(row)
        except (OSError,ValueError) as error:gap(path,type(error).__name__)
        finally:
            if fd is not None:os.close(fd)
    try:
        for value in PERSISTENCE_ROOTS:
            path=Path(value)
            try:
                with scan_root(path) as fd:
                    iterator=scan_entries(fd,path,report,deadline,gap)
                    try:
                        for directory_fd,directory,name in iterator:capture(directory_fd,directory,name)
                    finally:iterator.close()
            except FileNotFoundError:report['missing_roots'].append(value)
            except OSError:gap(path,'Persistence root inaccessible or symlinked')
        for value in PERSISTENCE_FILES:
            path=Path(value)
            try:
                with scan_root(path.parent) as fd:
                    try:os.stat(path.name,dir_fd=fd,follow_symlinks=False)
                    except FileNotFoundError:report['missing_roots'].append(value);continue
                    capture(fd,path.parent,path.name)
            except FileNotFoundError:report['missing_roots'].append(value)
            except OSError:gap(path,'Persistence file parent inaccessible')
        for value in paths:
            path=Path(value);selected=False
            try:
                with scan_root(path.parent) as parent:
                    try:info=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                    except FileNotFoundError:report['missing_roots'].append(value);continue
                    selected=True
                    if stat.S_ISDIR(info.st_mode):
                        with scan_root(path) as root:
                            opened=os.fstat(root)
                            if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):raise ValueError('Custom directory replaced before traversal')
                            iterator=scan_entries(root,path,report,deadline,gap)
                            try:
                                for directory_fd,directory,name in iterator:capture(directory_fd,directory,name)
                            finally:iterator.close()
                            with scan_root(path) as current:
                                after=os.fstat(current)
                                if (after.st_dev,after.st_ino)!=(opened.st_dev,opened.st_ino):raise ValueError('Custom directory replaced during traversal')
                    else:capture(parent,path.parent,path.name)
            except FileNotFoundError:
                if selected:gap(path,'Custom directory disappeared during traversal')
                else:report['missing_roots'].append(value)
            except (OSError,ValueError):gap(path,'Custom path inaccessible, symlinked ancestor or replaced directory')
    except TimeoutError:gap('Inventory','Persistence inventory budget exhausted')
    report['state']='incomplete' if report['gaps'] else 'collected'
    return report


def security_inspect(packages,persistence=True,custom_paths=None):
    """Local database comparison and metadata-only startup inventory; no remediation."""
    validate_inspection(packages,persistence,custom_paths)
    try:from bridge import bounded
    except ImportError:from target.bridge import bounded
    report={'version':1,'started':time.time(),'state':'incomplete','trust_basis':'target_local_package_database',
            'packages':[],'gaps':[],'persistence':None,
            'limitations':['Local package metadata is not an independent trusted vendor baseline.',
                          'Differences may be legitimate configuration changes; they are not malware verdicts.',
                          'No differences does not establish complete file coverage or a clean host.']}
    rpm=not Path('/var/lib/dpkg/status').exists()
    report['package_manager']='rpm' if rpm else 'dpkg'
    deadline=time.monotonic()+180
    def command(args,allowed=(0,)):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('Inspection deadline exhausted')
        return bounded(args,timeout=min(30,remaining),limit=512000,
                       env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/root'},
                       allowed_codes=allowed,return_status=True)
    remaining_findings=200
    for package in packages:
        row={'package':package,'state':'incomplete','findings':[],'gaps':[]};report['packages'].append(row)
        query_name=package.replace(':','.') if rpm else package
        query=(['rpm','-q','--qf','%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n','--',query_name] if rpm else
               ['dpkg-query','-W','-f=${db:Status-Status} ${Version}\n','--',query_name])
        verify=(['rpm','--verify','--noscripts','--nodeps','--',query_name] if rpm else
                ['dpkg','--verify-format=rpm','--verify','--',query_name])
        try:
            before,diagnostic,_=command(query)
            if diagnostic or not before.strip() or (not rpm and not before.startswith('installed ')):
                raise ValueError('Package is not installed or cannot be queried')
            if len(before)>4000:raise ValueError('Package identity exceeds limit')
            row['installed_identity']=before.strip()
            output,diagnostic,status=command(verify,(0,1))
            findings,row['gaps']=parse_package_verification(output)
            row['findings']=findings[:remaining_findings]
            remaining_findings-=len(row['findings'])
            if len(findings)>len(row['findings']):row['gaps'].append('Inspection-wide finding limit reached')
            if diagnostic:row['gaps'].append('Package manager reported diagnostics; inspection is incomplete')
            if status and not row['findings']:row['gaps'].append('Verification failed without attributable file findings')
            after,diagnostic,_=command(query)
            if diagnostic or after!=before:row['gaps'].append('Package identity changed during verification')
            row['state']='incomplete' if row['gaps'] else 'differences' if row['findings'] else 'no_reported_differences'
        except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.TimeoutExpired) as error:
            # Don't return arbitrary command diagnostics or configuration plaintext.
            row['gaps'].append(type(error).__name__+': package verification unavailable or interrupted')
        if time.monotonic()>deadline:
            report['gaps'].append('Inspection time budget exhausted; remaining packages not examined');break
    if persistence:report['persistence']=persistence_inventory(min(deadline,time.monotonic()+15),custom_paths)
    incomplete=report['gaps'] or any(row['state']=='incomplete' for row in report['packages']) or (persistence and report['persistence']['state']=='incomplete')
    report['state']='incomplete' if incomplete else 'collected'
    report['finished']=time.time()
    return report


def vendor_inspect(manifest):
    """Compare controller-authenticated regular-file bytes; never consult local checksums."""
    if not isinstance(manifest,dict):raise ValueError('Invalid vendor manifest')
    manager=manifest.get('package_manager','dpkg')
    if manager not in ('dpkg','rpm'):raise ValueError('Unsupported vendor package manager')
    name_pattern='[A-Za-z0-9][A-Za-z0-9+_.-]{0,199}' if manager=='rpm' else '[a-z0-9][a-z0-9+.-]{0,199}'
    arch_pattern='[A-Za-z0-9_]{1,64}' if manager=='rpm' else '[a-z0-9][a-z0-9-]{0,63}'
    if not re.fullmatch(name_pattern,manifest.get('package','')) or not re.fullmatch(arch_pattern,manifest.get('architecture','')):
        raise ValueError('Invalid vendor package identity')
    version=manifest.get('version');entries=manifest.get('entries')
    if not isinstance(version,str) or not 1<=len(version)<=200 or any(c.isspace() for c in version):raise ValueError('Invalid vendor version')
    if not isinstance(entries,list) or not 1<=len(entries)<=200:raise ValueError('Invalid vendor file scope')
    seen=set()
    for entry in entries:
        path=entry.get('path','')
        if not isinstance(path,str) or not path.startswith('/') or path.startswith('//') or str(Path(path))!=path or '..' in Path(path).parts or path in seen or len(path)>4096 or any(ord(c)<32 for c in path):raise ValueError('Invalid vendor file path')
        if not re.fullmatch('[a-f0-9]{64}',entry.get('sha256','')) or type(entry.get('size')) is not int or not 0<=entry['size']<=32*1024*1024:raise ValueError('Invalid vendor file hash or size')
        seen.add(path)
    try:from bridge import bounded
    except ImportError:from target.bridge import bounded
    result={'state':'incomplete','package':manifest['package'],'version':version,'architecture':manifest['architecture'],
            'scope_files':len(entries),'examined':0,'findings':[],'gaps':[],'trust_basis':'controller_authenticated_rpm_artifact' if manager=='rpm' else 'controller_authenticated_debian_artifact'}
    deadline=time.monotonic()+120;total=0
    def identity():
        if manager=='rpm':
            query=['rpm','-q','--qf','%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\n','--',manifest['package']+'.'+manifest['architecture']]
            expected=manifest['package']+' '+version+' '+manifest['architecture']
        else:
            query=['dpkg-query','-W','-f=${db:Status-Status} ${Version} ${Architecture}\n','--',manifest['package']+':'+manifest['architecture']]
            expected='installed '+version+' '+manifest['architecture']
        out,err,code=bounded(query,timeout=10,limit=4000,allowed_codes=(0,1),return_status=True)
        if code or err or out.strip()!=expected:raise ValueError('Installed package version/architecture is ambiguous or does not match authenticated artifact')
    try:
        identity()
        for entry in entries:
            if time.monotonic()>deadline:raise TimeoutError('Vendor comparison deadline exceeded')
            path=Path(entry['path']);fd=None
            try:
                with scan_root(path.parent) as parent:
                    before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                    if not stat.S_ISREG(before.st_mode):raise ValueError('Expected regular file; symlink or special file excluded')
                    fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                    opened=os.fstat(fd)
                    if (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino):raise ValueError('File replaced before read')
                    digest=hashlib.sha256();size=0
                    while True:
                        chunk=os.read(fd,65536)
                        if not chunk:break
                        size+=len(chunk);total+=len(chunk)
                        if size>32*1024*1024 or total>128*1024*1024 or time.monotonic()>deadline:raise TimeoutError('Vendor hashing limit exceeded')
                        digest.update(chunk)
                    after=os.fstat(fd);named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or (named.st_dev,named.st_ino,named.st_ctime_ns)!=(before.st_dev,before.st_ino,before.st_ctime_ns):raise ValueError('File changed during read')
                    with scan_root(path.parent) as current:
                        a=os.fstat(current);b=os.fstat(parent)
                        if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino):raise ValueError('Parent replaced during read')
                result['examined']+=1
                if digest.hexdigest()!=entry['sha256'] or size!=entry['size']:
                    result['findings'].append({'path':str(path),'status':'content_differs','expected_sha256':entry['sha256'],'observed_sha256':digest.hexdigest()})
            except FileNotFoundError:
                result['findings'].append({'path':str(path),'status':'missing'})
                result['examined']+=1
            except (OSError,ValueError,TimeoutError) as error:
                if len(result['gaps'])<20:result['gaps'].append(str(path)+': '+type(error).__name__)
                # Keep a persistent count even after the diagnostic cap.
                result['skipped']=result.get('skipped',0)+1
            finally:
                if fd is not None:os.close(fd)
        identity()
        result['state']='incomplete' if result['gaps'] or result['examined']!=len(entries) else 'differences' if result['findings'] else 'matches_artifact_bytes'
    except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.TimeoutExpired) as error:
        result['gaps'].append(type(error).__name__+': package identity unavailable, mismatched or comparison interrupted')
    return result

if __name__ == '__main__': main()
