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

SCAN_EXCLUDED = ('/proc','/sys','/dev','/run','/var/lib/mrpatchy-quarantine','/var/lib/mrpatchy-evidence')
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


EVIDENCE_ROOT=Path('/var/lib/mrpatchy-evidence')


def evidence_identity(info):
    return {k:getattr(info,'st_'+k) for k in ('dev','ino','size','uid','gid','mode','mtime_ns','ctime_ns','nlink')}


def evidence_prepare(expected):
    if not isinstance(expected,dict):raise ValueError('Invalid detection identity')
    path=expected.get('path','');sha=expected.get('sha256')
    if not isinstance(path,str) or not path.startswith('/') or path.startswith('//') or str(Path(path))!=path or '..' in Path(path).parts or len(path)>4096 or scan_excluded(Path(path)) or not re.fullmatch('[a-f0-9]{64}',sha or ''):raise ValueError('Invalid evidence scope')
    if type(expected.get('device')) is not int or type(expected.get('inode')) is not int:raise ValueError('A fresh scanner receipt with device/inode identity is required')
    path=Path(path);fd=None;deadline=time.monotonic()+30
    try:
        with scan_root(path.parent) as parent:
            before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or before.st_size>32*1024*1024 or (before.st_dev,before.st_ino)!=(expected['device'],expected['inode']):raise ValueError('Detected file changed or is outside regular-file limits')
            fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            if evidence_identity(os.fstat(fd))!=evidence_identity(before):raise ValueError('Evidence replaced before reading')
            digest=hashlib.sha256();total=0
            while True:
                chunk=os.read(fd,65536)
                if not chunk:break
                total+=len(chunk)
                if total>32*1024*1024 or time.monotonic()>deadline:raise TimeoutError('Evidence read budget exceeded')
                digest.update(chunk)
            if evidence_identity(os.fstat(fd))!=evidence_identity(before) or evidence_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))!=evidence_identity(before):raise ValueError('Evidence changed while reading')
            with scan_root(path.parent) as current:
                a=os.fstat(current);b=os.fstat(parent)
                if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino):raise ValueError('Evidence parent replaced')
            if digest.hexdigest()!=sha:raise ValueError('Evidence hash changed since detection')
            return {'path':str(path),'sha256':sha,'identity':evidence_identity(before),'parent':{'dev':b.st_dev,'ino':b.st_ino}}
    finally:
        if fd is not None:os.close(fd)


@contextmanager
def evidence_directory(path,create=False):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            except FileNotFoundError:
                if not create:raise
                os.mkdir(part,0o700,dir_fd=fd)
                os.fsync(fd)
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            info=os.fstat(child)
            if info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022:
                os.close(child);raise ValueError('Evidence vault ancestors must be root-owned and not group/world writable')
            os.close(fd);fd=child
        if stat.S_IMODE(os.fstat(fd).st_mode)!=0o700:raise ValueError('Evidence vault directory must be mode 0700')
        yield fd
    finally:os.close(fd)


def evidence_write(directory,name,value):
    temp='receipt-'+uuid.uuid4().hex
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try:
        with os.fdopen(os.dup(fd),'wb') as stream:
            stream.write(json.dumps(value,sort_keys=True).encode());stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    os.replace(temp,name,src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)


def evidence_read(directory,name):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>32000:raise ValueError('Unsafe evidence receipt')
        return json.loads(os.read(fd,32001))
    finally:os.close(fd)


def evidence_status_open(directory,identifier):
    receipt=evidence_read(directory,'receipt.json')
    if receipt.get('id')!=identifier:raise ValueError('Evidence receipt ID mismatch')
    if receipt.get('state')!='preserved':return {**receipt,'state':'incomplete'}
    fd=os.open('content',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or before.st_size>32*1024*1024:raise ValueError('Unsafe vault content')
        digest=hashlib.sha256();total=0;deadline=time.monotonic()+30
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            total+=len(chunk)
            if total>32*1024*1024 or time.monotonic()>deadline:raise TimeoutError('Vault verification budget exceeded')
            digest.update(chunk)
        if evidence_identity(before)!=evidence_identity(os.fstat(fd)) or digest.hexdigest()!=receipt['snapshot']['sha256'] or total!=receipt['snapshot']['identity']['size']:raise ValueError('Vault content changed or does not match receipt')
        return receipt
    finally:os.close(fd)


def evidence_preserve(identifier,snapshot=None,status_only=False):
    import fcntl
    if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9-]{36}',identifier):raise ValueError('Invalid evidence operation ID')
    if not status_only:
        if not isinstance(snapshot,dict) or set(snapshot)!={'path','sha256','identity','parent'}:raise ValueError('Invalid evidence snapshot')
        expected={'path':snapshot['path'],'sha256':snapshot['sha256'],'device':snapshot['identity']['dev'],'inode':snapshot['identity']['ino']}
    try:
        with evidence_directory(EVIDENCE_ROOT,create=not status_only) as root:
            if not status_only:
                try:os.mkdir(identifier,0o700,dir_fd=root);os.fsync(root)
                except FileExistsError:pass
            with evidence_directory(EVIDENCE_ROOT/identifier) as directory:
                fcntl.flock(directory,fcntl.LOCK_EX|fcntl.LOCK_NB)
                try:
                    old=evidence_status_open(directory,identifier)
                    if not status_only and old['snapshot']!=snapshot:raise ValueError('Operation ID is bound to different evidence')
                    return old
                except FileNotFoundError:
                    try:partial=evidence_read(directory,'receipt.json')
                    except FileNotFoundError:partial=None
                    if partial is not None:return {**partial,'state':'incomplete'}
                    if status_only:return {'id':identifier,'state':'incomplete'}
                if evidence_prepare(expected)!=snapshot:raise ValueError('Evidence metadata changed after preparation')
                receipt={'id':identifier,'state':'incomplete','snapshot':snapshot,'created':time.time(),'original_unchanged':True}
                evidence_write(directory,'receipt.json',receipt)
                path=Path(snapshot['path']);output=None;source=None
                try:
                    with scan_root(path.parent) as parent:
                        if {'dev':os.fstat(parent).st_dev,'ino':os.fstat(parent).st_ino}!=snapshot['parent']:raise ValueError('Evidence parent changed')
                        source=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                        if evidence_identity(os.fstat(source))!=snapshot['identity']:raise ValueError('Evidence changed before copying')
                        output=os.open('partial',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                        digest=hashlib.sha256();total=0;deadline=time.monotonic()+30
                        with os.fdopen(os.dup(output),'wb') as stream:
                            while True:
                                chunk=os.read(source,65536)
                                if not chunk:break
                                total+=len(chunk)
                                if total>32*1024*1024 or time.monotonic()>deadline:raise TimeoutError('Evidence copy budget exceeded')
                                digest.update(chunk);stream.write(chunk)
                            stream.flush();os.fsync(stream.fileno())
                        if digest.hexdigest()!=snapshot['sha256'] or evidence_identity(os.fstat(source))!=snapshot['identity']:raise ValueError('Evidence changed during copy')
                        if evidence_prepare(expected)!=snapshot:raise ValueError('Evidence path changed during copy')
                        os.rename('partial','content',src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
                        receipt['state']='preserved';receipt['finished']=time.time();evidence_write(directory,'receipt.json',receipt)
                        return evidence_status_open(directory,identifier)
                finally:
                    if output is not None:os.close(output)
                    if source is not None:os.close(source)
    except FileNotFoundError:
        if status_only:return {'id':identifier,'state':'not_found'}
        raise

def evidence_export(identifier,snapshot):
    """Export only an already preserved operation, never an arbitrary path."""
    import fcntl
    if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9-]{36}',identifier):raise ValueError('Invalid evidence operation ID')
    with evidence_directory(EVIDENCE_ROOT/identifier) as directory:
        fcntl.flock(directory,fcntl.LOCK_EX|fcntl.LOCK_NB)
        receipt=evidence_status_open(directory,identifier)
        if receipt.get('state')!='preserved' or receipt.get('snapshot')!=snapshot or receipt.get('original_unchanged') is not True:raise ValueError('Only the approved preserved snapshot may be acquired')
        fd=os.open('content',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or before.st_size>32*1024*1024:raise ValueError('Unsafe vault content')
            chunks=[];total=0;digest=hashlib.sha256();deadline=time.monotonic()+30
            while True:
                chunk=os.read(fd,65536)
                if not chunk:break
                total+=len(chunk)
                if total>32*1024*1024 or time.monotonic()>deadline:raise ValueError('Evidence export exceeded its budget')
                chunks.append(chunk);digest.update(chunk)
            if evidence_identity(before)!=evidence_identity(os.fstat(fd)) or evidence_identity(before)!=evidence_identity(os.stat('content',dir_fd=directory,follow_symlinks=False)) or digest.hexdigest()!=snapshot['sha256'] or total!=snapshot['identity']['size']:raise ValueError('Preserved evidence changed during export')
            if evidence_status_open(directory,identifier)!=receipt:raise ValueError('Evidence receipt changed during export')
            return {'id':identifier,'snapshot':snapshot,'content_base64':base64.b64encode(b''.join(chunks)).decode('ascii')}
        finally:os.close(fd)


RESPONSE_ROOT=Path('/var/lib/mrpatchy-quarantine')
RESPONSE_SCOPES=('/srv/','/opt/')


@contextmanager
def response_parent(path):
    """Only root-controlled namespace entries; no symlinks or writable ancestors."""
    if len(path.parts)>32:raise ValueError('Response path is too deeply nested')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);chain=[]
    try:
        for part in ('',*path.parts[1:]):
            if part:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=child
            info=os.fstat(fd)
            if info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022:raise ValueError('Response ancestors must be root-owned and not group/world writable')
            chain.append({k:getattr(info,'st_'+k) for k in ('dev','ino','uid','gid','mode')})
        yield fd,chain
    finally:os.close(fd)


def response_xattrs(fd):
    names=sorted(os.listxattr(fd))
    if len(names)>32 or any(len(n)>255 or n in ('security.capability','system.posix_acl_access') for n in names):raise ValueError('File capabilities or ACLs require console response')
    result={};total=0
    for name in names:
        value=os.getxattr(fd,name);total+=len(value)
        if total>65536:raise ValueError('Response extended attributes exceed budget')
        result[name]=hashlib.sha256(value).hexdigest()
    return result


def response_scope(snapshot):
    if not isinstance(snapshot,dict):raise ValueError('Invalid response snapshot')
    path=snapshot.get('path','')
    if not isinstance(path,str) or not path.startswith(RESPONSE_SCOPES) or path.startswith('/opt/drpatch/') or path=='/opt/drpatch':raise ValueError('Quarantine supports protected files under /srv and /opt, excluding Mr Patchy')
    expected={'path':path,'sha256':snapshot['sha256'],'device':snapshot['identity']['dev'],'inode':snapshot['identity']['ino']}
    # Reuse canonical path, exclusion, descriptor identity and content checks.
    if evidence_prepare(expected)!=snapshot:raise ValueError('Response source changed since evidence acquisition')
    info=snapshot['identity']
    if info['uid']!=0 or info['nlink']!=1 or info['mode']&0o7022:raise ValueError('Response requires a root-owned single-link file without writable group/other or special mode bits')
    return Path(path)


def response_rename(source_fd,source,dest_fd,dest):
    """No overwrite fallback. Kernel/filesystem support is mandatory."""
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    rename=getattr(libc,'renameat2',None)
    if rename is None:raise ValueError('Atomic no-overwrite rename is unavailable')
    rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
    if rename(source_fd,os.fsencode(source),dest_fd,os.fsencode(dest),1):
        code=ctypes.get_errno();raise OSError(code,'Atomic no-overwrite response move failed')


def response_prepare(snapshot):
    path=response_scope(snapshot)
    with response_parent(path.parent) as (parent,ancestors):
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            if evidence_identity(os.fstat(fd))!=snapshot['identity']:raise ValueError('Response source changed')
            attrs=response_xattrs(fd)
            if evidence_identity(os.fstat(fd))!=snapshot['identity']:raise ValueError('Response metadata changed')
        finally:os.close(fd)
    with response_parent(RESPONSE_ROOT.parent) as (parent,_):device=os.fstat(parent).st_dev
    if snapshot['identity']['dev']!=device:raise ValueError('Cross-filesystem quarantine is unsupported')
    try:
        with evidence_directory(RESPONSE_ROOT) as existing:
            if os.fstat(existing).st_dev!=device:raise ValueError('Quarantine vault filesystem differs from its protected parent')
    except FileNotFoundError:pass
    # Check the libc entry point without touching the source namespace.
    import ctypes
    if not hasattr(ctypes.CDLL(None),'renameat2'):raise ValueError('Atomic no-overwrite rename is unavailable')
    plan={'file':snapshot,'ancestors':ancestors,'xattrs':attrs,'vault_device':device}
    if len(json.dumps(plan,sort_keys=True).encode())>48000:raise ValueError('Response metadata exceeds budget')
    return plan


def response_json(directory,name,value=None):
    if value is not None:
        encoded=json.dumps(value,sort_keys=True).encode()
        if len(encoded)>128000:raise ValueError('Response journal exceeds budget')
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        with os.fdopen(fd,'wb') as stream:stream.write(encoded);stream.flush();os.fsync(stream.fileno())
        os.fsync(directory);return value
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or before.st_size>128000:raise ValueError('Unsafe response journal')
        result=json.loads(os.read(fd,128001))
        if evidence_identity(before)!=evidence_identity(os.fstat(fd)) or evidence_identity(before)!=evidence_identity(os.stat(name,dir_fd=directory,follow_symlinks=False)):raise ValueError('Response journal changed')
        return result
    finally:os.close(fd)


def response_file(directory,name,plan,modes):
    """Verify the captured inode, bytes and security metadata after namespace moves."""
    expected=plan['file']['identity'];fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        before=os.fstat(fd);actual=evidence_identity(before)
        if not stat.S_ISREG(before.st_mode) or any(actual[k]!=expected[k] for k in ('dev','ino','size','uid','gid','mtime_ns','nlink')) or stat.S_IMODE(before.st_mode) not in modes:raise ValueError('Response inode or metadata does not match approval')
        digest=hashlib.sha256();total=0;deadline=time.monotonic()+30
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            total+=len(chunk)
            if total>32*1024*1024 or time.monotonic()>deadline:raise ValueError('Response verification budget exceeded')
            digest.update(chunk)
        if digest.hexdigest()!=plan['file']['sha256'] or total!=expected['size'] or response_xattrs(fd)!=plan['xattrs'] or evidence_identity(before)!=evidence_identity(os.fstat(fd)) or evidence_identity(before)!=evidence_identity(os.stat(name,dir_fd=directory,follow_symlinks=False)):raise ValueError('Response bytes or metadata changed')
        return fd
    except BaseException:os.close(fd);raise


def response_present(directory,name):
    try:os.stat(name,dir_fd=directory,follow_symlinks=False);return True
    except FileNotFoundError:return False


def response_status_open(directory,identifier,plan,facts=None):
    facts={} if facts is None else facts
    result={'id':identifier,'plan':plan,'state':'uncertain','restore_ready':False,'restore_attempted':False}
    intent=response_json(directory,'intent.json')
    if intent.get('id')!=identifier or intent.get('plan')!=plan:raise ValueError('Response ID is bound to different approval evidence')
    facts['journal_verified']=True
    restored=response_present(directory,'restore-intent.json');result['restore_attempted']=restored
    if restored:
        review=response_json(directory,'restore-intent.json')
        if review.get('id')!=identifier or review.get('plan')!=plan:raise ValueError('Restoration intent does not bind approved evidence')
    path=Path(plan['file']['path']);mode=stat.S_IMODE(plan['file']['identity']['mode'])
    with response_parent(path.parent) as (parent,chain):
        facts['parents_match']=chain==plan['ancestors']
        if chain!=plan['ancestors']:return result
        held=response_present(directory,'held');source=response_present(parent,path.name)
        facts.update(held_present=held,source_present=source)
        if held:
            fd=response_file(directory,'held',plan,(0o600,mode))
            facts['held_verified']=True
            try:held_mode=stat.S_IMODE(os.fstat(fd).st_mode)
            finally:os.close(fd)
            if not source:
                result['restore_ready']=not restored
                if held_mode==0o600 and not restored:result['state']='quarantined'
        elif source:
            fd=response_file(parent,path.name,plan,(mode,));os.close(fd)
            result['state']='restored' if restored else 'not_moved'
    return result


def response_audit(identifier,plan):
    """Read-only classified observation; no journal creation or response replay."""
    if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9-]{36}',identifier):raise ValueError('Invalid response ID')
    import fcntl
    facts={'journal_verified':False,'parents_match':None,'held_present':None,'source_present':None,'held_verified':False}
    receipt=None;state='unavailable'
    try:
        with evidence_directory(RESPONSE_ROOT/identifier) as directory:
            fcntl.flock(directory,fcntl.LOCK_EX|fcntl.LOCK_NB)
            receipt=response_status_open(directory,identifier,plan,facts)
            state={'quarantined':'verified','restored':'restored','not_moved':'not_quarantined','uncertain':'uncertain'}[receipt['state']]
            if facts['parents_match'] is False:state='parent_changed'
            elif facts['held_verified'] and facts['source_present']:state='path_occupied'
    except FileNotFoundError:state='missing'
    except (ValueError,OSError,KeyError,TypeError):
        state='held_unverified' if facts['held_present'] is True else 'unavailable'
    return {'version':1,'id':identifier,'plan_digest':hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'state':state,'receipt':receipt,'facts':facts}


def response_status(identifier,plan):
    if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9-]{36}',identifier):raise ValueError('Invalid response ID')
    import fcntl
    try:
        with evidence_directory(RESPONSE_ROOT/identifier) as directory:
            fcntl.flock(directory,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return response_status_open(directory,identifier,plan)
    except FileNotFoundError:return {'id':identifier,'plan':plan,'state':'not_found','restore_ready':False,'restore_attempted':False}


RESPONSE_PROC_LIMITS={'processes':4096,'entries':50000,'matches':128,'seconds':15}


def response_proc_root():
    """Only inspect the kernel procfs mounted at the helper's /proc."""
    import ctypes
    fd=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        libc=ctypes.CDLL(None,use_errno=True);buffer=ctypes.create_string_buffer(256)
        if libc.fstatfs(fd,ctypes.byref(buffer)) or ctypes.c_long.from_buffer(buffer).value!=0x9fa0:
            raise ValueError('Process inspection requires Linux procfs')
        return fd
    except BaseException:os.close(fd);raise


def response_proc_read(directory,name,limit=4096):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        value=os.read(fd,limit+1)
        if len(value)>limit:raise ValueError('Process metadata exceeds budget')
        return value
    finally:os.close(fd)


def response_proc_identity(directory,pid):
    value=response_proc_read(directory,'stat');end=value.rfind(b') ')
    if end<0 or value.split(b' ',1)[0]!=str(pid).encode():raise ValueError('Invalid process identity')
    ticks=int(value[end+2:].split()[19])
    namespace=os.stat('ns/pid',dir_fd=directory).st_ino
    if ticks<=0 or namespace<=0:raise ValueError('Invalid process identity')
    return {'pid':pid,'start_ticks':ticks,'pid_namespace':namespace}


def response_proc_scan(identity):
    """Sample metadata only. Never read cmdline, environ, file bytes or memory."""
    limits=dict(RESPONSE_PROC_LIMITS);deadline=time.monotonic()+limits['seconds']
    result={'scope':'helper_visible_process_leaders','boot_id':None,'pid_namespace':None,'observer_pid':None,
            'processes_examined':0,'entries_examined':0,'matches':[],'gaps':{}}
    def gap(code):result['gaps'][code]=result['gaps'].get(code,0)+1
    class LimitReached(Exception):pass
    class DeadlineReached(Exception):pass
    def budget():
        if time.monotonic()>=deadline:gap('time_limit');raise DeadlineReached()
    def entry():
        budget()
        if result['entries_examined']>=limits['entries']:gap('entry_limit');raise LimitReached()
        result['entries_examined']+=1
    def same(info):return stat.S_ISREG(info.st_mode) and (info.st_dev,info.st_ino)==(identity['dev'],identity['ino'])
    try:
        root=response_proc_root()
        try:
            boot=response_proc_read(root,'sys/kernel/random/boot_id',64).decode('ascii').strip()
            if not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot):raise ValueError('Invalid boot identity')
            result['boot_id']=boot;result['pid_namespace']=os.stat('self/ns/pid',dir_fd=root).st_ino
            observer=os.readlink('self',dir_fd=root)
            if not re.fullmatch('[1-9][0-9]*',observer):raise ValueError('Invalid observer identity')
            result['observer_pid']=int(observer)
            with os.scandir(root) as processes:
                for process in processes:
                    entry()
                    if not re.fullmatch('[1-9][0-9]*',process.name) or process.name==observer:continue
                    if result['processes_examined']>=limits['processes']:gap('process_limit');break
                    result['processes_examined']+=1;directory=None
                    try:
                        directory=os.open(process.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
                        before=response_proc_identity(directory,int(process.name));references={}
                        try:
                            if same(os.stat('exe',dir_fd=directory)):references['executable']=1
                        except FileNotFoundError:pass # Kernel threads have no executable link.
                        except OSError:gap('executable_unavailable')
                        stopped=False
                        try:
                            for name,kind,pattern in (('fd','descriptor',r'[0-9]+'),('map_files','memory_map',r'[a-f0-9]+-[a-f0-9]+')):
                                links=None
                                try:
                                    links=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                                    with os.scandir(links) as entries:
                                        for link in entries:
                                            entry()
                                            if not re.fullmatch(pattern,link.name):gap('unexpected_entry');continue
                                            try:
                                                if same(os.stat(link.name,dir_fd=links)):references[kind]=references.get(kind,0)+1
                                            except FileNotFoundError:gap('reference_disappeared')
                                            except OSError:gap(kind+'_unavailable')
                                except OSError:gap(kind+'_unavailable')
                                finally:
                                    if links is not None:os.close(links)
                        except (LimitReached,DeadlineReached):stopped=True
                        if response_proc_identity(directory,int(process.name))!=before:gap('process_changed');continue
                        if references:
                            result['matches'].append({**before,'references':references})
                            if len(result['matches'])>=limits['matches']:gap('match_limit');break
                        if stopped:break
                    except (OSError,ValueError,IndexError):gap('process_unavailable')
                    finally:
                        if directory is not None:os.close(directory)
        finally:os.close(root)
    except (LimitReached,DeadlineReached):pass
    except (OSError,ValueError,UnicodeError):gap('procfs_unavailable')
    return result


def response_processes(identifier,plan):
    """Bind a bounded process reference observation to a still-held original inode."""
    if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9-]{36}',identifier):raise ValueError('Invalid response ID')
    import fcntl
    result={'version':1,'id':identifier,'plan_digest':hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'state':'unavailable','held_verified':False,'observation':None}
    try:
        with evidence_directory(RESPONSE_ROOT/identifier) as directory:
            fcntl.flock(directory,fcntl.LOCK_EX|fcntl.LOCK_NB)
            facts={};receipt=response_status_open(directory,identifier,plan,facts)
            if not facts.get('held_verified') or receipt['restore_attempted']:return result
            # Keep the captured inode open so it cannot be freed and reused while
            # comparing procfs references. Both hashes remain local to the helper.
            fd=response_file(directory,'held',plan,(0o600,stat.S_IMODE(plan['file']['identity']['mode'])))
            try:
                observation=response_proc_scan(plan['file']['identity'])
                after={};response_status_open(directory,identifier,plan,after)
                if not after.get('held_verified'):return result
                result.update(held_verified=True,observation=observation)
                if observation['boot_id'] and observation['pid_namespace'] and observation['observer_pid'] and (observation['matches'] or 'procfs_unavailable' not in observation['gaps']):
                    result['state']='references_found' if observation['matches'] else 'none_observed'
            finally:os.close(fd)
    except (OSError,ValueError,KeyError,TypeError):pass
    return result


def response_action(identifier,plan,approval,restore=False):
    import fcntl
    if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9-]{36}',identifier):raise ValueError('Invalid response ID')
    if not isinstance(approval,dict) or approval.get('action')!=('restore' if restore else 'quarantine') or not isinstance(approval.get('id'),str) or not re.fullmatch('[a-f0-9-]{36}',approval['id']):raise ValueError('Invalid typed response approval')
    expires=approval.get('expires')
    if type(expires) not in (int,float) or not time.time()<expires<=time.time()+300:raise ValueError('Response approval expired or invalid')
    if not isinstance(plan,dict) or set(plan)!={'file','ancestors','xattrs','vault_device'}:raise ValueError('Invalid response plan')
    if not restore:
        try:
            with evidence_directory(RESPONSE_ROOT/identifier):return response_status(identifier,plan)
        except FileNotFoundError:pass
        if response_prepare(plan['file'])!=plan:raise ValueError('Response source or scope changed after preparation')
    with evidence_directory(RESPONSE_ROOT,create=not restore) as root:
        if os.fstat(root).st_dev!=plan['vault_device']:raise ValueError('Quarantine vault filesystem changed')
        if not restore:
            try:os.mkdir(identifier,0o700,dir_fd=root);os.fsync(root)
            except FileExistsError:
                return response_status(identifier,plan) # Replays observe; never mutate again.
        with evidence_directory(RESPONSE_ROOT/identifier) as directory:
            fcntl.flock(directory,fcntl.LOCK_EX|fcntl.LOCK_NB)
            path=Path(plan['file']['path']);mode=stat.S_IMODE(plan['file']['identity']['mode'])
            if restore:
                current=response_status_open(directory,identifier,plan)
                if not current['restore_ready']:return current
                response_json(directory,'restore-intent.json',{'id':identifier,'plan':plan,'approval':approval,'created':time.time()})
            else:response_json(directory,'intent.json',{'id':identifier,'plan':plan,'approval':approval,'created':time.time()})
            with response_parent(path.parent) as (parent,chain):
                if chain!=plan['ancestors']:raise ValueError('Response parent changed before move')
                if time.time()>=expires:raise ValueError('Response approval expired before move')
                if restore:
                    if response_present(parent,path.name):raise ValueError('Restoration never overwrites an existing path')
                    source=response_file(directory,'held',plan,(0o600,mode))
                    try:
                        if time.time()>=expires:raise ValueError('Restoration approval expired after verification')
                        os.fchmod(source,mode);os.fsync(source)
                        response_rename(directory,'held',parent,path.name)
                    finally:os.close(source)
                else:
                    if response_prepare(plan['file'])!=plan:raise ValueError('Response source changed immediately before move')
                    if time.time()>=expires:raise ValueError('Quarantine approval expired after verification')
                    response_rename(parent,path.name,directory,'held')
                    source=response_file(directory,'held',plan,(mode,))
                    try:os.fchmod(source,0o600);os.fsync(source)
                    finally:os.close(source)
                os.fsync(parent);os.fsync(directory)
            observed=response_status_open(directory,identifier,plan)
            if observed['state']!=('restored' if restore else 'quarantined'):raise ValueError('Response verification is uncertain; review target console')
            response_json(directory,'restored.json' if restore else 'quarantined.json',{'id':identifier,'plan':plan,'approval':approval,'observed':observed,'finished':time.time()})
            return observed


if __name__ == '__main__': main()
