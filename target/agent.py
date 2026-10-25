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
from contextlib import contextmanager
import uuid
import re

ROOT = Path('/opt/drpatch')
MANAGED = ['/usr/local/lib/mrpatchy/agent.py', '/usr/local/lib/mrpatchy/bridge.py', '/etc/systemd/system/mrpatchy-agent.service', '/etc/sudoers.d/mrpatchy', '/opt/drpatch/.ssh/authorized_keys']
def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()
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
    errors=[]; processes=[]; namespaces={}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            namespace=(p/'ns/net').stat().st_ino
            if namespace not in namespaces:
                net,net_errors=sockets(p/'net');namespaces[namespace]=net;errors.extend(net_errors)
            net=namespaces[namespace]
            exe = os.readlink(p/'exe')
            stat = (p/'exe').stat()
            identity = (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_size)
            if identity not in hash_cache: hash_cache[identity] = digest(p/'exe')
            connections = []
            for fd in (p/'fd').iterdir():
                try:
                    link = os.readlink(fd)
                    if link.startswith('socket:[') and link[8:-1] in net: connections.append(net[link[8:-1]])
                except FileNotFoundError: pass
                except OSError as e: errors.append({'pid':p.name,'error':str(e)})
            uid = next(x.split()[2] for x in read(p/'status').splitlines() if x.startswith('Uid:'))
            processes.append({'pid':int(p.name),'executable':exe,'sha256':hash_cache[identity],'uid':uid,'network_namespace':namespace,'connections':connections})
        except FileNotFoundError: pass # short-lived process / kernel thread
        except (OSError, StopIteration) as e: errors.append({'pid':p.name,'error':str(e)})
    return processes, errors

def atomic(path, value):
    tmp = path.with_suffix('.tmp'); tmp.write_text(json.dumps(value)); tmp.chmod(0o600); tmp.replace(path)

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

def main():
    ROOT.mkdir(exist_ok=True)
    cache = {}; hashes = {}; metadata = {}; next_hash = 0; next_inventory = 0
    while True:
        started = time.monotonic()
        try:
            if started >= next_hash:
                cache = {}; hashes = {}; metadata = {}
                for p in MANAGED:
                    try:
                        hashes[p] = digest(p)
                        info=Path(p).stat()
                        metadata[p]={'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}
                    except OSError as e: hashes[p] = 'ERROR: '+str(e)
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
