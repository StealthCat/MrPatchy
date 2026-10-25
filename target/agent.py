#!/usr/bin/python3
"""Root-owned, outbound-network-free collector. No third-party dependencies."""
import base64
import glob
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

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
    arch = subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip()
    foreign = subprocess.check_output(['dpkg', '--print-foreign-architectures'], text=True).split()
    return {'os': read('/etc/os-release'), 'architecture': arch, 'foreign_architectures': foreign, 'status': read('/var/lib/dpkg/status'), 'files': files, 'keys': keys, 'machine_id': read('/etc/machine-id').strip(), 'collected': time.time()}
def address(value, ipv6):
    ip, port = value.split(':')
    raw = bytes.fromhex(ip)
    if ipv6: raw = b''.join(raw[i:i+4][::-1] for i in range(0,16,4))
    else: raw = raw[::-1]
    return socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET, raw), int(port,16)
def sockets():
    result = {}
    for proto in ['tcp','tcp6','udp','udp6']:
        try:
            for line in read('/proc/net/'+proto).splitlines()[1:]:
                fields = line.split()
                local, lp = address(fields[1], proto.endswith('6'))
                remote, rp = address(fields[2], proto.endswith('6'))
                result[fields[9]] = {'protocol':proto, 'local':local, 'local_port':lp, 'remote':remote, 'remote_port':rp, 'state':fields[3]}
        except OSError: pass
    return result

def collect(hash_cache):
    net = sockets(); processes = []; errors = []
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            exe = os.readlink(p/'exe')
            stat = (p/'exe').stat()
            identity = (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_size)
            if identity not in hash_cache: hash_cache[identity] = digest(p/'exe')
            connections = []
            for fd in (p/'fd').iterdir():
                try:
                    link = os.readlink(fd)
                    if link.startswith('socket:[') and link[8:-1] in net: connections.append(net[link[8:-1]])
                except OSError: pass
            uid = next(x.split()[1] for x in read(p/'status').splitlines() if x.startswith('Uid:'))
            processes.append({'pid':int(p.name),'executable':exe,'sha256':hash_cache[identity],'uid':uid,'connections':connections})
        except FileNotFoundError: pass # short-lived process / kernel thread
        except (OSError, StopIteration) as e: errors.append({'pid':p.name,'error':str(e)})
    return processes, errors

def atomic(path, value):
    tmp = path.with_suffix('.tmp'); tmp.write_text(json.dumps(value)); tmp.chmod(0o600); tmp.replace(path)
def main():
    ROOT.mkdir(exist_ok=True)
    cache = {}; hashes = {}; next_hash = 0; next_inventory = 0
    while True:
        started = time.monotonic()
        try:
            if started >= next_hash:
                cache = {}; hashes = {}
                for p in MANAGED:
                    try: hashes[p] = digest(p)
                    except OSError as e: hashes[p] = 'ERROR: '+str(e)
                hashed_at = time.time(); next_hash = started+300
            procs, errors = collect(cache)
            atomic(ROOT/'telemetry.json', {'collected':time.time(),'hashed_at':hashed_at,'managed':hashes,'processes':procs,'errors':errors})
            if started >= next_inventory:
                atomic(ROOT/'inventory.json', inventory()); next_inventory = started+300
            (ROOT/'collector-error.json').unlink(missing_ok=True)
        except Exception as e:
            atomic(ROOT/'collector-error.json', {'error':str(e),'at':time.time()})
        time.sleep(max(0.1, 30-(time.monotonic()-started)))
if __name__ == '__main__': main()
