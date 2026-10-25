#!/usr/bin/env python3
"""Offline SQLite deployment backup, verification and empty-directory restore.

Stop the app before backup/restore. Archives contain private keys and must be protected.
MySQL deployments require a database-native consistent dump in addition to volume backup.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path,PurePosixPath
import sqlite3
import tarfile
import tempfile

def verify(archive):
    with tarfile.open(archive,'r:gz') as tar:
        members=tar.getmembers()
        if len({m.name for m in members})!=len(members):raise ValueError('Duplicate archive entries')
        for member in members:
            p=PurePosixPath(member.name)
            if not member.isfile() or p.is_absolute() or '..' in p.parts or member.size>512*1024*1024:raise ValueError('Unsafe archive entry')
        manifest=json.load(tar.extractfile('manifest.json'))
        if set(manifest)!={m.name for m in members if m.name!='manifest.json'}:raise ValueError('Manifest mismatch')
        for name,digest in manifest.items():
            if hashlib.sha256(tar.extractfile(name).read()).hexdigest()!=digest:raise ValueError('Checksum mismatch: '+name)
    return manifest

def backup(source,destination):
    source=Path(source);destination=Path(destination)
    if not (source/'mrpatchy.db').is_file():raise ValueError('SQLite database missing; MySQL requires a native dump')
    with tempfile.TemporaryDirectory() as temporary:
        snapshot=Path(temporary)/'mrpatchy.db'
        with sqlite3.connect(source/'mrpatchy.db') as db,sqlite3.connect(snapshot) as copy:db.backup(copy)
        files={'mrpatchy.db':snapshot}
        for name in ('secret.key',):
            if not (source/name).is_file():raise ValueError('Missing '+name)
            files[name]=source/name
        for path in (source/'ssh').glob('*.key'):
            if path.is_symlink():raise ValueError('Refusing symlink key')
            files[str(path.relative_to(source))]=path
        with open(destination,'xb') as stream:
            os.chmod(destination,0o600)
            with tarfile.open(fileobj=stream,mode='w:gz') as tar:
                manifest={}
                for name,path in files.items():
                    data=path.read_bytes();manifest[name]=hashlib.sha256(data).hexdigest()
                    info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
                data=json.dumps(manifest,sort_keys=True).encode()
                info=tarfile.TarInfo('manifest.json');info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
    verify(destination)

def restore(archive,destination):
    verify(archive);destination=Path(destination)
    if destination.exists() and any(destination.iterdir()):raise ValueError('Restore destination must be empty')
    destination.mkdir(mode=0o700,parents=True,exist_ok=True)
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar.getmembers():
            if member.name=='manifest.json':continue
            target=destination/member.name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with open(target,'xb') as stream:os.chmod(target,0o600);stream.write(tar.extractfile(member).read())
    with sqlite3.connect(destination/'mrpatchy.db') as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Database integrity check failed')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['backup','verify','restore']);parser.add_argument('source');parser.add_argument('destination',nargs='?')
    parser.add_argument('--app-stopped',action='store_true')
    args=parser.parse_args()
    if args.action!='verify' and (not args.app_stopped or not args.destination):parser.error('Stop the app and provide --app-stopped and destination')
    if args.action=='verify':verify(args.source)
    elif args.action=='backup':backup(args.source,args.destination)
    else:restore(args.source,args.destination)
