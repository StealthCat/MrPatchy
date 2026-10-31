#!/usr/bin/env python3
"""Encrypted off-host app/TLS/DB recovery through restic. Run with all app/workers stopped."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import subprocess
import tempfile
from sqlalchemy.engine import make_url

def run(args,**kwargs):return subprocess.run(args,check=True,**kwargs)
def open_sqlite(path):
    path=Path(path)
    if not path.is_file() or path.is_symlink():raise ValueError('Existing SQLite database required')
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    try:
        if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Database integrity check failed')
        tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'settings','hosts','packages','jobs'}<=tables:raise ValueError('Database is missing Mr Patchy application tables')
        return db
    except Exception:
        db.close();raise
HOST_ID=re.compile('[A-Za-z0-9-]{1,64}')
def sqlite_key_hosts(db):
    """Servers whose SSH identity must exist: every server not deleted."""
    columns={row[1] for row in db.execute('PRAGMA table_info(hosts)')}
    query='SELECT id FROM hosts'+(' WHERE deleted_at=0' if 'deleted_at' in columns else '')
    return {row[0] for row in db.execute(query)}
def check_ssh(folder,hosts):
    """Distinguish an empty fleet from missing credentials for enrolled servers."""
    folder=Path(folder);missing=[]
    for host in sorted(hosts):
        if not isinstance(host,str) or not HOST_ID.fullmatch(host):raise ValueError('Invalid server identifier in recovery state')
        key=folder/(host+'.key')
        if key.is_symlink() or not key.is_file() or not key.stat().st_size:missing.append(host)
    if missing:raise ValueError('Missing SSH private key for enrolled server(s): '+', '.join(missing)+'. Restore the key or delete the server before recovery')
def sqlite_verified_archives(db):
    tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'security_evidence_archives' not in tables:return set()
    return {row[0] for row in db.execute("SELECT id FROM security_evidence_archives WHERE state='verified'")}

def check_archives(bundle,identifiers):
    for identifier in sorted(identifiers):
        if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9-]{36}',identifier):raise ValueError('Invalid verified archive identifier')
        folder=Path(bundle)/'evidence-archive'/identifier
        for name in ('content','receipt.json'):
            path=folder/name
            if path.is_symlink() or not path.is_file():raise ValueError('Missing verified evidence archive files; restore evidence before backup/activation')

def remote():
    repo=os.environ.get('RESTIC_REPOSITORY','')
    if not repo.startswith(('sftp:','s3:','rest:https://','b2:','azure:','gs:')):raise ValueError('Configure an off-host RESTIC_REPOSITORY')
    if not os.environ.get('RESTIC_PASSWORD_FILE'):raise ValueError('Use RESTIC_PASSWORD_FILE')
# Runtime caches (apt/rpm), locks and temporary requests are reconstructible.
# These directories contain retained evidence, operator trust or credentials.
DURABLE_STATE=('evidence-archive','vendor-packages','yara-rules','gcloud')
EXTERNAL_DEPENDENCIES=('Compose/.env and external secret/credential files',
    'database TLS CA/client files and database server provisioning',
    'externally configured CLOUDSDK_CONFIG/GOOGLE_APPLICATION_CREDENTIALS',
    'target-side evidence/quarantine and agent spool volumes')

def tree_inventory(source):
    """Hash only regular, singly linked files; never follow links or read devices."""
    source=Path(source)
    if not stat.S_ISDIR(source.lstat().st_mode):raise ValueError('Unsafe recovery directory (symlink or non-directory)')
    result={'.':{'type':'directory'}}
    for path in sorted(source.rglob('*')):
        info=path.lstat();name=path.relative_to(source).as_posix()
        if stat.S_ISDIR(info.st_mode):result[name]={'type':'directory'}
        elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
            digest=hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
            result[name]={'type':'file','size':info.st_size,'sha256':digest.hexdigest()}
        else:raise ValueError('Refusing symlink, hardlink or special file in recovery state')
    return result

def copy_tree(source,destination,private=False):
    before=tree_inventory(source)
    shutil.copytree(source,destination)
    if tree_inventory(destination)!=before:raise ValueError('Recovery directory changed during copy')
    if private:
        Path(destination).chmod(0o700)
        for path in Path(destination).rglob('*'):
            path.chmod(0o700 if path.is_dir() else 0o600)

def read_manifest(bundle):
    path=Path(bundle)/'manifest.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size>64*1024*1024:raise ValueError('Missing or unsafe recovery manifest')
    manifest=json.loads(path.read_text())
    if not isinstance(manifest,dict):raise ValueError('Unsupported backup format')
    if type(manifest.get('format')) is not int or manifest['format'] not in (1,2) or manifest.get('database') not in ('sqlite','mysql'):raise ValueError('Unsupported backup format')
    if manifest['format']==1:
        print('WARNING: Legacy format-1 bundle has no evidence/trust/GCP filesystem coverage. Recover these dependencies separately; full evidence recovery is unverified.',file=sys.stderr,flush=True)
    else:
        coverage=manifest.get('durable_state')
        if not isinstance(coverage,dict) or set(coverage)!=set(DURABLE_STATE):raise ValueError('Incomplete durable-state coverage manifest')
        for name in DURABLE_STATE:
            folder=Path(bundle)/name;expected=coverage[name]
            if expected is None:
                if os.path.lexists(folder):raise ValueError('Unexpected durable-state directory: '+name)
            elif not isinstance(expected,dict) or tree_inventory(folder)!=expected:
                raise ValueError('Durable-state contents differ from backup manifest: '+name)
        identifiers=manifest.get('verified_archives')
        if not isinstance(identifiers,list):raise ValueError('Missing verified archive coverage')
        check_archives(bundle,identifiers)
        absent=[name for name in DURABLE_STATE if coverage[name] is None]
        if absent:print('Recovery coverage: absent at backup: '+', '.join(absent)+'. No contents can be recovered for these directories.',file=sys.stderr,flush=True)
    print('External recovery dependencies must be supplied separately: '+'; '.join(EXTERNAL_DEPENDENCIES)+'.',file=sys.stderr,flush=True)
    return manifest

def mysql_options(url,directory):
    if url.get_backend_name()!='mysql' or not url.database or url.database.startswith('-'):raise ValueError('A named MySQL database is required')
    path=Path(directory)/'mysql.cnf'
    def escape(value):
        if any(c in value for c in '\r\n\x00'):raise ValueError('Invalid MySQL option')
        return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'
    path.write_text('[client]\n'+''.join(k+'='+escape(str(v))+'\n' for k,v in {'host':url.host or 'localhost','port':url.port or 3306,'user':url.username or '', 'password':url.password or ''}.items()))
    if url.host not in (None,'localhost','127.0.0.1','::1'):
        ca=os.environ.get('MYSQL_SSL_CA')
        if not ca:raise ValueError('Remote MySQL backup/restore requires MYSQL_SSL_CA (MariaDB client)')
        with path.open('a') as stream:stream.write('ssl-ca='+escape(ca)+'\nssl-verify-server-cert=1\n')
    path.chmod(0o600);return path
def active_database_url(data):
    data=Path(data)
    profile=data/'database-active.json'
    if profile.exists():
        from cryptography.fernet import Fernet
        try:
            value=json.loads(Fernet((data/'secret.key').read_bytes()).decrypt(json.loads(profile.read_text())['encrypted'].encode()))
            return make_url(value['url'])
        except Exception:raise ValueError('Cannot read active database profile; restore the matching secret.key') from None
    return make_url(os.getenv('DATABASE_URL') or 'sqlite:///'+str(data/'mrpatchy.db'))

def backup(data,tls,caddy_data,caddy_config):
    remote()
    with tempfile.TemporaryDirectory(prefix='mrpatchy-recovery-') as temporary:
        root=Path(temporary);bundle=root/'bundle';bundle.mkdir(mode=0o700)
        data=Path(data);url=active_database_url(data)
        if url.get_backend_name()=='sqlite':
            from contextlib import closing
            with closing(open_sqlite(url.database)) as source,sqlite3.connect(bundle/'database.sqlite') as destination:source.backup(destination)
            with closing(sqlite3.connect(bundle/'database.sqlite')) as snapshot:
                hosts=sqlite_key_hosts(snapshot);archives=sqlite_verified_archives(snapshot)
            backend='sqlite'
        elif url.get_backend_name()=='mysql':
            options=mysql_options(url,root)
            with open(bundle/'database.sql','wb') as stream:
                run(['mysqldump','--defaults-extra-file='+str(options),'--single-transaction','--routines','--events','--triggers','--hex-blob',url.database],stdout=stream)
            listed=subprocess.check_output(['mysql','--defaults-extra-file='+str(options),'--batch','--skip-column-names','--execute=SELECT id FROM hosts WHERE deleted_at=0',url.database],text=True)
            hosts={line.strip() for line in listed.splitlines() if line.strip()}
            listed=subprocess.check_output(['mysql','--defaults-extra-file='+str(options),'--batch','--skip-column-names',
                "--execute=SELECT id FROM security_evidence_archives WHERE state='verified'",url.database],text=True)
            archives={line.strip() for line in listed.splitlines() if line.strip()}
            backend='mysql'
        else:raise ValueError('Unsupported database')
        if (data/'secret.key').is_symlink() or not (data/'secret.key').is_file():raise ValueError('Missing or unsafe secret.key')
        shutil.copy2(data/'secret.key',bundle/'secret.key');(bundle/'secret.key').chmod(0o600)
        # Retain encrypted profiles for reference, not automatic restore activation.
        # A restore explicitly selects a new destination and may use new paths.
        for name in ('database-active.json','database-target.json'):
            if (data/name).is_file():shutil.copy2(data/name,bundle/name)
        # A fresh deployment has no ssh/ until its first server is added. Only
        # that zero-server state may be backed up as an explicit empty folder.
        if os.path.lexists(data/'ssh'):copy_tree(data/'ssh',bundle/'ssh')
        else:(bundle/'ssh').mkdir(mode=0o700)
        check_ssh(bundle/'ssh',hosts)
        copy_tree(tls,bundle/'tls')
        copy_tree(caddy_data,bundle/'caddy-data');copy_tree(caddy_config,bundle/'caddy-config')
        coverage={}
        for name in DURABLE_STATE:
            if os.path.lexists(data/name):
                copy_tree(data/name,bundle/name,private=True);coverage[name]=tree_inventory(bundle/name)
            else:coverage[name]=None
        (bundle/'manifest.json').write_text(json.dumps({'format':2,'database':backend,'ssh_hosts':sorted(hosts),'durable_state':coverage,'verified_archives':sorted(archives)}))
        read_manifest(bundle)
        # Stable relative archive path independent of temporary directory.
        run(['restic','backup','--tag','mrpatchy','bundle'],cwd=root)
        run(['restic','check','--read-data'])
def restore(snapshot,destination):
    remote();destination=Path(destination)
    if destination.exists() and any(destination.iterdir()):raise ValueError('Restore destination must be empty')
    destination.mkdir(mode=0o700,parents=True,exist_ok=True)
    run(['restic','restore',snapshot,'--target',str(destination),'--verify'])
    bundle=destination/'bundle'
    if not (bundle/'manifest.json').exists():
        candidates=list(destination.rglob('bundle/manifest.json'))
        if len(candidates)!=1:raise ValueError('Restore must contain exactly one recovery bundle')
        shutil.move(str(candidates[0].parent),str(bundle))
    manifest=read_manifest(bundle)
    if manifest['database']=='sqlite':
        open_sqlite(bundle/'database.sqlite').close()
    return bundle
def activate(bundle,data,tls,caddy_data,caddy_config,uid=10001):
    bundle=Path(bundle);data=Path(data);tls=Path(tls)
    if data.exists() and any(data.iterdir()) or tls.exists() and any(tls.iterdir()):raise ValueError('Activation requires empty app and TLS destinations')
    for location in (caddy_data,caddy_config):
        if Path(location).exists() and any(Path(location).iterdir()):raise ValueError('Caddy destinations must be empty')
    manifest=read_manifest(bundle)
    # Validate the whole bundle before touching destination volumes or MySQL.
    for name in ('secret.key','database.sql' if manifest['database']=='mysql' else 'database.sqlite'):
        if not (bundle/name).is_file() or (bundle/name).is_symlink():raise ValueError('Missing or unsafe bundle file: '+name)
    for name in ('ssh','tls','caddy-data','caddy-config'):
        folder=bundle/name
        if not folder.is_dir() or folder.is_symlink():raise ValueError('Missing or unsafe bundle directory: '+name)
        tree_inventory(folder)
    hosts=manifest.get('ssh_hosts',[])
    if not isinstance(hosts,list):raise ValueError('Unsupported backup format')
    hosts=set(hosts)
    if manifest['database']=='sqlite':
        from contextlib import closing
        with closing(open_sqlite(bundle/'database.sqlite')) as db:
            hosts|=sqlite_key_hosts(db)
            if manifest['format']==2:check_archives(bundle,sqlite_verified_archives(db))
    check_ssh(bundle/'ssh',hosts)
    data.mkdir(mode=0o700,parents=True,exist_ok=True)
    if manifest['database']=='mysql':
        url=make_url(os.environ['DATABASE_URL'])
        with tempfile.TemporaryDirectory() as temp:
            options=mysql_options(url,temp)
            existing=subprocess.check_output(['mysql','--defaults-extra-file='+str(options),'--batch','--skip-column-names','--execute=SHOW TABLES',url.database],text=True)
            if existing.strip():raise ValueError('Restore requires an empty MySQL database')
            with open(bundle/'database.sql','rb') as stream:run(['mysql','--defaults-extra-file='+str(options),url.database],stdin=stream)
    else:shutil.copy2(bundle/'database.sqlite',data/'mrpatchy.db')
    shutil.copy2(bundle/'secret.key',data/'secret.key');(data/'secret.key').chmod(0o600)
    if manifest['format']==2:
        for name in DURABLE_STATE:
            if manifest['durable_state'][name] is not None:copy_tree(bundle/name,data/name,private=True)
    copy_tree(bundle/'ssh',data/'ssh');(data/'ssh').chmod(0o700)
    if tls.exists():tls.rmdir()
    copy_tree(bundle/'tls',tls)
    for name,location in (('caddy-data',caddy_data),('caddy-config',caddy_config)):
        location=Path(location)
        if location.exists():location.rmdir()
        copy_tree(bundle/name,location)
    if os.geteuid()==0:
        for root in (data,tls):
            os.chown(root,uid,uid)
            for path in root.rglob('*'):os.chown(path,uid,uid)
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('action',choices=['backup','restore','activate','check','snapshots'])
    p.add_argument('--caddy-data');p.add_argument('--caddy-config');p.add_argument('--uid',type=int,default=10001)
    p.add_argument('--data');p.add_argument('--tls');p.add_argument('--destination');p.add_argument('--snapshot',default='latest');p.add_argument('--bundle')
    p.add_argument('--app-stopped',action='store_true');a=p.parse_args()
    if a.action in ('backup','activate') and not a.app_stopped:p.error('Stop all app and worker replicas and pass --app-stopped')
    if a.action=='backup':backup(a.data,a.tls,a.caddy_data,a.caddy_config)
    elif a.action=='restore':print(restore(a.snapshot,a.destination))
    elif a.action=='activate':activate(a.bundle,a.data,a.tls,a.caddy_data,a.caddy_config,a.uid)
    else:remote();run(['restic',a.action]+(['--read-data'] if a.action=='check' else []))
