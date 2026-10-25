#!/usr/bin/env python3
"""Encrypted off-host app/TLS/DB recovery through restic. Run with all app/workers stopped."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
from sqlalchemy.engine import make_url

def run(args,**kwargs):return subprocess.run(args,check=True,**kwargs)
def remote():
    repo=os.environ.get('RESTIC_REPOSITORY','')
    if not repo.startswith(('sftp:','s3:','rest:https://','b2:','azure:','gs:')):raise ValueError('Configure an off-host RESTIC_REPOSITORY')
    if not os.environ.get('RESTIC_PASSWORD_FILE'):raise ValueError('Use RESTIC_PASSWORD_FILE')
def copy_tree(source,destination):
    source=Path(source)
    if source.is_symlink():raise ValueError('Refusing symlink source')
    for path in source.rglob('*'):
        if path.is_symlink():raise ValueError('Refusing symlink: '+str(path))
    shutil.copytree(source,destination)
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
def backup(data,tls,caddy_data,caddy_config):
    remote()
    with tempfile.TemporaryDirectory(prefix='mrpatchy-recovery-') as temporary:
        root=Path(temporary);bundle=root/'bundle';bundle.mkdir(mode=0o700)
        data=Path(data);url=make_url(os.getenv('DATABASE_URL','sqlite:///'+str(data/'mrpatchy.db')))
        if url.get_backend_name()=='sqlite':
            with sqlite3.connect(url.database) as source,sqlite3.connect(bundle/'database.sqlite') as destination:source.backup(destination)
            backend='sqlite'
        elif url.get_backend_name()=='mysql':
            options=mysql_options(url,root)
            with open(bundle/'database.sql','wb') as stream:
                run(['mysqldump','--defaults-extra-file='+str(options),'--single-transaction','--routines','--events','--triggers','--hex-blob',url.database],stdout=stream)
            backend='mysql'
        else:raise ValueError('Unsupported database')
        shutil.copy2(data/'secret.key',bundle/'secret.key')
        copy_tree(data/'ssh',bundle/'ssh');copy_tree(tls,bundle/'tls')
        copy_tree(caddy_data,bundle/'caddy-data');copy_tree(caddy_config,bundle/'caddy-config')
        (bundle/'manifest.json').write_text(json.dumps({'format':1,'database':backend}))
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
    manifest=json.loads((bundle/'manifest.json').read_text())
    if manifest.get('format')!=1:raise ValueError('Unsupported backup format')
    if manifest['database']=='sqlite':
        with sqlite3.connect(bundle/'database.sqlite') as db:
            if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Database integrity check failed')
    return bundle
def activate(bundle,data,tls,caddy_data,caddy_config,uid=10001):
    bundle=Path(bundle);data=Path(data);tls=Path(tls)
    if data.exists() and any(data.iterdir()) or tls.exists() and any(tls.iterdir()):raise ValueError('Activation requires empty app and TLS destinations')
    for location in (caddy_data,caddy_config):
        if Path(location).exists() and any(Path(location).iterdir()):raise ValueError('Caddy destinations must be empty')
    manifest=json.loads((bundle/'manifest.json').read_text())
    data.mkdir(mode=0o700,parents=True,exist_ok=True)
    if manifest['database']=='mysql':
        url=make_url(os.environ['DATABASE_URL'])
        with tempfile.TemporaryDirectory() as temp:
            options=mysql_options(url,temp)
            existing=subprocess.check_output(['mysql','--defaults-extra-file='+str(options),'--batch','--skip-column-names','--execute=SHOW TABLES',url.database],text=True)
            if existing.strip():raise ValueError('Restore requires an empty MySQL database')
            with open(bundle/'database.sql','rb') as stream:run(['mysql','--defaults-extra-file='+str(options),url.database],stdin=stream)
    else:shutil.copy2(bundle/'database.sqlite',data/'mrpatchy.db')
    shutil.copy2(bundle/'secret.key',data/'secret.key');copy_tree(bundle/'ssh',data/'ssh')
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
