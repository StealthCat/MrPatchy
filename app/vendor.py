"""Offline Debian archive authentication, entirely on the controller."""
import email.utils
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import time


def sha(data):return hashlib.sha256(data).hexdigest()


def read_file(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:raise ValueError('Vendor bundle file type or size invalid')
        with os.fdopen(os.dup(fd),'rb') as stream:data=stream.read(limit+1)
        if len(data)>limit:raise ValueError('Vendor bundle file exceeds limit')
        return data
    finally:os.close(fd)


def fields(text):
    result={};key=None
    for line in text.splitlines():
        if line.startswith((' ','\t')) and key:result[key]+='\n'+line[1:];continue
        key,sep,value=line.partition(':')
        if not sep or key in result:raise ValueError('Malformed or duplicate metadata field')
        result[key]=value.strip()
    return result


def archive_files(data):
    """Read ar framing; tar members are streamed without filesystem extraction."""
    if data[:8]!=b'!<arch>\n':raise ValueError('Not a Debian archive')
    result={};offset=8
    while offset<len(data):
        header=data[offset:offset+60]
        if len(header)!=60 or header[58:]!=b'`\n':raise ValueError('Invalid ar header')
        size=int(header[48:58]);name=header[:16].decode('ascii').strip().rstrip('/')
        if size<0 or offset+60+size>len(data) or name in result:raise ValueError('Invalid ar member')
        result[name]=data[offset+60:offset+60+size];offset+=60+size+(size%2)
    if result.get('debian-binary')!=b'2.0\n':raise ValueError('Unsupported Debian archive')
    return result


def tar_members(data):
    total=0;started=time.monotonic()
    with tarfile.open(fileobj=io.BytesIO(data),mode='r|*') as archive:
        for count,member in enumerate(archive):
            total+=member.size
            if count>=2048 or member.size>32*1024*1024 or total>128*1024*1024 or time.monotonic()-started>20:
                raise ValueError('Vendor archive work limit exceeded')
            name=member.name.removeprefix('./')
            if name in ('','.'):continue
            if name.startswith('/') or any(p in ('','..','.') for p in name.split('/')) or len(name)>4095 or any(ord(c)<32 for c in name):
                raise ValueError('Unsafe vendor archive path')
            yield archive,member,'/'+name


def authenticate(bundle_id,now=None):
    """Keyring is operator-managed, separate from bundles and never read from target."""
    if not re.fullmatch('[A-Za-z0-9_-]{1,64}',bundle_id):raise ValueError('Invalid vendor bundle ID')
    root=Path(os.getenv('DATA_DIR','/data'))/'vendor-packages'
    # Reject aliases for operator-configured bundle directories too.
    if root.is_symlink() or (root/bundle_id).is_symlink():raise ValueError('Symlinked vendor bundle directory')
    directory=root/bundle_id
    keyring=read_file(root/'trustedkeys.gpg',4*1024*1024)
    release=read_file(directory/'Release',1024*1024)
    signature=read_file(directory/'Release.gpg',1024*1024)
    with tempfile.TemporaryDirectory() as tmp:
        for name,data in [('trustedkeys.gpg',keyring),('Release',release),('Release.gpg',signature)]:
            (Path(tmp)/name).write_bytes(data)
        result=subprocess.run(['gpgv','--homedir',tmp,'--keyring',str(Path(tmp)/'trustedkeys.gpg'),'--status-fd','1',str(Path(tmp)/'Release.gpg'),str(Path(tmp)/'Release')],capture_output=True,timeout=15)
        if result.returncode or b'[GNUPG:] VALIDSIG ' not in result.stdout:raise ValueError('Vendor Release signature verification failed')
        # Reject weak digest signatures, even if the local gpgv policy accepts them.
        signatures=[line.split() for line in result.stdout.decode().splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        if any(len(line)<10 or line[9] not in ('8','9','10','11') for line in signatures):raise ValueError('Weak vendor signature digest')
        signers=[line[2] for line in signatures]
    meta=fields(release.decode('utf-8'))
    now=time.time() if now is None else now
    def stamp(key):
        date=email.utils.parsedate_to_datetime(meta[key])
        if date.tzinfo is None:raise ValueError('Repository date lacks timezone')
        return date.timestamp()
    issued=stamp('Date')
    if issued>now+300 or now-issued>7*86400:raise ValueError('Vendor Release is stale or future dated')
    if 'Valid-Until' in meta and (stamp('Valid-Until')<now or stamp('Valid-Until')<issued):raise ValueError('Vendor Release expired')
    index=read_file(directory/'Packages',64*1024*1024)
    index_path=read_file(directory/'index-path',4096).decode().strip()
    matches=[line.split() for line in meta.get('SHA256','').splitlines() if len(line.split())==3 and line.split()[2]==index_path]
    if len(matches)!=1 or matches[0][:2]!=[sha(index),str(len(index))]:raise ValueError('Packages index is not authenticated by Release')
    artifact=read_file(directory/'package.deb',64*1024*1024)
    records=[fields(block) for block in index.decode('utf-8').strip().split('\n\n') if block.strip()]
    records=[r for r in records if r.get('SHA256')==sha(artifact) and r.get('Size')==str(len(artifact))]
    if len(records)!=1:raise ValueError('Package artifact is not uniquely authenticated by Packages')
    record=records[0]
    parts=archive_files(artifact)
    def section(prefix):
        rows=[v for k,v in parts.items() if k==prefix or k.startswith(prefix+'.')]
        if len(rows)!=1:raise ValueError('Missing or ambiguous package tar section')
        return rows[0]
    controls=[]
    for archive,member,path in tar_members(section('control.tar')):
        if path=='/control' and member.isfile():controls.append(fields(archive.extractfile(member).read().decode()))
    if len(controls)!=1 or any(controls[0].get(k)!=record.get(k) for k in ('Package','Version','Architecture')):
        raise ValueError('Artifact package identity mismatch')
    if not re.fullmatch('[a-z0-9][a-z0-9+.-]{0,199}',record['Package']) or not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',record['Architecture']):raise ValueError('Invalid vendor package identity')
    entries=[];seen=set();excluded=0
    for archive,member,path in tar_members(section('data.tar')):
        if path in seen:raise ValueError('Duplicate vendor path')
        seen.add(path)
        if member.isdir():continue
        if not member.isfile():excluded+=1;continue
        if len(entries)>=200:raise ValueError('Vendor regular-file limit exceeded (200)')
        entries.append({'path':path,'sha256':sha(archive.extractfile(member).read()),'size':member.size})
    if not entries:raise ValueError('Vendor artifact has no regular files')
    manifest={'package':record['Package'],'version':record['Version'],'architecture':record['Architecture'],'entries':entries}
    provenance={'bundle_id':bundle_id,'release_sha256':sha(release),'index_sha256':sha(index),'artifact_sha256':sha(artifact),
                'keyring_sha256':sha(keyring),'signers':signers,'release_date':issued,'authenticated_at':now,
                'origin':meta.get('Origin',''),'suite':meta.get('Suite',''),'codename':meta.get('Codename',''),
                'excluded_nonregular_entries':excluded,'scope':'Regular-file bytes only; no permissions, symlinks, maintainer-generated files or clean-host verdict.'}
    return manifest,provenance

def validate_receipt(manifest,result):
    if not isinstance(result,dict) or result.get('trust_basis')!='controller_authenticated_debian_artifact' or any(result.get(k)!=manifest[k] for k in ('package','version','architecture')):
        raise ValueError('Unsupported vendor receipt; update target helpers')
    state=result.get('state');count=len(manifest['entries']);examined=result.get('examined')
    if state not in ('incomplete','differences','matches_artifact_bytes') or type(examined) is not int or not 0<=examined<=count or result.get('scope_files')!=count:
        raise ValueError('Invalid vendor receipt scope')
    findings=result.get('findings');gaps=result.get('gaps')
    if not isinstance(findings,list) or len(findings)>count or not isinstance(gaps,list) or len(gaps)>21 or any(not isinstance(g,str) or len(g)>8192 for g in gaps):raise ValueError('Invalid vendor receipt coverage')
    expected={entry['path']:entry['sha256'] for entry in manifest['entries']};seen=set()
    for row in findings:
        if not isinstance(row,dict) or row.get('path') not in expected or row['path'] in seen or row.get('status') not in ('missing','content_differs'):raise ValueError('Invalid vendor finding')
        seen.add(row['path'])
        if row['status']=='content_differs' and (row.get('expected_sha256')!=expected[row['path']] or not re.fullmatch('[a-f0-9]{64}',row.get('observed_sha256',''))):raise ValueError('Invalid vendor finding digest')
    if len(findings)>examined or (state!='incomplete' and (gaps or examined!=count)) or (state=='matches_artifact_bytes' and findings) or (state=='differences' and not findings):raise ValueError('Contradictory vendor receipt')


if __name__=='__main__':
    import argparse
    import json
    parser=argparse.ArgumentParser(description='Authenticate and preview an offline vendor bundle without contacting a target')
    parser.add_argument('bundle_id')
    args=parser.parse_args()
    manifest,provenance=authenticate(args.bundle_id)
    print(json.dumps({'manifest':manifest,'authentication':provenance},indent=2))
