"""Offline RPM authentication through native librpm tools in an isolated database."""
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import xml.etree.ElementTree as ET
from .process import bounded
from .vendor import read_file,sha

FIELDS={'package':'NAME','epoch':'EPOCHNUM','version':'VERSION','release':'RELEASE','architecture':'ARCH','algorithm':'FILEDIGESTALGO'}
ARRAYS={'paths':'FILENAMES','digests':'FILEDIGESTS','modes':'FILEMODES','flags':'FILEFLAGS','sizes':'FILESIZES','longsizes':'LONGFILESIZES'}
QUERY='<metadata>'+''.join('<'+key+'>%{'+tag+':xml}</'+key+'>' for key,tag in FIELDS.items())+''.join('<'+key+'>[%{'+tag+':xml}]</'+key+'>' for key,tag in ARRAYS.items())+'</metadata>'


def signature_ids(output):
    # A zero exit status alone also accepts unsigned RPMs on older librpm.
    # Require explicit strong signature AND payload/header digest successes.
    if re.search(r'\b(NOKEY|NOT OK|BAD|NOTTRUSTED|UNKNOWN)\b',output,re.I):raise ValueError('RPM signature or digest verification failed')
    signatures=re.findall(r'^\s*Header V[34] (?:RSA|DSA|ECDSA|EdDSA)/SHA(?:224|256|384|512) Signature, key ID ([a-f0-9]{8,64}): OK\s*$',output,re.M|re.I)
    if not signatures or not re.search(r'^\s*Header SHA256 digest: OK\b',output,re.M) or not re.search(r'^\s*Payload SHA256 digest: OK\b',output,re.M):
        raise ValueError('RPM requires an explicitly verified strong header signature and SHA256 header/payload digests')
    return sorted(set(value.lower() for value in signatures))


def metadata_manifest(output):
    if '<!DOCTYPE' in output.upper() or '<!ENTITY' in output.upper():raise ValueError('Unexpected XML declarations')
    root=ET.fromstring(output)
    if root.tag!='metadata' or len(root)!=len(FIELDS)+len(ARRAYS):raise ValueError('Invalid RPM metadata')
    values={}
    for node in root:
        if node.tag in values or node.tag not in FIELDS|ARRAYS or len(node)>2048 or any(child.tag not in ('string','integer') or len(child) for child in node):raise ValueError('Invalid RPM metadata tag')
        values[node.tag]=[child.text or '' for child in node]
    def scalar(name):
        if len(values[name])!=1:raise ValueError('Ambiguous RPM package identity')
        return values[name][0]
    package=scalar('package');arch=scalar('architecture');epoch=scalar('epoch');ver=scalar('version');release=scalar('release')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9+_.-]{0,199}',package) or not re.fullmatch('[A-Za-z0-9_]{1,64}',arch) or not re.fullmatch('[0-9]{1,10}',epoch):raise ValueError('Invalid RPM package identity')
    if any(not re.fullmatch('[A-Za-z0-9._+~^]{1,90}',item) for item in (ver,release)):raise ValueError('Invalid RPM version')
    if scalar('algorithm')!='8':raise ValueError('RPM file digests must use SHA256')
    count=len(values['paths'])
    if not 1<=count<=2048 or any(len(values[key])!=count for key in ('digests','modes','flags','sizes')):raise ValueError('RPM file metadata arrays do not match')
    if any(not re.fullmatch('[0-9]+',value) for key in ('sizes','modes','flags') for value in values[key]):raise ValueError('Invalid numeric RPM file metadata')
    sizes=values['sizes']
    if values['longsizes'] not in ([],['(none)']):
        sizes=values['longsizes']
        if len(sizes)!=count:raise ValueError('RPM long file sizes do not match')
    entries=[];seen=set();excluded=0;total=0
    for path,digest,mode,flags,size in zip(values['paths'],values['digests'],values['modes'],values['flags'],sizes):
        if not path.startswith('/') or path.startswith('//') or str(Path(path))!=path or '..' in Path(path).parts or path in seen or len(path)>4096 or any(ord(c)<32 for c in path):raise ValueError('Unsafe or duplicate RPM file path')
        seen.add(path)
        mode=int(mode);flags=int(flags);size=int(size)
        if mode<0 or flags<0 or size<0:raise ValueError('Invalid RPM file metadata')
        if not stat.S_ISREG(mode) or flags&64:
            if not stat.S_ISDIR(mode):excluded+=1
            continue
        total+=size
        if size>32*1024*1024 or total>128*1024*1024 or len(entries)>=200:raise ValueError('RPM regular-file work limit exceeded')
        if not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('Invalid RPM regular-file SHA256')
        entries.append({'path':path,'sha256':digest,'size':size})
    if not entries:raise ValueError('RPM has no comparable regular files')
    return {'package_manager':'rpm','package':package,'version':str(int(epoch))+':'+ver+'-'+release,'architecture':arch,'entries':entries},excluded


def authenticate(directory,root,bundle_id,now=None):
    artifact=read_file(directory/'package.rpm',64*1024*1024)
    keys=read_file(root/'rpm-trustedkeys.asc',4*1024*1024)
    with tempfile.TemporaryDirectory(prefix='patchy-rpm-') as tmp:
        tmp=Path(tmp);database=tmp/'rpmdb';database.mkdir()
        package=tmp/'package.rpm';package.write_bytes(artifact)
        keyfile=tmp/'trustedkeys.asc';keyfile.write_bytes(keys)
        environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':str(tmp),'LC_ALL':'C','TZ':'UTC'}
        common=['--noplugins','--dbpath',str(database),'--define','_keyring rpmdb']
        def command(binary,args):return bounded([binary,*common,*args],timeout=30,limit=1024*1024,env=environment)
        # No keys from the bundle, target or controller's normal RPM database.
        command('/usr/bin/rpmkeys',['--import',str(keyfile)])
        output,diagnostics=command('/usr/bin/rpmkeys',['--checksig','--verbose',str(package)])
        if diagnostics:raise ValueError('RPM verification produced diagnostics')
        key_ids=signature_ids(output)
        output,diagnostics=command('/usr/bin/rpm',['-qp','--qf',QUERY,'--',str(package)])
        if diagnostics:raise ValueError('RPM query produced diagnostics')
        manifest,excluded=metadata_manifest(output)
    return manifest,{'bundle_id':bundle_id,'artifact_sha256':sha(artifact),'keyring_sha256':sha(keys),
                     'signature_key_ids':key_ids,'authenticated_at':time.time() if now is None else now,
                     'authentication':'native_rpm_signature_and_sha256_digests','excluded_nonregular_or_ghost_entries':excluded,
                     'scope':'Signed SHA256 regular-file hashes; no permissions, ghost/generated files, symlinks or clean-host verdict.',
                     'limitations':['Offline package authentication does not establish current repository membership, support status or latest key revocations.']}
