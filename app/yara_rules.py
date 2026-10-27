"""Offline signed, expiring YARA source bundles; keys are controller-managed."""
import json
import os
from pathlib import Path
import re
import tempfile
import time
from .vendor import read_file,sha
from .process import bounded


def authenticate(bundle_id):
    if not re.fullmatch('[A-Za-z0-9_-]{1,64}',bundle_id):raise ValueError('Invalid YARA bundle ID')
    root=Path(os.getenv('DATA_DIR','/data'))/'yara-rules';directory=root/bundle_id
    if root.is_symlink() or directory.is_symlink():raise ValueError('Symlinked YARA bundle directory')
    key=read_file(root/'trustedkeys.gpg',4*1024*1024)
    manifest=read_file(directory/'manifest.json',16000);signature=read_file(directory/'manifest.json.sig',16000)
    source=read_file(directory/'rules.yar',128*1024)
    with tempfile.TemporaryDirectory() as tmp:
        for name,data in [('trustedkeys.gpg',key),('manifest.json',manifest),('signature',signature)]:
            (Path(tmp)/name).write_bytes(data)
        out,_=bounded(['gpgv','--homedir',tmp,'--keyring',str(Path(tmp)/'trustedkeys.gpg'),'--status-fd','1',str(Path(tmp)/'signature'),str(Path(tmp)/'manifest.json')],timeout=15,limit=64000)
        valid=[line.split() for line in out.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        if not valid or any(len(v)<10 or v[9] not in ('8','9','10','11') for v in valid):raise ValueError('YARA manifest requires a strong trusted signature')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('Duplicate YARA manifest key')
            result[k]=v
        return result
    meta=json.loads(manifest,object_pairs_hook=unique)
    if not isinstance(meta,dict) or set(meta)!={'version','sha256','issued','expires'} or type(meta['version']) is not int or meta['version']!=1:raise ValueError('Invalid YARA manifest')
    from target.agent import validate_yara_rules
    packet={'source':source.decode('utf-8'),'sha256':meta['sha256'],'issued':meta['issued'],'expires':meta['expires']}
    validate_yara_rules(packet)
    return packet,{'bundle_id':bundle_id,'manifest_sha256':sha(manifest),'rules_sha256':sha(source),'keyring_sha256':sha(key),
                   'signers':[v[2] for v in valid],'issued':meta['issued'],'expires':meta['expires'],'authenticated_at':time.time()}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('bundle_id');args=parser.parse_args()
    _,proof=authenticate(args.bundle_id);print(json.dumps(proof,indent=2))
