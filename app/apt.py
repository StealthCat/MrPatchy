"""Run native APT centrally, with isolated state and target trust material.
Never import target apt.conf (hooks execute commands), or disable verification.
"""
import base64
import hashlib
import os
import pwd
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit
from .db import DATA

def paragraphs(text):
    for block in re.split(r'\n\s*\n',text.strip()):
        item={}; key=None
        for line in block.splitlines():
            if line.startswith('#'): continue
            if line[:1].isspace() and key: item[key]+='\n'+line
            elif ':' in line:
                key,value=line.split(':',1); item[key]=value.strip()
        if item: yield item

def installed(status):
    result=[]
    for p in paragraphs(status):
        state=p.get('Status','').split()
        if len(state)==3 and state[2]=='installed':
            result.append({'name':p['Package']+':'+p['Architecture'],'installed':p['Version'],'held':state[0]=='hold'})
    return result

def validate_source(content, deb822=False):
    # Fail visibly for unsafe trust overrides, local-file transports and unsupported options.
    if re.search(r'(?i)(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure|check-valid-until|check-date|valid-until-min|valid-until-max)\s*[:=]',content):
        raise ValueError('Repository weakens signature or expiry verification')
    if deb822:
        for block in paragraphs(content):
            if block.get('Enabled','yes').lower()=='no': continue
            if not set(block.get('Types','').split()) <= {'deb','deb-src'} or not block.get('Types'): raise ValueError('Invalid repository Types')
            if not block.get('Suites') or not block.get('URIs'): raise ValueError('Repository requires URIs and Suites')
            for uri in block['URIs'].split(): validate_uri(uri)
    else:
        for line in content.splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            m=re.match(r'^(deb|deb-src)\s+(?:\[[^\]]+\]\s+)?(\S+)\s+(\S+)',line)
            if not m: raise ValueError('Invalid one-line APT source')
            validate_uri(m[2])
    # Signed-By is remapped separately; inline armored keys are supported by APT.
    return content

def validate_uri(uri):
    parsed=urlsplit(uri)
    if parsed.scheme not in ('https','http') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Only HTTP(S) repositories without embedded credentials are supported')
    if any(x in uri for x in ['"','\\','\x00']): raise ValueError('Invalid repository URI')

def source_path(name):
    return name=='/etc/apt/sources.list' or bool(re.fullmatch(r'/etc/apt/sources\.list\.d/[A-Za-z0-9_.-]+\.(list|sources)',name))
def key_path(name):
    return name=='/etc/apt/trusted.gpg' or bool(re.fullmatch(r'/(etc/apt/(keyrings|trusted\.gpg\.d)|usr/share/keyrings)/[A-Za-z0-9_.+-]+\.(asc|gpg)',name))
def prepare(host_id, inv):
    root=DATA/'apt'/host_id; root.mkdir(parents=True,exist_ok=True)
    for d in ['etc/apt/sources.list.d','etc/apt/trusted.gpg.d','etc/apt/preferences.d','etc/apt/empty','var/lib/apt/lists/partial','var/cache/apt/archives/partial','var/lib/dpkg','var/log/apt']:
        (root/d).mkdir(parents=True,exist_ok=True)
    # Remove stale configuration, never stale lists silently after a failed refresh.
    for folder in ['sources.list.d','trusted.gpg.d','preferences.d']:
        for p in (root/'etc/apt'/folder).iterdir():
            if p.is_file(): p.unlink()
    for name in ['sources.list','trusted.gpg','preferences']:
        (root/'etc/apt'/name).unlink(missing_ok=True)
    for name,value in inv['keys'].items():
        if not key_path(name): continue
        p=root/name.lstrip('/'); p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(base64.b64decode(value,validate=True)); p.chmod(0o644)
    for name,value in inv['files'].items():
        if source_path(name):
            validate_source(value,name.endswith('.sources'))
            # Every absolute key path must resolve to captured signing material.
            refs=re.findall(r'/(?:etc/apt|usr/share/keyrings)/[^\s,\]"<>]+',value)
            for ref in sorted(set(refs),key=len,reverse=True):
                if not key_path(ref): raise ValueError('Unsupported signing key path: '+ref)
                value=value.replace(ref,str(root/ref.lstrip('/')))
        elif name!='/etc/apt/preferences' and not re.fullmatch(r'/etc/apt/preferences.d/[A-Za-z0-9_.-]+',name): continue
        p=root/name.lstrip('/'); p.write_text(value)
    (root/'var/lib/dpkg/status').write_text(inv['status'])
    arch=inv['architecture']; arches=[arch]+inv.get('foreign_architectures',[])
    if any(not re.fullmatch(r'[a-z0-9-]+',a) for a in arches): raise ValueError('Invalid architecture')
    cfg=root/'apt.conf'
    cfg.write_text(f'''Dir "{root}";
Dir::Etc "{root}/etc/apt";
Dir::Etc::main "-";
Dir::Etc::parts "{root}/etc/apt/empty";
Dir::State::status "{root}/var/lib/dpkg/status";
APT::Architecture "{arch}";
APT::Architectures {{ {' '.join(chr(34)+a+chr(34)+';' for a in arches)} }};
APT::Machine-ID "{inv.get('machine_id','') if re.fullmatch(r'[a-f0-9]{32}',inv.get('machine_id','')) else hashlib.sha256(host_id.encode()).hexdigest()[:32]}";
Acquire::Languages "none";
Acquire::Retries "1";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowUnauthenticated "false";
APT::Update::Error-Mode "any";
APT::Sandbox::User "{pwd.getpwuid(os.geteuid()).pw_name}";
''')
    return root,cfg

def run(cfg,args):
    p=subprocess.run(args,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','APT_CONFIG':str(cfg)},capture_output=True,text=True,timeout=900)
    if p.returncode: raise RuntimeError((p.stdout+p.stderr)[-16000:])
    return p.stdout

def parse_policy(text):
    result={}; current=None; version=None
    for line in text.splitlines():
        if line and not line.startswith(' ') and line.endswith(':'):
            current=line[:-1]; version=None; result[current]={'candidate':'','origin':''}
        elif current:
            if line.strip().startswith('Candidate:'):
                result[current]['candidate']=line.split(':',1)[1].strip()
            match=re.fullmatch(r'\s+(?:\*\*\* )?(\S+)\s+-?\d+',line)
            if match: version=match[1]
            elif version==result[current]['candidate'] and line.strip():
                result[current]['origin']+=line+'\n'
    return result

def refresh(host_id,inv):
    root,cfg=prepare(host_id,inv)
    log=run(cfg,['apt-get','update'])
    pkgs=installed(inv['status']); policies={}
    for offset in range(0,len(pkgs),150):
        policies.update(parse_policy(run(cfg,['apt-cache','policy',*[p['name'] for p in pkgs[offset:offset+150]]])))
    for p in pkgs:
        policy=policies.get(p['name'],policies.get(p['name'].split(':')[0],{}))
        candidate=policy.get('candidate',''); p['origin']=policy.get('origin','')
        # Native Debian comparison handles epochs, revisions and tildes correctly.
        newer=candidate not in ('','(none)') and subprocess.run(['dpkg','--compare-versions',candidate,'gt',p['installed']]).returncode==0
        p['candidate']=candidate if newer else ''
        # Feed absence is not a severity rating. Origin is a scheduling heuristic only.
        p['priority']='high' if newer and ('-security' in p['origin'] or '/security' in p['origin']) else 'normal'
    return pkgs,log
