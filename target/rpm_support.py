#!/usr/bin/python3
"""RPM inventory and DNF4 transactions. No target plugins or shell execution."""
import base64
import configparser
import fnmatch
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import shutil
import ssl
import urllib.request
import time
from urllib.parse import urlsplit

NAME = r'[A-Za-z0-9][A-Za-z0-9_.+\-]*'
ARCH = r'[A-Za-z0-9_]+'
EVR = r'(?:[0-9]+:)?[A-Za-z0-9._+~^]+-[A-Za-z0-9._+~^]+'
KEY_ROOT = '/etc/pki/rpm-gpg/'
REPO_ROOT = '/etc/yum.repos.d/'
MAIN_FILES = ('/etc/dnf/dnf.conf','/etc/yum.conf')
LOCK_FILES = ('/etc/dnf/plugins/versionlock.list','/etc/yum/pluginconf.d/versionlock.list','/etc/dnf/versionlock.toml')


def source_path(name): return bool(re.fullmatch(r'/etc/yum\.repos\.d/[A-Za-z0-9_.-]+\.repo',name))
def key_path(name): return bool(re.fullmatch(r'/etc/pki/rpm-gpg/[A-Za-z0-9_.+\-]+',name)) and '..' not in Path(name).parts

def parse(text):
    cfg=configparser.ConfigParser(interpolation=None,strict=True,inline_comment_prefixes=('#',';'))
    try: cfg.read_string(text)
    except configparser.Error as error: raise ValueError('Invalid RPM repository configuration: '+str(error)) from error
    if cfg.defaults(): raise ValueError('RPM INI defaults are not supported')
    return cfg


def truth(value):
    if str(value).lower() not in ('0','1','true','false','yes','no','on','off'):raise ValueError('Invalid repository boolean')
    return str(value).lower() in ('1','true','yes','on')


def expand(value, variables):
    def replace(match):
        key=match[1] or match[2]
        if key not in variables: raise ValueError('Unknown RPM repository variable: '+key)
        result=str(variables[key])
        if not re.fullmatch(r'[A-Za-z0-9_./-]{0,200}',result):raise ValueError('Unsafe RPM repository variable: '+key)
        return result
    return re.sub(r'\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z0-9_]+)',replace,value)


def url(value):
    parsed=urlsplit(value)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or any(c.isspace() or c in '\x00"\\' for c in value):
        raise ValueError('RPM repositories require HTTP(S) URLs without embedded credentials')
    return value


def repositories(files, variables):
    allowed={'name','enabled','baseurl','metalink','mirrorlist','gpgkey','gpgcheck','repo_gpgcheck','sslverify',
             'exclude','excludepkgs','includepkgs','priority','cost','module_hotfixes','metadata_expire',
             'sslcacert','skip_if_unavailable','countme','enabled_metadata','timeout','retries','minrate','bandwidth','throttle','ip_resolve','type'}
    main=validate_main({'files':files})
    inherited={k:main.get('main',k) for k in ('gpgcheck','repo_gpgcheck','sslverify','sslcacert') if main and main.has_option('main',k)}
    result=[];ids=set()
    for path,text in files.items():
        if not source_path(path):continue
        cfg=parse(text)
        for name in cfg.sections():
            if not re.fullmatch(NAME,name) or name in ids:raise ValueError('Duplicate or invalid RPM repository ID: '+name)
            ids.add(name);item={**inherited,**dict(cfg[name])}
            if not truth(item.get('enabled','1')):continue
            unknown=set(item)-allowed
            if unknown:raise ValueError('Unsupported active RPM repository options: '+', '.join(sorted(unknown)))
            if not truth(item.get('gpgcheck','1')) or not truth(item.get('sslverify','1')):
                raise ValueError('RPM package signature and TLS verification must remain enabled')
            values={key:expand(item.get(key,''),variables).split() for key in ('baseurl','metalink','mirrorlist','gpgkey')}
            if not any(values[key] for key in ('baseurl','metalink','mirrorlist')):raise ValueError('RPM repository requires baseurl, metalink or mirrorlist')
            for key in ('metalink','mirrorlist'):
                if len(values[key])>1:raise ValueError('Only one '+key+' URL is allowed')
            signed=truth(item.get('repo_gpgcheck','0'))
            for key in ('baseurl','metalink','mirrorlist'):
                for uri in values[key]:
                    url(uri)
                    if uri.startswith('http:') and not signed:raise ValueError('Unsigned RPM metadata must use HTTPS (or enable repo_gpgcheck)')
            for uri in values['gpgkey']:
                if not uri.startswith('file://') or not key_path(uri[7:]):raise ValueError('RPM signing keys must reference captured /etc/pki/rpm-gpg files; import remote keys through a trusted channel first')
            result.append({'id':name,'path':path,**item,**values,'repo_gpgcheck':signed})
    return result


def evr(value):
    if not re.fullmatch(EVR,value):raise ValueError('Invalid RPM epoch/version/release')
    epoch,sep,version=value.partition(':')
    if not sep:epoch,version='0',epoch
    version,release=version.rsplit('-',1)
    return epoch,version,release


def compare(a,b):
    import rpm
    return rpm.labelCompare(evr(a),evr(b))


def installed(inv):
    groups={}
    for p in inv.get('rpm_packages',[]):
        if not re.fullmatch(NAME,p['name']) or not re.fullmatch(ARCH,p['arch']):raise ValueError('Invalid RPM package identity')
        evr(p['evr']);key=p['name']+':'+p['arch']
        groups.setdefault(key,[]).append(p)
    result=[]
    for key,values in sorted(groups.items()):
        latest=max(values,key=functools.cmp_to_key(lambda a,b:compare(a['evr'],b['evr'])))
        result.append({'name':key,'installed':latest['evr'],'held':any(p.get('held') for p in values),
                       'dpkg_state':'install ok installed','installed_versions':sorted({p['evr'] for p in values})})
    return result


def redact_config(text):
    # Preserve layout while preventing common DNF credentials entering inventory/history.
    text=re.sub(r'(?im)^(\s*(?:password|proxy_password)\s*=).*$',r'\1[redacted]',text)
    return re.sub(r'(?i)(https?://)[^\s/@]+@',r'\1[redacted]@',text)


def local_inventory():
    import rpm
    files={};keys={};variables={}
    patterns=['/etc/yum.repos.d/*.repo','/etc/dnf/modules.d/*.module',*MAIN_FILES,*LOCK_FILES,
              '/etc/dnf/plugins/versionlock.conf','/etc/yum/pluginconf.d/versionlock.conf','/etc/dnf/vars/*','/etc/yum/vars/*']
    import glob
    for pattern in patterns:
        for name in glob.glob(pattern):
            p=Path(name)
            if p.is_file():
                if p.stat().st_size>2_000_000:raise ValueError('RPM configuration too large: '+name)
                files[name]=redact_config(p.read_text()) if source_path(name) or name in MAIN_FILES else p.read_text()
                if '/vars/' in name:variables[p.name]=files[name].strip()
    for name in glob.glob(KEY_ROOT+'*'):
        p=Path(name)
        if key_path(name) and p.is_file() and p.stat().st_size<2_000_000:keys[name]=base64.b64encode(p.read_bytes()).decode()
    info={k:v.strip().strip('"') for k,v in (line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)}
    arch=rpm.expandMacro('%{_arch}')
    import dnf.rpm
    releasever=variables.get('releasever') or dnf.rpm.detect_releasever('/') or info.get('VERSION_ID','').split('.')[0]
    variables.update(basearch=dnf.rpm.basearch(arch),arch=arch,releasever=releasever,
                     releasever_major=releasever.split('.')[0],releasever_minor=releasever.partition('.')[2])
    held=[]
    for name in ('/etc/dnf/plugins/versionlock.conf','/etc/yum/pluginconf.d/versionlock.conf'):
        if name in files:
            cfg=parse(files[name]);locklist=cfg.get('main','locklist',fallback='')
            if locklist and locklist not in LOCK_FILES:raise ValueError('Custom RPM versionlock path is unsupported; use the standard versionlock list')
    for name in LOCK_FILES[:2]:
        for line in files.get(name,'').splitlines():
            line=line.strip()
            if not line or line.startswith('#'):continue
            # Conservative: preserve every named package, even locks allowing some versions.
            pattern=re.sub(r'^!?\d+:','',line).rsplit('-',2)[0]
            if not pattern or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+-*?' for c in pattern):raise ValueError('Unsupported versionlock expression')
            held.append(pattern)
    if files.get(LOCK_FILES[2]):
        try:import tomllib
        except ImportError:raise ValueError('DNF5 versionlock inventory requires Python 3.11+')
        for item in tomllib.loads(files[LOCK_FILES[2]]).get('packages',[]):held.append(item['name'])
    packages=[]
    for h in rpm.TransactionSet().dbMatch():
        if h['name']=='gpg-pubkey':continue
        packages.append({'name':h['name'],'arch':h['arch'],'evr':str(h['epoch'] or 0)+':'+h['version']+'-'+h['release'],
                         'held':any(fnmatch.fnmatchcase(h['name'],pattern) for pattern in held)})
    packages.sort(key=lambda p:(p['name'],p['arch'],p['evr']))
    return {'package_manager':'rpm','rpm_packages':packages,'rpm_vars':variables,'module_platform_id':info.get('PLATFORM_ID',''),
            'os':Path('/etc/os-release').read_text(),'architecture':arch,'foreign_architectures':[],
            'status':json.dumps(packages,sort_keys=True),'files':files,'keys':keys,
            'machine_id':Path('/etc/machine-id').read_text().strip(),'collected':time.time()}


def validate_main(inv):
    main=next((parse(inv['files'][p]) for p in MAIN_FILES if p in inv['files']),None)
    if main and main.has_section('main'):
        if any(main.get('main',k,fallback='').strip() for k in ('password','username','proxy_password','proxy_username','sslclientcert','sslclientkey')):raise ValueError('Target DNF credentials/client certificates require a supported repository access adapter')
        if main.get('main','reposdir',fallback=REPO_ROOT).rstrip('/')!=REPO_ROOT.rstrip('/'):raise ValueError('Custom RPM reposdir is not supported; use /etc/yum.repos.d')
        if set(main.get('main','tsflags',fallback='').replace(',',' ').split())-{'nodocs'}:raise ValueError('Unsafe RPM tsflags require manual review (only nodocs is supported)')
    return main


def secure_mirrors(uri, ca=None, proxy=None):
    """An HTTPS mirror list is trustworthy only when its selected mirrors are too."""
    class HTTPSOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            if not newurl.startswith('https://'):raise ValueError('Insecure mirror-list redirect')
            return super().redirect_request(request,fp,code,msg,headers,newurl)
    if not uri.startswith('https://'):raise ValueError('Unsigned RPM mirror lists require HTTPS')
    context=ssl.create_default_context(cafile=str(ca) if ca else None)
    opener=urllib.request.build_opener(HTTPSOnly(),urllib.request.HTTPSHandler(context=context),
                                      urllib.request.ProxyHandler({'http':proxy,'https':proxy} if proxy else {}))
    with opener.open(uri,timeout=30) as response:content=response.read(2_000_001)
    if len(content)>2_000_000:raise ValueError('RPM mirror list exceeds size limit')
    result=[url(line.strip()) for line in content.decode().splitlines() if line.strip().startswith('https://')]
    if not result:raise ValueError('RPM mirror list contains no verified HTTPS mirrors; use an HTTPS baseurl or signed repository metadata')
    return result[:50]


def central_base(inv, root, access):
    import dnf
    root=Path(root);root.mkdir(parents=True,exist_ok=True);root.chmod(0o700)
    key_digest=hashlib.sha256(json.dumps(inv['keys'],sort_keys=True).encode()).hexdigest()
    stamp=root/'key-digest'
    if not stamp.exists() or stamp.read_text()!=key_digest:
        # libdnf's cached keyring must not retain a key removed from inventory.
        for directory in ('cache','persist'):shutil.rmtree(root/directory,ignore_errors=True)
        stamp.write_text(key_digest)
    for name in ('cache','persist','log'):(root/name).mkdir(parents=True,exist_ok=True)
    base=dnf.Base()
    base.conf.installroot=str(root)
    base.conf.cachedir=str(root/'cache');base.conf.persistdir=str(root/'persist');base.conf.logdir=str(root/'log')
    base.conf.reposdir=[];base.conf.plugins=False;base.conf.gpgcheck=True;base.conf.localpkg_gpgcheck=True
    base.conf.arch=inv['architecture'];base.conf.substitutions.update(inv['rpm_vars'])
    if inv.get('module_platform_id'):base.conf.module_platform_id=inv['module_platform_id']
    shutil.rmtree(root/'etc/dnf/modules.d',ignore_errors=True)
    for path,text in inv['files'].items():
        if re.fullmatch(r'/etc/dnf/modules\.d/[A-Za-z0-9_.-]+\.module',path):
            target=root/path.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
    main=validate_main(inv)
    if main and main.has_section('main'):
        base.conf.excludepkgs=main.get('main','exclude',fallback=main.get('main','excludepkgs',fallback='')).split()
        base.conf.includepkgs=main.get('main','includepkgs',fallback='').split()
    if access.get('default_release'):raise ValueError('APT default-release is not applicable to RPM; use target release variables')
    ca=root/'repository-ca.pem'
    if access.get('ca'):ca.write_text(access['ca']);ca.chmod(0o600)
    for item in repositories(inv['files'],inv['rpm_vars']):
        repo=dnf.repo.Repo(item['id'],base.conf)
        def remap(value):
            result=url(access.get('mirrors',{}).get(value,value))
            if result.startswith('http:') and not item['repo_gpgcheck']:raise ValueError('Unsigned RPM metadata mirrors must use HTTPS')
            return result
        repo.baseurl=[remap(v) for v in item['baseurl']]
        if item['metalink']:repo.metalink=remap(item['metalink'][0])
        if item['mirrorlist']:repo.mirrorlist=remap(item['mirrorlist'][0])
        repo.gpgcheck=True;repo.repo_gpgcheck=item['repo_gpgcheck'];repo.sslverify=True;repo.skip_if_unavailable=False
        repo.metadata_expire=0;repo.timeout=30;repo.retries=1
        repo.excludepkgs=item.get('excludepkgs',item.get('exclude','')).split();repo.includepkgs=item.get('includepkgs','').split()
        repo.priority=int(item.get('priority','99'));repo.cost=int(item.get('cost','1000'))
        repo.module_hotfixes=truth(item.get('module_hotfixes','0'))
        keyfiles=[]
        for uri in item['gpgkey']:
            name=uri[7:]
            if name not in inv['keys']:raise ValueError('RPM signing key was not captured: '+name)
            path=root/('key-'+hashlib.sha256(name.encode()).hexdigest()+'.asc')
            path.write_bytes(base64.b64decode(inv['keys'][name],validate=True));path.chmod(0o600);keyfiles.append(path.as_uri())
        repo.gpgkey=keyfiles
        if access.get('proxy'):repo.proxy=access['proxy']
        if item.get('sslcacert') and not access.get('ca'):raise ValueError('Upload the private repository CA under central Repository access')
        if access.get('ca'):repo.sslcacert=str(ca)
        for credentials in access.get('credentials',[]):
            scope=credentials['machine'].rstrip('/')
            matching=repo.baseurl and all(v==scope or v.startswith(scope+'/') for v in repo.baseurl)
            if matching:
                if item['metalink'] or item['mirrorlist']:raise ValueError('Scoped RPM credentials require direct baseurl, not mirrors')
                repo.username=credentials['login'];repo.password=credentials['password']
        if item['mirrorlist'] and not item['repo_gpgcheck']:
            repo.baseurl=secure_mirrors(repo.mirrorlist,ca if access.get('ca') else None,access.get('proxy'));repo.mirrorlist=''
        # Match DNF --refresh; metadata_expire=0 alone can reuse a same-second cache.
        repo._repo.expire()
        base.repos.add(repo);repo.enable()
    base.fill_sack(load_system_repo=False,load_available_repos=True)
    return base


def discover(inv, root, access):
    import hawkey
    packages=installed(inv);by_name={p['name']:p for p in packages}
    with central_base(inv,root,access) as base:
        choices={}
        for pkg in base.sack.query().available().filter(name=list({p['name'].rsplit(':',1)[0] for p in packages})):
            key=pkg.name+':'+pkg.arch
            if key not in by_name:continue
            old=choices.get(key)
            if old is None or pkg.repo.priority<old.repo.priority or pkg.repo.priority==old.repo.priority and compare(pkg.evr,old.evr)>0:choices[key]=pkg
        for row in packages:
            candidate=choices.get(row['name']);row.update(candidate='',origin='',priority='normal')
            if candidate is None or row['held'] or compare(candidate.evr,row['installed'])<=0:continue
            row['candidate']=str(candidate.epoch)+':'+candidate.version+'-'+candidate.release
            row['origin']=candidate.reponame
            # Advisory severity is metadata, not an AI classification.
            for advisory in candidate.get_advisories(hawkey.EQ | hawkey.LT | hawkey.GT):
                if not any(p.name==candidate.name and p.arch==candidate.arch and
                           compare(p.evr,row['installed'])>0 and compare(p.evr,candidate.evr)<=0 for p in advisory.packages):continue
                severity=str(advisory.severity or '').lower()
                if severity=='critical':row['priority']='critical'
                elif row['priority']!='critical' and (severity in ('important','high') or advisory.type==hawkey.ADVISORY_SECURITY):row['priority']='high'
    return packages


def patch(specs):
    import dnf
    inv=local_inventory()
    # Fail closed for unsupported trust/settings instead of silently ignoring them.
    definitions={r['id']:r for r in repositories(inv['files'],inv['rpm_vars'])};main_config=validate_main(inv)
    current={p['name']:p for p in installed(inv)}
    if not isinstance(specs,list) or not 1<=len(specs)<=500 or len(set(specs))!=len(specs):raise ValueError('Explicit RPM package:arch=epoch:version-release list required')
    with dnf.Base() as base:
        base.conf.read();base.conf.plugins=False;base.conf.gpgcheck=True;base.conf.localpkg_gpgcheck=True
        base.conf.tsflags=main_config.get('main','tsflags',fallback='').replace(',',' ').split() if main_config else []
        base.conf.assumeyes=False;base.conf.installonly_limit=0
        base.read_all_repos()
        for repo in base.repos.iter_enabled():
            if repo.id not in definitions:raise ValueError('Uncaptured active RPM repository: '+repo.id)
            repo.gpgcheck=True;repo.sslverify=True;repo.skip_if_unavailable=False;repo.metadata_expire=0
            repo._repo.expire()
            item=definitions[repo.id]
            if item['mirrorlist'] and not item['repo_gpgcheck']:
                repo.baseurl=secure_mirrors(item['mirrorlist'][0],item.get('sslcacert'),repo.proxy or None);repo.mirrorlist=''
        base.fill_sack()
        expected={}
        for spec in specs:
            if not isinstance(spec,str) or not re.fullmatch(NAME+':'+ARCH+'='+EVR,spec):raise ValueError('Invalid RPM patch specification')
            name,value=spec.rsplit('=',1);pkgname,arch=name.rsplit(':',1);record=current.get(name)
            if not record or record['held'] or compare(value,record['installed'])<=0:raise ValueError('RPM is absent, version-locked, or not an upgrade: '+name)
            candidates=[p for p in base.sack.query().available().filter(name=pkgname,arch=arch) if compare(p.evr,value)==0]
            if not candidates:raise ValueError('Exact RPM version unavailable: '+spec)
            selected=min(candidates,key=lambda p:(p.repo.priority,p.repo.cost,p.reponame));base.package_upgrade(selected);expected[name]=value
        base.resolve(allow_erasing=False)
        additions={p.name+':'+p.arch:p for p in base.transaction.install_set}
        for name,value in expected.items():
            if name not in additions or compare(additions[name].evr,value)!=0:raise ValueError('DNF changed an explicitly approved RPM candidate')
        for removed in base.transaction.remove_set:
            replacement=additions.get(removed.name+':'+removed.arch)
            if replacement is None or compare(replacement.evr,removed.evr)<0:raise ValueError('RPM removal, obsoleting replacement or downgrade is prohibited')
        for name,pkg in additions.items():
            if name in current and (current[name]['held'] or compare(pkg.evr,current[name]['installed'])<0):raise ValueError('Dependency transaction would alter a locked RPM or downgrade')
        base.download_packages(base.transaction.install_set)
        for pkg in base.transaction.install_set:
            result,message=base.package_signature_check(pkg)
            if result:raise ValueError('RPM signature verification failed; import the trusted signing key before retrying: '+str(message))
        base.do_transaction()
    # Conservatively request reboot for changed core runtime/kernel packages, only when policy permits.
    reboot=any(name.rsplit(':',1)[0] in ('kernel','kernel-core','glibc','systemd','linux-firmware') for name in additions)
    if reboot:Path('/opt/drpatch/rpm-reboot-required').write_text(Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    return {'output':'DNF completed verified exact-version upgrades: '+', '.join(specs),'reboot_required':reboot}


def main():
    request=json.loads(Path(sys.argv[1]).read_text());action=request['action']
    if action=='installed':result=installed(request['inventory'])
    elif action=='compare':result=[compare(a,b)>0 for a,b in request['pairs']]
    elif action=='discover':result=discover(request['inventory'],request['root'],request.get('access',{}))
    else:raise ValueError('Unknown native RPM operation')
    print(json.dumps(result))


if __name__=='__main__':main()
