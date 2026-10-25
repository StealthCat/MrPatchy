"""Opt-in OSV queries using distro-specific source package versions."""
import re
import time
import httpx
from .apt import paragraphs

def ecosystem(os_release,inventory=None):
    values={}
    for line in os_release.splitlines():
        if '=' in line:
            key,value=line.split('=',1);values[key]=value.strip('"')
    inv=inventory or {}
    packages={p.get('Package') for p in paragraphs(inv.get('status',''))}
    if packages & {'raspberrypi-sys-mods','raspi-config'} or any(
            'raspberrypi.' in value.lower() or 'raspbian.' in value.lower()
            for value in inv.get('files',{}).values()):
        raise ValueError('No verified advisory ecosystem mapping for Raspberry Pi OS vendor packages/repositories')
    name=values.get('ID');version=values.get('VERSION_ID','')
    if name=='debian' and re.fullmatch(r'\d+',version):return 'Debian:'+version
    if name=='ubuntu' and re.fullmatch(r'\d{2}\.\d{2}',version):
        return 'Ubuntu:'+version+(':LTS' if version.endswith('.04') and int(version[:2])%2==0 else '')
    raise ValueError('No verified advisory ecosystem mapping for this OS; derivative distributions are not silently treated as Debian')

def scan(inventory,names):
    eco=ecosystem(inventory.get('os',''),inventory);queries=[];mapped=[]
    packages={p['Package']+':'+p['Architecture']:p for p in paragraphs(inventory['status']) if 'Package' in p and 'Architecture' in p}
    for name in names:
        package=packages.get(name)
        if not package:raise ValueError('Unknown installed package: '+name)
        source=package.get('Source',package['Package'])
        match=re.fullmatch(r'([a-z0-9+.-]+)(?: \(([^)]+)\))?',source)
        if not match:raise ValueError('Invalid source package metadata')
        query={'package':{'ecosystem':eco,'name':match[1]},'version':match[2] or package['Version']}
        queries.append(query);mapped.append({'binary':name,**query})
    results=[[] for _ in queries];pending=list(range(len(queries)))
    for page in range(10):
        if not pending:break
        response=httpx.post('https://api.osv.dev/v1/querybatch',json={'queries':[queries[i] for i in pending]},timeout=30,follow_redirects=False)
        response.raise_for_status()
        batch=response.json().get('results',[])
        if len(batch)!=len(pending):raise ValueError('Advisory service returned an incomplete batch')
        again=[]
        for index,item in zip(pending,batch):
            results[index].extend(item.get('vulns',[]))
            if item.get('next_page_token'):queries[index]['page_token']=item['next_page_token'];again.append(index)
        pending=again
    if pending:raise ValueError('Advisory pagination limit exceeded; no complete result stored')
    return {'checked':time.time(),'ecosystem':eco,'source':'https://osv.dev','results':[{**item,'vulnerabilities':v} for item,v in zip(mapped,results)],
            'coverage':'Matching advisory IDs, not proof that unlisted packages are safe. Review vendor advisories before selecting patches.'}
