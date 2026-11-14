"""Opt-in OSV queries using distro-specific source package versions."""
import concurrent.futures
import re
import time
import httpx
from .apt import paragraphs
from . import cve_exposure

# Full OSV records are needed for range data: querybatch returns IDs only.
MAX_DETAIL_FETCHES=200
# Wall-clock budget for all detail fetches in one synchronous scan; later records become uncertain.
DETAIL_FETCH_DEADLINE=60
# Concurrent detail fetches sharing one pooled client; bounds and fail-closed results are unchanged.
DETAIL_FETCH_WORKERS=8
OSV_VULN_URL='https://api.osv.dev/v1/vulns/'
_ADVISORY_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}')
STATUSES=(cve_exposure.AFFECTED,cve_exposure.FIXED,cve_exposure.UNAFFECTED,cve_exposure.UNCERTAIN)
COVERAGE=('Matching advisory IDs, not proof that unlisted packages are safe. Applicability compares the installed '
    'source version with this distribution release\'s vendor ranges only; "affected" is version applicability, not '
    'evidence of exploitation, and "uncertain" is never treated as safe. Review vendor advisories before selecting patches.')

def ecosystem(os_release,inventory=None):
    values={}
    for line in os_release.splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key,value=line.split('=',1);values[key.strip()]=value.strip().strip('"').strip("'")
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
    if inventory.get('package_manager')=='rpm':raise ValueError('RPM priority comes from repository updateinfo; Debian/Ubuntu OSV matching is not applicable')
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
    records=_fetch_records({v.get('id') for vulns in results for v in vulns if isinstance(v,dict)})
    summary=dict.fromkeys(STATUSES,0);items=[]
    for item,vulns in zip(mapped,results):
        applicability=[_applicability(v,records,eco,item['package']['name'],item['version']) for v in vulns]
        for row in applicability:summary[row['status']]+=1
        items.append({**item,'vulnerabilities':vulns,'applicability':applicability})
    return {'checked':time.time(),'ecosystem':eco,'source':'https://osv.dev','results':items,'summary':summary,'coverage':COVERAGE}

def _detail_client():
    """One pooled client per scan; connection limits match the worker pool."""
    limits=httpx.Limits(max_connections=DETAIL_FETCH_WORKERS,max_keepalive_connections=DETAIL_FETCH_WORKERS)
    return httpx.Client(follow_redirects=False,limits=limits)

def _fetch_one(client,advisory_id,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:
        return 'Advisory detail time budget of '+str(DETAIL_FETCH_DEADLINE)+' seconds per scan was reached'
    try:
        response=client.get(OSV_VULN_URL+advisory_id,timeout=min(30,remaining),follow_redirects=False)
        response.raise_for_status();record=response.json()
    except Exception:  # noqa: BLE001 - any retrieval failure is uncertainty, never safety
        return 'Advisory detail could not be retrieved'
    if not isinstance(record,dict) or record.get('id')!=advisory_id:
        return 'Advisory detail did not match the requested record'
    return record

def _fetch_records(ids):
    """Fetch full OSV records by ID concurrently; a missing entry or reason string means uncertain."""
    records={};valid=sorted(i for i in ids if isinstance(i,str) and _ADVISORY_ID.fullmatch(i))
    for advisory_id in valid[MAX_DETAIL_FETCHES:]:
        records[advisory_id]='Advisory detail limit of '+str(MAX_DETAIL_FETCHES)+' records per scan was reached'
    selected=valid[:MAX_DETAIL_FETCHES]
    if not selected:return records
    deadline=time.monotonic()+DETAIL_FETCH_DEADLINE
    client=_detail_client()
    try:
        # Each task rechecks the shared deadline when it starts, so queued fetches past the
        # budget are never sent; per-request timeouts keep in-flight work inside it.
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DETAIL_FETCH_WORKERS,len(selected)),
                                                   thread_name_prefix='osv-detail') as pool:
            futures={advisory_id:pool.submit(_fetch_one,client,advisory_id,deadline) for advisory_id in selected}
            for advisory_id,future in futures.items():records[advisory_id]=future.result()
    finally:client.close()
    return records

def _applicability(vuln,records,eco,package,version):
    advisory_id=vuln.get('id') if isinstance(vuln,dict) else None
    record=records.get(advisory_id) if isinstance(advisory_id,str) else None
    if isinstance(record,dict):
        try:return cve_exposure.classify(record,eco,package,version)
        except Exception:  # noqa: BLE001 - classify is total, but never let a defect read as safe
            reason='Applicability could not be established'
    else:reason=record or 'Advisory ID is missing or invalid'
    return {'advisory_id':advisory_id if isinstance(advisory_id,str) and _ADVISORY_ID.fullmatch(advisory_id) else None,
            'cve_ids':[],'status':cve_exposure.UNCERTAIN,'reason':reason,'fixed_version':None,'fix_available':False}

def retained(result):
    """Return a stored scan result with uncertainty reasons reduced to fixed text.

    Results stored before #798 may contain raw comparator exception text; this
    read-side pass keeps those records uncertain while never returning that text.
    """
    if not isinstance(result,dict) or not isinstance(result.get('results'),list):return result
    items=[]
    for item in result['results']:
        if isinstance(item,dict) and isinstance(item.get('applicability'),list):
            item={**item,'applicability':[{**row,'reason':cve_exposure.sanitize_reason(row.get('reason'))}
                if isinstance(row,dict) and 'reason' in row else row for row in item['applicability']]}
        items.append(item)
    return {**result,'results':items}
