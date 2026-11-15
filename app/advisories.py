"""Opt-in OSV queries using distro-specific source package versions."""
import concurrent.futures
import hashlib
import re
import time
import httpx
from sqlalchemy import Double, Integer, String, Text, case, func, select
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base
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
    'evidence of exploitation, and "uncertain" is never treated as safe. Published and modified dates come from the '
    'advisory record: they are not the vendor fix date or the time exposure began, and an unknown date is left blank. '
    'Review vendor advisories before selecting patches.')
# A record date this far past the scan clock is treated as invalid rather than trusted.
RECORD_DATE_SKEW=86400
_RFC3339=re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})')

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

def record_date(value,now):
    """Return an OSV RFC 3339 timestamp as epoch seconds, or None when it cannot be trusted.

    Only timezone-qualified values are accepted; dates before 1990 or more than
    RECORD_DATE_SKEW past ``now`` are rejected instead of guessed.
    """
    if not isinstance(value,str) or len(value)>40 or not _RFC3339.fullmatch(value):return None
    from datetime import datetime  # local: keeps the module import block unchanged
    text=value[:-1]+'+00:00' if value.endswith('Z') else value
    head,_,tail=text.partition('.')
    if tail:text=head+'.'+tail[:-6][:6].ljust(6,'0')+tail[-6:]  # normalize to microseconds
    try:stamp=datetime.fromisoformat(text).timestamp()
    except (ValueError,OverflowError):return None
    if stamp<631152000 or stamp>now+RECORD_DATE_SKEW:return None
    return stamp

def _applicability(vuln,records,eco,package,version,now=None):
    now=time.time() if now is None else now
    advisory_id=vuln.get('id') if isinstance(vuln,dict) else None
    record=records.get(advisory_id) if isinstance(advisory_id,str) else None
    dates={'published_at':None,'modified_at':None}
    if isinstance(record,dict):
        dates={'published_at':record_date(record.get('published'),now),'modified_at':record_date(record.get('modified'),now)}
        try:return {**cve_exposure.classify(record,eco,package,version),**dates}
        except Exception:  # noqa: BLE001 - classify is total, but never let a defect read as safe
            reason='Applicability could not be established'
    else:reason=record or 'Advisory ID is missing or invalid'
    return {'advisory_id':advisory_id if isinstance(advisory_id,str) and _ADVISORY_ID.fullmatch(advisory_id) else None,
            'cve_ids':[],'status':cve_exposure.UNCERTAIN,'reason':reason,'fixed_version':None,'fix_available':False,**dates}

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
# Durable per-server exposure history (roadmap D, #858). The ``advisories:<host>``
# setting holds only the latest scan; this ledger keeps every advisory/source
# package pair a scan ever classified as affected, so patching never erases the
# fact or the window of exposure.
OPEN='open'
RESOLVED_STATUSES=(cve_exposure.FIXED,cve_exposure.UNAFFECTED)
NOT_LISTED='not-listed'  # the advisory service no longer matched the installed version
HISTORY_LIMIT=500
HISTORY_COVERAGE=('Exposure history records when a manual advisory scan first and last classified each advisory as '
    'affecting the installed source version, and when a later scan of the same package first observed a fixed or '
    'unaffected version, or the advisory was no longer listed for the installed version. Times between scans are '
    'telemetry gaps: exposure may have started before the first affected scan (advisory publication is not shown here) '
    'and ended at any point before the resolving scan. Version resolution is not verified effective installation: '
    'required service restarts or reboots are not confirmed. "uncertain" never resolves an exposure, and packages not '
    'included in a scan are never resolved by it. This is version applicability, not evidence of exploitation.')


class ExposureHistory(Base):
    __tablename__='cve_exposure_history'
    id: Mapped[str]=mapped_column(String(64),primary_key=True)
    host_id: Mapped[str]=mapped_column(String(36),index=True)
    advisory_id: Mapped[str]=mapped_column(String(128))
    package: Mapped[str]=mapped_column(String(255))
    ecosystem: Mapped[str]=mapped_column(String(64),default='')
    cve_ids: Mapped[str]=mapped_column(Text,default='')
    first_affected_at: Mapped[float]=mapped_column(Double,default=0)
    first_affected_version: Mapped[str]=mapped_column(Text,default='')
    last_affected_at: Mapped[float]=mapped_column(Double,default=0)
    last_affected_version: Mapped[str]=mapped_column(Text,default='')
    fixed_version: Mapped[str]=mapped_column(Text,default='')
    last_observed_at: Mapped[float]=mapped_column(Double,default=0)
    last_status: Mapped[str]=mapped_column(String(20),default='')
    resolved_at: Mapped[float]=mapped_column(Double,default=0)
    resolved_version: Mapped[str]=mapped_column(Text,default='')
    resolved_status: Mapped[str]=mapped_column(String(20),default='')
    reopened: Mapped[int]=mapped_column(Integer,default=0)


def _history_id(host_id,advisory_id,package):
    return hashlib.sha256('\0'.join((host_id,advisory_id,package)).encode()).hexdigest()


# Within one scan several binaries can share a source package; the most
# exposed classification wins so an affected binary is never hidden.
_RANK={cve_exposure.AFFECTED:3,cve_exposure.UNCERTAIN:2,cve_exposure.FIXED:1,cve_exposure.UNAFFECTED:1}


def _observations(result):
    """Return ``(scanned, seen)`` from one complete scan result.

    ``scanned`` maps each checked source package to its installed version.
    ``seen`` maps (advisory, package) to the strongest row for that pair.
    """
    scanned={};seen={}
    for item in result.get('results') or ():
        package=(item.get('package') or {}).get('name') if isinstance(item,dict) else None
        version=item.get('version') if isinstance(item,dict) else None
        if not isinstance(package,str) or not isinstance(version,str) or not 0<len(package)<=255:continue
        previous=scanned.get(package)
        scanned[package]=version if previous in (None,version) else None  # conflicting versions cannot resolve
        for row in item.get('applicability') or ():
            if not isinstance(row,dict) or row.get('status') not in _RANK:continue
            advisory_id=row.get('advisory_id')
            if not isinstance(advisory_id,str) or not _ADVISORY_ID.fullmatch(advisory_id):continue
            key=(advisory_id,package);current=seen.get(key)
            if current is None or _RANK[row['status']]>_RANK[current[0]['status']]:seen[key]=(row,version)
    return scanned,seen


def record_history(session,host_id,result,now=None):
    """Fold one complete scan into the durable ledger; the caller commits.

    Only packages in this scan are considered. Affected opens (or reopens) an
    exposure; fixed/unaffected, or the advisory no longer being listed for a
    scanned package, resolves an open one; uncertain changes nothing but the
    last observation.
    """
    now=time.time() if now is None else now
    scanned,seen=_observations(result)
    if not scanned:return
    eco=result.get('ecosystem') if isinstance(result.get('ecosystem'),str) else ''
    rows={(row.advisory_id,row.package):row for row in session.scalars(select(ExposureHistory).where(
        ExposureHistory.host_id==host_id,ExposureHistory.package.in_(sorted(scanned))))}
    for (advisory_id,package),(observed,version) in seen.items():
        status=observed['status'];entry=rows.get((advisory_id,package))
        if status!=cve_exposure.AFFECTED and entry is None:continue  # only ever-affected pairs are tracked
        if entry is None:
            entry=ExposureHistory(id=_history_id(host_id,advisory_id,package),host_id=host_id,advisory_id=advisory_id,
                package=package,first_affected_at=now,first_affected_version=version,resolved_at=0,reopened=0)
            session.add(entry);rows[(advisory_id,package)]=entry
        entry.ecosystem=eco[:64];entry.last_observed_at=now;entry.last_status=status
        cves=[c for c in observed.get('cve_ids') or () if isinstance(c,str)]
        if cves:entry.cve_ids=','.join(sorted(set(cves)))[:2000]
        if status==cve_exposure.AFFECTED:
            if entry.resolved_at:
                entry.reopened=(entry.reopened or 0)+1
                entry.resolved_at=0;entry.resolved_version='';entry.resolved_status=''
            entry.last_affected_at=now;entry.last_affected_version=version
            entry.fixed_version=observed.get('fixed_version') if isinstance(observed.get('fixed_version'),str) else ''
        elif status in RESOLVED_STATUSES and not entry.resolved_at:
            entry.resolved_at=now;entry.resolved_version=version;entry.resolved_status=status
    for (advisory_id,package),entry in rows.items():
        if (advisory_id,package) in seen or entry.resolved_at:continue
        version=scanned.get(package)
        if version is None:continue  # binaries of one source disagreed; do not resolve
        entry.last_observed_at=now;entry.last_status=NOT_LISTED
        entry.resolved_at=now;entry.resolved_version=version;entry.resolved_status=NOT_LISTED


def history(session,host_id,limit=HISTORY_LIMIT):
    # Open exposures sort first so the page cap never hides one behind newer
    # resolved pairs, and the open total is counted independently of the cap.
    rows=session.scalars(select(ExposureHistory).where(ExposureHistory.host_id==host_id).order_by(
        case((ExposureHistory.resolved_at==0,0),else_=1),ExposureHistory.first_affected_at.desc(),
        ExposureHistory.id).limit(limit+1)).all()
    open_count=session.scalar(select(func.count()).select_from(ExposureHistory).where(
        ExposureHistory.host_id==host_id,ExposureHistory.resolved_at==0)) or 0
    items=[{'advisory_id':row.advisory_id,'package':row.package,'ecosystem':row.ecosystem,
            'cve_ids':[c for c in (row.cve_ids or '').split(',') if c],'state':'resolved' if row.resolved_at else OPEN,
            'first_affected_at':row.first_affected_at,'first_affected_version':row.first_affected_version,
            'last_affected_at':row.last_affected_at,'last_affected_version':row.last_affected_version,
            'fixed_version':row.fixed_version or None,'last_observed_at':row.last_observed_at,'last_status':row.last_status,
            'resolved_at':row.resolved_at or None,'resolved_version':row.resolved_version or None,
            'resolved_status':row.resolved_status or None,'reopened':row.reopened or 0} for row in rows[:limit]]
    return {'items':items,'truncated':len(rows)>limit,'open':int(open_count),
            'coverage':HISTORY_COVERAGE}
