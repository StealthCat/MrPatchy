"""Pure co-location / failure-domain classification (first slice of #444).

Read-only: no database, route, dispatch or runtime authorization. Unknown, stale or
unproven placement never counts as independent or safe.
"""
FRESH_SECONDS=300
PROOF_SOURCES=('registration','agent_inventory','provider')
SOURCES=PROOF_SOURCES+('config','manual')
CONFIDENCE=('verified','declared','inferred')


def _observation(c,now,fresh):
    host=c.get('host_identity');src=c.get('source');conf=c.get('confidence')
    at=c.get('observed_at')
    if not isinstance(host,str) or not host.strip():return 'unknown'
    if src not in SOURCES or conf not in CONFIDENCE or not isinstance(at,(int,float)) or isinstance(at,bool):return 'unknown'
    if now-at>fresh or at>now+fresh:return 'stale'
    # A name/address match alone is never proof; only authenticated sources at verified confidence count.
    return 'verified' if src in PROOF_SOURCES and conf=='verified' else 'unverified'


def classify(components,now,fresh_seconds=FRESH_SECONDS):
    """Return per-component placement with manual corrections never overriding fresh conflicting proof."""
    rows={}
    for c in components:
        cid=c.get('id')
        if not isinstance(cid,str) or not cid:raise ValueError('component id required')
        if cid in rows and c.get('source')!='manual' and rows[cid]['source']!='manual':raise ValueError('duplicate component: '+cid)
        row={'id':cid,'kind':c.get('kind'),'required':bool(c.get('required',True)),'source':c.get('source'),
             'host_identity':c.get('host_identity'),'storage_id':c.get('storage_id'),'state':_observation(c,now,fresh_seconds)}
        old=rows.get(cid)
        if old is not None:
            auto,manual=(old,row) if row['source']=='manual' else (row,old)
            if auto['state']=='verified' and auto['host_identity']!=manual['host_identity']:
                auto['conflict']=True;rows[cid]=auto;continue
            if auto['state']!='verified':
                rows[cid]=manual;continue
            rows[cid]=auto;continue
        rows[cid]=row
    return [rows[k] for k in sorted(rows)]


def failure_domains(rows):
    """Group only verified components; shared storage merges host domains."""
    parent={}
    def find(x):
        parent.setdefault(x,x)
        while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
        return x
    for r in rows:
        if r['state']!='verified':continue
        h=find('host:'+r['host_identity'])
        if r.get('storage_id'):parent[find('storage:'+r['storage_id'])]=h
    groups={}
    for r in rows:
        if r['state']=='verified':groups.setdefault(find('host:'+r['host_identity']),[]).append(r['id'])
    return sorted(sorted(v) for v in groups.values())


def redundancy(rows,kind,minimum=2):
    """Verdict for one component kind: independent only with `minimum` distinct proven failure domains."""
    members=[r for r in rows if r['kind']==kind]
    domains=failure_domains(members)
    unproven=sorted(r['id'] for r in members if r['state']!='verified')
    ok=len(domains)>=minimum
    return {'kind':kind,'independent':ok,'domains':domains,'unproven':unproven,
            'reason':'independent' if ok else ('co-located or insufficient proven failure domains' if domains else 'no proven placement')}
