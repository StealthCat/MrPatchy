"""Stored fleet scan coverage, independently assessed per engine; no target I/O."""
import math
import time
from sqlalchemy import select,func,case
from .db import Host,Setting,Job
from .incidents import Scan,Incident

ENGINES=('ClamAV','YARA')


def number(value):return type(value) in (int,float) and math.isfinite(value)


def assessment(scan,attempt,now,max_age):
    result={'state':'never_scanned','scan_id':None,'created':None,'age_seconds':None,'overdue':True,'signatures':'unknown','findings':0,'scanned':0,'gaps':[],'roots':[],
            'last_attempt':{'id':attempt.id,'state':attempt.state,'created':attempt.created} if attempt else None}
    if scan:
        report=scan.report if isinstance(scan.report,dict) else {}
        age=now-scan.created
        result.update(scan_id=scan.id,created=scan.created,age_seconds=max(0,age),overdue=not 0<=age<=max_age)
        for name in ('scanned','findings'):
            value=report.get(name)
            result[name]=len(value) if name=='findings' and isinstance(value,list) else value if name=='scanned' and type(value) is int and value>=0 else 0
        result['roots']=[p[:4096] for p in report.get('roots',[])[:16] if isinstance(p,str)] if isinstance(report.get('roots'),list) else []
        result['gaps']=[str(g)[:500] for g in report.get('gaps',[])[:5]] if isinstance(report.get('gaps'),list) else ['Invalid coverage metadata']
        sig=report.get('signatures');sig=sig if isinstance(sig,dict) else {}
        signature='unknown'
        if sig.get('state') in ('recent','stale','future','changed','unknown'):signature=sig['state']
        if signature=='recent':
            if report.get('engine')=='YARA':
                if not number(sig.get('expires')) or sig['expires']<=now:signature='stale'
                elif number(sig.get('built_at')) and sig['built_at']>now+300:signature='future'
            else:
                built=sig.get('built_at')
                signature='unknown' if not number(built) else 'future' if built>now+300 else 'stale' if now-built>7*86400 else 'recent'
        result['signatures']=signature
        valid=(report.get('state') in ('no_detections','completed_with_findings') and report.get('available') is True
            and signature=='recent' and report.get('gaps')==[] and type(report.get('scanned')) is int and report['scanned']>=0
            and isinstance(report.get('findings'),list) and (report['state']=='completed_with_findings')==bool(report['findings']))
        result['state']='findings' if result['findings'] else 'incomplete' if not valid else 'overdue' if result['overdue'] else 'recorded'
    if attempt and (not scan or attempt.created>=scan.created):
        if attempt.state in ('failed','blocked','interrupted','recovery_required'):result['state']='attempt_failed'
        elif attempt.state in ('queued','running'):result['state']='pending'
        elif attempt.state=='complete' and (not scan or attempt.id!=scan.id):result['state']='receipt_missing'
    return result


def page(s,offset=0,limit=50,q='',now=None):
    now=time.time() if now is None else now
    query=select(Host).where(Host.deleted_at==0)
    if q:query=query.where(Host.name.contains(q,autoescape=True))
    hosts=list(s.scalars(query.order_by(Host.name,Host.id).offset(offset).limit(limit+1)))
    more=len(hosts)>limit;hosts=hosts[:limit];ids=[h.id for h in hosts]
    if not ids:return {'items':[],'more':False,'generated_at':now,'summary':{'servers':0,'disabled':0,'open_incidents':0}}
    engine=Scan.report['engine'].as_string()
    ranked=select(Scan.id,func.row_number().over(partition_by=(Scan.host_id,engine),order_by=(Scan.created.desc(),Scan.id)).label('rank')).where(Scan.host_id.in_(ids),engine.in_(ENGINES)).subquery()
    scans={(row.host_id,row.report['engine']):row for row in s.scalars(select(Scan).where(Scan.id.in_(select(ranked.c.id).where(ranked.c.rank==1))))}
    job_engine=case((Job.action=='yara-scan','YARA'),else_='ClamAV')
    ranked_jobs=select(Job.id,func.row_number().over(partition_by=(Job.host_id,job_engine),order_by=(Job.created.desc(),Job.id)).label('rank')).where(Job.host_id.in_(ids),Job.action.in_(('security-scan','execution-scan','yara-scan'))).subquery()
    attempts={(r.host_id,'YARA' if r.action=='yara-scan' else 'ClamAV'):r for r in s.scalars(select(Job).where(Job.id.in_(select(ranked_jobs.c.id).where(ranked_jobs.c.rank==1))))}
    counts=dict(s.execute(select(Incident.host_id,func.count()).where(Incident.host_id.in_(ids),Incident.state.in_(('open','acknowledged'))).group_by(Incident.host_id)).all())
    policies={r.key.split(':',1)[1]:r.value for r in s.scalars(select(Setting).where(Setting.key.in_(['security-policy:'+h for h in ids])))}
    items=[]
    for host in hosts:
        policy=policies.get(host.id,{})
        hours=policy.get('interval_hours',24) if policy.get('enabled') else 24
        hours=hours if type(hours) is int and 1<=hours<=720 else 24
        items.append({'id':host.id,'name':host.name,'enabled':host.enabled,'last_seen':host.last_seen,'open_incidents':counts.get(host.id,0),
            'expected_hours':hours,'engines':{e:assessment(scans.get((host.id,e)),attempts.get((host.id,e)),now,(hours if e=='ClamAV' else 24)*3600) for e in ENGINES}})
    return {'items':items,'more':more,'generated_at':now,'summary':{'servers':len(items),'disabled':sum(not h.enabled for h in hosts),'open_incidents':sum(i['open_incidents'] for i in items)}}
