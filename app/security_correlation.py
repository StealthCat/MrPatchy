"""Bounded, read-only incident pivots. Identity matches do not establish causation."""
import math
import re
import time
from sqlalchemy import select
from .db import Observation
from .incidents import Scan,Inspection,digest

PAGE_SIZE=50
ENTRY_LIMIT=256


def mapping(value):return value if isinstance(value,dict) else {}
def items(value):return value if isinstance(value,list) else []
def sha(value):return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None


def match(entry,path,hash_value,*,executable=False,vendor=False):
    entry=mapping(entry)
    found_path=entry.get('executable' if executable else 'path')
    found_hash=entry.get('observed_sha256' if vendor else 'sha256')
    path_match=isinstance(found_path,str) and found_path==path
    hash_match=sha(found_hash) and found_hash==hash_value
    if not path_match and not hash_match:return None
    result={'path':found_path[:4096] if isinstance(found_path,str) else '',
        'sha256':found_hash if sha(found_hash) else None,
        'relation':'path_and_hash' if path_match and hash_match else 'hash' if hash_match else 'path_different_hash' if sha(found_hash) else 'path_only'}
    # Whitelisted metadata only: never expose arguments, environment, contents or raw logs.
    for key in ('uid','pid'):
        if type(entry.get(key)) is int and entry[key]>=0:result[key]=entry[key]
    if executable:
        result['identity_verified']=entry.get('identity_verified') is True
        capture=entry.get('capture')
        result['capture']=capture if isinstance(capture,str) and capture in ('ebpf','procfs','sample') else 'unknown'
    return result


def entries(source,report):
    report=mapping(report)
    if source=='scans':return [(e,False,False,'Scanner finding') for e in items(report.get('findings'))[:100]]
    if source=='executions':return [(e,True,False,'Execution') for e in items(report.get('processes'))[:ENTRY_LIMIT]]
    result=[(e,False,False,'Startup / custom inventory') for e in items(mapping(report.get('persistence')).get('entries'))[:ENTRY_LIMIT]]
    result.extend((e,False,True,'Authenticated vendor comparison') for e in items(mapping(report.get('vendor_verification')).get('findings'))[:200])
    for package in items(report.get('packages'))[:16]:result.extend((e,False,False,'Local package database discrepancy') for e in items(mapping(package).get('findings'))[:200])
    return result


def page(s,incident,offset=0,as_of=None,expected_digest=''):
    now=time.time();as_of=now if as_of is None else as_of
    if not math.isfinite(as_of) or not 0<=as_of<=now+5:raise ValueError('Invalid evidence time boundary')
    evidence=mapping(incident.evidence);path=evidence.get('path');hash_value=evidence.get('sha256')
    if not isinstance(path,str) or not path.startswith('/') or len(path)>4096 or not sha(hash_value):raise ValueError('Incident has no valid file identity to correlate')
    revision=digest({'scan_id':incident.scan_id,'evidence':evidence})
    if expected_digest and expected_digest!=revision:raise ValueError('Incident evidence changed; reopen related evidence')
    sources={};results=[]
    for source,model,column in (('scans',Scan,Scan.created),('executions',Observation,Observation.received),('inspections',Inspection,Inspection.created)):
        rows=list(s.scalars(select(model).where(model.host_id==incident.host_id,column<=as_of).order_by(column.desc(),model.id).offset(offset).limit(PAGE_SIZE+1)))
        more=len(rows)>PAGE_SIZE;rows=rows[:PAGE_SIZE];omitted=0;limited=0
        for row in rows:
            report=row.evidence if source=='executions' else row.report
            candidates=entries(source,report)
            # Historical or imported reports may exceed current producer bounds.
            report_map=mapping(report)
            if source=='executions':omitted+=max(0,len(items(report_map.get('processes')))-ENTRY_LIMIT)
            elif source=='scans':omitted+=max(0,len(items(report_map.get('findings')))-100)
            else:
                omitted+=max(0,len(items(mapping(report_map.get('persistence')).get('entries')))-ENTRY_LIMIT)
                omitted+=max(0,len(items(mapping(report_map.get('vendor_verification')).get('findings')))-200)
                packages=items(report_map.get('packages'))
                omitted+=max(0,len(packages)-16)
                omitted+=sum(max(0,len(items(mapping(p).get('findings')))-200) for p in packages[:16])
            matches=[value|{'kind':kind} for entry,executable,vendor,kind in candidates if (value:=match(entry,path,hash_value,executable=executable,vendor=vendor)) is not None]
            gaps=items(mapping(report).get('gaps'))
            if source=='inspections':
                for section in [mapping(report).get('persistence'),mapping(report).get('vendor_verification'),*items(mapping(report).get('packages'))[:16]]:
                    gaps=gaps+items(mapping(section).get('gaps'))
            if not isinstance(report,dict) or gaps or (source!='executions' and mapping(report).get('state') not in ('collected','no_detections','completed_with_findings')):limited+=1
            if matches:
                results.append({'source':source,'id':row.id,'received':row.received if source=='executions' else row.created,
                    'observed':row.observed if source=='executions' else None,
                    'state':str(mapping(report).get('state','recorded'))[:80],
                    'matches':matches[:5],'matches_omitted':max(0,len(matches)-5),
                    'gaps':[str(g)[:500] for g in gaps[:5]],'gaps_omitted':max(0,len(gaps)-5)})
        sources[source]={'examined':len(rows),'more':more,'entries_omitted':omitted,'limited_receipts':limited}
    results.sort(key=lambda r:(-r['received'],r['source'],r['id']))
    return {'incident_id':incident.id,'evidence_digest':revision,'path':path,'sha256':hash_value,'as_of':as_of,'offset':offset,
        'page_size':PAGE_SIZE,'sources':sources,'items':results,'more':any(v['more'] for v in sources.values())}
