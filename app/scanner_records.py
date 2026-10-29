"""Portable stored scanner evidence; no target I/O, raw file acquisition or purge."""
import hashlib
import time
import uuid
from types import SimpleNamespace
from sqlalchemy import select
from . import incidents,response_records as records

FIELDS={
    'scans':'id host_id created report',
    'incidents':'id host_id state created updated scan_id evidence',
    'incident_events':'id incident_id created actor kind details',
    'advisory_plans':'id incident_id created run_id state evidence_digest content approved_by expires',
}
FINDING='path sha256 device inode size uid mode rule_ids'
SIGNATURES='state built_at checked_at age_seconds max_age_seconds database_version expires'
RULES='bundle_id rules_sha256 manifest_sha256 keyring_sha256 issued expires signers'
CONTEXT='state engine engine_version version started finished scanned skipped gaps gaps_truncated signatures rule_bundle origin'


def project(value,fields):
    return {key:value[key] for key in fields.split() if key in value} if isinstance(value,dict) else {}


def finding(value):
    result=project(value,FINDING)
    if isinstance(value,dict) and 'scan_context' in value:result['scan_context']=project(value['scan_context'],CONTEXT)
    if 'scan_context' in result:
        context=result['scan_context']
        context['signatures']=project(context.get('signatures'),SIGNATURES)
        context['rule_bundle']=project(context.get('rule_bundle'),RULES)
    return result


def scan_report(value):
    result=project(value,'version state available engine engine_version started finished roots scanned skipped examined entries_examined gaps')
    if not isinstance(value,dict):return result
    if isinstance(value.get('findings'),list) and len(value['findings'])>100:raise records.ExportLimit('Scanner finding count exceeds its validated bound; no partial export was created')
    result['findings']=[finding(row) for row in value.get('findings',[]) if isinstance(row,dict)] if isinstance(value.get('findings'),list) else []
    result['signatures']=project(value.get('signatures'),SIGNATURES)
    result['rule_bundle']=project(value.get('rule_bundle'),RULES)
    if isinstance(value.get('automation'),dict):result['automation_kind']='verified_execution' if value['automation'].get('kind')=='verified_execution' else 'unknown'
    return result


def build(s,host,actor,reason):
    b=records.Builder(fields=FIELDS)
    parents=select(incidents.Incident.id).where(incidents.Incident.host_id==host.id)
    for name,model,condition in (
        ('scans',incidents.Scan,incidents.Scan.host_id==host.id),
        ('incidents',incidents.Incident,incidents.Incident.host_id==host.id),
        ('incident_events',incidents.IncidentEvent,incidents.IncidentEvent.incident_id.in_(parents)),
        ('advisory_plans',incidents.Plan,incidents.Plan.incident_id.in_(parents))):
        rows=s.scalars(select(model).where(condition).order_by(model.created,model.id).limit(records.MAX_SECTION_ROWS+1).execution_options(yield_per=1))
        def projected():
            for row in rows:
                b.check()
                value={field:getattr(row,field) for field in FIELDS[name].split()}
                if name=='scans':value['report']=scan_report(row.report)
                elif name=='incidents':value['evidence']=finding(row.evidence)
                elif name=='incident_events':value['details']=project(row.details,'scan_id plan_id run_id previous_state state from to reason verification')
                else:
                    if isinstance(row.content,dict) and isinstance(row.content.get('steps'),list) and len(row.content['steps'])>16:raise records.ExportLimit('Advisory step count exceeds its validated bound; no partial export was created')
                    value['content']=project(row.content,'summary severity uncertainty')
                    value['content']['steps']=[project(step,'action reason impact verification evidence_ids') for step in row.content.get('steps',[])] if isinstance(row.content,dict) and isinstance(row.content.get('steps'),list) else []
                yield SimpleNamespace(**value)
        try:b.add(name,projected())
        finally:rows.close()
    scan_ids={r['id'] for r in b.sections['scans']}
    missing=sorted({r['scan_id'] for r in b.sections['incidents'] if r['scan_id'] not in scan_ids})
    known=scan_ids|{r['id'] for r in b.sections['incidents']}
    references={e['details']['scan_id'] for e in b.sections['incident_events'] if isinstance(e['details'].get('scan_id'),str)}
    references.update(ref for p in b.sections['advisory_plans'] for step in p['content']['steps'] for ref in (step.get('evidence_ids') if isinstance(step.get('evidence_ids'),list) else []) if isinstance(ref,str))
    unresolved=sorted(references-known)
    record={'format':'mrpatchy-scanner-record','version':1,
        'export':{'id':str(uuid.uuid4()),'created':time.time(),'actor':actor,'reason':reason},
        'host':{'id':host.id,'name':host.name,'fingerprint':host.fingerprint,'enabled':host.enabled,'deleted_at':host.deleted_at},
        'scope':{'source':'controller_database_under_host_operation_lock','history_truncated':False,
            'missing_scan_references':missing,'primary_references_complete':not missing and not unresolved,'missing_evidence_references':unresolved,
            'projection':'allowlisted scanner receipt, finding, review and advisory metadata only',
            'excludes':['raw_scanner_output','file_bytes','credentials_and_connection_configuration','job_payloads_and_outputs',
                'execution_observations_and_triggers','startup_and_package_integrity_records','file_responses_and_custody','AI_usage_records','legacy_latest_settings','unattributed_orphan_events','live_host_verification'],
            'limits':{'section_rows':records.MAX_SECTION_ROWS,'total_rows':records.MAX_ROWS,'bytes':records.MAX_BYTES}},
        'monitoring':{},'sections':b.sections}
    integrity={'algorithm':'sha256','canonicalization':'python-json-sort-keys-ascii-compact-v1','record_sha256':records.sha256(record),
        'sections':{name:{'sha256':records.sha256(rows),'records':len(rows),'bytes':len(records.canonical(rows))} for name,rows in b.sections.items()},
        'meaning':'Hashes detect changes against an independently trusted digest; they do not authenticate the controller or prove historical completeness.'}
    data=records.canonical({'record':record,'integrity':integrity})+b'\n';b.check()
    if len(data)>records.MAX_BYTES:raise records.ExportLimit('Scanner record exceeds the 16 MiB limit; no partial export was created')
    return record['export']['id'],data,hashlib.sha256(data).hexdigest()
