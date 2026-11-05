"""Pure, read-only classification of scheduled automation that may interfere with Mr Patchy.

This is the evidence contract only. It performs no discovery, never executes or sources
anything, changes nothing on a host and uses no AI. Inputs are normalized records produced
elsewhere; behavior tags describe what the entry's *effective configuration* does, never its
filename. A disable plan built here is a proposal that always requires explicit approval.
"""
from .incidents import digest

RULES_VERSION=1
# behavior tag -> evidence kinds that tag can plausibly explain (the versioned rule catalog)
RULES={
    'runs_package_manager':{'id':'R1','kinds':('lock_contention','interrupted_job'),'why':'runs a package manager that holds the native transaction lock'},
    'runs_firmware_updater':{'id':'R2','kinds':('lock_contention','interrupted_job'),'why':'runs a firmware updater that can hold device or transaction locks'},
    'reboots_host':{'id':'R3','kinds':('interrupted_job','connectivity_loss'),'why':'reboots the host on its own schedule'},
    'stops_managed_helper':{'id':'R4','kinds':('interrupted_job','state_drift'),'why':'stops or replaces Mr Patchy helpers'},
    'rewrites_managed_config':{'id':'R5','kinds':('state_drift',),'why':'rewrites managed repositories or configuration'},
    'changes_access_network':{'id':'R6','kinds':('connectivity_loss',),'why':'changes access or network settings'},
}
EVIDENCE_KINDS=('lock_contention','interrupted_job','state_drift','connectivity_loss')
OPERATIONS=('patch','release','reboot','firmware','recovery')
STATES=('observed','likely','insufficient_evidence')
# Only mechanisms where one trigger can be addressed without touching unrelated automation.
SUPPORTED_MECHANISMS=('cron_entry','systemd_timer')
ACTIONS=('prevent_future_starts','stop_active','terminate_process')
GAPS=[
    'Classification uses supplied effective-configuration behavior tags; unfamiliar scripts and overlapping schedules alone are never treated as proof.',
    'A finding describes operational interference, never intent: legitimate administrative automation can conflict.',
    'Alternative activation paths are not enumerated here; disabling one trigger does not prove every trigger is disabled.',
]
MAX_ENTRIES=500
MAX_EVIDENCE=500


def _tags(entry):
    unknown=set(entry.get('behaviors') or ())-set(RULES)
    if unknown:raise ValueError('Unknown behavior tag: '+sorted(unknown)[0])
    return sorted(entry.get('behaviors') or ())


def _check(entries,evidence):
    if len(entries)>MAX_ENTRIES or len(evidence)>MAX_EVIDENCE:raise ValueError('Too many automation records')
    ids=set()
    for e in entries:
        if not isinstance(e.get('entry_id'),str) or not e['entry_id'] or e['entry_id'] in ids:raise ValueError('Automation entry ids must be unique non-empty strings')
        ids.add(e['entry_id'])
        if not isinstance(e.get('digest'),str) or len(e['digest'])!=64:raise ValueError('Automation entry needs a sha256 digest')
        _tags(e)
    for v in evidence:
        if v.get('kind') not in EVIDENCE_KINDS:raise ValueError('Unknown evidence kind')
        if v.get('operation') not in OPERATIONS:raise ValueError('Unknown affected operation')
        if not isinstance(v.get('observed_at'),(int,float)):raise ValueError('Evidence needs observed_at')


def classify(entries,evidence,upcoming=()):
    """Return deterministic findings. `upcoming` is a list of {operation, window_start, window_end}
    maintenance windows; an enabled entry whose rule covers the operation and whose next run falls
    inside the window is `likely`. Observed requires evidence linked to that exact entry."""
    _check(entries,evidence)
    findings=[]
    for e in sorted(entries,key=lambda x:x['entry_id']):
        tags=_tags(e);refs=[];state='insufficient_evidence';rule=None;ops=set();reason='No linked interference evidence or conflicting behavior.'
        for t in tags:
            for v in evidence:
                if v.get('entry_id')==e['entry_id'] and v['kind'] in RULES[t]['kinds']:
                    refs.append({'kind':v['kind'],'operation':v['operation'],'observed_at':v['observed_at'],'job_id':v.get('job_id')});ops.add(v['operation']);rule=rule or RULES[t]
        if refs:
            state='observed';reason='Linked evidence shows this entry '+rule['why']+' during an affected operation.'
        elif tags and e.get('enabled') is not False and e.get('next_run') is not None:
            for w in upcoming:
                if w.get('operation') in OPERATIONS and w['window_start']<=e['next_run']<=w['window_end']:
                    ops.add(w['operation']);rule=RULES[tags[0]];state='likely'
                    reason='Enabled entry '+rule['why']+' and is scheduled inside an upcoming '+w['operation']+' window; no interference has been observed.'
        findings.append({'entry_id':e['entry_id'],'mechanism':e.get('mechanism'),'state':state,'rule':{'id':rule['id'],'version':RULES_VERSION} if rule else None,
            'behaviors':tags,'affected_operations':sorted(ops),'evidence':sorted(refs,key=lambda r:(r['observed_at'],r['kind'],str(r['job_id']))),
            'reason':reason,'entry_digest':e['digest'],'gaps':list(GAPS)})
    unlinked=[v for v in evidence if not v.get('entry_id') or v.get('entry_id') not in {e['entry_id'] for e in entries}]
    return {'rules_version':RULES_VERSION,'findings':findings,'unlinked_evidence':len(unlinked),'gaps':list(GAPS)}


def plan(finding,action,reason,mode='persistent',restore_at=None,separate_scope=False,mechanism=None):
    """Propose (never execute) a targeted disable. Always `requires_approval`; the approval binds
    the entry digest, the classification state and the plan revision."""
    if action not in ACTIONS:raise ValueError('Unknown action')
    if finding['state']=='insufficient_evidence':raise ValueError('Insufficient evidence cannot support a disable plan')
    if not reason or not reason.strip():raise ValueError('A reason is required')
    if mode not in ('persistent','temporary'):raise ValueError('Unknown mode')
    if mode=='temporary' and not isinstance(restore_at,(int,float)):raise ValueError('Temporary suspension needs an approved restore time')
    if mode=='persistent' and restore_at is not None:raise ValueError('Persistent disablement has no automatic restore time')
    if action!='prevent_future_starts' and not separate_scope:raise ValueError('Stopping or terminating needs separate explicit scope')
    mech=mechanism or finding.get('mechanism')
    supported=mech in SUPPORTED_MECHANISMS and action=='prevent_future_starts'
    body={'entry_id':finding['entry_id'],'mechanism':mech,'action':action,'scope':'single_entry','mode':mode,'restore_at':restore_at,'reason':reason.strip(),
        'entry_digest':finding['entry_digest'],'state':finding['state'],'revision':1,
        'execution':'typed_operation' if supported else 'manual_step',
        'needs_response_authorization':action!='prevent_future_starts','requires_approval':True,'never':['disable_service_wide','delete_shared_script','remove_lock_file','kill_package_manager'],
        'restore':'Reviewed restore of the captured before-state; later external edits are not overwritten.'}
    body['binding']=digest({k:body[k] for k in ('entry_id','action','mode','restore_at','entry_digest','state','revision')})
    return body


def approval_current(approved,current_finding):
    """An approval stays valid only for the exact entry content, state and entry it was given for."""
    return (approved.get('requires_approval') is True and approved['entry_id']==current_finding['entry_id']
        and approved['entry_digest']==current_finding['entry_digest'] and approved['state']==current_finding['state']
        and current_finding['state']!='insufficient_evidence')
