"""Immutable, read-only trusted replacement preparations; no execution approval."""
import time
from sqlalchemy import String,Double,JSON,Text
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,audit
from . import incidents,quarantine,vendor,ssh

ACTION='trusted-repair-prepare'
STATES=('quarantined','uncertain','not_found','console_recovered','not_moved')
FACTS=('retained_verified','quarantine_complete','parents_match','destination_empty','metadata_supported','package_matches','owner_matches','rechecked')
GAPS=('retained_unverified','quarantine_incomplete','parent_changed','destination_occupied','unsupported_metadata',
      'package_identity','package_owner','package_changed','changed_during_read','verification_unavailable')


class Preparation(Base):
    __tablename__='security_repair_preparations'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    quarantine_id:Mapped[str]=mapped_column(String(36),index=True)
    bundle_id:Mapped[str]=mapped_column(String(64))
    path:Mapped[str]=mapped_column(Text)
    actor:Mapped[str]=mapped_column(String(120))
    created:Mapped[float]=mapped_column(Double,default=time.time)
    finished:Mapped[float]=mapped_column(Double,default=0)
    state:Mapped[str]=mapped_column(String(30),default='queued')
    fingerprint:Mapped[str]=mapped_column(String(100))
    response_plan_digest:Mapped[str]=mapped_column(String(64))
    report:Mapped[dict]=mapped_column(JSON,default=dict)


def source(s,host,preparation):
    row=s.get(quarantine.Quarantine,preparation.quarantine_id)
    if not row or row.host_id!=host.id or row.state not in STATES or row.fingerprint!=host.fingerprint or preparation.fingerprint!=host.fingerprint or preparation.response_plan_digest!=incidents.digest(row.plan) or preparation.path!=row.plan['file']['path']:raise ValueError('Retained response scope or pinned host changed')
    return row


def validate(result,row,manifest):
    if not isinstance(result,dict) or set(result)!={'version','quarantine_id','response_plan_digest','manifest_digest','state','facts','gaps','replacement_mode'} or type(result['version']) is not int or result['version']!=1 or result['quarantine_id']!=row.id or result['response_plan_digest']!=incidents.digest(row.plan) or result['manifest_digest']!=incidents.digest(manifest) or result['state'] not in ('ready','blocked'):raise ValueError('Unbound repair readiness receipt')
    facts=result['facts'];gaps=result['gaps']
    if not isinstance(facts,dict) or set(facts)!=set(FACTS) or any(type(v) is not bool for k,v in facts.items() if k not in ('parents_match','destination_empty')) or any(facts[k] is not None and type(facts[k]) is not bool for k in ('parents_match','destination_empty')):raise ValueError('Invalid repair readiness facts')
    if not isinstance(gaps,list) or len(gaps)>len(GAPS) or any(not isinstance(g,str) or g not in GAPS for g in gaps) or len(set(gaps))!=len(gaps):raise ValueError('Invalid repair readiness gaps')
    mode=result['replacement_mode']
    if facts['metadata_supported']:
        if type(mode) is not int or mode not in (0o600,0o640,0o644,0o700,0o750,0o755) or mode!=(row.plan['file']['identity']['mode']&0o7777) or row.plan['file']['identity']['uid']!=0 or row.plan['file']['identity']['gid']!=0 or row.plan['xattrs']:raise ValueError('Unbound replacement metadata policy')
    elif mode is not None:raise ValueError('Unsupported replacement mode')
    ready=all(value is True for value in facts.values()) and not gaps
    if (result['state']=='ready')!=ready:raise ValueError('Contradictory repair readiness receipt')


def execute(s,host,job):
    preparation=s.get(Preparation,job.payload['preparation_id'])
    if not preparation or preparation.host_id!=host.id:raise ValueError('Repair preparation not found')
    if preparation.state!='queued':return {'preparation_id':preparation.id,'state':preparation.state}
    report={'version':1,'read_only':True,'publication':'not_implemented','scope_current':False};stage='scope';state='unavailable'
    try:
        if job.payload.get('quarantine_id')!=preparation.quarantine_id:raise ValueError('Repair preparation job scope changed')
        row=source(s,host,preparation);stage='authentication'
        manifest,proof=vendor.replacement(preparation.bundle_id,row.plan['file']['path'])
        authentication=vendor.authentication_digest(manifest,proof)
        report={'version':1,'manifest':manifest,'authentication':proof,'authentication_digest':authentication,'read_only':True,'publication':'not_implemented','scope_current':False}
        stage='helper';quarantine.healthy(s,host)
        s.rollback();s.expire_all();stage='scope';preparation=s.get(Preparation,job.payload['preparation_id']);row=source(s,host,preparation)
        stage='remote'
        result=ssh.call(host,{'action':'repair-readiness','id':row.id,'plan':row.plan,'manifest':manifest},timeout=150)
        stage='protocol';validate(result,row,manifest);report['target']=result
        stage='authentication_recheck'
        current_manifest,current_proof=vendor.replacement(preparation.bundle_id,row.plan['file']['path'])
        if vendor.authentication_digest(current_manifest,current_proof)!=authentication:raise ValueError('Vendor trust or replacement bytes changed during preparation')
        s.rollback();s.expire_all();stage='scope';preparation=s.get(Preparation,job.payload['preparation_id']);row=source(s,host,preparation)
        report['scope_current']=True;state=result['state']
    except Exception as error:
        s.rollback();s.expire_all();preparation=s.get(Preparation,job.payload['preparation_id'])
        if not preparation or preparation.host_id!=host.id:raise ValueError('Repair preparation removed during observation')
        report['scope_current']=False
        report['failure']={'stage':stage,'type':type(error).__name__}
        state='skipped' if stage=='scope' else 'unavailable'
    preparation.state=state;preparation.finished=time.time();preparation.report=report
    audit(s,'trusted repair preparation '+state,host.id+' '+preparation.id+' '+preparation.actor)
    return {'preparation_id':preparation.id,'state':state,'read_only':True,'outcome':'response_incomplete' if state=='unavailable' else 'observed'}
