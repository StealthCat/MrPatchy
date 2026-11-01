"""Suspend management, or permanently remove management while retaining history."""
from contextlib import contextmanager
import os
import re
import stat
import time
import uuid
from sqlalchemy import select,delete
from .db import Host,Session,Setting,Job,audit
from .coordination import Lock


class Inactive(ValueError):pass
class Busy(ValueError):pass


def active(host):
    # Transient Host fixtures/objects get SQLAlchemy defaults at insertion time.
    return bool(host and getattr(host,'enabled',True) is not False and not getattr(host,'deleted_at',0))


def active_ids():
    return select(Host.id).where(Host.enabled==True,Host.deleted_at==0)

def inactive_ids():
    return select(Host.id).where((Host.enabled==False)|(Host.deleted_at>0))


@contextmanager
def activity(host_ids,kind):
    """Keep lifecycle transitions out of in-flight SSH and provider requests."""
    locks=[]
    try:
        for identifier in sorted(set(host_ids)):
            lock=Lock('server-'+kind+':'+identifier)
            lock.acquire();locks.append(lock)
        revisions={}
        with Session() as s:
            for identifier in host_ids:
                host=s.get(Host,identifier)
                # Bootstrap/native tests may use unpersisted typed SSH hosts.
                if host and not active(host):raise Inactive('Server management is disabled or deleted')
                if host:revisions[identifier]=host.lifecycle_revision
        yield revisions
    finally:
        for lock in reversed(locks):lock.release()


@contextmanager
def changing(host_id):
    locks=[]
    try:
        for kind in ('queue','polling','telemetry','control','ai'):
            lock=Lock('server-'+kind+':'+host_id)
            if not lock.acquire(False):raise Busy('Server communication or AI work is active; retry after it finishes')
            locks.append(lock)
        yield
    finally:
        for lock in reversed(locks):lock.release()


def revoke_links(s,host_id):
    for row in s.scalars(select(Setting).where(Setting.key.like('enroll:%'))):
        if row.value.get('host_id')==host_id:s.delete(row)


def reject_pending_records(s,job,actor,reason):
    """Controller-local cleanup after the caller has fenced an unstarted job.

    State/host checks in each handler preserve uncertain or unrelated responses.
    The caller owns the host lock, queued-only transition and transaction.
    """
    from . import quarantine,process_response,repair_publication,repair_staging,repair_preparation,evidence_vault,evidence_archive
    if job.action in ('quarantine-apply','quarantine-restore'):quarantine.reject_unstarted(s,job)
    if job.action in ('process-suspend','process-resume'):process_response.reject_unstarted(s,job)
    if job.action=='trusted-repair-publish':repair_publication.reject_unstarted(s,job,actor,'cancelled')
    if job.action=='trusted-repair-stage':
        row=s.get(repair_staging.Stage,job.payload.get('stage_id'))
        if row and row.host_id==job.host_id and row.state=='queued':
            row.state='rejected';repair_staging.event(s,row,'cancelled',actor,{'reason':reason})
    if job.action=='trusted-repair-prepare':
        row=s.get(repair_preparation.Preparation,job.payload.get('preparation_id'))
        if row and row.host_id==job.host_id and row.state=='queued':row.state='cancelled';row.finished=time.time()
    if job.action=='evidence-preserve':
        row=s.get(evidence_vault.EvidenceCopy,job.payload.get('copy_id'))
        if row and row.host_id==job.host_id and row.state=='queued':row.state='rejected';row.expires=0
    if job.action=='evidence-acquire':
        row=s.get(evidence_vault.EvidenceArchive,job.payload.get('archive_id'))
        if row and row.host_id==job.host_id and row.state=='queued':
            row.state='rejected';evidence_archive.observe(s,row,'rejected',job.id)


def cancel_pending(s,host_id,actor):
    from . import releases,scheduling
    count=0
    for job in s.scalars(select(Job).where(Job.host_id==host_id,Job.state=='queued')):
        reject_pending_records(s,job,actor,'Server management disabled')
        job.state='cancelled';job.output='Server management disabled; cancelled work will not resume automatically'
        plan=s.get(releases.ReleasePlan,job.payload.get('plan_id')) if job.action in ('release-plan','release-upgrade') else None
        if plan and plan.host_id==host_id and plan.state in ('planning','approved','queued'):plan.state='cancelled';plan.error=job.output
        count+=1
    for run in s.scalars(select(scheduling.PatchRun).where(scheduling.PatchRun.host_id==host_id,scheduling.PatchRun.state.in_(('waiting','queued')))):
        run.state='cancelled';run.detail='Server management disabled'
    from . import execution_scans
    execution_scans.cancel(s,host_id,'Server management disabled; old execution triggers will not resume')
    return count


def set_enabled(s,host,enabled,expected,actor,reason):
    if host.deleted_at:raise ValueError('Deleted servers cannot be re-enabled; enroll a new server')
    if host.lifecycle_revision!=expected:raise ValueError('Server lifecycle changed; refresh before saving')
    if s.scalar(select(Job.id).where(Job.host_id==host.id,Job.state=='running').limit(1)):raise Busy('A running operation must finish or be reconciled before changing management')
    reason=reason.strip()
    if len(reason)<10:raise ValueError('Provide a meaningful lifecycle reason')
    cancelled=cancel_pending(s,host.id,actor) if not enabled else 0
    revoke_links(s,host.id)
    host.enabled=enabled;host.lifecycle_revision=str(uuid.uuid4())
    host.state=('offline' if host.fingerprint and host.baseline else 'enrolling') if enabled else 'disabled'
    if enabled:host.last_repo=0
    audit(s,'enable server' if enabled else 'disable server',host.id+' '+actor+' '+reason+'; cancelled='+str(cancelled))
    return cancelled


def remove_credentials(host_id):
    from . import ssh
    if not re.fullmatch('[A-Za-z0-9-]{1,64}',host_id):raise ValueError('Invalid server credential identifier')
    # APT keeps scoped authentication in the host's private metadata workspace.
    # Anchor every component; deleting credentials must not follow directory links.
    descriptor=os.open(ssh.DATA,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for component in ('apt',host_id,'etc','apt'):
            try:child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
            except FileNotFoundError:break
            os.close(descriptor);descriptor=child
        else:
            try:os.unlink('auth.conf',dir_fd=descriptor)
            except FileNotFoundError:pass
            os.fsync(descriptor)
    finally:os.close(descriptor)
    try:directory=os.open(ssh.DATA/'ssh',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    except FileNotFoundError:return
    try:
        info=os.fstat(directory)
        if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o022:raise ValueError('Unsafe local SSH credential directory')
        for suffix in ('.key','.next.key','.rotation.json','.rotation.tmp'):
            try:os.unlink(host_id+suffix,dir_fd=directory)
            except FileNotFoundError:pass
        os.fsync(directory)
    finally:os.close(directory)


def remove(s,host,expected,confirmation,actor,reason):
    from . import operations
    if confirmation!=host.name:raise ValueError('Type the server name exactly to delete it')
    if host.deleted_at:return
    if host.lifecycle_revision!=expected:raise ValueError('Server lifecycle changed; refresh before deleting')
    if operations.host_quarantined(s,host.id):raise Busy('Reconcile active operations and file, process, publication or service holds before deleting this server')
    # Commit inactivity before removing files. A crash/failure leaves a disabled
    # server that can be reviewed and retried; it can never keep contacting a key
    # while credential removal is incomplete.
    set_enabled(s,host,False,expected,actor,reason);s.commit()
    try:remove_credentials(host.id)
    except (OSError,ValueError):raise ValueError('Server disabled, but local credential cleanup failed. Refresh and retry deletion after reviewing controller storage') from None
    s.execute(delete(Setting).where(Setting.key.in_(['connection:'+host.id,'repository-access:'+host.id])))
    host.deleted_at=time.time();host.enabled=False;host.state='deleted';host.lifecycle_revision=str(uuid.uuid4())
    audit(s,'delete server',host.id+' '+actor+' '+reason.strip()+'; local credentials removed; history retained')
    s.commit()
