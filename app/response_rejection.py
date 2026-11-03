"""Shared controller-local cleanup for unstarted response jobs."""


def reject_unstarted(s, job, *, model, approval_model, payload_key, recovery_state, event, actor_from_approval):
    """Reject a queued response, restoring the approval's prior recovery state.

    The caller has already fenced the job under the host lock.  Keep the
    model-specific event writer and historical actor choice configurable while
    sharing the identity, state and hold transition.
    """
    row = s.get(model, job.payload.get(payload_key))
    if not row or row.host_id != job.host_id or row.state not in ('queued', recovery_state):
        return
    approval = s.get(approval_model, row.approval_id)
    row.state = 'rejected' if row.state == 'queued' else (approval.before_state if approval else 'uncertain')
    row.hold = approval.before_hold if approval else True
    actor = (approval.actor if approval else 'system') if actor_from_approval else job.payload.get('_actor', 'system')
    event(s, row, 'rejected', actor, {'job_id': job.id})
