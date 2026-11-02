"""Controller-local failed-observation transition; callers retain all gates/transactions."""


def mark_status_failed(s, row, actor, job_id, *, event, clock):
    """Retain uncertainty without changing caller scope, actor or commit ownership."""
    row.state='uncertain';row.hold=True;row.receipt={};row.observed=clock()
    event(s,row,'observation_failed',actor,{'job_id':job_id})
