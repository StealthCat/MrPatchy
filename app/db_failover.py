"""Pure database-failover safety contract: commit outcome and post-reconnect ownership (#453, first slice).

Nothing here opens a connection, reads a clock, promotes or repairs a database, or retries a statement.
Callers pass the facts they observed and decide what to do with the verdict. It authorizes no failover,
restore or reconfiguration, and it fails closed: malformed or ambiguous input is never "safe to replay"
and never "ownership restored".

Two questions are kept apart:

* ``classify_outcome`` - what do we know about a statement/transaction after an error? ``unsent`` means
  the server provably never received it; ``uncertain`` means it may have committed (connection lost
  after COMMIT was sent, acknowledgment lost). Only ``unsent`` may be replayed blindly, and only when
  the caller says the pool was invalidated; anything ``uncertain`` must be reconciled by durable
  operation ID, never replayed.
* ``resume_gate`` - after a reconnect or primary change, may a controller resume producing work or
  mutating targets? A successful reconnect does not restore ownership: GET_LOCK/session state is
  discarded, and the deployment and ownership epochs must be revalidated against the new writer.
"""

PHASES = ('before_send', 'sent', 'commit_sent', 'acknowledged')
ACTIONS = ('replay', 'reconcile', 'none', 'refuse')
LOCK_KINDS = ('session_lock', 'durable_row')


def classify_outcome(phase, operation_id=None, pool_invalidated=False):
    """Decide how to handle a failed SQL operation.

    ``phase`` is how far the operation provably got: ``before_send`` (connection error raised before any
    bytes were written), ``sent`` (statement sent, not a commit), ``commit_sent`` (COMMIT sent, no reply)
    or ``acknowledged`` (the server confirmed it; nothing failed). Returns
    ``{'outcome', 'action', 'reason'}``.
    """
    if phase not in PHASES or not isinstance(pool_invalidated, bool):
        return {'outcome': 'unknown', 'action': 'refuse', 'reason': 'invalid_input'}
    if operation_id is not None and (not isinstance(operation_id, str) or not operation_id):
        return {'outcome': 'unknown', 'action': 'refuse', 'reason': 'invalid_input'}
    if phase == 'acknowledged':
        return {'outcome': 'committed', 'action': 'none', 'reason': ''}
    if phase == 'before_send':
        if not pool_invalidated:
            return {'outcome': 'unsent', 'action': 'refuse', 'reason': 'pool_not_invalidated'}
        return {'outcome': 'unsent', 'action': 'replay', 'reason': ''}
    # sent / commit_sent: the primary may have applied it before it was lost, then been demoted or promoted.
    if operation_id:
        return {'outcome': 'uncertain', 'action': 'reconcile', 'reason': ''}
    return {'outcome': 'uncertain', 'action': 'refuse', 'reason': 'no_operation_id'}


def resume_gate(held, current, new_writer_verified):
    """May this controller resume after a reconnect / writer change? Returns ``{'resume', 'reason'}``.

    ``held`` is what the controller believed before: ``{'deployment_epoch', 'ownership_epoch',
    'locks': [{'name', 'kind'}]}``. ``current`` is read fresh from the new authoritative writer:
    ``{'deployment_epoch', 'ownership_epoch', 'owner_is_self'}``. ``new_writer_verified`` says the
    writer endpoint was authenticated over verified TLS and is the single primary.

    Session locks never survive: any held ``session_lock`` forces re-acquisition, so resume is refused
    until the caller drops them. Epochs must match exactly; a newer epoch means another owner fenced us.
    """
    if not isinstance(new_writer_verified, bool) or not isinstance(held, dict) or not isinstance(current, dict):
        return {'resume': False, 'reason': 'invalid_input'}
    epochs = [held.get('deployment_epoch'), held.get('ownership_epoch'),
              current.get('deployment_epoch'), current.get('ownership_epoch')]
    if any(isinstance(e, bool) or not isinstance(e, int) or e < 0 for e in epochs):
        return {'resume': False, 'reason': 'invalid_input'}
    if not isinstance(current.get('owner_is_self'), bool):
        return {'resume': False, 'reason': 'invalid_input'}
    locks = held.get('locks', [])
    if not isinstance(locks, (list, tuple)) or any(
            not isinstance(item, dict) or item.get('kind') not in LOCK_KINDS for item in locks):
        return {'resume': False, 'reason': 'invalid_input'}
    if not new_writer_verified:
        return {'resume': False, 'reason': 'writer_unverified'}
    if current['deployment_epoch'] != held['deployment_epoch']:
        return {'resume': False, 'reason': 'deployment_epoch_changed'}
    if current['ownership_epoch'] != held['ownership_epoch'] or not current['owner_is_self']:
        return {'resume': False, 'reason': 'ownership_lost'}
    if any(item['kind'] == 'session_lock' for item in locks):
        return {'resume': False, 'reason': 'session_locks_discarded'}
    return {'resume': True, 'reason': ''}
