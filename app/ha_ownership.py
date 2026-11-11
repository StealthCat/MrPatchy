"""Pure fencing contract for cluster ownership and failover safety (#448, first slice).

Nothing here touches the database, a lock, a remote host or a clock: callers pass ``now`` and the
authoritative ownership record they read transactionally, and persist whatever record is returned.
It authorizes no dispatch, failover or takeover by itself.

Model: one record per ownership scope (for example a scheduler, a host or an AI budget) holding a
monotonically increasing ``epoch``. A holder presents a token ``(owner, epoch)``; work is allowed
only while the stored record still names that exact token, it is unexpired and it is not revoked.
Losing a lock or connection never proves that remote work stopped, so outcomes are classified
separately and an uncertain operation is held for reconciliation instead of being replayed.
"""

NEVER_SUBMITTED = 'never_submitted'
SUBMITTED = 'submitted'
ACCEPTED = 'accepted'
COMPLETED = 'completed'
UNCERTAIN = 'uncertain'
OUTCOMES = (NEVER_SUBMITTED, SUBMITTED, ACCEPTED, COMPLETED, UNCERTAIN)


def _num(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def new_record():
    """An unowned scope. Epoch 0 means no owner has ever held it."""
    return {'epoch': 0, 'owner': None, 'expires_at': 0, 'revoked': False}


def _valid(record):
    return (isinstance(record, dict) and isinstance(record.get('epoch'), int) and not isinstance(record.get('epoch'), bool)
            and record['epoch'] >= 0 and _num(record.get('expires_at')))


def held(record, now):
    """True while the record names an owner whose lease is live and not revoked."""
    return bool(_valid(record) and record.get('owner') and not record.get('revoked') and _num(now) and now < record['expires_at'])


def acquire(record, member, now, ttl):
    """Take ownership if the scope is free. Returns ``(new_record, token_or_None, reason)``.

    A takeover always increments the epoch, so a paused former owner can never match again. A live
    lease held by another member refuses; the current owner re-acquiring keeps its epoch (renewal).
    """
    if not _valid(record) or not member or not isinstance(member, str) or not _num(now) or not _num(ttl) or ttl <= 0:
        return record, None, 'invalid_input'
    if held(record, now):
        if record['owner'] != member:
            return record, None, 'held_by_other'
        return {**record, 'expires_at': now + ttl}, {'owner': member, 'epoch': record['epoch']}, 'renewed'
    epoch = record['epoch'] + 1
    return ({'epoch': epoch, 'owner': member, 'expires_at': now + ttl, 'revoked': False},
            {'owner': member, 'epoch': epoch}, 'acquired')


def renew(record, token, now, ttl):
    """Extend a live lease. An expired, revoked or superseded token is not renewable (no resurrection)."""
    if not _num(ttl) or ttl <= 0:
        return record, 'invalid_input'
    verdict = check(record, token, now)
    if not verdict['allowed']:
        return record, verdict['reason']
    return {**record, 'expires_at': now + ttl}, 'renewed'


def revoke(record):
    """Explicitly revoke the current owner; the next acquire still bumps the epoch."""
    if not _valid(record):
        return record
    return {**record, 'revoked': True}


def check(record, token, now):
    """Decide whether the token may still produce side effects. Fails closed on any malformed input."""
    if not _valid(record) or not isinstance(token, dict) or not _num(now):
        return {'allowed': False, 'reason': 'invalid_input'}
    if token.get('epoch') != record['epoch'] or token.get('owner') != record.get('owner') or isinstance(token.get('epoch'), bool):
        return {'allowed': False, 'reason': 'superseded'}
    if record.get('revoked'):
        return {'allowed': False, 'reason': 'revoked'}
    if now >= record['expires_at']:
        return {'allowed': False, 'reason': 'expired'}
    return {'allowed': True, 'reason': ''}


def outcome(submitted_at=None, receipt=None):
    """Classify one operation from durable facts.

    ``receipt`` is an authenticated target receipt dict with ``state`` of ``accepted`` or ``completed``
    (anything else is ignored). A submission with no observed receipt is ``uncertain`` rather than
    assumed lost: the target may still be running it.
    """
    state = receipt.get('state') if isinstance(receipt, dict) else None
    if state == COMPLETED:
        return COMPLETED
    if state == ACCEPTED:
        return ACCEPTED
    if submitted_at is None:
        return NEVER_SUBMITTED
    return UNCERTAIN


def adoption(op_outcome, fence_enforced):
    """What a new owner may do with an operation left by a previous owner. Never replays.

    ``fence_enforced`` is True only when the target verifiably enforces the ownership epoch; a legacy
    endpoint that cannot enforce it forces a hold instead of an automatic takeover.
    """
    if op_outcome not in OUTCOMES:
        return {'action': 'hold', 'reason': 'unknown_outcome'}
    if op_outcome == COMPLETED:
        return {'action': 'record_result', 'reason': ''}
    if op_outcome == NEVER_SUBMITTED:
        return {'action': 'submit', 'reason': ''} if fence_enforced is True else {'action': 'hold', 'reason': 'fence_not_enforced'}
    if op_outcome == ACCEPTED and fence_enforced is True:
        return {'action': 'resume_observing', 'reason': ''}
    return {'action': 'hold', 'reason': 'uncertain_outcome' if op_outcome != ACCEPTED else 'fence_not_enforced'}


def side_effects_allowed(record, token, now):
    """Admission gate for new side effects and new work; reacquisition is a new token, never a reuse."""
    return check(record, token, now)['allowed']
