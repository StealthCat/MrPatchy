from app import ha_ownership as ha


def test_acquire_increments_epoch_and_refuses_live_other_owner():
    rec, tok, why = ha.acquire(ha.new_record(), 'a', 100, 30)
    assert (tok, why) == ({'owner': 'a', 'epoch': 1}, 'acquired')
    rec2, tok2, why2 = ha.acquire(rec, 'b', 110, 30)
    assert tok2 is None and why2 == 'held_by_other' and rec2 == rec


def test_takeover_after_expiry_fences_paused_old_owner():
    rec, old, _ = ha.acquire(ha.new_record(), 'a', 100, 30)
    rec, new, why = ha.acquire(rec, 'b', 131, 30)
    assert new == {'owner': 'b', 'epoch': 2} and why == 'acquired'
    assert not ha.side_effects_allowed(rec, old, 132)  # old owner wakes up after the pause
    assert ha.check(rec, old, 132)['reason'] == 'superseded'
    assert ha.side_effects_allowed(rec, new, 132)


def test_same_owner_reacquire_after_expiry_gets_new_epoch_not_old_token():
    rec, old, _ = ha.acquire(ha.new_record(), 'a', 100, 30)
    rec, new, _ = ha.acquire(rec, 'a', 200, 30)
    assert new['epoch'] == 2
    assert not ha.side_effects_allowed(rec, old, 201)


def test_expired_and_revoked_tokens_cannot_renew_or_act():
    rec, tok, _ = ha.acquire(ha.new_record(), 'a', 100, 30)
    assert ha.check(rec, tok, 130)['reason'] == 'expired'
    assert ha.renew(rec, tok, 130, 30) == (rec, 'expired')
    renewed, why = ha.renew(rec, tok, 120, 30)
    assert why == 'renewed' and renewed['expires_at'] == 150
    revoked = ha.revoke(renewed)
    assert ha.check(revoked, tok, 121)['reason'] == 'revoked'
    _, new, _ = ha.acquire(revoked, 'b', 121, 30)
    assert new['epoch'] == tok['epoch'] + 1


def test_malformed_input_fails_closed():
    rec, tok, _ = ha.acquire(ha.new_record(), 'a', 100, 30)
    for bad in (None, {}, [], {'epoch': True, 'expires_at': 5}, {'epoch': -1, 'expires_at': 5}):
        assert not ha.check(bad, tok, 101)['allowed']
        assert ha.acquire(bad, 'b', 101, 30)[1] is None
    assert not ha.check(rec, None, 101)['allowed'] and not ha.check(rec, tok, None)['allowed']
    assert not ha.check(rec, {'owner': 'a', 'epoch': True}, 101)['allowed']
    assert ha.acquire(rec, '', 101, 30)[1] is None and ha.acquire(rec, 'b', 101, 0)[1] is None


def test_outcome_classification_never_assumes_lost():
    assert ha.outcome() == ha.NEVER_SUBMITTED
    assert ha.outcome(submitted_at=5) == ha.UNCERTAIN
    assert ha.outcome(5, {'state': 'accepted'}) == ha.ACCEPTED
    assert ha.outcome(5, {'state': 'completed'}) == ha.COMPLETED
    assert ha.outcome(5, {'state': 'bogus'}) == ha.UNCERTAIN
    assert ha.outcome(None, 'x') == ha.NEVER_SUBMITTED


def test_adoption_never_replays_uncertain_or_unfenced_work():
    assert ha.adoption(ha.COMPLETED, False)['action'] == 'record_result'
    assert ha.adoption(ha.UNCERTAIN, True) == {'action': 'hold', 'reason': 'uncertain_outcome'}
    assert ha.adoption(ha.SUBMITTED, True)['action'] == 'hold'
    assert ha.adoption(ha.ACCEPTED, True)['action'] == 'resume_observing'
    assert ha.adoption(ha.ACCEPTED, False) == {'action': 'hold', 'reason': 'fence_not_enforced'}
    assert ha.adoption(ha.NEVER_SUBMITTED, True)['action'] == 'submit'
    assert ha.adoption(ha.NEVER_SUBMITTED, 'yes')['reason'] == 'fence_not_enforced'
    assert ha.adoption('weird', True)['reason'] == 'unknown_outcome'
