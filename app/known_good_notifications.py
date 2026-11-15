"""In-app notification when an AI contradiction revokes a fleet known-good candidate.

``known_good.invalidate_contradiction`` calls this inside the transaction that
revokes the candidate, so a rolled-back verdict save never announces anything.
Administrator revocation through the API is a direct administrator action and
is deliberately not notified.

The payload carries only fixed text, the contradicting risk word, the linked
assessment count and identifiers: executable paths, host names, model output
and evidence stay on the escaped assessment history page. The event is
fleet-scoped (no host) and admin-only. Revocation happens at most once per
candidate version, so each candidate produces at most one event revision per
revocation. The notification is advisory: it approves nothing, acknowledges
nothing and authorizes no response.
"""

from . import notifications

SOURCE = 'ai-known-good'
KIND = 'candidate-contradicted'
SUBJECT_TYPE = 'known-good-candidate'
SEVERITY = {'high': 'high', 'medium': 'medium', 'unknown': 'medium'}


def _link(subject, assessment_id):
    # Matches the "Review original assessment" route already used by fleet.js.
    from urllib.parse import quote
    return ('#investigations/item/' + quote(str(subject), safe='') +
            '/history/' + quote(str(assessment_id), safe=''))


def publish_contradiction(session, revoked, risk, *, now=None):
    """Publish one admin notification for an automatic contradiction revocation.

    ``revoked`` is the dict returned by ``known_good.invalidate_contradiction``.
    The caller owns the surrounding transaction. Returns ``True`` when a new
    notification revision was added.
    """
    if not revoked or risk not in SEVERITY:
        return False
    linked = int(revoked.get('linked_assessments') or 0)
    marker = str(revoked.get('revoked_by') or '')
    _, created = notifications.publish(
        session, source=SOURCE, kind=KIND, subject_type=SUBJECT_TYPE,
        subject_id=revoked['fingerprint'],
        subject_revision=('revoked:v' + str(revoked['version']) + ':' +
                          marker.removeprefix('assessment:'))[:128],
        severity=SEVERITY[risk],
        reason=('A new AI triage result rated the same exact verified context as ' + risk +
                ' risk, so Mr Patchy automatically revoked a fleet known-good candidate. '
                + str(linked) + ' linked assessment(s) keep their original result but now '
                'require review, and future exact matches cannot reuse the candidate. '
                'The result is advisory: it approves nothing and authorizes no response.'),
        deep_link=_link(revoked['source_subject'], revoked['source_assessment_id']),
        host_id='', minimum_role='admin', now=now)
    return created
