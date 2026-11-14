"""In-app notifications when a fleet known-good candidate is revoked.

``known_good.invalidate_contradiction`` calls this inside the transaction that
revokes the candidate, so a rolled-back verdict save never announces anything.
``publish_revocation`` does the same for an administrator revocation through
the API: the endpoint calls it before committing, so a failed or rolled-back
revocation announces nothing. Its separate ``candidate-revoked`` kind lets the
other administrators see a fleet trust change that leaves linked assessments
requiring review. The free-form revocation reason stays in the audit log.

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
REVOKED_KIND = 'candidate-revoked'
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


def publish_revocation(session, revoked, actor, *, now=None):
    """Publish one admin notification for an administrator revocation.

    ``revoked`` is the dict returned by ``known_good.revoke`` inside the
    caller's still-open transaction. Only the acting account name and the
    linked-assessment count reach the text; the free-form reason does not.
    Returns ``True`` when a new notification revision was added.
    """
    if not revoked or not str(actor or '').strip():
        return False
    from .ai_assessments import Assessment
    from .known_good import Entry
    entry = session.get(Entry, revoked['fingerprint'])
    origin = session.get(Assessment, entry.assessment_id) if entry else None
    # The candidate's original assessment history shows the revocation and the
    # retained reason; without it, fall back to the investigations workspace.
    deep_link = _link(origin.subject, origin.id) if origin and origin.subject else '#investigations'
    linked = int(revoked.get('linked_assessments') or 0)
    _, created = notifications.publish(
        session, source=SOURCE, kind=REVOKED_KIND, subject_type=SUBJECT_TYPE,
        subject_id=revoked['fingerprint'],
        subject_revision=('revoked:v' + str(revoked['version']) + ':admin')[:128],
        severity='medium',
        reason=('Administrator ' + str(actor).strip()[:64] + ' revoked a fleet known-good candidate. '
                + str(linked) + ' linked assessment(s) keep their original result but now require '
                'review, and future exact matches cannot reuse the candidate. The recorded reason is on '
                'the assessment history. This notification approves nothing and authorizes no response.'),
        deep_link=deep_link, host_id='', minimum_role='admin', now=now)
    return created
