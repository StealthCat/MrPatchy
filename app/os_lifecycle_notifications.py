"""Administrator notification when a server's verified OS release is past standard support.

``os_lifecycle.evaluate`` already reports the reviewed vendor lifecycle on the
server Overview, but nothing tells an administrator when a release crosses its
standard-support end date or has no remaining reviewed support phase.

This producer publishes one admin-only in-app event per server while its exact
Debian/Ubuntu release is past standard support and coverage is not verified:

* ``ended``: no reviewed vendor support phase remains (high);
* ``subscription``: Ubuntu standard support ended and extended coverage depends
  on an Ubuntu Pro entitlement that the inventory does not observe (medium);
* ``lts-unverified``: Debian standard support ended and the host is not verified
  as eligible for Debian LTS (medium).

While a release is still covered, an optional advance warning (``ending-soon``,
low) is published when the next reviewed support boundary falls within the
administrator-configured ``os_lifecycle_warning_days`` window (0 disables it):
the end of standard support, or the end of verified Debian LTS coverage. Once
the boundary passes, the same event moves to the attention category above, or
resolves if verified coverage continues.

Otherwise standard support and verified Debian LTS coverage need no attention. A changed,
unknown or unsupported release, or a disabled, deleted or re-enrolling server,
resolves the event because the earlier claim no longer applies. Stale or missing
inventory keeps the current state: freshness gaps cannot prove a server was
upgraded, and they are shown on the Overview lifecycle card.

It only reads stored inventory. Reason text is composed from the reviewed
controller catalog (label and end dates) and never carries endpoint text. It
changes no patching, upgrade or subscription state and acknowledges,
remediates or authorizes nothing.
"""
from datetime import date, datetime, timezone

from sqlalchemy import select

from . import host_lifecycle, notifications, os_lifecycle

SOURCE = 'os-lifecycle'
KIND = 'support-ended'
SUBJECT = 'server'
HOLD = object()
SEVERITY = {'ended': 'high', 'subscription': 'medium', 'lts-unverified': 'medium', 'ending-soon': 'low'}
MAX_WARNING_DAYS = 730
_HOLD_COVERAGE = {'missing_inventory', 'stale_inventory'}
RESOLVED = 'The operating-system support lifecycle of this server no longer needs administrator attention.'


def warning_days(value):
    """Return a valid advance-warning window in days; invalid stored values disable the warning."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_WARNING_DAYS:
        return 0
    return value


def _upcoming(assessment, now, days):
    """Return the next covered-support end date within ``days``, or ``None``."""
    if days <= 0:
        return None
    if assessment.get('state') == 'standard':
        boundary = assessment.get('standard_until')
    elif assessment.get('state') == 'extended' and assessment.get('coverage') == 'debian_lts':
        boundary = assessment.get('extended_until')
    else:
        return None
    try:
        end = date.fromisoformat(boundary)
        today = datetime.fromtimestamp(now, timezone.utc).date()
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    return boundary if 0 <= (end - today).days <= days else None


def classify(host, now, max_age_seconds, advance_days=0):
    """Return ``(category, assessment)``, ``(None, None)`` or ``(HOLD, None)`` for one server."""
    if host.deleted_at or not host_lifecycle.active(host) or host.state == 'enrolling':
        return None, None
    assessment = os_lifecycle.evaluate(host.inventory, now, max_age_seconds)
    state, coverage = assessment.get('state'), assessment.get('coverage')
    if state == 'ended':
        return 'ended', assessment
    if state == 'extended' and coverage == 'subscription_required':
        return 'subscription', assessment
    if state == 'unknown' and coverage == 'architecture_unverified':
        return 'lts-unverified', assessment
    if state == 'unknown' and coverage in _HOLD_COVERAGE:
        return HOLD, None
    boundary = _upcoming(assessment, now, warning_days(advance_days))
    if boundary:
        return 'ending-soon', {**assessment, 'boundary': boundary}
    return None, None


def message(category, assessment):
    """Fixed reason text built only from the reviewed catalog record."""
    label = assessment['label']
    standard = assessment['standard_until']
    extended = assessment.get('extended_until')
    if category == 'ending-soon':
        if assessment.get('state') == 'extended':
            return (label + ' Debian LTS coverage ends on ' + extended + '. After that date no reviewed vendor '
                    'support phase remains. Plan an upgrade to a supported release before then. Lifecycle status is '
                    'not a compromise verdict and changes no patching.')
        if assessment['vendor'] == 'Ubuntu' and extended:
            after = ('Extended coverage until ' + extended + ' requires an active Ubuntu Pro entitlement, which '
                     'this inventory does not observe.')
        elif extended:
            after = ('Debian LTS may cover it until ' + extended + ' on supported architectures only, with a '
                     'reduced package scope.')
        else:
            after = 'No further reviewed vendor support phase follows.'
        return (label + ' standard support ends on ' + standard + '. ' + after + ' Plan an upgrade or confirm '
                'coverage before then. Lifecycle status is not a compromise verdict and changes no patching.')
    if category == 'ended':
        last = extended or standard
        return (label + ' reached the end of its reviewed vendor support lifecycle on ' + last + '. '
                'Security updates are no longer expected from the vendor. Plan an upgrade to a supported '
                'release. Lifecycle status is not a compromise verdict and changes no patching.')
    if category == 'subscription':
        return (label + ' standard support ended on ' + standard + '. Extended coverage until ' + extended +
                ' requires an active Ubuntu Pro entitlement, which this inventory does not observe. Confirm the '
                'entitlement or plan an upgrade. Lifecycle status is not a compromise verdict and changes no patching.')
    return (label + ' standard support ended on ' + standard + '. This server is not verified as eligible for '
            'Debian LTS coverage (until ' + extended + ') because its architecture is missing or not covered. '
            'Review the server architecture or plan an upgrade. Lifecycle status is not a compromise verdict '
            'and changes no patching.')


def _link(host_id):
    return '#servers/' + host_id + '/overview'


def publish(session, hosts, now, max_age_seconds, advance_days=0):
    """Publish or resolve lifecycle events in the caller's transaction. Returns the attention host IDs."""
    attention, held = {}, set()
    for host in hosts:
        category, assessment = classify(host, now, max_age_seconds, advance_days)
        if category is HOLD:
            held.add(host.id)
        elif category:
            attention[host.id] = (category, assessment)
    for host_id, (category, assessment) in attention.items():
        revision = category + ':' + str(assessment['vendor']) + ':' + str(assessment['release'])
        if category == 'ending-soon':
            revision += ':' + assessment['boundary']
        notifications.publish(session, source=SOURCE, kind=KIND, subject_type=SUBJECT, subject_id=host_id,
                              host_id=host_id, subject_revision=revision, severity=SEVERITY[category],
                              reason=message(category, assessment), deep_link=_link(host_id),
                              minimum_role='admin', now=now)
    N, R = notifications.NotificationEvent, notifications.NotificationRevision
    active = session.execute(select(N.subject_id).join(R, (R.event_id == N.id) & (R.revision == N.revision)).where(
        N.source == SOURCE, N.kind == KIND, N.subject_type == SUBJECT, R.lifecycle == 'active')).scalars().all()
    for host_id in active:
        if host_id in attention or host_id in held:
            continue
        notifications.publish(session, source=SOURCE, kind=KIND, subject_type=SUBJECT, subject_id=host_id,
                              host_id=host_id, subject_revision='resolved', severity='info', reason=RESOLVED,
                              deep_link=_link(host_id), minimum_role='admin', lifecycle='resolved', now=now)
    return set(attention)
