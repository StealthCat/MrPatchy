"""In-app notifications for changed, missing or unbaselined managed agent files.

Telemetry ingestion records managed-file findings in ``Host.integrity`` next to
endpoint-supplied collector, eBPF and spool text. The raw ``integrity`` outbox
alert serializes that list, so it stays SMTP/webhook-only. This producer instead
classifies only the findings the controller itself writes for paths in the
server's enrolled baseline, and publishes fixed text with category counts. No
endpoint-supplied path or issue text reaches the bell. Repeating the same counts
is a no-op; resolution uses the shared operational path, which needs the kind
registered in ``operations.OPERATIONAL_NOTIFICATIONS``. Nothing here
acknowledges alerts, repairs files or authorizes any response.
"""
import logging

from . import host_lifecycle

ALERT_KIND = 'agent integrity'
# Exact issue strings written by worker.ingest for enrolled managed paths.
CHANGED = 'SHA-256 differs from enrolled version or file is missing'
METADATA = 'Managed file ownership/permissions changed or metadata is missing; upgrade the collector if needed'
BASELINE = 'Managed baseline missing; finish installation'


def classify(host):
    """Return (changed, metadata, baseline_missing) counts from controller-written findings only."""
    enrolled = host.baseline if isinstance(host.baseline, dict) else {}
    changed, metadata, baseline_missing = set(), set(), False
    for item in host.integrity if isinstance(host.integrity, list) else []:
        if not isinstance(item, dict):
            continue
        path, issue = item.get('path'), item.get('issue')
        if not isinstance(path, str):
            continue
        if path == 'baseline' and issue == BASELINE and not enrolled:
            baseline_missing = True
        elif path in enrolled and issue == CHANGED:
            changed.add(path)
        elif path in enrolled and issue == METADATA:
            metadata.add(path)
    return len(changed), len(metadata), baseline_missing


def message(changed, metadata, baseline_missing):
    parts = []
    if baseline_missing:
        parts.append('The managed agent baseline recorded at enrollment is missing.')
    if changed:
        parts.append(f'{changed} managed agent file(s) differ from the enrolled SHA-256 or are missing.')
    if metadata:
        parts.append(f'{metadata} managed agent file(s) have changed ownership or permissions, '
                     'or their metadata is missing.')
    return (' '.join(parts) + ' The agent or its privileged helper may have been modified. Review Agent health '
            'and the Integrity findings on this server\'s Overview; run a live check or a reviewed repair if the '
            'change was not expected. This notification does not repair files or authorize any response.')


def publish(hosts, now, notify, published):
    """Publish for every affected eligible server and add its key to ``published``.

    ``notify(host_id, alert_kind, message, now)`` is the operational publisher;
    servers left out of ``published`` are resolved by the caller.
    """
    from .operations import OPERATIONAL_NOTIFICATIONS
    kind = OPERATIONAL_NOTIFICATIONS[ALERT_KIND][0]
    for host in sorted(hosts, key=lambda h: h.id):
        if host.deleted_at or not host_lifecycle.active(host) or host.state == 'enrolling':
            continue
        changed, metadata, baseline_missing = classify(host)
        if not (changed or metadata or baseline_missing):
            continue
        # Keep the key even if publishing is rejected, so an active event is never resolved by mistake.
        published.add((host.id, kind))
        try:
            notify(host.id, ALERT_KIND, message(changed, metadata, baseline_missing), now)
        except ValueError:
            logging.getLogger(__name__).warning('Skipped in-app agent integrity notification on %s', host.id)
