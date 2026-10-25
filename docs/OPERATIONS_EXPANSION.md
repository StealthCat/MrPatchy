# Operational expansion checkpoint

This branch builds on PR #2. It is a **partial implementation of the full expansion list**, not a claim that all suggestions are finished.

## Implemented

- Named administrator/operator/viewer accounts. The original administrator password migrates to the named `admin` account. Pre-upgrade sessions are rejected. Roles are enforced server-side; privileged deployment, source configuration, trust approval, credentials and raw inventory history require administrators.
- Authenticator TOTP MFA: encrypted enrollment secret, confirmation, replay rejection, and session invalidation on enablement. Password changes, account changes and explicit session revocation invalidate prior sessions. Every authenticated mutation records actor, method, path and status without request-body secrets.
- Account UI for MFA, password changes, session revocation and user management.
- Persistent stale-telemetry, repository-error, integrity and overdue-package alerts. Administrator-configured HTTPS webhook delivery uses an outbox, retry backoff, stable IDs and acknowledgements. Delivery is at-least-once; receivers should deduplicate IDs. No real webhook messages are sent during development.
- Per-host maintenance windows, expressed as UTC weekday/minute intervals. Patch/recovery jobs wait until a window is open. Empty windows mean unrestricted scheduling.
- Staged rollouts: ordered servers, first-server canary, exact versions, dependency gating, post-patch collector/systemd failure checks. Failed/interrupted dependencies block later servers. This is sequential orchestration, not transactional rollback.
- Central dependency simulation API, queued-job cancellation API, per-host queue limits, authenticated metrics, JSONL audit export and CycloneDX component inventory export.
- Opt-in OSV advisory matching, with source package/version mapping and distro-specific Ubuntu/Debian ecosystems. Up to 100 selected binary packages per request; pagination is handled. Returned advisory IDs are not CVSS severity scores or proof that unlisted packages are safe. Raspbian/other derivatives are explicitly unsupported until their advisory mapping is established.
- Network-namespace-aware socket inventory. Namespace identity participates in behavior identity; changed identities need fresh approval.
- SQLite backup/verify/restore CLI. It snapshots the DB, includes app encryption and SSH keys, verifies a checksum manifest, refuses unsafe archive entries and nonempty restore targets, and checks restored SQLite integrity. Archives contain secrets and are mode 0600.

## Operator workflows

Use **Account** for identity controls and **Account → Operations** for notifications, maintenance windows, alerts, staged rollout and advisory matching. Rollout and mirror editors remain expert-oriented rather than a finished graphical planner.

API:
- `POST /api/hosts/{id}/preview` with `{"packages":["openssl:amd64"]}`
- `POST /api/operations/rollouts` with ordered `hosts` and package names
- `POST /api/operations/jobs/{id}/cancel` (queued only)
- `GET /api/hosts/{id}/sbom`
- `GET /api/audit/export?after=0&limit=1000`; paginate by the last returned ID
- `GET /api/metrics` (authenticated)
- `POST /api/operations/{id}/advisories` with selected package names; this discloses those names/versions and distro release to OSV

Stop the app before filesystem backup/restore:
```bash
python scripts/backup.py backup /path/to/app-volume ./mrpatchy-backup.tar.gz --app-stopped
python scripts/backup.py verify ./mrpatchy-backup.tar.gz
python scripts/backup.py restore ./mrpatchy-backup.tar.gz /empty/restore-directory --app-stopped
```
Back up the separate TLS volumes too. MySQL needs a database-native dump/restore; this CLI intentionally rejects a missing SQLite database. A checksum manifest detects accidental corruption, not malicious replacement of both files and manifest. Store exports in access-controlled/off-host storage.

## Still unfinished

These are explicitly not represented as completed features:
- OIDC/SSO, recovery codes, MFA recovery UI, SSH-key rotation/revocation workflows.
- SMTP/email delivery, escalation schedules and external incident integrations.
- Automatic reboot policies, snapshot/package rollback, graphical dependency-plan approval.
- Full advisory detail ingestion, CVSS-derived priority automation, derivative/vendor feed coverage and SBOM dependency relationships.
- Durable distributed workers/leases, multi-replica support, cache quotas, whole-fleet pagination and load/soak validation. One scheduler/replica remains required.
- eBPF short-lived process capture, interpreted script/shared-library provenance and hardware attestation.
- Automatic off-host append-only audit shipping, MySQL restore drills, TLS-volume backup integration and source-backup retention.
- Native local/media repository acquisition and vendor authentication helpers.
- Real Raspberry Pi/systemd reboot and live custom-ACME acceptance tests.

No changes are deployed to user targets automatically. Review/migrate in a disposable environment before relying on the new identity or rollout controls.

References:
- https://google.github.io/osv.dev/post-v1-querybatch/
- https://documentation.ubuntu.com/security/security-updates/osv/
