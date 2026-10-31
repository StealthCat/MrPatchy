# Operations

## Ports and connectivity

- Browser → Caddy: TCP 443; TCP 80 for redirects/ACME; UDP 443 for HTTP/3.
- Central app → targets: configured SSH port (normally TCP 22).
- Central app → repositories: HTTP(S), using the source configuration captured from the target.
- Central app → OpenAI: HTTPS for configured investigations/update scoring/release planning and administrator-initiated AI connection tests.
- Caddy → ACME directory: HTTPS, with an uploaded CA when required.
- No inbound target-agent port. The target collector needs no outbound network connection. Explicit target package installations still need access to configured package repositories.

Use a management LAN/VPN, limit target SSH ingress to the app host, and protect persistent volumes. Keep one app instance and one Uvicorn worker.

## Checks and troubleshooting

```bash
docker compose ps
docker compose logs --tail=200 app worker caddy
```

On an enrolled target:

```bash
sudo systemctl status mrpatchy-agent
sudo journalctl -u mrpatchy-agent --since '30 minutes ago'
sudo cat /opt/drpatch/collector-error.json  # Present only when a collection error occurred.
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

The collector's inventory refresh is five minutes; central explicit operations request an immediate inventory afterward. Its process snapshot is every 30 seconds. A central poll reads the newest snapshot. Very slow collection/SSH operations can exceed these cadences and are visible through stale telemetry/hash timestamps.

- **SSH host mismatch:** verify the new fingerprint through the target console, then change it in the UI. Never automatically accept a changed key.
- **Authentication refused:** confirm the bootstrap completed, sshd allows key authentication, the account home is `/opt/drpatch`, the root-owned authorized key is present, and the central IP can reach SSH. Use the ED25519 host fingerprint matching normal key negotiation.
- **Old installer stops at `ssh_host_dsa_key.pub is not a public key file`:** the preparation steps completed, but the old fingerprint-display loop stopped at a malformed/obsolete public key. On a target using the standard ED25519 host key, run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256`, copy only the `SHA256:…` value into enrollment step 3, and finish installation. No DSA key deletion or SSH-key regeneration is required. Updated installers inspect `sshd -T` and derive the fingerprint from the configured ED25519 private host key, so stale or missing `.pub` files do not affect the result. If no usable ED25519 host key is enabled, the script reports that explicitly and stops before claiming enrollment is ready.
- **Missing bootstrap prerequisite:** install Python 3, openssh-server, sudo and OpenSSL through your normal provisioning process; rerun the downloaded installer.
- **APT signing failure:** inspect Activity for the actual APT diagnostic. Obtain/verify the publisher's current public key, upload it, and repair Signed-By. Do not use `trusted=yes` or disable expiry verification.
- **Repository no longer exists:** edit its URI/suite, comment a legacy line, set `Enabled: no`, or save an empty definition. Previous source files are backed up under `/opt/drpatch/backups`.
- **Failed patch:** inspect the job output and target package state. No removal or forced hold changes are requested. A failed command may still have partially installed packages; inventory is refreshed on later polls. Do not assume transactional rollback.
- **Interrupted operation after app restart:** running release upgrades resume receipt observation without replaying installation. Other orphaned running jobs and recovery_required jobs quarantine that host’s queue. Recovery-required jobs create persistent alerts. Inspect package/service state, release journals, pending reboot timers and the temporary service-start guard, then use Activity → Review interrupted operation. See [release recovery](RELEASE_UPGRADES.md#execution-and-recovery-states).
- **Collector integrity mismatch:** investigate first. The repair action redeploys the collector/unit. If the bridge, sudoers or authorized_keys changed, rerun a freshly downloaded bootstrap through a trusted console before finishing installation again.
- **Enrollment reports `Unterminated string` / incomplete JSON:** update/rebuild the central app, then use **Servers → Manage → Finish / verify installation** again. The SSH reader now waits for stream EOF as well as exit status; an early status signal could previously truncate a large package inventory. Genuine malformed or disconnected replies include the action and received-byte count without exposing the inventory. A failed mutation is never automatically replayed; inspect Activity/target state first, especially for patch/recovery jobs. This transport fix does not require deleting the server, rotating keys, or weakening SSH pinning. If enrollment still fails, retain the new action-specific error and check the target SSH/service logs.
- **AI triage reports `HTTPStatusError`:** update the app to see a safe diagnostic including HTTP status, recognized provider code/parameter, request ID when available, and a suggested action. The old exception name alone cannot distinguish authentication, model access, billing, throttling or upstream errors. Correct the saved model/key in **Settings → AI investigations**, save, then click **Test saved AI settings**. The test uses the same Responses API JSON schema and token budget as investigations, sends no target evidence, and is limited to one test per minute per deployment. It is a billable API request. Use **AI run logs → Inspect run** for persisted request stages and the worker-status panel for missing settings/heartbeat, rate limits and backoff. **Investigations → Retry** permits an earlier retry without resetting the hourly allowance. Existing failed observations otherwise become eligible again after their one-hour backoff; a successful connection test does not approve behaviors or rerun those observations immediately.
- **API diagnostic guide:** HTTP 401 indicates authentication/access settings to check; 403/404 can indicate project/model access or an invalid model ID; 429 with quota/credit/spend codes requires correcting API billing/limits, while rate-limit codes call for lower request rates. HTTP 400 parameter/schema errors require a compatible Responses API model with structured-output support. Network/TLS failures identify central-server DNS, outbound HTTPS, proxy or CA checks. Incomplete/refused/malformed model output is never treated as a safety assessment. Raw provider bodies, API keys and evidence echoed by an error are not included in these diagnostics.

See [AI diagnostics, scoring, timing and package-history operations](AI_AND_PACKAGE_HISTORY.md) for the complete workflow, data sent to the provider and history retention.

## HTTPS changes and recovery

Certificate uploads require a matching private key, an unexpired leaf, and SAN coverage for the configured domain. ACME directory URLs must use HTTPS. Uploaded ACME root CA PEM is passed to Caddy's ACME issuer trust store, not installed globally on targets.

Changes are submitted to Caddy's config endpoint for validation/loading and then saved to the shared TLS volume. Automatic renewal applies only to ACME/internal issuance; upload renewed custom certificates yourself. If a domain change interrupts your browser session, use the new hostname. Keep `PUBLIC_URL` aligned in `.env` and recreate the app afterward.

The initial local CA certificate is available through `docker compose cp` as described in the README. Trust the root before sending credentials. Do not publish Caddy port 2019 or app port 8000 to untrusted networks.

## Backup and restore

Back up **all Compose named volumes** and your `.env` securely. For a consistent SQLite backup, stop all app and worker replicas before copying its volume, or use SQLite's online backup mechanism; do not copy only the `.db` while ignoring an active WAL. For MySQL, take a transactionally consistent DB backup and back up the app volume at the same time.

The app volume holds the database (SQLite), SSH private keys, API-secret encryption key, and central APT state. The TLS volume holds HTTPS keys/certificates and the saved Caddyfile. Caddy's volumes contain ACME accounts, its local CA, and issuance state. Losing the app encryption key prevents recovery of encrypted API credentials; losing SSH identities requires target reenrollment.

Recreate the deployment with matching volumes and database, then check host fingerprint pins and collection freshness. Do not run two restored copies against the same database/targets.

## Password reset

There is no unauthenticated password-reset endpoint. With trusted shell access to the Docker host:

```bash
docker compose exec -u mrpatchy app python -c 'import getpass; from app.db import Session,audit; from app.identity import User; from app.security import password_hash; p=getpass.getpass("New administrator password: "); assert len(p)>=12; s=Session(); u=s.get(User,"admin"); assert u is not None; u.password=password_hash(p); u.generation+=1; audit(s,"console password reset","admin"); s.commit(); s.close()'
```

This resets the named account and invalidates its existing sessions. It retains MFA. If MFA recovery is needed, use a separate trusted-console procedure to clear that account’s OTP fields and increment its session generation; changing the legacy `Setting("admin")` hash does not reset a named user.

## Remove a target's access

From a trusted target console, stop/disable the collector and remove its dedicated authorization before deleting any data:

```bash
sudo systemctl disable --now mrpatchy-agent
sudo rm /etc/sudoers.d/mrpatchy
sudo rm /opt/drpatch/.ssh/authorized_keys
sudo rm /etc/systemd/system/mrpatchy-agent.service
sudo systemctl daemon-reload
```

Keep `/opt/drpatch/backups` until you no longer need repository history. Remove the dedicated `drpatch` account and remaining Mr Patchy files through your normal account cleanup process. This release does not include a destructive in-app host deletion/uninstall action.

## References

- APT configuration: https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html
- APT source format and Signed-By: https://manpages.debian.org/bookworm/apt/sources.list.5.en.html
- Caddy TLS/ACME: https://caddyserver.com/docs/caddyfile/directives/tls
- OpenAI error codes: https://developers.openai.com/api/docs/guides/error-codes
- OpenAI request diagnostics: https://developers.openai.com/api/reference/overview
- OpenAI structured outputs: https://developers.openai.com/api/docs/guides/structured-outputs


## v0.2 enrollment and recovery

Use Add server → Endpoint → Prepare → Connect and verify. The third delivery option is offline preparation. Servers → Manage always provides a fresh download of that host's personalized Bash installer. Existing identities are preserved.

Repository credentials, CA/proxy/default-release and mirror mappings are configured under Repositories → Repository access. Source backup restoration is reviewed in the UI. Package recovery is separate from ordinary upgrades and can run maintainer scripts; inspect Activity after errors/timeouts before retrying.

Target events.db is a bounded SQLite spool. Do not delete it as routine cleanup: unacknowledged observations may be lost. Central history retention is configurable. `spool.queued_bytes`, configured limits and reasoned cumulative batch/observation loss counters distinguish an individually oversized record from 48 MB capacity eviction. A new counter increase is actionable; an unchanged cumulative value is retained historical evidence rather than an ongoing-loss claim.

See [completion review and upgrade notes](COMPLETION_REVIEW.md) for migration, validation and platform limits.

## Patch rollout service-health baselines

Scheduled patches and multi-server rollouts capture and persist a fresh service-health snapshot immediately before package changes. The post-patch gate compares systemd unit **names**, ignoring display ordering and description text. Existing failed units such as `logrotate.service` or `systemd-networkd-wait-online.service` remain visible in the job's health comparison but do not by themselves stop an ordinary rollout. A newly failed unit, collector loss, or missing/malformed health data still fails the job and stops dependent rollout jobs. A failure that disappears is listed as recovered.

The comparison records pre-existing, remaining, new and recovered units; the original baseline remains in the durable job payload. This is a service-state regression check, not proof that applications work correctly. It cannot detect worsening behavior inside a unit that was already failed or an application failure that systemd does not report. It does not clear failed-unit state or repair those services. Confirmed package inventory/history remains recorded even when the later health check fails; do not assume a failed job means no packages were installed.

Automatic reboot/rollback workflows retain the stricter requirement for clean service health. Both controller preflight and the updated target helper check it before package changes. Controller preflight failures are ordinary failed jobs, not uncertain patch transactions; the target's check happens before creating its transaction journal. Post-mutation disconnects and recovery failures retain their existing reconciliation requirements. Release upgrades and rollback verification keep their existing strict health checks. Single-server on-demand patches without automatic recovery retain their existing behavior; this change fixes the gates used by scheduled/multi-server rollouts.

Redeploy target helpers through **Finish / verify installation** after updating the controller to obtain the target-side preflight and complete, bounded failed-unit output. Older helpers still support the controller's legacy table parser, but their output may be truncated on hosts with unusually many failed units. Previously failed jobs are not automatically rerun or reclassified.
