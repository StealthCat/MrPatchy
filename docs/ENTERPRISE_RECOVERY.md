# SSO, worker scaling, target recovery and off-host backup

These features supersede the corresponding unfinished items in OPERATIONS_EXPANSION.md. They are implemented but need configuration and platform acceptance in your environment. No IdP, SMTP recipient, target reboot, rollback, or off-host provider is contacted automatically during installation or development tests.

## SSO

Set OIDC_ISSUER (HTTPS exact issuer), OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and an HTTPS PUBLIC_URL. Register PUBLIC_URL/auth/sso/callback at the provider. The authorization-code flow uses PKCE, state, nonce and Authlib ID-token signature/issuer/audience/expiry validation. Discovery endpoints must use HTTPS. Callback state is consumed once in the database.

Create a local account/role, then use **Account → Operations → SSO, SMTP & target policies** to bind the provider's immutable subject. Email/domain matching never grants access. The provider governs SSO MFA policy; configure conditional access/MFA there. Local authenticator MFA remains available for password login. The local admin account remains a recovery path. The IdP client secret is a deployment secret, not a browser setting.

## SSH-key rotation

The server action rotate-key, available in advanced controls, adds a replacement Ed25519 key alongside the old key, tests login with the replacement, atomically promotes it centrally, removes the old target key, and verifies login again. Both entries retain the forced command and restricted SSH options. A private rotation journal allows an interrupted operation to resume.

A failure before replacement-key authentication leaves the old central key intact. If the host cannot be reached, use its freshly downloaded installer via a trusted console. Back up the complete ssh directory, including pending keys and rotation journals. Rotation updates the expected authorized_keys integrity hash.

## SMTP

Advanced controls configure SMTP host/port, TLS or STARTTLS, credentials, sender, recipients and optional private CA. Plaintext SMTP is not supported. STARTTLS succeeds before credentials are transmitted; server certificates are verified. Configuration is encrypted at rest. SMTP and webhook are alternative delivery channels in this release.

The durable alert outbox retains retry state. Stable Message-ID/event IDs permit receiver deduplication; delivery is at least once, not exactly once. Acknowledged/resolved alerts stop retrying. Configuration alone does not send a test email.

## Automatic reboot and rollback

Per-host recovery policies default off. Patch and rollout confirmations display and capture the effective policy. A policy change before execution requires reapproval. Maintenance windows gate job start; recovery may extend past the window.

- Before patching with rollback enabled, central SQL stores a versioned original-state receipt before any target mutation. The target rechecks it before a trusted adapter probes and creates a snapshot. Unsupported old helpers fail closed; finish/verify installation first.
- The target writes a durable transaction journal, including reboot intent before submission. An interrupted attempt is never silently replayed or considered complete merely because package installation ended.
- A failed patch or post-patch health check invokes rollback automatically.
- A successful patch schedules reboot only if policy permits it and /var/run/reboot-required exists.
- Central completion retries transient SSH/service health failures for up to ten minutes and requires a changed boot ID. Persistent post-reboot health failure invokes one approved rollback when the target is reachable and has actually rebooted. A rollback reboot has its own verification window. Successful rollback still fails the patch stage and blocks rollout advancement.
- Original evidence is retained in the SQL job payload, independent of display-output truncation and the target journal. Both immediate and post-reboot rollback require the original package/OS/repository/key fingerprint, configuration manifest, clean dpkg audit, healthy collector and previously running services. A no-op adapter cannot pass after package/configuration changes. Uncertain recovery becomes recovery_required and quarantines the host.
- If rollback requires reboot while reboot policy is disabled, the job reports that a manual reboot is required.

The ordinary-patch configuration manifest covers `/etc` (including untracked files, directory permissions and symlink targets), dpkg conffile paths and managed helpers. It records hashes and metadata, not plaintext. Capture is limited to 10,000 entries, 3 MB serialized evidence and a 30-second hashing/traversal budget; oversized or unsupported file types block automatic rollback preparation. Symlinked directories are not traversed. It does not attest application data, external volumes, ACLs/xattrs or live memory. Site-specific snapshots/validation must cover those. Legitimate configuration changes during recovery can require manual reconciliation.

Install a validated root-owned executable at /etc/mrpatchy/rollback. It must not be group/world writable or a symlink. The fixed JSON contract is:
- probe JOB_ID → {"ready":true}
- snapshot JOB_ID → {"snapshot":"safe-identifier"}
- rollback SNAPSHOT_ID → {"reboot_required":true}

A Snapper/Btrfs root adapter is included at deploy/adapters/snapper-rollback. Install with mode 0755 only after testing that the target's root snapshot and bootloader layout can actually boot a rollback. ZFS/LVM/VM installations can implement the same fixed adapter contract. The app does not pretend an arbitrary ext4 Raspberry Pi has snapshot rollback. Snapshot scope determines which data is reverted; this is not a universal database/application transaction rollback guarantee.

## Distributed workers

Compose now separates the web app from workers:
```bash
docker compose up -d --build --scale worker=3
```
Workers atomically claim durable SQL jobs and use per-host cross-process locks. One elected coordinator polls targets, schedules repository checks, dispatches AI and handles notifications; other workers execute jobs. MySQL named locks coordinate separate hosts; SQLite uses filesystem locks and supports workers sharing the same local app volume, not unrelated disks/NFS.

All replicas must share the database, app encryption key and SSH identity storage. For workers on separate hosts, use MySQL and consistent shared/replicated secret storage; do not independently generate identities. Keep one web process unless separately validating deployment/migration coordination.

Orphaned running and recovery_required jobs block subsequent queued work and configuration mutations for that host; polling continues. Dispatch reserves the cross-process host lock before consuming a local job slot, including resumed release observations. Failed submissions release their reservations; locks held by other replicas cannot starve unrelated queued work. Review the target and pending reboot timers through a trusted console, then use Activity → Review interrupted operation or POST /api/operations/jobs/JOB/reconcile with {"verified_target_state":true}. This requires the central host lock to be free and the target mutation lock to be idle, and marks the job interrupted without resubmitting it. External side effects such as mail cannot be guaranteed exactly-once.

## eBPF and provenance

Script and executable-mapped library hashes are collected through procfs without exporting command-line arguments or file contents. Coverage is bounded to 128 files per process and 128 MB per file. Deleted or inaccessible mapped files are retained as unverified entries. map_files reads are preferred; a pathname fallback must match the mapped device/inode. The eBPF identity_verified flag survives central normalization and AI triage. Common interpreter option layouts are parsed conservatively, including Python `-I`/`-u` and `--`. Inline code, modules, preloads and unknown option layouts produce unverified evidence without argument values. Executables use the same descriptor/size/change checks as libraries; file and sweep elapsed budgets prevent ordinary oversized files from monopolizing collection. A blocked kernel filesystem read cannot be interrupted by a cooperative elapsed check.

Central polling drains up to 32 eight-record batches with a ten-second catch-up budget and separate lightweight event reads. Every batch commits before acknowledgement; lost acknowledgements replay idempotently. Remaining backlog stays durable. The target exposes its 48 MB capacity, queued bytes and cumulative oversize/capacity batch and observation losses; recovered cumulative loss remains telemetry, while only a counter increase creates a current integrity finding.

Advanced controls opt into bpftrace sched_process_exec events. Install bpftrace and compatible kernel tracing/BPF facilities on the target first. Missing tools, denied attachment, diagnostics and buffer errors are surfaced. Exited processes are retained as unverified exec observations when hashing is no longer possible. This is event-assisted monitoring, not guaranteed lossless kernel telemetry or hardware attestation.

Enabling BPF explicitly relaxes the collector's service sandbox to permit kernel tracing. The installed systemd override is included in the integrity baseline. Disabling BPF removes it and restores the base unit restrictions. Namespace identity and script/library provenance participate in behavior identity; existing approvals do not silently transfer.

## Complete encrypted off-host recovery

scripts/recovery.py uses restic for encrypted, content-verified off-host storage. It supports SFTP, S3, HTTPS REST and other listed restic remote backends. Install restic and, for MySQL, MariaDB client tools. Provision repository credentials through standard restic environment/password-file mechanisms; initialize the repository with restic init first.

Stop **all** web and worker replicas before taking a coordinated backup. Backups contain:
- SQLite snapshot or consistent MySQL dump, including routines/events/triggers;
- encryption key and entire SSH identity/rotation directory (an explicit empty directory for a deployment with no servers yet; a private key must be present for every server that is not deleted, or backup and activation stop);
- TLS configuration, Caddy certificate/private-CA data and Caddy configuration.

For remote MySQL connections set MYSQL_SSL_CA; verification is mandatory. Store the restic password separately from the repository and test recovery credentials.

```bash
export RESTIC_REPOSITORY='sftp:backup-host:/srv/backups/mrpatchy'
export RESTIC_PASSWORD_FILE='/secure/restic-password'
# For MySQL also set DATABASE_URL and, for non-local DB hosts, MYSQL_SSL_CA.
python scripts/recovery.py backup --app-stopped \
  --data /volumes/app-data --tls /volumes/tls-config \
  --caddy-data /volumes/caddy-data --caddy-config /volumes/caddy-config
python scripts/recovery.py check
python scripts/recovery.py snapshots
python scripts/recovery.py restore --snapshot latest --destination /empty/recovery-staging
python scripts/recovery.py activate --app-stopped --bundle /empty/recovery-staging/bundle \
  --data /empty/app-data --tls /empty/tls-config \
  --caddy-data /empty/caddy-data --caddy-config /empty/caddy-config
```

Backup opens an existing SQLite source read-only and checks integrity plus core application tables. Restore repeats those checks; activation validates bundle files/directories before destination mutation. Restore verifies restic content and SQLite integrity; activation refuses nonempty volume destinations and nonempty MySQL databases. When run as root it sets app/TLS ownership to UID 10001 (override with --uid). Recreate containers on the restored volumes, verify login, host-key pinning, TLS and a disposable target before resuming patching. DNS, firewall, Compose/.env secrets, restic credentials and MySQL server provisioning must be recovered through your infrastructure procedures.

## Validation boundaries

Automated tests cover protocol/policy behavior, key rotation over real SSH, cross-process locking, SQL compatibility, UI smoke checks and an encrypted restic backup/restore drill. The restic drill uses a local repository transport fixture; real off-host connectivity depends on your configured provider.

Actual IdP federation, SMTP delivery, BPF kernel attachment, hardware reboot and bootable filesystem rollback require acceptance tests in your environment. Unit mocks and container service stubs are not reported as proof of those conditions.

References:
- https://docs.authlib.org/en/latest/oauth2/client/web/
- https://bpftrace.org/tutorial-one-liners
