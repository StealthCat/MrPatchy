# Mr Patchy

**Patch management, release upgrades and security monitoring for your Linux fleet.**

Mr Patchy is a self-hosted, Dockerized control center for Ubuntu, Debian and Raspberry Pi OS. Manage packages and repositories over SSH, plan AI-assisted release upgrades with one go/no-go approval, monitor system integrity and process behavior, and coordinate patching, alerts and recovery across your fleet.

![Fleet overview with illustrative documentation data](docs/screenshots/overview.webp)

## Features

| Area | Capabilities |
|---|---|
| Enrollment | Three-step endpoint → offline preparation → SSH completion; downloadable per-server Bash installer; expiring curl links; independent installation verification |
| Package management | Installed/held/broken package inventory, inventory history, exact-version updates, dependency simulation, repair, configurable deadlines and priority overrides |
| Repositories | Central native APT signature/index verification; `.list` and Deb822 `.sources`; signing keys, scoped credentials, private CAs, proxies, pinning and mirror mappings |
| Distribution upgrades | Adjacent Ubuntu LTS/Debian release plans, AI configuration diffs, one go/no-go approval, detached execution and verified recovery |
| Safe patch operations | Maintenance windows, staged/canary rollouts, reviewed reboot/rollback policies, post-reboot health retries, durable recovery states and interrupted-host quarantine |
| Monitoring | 30-second process/connection sampling, five-minute integrity sweeps, network namespaces, script and mapped-library provenance, optional eBPF exec capture |
| Investigations | Optional two-stage OpenAI triage, fixed read-only evidence checks, explicit known-good approvals, durable observation spool and retained history |
| Identity | Named administrator/operator/viewer accounts, TOTP MFA, session revocation, OIDC SSO with explicit issuer/subject bindings, verified SSH-key rotation |
| Notifications | Persistent monitoring and recovery-required alerts with acknowledgements and retries; verified-TLS SMTP or HTTPS webhook delivery |
| Deployment and recovery | SQLite or MySQL, coordinated worker replicas, Caddy HTTPS, certificate upload/custom ACME, encrypted restic backup and staged restore |

[Quick start](#quick-start) · [Enrollment](#enroll-a-server-in-three-steps) · [Release upgrades](#distribution-release-upgrades) · [Recovery](#workers-databases-and-backups) · [Documentation](#documentation)

## Quick start

Requirements: Linux with Docker Engine and Compose v2, SSH access to targets, and HTTP(S) access to their repositories. Configure Caddy's published interface/ports with `BIND_IP`, `HTTP_PORT` and `HTTPS_PORT`; keep the app and Caddy administration ports private. Compose trusts forwarded client addresses only from Caddy's dedicated control-network IP. If `172.30.254.0/24` overlaps your network, change `CONTROL_SUBNET`, `CADDY_CONTROL_IP` and `APP_CONTROL_IP` in `.env` before starting.

```bash
git clone https://github.com/StealthCat/MrPatchy.git
cd MrPatchy
cp .env.example .env
# Edit ADMIN_PASSWORD, DOMAIN and PUBLIC_URL before starting.
docker compose up -d --build
```

Open `https://YOUR_DOMAIN`. Sign in as **admin** using your initial `ADMIN_PASSWORD` (at least 12 characters). The database stores the password hash; changing `.env` afterward does not reset the account.

The initial certificate uses Caddy's local CA. Trust its public root certificate on your administrator device before signing in:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./mrpatchy-local-ca.crt
```

In **Settings → Configure HTTPS**, configure independent **Internal** and **External / public** profiles. Each supports an uploaded certificate/key, Let's Encrypt or a custom ACME directory (with optional CA bundle, account email and EAB), or Caddy's built-in CA. Profiles use different hostnames on the same HTTPS listener. Existing generated single-site configurations migrate to the Internal profile with their certificate material preserved.

For example, bind only your server's LAN address using alternate host ports:

```dotenv
BIND_IP=192.168.1.20
HTTP_PORT=8080
HTTPS_PORT=8443
DOMAIN=patchy.home.example.com
PUBLIC_URL=https://patchy.home.example.com:8443
```

Run `docker compose up -d --build` after changing bindings. Optional `HTTP_BIND_IP` and `HTTPS_BIND_IP` override the shared address; HTTPS TCP and HTTP/3 UDP use the same address/port. HTTP redirects follow `HTTPS_PORT`, including after a container recreation. A profile's browser-facing port override handles routers that expose a different external port.

For dual CAs, use a private ACME server for `patchy.home.example.com` and Let's Encrypt for `patchy.example.com`. Both DNS names reach the same listener; TLS selects the appropriate certificate by hostname. **Internal is a certificate profile, not an access-control boundary**—use network controls if one name must be LAN-only. Public ACME HTTP-01/TLS-ALPN-01 validation still requires external TCP 80/443 forwarded to Caddy, even when Docker publishes 8080/8443. Wildcard issuance/DNS-01 is not included. Keep `PUBLIC_URL` aligned with the default enrollment/SSO address; curl enrollment can also use either enabled HTTPS profile. See [Docker bindings and dual TLS](docs/DOCKER_TLS.md) for setup, migration and recovery.

## Enroll a server in three steps

Targets need systemd, Python 3, OpenSSH server, sudo, OpenSSL and dpkg installed already. Offline preparation does not download missing prerequisites.

1. **Endpoint:** select **Add server** and enter a name, IP/hostname and SSH port.
2. **Prepare:** download the personalized Bash script, transfer it to the target and run `sudo bash mrpatchy-enroll.sh`. It creates `/opt/drpatch`, the `drpatch` account, its public SSH key, the root-owned bridge and restricted sudo permissions. The script performs no downloads, APT queries or callbacks. Click **I ran the script · Proceed to step 3**. Curl and ordinary-download delivery use the same bootstrap; curl links expire after one hour. In curl mode, select **Fetch from HTTPS endpoint**: the default `PUBLIC_URL`, **Internal HTTPS**, or **External HTTPS**. Enabled profiles use their configured hostname and browser-facing port. Choose an address reachable from the target; for a private CA, use curl’s `--cacert /path/to/ca.pem` with a trusted bundle for the site certificate.
3. **Connect and verify:** verify the printed ED25519 SHA256 host fingerprint through a trusted console, enter it, and click **Finish and verify installation**. Mr Patchy installs its collector/service over SSH and verifies file hashes, ownership, modes and service state.

**Servers → Manage → Download Bash installer** remains available for every configured server. A fresh download contains the server's current SSH identity; download again after key rotation. Re-running an old saved script can reinstall its old public key.

![Offline enrollment wizard](docs/screenshots/enrollment.webp)

![Curl enrollment with selectable HTTPS endpoint](docs/screenshots/enrollment-curl.webp)

## Review and install updates

Package discovery runs native APT **centrally**, using isolated target inventories, architectures, source definitions, keys and preferences. The collector does not run target APT queries for discovery. An offline target can still have repository metadata checked against its last saved inventory.

In **Packages**, select a server, review candidates and choose updates. Confirmation displays the effective reboot and snapshot-rollback policy. That policy is recorded with the job; if it changes before execution, the job fails for reapproval rather than silently adopting different behavior. Staged rollouts require the same policy review for every server.

Explicit installation refreshes target metadata and requests the recorded exact versions. Package removal and forced changes to holds are prohibited; existing configuration files are retained with `--force-confold`. Maintainer scripts may restart services. **Automatic reboot is available only under an explicitly reviewed, enabled policy.**

![Patch approval showing reboot and rollback policy](docs/screenshots/patch-review.webp)

| Priority | Default deadline |
|---|---:|
| Critical | 24 hours |
| High | 72 hours |
| Normal | 168 hours |
| Low | 720 hours |

Deadlines start at first discovery of an outstanding update and do not reset when a newer candidate supersedes it. Once the package is current, a future update starts a new deadline. Security-origin updates default to high; others default to normal. These are scheduling heuristics, **not CVSS severity ratings**. Deadlines highlight overdue work; they do not automatically approve upgrades. Unattended installation requires an explicitly enabled patch schedule.

**Account → Operations** provides UTC maintenance windows, ordered canary rollouts and advisory matching. Windows gate job start; a long installation/recovery can extend past the window. Advisory matching is opt-in and currently maps Ubuntu/Debian source packages to OSV; derivative coverage is explicitly limited.

## Scheduled and out-of-cycle patching

Open **Patch schedules** in the main menu to configure daily, weekly or monthly patching for all configured servers (including future enrollments) or a selected group. Set an IANA timezone, start time, allowed start-window length and regular priorities. The month calendar and hourly day view show upcoming windows and recorded urgent runs; times in the calendar use your browser’s timezone.

Each schedule can independently enable **high** and **critical** out-of-cycle updates after a configurable delay from first discovery. These rules respect server maintenance windows unless you explicitly authorize a bypass for that priority. Detection follows the central repository check interval. Priority labels are Mr Patchy policy labels, not automatic CVSS classifications.

Review and explicitly approve unattended installation before enabling a schedule. Jobs refresh signed repository metadata, select exact candidate versions and preserve package holds, host-key verification, recovery quarantine and per-host serialization. Unhealthy/offline targets wait within the allowed start window. Missed windows are skipped; pausing, editing or deleting cancels queued work while already running patches may finish. The selected reboot/rollback behavior must match each target’s saved recovery policy.

![Monthly patch calendar](docs/screenshots/patch-calendar.webp)

See [scheduling behavior, daylight saving, safety checks and failure handling](docs/PATCH_SCHEDULES.md). Distribution release upgrades still use their separate reviewed GO workflow.

## Reboot, rollback and interrupted operations

Configure each host under **Account → Operations → SSO, SMTP & target policies**. Reboot and rollback default off, and the controls load the saved policy when you select a server.

- Rollback requires a validated root-owned `/etc/mrpatchy/rollback` adapter and a bootable snapshot layout. A Snapper/Btrfs adapter is included; arbitrary ext4 systems do not gain snapshot rollback automatically.
- The target journals reboot intent **before** submitting a reboot. Completion requires a changed boot ID and healthy services.
- Transient SSH/health failures are retried for up to ten minutes. Persistent post-reboot health failure requests one approved snapshot rollback; a rollback reboot is verified separately.
- Before a rollback-enabled patch, the central database durably records the original inventory fingerprint, configuration hashes/ownership/modes and running services. Rollback must restore that evidence, clean dpkg state and service health; a healthy boot alone is insufficient. Missing or changed evidence requires reconciliation.
- A verified rollback leaves the patch job failed and blocks later rollout stages. Uncertain recovery becomes `recovery_required`.
- Orphaned `running` and `recovery_required` jobs block further queued work and configuration mutations for that host. Monitoring continues. Busy workers skip the host instead of tying up another worker slot.
- After inspecting package/service state, snapshots and pending reboot timers through a trusted console, use **Activity → Review interrupted operation**. Reconciliation also requires idle central and target mutation locks. It releases the queue without replaying the interrupted job.

A host that never returns over SSH cannot be automatically repaired from the central service. Keep an out-of-band recovery path. See [recovery contracts and procedures](docs/ENTERPRISE_RECOVERY.md).

## Distribution release upgrades

Use **Servers → Manage → Plan distribution upgrade** to prepare a saved release plan. Mr Patchy resolves package changes centrally, compares package-owned configuration with authenticated new vendor defaults, and uses the configured OpenAI API to propose the required edits. Review the diffs, package changes and recovery prerequisites, then choose **GO** or **No-go**.

Cancelling a queued planning or upgrade job also cancels its linked plan. Prepare a fresh plan before another GO; cancellation does not preserve approval.

One GO authorizes the named release transition, displayed configuration edits, service interruption, reboot and one snapshot rollback. The detached target runner survives SSH disconnects; workers resume observation after a central restart without replaying installation or resetting recovery deadlines. The approved plan binds configuration, inventory and executable recovery/validation hooks. A rollback is successful only when the original inventory, repository trust, configuration and services have been verified. Uncertain recovery quarantines the host and creates an alert.

Supported paths are Ubuntu **22.04 → 24.04 → 26.04 LTS** (only when offered by Ubuntu) and Debian **11 → 12 → 13**, one hop at a time on amd64/arm64 systemd hosts. Ubuntu uses its official release upgrader; its package list is labeled an estimate. Raspberry Pi OS major versions are flagged as requiring a new-image migration.

![Release upgrade review and configuration diff](docs/screenshots/release-upgrade.webp)

A tested release-capable snapshot adapter is mandatory. Generic root-only Snapper snapshots do not automatically qualify. AI review sends configuration text to your API provider and covers package-owned conffiles; custom applications, data migrations and external volumes require site-specific validation/recovery. Blockers disable GO. See [release upgrades, privacy, adapter contracts and limits](docs/RELEASE_UPGRADES.md) before enabling this workflow.

## Repository management

Use **Repositories** to inspect, add, edit or disable sources, upload signing keys and restore reviewed source backups. **Repository access** configures scoped HTTPS credentials, private CA bundles, proxies, default release and exact-URI mirror mappings. Secrets are encrypted in the database and staged in a private central APT auth file.

HTTP(S) repositories are supported directly. Local/media sources require an administrator-provisioned HTTP(S) mirror containing the same signed metadata. Arbitrary target `apt.conf` hooks and executable authentication/transport helpers are never imported. Deb822 field names must use canonical spelling without spaces or tabs before the colon; ambiguous or duplicate fields are rejected before native APT. Unsupported configurations remain visible and fail closed; “all repositories” is not an unconditional transport-compatibility claim.

**Servers → Manage → Repair broken package state** explicitly performs dependency repair and dpkg configuration. It can install dependencies and run maintainer scripts; inspect failed results before retrying.

## Monitoring, provenance and AI

Default cadences are **60 minutes** for configurable repository checks, **30 seconds** for process/socket sampling, and **five minutes** for integrity sweeps. Slow targets or large fleets can delay them; stale telemetry and overdue sweeps are reported.

The collector hashes Mr Patchy's managed files and readable running executables. Script operands, including supported interpreter options such as Python `-I`/`-u`, and executable-mapped libraries contribute to behavior identity. Inline code, modules, preloads and unrecognized option layouts retain explicit unverified entries without exporting argument values. Libraries are read through `/proc/PID/map_files` where permitted, or through a pathname only when its device/inode still matches. Deleted/inaccessible/replaced mappings remain explicit unverified evidence. Script hashes describe files, not the interpreter's live memory. Limits are 128 provenance files per process and 128 MiB per file. Descriptor-based hashing checks inode changes and uses a two-second per-file and ten-second per-sweep elapsed budget. Oversized, inaccessible or changed executables remain visible as unverified; these cooperative budgets cannot interrupt a kernel-stalled filesystem read.

Optional bpftrace exec capture retains short-lived observations. Unverifiable identities stay marked unverified through central processing. Enabling eBPF relaxes the collector sandbox for kernel tracing; kernel support and acceptance testing are required. It is not guaranteed lossless capture or hardware attestation.

Enable AI in **Settings** with an OpenAI API key and a compatible Responses API model. Each investigation uses at most two calls and only fixed, read-only follow-up checks. The default cap is 20 investigations/hour. No model-generated shell command runs, and no AI verdict automatically approves behavior. Process-investigation evidence can include paths, hashes, UIDs and network endpoints; arguments, environment variables, process memory and file contents are not sent by that workflow. Release configuration planning separately sends eligible configuration text, as disclosed before planning. `store: false` does not override organization-level API retention policies. API billing is separate from ChatGPT subscriptions.

The target's durable spool acknowledges batches only after central commit; overflow is visible. Each poll drains up to 32 eight-record batches within a ten-second catch-up budget, fetching events without repeating the full inventory. Outstanding batches stay queued for the next poll. Inventory/observation history defaults to 30-day retention. Known-good behavior approvals are tied to exact recorded identities, including provenance and verification uncertainty.

## Accounts, SSO, notifications and keys

**Account** manages named users, roles, authenticator MFA, password changes and session revocation. Administrators manage infrastructure and trust; operators can preview/queue patches and refresh repositories; viewers inspect monitoring.

Account and Sign out remain available in the header on mobile. Navigation and action controls reflect the signed-in role; the API independently enforces permissions. Password verification and MFA setup/confirmation share a limit of ten attempts per account in five minutes. A failed verification leaves the current session intact; successful password/MFA changes and session revocation require signing in again.

For OIDC, set `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`, register `PUBLIC_URL/auth/sso/callback`, then bind the provider's immutable subject to an existing local account. Preserve the exact issuer, including any trailing slash. SSO uses code/PKCE, nonce/state, validated ID tokens and one-time callback state. Configure MFA at your identity provider for SSO logins.

SMTP requires verified TLS or STARTTLS, with optional private CA support. SMTP and HTTPS webhooks are alternative delivery channels. Alerts use a durable retrying outbox and acknowledgements; delivery is at least once. SSH rotation proves a replacement key works before removing the old target key and records a resumable journal.

**Account → Operations** loads the selected server's saved maintenance windows. Notification forms load saved metadata without returning credentials. Leave a secret blank to retain it, or select its explicit clear checkbox to remove it. Changing the webhook URL or SMTP host, port, encryption mode or username requires providing or explicitly clearing the secret. Saving the other delivery channel replaces the current channel. **Activity** lets administrators cancel queued operations before execution; a linked release plan is also cancelled and needs replanning.

## Workers, databases and backups

Compose separates the web app, worker and Caddy services. Keep one web process. Scale workers on the same host with:

```bash
docker compose up -d --build --scale worker=3
```

Workers claim durable SQL jobs and coordinate with per-host locks; one elected coordinator polls and schedules. SQLite workers must share the same local app volume. Separate worker hosts require MySQL plus consistent shared identity/encryption storage; unrelated disks or SQLite over NFS are unsupported.

For an existing MySQL 8+ database, set a URL-encoded connection string in `.env` and recreate **both app and workers**:

```dotenv
DATABASE_URL=mysql+pymysql://mrpatchy:URL_ENCODED_PASSWORD@db-host:3306/mrpatchy?charset=utf8mb4
```

Switching the URL does not migrate existing data. Configure verified database TLS through your connection settings for remote deployments.

Use [the encrypted restic workflow](docs/ENTERPRISE_RECOVERY.md#complete-encrypted-off-host-recovery) to back up the database, encryption key, complete SSH rotation directory and TLS/Caddy volumes. Stop **all app and worker replicas** first. SQLite sources must exist, pass integrity checks and contain the application tables; a missing path cannot create an empty successful backup. Restore verifies content into staging before activation into empty destinations. Protect `.env`, IdP/database secrets and restic credentials separately through your infrastructure recovery procedures.

The older `scripts/backup.py` is a limited SQLite export; use `scripts/recovery.py` for full deployment recovery. Test restores before relying on them.

## Upgrade

1. Back up the database and all persistent volumes with app/workers stopped.
2. Pull `main`, review `.env`, then run `docker compose up -d --build`.
3. Use **Servers → Manage → Finish / verify installation** to upgrade each managed bridge/collector. Legacy bootstrap targets may require a fresh installer run through a trusted console first.
4. Regenerate unexecuted release plans after updating helpers; old plans cannot authorize changed runner, bridge or recovery/validation code. Do not update helpers while a release upgrade is running.
5. Review queued jobs: jobs created before recovery-policy capture cannot inherit an enabled reboot/rollback policy; resubmit them after reviewing the policy.
6. Reconcile interrupted/recovery-required jobs before resuming those hosts. Review new provenance identities rather than automatically transferring old approvals.

Schema initialization is idempotent. MySQL upgrades need ALTER privileges for existing timestamp/package-state migrations.

## Validation and development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
npm ci
npx playwright install chromium
npm run test:ui
```

CI covers SQLite/MySQL, signed repository fixtures, real SSH enrollment/rotation on Ubuntu and Debian, Docker HTTPS startup, desktop/mobile browser flows and an encrypted SQLite restic restore drill. Regression coverage includes orphan quarantine, policy approval, lost SSH replies, worker restart/recovery deadlines, original-system rollback verification, pinned Debian upgrade stages, dependency markings, stale browser responses, secret filtering, missing-database refusal, exact OIDC issuers and provenance uncertainty.

Browser regressions also exercise all three roles, 320px/390px layouts, account access, persisted maintenance and SMTP settings, queued cancellation, inline dialog errors, duplicate patch clicks, and delayed responses after navigation, dialog dismissal or sign-out.

Real distribution release upgrades, Raspberry Pi/systemd hardware, live IdP/SMTP/custom-ACME services, kernel eBPF attachment, bootable filesystem rollback and off-host provider connectivity require acceptance tests in your environment. The existing MySQL CI suite does not constitute a MySQL dump/import disaster-recovery drill.

Generate documentation screenshots with `SCREENSHOT_DIR=/tmp/mrpatchy-shots npm run test:ui`. Screenshots use illustrative fixtures and documentation-only addresses, not live infrastructure.

## Documentation

- [Operations and troubleshooting](docs/OPERATIONS.md)
- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Enterprise configuration and recovery](docs/ENTERPRISE_RECOVERY.md)
- [Distribution release upgrades](docs/RELEASE_UPGRADES.md)
- [Post-review fixes](docs/REVIEW_FIXES.md)
- [Latest code and interactive browser review](docs/FULL_REVIEW_2026-10-25.md)
- [Historical reviews](docs/COMPLETION_REVIEW.md) and [expansion checkpoint](docs/OPERATIONS_EXPANSION.md)

Central administrators and holders of target SSH keys can deploy root code. Protect the management network, accounts, database and secret volumes accordingly. A compromised target root/kernel can forge telemetry; hashes are not remote attestation.
