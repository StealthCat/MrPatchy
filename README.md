# Mr Patchy

Current source version: **1.35.30** · [Changelog](CHANGELOG.md). Source versions do not imply a published Docker image.

The major version stays at **1** until explicitly changed by the user. Existing minor/patch increments and all other [versioning instructions](AGENTS.md) continue to apply.

**Patch management, release upgrades and security monitoring for your Linux fleet.**

Mr Patchy is a self-hosted, Dockerized control center for Ubuntu, Debian, Raspberry Pi OS, Fedora and modern DNF/Yum-based RPM systems. Manage packages and repositories over SSH, plan AI-assisted release upgrades with one go/no-go approval, monitor system integrity and process behavior, and coordinate patching, alerts and recovery across your fleet.

![Fleet overview with illustrative documentation data](docs/screenshots/overview.jpg)

Meet **Mr Patchy**, the slightly wild raccoon in patched overalls keeping you company throughout the workspace. The glass interface brings consistent controls, readable status cards, responsive navigation, and guided enrollment to every part of fleet care. [UI design and component guide](docs/UI_DESIGN.md).

[Sign-in preview](docs/screenshots/login.jpg) · [Mobile workspace](docs/screenshots/mobile.jpg) · [Settings](docs/screenshots/settings.jpg) · [AI settings](docs/screenshots/ai-settings.jpg)

## License

**Free for individual, personal, noncommercial use. Commercial and organizational
use requires a separate paid license before deployment.**

See [LICENSE](LICENSE) for the full Mr Patchy Personal and Commercial License v1.0
and [COMMERCIAL.md](COMMERCIAL.md) for examples and commercial-license requests.
A personal homelab or private household is free; employer/client systems, paid
services and organizational deployments require a paid agreement or a separate
written exception. Pricing and scope are agreed in writing with Robert Cronin
through the [official project](https://github.com/StealthCat/MrPatchy/issues).

This is source-available software with commercial-use restrictions. Third-party
licenses and earlier valid license grants remain unchanged. New contributions
follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Features

| Area | Capabilities |
|---|---|
| Workspace | Dedicated server pages with tabbed overview, packages, patching timeline, investigations, AI activity, history, repositories and maintenance; glass panels, mascot-guided onboarding, modular UI components, responsive desktop/mobile layouts, keyboard focus and reduced-motion support |
| Enrollment | Three-step endpoint → offline preparation → SSH completion; downloadable per-server Bash installer; expiring curl links; independent installation verification |
| Package management | Installed/held/broken inventory, select-all reviewed batches, explained AI importance scores, expected start times, per-package change history, exact-version updates, APT dependency simulation, RPM target-side resolution, repair and priority policies |
| Repositories | Central native APT/DNF verification; `.list`, Deb822 `.sources` and RPM `.repo`; signing keys, scoped credentials, private CAs, proxies, pinning and mirror mappings |
| Distribution upgrades | Adjacent Ubuntu LTS/Debian release plans, AI configuration diffs, one go/no-go approval, detached execution and verified recovery |
| Safe patch operations | Maintenance windows, staged/canary rollouts, reviewed reboot/rollback policies, post-reboot health retries, durable recovery states and interrupted-host quarantine |
| Monitoring | 30-second process/connection sampling, five-minute integrity sweeps, network namespaces, script and mapped-library provenance, optional eBPF exec capture |
| Investigations | Optional two-stage OpenAI triage, persistent redacted run logs, worker health/backoff diagnostics, bounded manual retry, fixed read-only evidence checks, explicit known-good approvals and a saved-settings connection test |
| Identity | Local administrator password-reset script, dedicated Users page, named administrator/operator/viewer accounts, self-service passwords, TOTP MFA, session revocation, OIDC SSO with explicit issuer/subject bindings, verified SSH-key rotation |
| Notifications | Persistent monitoring and recovery-required alerts with acknowledgements and retries; verified-TLS SMTP or HTTPS webhook delivery |
| Deployment and recovery | SQLite or MySQL, coordinated worker replicas, Caddy HTTPS, certificate upload/custom ACME, encrypted restic backup and staged restore |

[Quick start](#quick-start) · [Enrollment](#enroll-a-server-in-three-steps) · [Release upgrades](#distribution-release-upgrades) · [Recovery](#workers-databases-and-backups) · [Documentation](#documentation)

## Server workspaces

Open **Servers → a server name** (or **Open server**) to see everything recorded for that server in one place. Separate tabs cover its overview, packages, patching timeline, investigations, AI activity with estimated costs, history, repositories and maintenance. Switch servers while keeping the same tab, or bookmark a server tab directly. Sensitive tabs and actions retain the existing role permissions.

Administrators can **Disable server** or **Delete server** from **Servers → Open server → Settings → Server management**, the server list, or the **Manage** dialog. These controls require an administrator account. If they are missing, update/rebuild the controller and verify its displayed source version is **0.4.1** or later. Disable suspends polling, scheduled work and host AI requests, cancels queued operations and revokes enrollment links. Enable resumes future management; cancelled jobs do not restart. Delete requires the exact server name and a reason, removes local SSH/repository credentials and removes the entry from the managed fleet. **Servers → Deleted servers** retains read-only inventory, patching, AI, security and audit history. Running work and unresolved response/recovery holds must be reconciled before deletion. These controls leave the remote agent, account and services running; uninstall them separately through a trusted console if required. See [server lifecycle safeguards](docs/SECURITY_IMPLEMENTATION.md#server-management-lifecycle).

![Individual server overview with illustrative data](docs/screenshots/server-overview.jpg)

[Server tabs and permissions](docs/SERVER_WORKSPACES.md) · [Patching timeline preview](docs/screenshots/server-patching.jpg)

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

In **Settings → HTTPS & certificates → Configure HTTPS**, configure independent **Internal** and **External / public** profiles. Each supports an uploaded certificate/key, Let's Encrypt or a custom ACME directory (with optional CA bundle, account email and EAB), or Caddy's built-in CA. Profiles use different hostnames on the same HTTPS listener. Existing generated single-site configurations migrate to the Internal profile with their certificate material preserved.

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


## Reset an administrator password locally

From your deployment directory, with the updated app container running:

```bash
./reset-admin-password.sh
# Another existing administrator:
./reset-admin-password.sh --username alice
# Explicit account recovery when required:
./reset-admin-password.sh --username alice --reset-mfa --enable
```

The script prompts twice without echoing the password (12–1024 characters), updates the existing administrator and revokes their sessions. MFA and disabled status are preserved unless their flags are selected. It never creates/promotes an account or changes SSO bindings. Access to Docker/the database is required; there is no public password-reset endpoint.

For a script stored elsewhere, set `MRPATCHY_PROJECT_DIR` to the deployment directory. `COMPOSE_FILE` and `COMPOSE_PROJECT_NAME` can select your deployment. Automation can pipe a secret from its secret manager into `./reset-admin-password.sh --password-stdin`; do not put passwords in command arguments, shell history or environment variables. A direct installation can run `python -m app.admin_reset` with its existing `DATA_DIR`/`DATABASE_URL`. If login was rate-limited, wait five minutes or restart the app after resetting.

## Enroll a server in three steps

Targets need systemd, Python 3, OpenSSH server, sudo and OpenSSL installed already. Debian-family targets need dpkg; RPM targets need `python3-dnf` and `python3-rpm` (including Fedora with DNF5). SELinux-enabled targets need `policycoreutils-python-utils`. See [RPM setup and support boundaries](docs/RPM_SUPPORT.md). Offline preparation does not download missing prerequisites.

1. **Endpoint:** select **Add server** and enter a name, IP/hostname and SSH port.
2. **Prepare:** download the personalized Bash script, transfer it to the target and run `sudo bash mrpatchy-enroll.sh`. It creates `/opt/drpatch`, the `drpatch` account, its public SSH key, the root-owned bridge and restricted sudo permissions. The script performs no downloads, APT queries or callbacks. Click **I ran the script · Proceed to step 3**. Curl and ordinary-download delivery use the same bootstrap; curl links expire after one hour. In curl mode, select **Fetch from HTTPS endpoint**: the default `PUBLIC_URL`, **Internal HTTPS**, or **External HTTPS**. Enabled profiles use their configured hostname and browser-facing port. Choose an address reachable from the target; for a private CA, use curl’s `--cacert /path/to/ca.pem` with a trusted bundle for the site certificate.
3. **Connect and verify:** verify the printed ED25519 SHA256 host fingerprint through a trusted console, enter it, and click **Finish and verify installation**. Mr Patchy installs its collector/service over SSH and verifies file hashes, ownership, modes and service state.

**Servers → Manage → Download Bash installer** is available for enabled servers. A fresh download contains the server's current SSH identity; download again after key rotation. Re-running an old saved script can reinstall its old public key.

![Offline enrollment wizard](docs/screenshots/enrollment.jpg)

![Curl enrollment with selectable HTTPS endpoint](docs/screenshots/enrollment-curl.jpg)

## Workspace settings

Settings is a section hub with separate pages for **AI & models**, **Patch policy**, **Database**, **HTTPS & certificates**, and **History retention**. Each section saves independently without overwriting other sections. Direct links such as `#settings/ai` survive refresh and browser back/forward navigation.

## Review and install updates

Package discovery runs native APT or DNF **centrally**, using isolated target inventories, architectures, source definitions, keys and preferences. The collector reads local package databases without target repository queries for discovery. An offline target can still have repository metadata checked against its last saved inventory.

In **Packages**, select a server, review candidates and choose updates. **Select all eligible updates** selects the current filtered view, up to 500 packages per reviewed batch; held, broken and already queued packages are excluded. Clear selection is available beside it. Confirmation displays the effective reboot and snapshot-rollback policy. That policy is recorded with the job; if it changes before execution, the job fails for reapproval rather than silently adopting different behavior. Staged rollouts require the same policy review for every server.

Explicit installation refreshes target metadata and requests the recorded exact versions. Package removal and forced changes to holds are prohibited; APT retains existing configuration files with `--force-confold`; RPM follows native config-file flags and may create `.rpmnew`/`.rpmsave` files. RPM preview shows candidates; dependency resolution runs on the target before installation. Maintainer scripts may restart services. **Automatic reboot is available only under an explicitly reviewed, enabled policy.**

![Patch approval showing reboot and rollback policy](docs/screenshots/patch-review.jpg)

| Priority | Default deadline |
|---|---:|
| Critical | 24 hours |
| High | 72 hours |
| Normal | 168 hours |
| Low | 720 hours |

Deadlines start at first discovery of an outstanding update and do not reset when a newer candidate supersedes it. Once the package is current, a future update starts a new deadline. Security-origin updates default to high; others default to normal. These are scheduling heuristics, **not CVSS severity ratings**. Deadlines highlight overdue work; they do not automatically approve upgrades. Unattended installation requires an explicitly enabled patch schedule.

**Account → Operations** provides UTC maintenance windows, ordered canary rollouts and advisory matching. Windows gate job start; a long installation/recovery can extend past the window. Advisory matching is opt-in and currently maps Ubuntu/Debian source packages to OSV; derivative coverage is explicitly limited.

## Update importance, expected installation and package history

Enable **AI update importance scores** in Settings alongside AI investigations. Pending updates receive an advisory **0–100** score with an expandable explanation, limitations, model and assessment time. Assessments bind to the exact installed/candidate versions and policy evidence; a changed candidate needs a new assessment. The default separate allowance is 20 batches/hour, with up to five updates per call. Scores use package metadata and repository classification, carry **low confidence**, and do not claim verified CVE/changelog evidence or change your patch schedule/priority.

**Expected installation** shows the earliest estimated start from an approved schedule or queued job, including maintenance windows and urgent exceptions. It is separate from the policy deadline. Unscheduled updates say **Not scheduled**; holds, recovery, offline targets and unknown dependency completion explain why a date cannot be given. All times displayed in the table use your browser's timezone.

![Explained AI importance and expected installation](docs/screenshots/update-importance.jpg)

**Package history** records observed installations, version changes, removals and package-state changes, with before/after versions, observation/recording times and a job/actor link when known. It preserves RPM install-only version sets and dependency changes. Existing retained inventory snapshots are backfilled on the next inventory collection; the initial snapshot is a baseline, not proof of an installation time. Outside changes can only be dated to when Mr Patchy observes them. See [AI diagnostics, update scoring and package history](docs/AI_AND_PACKAGE_HISTORY.md) for limits and retention.

![Package change ledger](docs/screenshots/package-history.jpg)

## Scheduled and out-of-cycle patching

Open **Patch schedules** in the main menu to configure daily, weekly or monthly patching for all configured servers (including future enrollments) or a selected group. Set an IANA timezone, start time, allowed start-window length and regular priorities. The month calendar and hourly day view show upcoming windows and recorded urgent runs; times in the calendar use your browser’s timezone.

Each schedule can independently enable **high** and **critical** out-of-cycle updates after a configurable delay from first discovery. These rules respect server maintenance windows unless you explicitly authorize a bypass for that priority. Detection follows the central repository check interval. Priority labels are Mr Patchy policy labels, not automatic CVSS classifications.

Review and explicitly approve unattended installation before enabling a schedule. Jobs refresh signed repository metadata, select exact candidate versions and preserve package holds, host-key verification, recovery quarantine and per-host serialization. Unhealthy/offline targets wait within the allowed start window. Missed windows are skipped; pausing, editing or deleting cancels queued work while already running patches may finish. The selected reboot/rollback behavior must match each target’s saved recovery policy.

![Monthly patch calendar](docs/screenshots/patch-calendar.jpg)

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

![Release upgrade review and configuration diff](docs/screenshots/release-upgrade.jpg)

A tested release-capable snapshot adapter is mandatory. Generic root-only Snapper snapshots do not automatically qualify. AI review sends configuration text to your API provider and covers package-owned conffiles; custom applications, data migrations and external volumes require site-specific validation/recovery. Blockers disable GO. See [release upgrades, privacy, adapter contracts and limits](docs/RELEASE_UPGRADES.md) before enabling this workflow.

## Repository management

Use **Repositories** to inspect, add, edit or disable sources, upload signing keys and restore reviewed source backups. **Repository access** configures scoped HTTPS credentials, private CA bundles, proxies, default release and exact-URI mirror mappings. Secrets are encrypted in the database and staged in a private central APT auth file.

HTTP(S) repositories are supported directly. Local/media sources require an administrator-provisioned HTTP(S) mirror containing the same signed metadata. Arbitrary target `apt.conf` hooks and executable authentication/transport helpers are never imported. Deb822 field names must use canonical spelling without spaces or tabs before the colon; ambiguous or duplicate fields are rejected before native APT. Unsupported configurations remain visible and fail closed; “all repositories” is not an unconditional transport-compatibility claim.

**Servers → Manage → Repair broken package state** explicitly performs dependency repair and dpkg configuration. It can install dependencies and run maintainer scripts; inspect failed results before retrying.

## Monitoring, provenance and AI

Default cadences are **60 minutes** for configurable repository checks, **30 seconds** for process/socket sampling, and **five minutes** for integrity sweeps. Slow targets or large fleets can delay them; stale telemetry and overdue sweeps are reported.

The collector hashes Mr Patchy's managed files and readable running executables. Script operands, including supported interpreter options such as Python `-I`/`-u`, and executable-mapped libraries contribute to behavior identity. Inline code, modules, preloads and unrecognized option layouts retain explicit unverified entries without exporting argument values. Libraries are read through `/proc/PID/map_files` where permitted, or through a pathname only when its device/inode still matches. Deleted/inaccessible/replaced mappings remain explicit unverified evidence. Script hashes describe files, not the interpreter's live memory. Limits are 128 provenance files per process and 128 MiB per file. Descriptor-based hashing checks inode changes and uses a two-second per-file and ten-second per-sweep elapsed budget. Oversized, inaccessible or changed executables remain visible as unverified; these cooperative budgets cannot interrupt a kernel-stalled filesystem read.

Optional bpftrace exec capture retains short-lived observations. Unverifiable identities stay marked unverified through central processing. Enabling eBPF relaxes the collector sandbox for kernel tracing; kernel support and acceptance testing are required. It is not guaranteed lossless capture or hardware attestation.

Open **Settings → AI & models** and use **Save API key** first; no valid model is required to save a key. Click **Refresh available models** and choose a model, or select **Enter a model ID manually** if discovery is unavailable. **Save AI settings** only persists your choice; **Save and test selected model** saves it first and then tests that exact model. A provider error never rolls back the save. Results identify the tested model and retain the request ID when supplied. The list comes from your key’s accessible models; it does not certify Responses API/structured-output compatibility. A saved model missing from the list is marked unavailable without silently selecting a replacement. Each investigation uses at most two calls and only fixed, read-only follow-up checks. The default cap is 20 investigations/hour. No model-generated shell command runs, and no AI verdict automatically approves behavior. Process-investigation evidence can include paths, hashes, UIDs and network endpoints; arguments, environment variables, process memory and file contents are not sent by that workflow. Release configuration planning separately sends eligible configuration text, as disclosed before planning. `store: false` does not override organization-level API retention policies. API billing is separate from ChatGPT subscriptions.

Open **AI run logs** to inspect request stages, safe provider errors, model, request IDs and attempt times. The worker-status panel explains disabled/missing settings, missing heartbeat, active work, hourly limits and retry backoff. **Investigations → Retry** makes a failed/pending behavior eligible again without bypassing the hourly quota. Unhandled background failures are recorded instead of silently disappearing. See [the troubleshooting workflow](docs/AI_AND_PACKAGE_HISTORY.md#diagnose-stalled-triage).

Each action now shows **estimated API cost in USD**, including follow-up calls. Inspect it for token usage, cached input, reasoning and the saved rates per call. Failed responses can still incur charges; missing usage/pricing and historical entries show **Unavailable**, while incomplete totals show **Partial**. See [cost coverage and limitations](docs/AI_AND_PACKAGE_HISTORY.md#cost-per-ai-action).

![AI diagnostics and worker status](docs/screenshots/ai-run-logs.jpg)

The target's durable spool partitions normal observations into batches of at most 256 KiB and acknowledges them only after central commit. It retains up to 48 MB, exposes queued bytes and reasoned cumulative oversize/capacity loss counters, and reports only newly observed loss as an active integrity finding. Each poll drains up to 32 eight-record batches within a ten-second catch-up budget, fetching events without repeating the full inventory. Outstanding batches stay queued for the next poll. Inventory/observation history defaults to 30-day retention. Known-good behavior approvals are tied to exact recorded identities, including provenance and verification uncertainty.

## Reviewed file replacement

**Security coverage** provides an administrator-only fleet overview of independent ClamAV/YARA receipts, scan freshness, signature age, failed attempts and open scanner incidents. Search by server name and open the relevant server Security tab. Results describe stored, bounded coverage; they do not certify a clean host.

**Servers → server → Security → Execution-triggered scans** optionally queues bounded
ClamAV directory scans when new, fresh, verified eBPF executable identities appear in
the event spool. The policy is off by default and includes scan directories, debounce,
cooldown and hourly limits. Trigger history records coalescing, skips, failures and
capacity drops. This complements recurring scans: it does not scan every execution,
attest that the original executable bytes were examined, or detect files that are
never executed. Existing automatic AI incident-plan policy applies to resulting
detections. See [execution scan behavior and limits](docs/SECURITY_IMPLEMENTATION.md#execution-triggered-scoped-scanning).

Under **Servers → server → Security**, administrators can preserve evidence, review
quarantine, authenticate an offline vendor replacement, separately approve private
staging, and then use **Review replacement publication** with `PUBLISH` to make that
exact staged inode live without overwriting an existing destination. The original
stays quarantined. Publication creates a separate server pause; verify the result
and review service impact before using `KEEP REPLACEMENT`. Process pauses remain
independent. Existing opt-in retained-response monitoring verifies both the live
replacement and original evidence. See [scope, approvals, recovery and limits](docs/SECURITY_IMPLEMENTATION.md#separately-approved-live-replacement-publication).

**Check service health** reads explicitly selected systemd services without changing
them. Capture a baseline, compare a later check, and review **Service health history**
before deciding whether to release a response pause. Checks never restart services or
release pauses. See [service observation scope](docs/SECURITY_IMPLEMENTATION.md#response-service-health-observations).

**Configure service watch** enables recurring checks for the exact services from a
fresh healthy manual observation. Failed, unavailable and overdue checks raise alerts;
an optional **pause on problem** adds a separate service pause. Disabling monitoring
keeps that pause until **Review service pause** records a separate decision. File,
publication and process pauses remain independent. See [automatic service watches](docs/SECURITY_IMPLEMENTATION.md#automatic-service-watches).

Use **Export response record** on a reviewed file response to download its stored
investigation, custody, approvals, process actions, replacement receipts and monitoring
history as JSON. Download the checksum and retain both independently in protected
storage. File bytes, target journal files and credential configuration require their
separate backup workflows. Verify an export offline with Python 3 and no dependencies:

```bash
python3 tools/verify_response_record.py response.json --sha256 <independently-retained-sha256>
```

Hashes detect changes against a trusted digest; they do not authenticate the controller,
prove historical completeness or verify current target state. Oversized histories are
refused as a whole. See [response-record scope and limits](docs/SECURITY_IMPLEMENTATION.md#portable-response-records).

## Accounts, SSO, notifications and keys

**Users** gives administrators a dedicated place to create, disable and edit named accounts, assign roles and reset passwords. Each user chooses their own password through **Account → Change password**, entering the current password and confirming the new one. **Account** also manages authenticator MFA and session revocation. Administrators manage infrastructure and trust; operators can preview/queue patches and refresh repositories; viewers inspect monitoring.

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

Configure MySQL host, port, database, credentials and verified TLS in **Settings → Database**. Saving stages the destination without changing the running database. The displayed offline workflow stops app/workers, checks the source and empty destination, copies all application tables, verifies row counts/content fingerprints and activates the destination only after success. SQLite ↔ MySQL is supported; the source is preserved. See [database migration and recovery](docs/DATABASE_MIGRATION.md).

For a new deployment without existing data, you can still configure MySQL 8+ through `.env` and recreate **both app and workers**:

```dotenv
DATABASE_URL=mysql+pymysql://mrpatchy:URL_ENCODED_PASSWORD@db-host:3306/mrpatchy?charset=utf8mb4
```

Switching the URL does not migrate existing data. After an offline migration, the encrypted active profile overrides `DATABASE_URL` for both app and workers. Configure verified database TLS for remote deployments.

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

CI runs on Node 24-based GitHub Actions (`actions/checkout`, `setup-python` and `setup-node` v7) on runners pinned to `ubuntu-24.04`, and uses Node.js 26 LTS for browser checks. Adopting Ubuntu 26.04 is a deliberate change validated by a full CI run, not an `ubuntu-latest` rollover. A fast `static` job checks version metadata, Python byte-compilation, every tracked shell and JavaScript file, and both Compose configurations. The MySQL suite is split by test file across four jobs; reproduce one locally with `MRPATCHY_TEST_SHARD=1/4 python -m pytest -q`. Pull request runs are superseded by newer pushes to the same pull request. Every push to `main` is verified in full. It covers SQLite/MySQL, signed repository fixtures, real SSH enrollment/rotation on Ubuntu, Debian, Fedora and AlmaLinux, signed/unsigned RPM installation checks, Docker HTTPS startup, desktop/mobile browser flows and an encrypted SQLite restic restore drill. Regression coverage includes orphan quarantine, policy approval, lost SSH replies, worker restart/recovery deadlines, original-system rollback verification, pinned Debian upgrade stages, dependency markings, stale browser responses, secret filtering, missing-database refusal, exact OIDC issuers and provenance uncertainty.

Browser regressions also exercise all three roles, 320px/390px layouts, account access, persisted maintenance and SMTP settings, queued cancellation, inline dialog errors, duplicate patch clicks, and delayed responses after navigation, dialog dismissal or sign-out.

Real distribution release upgrades, Raspberry Pi/systemd hardware, live IdP/SMTP/custom-ACME services, kernel eBPF attachment, bootable filesystem rollback and off-host provider connectivity require acceptance tests in your environment. The existing MySQL CI suite does not constitute a MySQL dump/import disaster-recovery drill.

Generate documentation screenshots with `SCREENSHOT_DIR=/tmp/mrpatchy-shots npm run test:ui`. Screenshots use illustrative fixtures and documentation-only addresses, not live infrastructure.

## Documentation

- [Google Cloud VM connections and IAP setup](docs/GCP.md)

- [Server workspaces, tabs and permissions](docs/SERVER_WORKSPACES.md)
- [Fedora, RPM and DNF/Yum support](docs/RPM_SUPPORT.md)
- [Operations and troubleshooting](docs/OPERATIONS.md)
- [AI diagnostics, update scores, expected installation and package history](docs/AI_AND_PACKAGE_HISTORY.md)
- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Enterprise configuration and recovery](docs/ENTERPRISE_RECOVERY.md)
- [Database settings and offline SQLite/MySQL migration](docs/DATABASE_MIGRATION.md)
- [Distribution release upgrades](docs/RELEASE_UPGRADES.md)
- [Post-review fixes](docs/REVIEW_FIXES.md)
- [Latest code and interactive browser review](docs/FULL_REVIEW_2026-10-25.md)
- [Historical reviews](docs/COMPLETION_REVIEW.md) and [expansion checkpoint](docs/OPERATIONS_EXPANSION.md)

Central administrators and holders of target SSH keys can deploy root code. Protect the management network, accounts, database and secret volumes accordingly. A compromised target root/kernel can forge telemetry; hashes are not remote attestation.

### Google Cloud runtime and agent maintenance

Use [`install-gcp.sh`](install-gcp.sh) to build a controller runtime containing
Google Cloud CLI for both app and worker. See [GCP setup](docs/GCP.md) for attached
service-account/federation prerequisites and IAP enrollment. Each server's
**Agent health** tab exposes version/drift checks and opt-in automatic helper
maintenance; [Agent maintenance](docs/AGENT_MAINTENANCE.md) documents verification,
retry limits and cases requiring trusted-console recovery.

Scanner incidents now offer **Related evidence** to pivot across stored scanner,
process, startup/custom-file and package-integrity records on that server. Exact
hash matches, path-only matches and changed bytes are labeled separately. Searches
are bounded and paginated; matches do not establish causation or authorize response.
See [the implementation checkpoint](docs/SECURITY_IMPLEMENTATION.md#cross-source-incident-evidence-pivots).

Each server workspace includes an administrator **AI integration** pause/resume control.
Pausing blocks new provider calls for that server, including queued security proposals,
triage follow-ups and shared update scoring. Other servers and non-AI operations
continue; historical results remain visible. In-flight requests must finish before a
state change can save (409 means retry; state unchanged). Resume respects global AI
settings and quotas. Reasons and state changes are audited.

**Server → Security → Export scanner record** downloads bounded scanner receipts,
incidents, reviews and advisory plans without requiring quarantine. It also works in
retained server history. The record excludes raw scanner output, file payloads,
startup/package inspections and file-response custody. Protect the sensitive JSON and
retain its checksum independently; verify it offline with
`python tools/verify_response_record.py FILE.json --sha256 TRUSTED_DIGEST`.
Exports refuse oversized histories (1,000 rows/section, 16 MiB); this does not enable
automatic retention, deletion or external immutable storage. See the
[scanner-record scope](docs/SECURITY_IMPLEMENTATION.md#portable-per-server-scanner-records).


Manual scanner AI response plans offer an opt-in **Include related execution and
integrity evidence** review. This shares bounded historical identity matches and
coverage gaps, retains an inspectable evidence snapshot and rejects changed evidence
at generation/approval. Automatic plans remain scanner-only; no AI plan executes a
response. See the [implementation checkpoint](docs/SECURITY_IMPLEMENTATION.md).

Use **File integrity → Browse startup files** to search bounded stored startup metadata, review baseline-change labels and inspect mechanism/collection gaps. Origin and job-level discovery remain unassessed.

After **Finish and verify installation**, Mr Patchy follows the deployment job and opens that server’s Overview only after backend verification succeeds. This tab retains the success notice and restores pending progress after reload. Failures stay on the verification step with Activity and explicit retry controls. An unconfirmed submission is checked against server job history rather than replayed; ambiguous results require Activity review. Closing the dialog does not cancel work. **Stop tracking** clears only this tab’s progress, not the server or job. Progress is scoped to the signed-in account in browser session storage; a different browser/tab can use Manage → Finish / verify installation and existing active deployment jobs.

Server workspaces use primary **Overview / Packages / Security / Settings** tabs (subject to role and server state), plus **More sections** grouped into updates/history, investigations/evidence and administration. Existing deep links still work. Package search and Updates only filters are remembered per server and separately for the fleet view while signed in, including when refreshing or returning with Back/Forward. Signing out or reloading clears these in-memory filters; patch selections are never restored. See [UI design and migration inventory](docs/UI_DESIGN.md#screen-migration-inventory).

The Servers directory has local name/address/architecture search, enabled/disabled filters and 24-server pages. Filters/page position survive navigation and refresh while signed in, then clear on reload/sign-out. Each server’s Overview has **Summary**, **System & collector**, and **Patching status** pages with deep links (`#servers/ID/overview/system`, `#servers/ID/overview/patching`); switching servers keeps the selected Overview page. Server controls and backend verification/approval rules are unchanged.


### Worker registrations and cooperative drain (v0.9.0)

Administrators can open **Activity → Workers** (`#activity/workers`) for registered
scheduler runtime self-reports: identity/boot ID, source version, configured runtime
type, heartbeat, uptime, coordinator flag and actual executor capacity/active work
at the report time. Periodic reports are written every 15 seconds, with immediate control/state transitions, and become stale
after 120 seconds. Future heartbeats beyond a five-second tolerance are unknown;
version mismatch is shown separately. Readiness remains **not assessed**: these
reports do not verify containers, secrets/shared storage, targets or completed jobs.
Older workers do not register; an empty list does not mean no worker is running.

The existing complete Compose deployment sets `MRPATCHY_RUNTIME_ROLE=worker`, so
its worker entrypoint prepares `/data` and skips `/tls` and `app.tls`; app/Caddy
bootstrap is unchanged. It also reports `MRPATCHY_DEPLOYMENT_TYPE=docker`. Other
worker processes report `process` unless explicitly configured. Metadata reads the
single `APP_VERSION` authority without importing the web application.

Optionally set `MRPATCHY_WORKER_ID=patchy-worker-01` for one worker instance. Every
simultaneous instance needs a unique, case-sensitive ID. A named cross-process lock rejects a
collision; detected loss or uncertainty exits before the next scheduling work.
Without an ID, each boot generates a new registration. Explicit stable IDs reuse
the current registration across restarts and get a new boot ID; registration/stop
events remain in audit. Generated/stale registrations are retained with no automatic
cleanup yet. Leave the ID unset for Compose replicas unless each instance can be
configured uniquely. Graceful shutdown records stopped after pools finish; abrupt
loss is inferred only from stale heartbeat, never successful remediation.

Rebuild/restart the controller and workers to enable reporting. No schema migration
or target-helper update is needed: records use the existing settings/audit tables,
which are already included in offline database migration. Existing job claims,
per-host/recovery locks, coordinator election and operational approval boundaries
are preserved. Defaults remain 2 jobs/8 polls/1 AI task. Supported separate-host workers,
shared secrets/artifacts/state preflight, expected-node
inventory, controller/endpoint/GCP health and full deployment acceptance remain
planned; this view does not complete remote-worker deployment or the unified dashboard.


Administrators can **Drain worker** or **Resume admission** beside its identity in
Activity → Workers. Review the exact boot and enter a reason. Requests persist in
the database and audit trail, target that boot only, and reject stale revisions,
stale/stopped workers and source-version mismatches. A restart creates a new boot
that does **not** inherit the old drain request, even with a stable worker ID.

The UI separates the requested revision from the worker's observed revision.
The worker checks control state before each admission tick (normally every second),
then releases coordinator leadership and stops scheduling/claiming new jobs, polls,
AI tasks, notifications and cleanup work. A tick already in progress can finish.
Assigned work, including queued executor polls and a whole assigned AI cycle,
continues under its existing locks/policies. **Draining** means assigned work is
finishing; **drained** means this boot reports no assigned work and admission is
paused. Neither means the process exited or that maintenance/recovery is safe.
Refresh to verify the current boot, observed revision and fresh state. If all workers
are drained, background collection/schedules/scanning/AI/notifications wait; the
controller can still accept operations into the database queue. Resume respects
all existing global AI, server AI pause, lifecycle and response controls.

Unreadable/invalid control state blocks the current admission tick. Heartbeats
then expire if reporting cannot resume; no operation is marked successful as a
result. Requests, worker acknowledgement, drained transitions and stops are audited.
Use existing operation/recovery views for failures; drain never clears a hold or
replays an interrupted mutation. Abrupt process loss retains existing recovery
semantics. This is a local/shared-state foundation, not remote maintenance acceptance.

Set startup-only `MRPATCHY_JOB_CONCURRENCY` (1–8, default 2),
`MRPATCHY_POLL_CONCURRENCY` (1–32, default 8) and `MRPATCHY_AI_CONCURRENCY`
(1–8, default 4; set 1 for serial operation) in `.env`, then recreate the worker.
Direct worker/embedded processes use the same variables. Invalid values refuse
startup. These limits size the real executors. Poll/notification work shares the
poll pool; process investigations and update scoring share AI slots.

Independent servers can now undergo process triage concurrently. A durable,
renewable claim permits one process investigation per server across supported
workers, with atomic existing hourly admission and ownership/evidence checks
before calls and acceptance. The coordinator schedules update scoring, alternating
purposes even with one AI slot. Claims expire after 120 seconds without renewal;
interrupted attempts retain the existing recovery delay and finite retry limits.
A lease cannot cancel an already sent request or guarantee exactly-once billing.
The full model, evidence and conditional SSH/follow-up flow remain unchanged.
Same-server parallel investigations, broader fairness and native complete-context
collection remain unfinished.
v1.30.0 adds exact-context contradiction invalidation and linked review for the
complete exact candidates described below.

The Investigations/AI activity views report active claims, queued work and fresh
reported AI capacity. Workers report actual active task counts and configured
capacity, including draining capacity; these reports are not a readiness guarantee.
Higher concurrency increases database/target/provider load and can consume shared
admission or daily spending capacity sooner. No provider invoice guarantee is implied.
Set AI concurrency to 1 to preserve serial resource use.

### Shared smooth-rate admission (v1.31.0)

Every existing billable Responses API call now crosses one durable fleet-wide
admission boundary. **Shared smooth rate throttle** spaces independent logical AI
work starts evenly and never accumulates a burst. Required second-stage calls stay
inside their admitted work item while rechecking pause/lifecycle policy. The next
eligible time is retained across controller/worker
restarts and shown in AI worker status. Competing SQLite/MySQL workers serialize the
reservation before any provider request or usage receipt is created. A refused start
does not call the provider or consume a triage retry attempt.

Existing installations initially retain their separate investigation, scoring and
incident-plan hourly allowances. Settings shows the conservative suggested shared
rate (the lower existing automatic allowance); an administrator must review and save
the migration, which is audited. Fresh installations use shared rate mode. The legacy
incident/startup-plan queue allowance is disabled only after that explicit migration.

**Unthrottled by Mr Patchy** removes this application pacing only. Finite AI worker
concurrency, provider limits, global/per-server pause, lifecycle checks, roles and
data-sharing controls still apply. Invalid local model/key configuration is rejected
before a reservation.

### Daily spend admission (v1.32.0)

Settings offers **Daily spend cap** and **Rate throttle + daily spend cap** alongside
rate-only and unthrottled modes. Capped modes atomically reserve a conservative USD
ceiling before every current provider call, using bounded request bytes, maximum
output tokens, requested tier and a versioned exact-model public price catalog.
Unknown models, tiers, tool fees, output bounds or long-context pricing fail closed;
they are never admitted as free. Rate-plus-cap work reserves budget before consuming
a smooth-rate start.

Valid provider usage reconciles the ceiling to a retained estimate. Transmitted calls
without reliable pricing or usage—including timeouts and interrupted workers—keep the
full ceiling counted. Unsent failures release their reservation. The separate ledger
is not deleted with diagnostic AI history and exposes settled, reserved, uncertain,
remaining and next-reset values in Settings and AI worker status. The administrator
sets the USD/day amount and explicit IANA reset timezone; mode, cap and timezone
changes are audited. Estimates use published token prices and may differ from the
provider invoice.

Exact durable defer/resume for every manual/plan path, pricing-catalog lifecycle
alerts, invoice reconciliation, long-horizon spend reports and full SQLite/MySQL
failover/reset acceptance remain required before the shared controls program is
complete.

### Shared provider backoff (v1.33.0)

Every current billable provider path checks one durable fleet-wide transient-failure
floor before budget and rate admission. A valid provider `Retry-After` is retained
exactly; transient 408/429/5xx responses, connection failures and timeouts without a
valid floor use bounded exponential backoff with full jitter from 30 seconds up to 30
minutes. The sanitized state is shared across controllers and workers, survives
restart and is cleared by the next completed/non-transient provider response that
started after the latest recorded failure. An older parallel success cannot erase a
newer floor.

No automatic HTTP replay occurs: each transmitted attempt still has one receipt and,
in capped mode, one reservation. Calls blocked by the shared floor create neither a
receipt nor a rate/budget reservation. Process investigations remain durably queued
at the shared eligibility time without consuming another attempt, and manual retry
cannot bypass it. Settings and AI worker status show consecutive transient failures
and the next eligible time.

Already concurrent in-flight calls cannot be recalled after another call discovers a
provider floor. Exact durable queue/resume for every manual plan and connection-test
request and full multi-controller failover acceptance remain unfinished.

### Durable update-scoring deferral (v1.34.0)

An update-scoring batch refused by the shared rate, spend or provider-backoff boundary
now remains durably deferred at its exact next eligibility rather than becoming a
generic error subject to an unrelated one-hour retry delay. The Packages assessment
and AI worker status explain that retained state and show its next eligible time. No
provider request, rate start or budget reservation is created by a pre-send refusal;
a transmitted transient failure keeps the existing receipt and spend outcome while
retaining the shared provider floor for later scoring work.

Before a resumed result is accepted, scoring rechecks current package evidence and
server policy. Changed evidence supersedes the old deferred identity, removed updates
drop out of the queue count, and pause/lifecycle/global controls continue to apply.
At v1.34.0, manual incident/release/startup plans and connection tests still rejected
safely rather than becoming durable resumable jobs. The next milestone narrows that
remaining gap for the two single-call advisory plan paths.

### Durable advisory-plan deferral (v1.35.0, corrected v1.35.3)

Incident-response and startup-change AI plan jobs now remain queued when a shared
rate, daily-spend or provider-backoff boundary refuses their single provider call.
Timed waits retain the exact shared eligibility; administrator-controlled global or
per-server pause waits retain the job without inventing a retry time. Activity and AI
worker status show the retained plan and its next start or resume requirement.

The v1.35.3 API projects only a sanitized `ai_deferred` Boolean, never the internal
job payload, so both Activity list and detail views can render that state through the
production contract. A plan eligible now takes status precedence over another plan's
future wait, with separate eligible/deferred counts. Untimed administrator pauses also
reclassify any already-started diagnostic run as deferred instead of a false error.

Every resume revalidates the current host lifecycle, AI pause and incident evidence,
then follows the normal admission, budget and provider boundaries. A pre-send refusal
creates no call receipt or charge. A transmitted transient failure is not replayed
inside the HTTP request: its existing receipt and spend outcome remain, and the job
becomes eligible for a later scheduler attempt at the shared provider floor.

Release planning remains excluded because one release plan can make multiple paid
calls without per-stage persistence; replaying the whole job could duplicate a
successful earlier stage. Connection tests are interactive rather than durable jobs.
Those paths, plus complete multi-controller failover acceptance, remain unfinished.

### Interrupted advisory-plan recovery (v1.35.4)

After a controller or worker restart, the elected scheduler now checks each running
incident/startup advisory job under that server's distributed worker lock. A job whose
lock is still owned remains untouched. An orphan becomes recovery-required and its
matching diagnostic run becomes interrupted; Mr Patchy never automatically replays
the possibly billable provider request.

Activity explains the retained review. An administrator must inspect the AI run,
per-call usage receipt and durable spend reservation before releasing the server
queue. Call and budget rows are not rewritten by restart recovery, and advisory-only
reconciliation does not contact or mutate the managed server.

For v1.22.0, drain/stop all old workers first, rebuild/start the controller to
create `ai_triage_claims`, then start matching workers. Mixed old/new active workers
are unsupported: older orphan reconciliation does not recognize live claims.
The startup model registry also includes claims in verified offline database
migration and schema preflight. No target-agent upgrade is needed for concurrency.
Remote shared state, broader health and cross-host maintenance acceptance remain
planned. No Git tags or Docker-image publication are implied.


Worker control requests carry the exact case-sensitive identity in the validated
JSON body of `POST /api/operations/workers/control`, alongside boot, revision,
action and reason. This preserves valid identities such as `.` and `..` without
URL path normalization. There is no released path-based worker-control API.

New related-evidence scanner plans use evidence scope v2, retaining the exact
captured time boundary as controller-generated hexadecimal text. MySQL JSON may
round the numeric timestamp in the displayed snapshot; approval reconstructs the
original exact boundary and still requires the full evidence digest to match.
Changed/deleted evidence, foreign references, malformed boundaries and tampered
exact boundaries remain rejected. Scanner-only and legacy v1 history stays readable;
v1 plans whose numeric boundary already lost precision may require regeneration.
Old evidence/digests are never rewritten to make approval succeed.


### AI run pages (v0.10.0)

AI activity opens saved runs in deep-linked Summary, Cost and Timeline pages, in
both fleet and server workspaces. Server detail requests verify direct, shared or
legacy scoring membership; unrelated runs return 404 in that context. List purpose
and pagination are remembered separately for fleet and each server during navigation
and refresh, clearing on reload/sign-out. Back/Forward and direct detail reloads
work without sending AI requests. Cost estimates/partial/unavailable states retain
their saved usage/rate limitations; shared batch cost covers the whole run.
Historical AI views remain available under existing administrator and lifecycle
controls. No retry, approval or target action occurs when browsing.


### Stored startup review pages (v0.11.0)

Server More sections → Startup files opens dedicated Files and Coverage pages
(`#servers/ID/startup/files` or `/coverage`). Browse startup files from File
integrity opens the same workspace. Search/page position and receipt revision are
remembered per server during navigation/refresh, clearing on reload/sign-out.
Back/Forward and direct links work; switching servers retains the selected review
page with separate search context. A changed receipt/baseline requires **Refresh
latest inventory**, which resets paging and the revision guard for review.

Administrators can read retained startup receipts for disabled/deleted servers.
The view performs no scan, baseline approval, AI request or remediation. It lists
only bounded metadata already stored by existing inspections, with explicit scope,
missing roots, skipped entries, gaps and unassessed origin. Comprehensive job/unit
discovery, effective configuration, vendor-default provenance and AI classification
remain unfinished. Rebuild controller and keep workers on the matching source
version; no agent/schema update is required for these review pages.


### Expected worker inventory

On the controller, optionally set `MRPATCHY_EXPECTED_WORKER_IDS=worker-east,worker-west`
to list up to 100 unique case-sensitive worker identities in Activity → Workers.
Set each worker's `MRPATCHY_WORKER_ID` to the corresponding stable identity. Each
replica needs a unique ID; do not assign one shared ID to scaled replicas. Restart
the controller after changing its environment. Keep this deployment configuration
in your normal protected installation/backup configuration. Removing an expectation
does not remove registration history, drain a worker or stop a process.

The expected inventory is independent of registration pagination. Missing means no
matching registration, not a verified stopped process. Stale clocks, stopped reports,
version mismatches and drain states remain explicit. Invalid configuration shows an
error instead of silently treating the deployment as complete. Empty configuration
means expectations are not configured; it does not mean all workers are present.
This remains worker-only self-report inventory, with readiness not assessed.
Controller, endpoint-agent and GCP-node coverage, alerts and remote deployment
acceptance remain planned. Rebuild the controller and keep worker versions matched.


### Worker controller/key startup gate (v0.13.0)

Complete Compose enables `MRPATCHY_REQUIRE_CONTROLLER_STATE=1` for workers. Before
initializing tables or admitting jobs, workers must read the controller's versioned
database receipt and decrypt its canary with the existing private `/data/secret.key`.
The controller publishes this receipt during startup and refuses to overwrite a
receipt it cannot decrypt. Start/rebuild the controller before upgrading workers.
The key must be a regular, non-symlinked 44-byte Fernet key, mode 0600 (or stricter),
owned by the runtime user. Restore the correct protected key; never delete a receipt
or generate a replacement key to make a mismatch pass. Preserve normal backups.

Non-Compose processes retain legacy behavior unless the gate is explicitly enabled
with that variable. Workers displays verified-at-startup, not enabled or not reported;
none means general readiness. Failures terminate startup with a safe diagnostic.
This checks a receipt/key/version at startup only, not ongoing state freshness, schema
compatibility, SSH keys, artifact/evidence mounts, correct selection among cloned
databases using the same key, or target access. It is not a supported remote-worker
provisioning solution. Full shared-state preflight and remote deployment acceptance
remain planned. This source update requires no endpoint-agent or schema migration.


### Required schema structure and receipt protocol (v0.14.0)

Strict worker admission also requires receipt protocol 1 and a matching source
requirements digest, then checks every mapped table, required column and primary
key using read-only database inspection before worker init. Extra tables/columns
are allowed for additive compatibility. Missing tables/columns, views replacing
tables, wrong primary keys or inspection permission failures refuse admission;
workers do not create or repair them to pass. Workers shows this startup result
separately from the key check and general readiness.

Start the upgraded controller first. It upgrades valid legacy v0.13 receipts with
protocol/requirements metadata while retaining the encrypted canary; unknown or
partially malformed protocol metadata refuses publication. Restore missing state
or run the normal controller upgrade rather than dropping validation records.
This is not full schema compatibility: column types/lengths, nullability, defaults,
indexes, foreign/check constraints, data validity, ongoing drift and cross-host
migration fencing remain unassessed. Shared-state provisioning and real remote
deployment acceptance remain planned; no endpoint-agent/schema migration is added.


### Fleet Overview pages (v0.15.0)

Overview has deep-linked Summary (`#overview`), Server attention
(`#overview/attention`) and Monitoring (`#overview/monitoring`) pages. Server
attention searches stored names/addresses and groups expired, unknown, disabled or
recent contact in twelve-card pages. Filter/page context survives navigation and
refresh, clearing on reload/sign-out. A shrinking snapshot clamps the page.

Recent contact means a timestamp within two minutes, reported online state and no
stored integrity findings or target error. Missing/future timestamps remain
unknown; disabled management is shown separately. This UI interpretation does not
change the legacy dashboard API's online metric. Counts and server snapshots are
read separately and may differ during concurrent changes. No view performs a
target probe, provider call, patch or trust decision. Review operation outcomes
and individual collector timestamps before acting. These pages do not complete
the planned deployment-health dashboard, expanded protection or full UI rework.
Rebuild the controller and keep workers matched; no agent/schema upgrade is needed.


### Historical snapshot pages (v0.16.0)

Server History has Package changes, Inventory revisions and Process observations
pages. Administrators can open retained inventory/process records by deep link
(`history/inventory/{record}` or `history/observations/{record}`), return to their
scoped list page and reload a detail directly. Switching servers preserves the
history type and drops the previous server's record ID. Pagination is held in
account-session memory and clears on reload/sign-out. Existing inspection-dialog
links now navigate to these pages. Missing/deleted snapshots offer list/retry links.
These are retained observations, not current state or malware verdicts; offset
pages can shift during collection/retention. No target/provider calls are added.


### Activity review pages (v0.17.0)

Activity separates Operations, administrator Audit trail and Workers. Operations
and audit lists use fifty-record pages and remember position per fleet/server or
audit context until reload/sign-out. Audit entries (`#activity/audit/{id}`) and
operations (`#activity/jobs/{id}`) have read-only detail links and error recovery.
Server operation links use `#servers/{host}/patching/jobs/{id}` and send an expected
host ID; mismatched records return 404. Cancellation/recovery remain on lists under
existing administrator confirmations; viewing details does not replay work.
Audit API reads accept offset/limit (default/max 200), with timestamp/ID ordering
and administrator-only `/api/audit/entries/{id}` reads. Existing unscoped job reads
and payload exclusion remain. Offset pages can shift during collection/retention.


### AI transport and performance baseline (v1.18.0)

Billable Responses API calls reuse a bounded, process-local HTTP pool. Each call
still passes existing server/global policy gates and has its own attempted-call
receipt; credentials are request-local, cookies are discarded and redirects and
automatic retries are disabled. Pool/connect waits are bounded to 5/10 seconds;
existing read/write budgets remain. Worker drain closes idle connections and
shutdown waits for in-flight sends before closing the pool.

Administrator AI activity → Run → Timeline includes monotonic stage timings for
provider admission/request, receipts and usage. Serial process triage also records
queue age, admission, requested SSH evidence and evidence/result persistence.
Timings overlap and must not be summed. Queue age includes pause/backoff and time
before eligibility. Small diagnostic batches flush at run completion (or 32 events);
crashes/database failures can leave gaps. Run timing excludes creation/admission
and the final timing flush. Existing run-history retention applies to these metrics.

`python tools/benchmark_ai.py --runs 20` runs the serial pipeline against disposable
loopback provider/SSH fixtures and SQLite; it never uses deployment state or a paid
provider. See [baseline results](docs/benchmarks/ai-transport-v1180.json) and the
[implementation checkpoint](docs/SECURITY_IMPLEMENTATION.md). Fixture connection
reuse is validated; this is not a production speed or parallel-throughput promise.
Threaded claims/leases and classified retries are implemented. Strict exact fleet
reuse is available only for fully complete candidates; administrators can invalidate
an entry fleet-wide and a retained final non-low provider result for the identical
model, policy and verified context invalidates it automatically. Linked history is
flagged for review. Native completeness remains planned. Shared rate, daily-cap,
combined and unthrottled modes are available; complete durable deferral, pricing
lifecycle and end-to-end failover acceptance remain unfinished. Existing model,
evidence, follow-ups, approval and AI pause behavior remain in force.


### Pooled SQLite initialization (v1.18.1)

Startup reflection and existing schema upgrades now use one connection, refreshing
SQLite catalog state first. This prevents stale pooled connections from repeating
an already-completed column addition. Single-controller/migration-owner startup
remains required; this does not enable concurrent or cross-host migrations.


### Process-investigation retry scheduling (v1.19.0)

Transient timeouts, network failures, explicit rate-limit responses and common
server errors now queue a durable retry with exponential jitter and provider
`Retry-After` eligibility. The worker does not sleep in a slot. Automatic attempts
are bounded to five per subject/configuration. Billing, authentication, request
configuration and unclassified failures require correction or an explicit Retry.
Saving a changed model/key permits another attempt; enable toggles do not reset
limits. Provider delay floors also apply to manual Retry. Pending work, retained
usage receipts and uncertain charges survive; no assessment or approval is inferred
from a failure. AI pause/resume and lifecycle checks still apply to every call.

Investigations and AI logs show eligible, review-blocked and paused counts; each
pending/error item explains its retry state and eligibility. Eligibility is not a
promised start time: existing hourly limits and the serial worker still apply.
Legacy attempts and lost-worker attempts retain their one-hour recovery interval.
This is process-triage scheduling only, not shared provider-wide rate admission,
daily spend controls or faster-triage program completion. Other AI purposes retain
their existing retry/allowance behavior. Rebuild controller first to create the new
retry table, then restart matched workers; no endpoint-agent upgrade is needed.


### Retained assessments and Re-triage (v1.20.0)

Investigations now have administrator **Assessment history** list/detail pages,
including server-scoped deep links, pagination, Back and reload. New completed
process assessments retain their evidence snapshot, actual supplied inputs for
each stage, requested model, policy digest and original run ID independently of
normal AI diagnostic pruning. Existing results are not retrospectively assigned
a model or original timestamp: when preserved for refresh they are labelled
legacy with unverified original input/model provenance. Retained AI results are
advisory and never confer administrator approval or a clean-host guarantee.

Administrators can **Re-triage** a completed observation with a reason. A revision
check rejects stale results or approval changes. Approved behavior requires an
explicit confirmation withdrawing that approval; fresh AI output does not restore
it. The previous result is retained, and the refresh request survives a failed
attempt. Existing Retry handles failed/pending work. Re-triage does not send AI
requests from the web handler or bypass pause, saved model, data-sharing, lifecycle,
provider delay or hourly controls. If a later manual approval holds queued work,
revoke that approval to resume it. Inactive/deleted servers offer read-only history.

Only a fully complete canonical match can use the fleet registry. Current native
receipts still declare evidence gaps and therefore contact the provider under existing
policy. Complete synthetic acceptance covers publication, zero-call lookup, explicit
Re-triage bypass, administrator invalidation and final exact-context contradiction
invalidation; native complete evidence and shared rate/spend modes remain planned.
New assessment, refresh and registry tables require controller-first startup, then
matched workers.
No target-helper upgrade is required. Retained evidence is sensitive; history has no
automatic deletion or immutable external storage yet.

### Canonical known-good readiness (v1.24.0)

Assessment detail now evaluates a versioned, host-independent exact-match contract.
It produces a candidate fingerprint only for a completed low-risk AI result with the
recorded model/policy and explicit verified manifests for artifact bytes, authenticated
provenance, configuration, effective behavior, required follow-up evidence and coverage.
Host/PID/start/time and ephemeral-source-port observations remain in local evidence but
are excluded from the key. If an observation-only field appears inside canonical
evidence, or any required identity/manifest is missing or incomplete, evaluation fails
closed and explains the cache miss.

Existing receipts do not yet produce the complete manifest and therefore remain
host-specific. The detail page never publishes or looks up a cache entry, grants an
approval, suppresses deterministic protection, or avoids a provider call. Durable
publication, concurrent cross-server lookup/hits, revocation/contradiction review and
zero-call SQLite/MySQL acceptance remain the next known-good milestones. This update
adds no database schema or target-helper change.

### Authenticated artifact provenance (v1.25.0)

Completed offline vendor inspections now retain the controller-authenticated package
manifest alongside its signature proof and exact target verification. When a later
AI follow-up is bound to the exact recorded process, Mr Patchy can reuse a same-server
inspection only if that executable path and SHA-256 match a fully verified signed
package regular file. This removes only the authenticated-package coverage gap and
records versioned artifact/provenance components for the future exact-match key.

The package proof is revalidated before storage and again before binding. A changed
artifact hash, incomplete target verification, malformed receipt or target-local
package ownership is a hard miss. Authentication time, inspection ID and server/process
identity remain local observations and are excluded from both the canonical components
and AI provider input. Configuration, effective behavior, required follow-up and
complete coverage are still explicit misses, so this milestone creates no fingerprint,
cache publication/hit, approval, detector suppression or provider-call bypass. It adds
no database schema or target-helper change.

### Exact follow-up evidence manifests (v1.26.0)

An authenticated vendor match now also completes the canonical follow-up receipt
component when the target returns the full supported v2 context. Mr Patchy binds the
sorted requested checks, credentials/capabilities, executable and mapped/script file
hashes and metadata, maps/cgroup digests, optional check results, declared gaps and
the exact collection policy into versioned requirements and evidence digests.

Only process-instance and namespace-inode identifiers are excluded from these digests;
they remain retained observations. Identical verified receipts therefore stay stable
across servers even when PID, boot, proc and namespace instances differ, while any
credential, artifact, context hash, optional result, check set or coverage change is
a miss. Partial, malformed, oversized or internally inconsistent receipts keep every
gap and produce no binding.

This milestone does not claim that application configuration or effective behavior
has been fully collected. Those components and complete coverage remain ineligible,
so there is still no cache publication/lookup, provider-call bypass, implicit approval
or deterministic-protection suppression. It adds no schema or target-helper change.

### Durable safe-candidate publication (v1.27.0)

Completed low-risk AI assessments that satisfy the entire canonical exact-match
contract now publish a durable safe candidate. One atomic fingerprint-keyed entry
retains its model, assessment-policy binding, canonical components and original
assessment provenance; separate assessment-keyed rows retain each server's isolated
observation. Concurrent identical publications deduplicate without discarding either
observation, and a previously inactive entry is never silently reactivated.

Current runtime evidence still declares configuration, effective-behavior and coverage
gaps, so it remains ineligible and publishes nothing. Publication is storage only:
there is no lookup, provider-call bypass, approval, response authorization or detector
suppression. The new candidate/observation tables require current controller startup
before an offline database migration or matched workers use this schema.

### Exact safe-result reuse (v1.28.0)

Before a process investigation sends evidence to the provider, the worker now checks
the active durable registry for the exact complete canonical context, requested model
and one- or two-stage policy digest. A hit is revalidated against the original retained
AI assessment and its isolated observation. It then retains a new per-server
**Exact-match reuse** assessment and observation with the original explanation and
provenance, while the run records zero API calls.

Administrator **Re-triage** explicitly bypasses this lookup and follows the normal
provider path. Changed, incomplete, revoked, orphaned or mismatched context remains a
miss. Reuse grants no approval, authorizes no response and suppresses no deterministic
scanner or later threat evidence. Current runtime collection still declares
configuration, effective-behavior and coverage gaps, so ordinary production evidence
does not yet publish or hit this cache; complete synthetic acceptance proves the
boundary without weakening those gaps.

Lookup currently runs after the existing process-triage claim, AI enablement/pause,
key/model and configured shared/legacy admission gates. Complete native evidence
collection, administrator-origin classifications, broader budget concurrency and
SQLite/MySQL runtime acceptance remain planned. No target-helper or endpoint-agent
update is introduced after v1.27.0.

### Fleet candidate invalidation (v1.29.0)

From any published or reused Assessment detail, an administrator can revoke the exact
candidate across the fleet with a reviewed reason and explicit confirmation. The
mutation uses the shared AI-state lock, checks the fingerprint version, records the
actor/time/reason and linked count, and immediately prevents later reuse. CSRF and
administrator-role enforcement remain server-side.

Source and reused assessments are never rewritten. Every linked detail instead shows
**review required**, the escaped revocation reason and retained original provenance;
Re-triage remains the explicit way to request fresh provider work. Revocation does not
approve remediation, suppress scanners or infer that a host is clean.

### Automatic contradiction invalidation (v1.30.0)

After an explicit Re-triage or other fresh provider investigation, a retained final
medium/high/unknown result automatically invalidates an active candidate only when
its verified canonical context, model and policy digest match exactly. Partial results
that still request evidence, provider failures and changed or incomplete context do
nothing. The invalidation is retained and audited with the contradictory assessment
identity; every already-linked source/reuse assessment shows review-required state and
a deep link to the new advisory result.

The contradictory result does not rewrite the earlier assessments, grant or withdraw
a host approval, authorize containment, suppress deterministic protection or create
an arbitrary response action. Current native evidence remains ineligible, so this is
a strict complete-contract boundary validated with synthetic acceptance. No schema,
target-helper or endpoint-agent update is introduced.


### Identity-bound follow-up context (v1.21.0)

After a reviewed helper/collector upgrade, existing AI follow-up checks also retain
a bounded context sample: boot/PID/start identity, credentials/capabilities, namespaces,
executable bytes/metadata and script/mapped-file hashes/metadata. The helper pins one
proc directory, compares facts around collection, and rechecks artifacts after optional
package/service queries. Changed, exited, inaccessible or over-budget candidates do not
produce a verified mixed result. Raw arguments, environment, maps and cgroup text are
not added to AI evidence; existing allowlisted package/service outputs remain.

Starting in v1.23.0, new periodic and execution observations retain the process's
boot ID, PID namespace, PID/start ticks and pinned proc-directory identity. Follow-up
collection opens that exact PID and requires every field to match before and after
optional evidence commands. It never substitutes another process merely because its
path, bytes and account match. Pending observations can adopt a newer verified process
identity without changing their existing behavior-deduplication key; completed history
keeps the identity it actually assessed. Older observations without this identity keep
the conservative **one current matching executable** scope and an explicit gap. The
local selector is retained in the assessment snapshot but removed from provider input.

Matching before/after samples are not an atomic snapshot or memory attestation. Even
an exact recorded-process match remains ineligible for fleet cache reuse: authenticated
package provenance, relevant configuration, startup/behavior and other required context
remain unfinished. Existing model, evidence limits, optional second-stage checks and
response authorization remain. Oversized combined evidence is refused under the existing
limit, never silently cut.

Rebuild controller/workers and use the existing reviewed Agent upgrade workflow on
each target to install both new helper and collector. Older helpers and observations
remain readable but cannot bind follow-up to the recorded process. No new schema,
automatic target upgrade, Docker-image publication or cache-hit claim is made.
Assessment history retains the context actually supplied to each AI stage.
