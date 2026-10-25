# Mr Patchy

**A little care. A healthier Linux fleet.**

Mr Patchy is a self-hosted, Dockerized dashboard for Ubuntu and Raspberry Pi OS / Raspbian servers. It collects inventory over pinned-key SSH, resolves available APT versions centrally, tracks patch deadlines, and investigates unfamiliar process behavior through the OpenAI API.

![Mr Patchy overview](docs/screenshots/overview.webp)

See the [v0.2 completion and security review](docs/COMPLETION_REVIEW.md) for current requirement coverage, test evidence, remaining limits, and suggested expansions. The [original review](docs/REVIEW.md) is retained as historical evidence.

## What is implemented

- Responsive dashboard: fleet overview, enrollment, searchable installed packages, updates, repositories, investigations, operation results, and audit trail.
- A dedicated SSH key per target, verified host-key fingerprints, a forced SSH command, and a fixed sudo entry point.
- Downloadable **offline enrollment script** containing the public key and bootstrap bridge. The same script is available through an expiring curl link served by the running application.
- Central deployment/repair of a root-owned Python collector, bootstrap bridge, and systemd service, with `/opt/drpatch` as the target account home and spool directory.
- Persistent SQLite inventory by default; MySQL through SQLAlchemy. Inventory includes held, multi-architecture, unpacked, half-configured, and other broken package states, with retained revisions. Package changes/removals are audited after initial discovery.
- Native APT runs **inside the central container** with isolated per-host status, source files, keys, preferences, architecture, and machine ID. The collector never runs `apt update`, `apt list`, or `apt-cache` for discovery.
- APT signature and index-hash verification. Failed repository refreshes stay visible and do not advance the last-success timestamp.
- Inspect/edit/add/disable repository definitions in `.list` and Deb822 `.sources` format; upload scoped signing keys; back up source files before changes and review/restore backups from the UI. Central access supports scoped HTTPS credentials, private CA bundles, proxies, default-release policy, and exact-URI mirror mappings for local/media sources.
- Operator-selected exact-version upgrades, with package-removal protection and respect for holds. Target APT runs only during an explicitly requested installation or dependency-repair operation.
- Configurable repository refresh interval (**60 minutes** default), priority deadlines, and per-package priority overrides.
- Target process and TCP/UDP connection sampling every **30 seconds**. SHA-256 sweeps of Mr Patchy's installed artifacts and running executables every **five minutes**, with ownership/mode checks for managed artifacts.
- Central two-stage AI investigations with allowlisted read-only follow-up evidence, queue visibility, structured results, encrypted API-key storage, a configurable rate limit, retry backoff, and explicit known-good approval/revocation.
- Durable target observation spool with acknowledgement only after database commit; replay deduplication, explicit overflow reporting, and configurable central history retention.
- HTTPS via Caddy: upload a certificate/private key, use public or custom ACME, and upload a private ACME root CA.

## Start the application

Requires Docker Engine with Compose v2 on a Linux host that can reach your targets over SSH and their configured repositories over HTTP(S).

```bash
git clone git@github.com:StealthCat/MrPatchy.git
cd MrPatchy
cp .env.example .env
# Edit .env: choose a unique ADMIN_PASSWORD, DOMAIN, and PUBLIC_URL.
docker compose up -d --build
```

Open `https://YOUR_DOMAIN` and sign in with `ADMIN_PASSWORD`. The password must be at least 12 characters. It is hashed on first startup; later environment changes do not reset it.

The initial certificate uses Caddy's local CA so the first administrator can configure HTTPS without an HTTP password exchange. Trust that CA on your administrator device before signing in. Export its public certificate:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./mrpatchy-local-ca.crt
```

Ensure `DOMAIN` resolves to the Docker host. In **Settings → Configure HTTPS**, choose uploaded certificates or your ACME directory. Public/custom ACME must be able to validate this hostname using HTTP or TLS-ALPN challenges on ports 80/443. The private Caddy admin endpoint is not published to the host. Set `PUBLIC_URL` to the final browser-facing URL so enrollment links use the correct hostname.

## Upgrading an existing installation

Back up your volumes/database, then rebuild. MySQL timestamps are migrated from FLOAT to DOUBLE at startup (ALTER privileges required). Existing targets need one trusted-console rerun of the newly downloaded installer, followed by **Finish / repair installation**, to replace the legacy bridge. New behavior identities may require review after the effective-UID and listener-bind-address improvements. The v0.2 startup also adds the package-state column and history tables idempotently. v0.1.1 targets can use Finish / verify installation to upgrade their managed bridge and collector. See [upgrade details](docs/COMPLETION_REVIEW.md#upgrade).

## Enroll a target: three steps

Target prerequisites: a systemd-based Ubuntu or Raspberry Pi OS machine with **Python 3, OpenSSH server, sudo, OpenSSL and dpkg** already installed.

1. **Endpoint:** select Add server and enter its IP address or hostname, display name, and SSH port.
2. **Prepare:** select one of three delivery modes: curl from the running app, downloaded script, or **offline preparation**. Download the personalized Bash script and run it with `sudo bash mrpatchy-enroll.sh`. It creates `/opt/drpatch`, the `drpatch` account, public SSH key, root-owned bootstrap bridge and restricted sudo permissions. It makes no outbound connection or APT query. Click **I ran the script · Proceed to step 3**.
3. **Connect and verify:** paste the ED25519 SHA256 host fingerprint printed on the target, verify it through a trusted console, and click **Finish and verify installation**. Mr Patchy connects over SSH, installs its collector and service, and checks installed hashes, owner/group, permissions and active service state. The wizard displays the job result.

**Servers → Manage → Download Bash installer** is always available for every configured server, including already-enrolled servers. Re-downloading preserves that server's existing SSH identity. The installer is repeatable; it does not rotate keys.

All three modes use the same offline-safe bootstrap. Curl links expire after one hour; authenticated downloads remain available. For a private HTTPS CA, use curl's `--cacert`; never disable TLS verification. Ongoing management requires central-to-target SSH access.

## Repository access and recovery

In **Repositories → Repository access**, configure scoped HTTPS credentials, a CA bundle, an HTTP(S) proxy, an optional default release, and exact source-URI mirror mappings. Secrets are encrypted in the database, never returned by the access API, and staged in a mode-0600 central APT auth file. Saving access invalidates existing candidate freshness.

A mapping such as `{"file:/srv/repo":"https://mirror.example.com/repo"}` lets central APT check the same signed metadata through an accessible mirror. You must provision that mirror; Mr Patchy does not expose target filesystem content as an HTTP server. Original target sources are preserved. Referenced public keys outside normal directories are captured and safely remapped centrally.

Sources show disabled, blocked, unverified, checked or check-failed status. A blocked source remains visible and fails the aggregate refresh. Use the editor to repair or disable it; **Restore backup** reviews a prior configuration before applying it. Legacy unstructured backups remain available on the target for manual recovery.

**Servers → Manage → Repair broken package state** explicitly runs APT dependency repair with removal prohibited, then dpkg configuration. It may install dependencies and run maintainer scripts. Ordinary update selection rejects broken packages until repaired.

Central repository refreshes can use the last saved inventory while a target is offline. Candidate data describes that inventory; patch execution always reconnects and validates current state.

## Observation and inventory history

The target keeps observation batches in a transactional SQLite spool (48 MB payload budget, at most 2 MB per batch). The central server acknowledges only committed batches, and duplicate delivery is idempotent. Capacity overflow is counted persistently and shown as an integrity finding; storage is bounded, not lossless forever.

Inventory changes, including reversions, create historical revisions. **Servers → Manage → Observation & inventory history** browses paginated records. Settings controls retention (30 days default). Time is target-reported, and periodic sampling cannot see every short-lived process.

## Patch workflow

Open **Packages**, choose a server, and filter to available updates. Assign priorities if needed, select packages, and review the installation confirmation. Explicit patch installation refreshes the target's APT metadata and installs the recorded exact versions. `--no-remove`, `--only-upgrade`, and default hold protection apply; existing configuration files are preserved with `--force-confold`. Maintainer scripts may restart services. Mr Patchy never automatically reboots a target.

Deadlines are measured from the first central discovery of each candidate version:

| Priority | Default deadline |
|---|---:|
| Critical | 24 hours |
| High | 72 hours |
| Normal | 168 hours |
| Low | 720 hours |

Security-origin candidates default to high, other candidates to normal. These are **scheduling heuristics, not CVSS/CVE severity ratings**. Use per-package overrides for your own policy. Deadlines highlight overdue work; they do not perform unattended upgrades. Candidate availability is not a guarantee that the target can successfully install a version: dependencies, vendor hooks, phasing, and repository changes can affect the final transaction.

## AI investigations

Configure an OpenAI API key and a compatible Responses API model in Settings, then enable investigations. No API call occurs until enabled with both credentials and a model. A ChatGPT subscription is separate from API billing.

Each new executable SHA-256 / path / UID / connection-pattern combination is queued per host. PID and ephemeral client ports are excluded from the identity so ordinary restarts do not create an investigation storm. The default limit is 20 investigations per hour. Unfamiliar behavior is persisted even when AI is disabled; failed requests retry with a one-hour backoff.

Initial evidence contains executable paths, hashes, effective UIDs, and network endpoint metadata. The model may request fixed read-only checks of executable metadata, package ownership and selected systemd service properties; a second model call evaluates those results. No model-generated command is executed. Each investigation consumes at most two API calls. No command-line arguments, environment variables, process memory, or executable bytes are sent. The Responses API request uses `store: false`; this does not override your API organization's retention policies. AI results cannot execute commands, patch systems, or automatically create trusted baselines. Known-good status requires an explicit administrator decision and changes in the behavior identity create a new review item.

## MySQL

Create a dedicated database/user on an existing MySQL 8+ server and set:

```dotenv
DATABASE_URL=mysql+pymysql://mrpatchy:URL_ENCODED_PASSWORD@db-host:3306/mrpatchy?charset=utf8mb4
```

Then recreate the app container. SQLite is the default and needs no separate database service. Switching the URL does **not** migrate existing records. Back up the old DB and perform an explicit data migration if you already enrolled targets. CI runs the test suite and schema migrations against a disposable MySQL 8.4 service.

## Scope and operating limits

This is the first implementation, not a claim of production certification. Read [architecture and trust boundaries](docs/ARCHITECTURE.md), [operations](docs/OPERATIONS.md), and the [validation record](docs/VALIDATION.md) before deploying broadly.

- Central resolution uses HTTP(S), including configured authentication and private CAs. Local/media sources need an explicit reachable mirror mapping. Credential-bearing source URLs, custom executable transports and vendor authentication helpers must be converted to a supported configuration; executable target APT hooks are never imported. Private network mirrors are intentionally allowed; this application is for a trusted administrator on a management network.
- Imported source trust/expiry overrides are rejected. Existing trust anchors are acquired through your pinned SSH connection; Mr Patchy cannot independently prove that a pre-existing target key was originally legitimate.
- File integrity covers **Mr Patchy's managed artifacts** and hashes the executable behind each readable `/proc/PID/exe`. It does not validate every OS package file, shared library, script contents, kernel module, or process memory. Executable hashes form a reviewed behavioral baseline, not a claim of vendor provenance. A compromised root/kernel can forge telemetry; hashing is not remote attestation.
- TCP/UDP connections are associated through `/proc` socket inodes in the collector's network namespace. Short-lived activity between samples, other network namespaces, and some inaccessible descriptors can be missed.
- Use one app replica and one Uvicorn worker. Polls use bounded pools; very large fleets, slow links, huge process sets, or long-running target operations may delay collection. Stale telemetry and hash checks are surfaced. No external notification delivery is implemented.
- Repository checks preserve APT preferences/architecture and native Debian version comparisons. Declare default release, credentials, proxy and CA settings centrally; arbitrary target apt.conf is not executed. Vendor token-refresh/entitlement agents are not replicated.
- There is one administrator account. This release has no RBAC, SSO, tamper-evident audit chain, scheduled unattended patching, OS release upgrades, or automatic rollback of package maintainer-script effects.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
```

Tests include a real signed ARM64 repository fixture, altered-index/signature rejection, enrollment script syntax, auth/CSRF, holds, SSH fingerprint pinning, TLS validation, and AI trust boundaries. GitHub Actions also validates Compose and builds the Docker image.

Local preview (development only):

```bash
DATA_DIR=/tmp/mrpatchy-dev COOKIE_SECURE=false \
ADMIN_PASSWORD='choose-a-long-development-password' \
DISABLE_SCHEDULER=1 uvicorn app.main:app --host 127.0.0.1 --port 8000
```

See [the UI screenshots](docs/screenshots/) for the desktop, mobile, enrollment, and settings screens. Example screenshots use a documentation-only IP address and no live infrastructure.
