# Mr Patchy

**A little care. A healthier Linux fleet.**

Mr Patchy is a self-hosted, Dockerized dashboard for Ubuntu and Raspberry Pi OS / Raspbian servers. It collects inventory over pinned-key SSH, resolves available APT versions centrally, tracks patch deadlines, and investigates unfamiliar process behavior through the OpenAI API.

![Mr Patchy overview](docs/screenshots/overview.webp)

## What is implemented

- Responsive dashboard: fleet overview, enrollment, searchable installed packages, updates, repositories, investigations, operation results, and audit trail.
- A dedicated SSH key per target, verified host-key fingerprints, a forced SSH command, and a fixed sudo entry point.
- Downloadable **offline enrollment script** containing the public key and bootstrap bridge. The same script is available through an expiring curl link served by the running application.
- Central deployment/repair of a root-owned Python collector and systemd service, with `/opt/drpatch` as the target account home and spool directory.
- Persistent SQLite inventory by default; MySQL through SQLAlchemy. Inventory includes held and multi-architecture packages. Package changes/removals are audited after initial discovery.
- Native APT runs **inside the central container** with isolated per-host status, source files, keys, preferences, architecture, and machine ID. The collector never runs `apt update`, `apt list`, or `apt-cache` for discovery.
- APT signature and index-hash verification. Failed repository refreshes stay visible and do not advance the last-success timestamp.
- Inspect/edit/add/disable repository definitions in `.list` and Deb822 `.sources` format; upload scoped signing keys; back up source files before changes.
- Operator-selected exact-version upgrades, with package-removal protection and respect for holds. Target APT runs only during an explicitly requested installation.
- Configurable repository refresh interval (**60 minutes** default), priority deadlines, and per-package priority overrides.
- Target process and TCP/UDP connection sampling every **30 seconds**. SHA-256 sweeps of Mr Patchy's installed artifacts and running executables every **five minutes**.
- Central AI investigations with structured results, encrypted API-key storage, a configurable rate limit, retry backoff, and explicit known-good approval/revocation.
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

## Enroll a target

1. Target prerequisites: a systemd-based Ubuntu or Raspberry Pi OS machine with **Python 3, OpenSSH server, sudo, OpenSSL, and dpkg** already installed. An offline bootstrap cannot install missing prerequisites.
2. Select **Add server** and enter a display name, SSH address, and port.
3. Download its personalized installer or obtain its one-hour curl link. Run as root:

   ```bash
   sudo bash mrpatchy-enroll.sh
   ```

   The UI supplies a command to download the installer from your running application. For private HTTPS, use curl's `--cacert` option; do not disable TLS verification.
4. The installer creates `drpatch`, `/opt/drpatch`, the forced-command authorized key, the bridge, and a narrow sudoers entry. It makes **no outbound connection**, downloads no dependencies, and does not query APT.
5. Copy the **ED25519 host-key SHA256 fingerprint** printed by the installer into the server form. Verify it through the machine's console or another trusted channel. Allow inbound SSH from the central server.
6. Select **Finish installation**. The app uploads its collector, installs/enables the service, records expected artifact hashes, and begins collecting. A repository refresh follows after the first poll. Use **Activity** to inspect results.

Offline enrollment means the bootstrap does not need Internet or central-server access. Ongoing management requires the central server to reach the target over SSH. Both installer delivery options use the same offline-safe bootstrap and the same web-based completion step.

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

Only executable paths, hashes, UIDs, and network endpoint metadata are sent. No command-line arguments, environment variables, process memory, or executable bytes are sent. The Responses API request uses `store: false`; this does not override your API organization's retention policies. AI results cannot execute commands, patch systems, or automatically create trusted baselines. Known-good status requires an explicit administrator decision and changes in the behavior identity create a new review item.

## MySQL

Create a dedicated database/user on an existing MySQL 8+ server and set:

```dotenv
DATABASE_URL=mysql+pymysql://mrpatchy:URL_ENCODED_PASSWORD@db-host:3306/mrpatchy?charset=utf8mb4
```

Then recreate the app container. SQLite is the default and needs no separate database service. Switching the URL does **not** migrate existing records. Back up the old DB and perform an explicit data migration if you already enrolled targets. MySQL deployment has not been exercised against a live database in the development workspace.

## Scope and operating limits

This is the first implementation, not a claim of production certification. Read [architecture and trust boundaries](docs/ARCHITECTURE.md), [operations](docs/OPERATIONS.md), and the [validation record](docs/VALIDATION.md) before deploying broadly.

- HTTP(S) APT repositories are supported. `file:`, `cdrom:`, credential-bearing URLs, arbitrary external key paths, vendor authentication helpers, and custom target `apt.conf` hooks are not mirrored. They remain visible for review where captured, and unsupported active sources fail visibly. Use a centrally reachable, signed HTTP(S) mirror. Private network mirrors are intentionally allowed; this application is for a trusted administrator on a management network.
- Imported source trust/expiry overrides are rejected. Existing trust anchors are acquired through your pinned SSH connection; Mr Patchy cannot independently prove that a pre-existing target key was originally legitimate.
- File integrity covers **Mr Patchy's managed artifacts** and hashes the executable behind each readable `/proc/PID/exe`. It does not validate every OS package file, shared library, script contents, kernel module, or process memory. Executable hashes form a reviewed behavioral baseline, not a claim of vendor provenance. A compromised root/kernel can forge telemetry; hashing is not remote attestation.
- TCP/UDP connections are associated through `/proc` socket inodes in the collector's network namespace. Short-lived activity between samples, other network namespaces, and some inaccessible descriptors can be missed.
- Use one app replica and one Uvicorn worker. Polls use bounded pools; very large fleets, slow links, huge process sets, or long-running target operations may delay collection. Stale telemetry and hash checks are surfaced. No external notification delivery is implemented.
- Repository checks preserve native APT preferences/architecture and use native Debian version comparisons. They do not import target APT executable hooks or automatically match custom `APT::Default-Release` settings. Ubuntu Pro/authenticated feeds need additional credential support.
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
