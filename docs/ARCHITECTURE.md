# Architecture and trust boundaries

## Components

| Component | Responsibility | Runtime |
|---|---|---|
| Caddy | HTTPS termination, certificate management, reverse proxy | Separate Docker container |
| FastAPI application | Admin authentication, UI/API, configuration, job/audit records | Unprivileged `mrpatchy` user in the app container |
| Scheduler | SSH polling, queued target operations, repository refreshes, AI investigation dispatch | One process with separate bounded thread pools |
| Central APT resolver | Fetch/verify repository metadata and derive candidates for each target inventory | Native APT subprocesses in isolated per-target directories |
| Bootstrap bridge | Fixed JSON actions over forced-command SSH | Root via a fixed sudoers entry |
| Collector | Inventory, process/connection snapshots, SHA-256 sweeps | Root-owned systemd service, no outbound networking |
| Database | Hosts, packages, candidates, known-good behaviors, investigations, policies, audit, jobs | SQLite or MySQL |

The target collector writes atomic snapshots plus a bounded transactional observation spool under `/opt/drpatch`. The server pulls them over SSH; targets do not post to an Internet-facing ingestion endpoint. SSH protects transport authenticity and confidentiality, with a per-target client key and administrator-pinned host fingerprint.

## Enrollment lifecycle

1. Create a host row and a unique Ed25519 client key. Store private material only in the server's persistent volume.
2. Render a personalized bootstrap script containing the **public** key and bridge source. The script is usable offline.
3. Bootstrap establishes a dedicated account, root-controlled home/authorized-key location, fixed sudo command, and root-owned bridge. An unrelated existing `drpatch` account is rejected.
4. Administrator pins a target-console ED25519 fingerprint. A mismatch stops SSH authentication.
5. Central deployment sends the collector source and its SHA-256 over authenticated SSH. The bridge validates the digest and Python syntax, writes the service, and starts it.
6. Expected managed-artifact hashes are generated from central source/configuration, not learned from arbitrary reported target hashes.

The digest accompanying deployment detects transfer/content mismatch; authenticity comes from SSH. Possession of the central SSH private key permits collector deployment and therefore root-code deployment on that target. Restricting the command limits accidental/general shell access but does not remove this administrative trust relationship. Protect central storage and administrator access accordingly.

## Central repository resolution

The collector reads `/var/lib/dpkg/status`, `/etc/os-release`, source definitions, preferences, machine ID, and usual signing-key directories. `dpkg --print-architecture` and `--print-foreign-architectures` provide architecture metadata; these are not APT queries.

The app builds an isolated APT directory per host and maps Signed-By paths to captured keys. It never imports `apt.conf` executable hooks. It supplies captured dpkg status, preferences, machine ID and architectures to native APT, runs `apt-get update` centrally, then reads central `apt-cache policy` for the installed package names. Native `dpkg --compare-versions` handles epochs/tildes/revisions. APT validates Release/InRelease signatures and index hashes. Refresh errors do not update the success timestamp or replace previously known candidates with an empty success.

Initial trust in captured signing keys comes from enrollment. Unsupported source schemes and verification-weakening directives fail closed. Internal repositories are allowed deliberately; administrator-authored repositories can cause outbound HTTP(S) from the management container. Use network policy to restrict that egress if needed.

Only an operator-requested patch or repair job invokes target `apt-get update` followed by exact-version installation. Discovery never depends on refreshing the target's APT cache. This separation also means a central candidate is availability evidence rather than a guaranteed install plan.

## Integrity and behavioral identity

Managed artifact manifest: collector source, bridge source, systemd unit, sudoers entry, and authorized_keys. Every five minutes the collector clears its executable-hash cache, rehashes managed files, and hashes each running executable. Between sweeps, a newly observed inode/mtime/size identity is hashed immediately. A five-minute sweep detects changed bytes even if their metadata was preserved, provided the collector/kernel remain honest.

Behavior identity is SHA-256 over host ID plus executable path/hash, UID and normalized network endpoints. PIDs and ephemeral client source ports are excluded. Listening ports remain part of the identity. The database retains first/last observation times, evidence, AI result, and the administrator's approval bit. Approval never propagates across hosts or changed identities.

This is periodic observation, not EDR or hardware-backed attestation. It can miss short-lived processes, mmap'ed code, libraries, deleted executable content unavailable through procfs, scripts interpreted by a trusted interpreter, and sockets outside the current network namespace. Read/collection errors and stale timestamps are surfaced.

## AI boundary

All OpenAI requests originate centrally. API keys are encrypted at rest with a Fernet key stored in the app volume. This protects a database-only disclosure; an attacker controlling both database and app volume can decrypt them. The system instruction treats telemetry as untrusted evidence. Strict JSON-schema results, output limits, a two-stage workflow with only fixed package/service/executable evidence checks, no model-generated shell execution, no automatic approval, a per-hour dispatch cap, and retry backoff constrain the workflow.

An AI classification is a triage aid, not proof that a binary is benign. Approval is a separate audited administrator action. Records do not silently become known good on a model's recommendation.

## Web and deployment boundary

Password hashes use scrypt. Sessions are random opaque tokens stored only as token hashes, with expiration, HttpOnly/SameSite=Strict/Secure cookies, and CSRF tokens on mutations. Login attempts are rate-limited. The UI escapes server-controlled text, uses a restrictive CSP, and does not load third-party scripts. API keys and TLS private keys are not returned through settings APIs.

Caddy and the app share only a TLS configuration volume; Caddy does not mount the app's database/SSH secrets. Its administration port exists only on Docker networks and is not host-published. The app runs as an unprivileged UID after entrypoint volume preparation. The Docker socket is never mounted. A single worker is required because scheduler ownership/locks are in-process.

Local audit records support review but are not immutable against a database administrator. Session and enrollment tokens are stored hashed. Installer links expire after an hour and may be reused during that hour; they contain no client private key.


## v0.2 data delivery and access

Observation batches use UUIDs on the target and host-scoped SHA-256 IDs centrally. A transaction persists the batch and behavior records before ACK; interrupted delivery retries safely. A 48 MB target payload budget and 2 MB batch ceiling bound storage, with explicit persistent overflow counters. Central received-time retention controls history cleanup. Inventory revisions are written on changes, including A → B → A transitions.

Central repository access is declarative and encrypted in Setting records. Native APT receives a private auth.conf, optional CA/proxy/default-release, and rewritten mirror URIs. Unsupported source configurations fail closed; all captured source files remain editable. Local/media mirrors are administrator-provisioned. Custom target hooks and arbitrary filesystem access are not delegated to APT.

Process investigations re-identify a currently running executable by path and SHA-256 before collecting fixed metadata. A process that has exited/changed produces an explicit unavailable identity result. Package ownership is evidence, not a verified publisher signature. The AI cannot request arbitrary files, commands, package mutations, or trust approvals.

Subprocess pipes are drained concurrently with a 16 MB output ceiling and total deadline. Failed/oversize commands are terminated and reported; successful operation logs are bounded below MySQL TEXT's byte limit. A timeout during APT can leave a target requiring explicit recovery.

Installation completion checks actual file bytes and metadata plus service active state. This establishes installed artifacts and service startup, not future uptime; subsequent telemetry freshness remains independently monitored.
