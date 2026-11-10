# Secret custody and key rotation: inventory and migration contract

Status: **design only** (issue #346, first slice). Nothing in this document is implemented or changes runtime behavior. No provider is contacted, no key semantics change, and no response action is authorized by it.

## 1. Current behavior (inventory on main)

One local key file, `DATA_DIR/secret.key`, holds a Fernet key. It is created with mode 0600 on first use (`app/security.py:_key`) and cached until its inode, size or mtime changes. Two things depend on it:

1. **Direct Fernet encryption** with `seal()`/`unseal()` (plain Fernet tokens, no key identifier, no version prefix).
2. **HKDF-SHA256 subkeys** from `derive_key(purpose)`, salt `None`, info `b'mrpatchy:' + purpose`.

### 1.1 Consumers of the Fernet key (ciphertext at rest)

| Consumer | Stored in | Written by | Read by |
|---|---|---|---|
| AI provider API key | `Setting` `openai_key` → `{'encrypted': …}` | `app/main.py` (AI settings, AI test) | `main.py`, `releases.py`, `startup_ai.py`, `update_scores.py`, `incidents.py`, `worker.py` |
| Per-host repository access | `Setting` `repository-access:<host>` | `app/main.py` | `app/worker.py` |
| Notification (SMTP/webhook) configuration | `Setting` `notifications` | `app/main.py` | `app/main.py`, `app/operations.py` |
| Local MFA secret (active and pending) | user columns `otp_secret`, `otp_pending` | `app/main.py` | `app/identity.py` |
| Release-upgrade plan bodies | release table column `encrypted` (+ `digest` of the canonical plan) | `app/releases.py:store` | `app/releases.py:body` |
| Database profiles (including MySQL password) | `DATA_DIR/database-<name>.json` → `{'encrypted': …}` | `app/database_config.py` | `database_config.py`, `scripts/recovery.py` |

Notes:

- Database profiles live in files, not in the database. They are read with a **second, separate** Fernet construction (`database_config.read_profile`, `scripts/recovery.py`) that opens `secret.key` directly and bypasses `app/security.py`. Any change to key semantics must touch these call sites too.
- Rows are not tagged with the key that sealed them, so a row cannot be told apart from one sealed by an older key without trying to decrypt it.

### 1.2 Consumers of derived subkeys

| Purpose label | Use | Effect of key change |
|---|---|---|
| `oidc-flow-cookie` | Starlette `SessionMiddleware` signing key for the 5-minute SSO flow cookie (`app/main.py`) | In-flight SSO logins fail; the user retries. No stored data affected. |

Authenticated browser sessions are server-side rows (`session:<token hash>`), not signed with this key. The OIDC client secret is a deployment environment variable, not stored by the controller.

### 1.3 Backup and recovery

`scripts/recovery.py` copies `secret.key` into every backup bundle beside the database dump and requires it on restore (`Missing or unsafe secret.key`). A backup is therefore only restorable together with the key that sealed its contents. The existing threat model (docs/SECURITY_IMPLEMENTATION.md, "Password hashes and secret-key handling") already records that `secret.key` shares a volume with the database, so at-rest encryption mainly helps when only the database is leaked.

### 1.4 Gaps this design addresses

- No key identifier, so no staged or resumable rotation and no mixed-version detection.
- No supported way to keep the key off the data volume.
- Rotation today would be a manual all-or-nothing file swap that would orphan every existing ciphertext.
- Three code paths build Fernet independently.

## 2. Goals and non-goals

Goals: optional external key custody; versioned envelopes; resumable, replica-safe rotation; fail-closed behavior; recovery of pre- and post-rotation backups; unchanged behavior for existing local-file deployments.

Non-goals for the first implementation slice: HSM-specific features, per-tenant keys, rotating the HKDF subkey semantics (see 4.4), and changing what is encrypted. The local-file mode stays supported and is the default.

## 3. Provider boundary

A small interface in a new module (for example `app/secret_provider.py`) used by `app/security.py` only. `database_config.py` and `scripts/recovery.py` must call into `security` rather than constructing Fernet themselves.

```
class SecretProvider:
    def active_key_id(self) -> str                  # id used for new writes
    def data_key(self, key_id: str) -> bytes        # 32-byte Fernet-compatible key
    def known_key_ids(self) -> list[str]            # ids that may still decrypt
```

Rules:

- **Local-file provider** (default, compatibility): key id `local-1`, key = contents of `secret.key`. Existing files keep working unchanged.
- **External provider** (one adapter, later slice): resolves keys from a KMS/Vault-style service. Prefer envelope use: the provider unwraps a data key; the controller never sends application data to the provider. Credentials for the provider are least-privilege (unwrap/decrypt on named keys only, no key administration) and supplied through the deployment environment, never the browser.
- **Fail closed:** if the provider is unreachable, returns the wrong key, or a required key id is unknown, `seal`/`unseal` raise a typed error. They never fall back to another key, to plaintext, or to generating a new key. The server surfaces a generic, masked error; audit records name the key id and operation, never key or secret material.
- A startup/readiness check verifies the active key can decrypt a sentinel value before the controller accepts writes.
- Cache provider-returned keys in memory only, with a bounded lifetime; never write them to disk, logs, audit or diagnostics.

## 4. Versioned envelope

### 4.1 Format

New ciphertext is prefixed so the key is identifiable: `mp1:<key_id>:<fernet token>`. Fernet tokens use the URL-safe base64 alphabet and never contain `:`, so the prefix is unambiguous. Key ids are restricted to `[A-Za-z0-9._-]{1,64}`.

### 4.2 Read compatibility

`unseal` accepts both forms:

- `mp1:` envelope → look up `key_id`.
- A bare Fernet token (every row written today) → treated as key id `local-1`, the legacy key.

This makes the first release of the format **read-compatible with all existing data and all existing backups**. New writes use the envelope only after the migration in section 5 is enabled, so a rolled-back replica never meets ciphertext it cannot read until the operator has confirmed all replicas run the new version (see 5.1).

### 4.3 Consumers to convert

All rows in table 1.1, through one `seal`/`unseal` path. The database-profile files and `scripts/recovery.py` are converted to the same path. Each consumer needs an enumerate-and-rewrite hook (section 5.2), so a new consumer cannot be added without being covered by rotation. A test must fail if any module outside `app/security.py` imports `Fernet`.

### 4.4 Derived subkeys

`derive_key` keeps deriving from the **legacy local key** (`local-1`) until a separate decision is made, because changing it only invalidates 5-minute SSO flow cookies and is not a data-loss risk. Rotation of the active data key therefore does not break existing cookie signing. If subkeys later derive from the active key, the label must include the key id, and the old key must verify cookies for their max age.

## 5. Rotation procedure

### 5.1 Preconditions and ordering

1. Every replica (controller and worker) runs a version that can read `mp1:` envelopes. Mixed-version rollout is detected by a per-replica version heartbeat; the rotation command refuses to start while any live replica is older.
2. Add the new key to the provider and mark it a *known* key (decrypt-capable) before making it *active*. Order is always: **add → verify read on all replicas → make active → re-encrypt → retire**.

### 5.2 Re-encryption

- A resumable job walks each consumer in table 1.1 and rewrites ciphertext under the active key id, one row per transaction (rows) or via atomic replace (profile files).
- Progress is per-row, determined by the envelope's key id, so the job is naturally idempotent and can resume after interruption with no separate journal. A small status record (counts per consumer, last error, started/finished) is kept for display.
- A row is replaced only after the new ciphertext decrypts back to the original plaintext in memory. A failure on any row leaves that row unchanged and the job reports it; it never deletes the old ciphertext first.
- Concurrency: a database advisory lock or lease row ensures a single rotation job per deployment; replicas keep reading with all known keys while it runs.
- Rewrites do not change `digest` fields (they hash plaintext plans) and are not logged with plaintext.

### 5.3 Retiring the old key

An old key id may be retired only when a scan finds **no** ciphertext (rows and profile files) naming it **and** the operator confirms that no backup they intend to restore still needs it. Retirement is two-step: *disable for writes/reads in the running service*, then, after a retention period set by the operator, *destroy in the provider*. Revocation never happens automatically.

## 6. Backup and disaster recovery

- A bundle records, in its manifest, the set of key ids present in its ciphertext and the provider type. It no longer needs to embed the key when an external provider is configured; local mode keeps copying `secret.key` as today.
- A bundle made **before** rotation needs the old key id; one made **after** needs the new id. Restore verifies up front that every key id named by the manifest is available, and otherwise fails before writing anything, listing missing ids (not material).
- Offline procedure: the operator keeps an escrowed, offline copy of each key not yet retired, stored separately from the bundles. The local-file mode documents exporting the key file to that escrow.
- Rehearsal required before widening support: restore a pre-rotation backup and a post-rotation backup into a clean deployment, then confirm database profiles, SSH trust material, MFA secrets and release plans all decrypt.

SSH private keys under `DATA_DIR/ssh/` are not Fernet-encrypted today; they are protected by file permissions and are outside this design's first slice. If they are brought under custody later, they join table 1.1 and the rotation job.

## 7. Test matrix (to be implemented with the adapter)

| Case | Expected |
|---|---|
| Legacy bare token read | decrypts as `local-1` |
| New write then read | `mp1:` envelope round-trips |
| Provider outage on read/write | typed error, no fallback, no partial write, masked message |
| Wrong key / unknown key id | typed error naming the id only |
| Rotation interrupted after N rows | resume completes; all rows readable throughout |
| Mixed-version replica present | rotation refuses to start |
| Partial migration (rows under two ids) | both readable; scan reports counts per id |
| Retire with ciphertext remaining | refused |
| Restore of pre- and post-rotation bundles | succeed when keys available; fail up front, before writes, when not |
| Restore with retired/unavailable key | fails closed, lists missing ids |
| Diagnostics, audit, logs | contain key ids and counts only, never key or plaintext |
| No stray Fernet construction | static test: only `app/security.py` imports Fernet |

Local fixtures validate the interface and local-file mode only. They do not demonstrate support for any real KMS/Vault product; that needs its own adapter, credentials and acceptance test.

## 8. Suggested delivery sequence

1. This document (inventory and contract).
2. Refactor: route `database_config.py` and `scripts/recovery.py` through `app/security.py`; add the static no-stray-Fernet test. No format change.
3. Read-side envelope support plus version heartbeat (still writes legacy tokens).
4. Write-side envelopes, rotation job, retirement scan, backup manifest key ids; local-file provider only.
5. One external provider adapter, rehearsed rotation and restore.

Other #346 items (dependency-vulnerability gates, worker healthcheck, Compose capability/read-only/resource limits) are separate slices and are not covered here.
