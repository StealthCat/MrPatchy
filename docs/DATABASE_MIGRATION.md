# Database settings and offline migration

Administrators can configure a destination in **Settings → Database**. SQLite remains the default. MySQL fields include host, port, database, username, password, verified TLS and an optional CA file. Passwords are encrypted with the deployment's existing `secret.key`; API responses and audit records never return them. Blank passwords retain the staged secret only when the connection and TLS fields are unchanged. Changing that identity requires a new password or explicit **use no password**.

**Save migration destination** only stages a profile. It does not change the active database, initialize a MySQL server, install packages or copy data. Use an existing empty dedicated MySQL 8+ database with utf8mb4 support and an account permitted to create tables/indexes, read/write rows and perform future schema upgrades. TLS verification defaults on and verifies the certificate and hostname using system trust or the mounted CA file. Mount a custom CA at the same absolute container path for app and workers. Disabling verification is an explicit choice; do not use it for untrusted networks.

SQLite destinations are filenames inside `DATA_DIR` (`/data` in Compose). Choose a **new** filename when returning from MySQL: the original SQLite database is intentionally preserved and will be rejected as a nonempty destination.

## Procedure

1. Update to the same Mr Patchy version on all app/worker hosts and let normal schema initialization finish. Finish running jobs or reconcile interrupted operations; the migration refuses jobs still marked `running`.
2. Save the destination in Settings. Check the active database and destination details. Back up the database and all persistent identity/SSH/TLS volumes. Preserve the existing `secret.key` and SSH directories.
3. Stop **all** app and worker replicas, including remote hosts, and any other database writers. An application maintenance lock protects processes using the same shared data directory. It cannot prove that older software, another data directory, external SQL clients or replicas on an unrelated filesystem have stopped. `--confirm-offline` is your explicit assertion that these writers are stopped. Do not expose the destination to other clients during migration.
4. Run the dry run, then the verified migration. Run each command separately and inspect its exit status before continuing:

```bash
docker compose stop app worker

docker compose run --rm --no-deps app python -m app.database_migrate \
  --confirm-offline --dry-run

docker compose run --rm --no-deps app python -m app.database_migrate \
  --confirm-offline --activate
```

The one-off container uses your saved destination and current source; no database password appears in shell arguments. Caddy may remain running but the UI will be unavailable. The dry run validates source schema/integrity, fingerprints source data, and checks destination emptiness without copying data or creating a destination SQLite file. It does not prove INSERT/DDL permissions or cross-database compatibility; those are verified by the actual copy.

5. After exit status zero and `"activated": true`, restart app and workers with your normal worker count:

```bash
docker compose up -d app worker
# If you normally use three workers:
# docker compose up -d --scale worker=3 app worker
```

Sign in and check Settings, users, hosts, package history, schedules and AI logs. Existing sessions, identities, encrypted credentials, queued work, audit/history rows and exact IDs are preserved. The source remains intact. Do not run both copies independently; queued work could be executed twice. If a remote deployment uses copies of the identity volume, distribute the activated encrypted profile with the matching key to every stopped replica before restarting it.

For direct Python installations, run `python -m app.database_migrate` with the same arguments and `DATA_DIR`/deployment environment after stopping your services.

## Progress and failure diagnostics

The command writes readable stage progress to stderr and only the JSON result to stdout. A failure names the stage (for example `destination-connect`, `copy` or `verify-committed`), the source/destination role and table, a sanitized category and exception class with a safe code (MySQL error number, SQLite result name, errno or SQLSTATE), a specific next check, and whether the destination may have been written. Passwords, connection-string secrets, rows, SQL parameters and raw driver messages are never printed. Add `--verbose` to also print the sanitized exception-class chain and bounded stack locations when asking for help. Stages skipped by `--dry-run` are marked as skipped.

## Validation and failure behavior

The copier registers all current application models, requires the source schema to match, rejects unknown tables/views, and refuses nonempty destinations. SQLite sources are opened read-only and checked for integrity and foreign-key violations. MySQL sources must use transactional InnoDB tables and are read through a consistent read-only snapshot. Data is copied in bounded batches inside a destination transaction; IDs, nullable values, JSON, timestamps, authentication state and encrypted values are copied directly.

Every table is checked by row count and an order-independent multiset fingerprint (sum modulo 2^256 of canonical-row SHA-256 hashes). This avoids differences in MySQL/SQLite row ordering and collation while keeping memory bounded. Verification runs before commit and again on a fresh connection after commit. MySQL collation collisions, length restrictions, encoding errors and value coercions cause failure rather than intentional truncation. No source data is deleted and no destination rows are overwritten.

A DDL failure may leave empty destination tables because MySQL DDL is not transactional. DML or verification failures normally roll back inserted rows. A process interruption after commit can leave a complete nonempty destination without activation. Do not restart services until you have inspected the active profile and destination. Use a fresh empty destination for retry; do not delete the source. The tool deliberately refuses to overwrite a partially populated destination.

Only `--activate` after a successful verified copy writes `DATA_DIR/database-active.json` atomically. The profile is encrypted, mode 0600, and takes precedence over `DATABASE_URL` for **both** app and workers at startup. `database-target.json` is the encrypted staged destination. Editing `.env` after activation does not override the active profile. To change destinations again, stage another target and repeat the offline migration.

A copy without `--activate` is supported for validation/export; it does not switch the deployment. A later migration will refuse that nonempty copy, so use a fresh empty destination for a subsequent activation run. Never use both copies as live systems.

## Backup, restore and rollback

`scripts/recovery.py backup` resolves the active profile before selecting the database to dump and retains both encrypted profiles in the encrypted backup bundle. Remote MySQL native backups still require `MYSQL_SSL_CA` as documented in the recovery workflow. The legacy `scripts/backup.py` refuses deployments with an active profile to prevent silently exporting a stale SQLite file.

Recovery activation deliberately uses the **new restore destination** (explicit `DATABASE_URL` for MySQL, `mrpatchy.db` in the new data directory for SQLite). It does not reinstall the old active/staged profiles from the bundle, which may refer to obsolete paths or credentials. Keep the bundle profiles as recovery reference; configure future migrations again after restore.

For rollback **before any writes to the new database**, stop all replicas and restore the original active profile together with the matching original database, or remove the newly activated profile if the original deployment used `DATABASE_URL`/the SQLite default. After the new database has accepted writes, returning to the old source loses those writes: migrate back into a new empty destination instead. Keep database snapshots and encryption/SSH/TLS material together.

## Current-schema refusal in older migration commands

The standalone migration command in v1.19.0/v1.20.0 can reject an already-upgraded
source because its separate model list omits AI retry and assessment/refresh tables.
Restarting that same version does not correct this defect. v1.20.1 uses the same
model registry as startup, including these retained records. Update/rebuild the
migration container from the corrected source and repeat the offline dry run before
copy/activation. Keep all app/workers stopped during the migration as described above.

Do not delete the AI tables, bypass schema validation, or overwrite a nonempty
destination to work around this message. Genuine version/schema mismatches and
unknown tables/views still require review; this fix does not automatically upgrade
a source schema or relax the copier's safeguards. Source data is preserved, and a
refused dry run does not activate a destination.

Starting in v1.23.1, the refusal identifies a bounded list of missing tables,
unexpected tables and unexpected views. Names are escaped before they are printed.
Missing current tables mean the source has not completed current-version startup
initialization; restart the current controller against the source, confirm startup
completed, stop every writer again, and repeat the dry run. Unexpected tables or
views remain a review blocker. The diagnostic does not delete, rename, copy around
or silently accept any object. If more than eight objects occur in one category,
the message reports the remaining count without producing unbounded output.
