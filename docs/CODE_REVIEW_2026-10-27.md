# Code review and implementation checkpoint — October 27, 2026

Reviewed the working tree based on PR #29 (`10ea47a23a4437c51b537cbe84e3999b291a878a`). This is a source and regression-test review, not certification that the application is free of defects or a live-host penetration test.

## Confirmed findings fixed

| Priority | Finding | Change and regression evidence |
| --- | --- | --- |
| High | Polling consumed snapshots before independent verification. Snapshot/event handling can import the collector, including a modified collector. A recorded failure also did not stop ordinary queued remote work. | Perform due independent checks before polling enrolled hosts; pause ingestion for drifted, blocked or unavailable results; block new ordinary remote jobs after those results. Maintenance checks, reviewed deployment and advisory AI plans remain available. Already-running release recovery observation remains available. Tests assert no snapshot/remote repair call after detected drift, while automatic agent repair can still queue. |
| High | Finish installation verified by importing the newly deployed collector, and could leave an earlier failed agent-health record in place. Verification did not evaluate unexpected loaded unit overrides. | Use the independent `agent-status` receipt and full manifest/configuration assessment. Persist the successful receipt with the enrolled baseline; reject unexpected overrides without advancing it. Tests cover both outcomes. |
| Medium | An unenrolled `observability.conf` on disk could pass assessment if systemd had not loaded it yet. A later deployment reload could activate it. | Block maintenance when this optional managed file exists without an enrolled digest, even if absent from the loaded drop-in list. Test reproduces the dormant file. |
| Medium | Bounded subprocess runners killed their process group only while the immediate parent was alive. A child retaining output pipes could survive a timeout after the parent exited. | Kill the original process group on failed execution even after the parent exits. Real fork/process tests cover both controller and target runners. Successful commands retain their existing behavior. |
| Medium | Persistence receipts validated entry count but not paths, hashes, metadata, duplicates or contradictory coverage. This was insufficient for dependable history comparisons. | Validate bounded scope, canonical absolute paths, entry types/digests/metadata, missing roots and coverage before saving new receipts. Historical malformed receipts stay immutable and compare as unavailable. |

Independent checks remain periodic (about five minutes) and use the enrolled bridge and remote kernel. They do not attest a compromised root/kernel or eliminate changes between checks. Polling during an active operation can use the last assessment so it does not block behind target mutation locks. Unenrolled/legacy hosts still need the trusted installation workflow. A failed check preserves old telemetry with its old timestamps; it never fabricates fresh telemetry.

## Continued implementation: persistence-history comparison

The server **File integrity** tab now provides **Compare startup inventory**. It compares the selected receipt with the immediately preceding persistence receipt on that server, skipping package-only inspections. It does not skip incomplete persistence receipts to find an older convenient match.

Comparison requires valid, complete inventories with identical scopes. It reports additions, removals, content hashes, ownership, permissions, size, type and symlink target changes. Modification time alone is ignored. Both receipt IDs and observation timestamps are returned. Missing roots are explicit. A gap, malformed historical receipt, absent prior observation or changed scope produces an unavailable comparison, never an inferred deletion or clean result. At most 512 path changes can result from two 256-entry inventories. The comparison is computed from immutable receipts; no database schema change is needed.

This is history comparison, not an approved baseline, automatic malware finding, incident correlation or remediation. No new AI upload, quarantine, deletion or cloud mutation is performed.

## Review scope and remaining improvements

Source review covered the agent lifecycle, SSH routing/enrollment, command dispatch and process limits, worker locking/claim/recovery paths, authentication/CSRF/roles and OIDC, AI request/usage handling, evidence/incident handling, inspection traversal, package repository trust, release execution, patch schedules, offline database migration, TLS configuration, GCP installer and changed browser workflows. Existing regressions exercise these areas; they do not prove every execution path correct.

The next security milestones remain:

1. Approved custom baselines and persistence-change incident linkage, with explicit human review of legitimate administrative changes.
2. Independent trusted-vendor artifact verification, authenticated YARA rules and offline delivery.
3. Typed, approved remediation with execution-time identity checks, race-resistant quarantine/restore and post-action verification.
4. Retention and external immutable evidence, and disposable VM acceptance tests for real systemd, ClamAV/YARA, IAP, reboot/rollback and failure injection.

Other review limitations: multi-web-process shared authentication throttling/MFA transactions remain unfinished (distributed workers are a separate feature); large-fleet capacity requires benchmarking. Root-owned local package databases are not independent vendor trust. Remote helper deployment replaces individual files atomically, not as a multi-file transaction; a lost verification receipt can require console reconciliation. The managed optional-file check does not enumerate every possible dormant systemd override across all systemd search paths. Live configuration inspection and full-VM testing should be expanded before claiming exhaustive service attestation.

## Validation

Validation results are recorded in the pull request after the complete Python suite, desktop/mobile browser suite and GitHub jobs finish. Bandit was unavailable in this workspace; no fresh static-scanner pass is claimed. No real cloud credentials, paid model calls or user-managed hosts were used.
