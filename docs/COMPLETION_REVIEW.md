# Mr Patchy v0.2 — completion and follow-up review

Baseline: main commit `ba82bd176721cea56b44b8322862e53a1bd00eaf`, including the fixes from PR #1. This document supersedes the original review's requirement-status table; the original findings remain historical evidence.

## Delivered behavior

| Requirement / previous gap | Implementation | Practical boundary |
|---|---|---|
| Three-step offline installation | Endpoint form → downloadable offline Bash preparation → pinned SSH completion and verification | Prerequisites must exist on the target; no offline dependency installation is claimed |
| Re-download script for any configured host | Permanent authenticated download in each server's Manage dialog | Script retains that server's assigned public key; it does not rotate identities |
| Central completion and verification | Deploy collector/bridge/unit; compare actual file SHA-256, UID/GID/mode and active service state | Fresh telemetry independently establishes continuing operation |
| Broken package inventory | Preserve unpacked, half-configured, reinstreq and other non-removed states; show state beside version | Residual config-files-only records are not installed packages |
| Package recovery | Explicit reviewed APT dependency repair with no removals, followed by dpkg configuration | Maintainer scripts may restart services; this is not transactional OS rollback |
| Inventory history | Retained revisions include repeated A → B → A changes; paginated summary/detail API and UI | Retention defaults to 30 days and is configurable |
| Durable process observations | Target SQLite spool; bounded partitioning; UUID batches; commit-before-ACK; replay deduplication; retained central observations | 48 MB payload budget, 256 KiB batch ceiling; individually oversized records and capacity eviction are explicit, reasoned and cumulative |
| AI investigations | First structured assessment can request allowlisted executable/package/service evidence; second assessment evaluates it | At most two model calls; exited/changed identities are reported; no arbitrary commands or automatic trust |
| Investigation backlog | Pending count, oldest pending time, enabled state and rate cap visible in UI | API availability and configured budget still constrain throughput |
| Authenticated/private repositories | Encrypted scoped credentials, private CA bundle, HTTP(S) proxy, default-release policy | Vendor token-refresh/entitlement helpers are not replicated |
| External signing-key paths | Capture referenced public .asc/.gpg keys; remap to isolated central paths | Only explicit public-key file paths; no central filesystem fallback |
| Local/media repositories | Exact source-URI mapping to an accessible HTTP(S) mirror, retaining signed metadata validation | Administrator must provision the mirror; the app does not create or expose one |
| Repository health and repair | Source-file status, validation errors, source editor/disable, key management, reviewed backup restoration | A failed aggregate refresh is not presented as per-source success; arbitrary hooks remain prohibited |
| Central checks while target is offline | Use saved inventory; refresh native APT centrally; revalidate target before patch | Results describe the saved inventory, not unseen target changes |
| Bounded operation output | Concurrent pipe draining, deadlines, 16 MB ceiling; successful DB logs limited to 48 KB | Timeout/limit termination during package operations can require manual recovery |
| Existing core requirements | Docker, SQLite/MySQL, pinned SSH, 60-minute configurable repository checks, four patch deadlines, 30-second sampling, five-minute integrity sweeps, HTTPS/uploaded cert/custom ACME retained | See validation limits below |

“All repositories” is not an honest unconditional claim for arbitrary APT transport plugins, executable authentication hooks, disconnected media or unavailable credentials. Those configurations remain visible and fail closed; HTTP(S) access and explicit mirror mappings cover the implemented central transport. Similarly, hashing Mr Patchy's installed artifacts and running executables is not full operating-system attestation.

## Follow-up correctness and security review

The following issues were addressed while adding the features:

1. **False installation completion:** deployment acknowledgement alone did not establish final ownership, permissions or active service state. Completion now requires an independent verification action; mismatches fail the job.
2. **Lost intermediate observations:** latest-only snapshots could hide behavior during delays/outages. Batches are durable and acknowledged only after commit, with replay tests and explicit overflow counters.
3. **Broken package invisibility:** dpkg filtering omitted half-configured and unpacked packages. Their state is persisted and visible; ordinary patch selection rejects broken states until explicit recovery.
4. **Repository availability coupled to SSH:** central refresh previously stopped for offline hosts. Cached-inventory resolution now works independently of SSH, without claiming the target inventory is current.
5. **Credential/configuration injection:** repository access is a declarative allowlist. Credential fields reject delimiter/control injection; HTTPS credential scopes and mirror destinations are validated. Secrets are not returned by the UI API.
6. **Configuration races:** access/fingerprint/priority changes cannot race a host's active operation. Freshness is invalidated after access changes.
7. **Stale signing material and central path confusion:** removed keys fail closed; external public keys receive isolated hashed filenames rather than arbitrary central paths.
8. **History deduplication hiding reversions:** revisions track changes, not merely unique content hashes, so repeated states remain historical events.
9. **Unbounded subprocess output/MySQL TEXT overflow:** central/target subprocess output has explicit byte and time limits; successful and failed job output is capped by bytes before persistence.
10. **Recovery ordering:** missing dependencies can prevent dpkg configuration. Explicit recovery resolves dependencies first, then configures packages.
11. **Unrestricted AI tool risk:** the model can request only fixed evidence categories; the bridge re-identifies an executable by path/hash and reads selected metadata. No model-provided executable command or arbitrary file path is executed/read.
12. **History response amplification:** history lists return small metadata records; large details load individually and are host-scoped.
13. **Source symlink backup leakage:** source mutation rejects symlinks before reading backup contents.
14. **Duplicate CI cancellation:** pushes to main and pull requests trigger checks; branch push plus PR no longer launch competing duplicate runs.

The existing single-administrator security model remains. Central administrators/SSH private-key holders can deploy root collector code; the forced command reduces accidental shell exposure, not that administrative trust. A root-compromised target can forge its own telemetry.

## Validation

- Local Python suite: **89 passed, one MySQL-only test skipped** at the completion checkpoint.
- Native APT integration checks both a public HTTP signed ARM64 repository and an authenticated HTTPS fixture with a private CA and local-source mirror mapping. Tampered index and signature tests fail closed.
- Browser test covers all three enrollment steps, generated installer download, curl delivery option, verification result, persistent Manage download, settings and the prior wrong-server response regression.
- Docker CI adds real OpenSSH/sudo verification, durable batch acknowledgement, source backup/restore and existing ownership/pinning checks on Ubuntu 24.04 and Debian Bookworm.
- MySQL CI runs the full suite, including idempotent package-state and timestamp migrations.
- AI tests use a mocked Responses API. No paid API requests or operations on real user targets are performed.
- Fixture service control is stubbed. Actual systemd boot persistence, Raspberry Pi ARM hardware, live custom-ACME issuance, real production package recovery, other namespaces and fleet load are **not established by these tests**. Green CI must not be described as proof of those conditions.

## Suggested improvements and functionality expansion

Priority order:

1. **Identity and access:** MFA/OIDC, named users, viewer/operator/admin roles, audit attribution, session management and SSH-key rotation/revocation.
2. **Operational notifications:** email/webhooks for overdue patches, stale telemetry, failed repository checks, integrity changes and spool overflow; acknowledgement and escalation policies.
3. **Patch orchestration:** maintenance windows, staged/canary rollout, dependency-plan preview, reboot policy and post-patch service checks. Snapshot rollback should be platform-specific and explicitly tested.
4. **Security prioritization:** map distro advisories/CVEs to installed packages, track affected/fixed versions, distinguish severity from current repository-origin scheduling heuristics, and export SBOMs.
5. **Repository transport breadth:** native read-only local/media index acquisition, vendor entitlement/token-refresh integration and authenticated proxies, with dedicated trust and credential-scoping tests.
6. **Fleet scale:** durable multi-worker queue, per-host backpressure/jitter, APT metadata cache quotas, batch history storage, pagination/filtering across all fleet tables and metrics. Current scheduler requires one process/replica.
7. **Deeper observation:** namespace-aware collection, interpreted-script/library provenance, eBPF event capture for short-lived processes, package-artifact verification and hardware attestation where appropriate. These require additional target privileges and explicit coverage claims.
8. **Audit and recovery:** off-host append-only audit export, database/secret backup validation and restore drills, source backup retention/cleanup, and disaster-recovery tooling.
9. **UI refinement:** structured credential/mirror editors instead of JSON, source-level fetch diagnostics, timeline diffs, searchable investigation history, and accessible progress announcements.
10. **Platform acceptance:** real systemd Ubuntu and Raspberry Pi tests, ARM image builds, disposable package upgrade/repair scenarios, custom-ACME issuance/renewal and long-running load/failure testing.

## Upgrade

Back up the database and app/TLS volumes. Rebuild after merging. Startup creates history tables and adds the package-state column idempotently; MySQL requires schema ALTER privileges. SQLite remains the default.

For legacy v0.1 targets, re-download/run the bootstrap once. For targets with the v0.1.1 managed bridge, **Finish / verify installation** updates the collector and bridge directly. The current installer is also always available for recovery.

The historical source backup format is preserved on disk, but only new structured backups appear in the restore UI. Existing known-good approvals are not silently expanded. Observation history begins when the upgraded collector runs; it cannot reconstruct past missed samples.

## References

- [APT authentication format](https://manpages.debian.org/testing/apt/apt_auth.conf.5.en.html)
- [APT HTTPS transport and private CA configuration](https://manpages.ubuntu.com/manpages/noble/man1/apt-transport-https.1.html)
