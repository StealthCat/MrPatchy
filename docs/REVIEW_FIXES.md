# Post-review fixes

This follow-up resolves the concrete defects identified in the requirements/security review after the enterprise-recovery merge. It is not a claim that every possible defect has been eliminated.

| Defect | Corrected behavior | Regression coverage |
|---|---|---|
| Missing SQLite backup source created an empty database | Read-only opening requires an existing regular database, integrity validation and core application tables; restore activation validates the bundle before touching destinations | Missing/non-application backup refusal; encrypted restic restore drill |
| Orphaned running jobs allowed later mutations | Running/recovery-required jobs quarantine the host queue and configuration; explicit reconciliation checks idle central/target locks | Orphan quarantine, protected failure receipt, reconciliation, busy worker |
| Reboot journal reported completion before reboot submission | Persist intent first; only finalize after a changed boot ID and healthy services | Crash before submission; no replay before reconciliation |
| Temporary post-reboot health failures stopped recovery; persistent failures never invoked rollback | Retry health/SSH for ten minutes, request one approved rollback, then verify its reboot separately using the persisted central receipt | Transient retries, rollback once, reverted target journal |
| Patch UI promised no reboot despite enabled policy | Show and capture each host's policy in patch/rollout approval; reject policy changes before execution; load existing settings in target controls | API policy rejection/capture, staged rollout, browser confirmation/hydration |
| Issuer normalization broke trailing-slash OIDC providers | Preserve the exact issuer; normalize only the discovery URL separator | Exact configured issuer and provider metadata |
| New candidates reset overdue patch deadlines | Preserve first outstanding-update time until the package becomes current | Supersession, clearing and new deadline |
| Deleted/replaced mapped libraries disappeared or inherited pathname identity | Prefer mapped-file descriptors; validate device/inode on fallback, hash through one descriptor, retain uncertainty; preserve eBPF verification flags centrally | Deleted/replaced/unlinked mapping fixtures; eBPF flag preservation |
| Viewer Activity attempted an administrator audit request | Fetch audit records only for administrators; show jobs to authorized readers | Role API coverage and browser smoke flow |
| Populated overview overflowed narrow mobile screens | Allow grid children to shrink while tables scroll within their cards | Populated 390-pixel browser viewport |

## Documentation and presentation

The README now supplies the project description, capability overview, three-step enrollment, policy approval semantics, current recovery workflow, upgrade instructions and explicit limits. Operations documentation resets the named administrator account rather than the obsolete legacy password setting. Architecture/recovery documentation reflects worker coordination, quarantine and provenance uncertainty. Screenshots are regenerated from the browser smoke flow with illustrative data and reserved documentation addresses.

## Validation scope

Local validation: 133 Python tests pass; the optional MySQL and real-restic cases are skipped when their services/tools are absent. Desktop/mobile browser smoke checks cover enrollment, installer download, repository settings, stale server responses, patch approvals and saved policy controls. CI additionally runs the MySQL suite, Ubuntu/Debian SSH integration, Docker/Caddy HTTPS startup and an encrypted SQLite restic restore drill.

Acceptance testing is still required for real Raspberry Pi/systemd devices, live identity providers and SMTP/custom ACME servers, kernel eBPF attachment, bootable filesystem rollback and off-host provider connectivity. MySQL compatibility tests do not validate a complete MySQL dump/import recovery drill. Target reboot and rollback regression tests use isolated fixtures; they do not reboot real machines.

## Upgrade consequences

- Update the central app/workers, then finish/verify installation on each target to install the new bridge/collector.
- Existing queued patches cannot inherit an enabled recovery policy without new approval.
- Reconcile orphaned jobs only after inspecting target state and pending reboot timers through a trusted console.
- Re-review changed provenance identities; uncertainty must not inherit an old known-good approval automatically.
- Preserve all existing branches; this update is committed directly to `main`.
