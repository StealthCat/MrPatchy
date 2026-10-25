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

## Release-upgrade review

| Defect | Corrected behavior | Regression coverage |
|---|---|---|
| SSH loss during restart/submission prematurely quarantined accepted work | Retry receipt observation; persist submission intent and never repeat an ambiguous start | Disconnect before status, lost start reply, missing receipt |
| Truncated display logs doubled as recovery state; restarts reset health budgets | Persist bounded structured receipts and absolute phase deadlines in SQL job payloads | Non-JSON display log, expired deadline after restart, lost rollback reply |
| Healthy newer OS could be mistaken for successful rollback | Require original OS/package/source/key fingerprint, configuration hashes/metadata, clean dpkg and original services | Healthy target with wrong inventory is rejected; reverted journal recovery |
| Service guard cleanup happened after reboot scheduling | Remove and sync only the exact owned guard before reboot/rollback; preserve unexpected replacements and quarantine | Guard absent when reboot/rollback is submitted; foreign guard retained |
| Normal and rollback reboot timers reused a unit name | Separate timer units and stop a pending normal timer before requested rollback | Distinct timer names |
| Minimal Debian upgrade was unpinned; pinned installs converted dependencies to manual | Simulate and pin both stages, enforce the reviewed transaction and restore automatic markings | Unapproved minimal changes rejected; original/manual/new-dependency flags |
| Existing site validator could be ignored; executable hooks could change after approval | Always include an available validator; bind bridge/recovery/validation file hashes and metadata | Validator retained for built-in edits; changed hook rejects approval |
| Secret heuristic missed compound keys and URL passwords | Block compound password/token/API-key keys and URL credentials before AI requests | Compound and quoted keys, credential-bearing URL |
| Delayed progress response could attach old approval to a new plan dialog | Bind controls to captured DOM/view; invalidate stale requests on close/navigation/login | Delayed old job response, new plan GO, close during fetch |
| Failed distributed-lock acquisition leaked its connection | Close connection/file resources on acquisition and release errors | Database disconnect releases resource and local lock |
| Quarantined operations produced no recovery alert | Persist an alert until reconciliation clears recovery-required jobs | Alert opens and resolves without sending external messages |

Two older feature branches contained historical commits that were not ancestors of main, although their operational features had already been incorporated by subsequent changes. Their source differences were reviewed, and their history is merged while retaining current fixes and all branches.

## Documentation and presentation

The README now supplies the project description, capability overview, three-step enrollment, policy approval semantics, current recovery workflow, upgrade instructions and explicit limits. Operations documentation resets the named administrator account rather than the obsolete legacy password setting. Architecture/recovery documentation reflects worker coordination, quarantine and provenance uncertainty. Screenshots are regenerated from the browser smoke flow with illustrative data and reserved documentation addresses.

## Validation scope

Local validation runs the full Python regression suite; the optional MySQL and real-restic cases are skipped when their services/tools are absent. Desktop/mobile browser smoke checks cover enrollment, installer download, repository settings, stale server/plan responses, exact-plan GO decisions, patch approvals and saved policy controls. CI additionally runs the MySQL suite, Ubuntu/Debian SSH integration, Docker/Caddy HTTPS startup and an encrypted SQLite restic restore drill.

Acceptance testing is still required for real Raspberry Pi/systemd devices, live identity providers and SMTP/custom ACME servers, kernel eBPF attachment, bootable filesystem rollback and off-host provider connectivity. MySQL compatibility tests do not validate a complete MySQL dump/import recovery drill. Target reboot and rollback regression tests use isolated fixtures; they do not reboot real machines.

## Upgrade consequences

- Update the central app/workers, then finish/verify installation on each idle target to install the new bridge/collector/release runner. Regenerate unexecuted release plans after helper updates; never redeploy helpers during an active upgrade.
- Existing queued patches cannot inherit an enabled recovery policy without new approval.
- Reconcile orphaned jobs only after inspecting target state and pending reboot timers through a trusted console.
- Re-review changed provenance identities; uncertainty must not inherit an old known-good approval automatically.
- Preserve all existing branches; this update is committed directly to `main`.
