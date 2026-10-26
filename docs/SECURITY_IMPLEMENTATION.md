# Security implementation checkpoint

This branch is an incomplete first stage of the proposed endpoint protection expansion. It must not be represented as complete malware protection or automated incident response.

Implemented: administrator-only, on-demand and interval-scheduled read-only ClamAV scan jobs; a server Security tab with scan policy, coverage, paginated scan history, incidents and response plans. Scan receipts are stored in dedicated tables and are never overwritten by a later scan. Repeated path/hash detections on the same host update an incident while retaining each scan receipt. Historical reports from the first draft remain readable as a legacy latest report; new scans use durable history.

Administrators can request an AI response plan for an incident. Generation uses the saved AI settings, caps requests at ten per hour across the fleet, validates allowed advisory action types and evidence IDs, and records the model run and usage through existing AI activity logging. Evidence changes during generation reject the result. Scanner failures do not require a working AI provider.

Plans are advisory manual tasks. Approval never executes shell commands, quarantines files, isolates hosts, or marks an incident remediated. A plan must match the current incident evidence and be reviewed within 24 hours. Approved reviews expire after one hour. Repeat detections supersede prior approvals. The UI identifies expired approvals. No user-facing claim of automated remediation is made.

New tables are included in the offline SQLite/MySQL migration metadata. Security records currently have no automatic deletion policy; size storage accordingly. Engine installation, signature freshness enforcement, external evidence storage and automatic AI investigation remain unfinished.

Prerequisites: install ClamAV and current signatures on the managed target and redeploy the Mr Patchy collector/bridge using the existing reviewed installation workflow. No scanner installation or signature updates are performed automatically. Engine version is captured with the scan report.

Limits: 16 explicit root directories, 2,000 examined files, 32 MiB per file, four-minute overall work budget and 30-second per-file scanner timeout. Symlinks are not followed during traversal. Virtual filesystem directories and the reserved quarantine directory are excluded. Exclusions and failures are reported as incomplete coverage. Scanning uses an opened descriptor and checks metadata before accepting the result. A compromised root/kernel remains outside this trust boundary. Reports never claim the server is clean.

Still required before the requested system is complete:

- Configurable retention and external immutable evidence storage; incident lifecycle and fleet correlation workflows.
- Event-triggered scans, YARA integration, authenticated rule distribution, trusted vendor package verification and approved custom baselines.
- Runtime detection integration, persistence inventory, fleet correlation and agent tamper monitoring.
- Follow-up AI evidence collection tools; approved typed execution of response plans. Current AI plans use scanner evidence only.
- Execution-time identity revalidation, race-resistant quarantine, restore workflows, external host isolation and recovery-path testing.
- Typed remediation executors, trusted restoration, credential rotation tasks, rebuild escalation and post-action verification.
- Coverage dashboards, incident/plan/quarantine views, policy settings, offline delivery and independently retained audit evidence.
- Browser coverage and real scanner/OS integration tests, performance tests and failure-injection response drills.

No destructive security response is enabled in this checkpoint.
