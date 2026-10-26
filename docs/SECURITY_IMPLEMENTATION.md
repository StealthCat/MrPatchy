# Security implementation checkpoint

This branch is an incomplete first stage of the proposed endpoint protection expansion. It must not be represented as complete malware protection or automated incident response.

Implemented: administrator-only, on-demand and interval-scheduled read-only ClamAV scan jobs; a server Security tab with scan policy, coverage, paginated scan history, incidents and response plans. Scan receipts are stored in dedicated tables and are never overwritten by a later scan. Repeated path/hash detections on the same host update an incident while retaining each scan receipt. Historical reports from the first draft remain readable as a legacy latest report; new scans use durable history.

Administrators can request an AI response plan for an incident. Generation uses the saved AI settings, caps requests at ten per hour across the fleet, validates allowed advisory action types and evidence IDs, and records the model run and usage through existing AI activity logging. Evidence changes during generation reject the result. Scanner failures do not require a working AI provider.

Plans are advisory manual tasks. Approval never executes shell commands, quarantines files, isolates hosts, or marks an incident remediated. A plan must match the current incident evidence and be reviewed within 24 hours. Approved reviews expire after one hour. Repeat detections supersede prior approvals. The UI identifies expired approvals. No user-facing claim of automated remediation is made.

New tables are included in the offline SQLite/MySQL migration metadata. Security records currently have no automatic deletion policy; size storage accordingly. Engine installation, signature freshness enforcement, external evidence storage remain unfinished. Automatic proposal generation is available as described below.

Prerequisites: install ClamAV and current signatures on the managed target and redeploy the Mr Patchy collector/bridge using the existing reviewed installation workflow. No scanner installation or signature updates are performed automatically. Engine version is captured with the scan report.

Limits: 16 explicit root directories, 2,000 examined files, 32 MiB per file, four-minute overall work budget and 30-second per-file scanner timeout. Symlinks are not followed during traversal. Virtual filesystem directories and the reserved quarantine directory are excluded. Exclusions and failures are reported as incomplete coverage. Scanning uses an opened descriptor and checks metadata before accepting the result. A compromised root/kernel remains outside this trust boundary. Reports never claim the server is clean.

Still required before the requested system is complete:

- Configurable retention and external immutable evidence storage; broader behavioral and threat-intelligence correlation.
- Event-triggered scans, YARA integration, authenticated rule distribution, trusted vendor package verification and approved custom baselines.
- Runtime detection integration, persistence inventory, fleet correlation and agent tamper monitoring.
- Follow-up AI evidence collection tools; approved typed execution of response plans. Current AI plans use scanner evidence only.
- Execution-time identity revalidation, race-resistant quarantine, restore workflows, external host isolation and recovery-path testing.
- Typed remediation executors, trusted restoration, credential rotation tasks, rebuild escalation and post-action verification.
- Coverage dashboards, incident/plan/quarantine views, policy settings, offline delivery and independently retained audit evidence.
- Browser coverage and real scanner/OS integration tests, performance tests and failure-injection response drills.

No destructive security response is enabled in this checkpoint.


## Incident review and fleet hash correlation

Server Security cards now provide **Review incident**, **Incident timeline**, and **Find hash across fleet**. Administrators can acknowledge, reopen, mark a false positive, or record manual resolution with a reason of 10–4,000 characters. Resolution records the administrator's assessment; it does not certify a clean host or execute remediation. A new detection reopens the incident, including a previously resolved or false-positive record. False-positive review is not an allowlist.

Reviews use the displayed update timestamp to reject stale decisions and share the host operation lock with scan workers. Any status change supersedes draft and approved plans. Scans and their evidence remain unchanged. Timelines record new detections, previous state, plan generation, plan approval, and manual reviews with actors and timestamps. Timeline capture starts with this version; earlier events are not fabricated.

Hash correlation searches exact SHA-256 values among stored incident detections across the fleet, with pagination and administrator-only access. It does not initiate a fleet scan, establish that matching files are malware, or prove absence on hosts with no stored detection. Scan and timeline models are included automatically in database migration metadata.


## Optional automatic AI plans

Each server's scan policy can enable automatic AI response proposals. It is off by default and sends scanner evidence through the existing configured AI integration. The leader checks for unplanned open incidents, with at most ten queued plan requests per hour across the fleet (including manual requests) and one outstanding plan per host. Each incident/scan revision receives at most one automatic attempt; failures require manual retry or a later detection. Disabling the option prevents queued automatic jobs from making a new provider call. A changed or reviewed incident is checked again at execution. No plan is automatically approved or executed, and detection continues without AI.
