# Server workspaces

Choose **Servers**, then click a server name or **Open server**. The selected server stays visible above every tab. The server switcher preserves the current tab; **All servers** returns to the list. Browser back, reload and links such as `/#servers/<server-id>/patching` preserve the selected server and tab. A removed or unknown server produces a not-found page rather than silently selecting another server.

| Tab | Contents | Access |
|---|---|---|
| Overview | Identity, SSH fingerprint, OS report, inventory and collector timestamps, package counts, patch status and integrity findings | All roles |
| Connection | Direct SSH endpoint or Google Cloud IAP project/zone/instance, stale-edit protection and read-only saved connection test; see [GCP setup](GCP.md) | Admin |
| Packages | Installed and pending packages, holds, priorities, AI importance, installation forecasts and reviewed patch selection | All roles; operators/admins can patch |
| Patching timeline | Monthly scheduled start windows and run states, assigned schedules, maintenance/recovery policy, pending update forecasts and operation output | All roles; recovery actions require admin |
| Investigations | This server's process investigations, AI verdicts, evidence and approval state | All roles; trust changes/retries require admin |
| AI activity | Linked triage, update-scoring and release-configuration runs, call details and estimated API costs | Admin |
| History | Package changes and reasons; inventory revisions and process observations for admins | All roles for package history |
| Repositories | Repository files, signing keys and access configuration | Admin |
| Maintenance | Installation/repair tools, repository refresh, release plans, SBOM download, recovery policy, UTC maintenance windows and stored raw snapshots | Admin |

Automatic refresh applies to the fleet overview, server list and server overview. Other server tabs refresh on navigation or with the toolbar Refresh button, preserving selections and unsaved forms while you work.

Fleet-level views remain available. The existing **Manage** dialog also remains accessible for installation and repair actions.

## Scope and history

Investigations, jobs, package history, AI activity and calendar run states are filtered by server on the backend before pagination. A busy server cannot crowd another server's records out of its page. Calendar windows include only schedules assigned to the server, plus its historical scheduled runs. Operation history includes on-demand work. Opening a page does not contact or modify the target.

New AI runs save durable server associations, including all members of a shared update-scoring batch. These associations survive replacement or retry of individual package scores and expire with retained AI logs. Older runs are linked using their existing host ID or surviving package-score association. Unlinked historical runs remain in the fleet AI logs.

A **Shared batch** AI run reports the whole batch's estimated API cost; it is not a per-server charge. The same shared batch can appear on multiple server pages, so do not add those copies together as separate spend. Existing unavailable/partial cost labels still apply.

## Freshness, forecasts and permissions

Overview and snapshot data reflect the latest stored collection. Last contact, inventory collection, telemetry collection and integrity sweep have separate timestamps. No hardware utilization metrics are inferred from these records.

Timeline events are allowed start windows, not completion promises. Installation forecasts still depend on schedules, maintenance restrictions, holds, repository verification, target health and approvals. Schedule times use the schedule's timezone; timeline timestamps use the browser's timezone; host maintenance windows use UTC.

Patch installation still requires review of exact versions and recovery policy. AI verdicts do not approve process behavior automatically. Raw snapshots, repository credentials/configuration, AI logs and inventory/observation history keep administrator-only access, enforced by the API as well as the interface.
