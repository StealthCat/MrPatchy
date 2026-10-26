# AI diagnostics, update importance and package history

## Diagnose stalled triage

1. Open **Investigations** or **AI run logs** as an administrator. The status card distinguishes disabled AI, missing configuration, a missing scheduler heartbeat, an active investigation, an exhausted hourly allowance, retry backoff and an empty queue. A heartbeat older than 90 seconds is considered stale; it is a scheduler heartbeat, not proof that OpenAI is reachable.
2. Open **Settings → AI & models**. **Save API key** works without a valid model. Refresh the model dropdown, or choose **Enter a model ID manually** if discovery fails. Use **Save AI settings** to persist without calling OpenAI, or **Save and test selected model** to save first and test the selected model. This makes a billable structured-output request without target evidence. A successful test verifies that request, not the outcome of subsequent investigations.
3. In **AI run logs**, inspect a failed run. Logs retain purpose, model, target ID for triage, timestamps, API-call count and stages such as request, HTTP response, SSH evidence collection and failure. Recognized provider errors explain credentials, model/schema access, billing/quota, throttling or network/TLS issues. A validated provider request ID is retained when available.
4. Correct the reported issue. **Investigations → Retry** makes an unapproved failed/pending observation eligible again. It does not enable AI, approve the behavior or bypass the hourly allowance. Automatic retries otherwise wait one hour. Concurrent triage and manual retry coordinate through the same distributed lock.
5. If the worker is missing or diagnostics cannot be written, inspect the container logs:

   ```bash
   docker compose ps
   docker compose logs --since=30m --tail=300 app worker
   ```

The Compose app disables its embedded scheduler and runs a separate worker. Check that the worker is running with the same database and secret volume. A scheduler/container failure cannot reliably report to an unavailable database; console logs remain the fallback. Worker tasks now consume background-future failures and record a safe diagnostic instead of dropping them silently. Interrupted triage/scoring runs are reconciled when a worker reacquires their execution lock.

AI logs contain controlled diagnostics, not API keys, raw prompts, raw provider bodies, process evidence or arbitrary exception text. Unexpected failures retain the exception class and a generic health-check instruction. Full process evidence remains in its existing authenticated investigation view. These logs cover process triage, update scoring, saved-settings connection tests and background AI failures; distribution-release planning retains its existing Activity/plan diagnostics.

## Recover from a model error

A `model_not_found` error is a provider test/inference failure, not a database-save failure. The AI page displays **Saved model**, a separate save result, and a separate test result. A failed test keeps the new model saved so you can select another without being blocked by the previous model. Save and test sends the exact saved model and an opaque key revision; if another administrator changes either before the test starts, it refuses the stale test without making a provider request. Provider failures include the tested model, log run ID in the API response, and a sanitized request ID when available. The one-minute connection-test limit remains in effect; saving a replacement does not bypass it.

The model list reports IDs accessible to the saved API key; it does not certify Responses API or JSON-schema compatibility. If a chosen model continues to fail, inspect the **fresh** test result for its exact ID and request ID, check the API project's access, and select a compatible model. An error from discovery leaves manual entry available. The app cannot grant API model access or make an unsupported model compatible. Do not send API keys in troubleshooting messages.

## Explained update scores

Enable automatic AI and **AI update importance scores** in Settings. Scoring uses the saved model/key, with a separate hourly batch allowance. Defaults are 20 process investigations/hour and 20 score batches/hour. Each score batch contains at most five pending updates; failures consume allowance, and a failed assessment retries no sooner than one hour. Up to 100 updates/hour is a throughput ceiling at the default setting, not a guaranteed rate. Process triage and score batches share one AI worker slot; a slow provider or follow-up SSH check can delay both.

The score request includes package name, installed version(s), candidate version, package-manager family, OS identification/version, held/package state and the current priority signal with its source. It excludes host addresses, repository credentials/source files and process evidence. The request treats all metadata as untrusted data, asks for structured output and sets `store: false`; that flag does not override provider organization retention policies. Scoring is billable API usage separate from a ChatGPT subscription. Disable its checkbox to stop new scoring requests; saved scores remain visible. Global AI disable stops both automatic workflows.

| Score | Requested interpretation |
|---|---|
| 0–19 | Optional |
| 20–39 | Routine |
| 40–59 | Meaningful maintenance |
| 60–79 | High priority |
| 80–100 | Urgent security or service continuity |

These are advisory AI estimates, not CVSS ratings or verified vulnerability findings. Current input does not include authenticated candidate changelogs, verified CVE applicability or service exposure. Persisted confidence is therefore **low**, even if a model claims greater certainty. The UI shows the explanation, limitations, model and assessment time. Scores never change priority, approve behavior or authorize installation. Use the separate priority controls and reviewed schedules for policy decisions.

Each result binds to an identity derived from the server and exact evidence. Changed installed versions, candidate versions, hold/state, priority or OS metadata invalidate the visible assessment. Responses must contain each requested identity exactly once, integer scores from 0 through 100 and valid nonempty explanations. Malformed, duplicate, incomplete or superseded results are not accepted as current scores.

## Select and install updates

The Packages view provides **Select all eligible updates**, **Clear selection**, a count and the normal reviewed installation confirmation. Selection follows the current server/search/update filter and is bounded to 500 packages per job. Held/version-locked, broken and already queued/running packages are excluded, including queued work waiting on a canary or recovery. Viewers cannot select or queue packages; operators and administrators can. Candidate/version and recovery-policy checks still run on submission and execution.

The release-upgrade package preview remains part of its atomic reviewed release plan; its GO approval cannot be replaced by selecting individual upgrade-plan packages.

## Expected installation times

Every pending candidate has an installation status and explanation. Where calculable, the timestamp is the **earliest estimated start**, not a promised finish time or the priority deadline. Displayed dates use the browser timezone; schedule recurrence uses the schedule's configured timezone and server maintenance windows remain UTC.

- **Scheduled:** earliest eligible regular/urgent start, intersected with the server maintenance window unless that urgency's approved bypass applies. Forecasts look ahead 62 days and respect schedule revision, prior runs and recovery-policy compatibility.
- **Queued:** earliest allowed worker start for the exact candidate. Repository revalidation and worker availability still apply.
- **In progress:** the job is running; its completion time is unknown.
- **Waiting/Blocked:** held/broken state, unhealthy/offline target, stale repository data for a queued job, recovery or unknown dependency completion prevents a reliable timestamp. Open Timing details for the reason.
- **Not scheduled:** no approved matching schedule/eligible occurrence. Select the update for on-demand installation or configure a schedule.

Forecasts do not reserve a worker or create jobs. A changed candidate, approval, health state, repository result or schedule can change the estimate. Failed/terminal urgency batches are not presented as automatically scheduled again; review the failure and submit a new approved operation when appropriate.

## Package change ledger

**Package history** is readable by all authenticated roles. Filter by server and package name, page through events and open linked operations. Records include action, all observed before/after versions, package state, observation time, central recording time, source and job/actor when known.

The first observed inventory creates **baseline** records. Subsequent observations record additions, removals, version changes and package-state changes, including dependency changes and all RPM install-only versions. Unchanged inventories do not create duplicate events. Version changes can represent an upgrade, downgrade or rollback; the ledger does not incorrectly classify every version difference as an upgrade.

After updating an existing deployment, the next inventory collection reconstructs a baseline and changes from retained inventory revisions before recording current changes. Previously pruned snapshots cannot be recovered. Historical snapshots have no invented job/actor association. External/manual changes are attributed only to observation, with the actual install time and actor unknown.

When a patch, rollout or release-upgrade job yields a confirmed post-operation inventory, the ledger links observed changes to that operation and its requesting user or schedule. This association means **observed during the operation**, not proof that it caused every change. Confirmed inventory is committed before later health validation, so a failed health check does not erase installed-package evidence. If the package command or SSH connection fails before a new inventory is obtained, the next successful poll records changes with unknown attribution. A failed job is never itself proof that no packages changed.

AI run/event logs and raw inventory/observation snapshots follow configurable `history_days` (default 30 days). Structured package events and saved update assessments are retained independently; there is currently no automatic pruning for those tables. Include them in normal database backups and monitor database growth. The ledger is an application audit trail, not tamper-proof storage or remote attestation: a privileged database administrator or compromised target can falsify evidence.

## Deployment and validation

Back up the database/volumes, then rebuild **both app and worker** from the same revision. Startup creates the new tables in SQLite or MySQL. No target bootstrap or SSH-key change is needed for these central/UI features; history starts/backfills on subsequent successful inventory collection.

Regression coverage includes safe provider-error logging, worker failures, retry quotas, role restrictions, personal password changes, strict score validation and candidate races, RPM multi-version history, retained-snapshot backfill, post-install health failure, and schedule/window forecasts. Browser checks cover the new pages at desktop/mobile widths, update selection, diagnostic stages, package history, user creation and sign-in after a personal password change. Live OpenAI billing/model access and production target behavior require validation after deployment.
