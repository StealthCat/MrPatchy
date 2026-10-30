# Mr Patchy's glass workbench

The interface pairs a smoky blue/teal glass surface with Mr Patchy: a scruffy, slightly wild-eyed cartoon raccoon in patched denim overalls. Mint marks actions and healthy states, amber marks attention, and coral marks errors or critical priorities. Status labels remain visible alongside color.

## Structure

- `app/static/ui.js`: shared presentation-only icons, mascot treatments, page introductions, empty/loading states and enrollment progress. It makes no API calls and owns no authorization or fleet state.
- `app/static/style.css`: design tokens, base controls, shell, component styles, calendar, responsive layouts and accessibility overrides. Adjust tokens in `:root` before adding one-off colors or dimensions.
- `app/static/index.html`: accessible page landmarks, local assets, the sign-in layout, navigation, dialogs and notices.
- `app/static/fleet.js`: AI run logs, package history and Users views, plus shared importance-score, expected-installation and worker-status components. All untrusted explanations and diagnostics are escaped.
- `app/static/app.js` and `schedules.js`: existing API-backed interactions and page composition. Text originating from servers or API errors must continue to pass through `esc()` or `textContent`.
- `app/static/mascot/`: the two shared transparent PNG illustrations. Browser caching reuses them across sign-in, navigation, introductions, onboarding, empty states, notices and the footer. No external fonts, image services or UI scripts are required at runtime.

Shared components accept trusted markup for actions and headings. Callers must escape variable text before composing markup. Mascot variants are selected from fixed local filenames. Decorative artwork has empty alt text; the sign-in illustration introduces the character with descriptive alt text.

## Layout and interaction

Desktop navigation sits in a floating glass sidebar, grouped into fleet and operational tasks. Narrow layouts use a horizontally scrollable navigation strip, keeping every authorized view reachable. Dense package/repository tables and calendars scroll within their own containers. Main workflows have consistent introductions, toolbars, cards and explicit action buttons.

The overview adds shortcuts to packages, investigations and patch schedules. Enrollment shows the three steps without changing the preparation or approval flow. View failures show an escaped diagnostic and a retry action. Route changes reset the page scroll position; background refreshes do not. The keyboard skip link focuses the current heading without changing the route, or the username input on sign-in.

Glass effects use a legible dark fallback, and only enhance surfaces when backdrop filtering is supported. Focus indicators, text status labels, reduced-motion and reduced-transparency preferences, and forced-color borders are included. Critical operational confirmations, role checks, MFA, API diagnostics and patch approvals retain their existing behavior.

## Validation and screenshots

Run `npm run test:ui` against the disposable test database. The suite exercises real local login, role restrictions, enrollment, package approval, schedules, settings, TLS, operations and release-plan review. Fleet checks cover select-all/clear with held/broken/queued exclusions, score explanations, expected start states, run-log stages, history, real user creation and personal password changes. Additional design checks traverse every main page at 320, 768 and 1440 pixels, check horizontal overflow, local image loading, keyboard skip behavior, reduced motion, escaped loading errors and retry recovery.

To refresh documentation images:

```bash
SCREENSHOT_DIR=/tmp/mrpatchy-shots npm run test:ui
cp /tmp/mrpatchy-shots/*.jpg docs/screenshots/
```

Screenshots are captured directly by the browser as JPEGs after local images decode. Fixture addresses and counts are illustrative; no production host or AI account is contacted. Inspect desktop, mobile and dialog screenshots before publishing. Browser assertions do not constitute a complete WCAG audit.

## Mascot provenance

The illustrations were created for this project with the built-in image-generation tool. The working pose used the welcome pose as its visual identity reference. Original transparent outputs are committed as project assets; there is no runtime image-generation dependency. The exact prompts are retained in `app/static/mascot/PROMPTS.md`.


## Planned full-application UI rework

The next full UI rework is tracked in
[the implementation roadmap](SECURITY_IMPLEMENTATION.md#planned-complete-ui-rework-with-glass-styling-and-extensive-mascot-use).
The existing theme and two mascot illustrations are its foundation; this guide's
current-state descriptions do not mean that the new rework has been implemented.

Retain the current color scheme, status semantics and established Mr Patchy
character. Use the mascot extensively across navigation, introductions, summaries,
onboarding, help and application states, creating consistent additional artwork
where useful. Use as many graphics and graphic details as needed for the desired
polished glass-like appearance, while keeping text, controls and evidence clear.

Plan the navigation before migrating screens. Use separate pages for major tasks,
contextual tabs for related views and grouped menus for secondary actions; split
crowded workspaces and long dialogs into focused views. Preserve deep links,
browser navigation and the user's place during refresh. Readability, usability and
uncluttered navigation are acceptance criteria alongside the visual finish.

Implement a shared system of glass surfaces, typography, spacing, icons, forms,
tables and mascot-supported loading/empty/error/success states. Keep high-contrast
reading surfaces, keyboard/screen-reader behavior, responsive layouts and reduced
motion/transparency fallbacks. Use real data in charts and show unknown states
honestly. Preserve authorization, escaping, audit and operational approval rules.

Track the finite screen inventory and migration progress in the roadmap. Refresh
actual desktop/tablet/mobile screenshots and verify critical workflows through the
new pages, tabs and menus before declaring the full rework complete. Finished UI
work remains subject to the scheduled development completion gate.


## Implemented server workbench navigation (v0.6.0)

The server workspace is the first migrated navigation surface, not a completed
application redesign. The compact header retains the local mascot and explicit
lifecycle controls. Navigation now precedes AI policy content. A shared
`PatchyUI.sectionNavigation` component renders ordinary route links and a native
`details` disclosure; it owns no authorization or API calls. The server caller
supplies the already-filtered role/lifecycle destinations.

| Navigation | Destinations |
|---|---|
| Primary | Overview, Packages, Security, Settings |
| More sections → Updates & history | Patching timeline, History, Repositories |
| More sections → Investigations & evidence | Investigations, AI activity, File integrity |
| More sections → Server administration | Connection, Agent health, Maintenance |

Settings and its deletion controls remain directly discoverable. Unauthorized or
inactive destinations are omitted using the existing route rules; direct links
still enforce the same role checks. A current secondary page is named in the
closed disclosure and breadcrumb. Link URLs remain `#servers/{id}/{tab}`, so
bookmarks and Back/Forward continue working. Switching servers retains the current
section where that server's lifecycle permits it.

Desktop uses a contained glass panel with three readable groups; narrow screens
expand the groups in the page flow. Native Enter/Space/Tab behavior is retained;
Escape closes the disclosure and restores focus to its summary. Outside clicks
and route links close it. The component has solid and forced-color fallbacks.
The existing local mascot portrait anchors the panel without obscuring controls.

Package search and Updates only filters are held in memory, scoped to server ID
and fleet/server context, and restored when returning or refreshing the view.
They clear on sign-out/reload and never restore patch-selection checkboxes.
This is not yet universal filter/pagination/scroll persistence. Other workspaces
remain on their existing components until their migration below.

## Screen migration inventory

This is the finite acceptance inventory for the requested full rework. New planned
workspaces join their named family when their underlying features are delivered.
Existing glass CSS does not count as migrated content. Each remaining row needs
shared components, readable states, role/workflow checks and inspected renders.

| Milestone / screen family | Current delivery | Remaining acceptance |
|---|---|---|
| Route map and shared navigation | Server route map and grouped disclosure, v0.6.0 | Apply shared navigation/context rules across families |
| Shell, authentication and account | Existing sidebar, login, MFA/account dialogs | Global navigation, shell/typography/state-system migration; keyboard/mobile review |
| Fleet Overview, Servers and enrollment | Fleet Summary/Server attention/Monitoring pages v0.15.0; server directory v0.7.0; verified landing v0.5.0 | Onboarding migration; complete loading/error-state system and whole-family acceptance |
| Server Overview and navigation | Route groups v0.6.0; Summary/System/Patching pages and stored-data cards v0.7.0 | Lifecycle/AI control content migration and whole-family acceptance |
| Packages, repositories, patching and schedules | Existing pages; scoped filters v0.6.0 | Shared tables/forms, history/calendar detail pages, approvals and context retention |
| Investigations and AI activity | Fleet/server run Summary/Cost/Timeline routes and scoped list context v0.10.0 | Investigation evidence/details and wider AI control/loading/pause state migration |
| Security, integrity, startup and response | Startup Files/Coverage pages (v0.11.0); existing scanner/baseline/vendor/file/process workflows | Migrate other crowded workspaces, review/recovery/export states; comprehensive startup discovery/provenance/classification remains planned |
| Activity, audit and inventory/package history | Server snapshots v0.16.0; Activity/audit lists/details v0.17.0; existing package history | Shared filter/long-output/control components and whole-family acceptance |
| Settings, users and operations | Existing settings pages/forms/dialogs | Consistent grouped administration, accessible forms and destructive confirmations |
| Deployment, worker and GCP health | Worker registration/liveness, cooperative controls v0.9.0 and expected-worker inventory v0.12.0 | Full expected-component inventory, readiness, controller/endpoint/GCP health and cross-deployment acceptance remain planned |
| Whole-application acceptance | Not complete | All rows migrated; cross-role workflows, state/asset/readability consistency and actual mobile/tablet/desktop review |

No additional mascot artwork is required for this bounded route milestone; it
reuses the established illustrations. New poses/graphics remain part of the later
shared-visual-system/content work. Do not mark the full rework complete from this
navigation component alone.

Reviewed fixture renders for this milestone: [desktop](screenshots/workbench-navigation-desktop.jpg), [tablet](screenshots/workbench-navigation-tablet.jpg), [mobile](screenshots/workbench-navigation-mobile.jpg). These show the open section chooser; closed-state navigation, roles, Back and server switching are also exercised by the browser suite.


## Server directory and Overview pages (v0.7.0)

The Servers page now presents 24 cards per page, with local search across name,
address, architecture and package manager plus enabled/disabled filtering. Counts
and status describe stored observations, not independent health certification.
Each card keeps Open server, Manage/Inspect and authorized lifecycle actions; no
new mutation endpoint or bulk action is introduced. Search/state/page position are
held in account-session memory, clamped when results shrink, and cleared on
sign-out/reload. Background refresh does not interrupt focus inside these filters.
Deleted server history remains its own existing administrator page.

Overview is now a focused set of route pages:

| Page | Deep link | Content |
|---|---|---|
| Summary | `#servers/{id}/overview` | Stored metrics, identity summary, integrity findings and contextual mascot guidance |
| System & collector | `#servers/{id}/overview/system` | Full identity, pinned fingerprint, OS report and independent collection timestamps |
| Patching status | `#servers/{id}/overview/patching` | Queued/running/recovery counts, repository diagnostics, last submitted patch and timeline link |

Existing Overview links open Summary. Back/Forward and reload retain deep links;
server switching retains System/Patching where applicable. Breadcrumb/title and
active local navigation identify the page. Unknown detail routes fall back to
Summary. The existing administrator AI pause panel remains prominently visible;
its control-content migration is still outstanding. Missing/stale/future timestamps
never imply fresh data, and last submission is not presented as verified patching.

The directory and Overview reuse the established palette, typography, mascot and
shared surface tokens. Narrow action groups wrap as whole controls, title/status
layout avoids pinching names, and dense card content has a solid reading surface.
This milestone does not migrate the fleet dashboard, enrollment content, security
workspaces or future deployment-health screens. Their finite inventory remains above.

Reviewed fixture renders: [directory desktop](screenshots/server-directory-v070-desktop.jpg), [directory phone](screenshots/server-directory-v070-mobile.jpg), [Overview Summary](screenshots/server-overview-v070-summary.jpg), [System/collector tablet](screenshots/server-overview-v070-system.jpg), [Patching status phone](screenshots/server-overview-v070-patching.jpg). The browser suite also exercises empty results/fleet, malicious text, role restrictions, stale/future observations and recovery warnings.


## Worker registrations (v0.8.0)

Activity now has route-linked Operations & audit / Workers pages for administrators.
The Workers page keeps the shared glass navigation, local mascot introduction,
readable coverage panel, bounded paginated table and explained liveness states.
Readiness is always explicitly not assessed. The table scrolls locally on phones,
with a visible hint; no operational control is introduced. Deep links, Back/reload,
role restrictions, empty state and untrusted identity escaping are browser tested.
This is a worker-only self-report foundation, not migration/completion of the
planned all-component deployment-health dashboard. Existing operations/recovery
controls stay on their original page, and no Docker-daemon access is added.

Reviewed fixture renders: [desktop](screenshots/worker-registrations-v080-desktop.jpg), [tablet](screenshots/worker-registrations-v080-tablet.jpg), [phone](screenshots/worker-registrations-v080-mobile.jpg). Readiness/coverage text stays visible above the table; horizontal scrolling exposes remaining columns on narrow screens.


## Worker admission controls (v0.9.0)

The registered-worker page now keeps Drain/Resume controls beside each identity,
visible before horizontal table scrolling. Reasons and exact boot information are
reviewed in a responsive confirmation, and requested/observed revisions distinguish
an accepted request from runtime acknowledgement. Running/queued polls and assigned
notification work explain why a boot is still draining. Stale/unknown/stopped or
incompatible runtimes offer no control. Conflicts retain the form and actionable
error; roles, native form validation and double-submit guards remain enforced.
Glass surfaces, mint/amber state treatments and existing raccoon artwork are reused.

This migrates the new operational controls only; the all-component dashboard and
whole-application acceptance remain planned. Reviewed fixture renders:
[desktop](screenshots/worker-controls-v090-desktop.jpg),
[tablet](screenshots/worker-controls-v090-tablet.jpg),
[phone](screenshots/worker-controls-v090-mobile.jpg),
[desktop review](screenshots/worker-drain-review-v090-desktop.jpg),
[phone review](screenshots/worker-drain-review-v090-mobile.jpg).

The v0.9 reconciliation rechecks these renders and sends exact worker identity in
a validated request body so dot-segment IDs remain controllable. Browser coverage
now includes `.`/`..` and distinct case IDs, preserving the same confirmation,
requested/observed states and glass/mascot surfaces. No visual asset or layout
change is required for this transport correction.


## AI run pages (v0.10.0)

Fleet and server AI activity now open Summary, Cost and Timeline pages. Shared
responsive navigation and facts replace the long inspection modal while retaining
mascot artwork, glass surfaces, mint state accents and readable diagnostics.
Purpose/page context survives navigation/refresh per scope; reload/sign-out clears
it. Server detail requests verify membership. Costs remain saved estimates with
partial/unavailable and shared-batch caveats, and viewing history performs no AI
retry, approval or target action. Back/reload, roles, failure/missing history and
stale response races are browser tested. This does not complete the full AI family.

Reviewed renders: [summary desktop](screenshots/ai-run-v0100-desktop.jpg),
[summary tablet](screenshots/ai-run-v0100-tablet.jpg),
[summary phone](screenshots/ai-run-v0100-mobile.jpg),
[cost](screenshots/ai-run-v0100-cost.jpg),
[timeline](screenshots/ai-run-v0100-timeline.jpg).


## Startup review pages (v0.11.0)

Server More sections → Startup files opens route-linked Files and Coverage pages.
The existing File integrity Browse startup files control opens the same workspace.
Files uses readable metadata cards, search and pagination; Coverage separates the
receipt scope, missing roots, skipped entries, mechanism counts and explicit gaps.
Both reuse the glass surfaces, mint navigation and established raccoon artwork.
The unrelated AI policy panel remains on other server pages; the new read-only
workspace does not add AI or target controls. Administrators can review retained
inactive/deleted history; other roles retain the existing access boundary.

Search, page and receipt revision survive navigation/refresh independently per
server, clearing on reload/sign-out. Back/Forward and deep links retain the selected
page. A changed receipt rejects stale pagination; Refresh latest inventory explicitly
opens the latest snapshot without approving a baseline. Empty/error states and
untrusted metadata are tested. This is a stored-metadata screen migration only,
not individual-job discovery, authenticated provenance or AI classification.

Reviewed renders: [Files desktop](screenshots/startup-review-v0110-desktop.jpg),
[Files tablet](screenshots/startup-review-v0110-tablet.jpg),
[Files phone](screenshots/startup-review-v0110-mobile.jpg),
[Coverage desktop](screenshots/startup-review-v0110-coverage-desktop.jpg),
[Coverage phone](screenshots/startup-review-v0110-coverage-mobile.jpg).


## Expected worker inventory (v0.12.0)

Activity → Workers now separates controller-configured expected identities from
paginated registration history. Responsive cards show missing registrations and
the same stopped/stale/future-clock/version/drain explanations used by the runtime
table. Configuration errors and absent configuration remain visible; neither is
presented as a complete or healthy deployment. Readiness remains not assessed.
The cards reuse glass borders, mint/amber states and the established mascot;
read-only viewing adds no control or target action. Existing boot/revision-checked
drain/resume stays solely beside eligible registered runtimes.

Reviewed renders: [desktop](screenshots/expected-workers-v0120-desktop.jpg),
[tablet](screenshots/expected-workers-v0120-tablet.jpg),
[phone](screenshots/expected-workers-v0120-mobile.jpg). This completes only the
expected-worker inventory increment, not controller/agent/GCP health or full
responsive/accessibility acceptance of the application.


## Controller/key startup check (v0.13.0)

Registered workers now show verified-at-startup, not enabled or not reported beside
their identity, visible before horizontal scrolling on phones. The explanation
explicitly excludes shared-file and target access verification. Readiness remains
not assessed and stale/version/drain interpretations are unchanged. The same
readable glass surfaces, state colors and established mascot are retained; no
new operational action or confirmation is added.

Reviewed renders: [desktop](screenshots/worker-preflight-v0130-desktop.jpg),
[tablet](screenshots/worker-preflight-v0130-tablet.jpg),
[phone](screenshots/worker-preflight-v0130-mobile.jpg). Wider component health,
preflight diagnostics and the remaining UI inventory remain planned.


## Schema structure / receipt protocol (v0.14.0)

Workers separates schema-structure/receipt-protocol startup results from key checks
and readiness. Concise per-identity states remain visible before phone scrolling;
a shared coverage explanation defines required tables/columns/primary keys and
unassessed types/other constraints. Unknown old reports never become verified.
Existing glass surfaces, mint/amber states, typography, mascot and drain safeguards
are preserved. Browser fixtures derive current versions from health metadata,
keeping matched/control-enabled examples honest across source upgrades.

Reviewed renders: [desktop](screenshots/worker-schema-v0140-desktop.jpg),
[tablet](screenshots/worker-schema-v0140-tablet.jpg),
[phone](screenshots/worker-schema-v0140-mobile.jpg). This is a bounded preflight
UI increment, not full schema compatibility, component health or completion of
the application-wide redesign.


## Fleet Summary, Server attention and Monitoring (v0.15.0)

The fleet dashboard is now three focused route pages using shared navigation,
mascot introductions and glass surfaces. Summary shows observation counts and a
compact review queue, a contextual mascot guide and three server preview cards.
Server attention offers read-only, twelve-card pagination with search and separate
expired/unknown/disabled/recent groups. Monitoring separates configured timing from
actual collector success and links to existing server/outcome/coverage workspaces.

The two-minute UI freshness interpretation rejects future and missing timestamps
and excludes disabled management from recent-contact counts. It does not certify
readiness or protection, change the existing online API metric, approve trust or
call targets/providers. Snapshot differences and collection gaps are explicit.

Route links retain Back/Forward and reload. Filters/page survive navigation and
refresh, clear on reload/sign-out, and clamp when results shrink. Automatic refresh
does not interrupt focused review controls. Role-specific links and enrollment
controls retain their existing restrictions. Reading panels are solid, cards wrap
long diagnostics, focus/forced-color/reduced-transparency rules are retained, and
phone layouts put whole controls in one column. Existing local artwork supplies
working/welcome poses across introductions, guidance and empty states.

Reviewed renders: [Summary desktop](screenshots/fleet-summary-v0150-desktop.jpg),
[Summary tablet](screenshots/fleet-summary-v0150-tablet.jpg),
[Summary phone](screenshots/fleet-summary-v0150-mobile.jpg),
[Server attention desktop](screenshots/fleet-attention-v0150-desktop.jpg),
[Server attention phone](screenshots/fleet-attention-v0150-mobile.jpg),
[Monitoring phone](screenshots/fleet-monitoring-v0150-mobile.jpg).

This completes the bounded fleet-dashboard migration, not onboarding, the full
Overview/Servers family or the application-wide redesign. The finite inventory
and all operational/authorization acceptance requirements remain in force.


## Historical inventory/process snapshots (v0.16.0)

History now uses Package changes / Inventory revisions / Process observations route
links. Snapshot lists retain offset by server/type; detail pages have ordinary Back
to list links, identity/timestamp facts and keyboard-focusable, wrapped evidence
reading surfaces. Reload supports direct detail links; switching servers retains
the type and drops record IDs. Administrator UI boundaries remain; retained
inactive history is readable, missing records offer retry/list recovery, and stale
responses cannot replace a new view. Existing mascot introductions and portraits,
glass navigation and solid reading panels are reused. No target or AI action is
introduced. Offset pages may shift under ongoing collection/retention, and raw
snapshot evidence is not a current-state or malware verdict. This is a bounded
history migration, not full long-output/accessibility/application acceptance.

Reviewed renders: [detail desktop](screenshots/snapshot-detail-v0160-desktop.jpg),
[detail tablet](screenshots/snapshot-detail-v0160-tablet.jpg),
[detail phone](screenshots/snapshot-detail-v0160-mobile.jpg),
[list tablet](screenshots/snapshot-list-v0160-tablet.jpg).


## Activity and audit review (v0.17.0)

Operations, Audit trail and Workers are separate pages. Administrator audit lists
use fifty-record pages and timestamp/ID ordering; audit entry detail has escaped,
keyboard-scrollable text. Fleet/server operations link to identity-checked details
with recorded outcome/output, leaving existing cancellation/recovery confirmations
on the lists. Pagination survives route navigation and clears on reload/sign-out;
server contexts remain independent. Missing records offer retry/back links.
Historical observations never certify target state or successful recovery.

Shared glass navigation, mascot introductions/portraits, solid reading surfaces,
responsive two-column facts and phone spacing are reused. This is a finite detail
page migration; operation controls, shared long-output/filter components and full
application accessibility/visual acceptance remain planned. Offset paging may
shift with new records or retention.

Reviewed renders: [operation desktop](screenshots/operation-detail-v0170-desktop.jpg),
[operation tablet](screenshots/operation-detail-v0170-tablet.jpg),
[operation phone](screenshots/operation-detail-v0170-mobile.jpg),
[audit desktop](screenshots/audit-entry-v0170-desktop.jpg),
[audit phone](screenshots/audit-entry-v0170-mobile.jpg).


### v1.18.0 — AI timing diagnostics

The existing administrator Run → Timeline page now labels timing stages readably
and explains overlap, queue-age and incomplete coverage. No retry or approval is
triggered by reading the timeline. Existing glass/solid reading surfaces, mascot,
role/scope restrictions and Back/reload routes remain. Actual renders inspected:
[phone](screenshots/ai-run-timing-v1180-320.jpg),
[tablet](screenshots/ai-run-timing-v1180-768.jpg),
[desktop](screenshots/ai-run-timing-v1180-1440.jpg).
The shared queue/concurrency/rate/spend controls and full AI workspace acceptance
remain planned under the faster-triage program; timing labels do not complete them.

## Planned live notification center

Implement the [live notification roadmap](SECURITY_IMPLEMENTATION.md#planned-live-in-app-notifications-and-human-attention-alerts) as part of the shared application shell. Keep a persistent Notifications icon with an accessible unread badge, a compact recent panel and a dedicated paginated/filterable notification center. Apply the existing glass/status palette and Mr Patchy artwork while keeping event text readable.

Human-attention events and significant triage findings should arrive through authenticated server push and update the badge/panel plus bounded in-app alerts without page refresh, navigation, stolen focus or lost form/dialog state. Keep durable per-user read state, severity/source/server/time and exact review links. Reading/dismissing differs from acknowledging/resolving the underlying issue. Retain urgent items in history, handle reconnect/catch-up and visible degraded state, and filter both payloads and counts to current permissions. Existing SMTP/webhook delivery remains independent.

Verify actual asynchronous updates, multi-session read synchronization, replay/deduplication/reopening, role/session boundaries, keyboard/live-region behavior and mobile/tablet/desktop renders. This remains planned until the runtime and acceptance milestones are delivered.


### v1.19.0 — Explained process retry eligibility

The existing glass Investigations cards and AI worker status now distinguish
eligible work, items needing review and paused servers. Per-item text shows the
attempt count, durable deferral/block reason and recorded eligibility. Eligibility
is not a promised start time. Reading these surfaces never calls the provider;
Retry remains an explicit administrator action with CSRF, lifecycle, hourly and
provider-delay checks. A blocked Retry returns an accessible non-disruptive status
message without approving the behavior. Text is escaped. The established palette,
shared navigation and mascot assets are retained. Reload reads authoritative state.

Browser acceptance covers attempted early Retry, text injection, reload, no
horizontal overflow and actual [phone](screenshots/ai-retry-v1190-320.jpg),
[tablet](screenshots/ai-retry-v1190-768.jpg) and
[desktop](screenshots/ai-retry-v1190-1440.jpg) renders. These screens are fixtures,
not live fleet evidence. They do not complete the queue/concurrency/spend workspace,
full UI rework or planned asynchronous notification program.


### v1.20.0 — Retained process assessment review

Fleet and server Investigations link to paginated Assessment history and individual
assessment pages. Deep links support Back/reload, scoped server identity checks and
retained list offsets; sign-out clears offsets. Current behavior approval is shown
separately from the selected saved advisory assessment. Legacy snapshots explicitly
state that original model, inputs and assessment timestamp are unavailable.

Re-triage uses the shared mascot dialog, a required reason and explicit withdrawal
of an existing approval. Stale submissions keep the dialog/reason visible and do
not queue work; double submission is guarded. Pending refreshes link to retained
prior results. Existing Retry handles failures; inactive-server history hides
mutating controls. Provider/evidence/policy details are escaped, bounded reading
surfaces, with long digests wrapping inside optional provenance details. History
is read-only for AI/target operations, and viewers/operators cannot open it.

Actual 320/768/1440 history and confirmation renders are reviewed with the existing
glass palette, responsive facts and mascot assets. This is a finite AI workspace
migration and explicit refresh flow. Fleet cache controls, shared admission/spend
views, asynchronous notifications and full application acceptance remain planned.


Reviewed fixtures: assessment detail [phone](screenshots/assessment-history-v1200-320.jpg),
[tablet](screenshots/assessment-history-v1200-768.jpg),
[desktop](screenshots/assessment-history-v1200-1440.jpg); Re-triage confirmation
[phone](screenshots/retriage-confirm-v1200-320.jpg),
[tablet](screenshots/retriage-confirm-v1200-768.jpg),
[desktop](screenshots/retriage-confirm-v1200-1440.jpg).
