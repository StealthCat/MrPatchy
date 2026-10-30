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
| Fleet Overview, Servers and enrollment | Existing pages; verified landing v0.5.0 | Full dashboard/list/onboarding migration, empty/error/progress states |
| Server Overview and navigation | Compact header/route groups v0.6.0 | Summary cards, lifecycle/AI controls and dense content migration |
| Packages, repositories, patching and schedules | Existing pages; scoped filters v0.6.0 | Shared tables/forms, history/calendar detail pages, approvals and context retention |
| Investigations and AI activity | Existing global/server pages | Focused evidence/run detail, cost/uncertainty/pause states |
| Security, integrity, startup and response | Existing scanner/baseline/vendor/file/process workflows | Split crowded workspaces and long dialogs; migrate review/recovery/export states |
| Activity, audit and inventory/package history | Existing global/server pages | Dedicated detail views, shared pagination/filter/long-output components |
| Settings, users and operations | Existing settings pages/forms/dialogs | Consistent grouped administration, accessible forms and destructive confirmations |
| Deployment, worker and GCP health | Planned backend features | Migrate when implemented, without fabricating component health |
| Whole-application acceptance | Not complete | All rows migrated; cross-role workflows, state/asset/readability consistency and actual mobile/tablet/desktop review |

No additional mascot artwork is required for this bounded route milestone; it
reuses the established illustrations. New poses/graphics remain part of the later
shared-visual-system/content work. Do not mark the full rework complete from this
navigation component alone.

Reviewed fixture renders for this milestone: [desktop](screenshots/workbench-navigation-desktop.jpg), [tablet](screenshots/workbench-navigation-tablet.jpg), [mobile](screenshots/workbench-navigation-mobile.jpg). These show the open section chooser; closed-state navigation, roles, Back and server switching are also exercised by the browser suite.
