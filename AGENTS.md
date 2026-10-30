# Development instructions

- Read CONTRIBUTING.md and docs/SECURITY_IMPLEMENTATION.md. Before writing, apply its read-only completion gate; no changes or version bumps for feature-complete no-op cycles.
- Work in a focused feature branch targeting main. Reconcile unfinished related PRs first. Preserve the mascot/theme, roles, audit history and explicit response authorization boundaries.
- For every completed update, increment APP_VERSION in app/main.py using SemVer (patch for incremental changes, minor for substantial compatible features, major for breaking changes). Never reuse/decrease versions or rewrite past commits.
- Keep README's current source version and the newest numbered CHANGELOG.md entry synchronized. UI, health and FastAPI metadata derive their version from APP_VERSION.
- Run `python tools/check_version.py --base-ref <base-commit>` before publication; CI enforces this. Version metadata belongs in the tested commit.
- Every development and merge commit subject and PR title must include [vX.Y.Z]. Apply a matching GitHub version label where supported; inability to create a label must not block an otherwise valid update. Git tags are skipped by explicit user instruction.
- All applicable checks must pass on the exact final PR commit before merging. Record the version and PR/checkpoint references. Do not claim source versioning publishes a Docker image.
