# Roadmap and delivery checkpoints

From 2026-11-25 (issue #1523), each PR records its roadmap or delivery checkpoint in
its own file here, named after the issue it delivers or tracks: `docs/checkpoints/<issue>.md`
(for example `docs/checkpoints/1338.md`). If a later PR continues the same issue, add a
new dated section to that issue's file.

A checkpoint file states:

- the roadmap item and issue it belongs to;
- what was delivered, at which commit or PR;
- validation evidence;
- what remains, and any coverage gaps or compatibility impacts.

Earlier checkpoints remain in [the security implementation checkpoint](../SECURITY_IMPLEMENTATION.md),
which still holds the policy and design sections. Do not append new checkpoint sections
to that file: every such append conflicts with every other open PR doing the same.
