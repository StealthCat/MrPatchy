# Changelog

## 1.54.8 — 2026-11-10

1. [PR #630](https://github.com/StealthCat/MrPatchy/pull/630): Upgrade the hash-pinned Authlib runtime dependency from 1.9.1 to 1.9.4, including upstream OAuth ID-JAG scope and issuer/subject user-resolution fixes. Application OAuth configuration, schema and public API remain unchanged; existing integrations gain these upstream fixes where ID-JAG is used, with no expected compatibility impact. This source update does not publish a Docker image.

