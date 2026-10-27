#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
args=(--env-file .env --env-file .env.gcp -f compose.yaml -f compose.gcp.yaml)
if [[ -f compose.gcp-auth.json ]]; then args+=(-f compose.gcp-auth.json); fi
exec docker compose "${args[@]}" "$@"
