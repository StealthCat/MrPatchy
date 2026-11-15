#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
# install-gcp.sh records its mode in .env.gcp; earlier installations have none and are complete.
mode=complete
if [[ -f .env.gcp ]] && grep -qx 'MRPATCHY_GCP_MODE=controller' .env.gcp; then mode=controller; fi
if [[ "$mode" == controller ]]; then
  args=(--env-file .env --env-file .env.gcp -f compose.controller.yaml -f compose.controller.gcp.yaml)
  if [[ -f compose.controller.gcp-auth.json ]]; then args+=(-f compose.controller.gcp-auth.json); fi
else
  args=(--env-file .env --env-file .env.gcp -f compose.yaml -f compose.gcp.yaml)
  if [[ -f compose.gcp-auth.json ]]; then args+=(-f compose.gcp-auth.json); fi
fi
exec docker compose "${args[@]}" "$@"
