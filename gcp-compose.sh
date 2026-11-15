#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
# install-gcp.sh records its mode in .env.gcp; earlier installations have none and are complete.
mode=complete
if [[ -f .env.gcp ]] && grep -qx 'MRPATCHY_GCP_MODE=controller' .env.gcp; then mode=controller; fi
controller_args=(--env-file .env --env-file .env.gcp -f compose.controller.yaml -f compose.controller.gcp.yaml)
if [[ -f compose.controller.gcp-auth.json ]]; then controller_args+=(-f compose.controller.gcp-auth.json); fi
if [[ "${1:-}" == --workers ]]; then
  # The worker project joined by install-gcp.sh --mode worker, beside a controller-mode installation.
  shift
  [[ "$mode" == controller ]] || { echo 'gcp-compose.sh --workers needs a --mode controller installation' >&2; exit 2; }
  [[ -f .env.worker && ! -L .env.worker ]] || { echo 'No .env.worker; run ./install-gcp.sh --mode worker first' >&2; exit 2; }
  name=$(sed -n "s/^COMPOSE_PROJECT_NAME=['\"]\{0,1\}\([a-z0-9][a-z0-9_-]*\)['\"]\{0,1\}$/\1/p" .env.worker | tail -n 1)
  [[ -n "$name" ]] || { echo '.env.worker has no valid COMPOSE_PROJECT_NAME' >&2; exit 2; }
  # .env.worker can be edited after installation: never let the worker project become the controller's.
  controller=$(docker compose "${controller_args[@]}" config --format json 2>/dev/null \
    | python3 -c 'import json,sys;n=json.load(sys.stdin).get("name");print(n if isinstance(n,str) else "")' 2>/dev/null) || controller=''
  [[ -n "$controller" ]] || { echo 'Could not render the controller project; refusing to operate the worker project' >&2; exit 2; }
  [[ "$name" != "$controller" ]] || { echo ".env.worker COMPOSE_PROJECT_NAME must differ from the controller project $controller" >&2; exit 2; }
  args=(-p "$name" --env-file .env.worker --env-file .env.gcp -f compose.worker.yaml -f compose.worker.gcp.yaml)
  if [[ -f compose.worker.gcp-auth.json ]]; then args+=(-f compose.worker.gcp-auth.json); fi
elif [[ "$mode" == controller ]]; then
  args=("${controller_args[@]}")
else
  args=(--env-file .env --env-file .env.gcp -f compose.yaml -f compose.gcp.yaml)
  if [[ -f compose.gcp-auth.json ]]; then args+=(-f compose.gcp-auth.json); fi
fi
exec docker compose "${args[@]}" "$@"
