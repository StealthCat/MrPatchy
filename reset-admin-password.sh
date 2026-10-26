#!/usr/bin/env bash
set -euo pipefail
# Run beside compose.yaml, or set MRPATCHY_PROJECT_DIR to the deployment directory.
project_dir=${MRPATCHY_PROJECT_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}
args=(exec --user mrpatchy)
for argument in "$@"; do
  if [[ "$argument" == '--password-stdin' ]]; then args+=(-T); break; fi
done
exec docker compose --project-directory "$project_dir" "${args[@]}" app python -m app.admin_reset "$@"
