#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ $# -ne 1 ]]; then
  echo "Usage: scripts/validate-feature-context.sh <feature-directory>" >&2
  exit 2
fi
exec "$ROOT/scripts/validate-instructions.sh" --context "$1/instruction-context.yaml"
