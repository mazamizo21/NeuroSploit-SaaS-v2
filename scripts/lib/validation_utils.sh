#!/bin/bash

# Shared helpers for validation scripts.
# Intentionally does NOT set shell options (set -euo pipefail) so callers control behavior.

utc_ts() {
  date -u +%Y%m%dT%H%M%SZ
}

log_banner() {
  local title="$1"
  echo ""
  echo "============================================================"
  echo "$title"
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "============================================================"
}

run_step() {
  # Usage:
  #   run_step "step_name" "/abs/path/to/output.txt" cmd arg1 arg2...
  local step_name="$1"
  local out_file="$2"
  shift 2

  echo ""
  echo "------------------------------------------------------------"
  echo "STEP: ${step_name}"
  echo "out_file=${out_file}"
  echo "cmd=$*"
  echo "------------------------------------------------------------"

  mkdir -p "$(dirname "${out_file}")"

  # Ensure the exit code of the step isn't lost due to `tee`.
  (
    set -o pipefail
    "$@" 2>&1 | tee "${out_file}"
  )
}
