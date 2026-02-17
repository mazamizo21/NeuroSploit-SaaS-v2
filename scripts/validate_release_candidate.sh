#!/bin/bash
# Release Candidate validation (local + CI)
#
# Runs:
# - pytest (host venv)
# - frontend lint + build
# - docker compose smoke tests (Sprint 0/2/3)
#
# All outputs are archived under:
#   Project/Docs/release/validation/<timestamp>/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Allow CI to provide a deterministic timestamp-like ID.
RC_TS="${RC_TS:-}"
if [[ -z "$RC_TS" ]]; then
  # shellcheck disable=SC1091
  source "$REPO_ROOT/scripts/lib/validation_utils.sh"
  RC_TS="$(utc_ts)"
else
  # shellcheck disable=SC1091
  source "$REPO_ROOT/scripts/lib/validation_utils.sh"
fi

OUT_DIR="$REPO_ROOT/Project/Docs/release/validation/$RC_TS"
mkdir -p "$OUT_DIR"

# Mirror all stdout/stderr into the release directory.
exec > >(tee -a "$OUT_DIR/release_validation.txt") 2>&1

log_banner "RELEASE CANDIDATE VALIDATION — START"
echo "repo_root=$REPO_ROOT"
echo "out_dir=$OUT_DIR"

die() {
  echo "ERROR: $*" >&2
  echo "out_dir=$OUT_DIR" >&2
  exit 1
}

require_cmd() {
  local c="$1"
  command -v "$c" >/dev/null 2>&1 || die "missing_required_command=$c"
}

require_cmd git
require_cmd python3
require_cmd node
require_cmd npm
require_cmd docker
require_cmd tee

# docker compose may be either `docker compose` or `docker-compose`.
if docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE=(docker-compose)
else
  die "missing_required_command=docker_compose"
fi

echo ""
echo "[meta] git"
(
  cd "$REPO_ROOT"
  echo "git_rev=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_status_porcelain_count=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
)

echo ""
echo "[meta] tool versions"
run_step "docker_version" "$OUT_DIR/docker_version.txt" docker version
run_step "docker_compose_version" "$OUT_DIR/docker_compose_version.txt" "${DOCKER_COMPOSE[@]}" version
run_step "node_version" "$OUT_DIR/node_version.txt" node --version
run_step "npm_version" "$OUT_DIR/npm_version.txt" npm --version
run_step "python_version" "$OUT_DIR/python_version.txt" python3 --version

log_banner "DOCKER: build kali executor image (once)"
run_step "docker_build_kali" "$OUT_DIR/docker_build_kali.txt" "${DOCKER_COMPOSE[@]}" -f "$REPO_ROOT/docker-compose.yml" build kali

# Avoid rebuilding kali multiple times (Sprint 0/2/3 smoke tests each try to build by default).
export SKIP_KALI_BUILD=1

log_banner "PYTHON: unit tests (pytest)"
VENV_DIR="${VENV_DIR:-$REPO_ROOT/.venv-rc}"
echo "venv_dir=$VENV_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
  run_step "python_create_venv" "$OUT_DIR/python_create_venv.txt" python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

run_step "python_pip_upgrade" "$OUT_DIR/python_pip_upgrade.txt" python -m pip install --upgrade pip

# Install a unified dependency set needed for unit tests that import both control-plane and execution-plane modules.
run_step "python_install_deps" "$OUT_DIR/python_install_deps.txt" \
  python -m pip install \
    -r "$REPO_ROOT/control-plane/requirements.txt" \
    -r "$REPO_ROOT/execution-plane/requirements.txt" \
    pytest neo4j

run_step "pytest_unit" "$OUT_DIR/pytest_unit.txt" python -m pytest -q tests/unit

log_banner "FRONTEND: lint + build"
FRONTEND_DIR="$REPO_ROOT/frontend"
if [[ ! -d "$FRONTEND_DIR" ]]; then
  die "frontend_dir_missing=$FRONTEND_DIR"
fi

run_step "frontend_npm_ci" "$OUT_DIR/frontend_npm_ci.txt" bash -lc "cd '$FRONTEND_DIR' && npm ci"
run_step "frontend_lint" "$OUT_DIR/frontend_lint.txt" bash -lc "cd '$FRONTEND_DIR' && npm run lint"
run_step "frontend_build" "$OUT_DIR/frontend_build.txt" bash -lc "cd '$FRONTEND_DIR' && npm run build"

log_banner "DOCKER: smoke tests (Sprint 0/2/3)"
run_step "sprint0_approval_gate_ws_e2e" "$OUT_DIR/sprint0_approval_gate_ws_e2e.txt" bash "$REPO_ROOT/scripts/validate_sprint0_approval_gate_ws_e2e.sh"
run_step "sprint2_neo4j_smoke" "$OUT_DIR/sprint2_neo4j_smoke.txt" bash "$REPO_ROOT/scripts/validate_sprint2_neo4j_docker.sh"
run_step "sprint3_job_settings_smoke" "$OUT_DIR/sprint3_job_settings_smoke.txt" bash "$REPO_ROOT/scripts/validate_sprint3_job_settings_docker.sh"

echo ""
echo "[post] docker compose ps"
run_step "docker_compose_ps" "$OUT_DIR/docker_compose_ps.txt" "${DOCKER_COMPOSE[@]}" -f "$REPO_ROOT/docker-compose.yml" ps

echo ""
echo "[post] api logs tail (safe: uvicorn access logs disabled in compose)"
run_step "docker_logs_api_tail" "$OUT_DIR/docker_logs_api_tail.txt" "${DOCKER_COMPOSE[@]}" -f "$REPO_ROOT/docker-compose.yml" logs --tail 300 api

log_banner "RELEASE CANDIDATE VALIDATION — PASS"
PASS_FILE="$OUT_DIR/PASS.txt"
{
  echo "PASS timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_rev=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "out_dir=$OUT_DIR"
} >"$PASS_FILE"

echo "PASS_FILE=$PASS_FILE"
echo "RC_OUT_DIR=$OUT_DIR"
