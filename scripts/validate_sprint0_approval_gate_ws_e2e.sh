#!/bin/bash
# Sprint 0 validation: Approval Gate end-to-end (DynamicAgent -> Redis pubsub -> WS -> Redis key -> DynamicAgent)
#
# Archives output under Project/Docs/sprint0/validation/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$REPO_ROOT/Project/Docs/sprint0/validation"
LOG_FILE="$LOG_DIR/approval_gate_ws_e2e.txt"

mkdir -p "$LOG_DIR"

# Append so every run is archived.
exec > >(tee -a "$LOG_FILE") 2>&1

echo ""
echo "============================================================"
echo "RUN START timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"
echo "Sprint 0 E2E: Approval Gate WS flow"
echo "repo_root=$REPO_ROOT"
echo "log_file=$LOG_FILE"
echo "============================================================"

echo ""
echo "[1/9] Ensure external lab network exists (required by kali service)"
if docker network inspect tazosploit-lab >/dev/null 2>&1; then
  echo "OK: docker_network_exists=tazosploit-lab"
else
  echo "Creating docker_network=tazosploit-lab"
  docker network create tazosploit-lab
fi

echo ""
echo "[2/9] Build kali executor image (ensures latest agent code is in-container)"
if [[ "${SKIP_KALI_BUILD:-}" =~ ^(1|true|yes)$ ]]; then
  echo "SKIP: kali_build=true (SKIP_KALI_BUILD=${SKIP_KALI_BUILD:-})"
else
  docker compose -f "$REPO_ROOT/docker-compose.yml" build kali
fi

echo ""
echo "[3/9] Start core services (postgres, redis, api) + kali"
docker compose -f "$REPO_ROOT/docker-compose.yml" up -d postgres redis api kali

# Uvicorn runs without --reload in docker-compose.yml.
# When the control-plane code is bind-mounted (./control-plane:/app), we must restart
# the api container so it reloads the updated Python modules (including WS routes).
docker compose -f "$REPO_ROOT/docker-compose.yml" restart api

echo ""
echo "[4/9] Wait for API health"
API_BASE="${API_BASE:-http://localhost:8000}"
for i in $(seq 1 60); do
  if curl -fsS "$API_BASE/health" >/dev/null 2>&1; then
    echo "OK: api_healthy=true"
    break
  fi
  sleep 1
  if [ "$i" -eq 60 ]; then
    echo "ERROR: api health check timed out" >&2
    exit 1
  fi
done

echo ""
echo "[5/9] Create scope + job (internal service auth)"
# Derive internal auth token from the running API container to avoid host/compose mismatch.
# NOTE: Do not print the secret to logs.
SECRET_KEY="$(
  docker compose -f "$REPO_ROOT/docker-compose.yml" exec -T api sh -lc 'printf "%s" "${SECRET_KEY:-}"' \
    | tr -d '\r\n'
)"
if [ -z "$SECRET_KEY" ]; then
  SECRET_KEY="dev-secret-change-in-production"
fi

INTERNAL_TOKEN="internal-${SECRET_KEY}"
LLM_PROVIDER_EFFECTIVE="${LLM_PROVIDER:-anthropic}"
TOKEN_ENC="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$INTERNAL_TOKEN")"

echo "OK: internal_token_source=api_container_env secret_key_len=${#SECRET_KEY} internal_token_len=${#INTERNAL_TOKEN} internal_token_urlencoded_len=${#TOKEN_ENC}"

CREATE_JSON="$(
  INTERNAL_TOKEN="$INTERNAL_TOKEN" \
  API_BASE="$API_BASE" \
  LLM_PROVIDER="$LLM_PROVIDER_EFFECTIVE" \
  node - <<'NODE'
(async () => {
  const apiBase = String(process.env.API_BASE || 'http://localhost:8000');
  const token = String(process.env.INTERNAL_TOKEN || '').trim();
  const llmProvider = String(process.env.LLM_PROVIDER || 'anthropic').trim();
  if (!token) throw new Error('INTERNAL_TOKEN missing');

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const target = 'juiceshop';

  const scopeBody = {
    name: `e2e-approval-scope-${ts}`,
    description: 'E2E validation scope for approval gate',
    targets: [target],
    excluded_targets: [],
    allowed_phases: ['RECON', 'VULN_SCAN'],
    max_intensity: 'medium',
  };

  const scopeRes = await fetch(`${apiBase}/api/v1/scopes`, {
    method: 'POST',
    headers,
    body: JSON.stringify(scopeBody),
  });

  const scopeText = await scopeRes.text();
  if (!scopeRes.ok) {
    throw new Error(`create_scope_failed status=${scopeRes.status} body=${scopeText}`);
  }
  const scope = JSON.parse(scopeText);

  const jobBody = {
    name: `e2e-approval-job-${ts}`,
    description: 'E2E approval gate validation job',
    scope_id: String(scope.id),
    phase: 'RECON',
    targets: [target],
    intensity: 'low',
    timeout_seconds: 3600,
    auto_run: false,
    target_type: 'lab',
    authorization_confirmed: true,
    exploit_mode: 'explicit_only',
    max_iterations: 10,
    llm_provider: llmProvider,
  };

  const jobRes = await fetch(`${apiBase}/api/v1/jobs`, {
    method: 'POST',
    headers,
    body: JSON.stringify(jobBody),
  });

  const jobText = await jobRes.text();
  if (!jobRes.ok) {
    throw new Error(`create_job_failed status=${jobRes.status} body=${jobText}`);
  }
  const job = JSON.parse(jobText);

  const out = {
    scope_id: String(scope.id),
    job_id: String(job.id),
  };
  console.log(JSON.stringify(out));
})().catch((e) => {
  console.error(String(e && e.stack ? e.stack : e));
  process.exit(1);
});
NODE
)"

JOB_ID="$(python3 -c 'import json,sys; s=sys.stdin.read().strip(); print((json.loads(s) if s else {}).get("job_id", ""))' <<<"$CREATE_JSON")"

if [ -z "$JOB_ID" ]; then
  echo "ERROR: job_id missing from create output" >&2
  echo "$CREATE_JSON" >&2
  exit 1
fi

echo "OK: job_id=$JOB_ID"

echo ""
echo "[6/9] Start WS approval client"
WS_URL="ws://localhost:8000/api/v1/ws/jobs/${JOB_ID}/chat?token=${TOKEN_ENC}"
export WS_URL
export DECISION="approve"
export TIMEOUT_MS="60000"

node "$REPO_ROOT/scripts/ws_approval_gate_client.mjs" &
WS_PID=$!

# Give the client a moment to connect before agent emits pubsub event.
sleep 2

echo ""
echo "[7/9] Trigger approval gate from DynamicAgent (inside kali)"
# The agent uses internal phases: RECON -> VULN_DISCOVERY -> EXPLOITATION -> POST_EXPLOIT
# Approval gate triggers on transition to EXPLOITATION when REQUIRE_APPROVAL_FOR_EXPLOITATION=true.

docker compose -f "$REPO_ROOT/docker-compose.yml" exec -T \
  -e JOB_ID="$JOB_ID" \
  -e JOB_PHASE="RECON" \
  -e REQUIRE_APPROVAL_FOR_EXPLOITATION="true" \
  kali bash -lc "\
    set -euo pipefail; \
    python3 - <<'PY'
import os
import sys
import time

sys.path.insert(0, '/opt/tazosploit')

from dynamic_agent import DynamicAgent

job_id = os.getenv('JOB_ID', '').strip()
if not job_id:
    raise SystemExit('JOB_ID missing')

agent = DynamicAgent(log_dir='/tmp/tazosploit_approval_gate_ws_e2e', llm_provider=None)
print('agent_job_id=', agent.job_id)
print('phase_start=', agent.phase_current)

# Ensure WS client has time to connect.
time.sleep(1.5)

agent._advance_phase('EXPLOITATION')
print('awaiting_approval=', getattr(agent, '_awaiting_approval', False))
print('pending_phase=', getattr(agent, '_pending_phase', None))

deadline = time.time() + 45
while time.time() < deadline:
    if not getattr(agent, '_awaiting_approval', False):
        break
    decision = agent._check_approval_response()
    if decision is None:
        time.sleep(0.5)
        continue
    print('approval_decision=', decision)

if getattr(agent, '_awaiting_approval', False):
    raise SystemExit('approval_response_timeout')

print('phase_final=', agent.phase_current)
assert agent.phase_current == 'EXPLOITATION', f"unexpected final phase={agent.phase_current}"
print('approval_gate_ws_e2e_ok=True')
PY
  "

echo ""
echo "[8/9] Wait for WS client to exit"
wait "$WS_PID"

echo ""
echo "[9/9] Cleanup: mark job completed (avoid quota accumulation)"
curl -fsS -X PATCH "$API_BASE/api/v1/jobs/${JOB_ID}" \
  -H "Authorization: Bearer ${INTERNAL_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"status":"completed","result":{"validation":"approval_gate_ws_e2e"}}' >/dev/null

echo "PASS: approval gate WS E2E validated job_id=$JOB_ID"
