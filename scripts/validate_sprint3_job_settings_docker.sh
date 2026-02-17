#!/bin/bash
# Sprint 3 validation: Redis-backed per-job settings + interactive controls smoke test
#
# Validates that the Kali executor container can:
# - reach Redis over REDIS_URL
# - read/write job:{job_id}:settings
# - load per-job settings via dynamic_agent.py (project_settings integration)
#
# Archives output under Project/Docs/sprint3/validation/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$REPO_ROOT/Project/Docs/sprint3/validation"
LOG_FILE="$LOG_DIR/docker_job_settings_smoke_test_sprint3.txt"

mkdir -p "$LOG_DIR"

# Append so every run is archived.
exec > >(tee -a "$LOG_FILE") 2>&1

echo ""
echo "============================================================"
echo "RUN START timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"
echo "Sprint 3 Docker Smoke Test: Redis + Job Settings"
echo "repo_root=$REPO_ROOT"
echo "log_file=$LOG_FILE"
echo "============================================================"

echo ""
echo "[1/6] Docker versions"
docker version

docker compose version

echo ""
echo "[2/6] Ensure external lab network exists (required by kali service)"
if docker network inspect tazosploit-lab >/dev/null 2>&1; then
  echo "OK: docker_network_exists=tazosploit-lab"
else
  echo "Creating docker_network=tazosploit-lab"
  docker network create tazosploit-lab
fi

echo ""
echo "[3/6] Build kali executor image (ensures python redis client installed)"
if [[ "${SKIP_KALI_BUILD:-}" =~ ^(1|true|yes)$ ]]; then
  echo "SKIP: kali_build=true (SKIP_KALI_BUILD=${SKIP_KALI_BUILD:-})"
else
  docker compose -f "$REPO_ROOT/docker-compose.yml" build kali
fi

echo ""
echo "[4/6] Start redis + kali"
docker compose -f "$REPO_ROOT/docker-compose.yml" up -d redis kali

echo ""
echo "[5/6] Verify Redis connectivity + job settings apply inside kali container"
JOB_ID="sprint3_smoke_job_settings"

# -T disables TTY (CI-friendly)
docker compose -f "$REPO_ROOT/docker-compose.yml" exec -T -e JOB_ID="$JOB_ID" kali bash -lc "\
  set -euo pipefail; \
  echo \"REDIS_URL=\$REDIS_URL\"; \
  python3 - <<'PY'
import json
import os
import sys

sys.path.insert(0, '/opt/tazosploit')

redis_url = os.getenv('REDIS_URL', '').strip()
if not redis_url:
    raise SystemExit('REDIS_URL missing in kali env')

import redis
r = redis.from_url(redis_url, decode_responses=True)
print('redis_ping=', r.ping())

job_id = os.getenv('JOB_ID', 'sprint3_smoke')
key = f'job:{job_id}:settings'
settings = {
    'USE_STRUCTURED_OUTPUT': True,
    'KNOWLEDGE_GRAPH_ENABLED': False,
    'REQUIRE_APPROVAL_FOR_EXPLOITATION': True,
    'KG_INJECT_EVERY': 9,
}
r.set(key, json.dumps(settings, ensure_ascii=True), ex=3600)
print('redis_set_ok=True', 'key=', key)

from dynamic_agent import DynamicAgent

tag = DynamicAgent(log_dir='/tmp/tazosploit_sprint3_smoke', llm_provider=None)
print('agent_job_id=', getattr(tag, 'job_id', None))
print('agent_use_structured_output=', getattr(tag, 'use_structured_output', None))
print('agent_knowledge_graph_enabled=', getattr(tag, 'knowledge_graph_enabled', None))
print('agent_approval_exploit=', os.getenv('REQUIRE_APPROVAL_FOR_EXPLOITATION'))
print('agent_kg_inject_every=', getattr(tag, 'kg_inject_every', None))

assert tag.job_id == job_id, f'Expected JOB_ID={job_id} got {tag.job_id}'
assert tag.use_structured_output is True
assert tag.knowledge_graph_enabled is False
assert os.getenv('REQUIRE_APPROVAL_FOR_EXPLOITATION', '').lower() in ('1','true','yes')
assert int(tag.kg_inject_every) == 9
print('job_settings_applied_ok=True')
PY\
"

echo ""
echo "[6/6] PASS: Redis + per-job settings verified in Kali"
