#!/bin/bash
# Sprint 2 validation: Neo4j + KnowledgeGraph end-to-end smoke test
#
# - Brings up neo4j + kali services (docker-compose.yml)
# - Verifies neo4j health
# - Verifies the kali executor can import neo4j driver and connect via KnowledgeGraph
# - Archives output under Project/Docs/sprint2/validation/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$REPO_ROOT/Project/Docs/sprint2/validation"
LOG_FILE="$LOG_DIR/docker_neo4j_connectivity_smoke_test_sprint2.txt"

mkdir -p "$LOG_DIR"

# Append so every run is archived.
exec > >(tee -a "$LOG_FILE") 2>&1

echo ""
echo "============================================================"
echo "RUN START timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"

echo "============================================================"
echo "Sprint 2 Docker Smoke Test: Neo4j + KnowledgeGraph"
echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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
echo "[3/6] Build kali executor image (ensures neo4j python driver installed)"
if [[ "${SKIP_KALI_BUILD:-}" =~ ^(1|true|yes)$ ]]; then
  echo "SKIP: kali_build=true (SKIP_KALI_BUILD=${SKIP_KALI_BUILD:-})"
else
  docker compose -f "$REPO_ROOT/docker-compose.yml" build kali
fi

echo ""
echo "[4/6] Start neo4j + kali"
docker compose -f "$REPO_ROOT/docker-compose.yml" up -d neo4j kali

echo ""
echo "[5/6] Wait for neo4j health"
status=""
for i in $(seq 1 60); do
  status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' tazosploit-neo4j 2>/dev/null || echo missing)"
  echo "neo4j_health=$status attempt=$i/60"
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  sleep 2
done

if [[ "$status" != "healthy" ]]; then
  echo "ERROR: neo4j_not_healthy status=$status"
  echo "--- neo4j logs (tail 200) ---"
  docker logs --tail 200 tazosploit-neo4j || true
  exit 1
fi

echo ""
echo "[6/6] KnowledgeGraph connectivity test inside kali container"
# -T disables TTY (CI-friendly)
docker compose -f "$REPO_ROOT/docker-compose.yml" exec -T kali python3 - <<'PY'
import os
import sys

# Ensure agent modules are importable
sys.path.insert(0, "/opt/tazosploit")

print("python_executable=", sys.executable)
print("python_version=", sys.version)
print("NEO4J_URI=", os.getenv("NEO4J_URI"))
print("NEO4J_USER=", os.getenv("NEO4J_USER"))
print("KNOWLEDGE_GRAPH_ENABLED=", os.getenv("KNOWLEDGE_GRAPH_ENABLED"))

import neo4j  # noqa: F401
print("neo4j_driver_import_ok=True")
print("neo4j_driver_version=", getattr(neo4j, "__version__", "unknown"))

from knowledge_graph import KnowledgeGraph

kg = KnowledgeGraph(job_id="sprint2_smoke", user_id="smoke")
print("kg_available=", bool(getattr(kg, "available", False)))
if not getattr(kg, "available", False):
    raise SystemExit(2)

kg.add_host(ip="10.10.10.10", hostname="kg-smoke")
kg.add_service(host_ip="10.10.10.10", port=80, protocol="tcp", name="http", version="Apache-smoke")
kg.add_vulnerability(
    host_ip="10.10.10.10",
    port=80,
    vuln_type="nuclei-smoke-template",
    cve="CVE-2020-0000",
    severity="low",
    details="smoke",
)
kg.record_exploit_attempt(
    host_ip="10.10.10.10",
    port=80,
    tool="curl",
    command="curl -sS http://10.10.10.10/",
    success=False,
    evidence="smoke",
    cve="CVE-2020-0000",
)

summary = kg.get_attack_surface_summary(max_chars=800)
print("\n--- kg_summary ---\n" + summary)
PY

echo ""
echo "PASS: neo4j + knowledge graph connectivity verified"
