# Sprint 2 — Knowledge Graph (Neo4j) (Tracking)

Status legend: `[ ]` todo, `[x]` done, `[~]` in progress.

## §2A — Neo4j Container
- [x] Add `neo4j` service to `docker-compose.yml` (ports, volumes, healthcheck).
- [x] Ensure network reachability from the Kali executor container (agent runtime) to Neo4j.
- [x] Add Neo4j env vars to `.env.example`.

## §2B — Knowledge Graph Client
- [x] Create `kali-executor/open-interpreter/knowledge_graph.py` (lazy driver, schema init, read/write helpers).
- [x] Ensure Neo4j is optional (no-op when driver/container unavailable).

## §2C — Output Parsers → Graph Updates
- [x] Create `kali-executor/open-interpreter/graph_parsers.py`.
  - [x] `parse_nmap_output()` → Host/Service nodes.
  - [x] `parse_nuclei_output()` → Vulnerability nodes.
  - [x] `auto_parse()` dispatch by tool.

## §2D — Agent Integration
- [x] Integrate KnowledgeGraph into `kali-executor/open-interpreter/dynamic_agent.py` (optional; fail-open).
- [x] After each execution, parse output and update KG.
- [x] Before LLM calls, inject KG summary periodically (with digest-based change detection).

## Validation (archive logs under `Project/Docs/sprint2/validation/`)
- [x] `python -m compileall` updated/new modules: `Project/Docs/sprint2/validation/python_compileall_sprint2_kg.txt`.
- [x] Import/init smoke test (host venv): `Project/Docs/sprint2/validation/dynamic_agent_kg_init_smoke_test_sprint2_venv.txt`.
- [x] KG context injection smoke test (host venv): `Project/Docs/sprint2/validation/dynamic_agent_kg_context_injection_smoke_test_sprint2_venv.txt`.
- [x] Unit tests (host venv): `Project/Docs/sprint2/validation/pytest_unit_sprint2_venv.txt`.
- [x] Optional: Docker Neo4j connectivity smoke test from Kali container:
  - Runner: `scripts/validate_sprint2_neo4j_docker.sh`
  - Output: `Project/Docs/sprint2/validation/docker_neo4j_connectivity_smoke_test_sprint2.txt`
