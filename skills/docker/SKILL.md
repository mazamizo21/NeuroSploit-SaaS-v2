# Docker Service Skill

## Overview
Service-first methodology for Docker daemon discovery and safe configuration review.

## Scope Rules
1. Only operate on explicitly authorized hosts, daemons, and sockets.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Prefer read-only commands; avoid container creation or exec unless authorized.
4. Do not pull images or run containers unless explicitly authorized.

## Methodology

### 1. Discovery and API Access
- Identify exposed Docker daemon endpoints (TCP 2375/2376) or local sockets.
- Capture daemon version and TLS configuration where available.

### 2. Access Validation
- Validate access with read-only `docker version` and `docker info`.
- Record authentication or TLS failures once per host.

### 3. Inventory (Authorized)
- Enumerate running containers, images, networks, and volumes.
- Capture host OS and daemon configuration summaries.

### 4. Configuration Review
- Check for unauthenticated Docker API exposure.
- Review daemon flags and security posture (rootless, TLS, authorization).

### 5. Explicit-Only Actions
- Container exec, image export, or container creation requires explicit authorization.

## Deep Dives
Load references when needed:
1. Daemon exposure: `references/daemon_exposure.md`
2. Inventory review: `references/inventory.md`
3. Benchmarks and hardening: `references/benchmarks.md`

## Service-First Workflow (Default)
1. Discovery: `nmap` to identify daemon ports.
2. Access validation: `docker` read-only inventory via `DOCKER_HOST`.
3. Automated review: `docker-bench-security` for CIS checks.
4. Explicit-only: container exec or image export.

## Evidence Collection
1. `docker_inventory.json` with daemon info, containers, and images (summarized from `docker info` and `docker ps`).
2. `evidence.json` with raw `docker info` and `docker ps` outputs.
3. `findings.json` with exposure or misconfiguration evidence.

## Evidence Consolidation
Use `summarize_docker_info.py` to consolidate `docker info` and `docker ps` outputs into `docker_inventory.json`.

## Success Criteria
- Docker daemon access scope confirmed.
- Inventory captured safely.
- High-risk configuration issues documented.

## Tool References
- ../toolcards/docker.md
- ../toolcards/docker-bench-security.md
- ../toolcards/trivy.md
- ../toolcards/nmap.md
