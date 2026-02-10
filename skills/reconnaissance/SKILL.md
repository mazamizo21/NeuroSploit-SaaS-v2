# Reconnaissance Skill

## Overview
Systematic information gathering about target infrastructure and services with minimal impact.

## Scope Rules
1. Only operate on explicitly in-scope targets.
2. External targets: avoid aggressive scans and brute force unless explicitly authorized.
3. Prefer passive sources and conservative rate limits.
4. If scope expansion is enabled (lab), map adjacent/internal subnets to support lateral movement.

## Methodology

### 1. Scope Normalization
- Normalize targets to canonical host/port/URL lists.
- Deduplicate and respect allowlists.

### 2. Network Discovery
- Identify active hosts and open services.
- Use conservative scan rates and limited retries.

### 3. Service Mapping
- Capture service banners, versions, and protocols.
- Correlate evidence into a service inventory.

### 4. Web Recon
- Discover endpoints and technology stacks safely.
- Capture screenshots only when authorized.

## Deep Dives
Load references when needed:
1. Scope normalization: `references/scope_normalization.md`
2. Rate limits: `references/rate_limits.md`
3. Service mapping: `references/service_mapping.md`
4. Evidence capture: `references/evidence_capture.md`

## Evidence Collection
1. `recon_hosts.json` with hosts and ports (parsed from nmap output).
2. `services.json` with service inventory and version hints.
3. `endpoints.json` with URLs, status codes, and titles (from HTTP discovery).
4. `evidence.json` with raw outputs, command lines, and timestamps.
5. `findings.json` with recon observations.

## Evidence Consolidation
1. Use `parse_nmap_grepable.py` to convert `-oG` output into `recon_hosts.json`.
2. Use `summarize_httpx.py` from `skills/http/scripts/` when HTTP discovery is used.

## Success Criteria
- Active hosts and services identified with evidence.
- Recon outputs captured safely and consistently.
