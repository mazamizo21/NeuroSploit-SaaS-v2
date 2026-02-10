# Skill Roadmap and Service Coverage Plan

This document defines the end-to-end plan to build service- and phase-specific skills that make TazoSploit a high-fidelity red-team platform. It is designed to be executed iteratively while maintaining strict scoping and safety for external targets.

## Goals

1. Build a skill per service and phase, with advanced techniques and reliable evidence output.
2. Make skill selection deterministic and evidence-driven, with LLM used as a tie-breaker.
3. Ensure external targets are safe by default with explicit authorization gates.

## Skill Unit Structure

Each skill must include:

1. `SKILL.md` with methodology, success criteria, and safety notes.
2. `skill.yaml` metadata for routing, prerequisites, and outputs.
3. `tools.yaml` with tool definitions, install commands, and examples.
4. Optional scripts in `scripts/` for repeatable workflows.

Recommended additions:

1. `toolcards/` per tool, with advanced flags and safe defaults.
2. `playbooks/` for service workflows (sequence of toolcards).

## Phase Coverage

Phases map to the API `job.phase` and to skills:

1. `RECON` — discovery, enumeration, fingerprinting.
2. `VULN_SCAN` — vulnerability identification and safe validation.
3. `EXPLOIT` — minimal proof-of-impact with evidence capture.
4. `POST_EXPLOIT` — credential access, privilege escalation, lateral movement, persistence, defense evasion, data access validation.
5. `REPORT` — evidence synthesis and remediation.

## Service Coverage Matrix

Each service should have skills for recon, vuln scan, exploit, and post-exploit as applicable.

Services to cover:

1. HTTP/HTTPS
2. DNS
3. TLS/SSL
4. SSH
5. SMB/CIFS
6. RDP
7. FTP
8. SMTP/IMAP/POP
9. SNMP
10. LDAP/AD
11. Kerberos
12. Databases: MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch
13. Web Apps: WordPress, Joomla, Drupal
14. API gateways and developer portals
15. Containers: Docker, Kubernetes
16. Cloud: AWS, GCP, Azure
17. Wireless
18. VPNs and tunneling
19. CI/CD, SCM platforms, and secrets managers
20. Host OS focus: Windows and Linux operational security
21. Network evasion and traffic shaping (authorized only)
22. Application security patterns (OWASP, API auth, session handling)

## Tool Ingestion Workflow

Use local and online information sources per tool:

1. Read `man tool` and `tool --help` for flags and defaults.
2. Use the official Kali tool page for usage examples and links to upstream docs.
3. Use upstream documentation for advanced techniques and safe workflows.

## Build Plan (Iterative Waves)

Wave 1 — Core network and web services

1. HTTP/HTTPS
2. DNS
3. TLS/SSL
4. SSH
5. SMB
6. MySQL, PostgreSQL, Redis

Wave 2 — Enterprise services

1. LDAP/AD
2. Kerberos
3. RDP
4. MSSQL
5. Elasticsearch

Wave 3 — Web frameworks and CMS

1. WordPress
2. Joomla
3. Drupal
4. API gateway patterns

Wave 4 — Cloud and containers

1. Docker
2. Kubernetes
3. AWS
4. GCP
5. Azure

Wave 5 — Long tail

1. Wireless
2. VPNs and tunneling
3. CI/CD, SCM, secrets managers

Wave 6 — Host OS and Evasion

1. Windows host hardening and post-exploit validation (authorized only)
2. Linux host hardening and post-exploit validation (authorized only)
3. Network evasion and traffic shaping techniques (authorized only)
4. Application-layer security validation playbooks

## Evidence and Output Contract

Every skill must output structured evidence to the job output dir:

1. `ports.json`, `services.json`, `tech_fingerprint.json` for recon.
2. `vulns.json`, `findings.json` for vuln scan.
3. `access.json`, `evidence.json` for exploitation.
4. `creds.json`, `priv_esc.json`, `lateral.json`, `persistence.json` for post-exploit.
5. `report.json`, `report.md` for reporting.

## Safety for External Targets (Default Policy)

1. Recon and vuln scan only by default.
2. Exploit and post-exploit require explicit authorization per scope/job.
3. No subnet scans unless CIDR is explicitly in scope.
4. Conservative rate limits and low concurrency on external targets.

## Implementation Notes

1. Use skill metadata in `skill.yaml` to drive deterministic routing.
2. Use service hints from evidence to select service-specific skills.
3. Log routing decisions for audit and debugging.
