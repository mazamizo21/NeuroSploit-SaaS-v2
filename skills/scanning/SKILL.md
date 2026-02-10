# Vulnerability Scanning Skill

## Overview
Identify likely vulnerabilities and misconfigurations using safe, automated scanning.

## Scope Rules
1. Only scan explicitly in-scope services.
2. External targets: avoid aggressive scans unless explicitly authorized.
3. Validate findings before reporting.

## Methodology

### 1. Service-Scoped Scanning
- Use recon outputs to focus on discovered services
- Avoid unnecessary noise or broad scans

### 2. Web Vulnerability Scans
- Run web scanners with conservative rate limits
- Capture evidence for findings

### 3. Version and CVE Correlation
- Map detected versions to known CVEs
- Validate with lightweight checks

## Deep Dives
Load references when needed:
1. Safe scanning practices: `references/safe_scanning.md`
2. CVE correlation: `references/cve_correlation.md`
3. False positive reduction: `references/false_positive_reduction.md`

## MITRE ATT&CK Mappings
- T1595 - Active Scanning
- T1190 - Exploit Public-Facing Application

## Tools Available
- nuclei
- nikto
- nmap (vuln scripts)
- wpscan

## Evidence Collection
1. `scan_findings.json` with parsed scanner output (use `parse_nuclei_json.py` when available).
2. `evidence.json` with raw scanner outputs and command lines.
3. `findings.json` with validated issues and evidence.
4. Proof of vulnerable endpoints with request/response notes.

## Evidence Consolidation
Use `parse_nuclei_json.py` to convert nuclei JSON/JSONL output into `scan_findings.json`.

## Success Criteria
- Vulnerabilities identified with evidence
- False positives minimized
