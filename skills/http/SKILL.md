# HTTP Service Skill

## Overview
Service-specific methodology for HTTP/HTTPS discovery, fingerprinting, and safe validation.

## Scope Rules
1. Only operate on explicitly in-scope hosts and URLs.
2. External targets: no exploitation or credential attacks unless explicit authorization is confirmed.
3. Use conservative rate limits and avoid disruptive requests on external targets.
4. Exploit or data extraction workflows require explicit authorization (external_exploit=explicit_only).

## Methodology

### 1. Normalize Targets
- Build canonical base URLs from host and port evidence.
- Verify reachability and capture status, title, and redirect chain.

### 2. Fingerprint Stack and Controls
- Identify server, frameworks, and technologies.
- Detect WAFs and capture security headers.

### 3. Endpoint and Content Discovery
- Enumerate directories, files, and API paths with wordlists.
- Check robots.txt, sitemap.xml, and well-known paths.

### 4. Safe Validation
- Run template-based scanners with low and medium severity filters.
- Validate findings with minimal-impact requests.

### 5. Optional Exploit (Explicit Authorization Only)
- Only when `authorization_confirmed` and phase is EXPLOIT.
- Perform targeted proof-of-impact and stop after evidence.

## Deep Dives
Load references when needed:
1. Fingerprinting and stack detection: `references/fingerprinting.md`
2. Security headers: `references/headers_controls.md`
3. Endpoint discovery: `references/discovery_paths.md`
4. WAF detection: `references/waf_detection.md`
5. Safe scanning patterns: `references/safe_scanning.md`

## Service-First Workflow (Default)
1. Discovery: normalize URLs and verify reachability with `httpx` or `httprobe`.
2. Fingerprint: identify technologies and WAFs using `whatweb` and `wafw00f`.
3. Content discovery: use scoped fuzzers or brute-forcers with conservative rates.
4. Safe validation: template-based checks or scanners at low impact.
5. Explicit-only exploit: targeted proof-of-impact only when authorization is confirmed.

## Evidence Collection
1. `tech_fingerprint.json` with stack and header evidence.
2. `endpoints.json` with status codes and response metadata (summarized from `httpx` output).
3. `evidence.json` with raw header captures, WAF detection output, and scan commands.
4. `findings.json` with validated issues and evidence.

## Evidence Consolidation
Use `summarize_httpx.py` to convert `httpx` JSONL output into `endpoints.json`.

## Success Criteria
- Live web services verified.
- Tech stack and security controls identified.
- High-confidence findings documented with evidence.

## Tool References
- ../toolcards/httpx.md
- ../toolcards/httprobe.md
- ../toolcards/whatweb.md
- ../toolcards/wafw00f.md
- ../toolcards/ffuf.md
- ../toolcards/gobuster.md
- ../toolcards/dirsearch.md
- ../toolcards/feroxbuster.md
- ../toolcards/dirb.md
- ../toolcards/dirbuster.md
- ../toolcards/nikto.md
- ../toolcards/nuclei.md
- ../toolcards/wapiti.md
