# Network Evasion & Traffic Shaping Skill

## Overview
Service-first methodology for authorized traffic shaping, rate control, and safe network testing behaviors. This skill focuses on *defensive-safe* evasion concepts that reduce risk and avoid disruption, not on bypassing security controls.

## Scope Rules
1. Only operate on explicitly authorized networks and hosts.
2. External targets: any active evasion techniques require explicit authorization (external_exploit=explicit_only).
3. Avoid spoofing, bypass attempts, or stealth tactics unless explicitly authorized and documented.
4. Prefer low-impact, rate-limited probes and transparent traffic patterns.

## Methodology

### 1. Baseline Network Posture
- Establish baseline reachability and latency using low-rate probes.
- Capture baseline TTL, jitter, and packet loss for evidence.

### 2. Traffic Shaping and Rate Control
- Use conservative rate limits and backoff strategies.
- Align request concurrency with target capacity and engagement constraints.

### 3. Safe Evasion Checks (Authorized)
- Validate that scan profiles are not triggering rate limiting or WAF throttling.
- Adjust timing and retry behavior instead of evasion tactics.

### 4. Explicit-Only Actions
- Any stealth, obfuscation, fragmentation, or spoofing tests require explicit authorization.

## Deep Dives
Load `references/profiles.md` for approved timing and rate-control profiles.

## Service-First Workflow (Default)
1. Baseline: low-rate discovery with `nmap` timing profiles.
2. Shaping: route traffic through `proxychains` or controlled proxies when required.
3. Monitoring: `tcpdump` or `tshark` for evidence of throttling or resets.
4. Explicit-only: advanced evasion techniques only when authorized.

## Evidence Collection
1. `network_profile.json` with timing, rate limits, and baseline metrics (summarized from profiling output).
2. `evidence.json` with raw profiling notes and capture references.
3. `findings.json` with rate-limit or throttling evidence.

## Evidence Consolidation
Use `summarize_network_profile.py` to convert key:value notes into `network_profile.json`.

## Success Criteria
- Baseline network profile recorded.
- Rate controls applied safely.
- Evidence captured without service disruption.

## Tool References
- ../toolcards/nmap.md
- ../toolcards/proxychains.md
- ../toolcards/tor.md
- ../toolcards/tcpdump.md
- ../toolcards/tshark.md
- ../toolcards/hping3.md
