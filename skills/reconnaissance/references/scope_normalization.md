# Scope Normalization

## Goals
1. Normalize targets into canonical host, port, and URL lists.
2. Avoid scanning out-of-scope assets.
3. Preserve source-of-scope metadata for reporting.

## Safe Checks
1. Deduplicate targets and resolve to IPs.
2. Normalize scheme and ports (HTTP/HTTPS, custom ports).
3. Maintain an allowlist and blocklist with sources.
4. Record wildcard DNS findings and resolve carefully.

## Evidence Checklist
1. Normalized target list with source notes.
2. Allowlist and blocklist with timestamps.
3. Resolution outputs (A/AAAA/CNAME) for key hosts.
