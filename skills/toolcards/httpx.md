# httpx Toolcard

## Overview
- Summary: httpx is a fast, multi-purpose HTTP toolkit for probing hosts and URLs and enriching them with response metadata.

## Advanced Techniques
- Probe large target lists and enrich with status code, title, and tech detection.
- Use JSON output to feed downstream tooling and diff scan results over time.
- Leverage HTTP/HTTPS auto-fallback for mixed target lists.

## Safe Defaults
- Rate limits: use conservative concurrency on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: httpx.json (probe results), tech_fingerprint.json

## References
- https://docs.projectdiscovery.io/opensource/httpx/overview
