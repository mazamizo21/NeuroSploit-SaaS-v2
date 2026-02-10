# dnsenum Toolcard

## Overview
- Summary: dnsenum gathers DNS information, attempts zone transfers, and supports brute-force subdomain enumeration.

## Advanced Techniques
- Start with passive enumeration and zone transfer checks.
- Use brute-force modes only with explicit authorization.

## Safe Defaults
- Rate limits: conservative query rates on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: dns_records.json, subdomains.json

## References
- https://github.com/fwaeytens/dnsenum
