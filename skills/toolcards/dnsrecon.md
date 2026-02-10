# dnsrecon Toolcard

## Overview
- Summary: dnsrecon performs DNS reconnaissance including record enumeration, zone transfer attempts, and brute-force discovery.

## Advanced Techniques
- Use standard enumeration first, then escalate to brute force only when authorized.
- Capture authoritative servers and SOA records for evidence.

## Safe Defaults
- Rate limits: conservative query rates on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: dns_records.json, subdomains.json

## References
- https://github.com/darkoperator/dnsrecon
