# joomscan Toolcard

## Overview
- Summary: OWASP JoomScan is a Joomla vulnerability scanner used to enumerate components and identify known issues.

## Advanced Techniques
- Use component enumeration to build a plugin inventory.
- Set user-agent and proxy settings for controlled scans.

## Safe Defaults
- Rate limits: keep timeouts conservative and avoid excessive concurrency.
- Scope rules: explicit target only; no credential attacks unless authorized.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.kali.org/tools/joomscan/
