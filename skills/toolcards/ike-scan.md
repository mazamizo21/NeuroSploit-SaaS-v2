# ike-scan Toolcard

## Overview
- Summary: ike-scan discovers and fingerprints IKE/IPsec VPN endpoints.

## Advanced Techniques
- Use aggressive mode checks only when explicitly authorized.
- Limit retries and scan rate for production endpoints.

## Safe Defaults
- Explicit authorization required for probing.
- Scope to in-scope IP ranges only.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/royhills/ike-scan
