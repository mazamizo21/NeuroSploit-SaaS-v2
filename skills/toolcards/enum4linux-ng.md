# enum4linux-ng Toolcard

## Overview
- Summary: enum4linux-ng is the modern rewrite of enum4linux that gathers SMB/NetBIOS and Active Directory information with structured output options.

## Advanced Techniques
- Use JSON/YAML output for evidence ingestion.
- Focus enumeration on approved domains and hosts to reduce noise.

## Safe Defaults
- Avoid brute force or password spraying on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: smb_shares.json, findings.json (as applicable)

## References
- https://github.com/cddmp/enum4linux-ng
