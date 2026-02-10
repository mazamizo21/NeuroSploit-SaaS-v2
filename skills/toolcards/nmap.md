# nmap Toolcard

## Overview
- Summary: Nmap is a network exploration and security auditing tool that supports host discovery, port scanning, service/version detection, OS fingerprinting, and scripting via NSE. It supports many scan techniques and flexible target specification.

## Advanced Techniques
- Use `-A` for combined OS detection, version detection, script scanning, and traceroute on smaller scopes.
- Use NSE scripts for targeted checks (`--script`), but prefer service-specific scripts over broad categories.
- Use `ssh2-enum-algos` for SSH algorithm discovery and `smb-protocols` or `smb2-security-mode` for SMB.
- Use `ndiff` to compare XML outputs between scans and spot deltas over time.

## Safe Defaults
- Rate limits: use conservative timing (`-T3`) on external targets; increase only with explicit authorization.
- Scope rules: explicit target only

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://nmap.org/docs.html
