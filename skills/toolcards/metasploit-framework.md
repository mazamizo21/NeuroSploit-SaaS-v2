# metasploit-framework Toolcard

## Overview
- Summary: Metasploit Framework is an open source penetration testing framework with modules for validation, exploitation, and post-exploitation workflows.

## Advanced Techniques
- Prefer auxiliary modules for safe validation and limit module settings to explicit scope.
- Use workspaces to separate targets, evidence, and findings.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Stop after minimal proof of impact and avoid destructive modules by default.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://docs.rapid7.com/metasploit/metasploit-framework/
- https://github.com/rapid7/metasploit-framework
