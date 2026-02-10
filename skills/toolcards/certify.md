# certify Toolcard

## Overview
- Summary: Certify is a C# tool from GhostPack for enumerating and identifying misconfigurations in Active Directory Certificate Services (AD CS).

## Advanced Techniques
- Use enumeration modes first to map certificate authorities and templates.
- Validate potential issues only with explicit authorization.

## Safe Defaults
- Do not request or enroll certificates without explicit authorization.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: findings.json, evidence.json (as applicable)

## References
- https://github.com/GhostPack/Certify
