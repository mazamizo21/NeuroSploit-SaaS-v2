# certipy Toolcard

## Overview
- Summary: Certipy is an Active Directory Certificate Services (AD CS) tool for enumeration and abuse paths such as ESC1–ESC16.

## Advanced Techniques
- Use the find/enumeration modes to map certificate templates and CA configuration first.
- Validate exploitation paths only with explicit authorization.

## Safe Defaults
- Avoid certificate requests or enrollment abuse unless explicitly authorized.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: findings.json, evidence.json (as applicable)

## References
- https://github.com/ly4k/Certipy
