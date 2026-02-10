# linpeas Toolcard

## Overview
- Summary: linPEAS is part of the PEASS-ng suite and helps identify local privilege escalation misconfigurations on Linux and Unix systems.

## Advanced Techniques
- Focus on high-signal checks and minimize sensitive output collection.
- Use `-a` for all checks only when authorized; default to scoped modes.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Treat output as sensitive and minimize data collection.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.kali.org/tools/peass-ng/
