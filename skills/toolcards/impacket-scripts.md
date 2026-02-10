# impacket-scripts Toolcard

## Overview
- Summary: Impacket is a collection of Python classes and example scripts for working with network protocols, shipped in Kali as multiple `impacket-*` utilities such as `impacket-secretsdump` and `impacket-wmiexec`.

## Advanced Techniques
- Use the least-privileged script that satisfies the validation goal.
- Prefer read-only or metadata queries unless explicit authorization is confirmed.

## Safe Defaults
- Avoid repeated authentication attempts on external targets.
- Capture only minimal evidence required for findings.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.kali.org/tools/impacket/
