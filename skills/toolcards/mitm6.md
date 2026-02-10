# mitm6 Toolcard

## Overview
- Summary: mitm6 is a pentest tool that exploits default Windows IPv6 settings by advertising itself as the DNS server, which can enable traffic interception in dual-stack networks.

## Advanced Techniques
- Use only in tightly scoped lab or explicitly authorized internal assessments.
- Pair with defensive monitoring to measure impact and exposure.

## Safe Defaults
- Avoid running in production without explicit authorization.
- Keep runtime short and clearly documented for incident response teams.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/dirkjanm/mitm6
