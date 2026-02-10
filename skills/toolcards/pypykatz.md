# pypykatz Toolcard

## Overview
- Summary: pypykatz is a Python implementation of Mimikatz that can parse LSASS minidumps and credential material from Windows systems.

## Advanced Techniques
- Use it for offline parsing of dumps to reduce impact on target systems.
- Correlate extracted material with ticket metadata for evidence.

## Safe Defaults
- Do not run on external targets without explicit authorization.
- Handle extracted material under approved evidence controls.

## Evidence Outputs
- outputs: creds.json, evidence.json (as applicable)

## References
- https://github.com/skelsec/pypykatz
