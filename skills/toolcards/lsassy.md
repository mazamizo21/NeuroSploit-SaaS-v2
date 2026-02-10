# lsassy Toolcard

## Overview
- Summary: lsassy is a Python tool to remotely extract credentials from LSASS on Windows hosts, parsing dumps with pypykatz.

## Advanced Techniques
- Use read-only collection options that avoid disk writes when authorized.
- Limit targets to approved hosts and short collection windows.

## Safe Defaults
- Do not run on external targets without explicit authorization.
- Coordinate with defenders to avoid endpoint protection disruption.

## Evidence Outputs
- outputs: creds.json, evidence.json (as applicable)

## References
- https://pypi.org/project/lsassy/
- https://github.com/Hackndo/lsassy
