# rpcclient Toolcard

## Overview
- Summary: rpcclient is a Samba client used to execute MS-RPC functions against Windows hosts over SMB for administration and enumeration.

## Advanced Techniques
- Use the `-c` option to run a limited set of RPC commands in one session.
- Choose appropriate binding transports and keep queries read-only when possible.

## Safe Defaults
- Avoid repeated authentication attempts on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
