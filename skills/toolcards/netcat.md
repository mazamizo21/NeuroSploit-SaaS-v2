# netcat Toolcard

## Overview
- Summary: netcat is a utility for reading from and writing to network connections using TCP or UDP.

## Advanced Techniques
- Use verbose mode for banner capture and timing analysis.
- Prefer short, targeted connections to reduce noise.

## Safe Defaults
- Rate limits: avoid repeated connection attempts on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://man.openbsd.org/nc.1
