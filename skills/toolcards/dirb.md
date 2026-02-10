# dirb Toolcard

## Overview
- Summary: DIRB is a web content scanner that uses a dictionary to find existing or hidden web objects.

## Advanced Techniques
- Use curated wordlists and target-specific extensions to reduce noise.
- Filter response codes or sizes to focus on likely hits.

## Safe Defaults
- Rate limits: keep request rates low on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: endpoints.json, findings.json (as applicable)

## References
- https://www.kali.org/tools/dirb/
