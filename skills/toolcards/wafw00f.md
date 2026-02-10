# wafw00f Toolcard

## Overview
- Summary: wafw00f detects and fingerprints web application firewalls by sending HTTP requests and matching responses.

## Advanced Techniques
- Use targeted scans against specific paths to reduce noise.
- Validate detections by cross-checking headers and response behavior.

## Safe Defaults
- Rate limits: avoid aggressive modes on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: tech_fingerprint.json

## References
- https://github.com/EnableSecurity/wafw00f
