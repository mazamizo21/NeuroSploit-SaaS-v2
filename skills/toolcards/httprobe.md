# httprobe Toolcard

## Overview
- Summary: httprobe takes a list of domains and probes for working HTTP and HTTPS servers.

## Advanced Techniques
- Use curated input lists and de-duplicate targets before probing.
- Capture status and protocol results for downstream discovery.

## Safe Defaults
- Rate limits: keep probe rates low on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: endpoints.json, evidence.json (as applicable)

## References
- https://github.com/tomnomnom/httprobe
