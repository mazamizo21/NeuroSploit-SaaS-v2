# ffuf Toolcard

## Overview
- Summary: ffuf is a fast web fuzzer that uses the FUZZ keyword for payload placement and supports matchers and filters to reduce noise.

## Advanced Techniques
- Use matchers and filters to focus on relevant status codes, sizes, or words.
- Apply recursion or multiple wordlists for deep content discovery.
- Rate-limit requests on external targets.

## Safe Defaults
- Rate limits: keep low request rates for external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: endpoints.json, findings.json (as applicable)

## References
- https://github.com/ffuf/ffuf
