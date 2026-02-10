# amass Toolcard

## Overview
- Summary: OWASP Amass maps attack surfaces using passive and active discovery and multiple data sources.

## Advanced Techniques
- Use intel and enum modes to separate passive discovery from active enumeration.
- Leverage the Amass database for tracking and diffing results across runs.

## Safe Defaults
- Rate limits: prefer passive collection on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: subdomains.json, dns_records.json

## References
- https://owasp.org/www-project-amass/
- https://github.com/owasp-amass/amass/wiki/User-Guide
