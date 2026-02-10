# wpscan Toolcard

## Overview
- Summary: WPScan is a WordPress vulnerability scanner for core, themes, and plugins.

## Advanced Techniques
- Use `--enumerate` to scope checks to plugins/themes/users.
- Provide an API token for vulnerability database lookups.

## Safe Defaults
- Use passive or mixed detection first.
- Rate-limit requests on production sites.
- Avoid brute-force modules unless explicitly authorized.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/wpscanteam/wpscan
- https://wpscan.com/how-to-install-wpscan/
