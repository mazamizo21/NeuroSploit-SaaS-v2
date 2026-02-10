# droopescan Toolcard

## Overview
- Summary: Droopescan is a plugin-based scanner that detects and enumerates CMS installations like Drupal and Joomla.

## Advanced Techniques
- Use the CMS-specific scan module for targeted enumeration.
- Capture version and module/plugin identifiers for follow-up validation.

## Safe Defaults
- Rate limits: keep scans lightweight on production sites.
- Scope rules: explicit target only; avoid brute force unless authorized.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/SamJoan/droopescan
