# smtp-user-enum Toolcard

## Overview
- Summary: smtp-user-enum enumerates users on SMTP servers using commands like VRFY, EXPN, and RCPT.

## Advanced Techniques
- Prefer RCPT checks when VRFY/EXPN are disabled.
- Use targeted user lists to reduce noise.

## Safe Defaults
- Require explicit authorization for user enumeration on external targets (external_exploit=explicit_only).
- Rate limits: keep low and stop on lockout signals.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/cytopia/smtp-user-enum
