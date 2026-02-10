# responder Toolcard

## Overview
- Summary: Responder is a LLMNR/NBT-NS/MDNS poisoner with built-in rogue authentication servers for protocols like SMB, HTTP, MSSQL, FTP, and LDAP.

## Advanced Techniques
- Prefer analysis-only or passive modes unless explicit authorization allows active poisoning.
- Keep capture windows short and scoped to approved segments.

## Safe Defaults
- Do not run on external targets without explicit authorization.
- Avoid any credential interception outside of approved scope.

## Evidence Outputs
- outputs: creds.json, evidence.json (as applicable)

## References
- https://github.com/SpiderLabs/Responder
