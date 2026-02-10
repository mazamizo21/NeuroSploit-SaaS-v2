# bloodyad Toolcard

## Overview
- Summary: BloodyAD is an Active Directory privilege escalation framework that performs LDAP operations against a domain controller to execute AD privilege escalation paths.

## Advanced Techniques
- Use the authentication mode that matches approved access (cleartext, pass-the-hash, pass-the-ticket, certificates).
- Prefer LDAPS when sensitive attributes are involved.
- Use SOCKS proxy support when operating through approved pivots.

## Safe Defaults
- Scope rules: explicit target only.
- Avoid modifying directory objects unless explicitly authorized.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/CravateRouge/bloodyAD
