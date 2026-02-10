# klist Toolcard

## Overview
- Summary: klist lists Kerberos ticket cache entries and their lifetimes.

## Advanced Techniques
- Use detailed listings to validate ticket renewal and expiration.
- Confirm ticket cache contents before and after access validation.

## Safe Defaults
- Rate limits: read-only.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: kerberos_tickets.json

## References
- https://web.mit.edu/kerberos/krb5-1.21/doc/user/user_commands/klist.html
