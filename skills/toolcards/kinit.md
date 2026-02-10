# kinit Toolcard

## Overview
- Summary: kinit obtains Kerberos tickets and stores them in a credential cache for subsequent Kerberos operations.

## Advanced Techniques
- Use keytabs for service accounts when available.
- Validate ticket lifetimes and renewability after acquisition.

## Safe Defaults
- Rate limits: avoid repeated auth attempts on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: kerberos_tickets.json

## References
- https://web.mit.edu/kerberos/krb5-1.21/doc/user/user_commands/kinit.html
