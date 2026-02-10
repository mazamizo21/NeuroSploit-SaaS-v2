# ldapdomaindump Toolcard

## Overview
- Summary: ldapdomaindump collects LDAP directory information and exports results in structured formats for analysis.

## Advanced Techniques
- Use it after RootDSE discovery to confirm naming contexts and credentials.
- Limit scope to reduce exposure and noise on external targets.

## Safe Defaults
- Rate limits: avoid repeated full dumps on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: ldap_objects.json

## References
- https://github.com/dirkjanm/ldapdomaindump
