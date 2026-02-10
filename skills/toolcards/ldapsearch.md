# ldapsearch Toolcard

## Overview
- Summary: ldapsearch is an OpenLDAP client for querying LDAP directories and retrieving entries, including RootDSE metadata.

## Advanced Techniques
- Query RootDSE to capture naming contexts and supported capabilities.
- Use scoped filters and attribute lists to reduce output volume.

## Safe Defaults
- Rate limits: keep query scope narrow on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: ldap_rootdse.json, ldap_objects.json

## References
- https://man7.org/linux/man-pages/man1/ldapsearch.1.html
