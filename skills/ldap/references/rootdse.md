# LDAP RootDSE and Naming Contexts

## Goals
- Identify naming contexts and default naming context.
- Capture supported LDAP versions, controls, and SASL mechanisms.
- Record server identity metadata for reporting.

## Safe RootDSE Query
Use a base-scope query with an empty DN:
- `ldapsearch -H ldap://target -x -s base -b "" "(objectClass=*)" +
`

Prefer LDAPS or StartTLS when available, and record whether TLS is enforced.

## High-Value RootDSE Attributes
- `defaultNamingContext`
- `namingContexts`
- `supportedLDAPVersion`
- `supportedSASLMechanisms`
- `supportedControl`
- `supportedCapabilities`
- `vendorName`, `vendorVersion`
- `dnsHostName`, `ldapServiceName`, `serverName`
- `highestCommittedUSN`

## Evidence Checklist
- RootDSE LDIF output saved
- Parsed JSON summary with naming contexts and supported controls
- TLS mode noted (LDAP/LDAPS/StartTLS)

