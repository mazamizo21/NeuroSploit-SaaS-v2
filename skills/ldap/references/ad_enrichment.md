# AD-Enriched LDAP Enumeration

## Goal
Perform safe, scoped enumeration that builds useful security context without high-volume queries.

## Recommended Safe Queries
- Users: `(&(objectClass=user)(!(objectClass=computer)))`
- Computers: `(objectClass=computer)`
- Groups: `(objectClass=group)`
- Domain Controllers: `(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))`

Apply size limits and attribute filters where possible:
- `-z 200` to cap results
- `-A` to skip attribute values for inventory-only counts
- Request minimal attributes: `sAMAccountName`, `distinguishedName`, `memberOf`

## AD-Integrated DNS (Scoped)
If AD DNS is in scope, use `adidnsdump` with provided credentials and record zone names only. Avoid bulk record dumps without explicit authorization.

## Sensitive Attribute Handling
If attributes like `ms-Mcs-AdmPwd`, `msDS-ManagedPassword`, or `servicePrincipalName` are exposed, record presence and scope only. Do not attempt credential abuse unless explicitly authorized.

## Evidence Checklist
- Object counts by class
- Group membership samples (small, scoped)
- AD DNS zone list (if in scope)
- Evidence of sensitive attribute exposure (metadata only)

