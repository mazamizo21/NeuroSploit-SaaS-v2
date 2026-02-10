# Anonymous Bind Validation

## Goal
Determine whether anonymous binds allow directory access beyond RootDSE.

## Safe Check
1. Query RootDSE without credentials.
2. Attempt a scoped search on a single naming context with a small size limit:
   - Use `-z` to cap results and avoid heavy queries.

Example:
- `ldapsearch -H ldap://target -x -b "dc=example,dc=com" -s sub -z 5 "(objectClass=*)"`

## What to Record
- Bind result and any access errors.
- Whether objects or attributes were returned without credentials.
- Whether sensitive attributes were exposed (e.g., email, phone, group membership).

## Evidence Checklist
- Raw output showing anonymous bind results
- JSON summary of exposed object types and attributes
- Scope context and target naming context

## Notes
Avoid repeating failed binds or running high-volume enumeration without explicit authorization.

