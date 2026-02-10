# MongoDB Roles and Privileges

## Goals
1. Identify built-in roles and privileged users.
2. Confirm least-privilege assignments.
3. Record role inheritance and custom role actions.

## Safe Checks
1. `db.getSiblingDB(\"admin\").getUsers()` (authorized)
2. `db.getRoles({showBuiltinRoles: true})` (authorized)
3. `db.getRoles({showBuiltinRoles: false, showPrivileges: true})` (authorized)

## Indicators to Record
1. Users with `root` or `dbOwner` roles.
2. Roles granting wildcard actions.
3. Custom roles with broad privileges.

## Evidence Checklist
1. Role list summary.
2. Privileged user count.
3. Custom role privilege evidence.
