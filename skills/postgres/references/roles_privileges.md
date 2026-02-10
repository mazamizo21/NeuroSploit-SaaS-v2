# PostgreSQL Roles and Privileges

## Goals
1. Identify superusers and high-privilege roles.
2. Confirm least-privilege access.
3. Record role inheritance and membership.

## Safe Checks
1. `\\du` or `SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles;`
2. `SELECT datname FROM pg_database;`
3. `SELECT roleid::regrole, member::regrole FROM pg_auth_members;`

## Indicators to Record
1. Excessive superuser roles.
2. Roles with create role or create DB privileges.
3. Unusual role memberships or inherited privileges.

## Evidence Checklist
1. Role list and privilege flags.
2. Database list summary.
3. Role membership evidence.
