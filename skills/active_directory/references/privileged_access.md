# Privileged Access Review

## Priority Groups
- Domain Admins, Enterprise Admins, Schema Admins
- Account Operators, Server Operators, Backup Operators
- Administrators and local admin equivalents

## Access Mapping
- Identify users with elevated group memberships.
- Map group nesting that grants admin access.
- Note high-risk delegation and admin-to-host relationships.

## Capture
- Summarize privileged group membership in `ad_groups.json`.
- Record risky exposures in `findings.json`.
