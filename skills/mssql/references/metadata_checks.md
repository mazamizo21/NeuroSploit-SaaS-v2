# MSSQL Metadata Checks (Read-Only)

## Goal
Inventory databases, logins, and roles with minimal queries.

## Safe Queries
- `SELECT @@VERSION;`
- `SELECT name FROM sys.databases;`
- `SELECT name, type_desc FROM sys.server_principals WHERE type IN ('S', 'U');`
- `SELECT name, is_disabled FROM sys.server_principals WHERE type_desc = 'SQL_LOGIN';`

Use `SET NOCOUNT ON;` to reduce noise and prefer JSON output where possible.

## Evidence Checklist
- Database list and counts
- Login inventory (no password data)
- Role membership samples (scoped)
 - Instance name and version evidence
