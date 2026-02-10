# DBMS Fingerprinting

## Goals
- Identify the backend DBMS safely.
- Use minimal queries or error messages.

## Safe Checks
- Error message patterns
- Version functions (read-only):
  - MySQL: `SELECT @@version`
  - PostgreSQL: `SELECT version()`
  - SQL Server: `SELECT @@version`

## Evidence Checklist
- DBMS type and version
- Source of fingerprint evidence

