# Explicit-Only Advanced Actions

## Scope Gate
These actions require explicit authorization and should only be used when `exploit_mode=autonomous`
or documented approval exists. NEVER perform these on external targets without written permission.

## File Read Operations
- `LOAD_FILE()` on MySQL
- `pg_read_file()` / `COPY FROM` on PostgreSQL
- `OPENROWSET(BULK ...)` on MSSQL
- Reading web.config, config.php, /etc/shadow, etc.
**Authorization required:** Must have explicit approval specifying file paths or "any file"

## File Write Operations
- `INTO OUTFILE` / `INTO DUMPFILE` on MySQL
- `COPY TO` on PostgreSQL
- `xp_cmdshell echo ... >` on MSSQL
- Writing webshells to web root
**Authorization required:** Must specify target file path and content type

## OS Command Execution
- `xp_cmdshell` on MSSQL
- `COPY TO PROGRAM` on PostgreSQL
- UDF loading on MySQL
- `UTL_HTTP` / Java procedures on Oracle
**Authorization required:** Must specify command types (recon only vs reverse shell)

## Large Data Dumps
- Dumping entire user tables
- Extracting all database contents
- Password hash extraction
**Authorization required:** Must specify which tables/columns and row limits

## WAF Bypass and Evasion
- Using tamper scripts or encoding to bypass security controls
- Chunked transfer encoding manipulation
- Parameter pollution attacks
**Authorization required:** Target must be explicitly approved for WAF testing

## Stacked Queries for Data Modification
- CREATE TABLE, DROP TABLE, INSERT, UPDATE, DELETE
- Creating new database users
- Modifying existing data
**Authorization required:** EXTREME CAUTION — can cause data loss

## Evidence Guidelines
- Capture minimal proof of impact
- Redact ALL sensitive values (passwords, PII, keys)
- Document the exact scope of authorization
- Screenshot the approval before proceeding
- Log all commands executed with timestamps
