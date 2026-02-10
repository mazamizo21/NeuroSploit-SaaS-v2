# MSSQL Configuration Review (Read-Only)

## Goal
Identify risky settings without enabling or changing anything.

## Safe Queries
- `SELECT name, value_in_use FROM sys.configurations;`
- `SELECT is_trustworthy_on FROM sys.databases;`
- `SELECT name, provider_string FROM sys.servers;` (linked servers)

## Risky Settings to Flag
- `xp_cmdshell` enabled
- `Ad Hoc Distributed Queries` enabled
- `CLR Enabled` enabled
- Untrusted databases with elevated privileges
 - `Ole Automation Procedures` enabled
 - `Cross DB ownership chaining` enabled

## Evidence Checklist
- Configuration values captured
- Linked server inventory
- Findings tied to specific configuration rows
