# PostgreSQL Authentication and TLS

## Goals
1. Identify auth methods and TLS requirements.
2. Capture server version and connection info.
3. Record password encryption settings.

## Safe Checks
1. `SHOW ssl;`
2. `SHOW ssl_prefer_server_ciphers;`
3. `SHOW password_encryption;`
4. `SELECT version();`

## Indicators to Record
1. TLS not required on public interfaces.
2. `password_encryption` set to weak algorithms.
3. `ssl_min_protocol_version` too low.

## Evidence Checklist
1. Version and SSL settings.
2. Auth method hints (from pg_hba if accessible).
3. Password encryption settings.
