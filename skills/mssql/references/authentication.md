# MSSQL Authentication Modes

## Goal
Identify authentication mode and encryption posture without changing configuration.

## Safe Checks
- Use `nmap` scripts (`ms-sql-info`, `ms-sql-ntlm-info`).
- Attempt login only with provided credentials.
 - Capture `encrypt` and `trust_server_certificate` client settings when available.

## Indicators
- Windows authentication vs SQL authentication signals
- Encryption requirements or force-encryption settings
 - Mixed mode enabled on external endpoints

## Evidence Checklist
- Script output showing auth mode hints
- Successful/failed auth attempts with timestamps
 - TLS posture evidence and server certificate metadata
