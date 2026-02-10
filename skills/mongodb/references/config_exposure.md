# MongoDB Configuration Exposure

## Goals
1. Identify exposed admin interfaces or misconfigurations.
2. Capture server parameters related to security.
3. Record audit and logging posture where available.

## Safe Checks
1. `db.adminCommand({getParameter: '*'})` (authorized, use caution)
2. `db.adminCommand({serverStatus:1})` (authorized, metadata only)
3. `db.adminCommand({getLog: 'startupWarnings'})` (metadata only)

## Indicators to Record
1. `net.bindIp` set to all interfaces.
2. `security.authorization` disabled.
3. `enableLocalhostAuthBypass` enabled (legacy).
4. Audit logging disabled when required.

## Evidence Checklist
1. Server parameter summary.
2. Notes on exposure indicators.
3. Startup warnings and audit posture evidence.
