# PostgreSQL Security Settings

## Goals
1. Identify risky configuration values.
2. Capture log and connection settings.
3. Record network exposure controls.

## Safe Checks
1. `SHOW log_connections;`
2. `SHOW log_disconnections;`
3. `SHOW log_statement;`
4. `SHOW password_encryption;`
5. `SHOW ssl_min_protocol_version;`
6. `SHOW listen_addresses;`

## Indicators to Record
1. Logging disabled.
2. Weak password encryption.
3. `listen_addresses` set to `*` without network controls.

## Evidence Checklist
1. Security settings values.
2. Notes on risky configuration.
3. Logging posture and network exposure evidence.
