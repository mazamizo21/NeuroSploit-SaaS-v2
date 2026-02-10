# MySQL Secure Configuration

## Goals
1. Identify risky server settings without changing configuration.
2. Capture key security variables.
3. Record logging and network exposure posture.

## Safe Checks
1. `SHOW VARIABLES LIKE 'local_infile';`
2. `SHOW VARIABLES LIKE 'log_error';`
3. `SHOW VARIABLES LIKE 'skip_name_resolve';`
4. `SHOW VARIABLES LIKE 'bind_address';`
5. `SHOW VARIABLES LIKE 'general_log';`

## Indicators to Record
1. `local_infile` enabled.
2. Error log disabled or inaccessible.
3. Name resolution enabled on exposed servers.
4. Bound to all interfaces when not required.

## Evidence Checklist
1. Security variable values.
2. Notes on risky settings.
3. Log configuration evidence.
