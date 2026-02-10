# Redis Configuration Hardening

## Goals
1. Capture key configuration values related to security.
2. Identify risky default settings.
3. Record network exposure and command restrictions.

## Safe Checks
1. `redis-cli CONFIG GET *` (authorized, use sparingly)
2. `redis-cli INFO server`
3. `redis-cli CONFIG GET bind` (authorized)

## Indicators to Record
1. `protected-mode` disabled.
2. `bind` set to 0.0.0.0.
3. `rename-command` unused for dangerous commands.
4. `requirepass` or ACLs missing on exposed instances.

## Evidence Checklist
1. Config values (redacted).
2. Notes on risky settings.
3. Network exposure and bind evidence.
