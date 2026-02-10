# Redis Authentication Posture

## Goals
1. Identify whether authentication is required.
2. Capture version and configuration context.
3. Record protected-mode and ACL posture.

## Safe Checks
1. `redis-cli INFO`
2. `redis-cli CONFIG GET requirepass` (authorized)
3. `redis-cli ACL LIST` (authorized, metadata only)

## Indicators to Record
1. `requirepass` empty on exposed endpoints.
2. `protected-mode` disabled.
3. Default user with full access.

## Evidence Checklist
1. INFO output summary.
2. Auth requirement status.
3. ACL configuration summary (redacted).
