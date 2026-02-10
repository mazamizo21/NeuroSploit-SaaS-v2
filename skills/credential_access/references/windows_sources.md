# Windows Credential Sources (Evidence-Only)

## Goals
1. Identify common credential storage locations.
2. Validate exposure without persistence or disruption.
3. Record access context and authorization.

## Typical Sources
- LSASS memory (requires explicit authorization)
- SAM/SYSTEM/SECURITY hives (offline)
- DPAPI-protected secrets (user scope)
- Credential Manager and browser stores

## Safe Handling
1. Capture minimal proof of exposure.
2. Redact sensitive values in evidence.
3. Avoid dumping full secret contents.
