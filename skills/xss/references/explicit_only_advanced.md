# Explicit-Only Advanced Actions

## Scope Gate
These actions require explicit authorization and should only be used when `exploit_mode=autonomous`
or documented approval exists.

## Examples
- Credential capture or session token collection
- Payloads that affect other users (stored XSS)
- Browser exploitation frameworks

## Evidence Guidelines
- Capture minimal proof of impact
- Redact sensitive tokens or personal data
- Document approval scope

