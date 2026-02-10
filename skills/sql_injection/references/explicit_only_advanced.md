# Explicit-Only Advanced Actions

## Scope Gate
These actions require explicit authorization and should only be used when `exploit_mode=autonomous`
or documented approval exists.

## Examples
- File read/write via database functions
- Large data dumps
- OS command execution or shells
- WAF bypass and tamper scripts

## Evidence Guidelines
- Capture minimal proof of impact
- Redact sensitive values
- Document approval scope

