# Explicit-Only Kerberos Abuse Checks

## Scope Gate
These actions require explicit authorization and should be performed only when `exploit_mode=autonomous` or explicit approval is recorded.

## Examples of Explicit-Only Actions
- User enumeration and password spraying
- AS-REP roasting or Kerberoasting
- Delegation abuse validation
- Ticket forging or key material extraction

## Evidence Guidelines
If authorized, capture minimal proof:
- Command output snippets
- Target principal names only (no secrets)
- Clear scope and approval reference

