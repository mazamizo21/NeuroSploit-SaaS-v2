# Ticket Hygiene Checks

## Goal
Assess whether ticket lifetimes, renewability, and pre-auth requirements align with policy.

## Safe Checks
- Use `klist -A` to list cached tickets and lifetimes.
- Record ticket start/end times and renewability.
- Note whether pre-auth is required based on `kinit` responses.

## Indicators to Record
- Very long ticket lifetimes or renew windows
- Non-renewable tickets where renewability is expected
- Pre-auth disabled warnings (do not exploit without authorization)

## Evidence Checklist
- `klist` output saved
- Parsed JSON summary of ticket metadata

