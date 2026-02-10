# CSP and Mitigations

## Goals
- Identify whether CSP blocks execution.
- Record CSP headers and directives.

## Safe Checks
- Capture `Content-Security-Policy` header.
- Validate whether inline scripts are allowed.

## Indicators to Record
- `unsafe-inline` presence
- Missing CSP on sensitive endpoints

## Evidence Checklist
- CSP header values
- Notes on enforcement behavior

