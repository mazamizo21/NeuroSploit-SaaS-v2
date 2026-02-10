# Tool: smtp-user-enum

## Overview
Use smtp-user-enum for controlled username enumeration against SMTP services.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Choose the method (VRFY/EXPN/RCPT) that is permitted and least intrusive.
2. Limit concurrency and timebox requests.
3. Record positive results and server responses.

## Deep Dives
Load references as needed:
1. ../toolcards/smtp-user-enum.md
2. references/advanced.md

## Evidence Collection
1. smtp-user-enum output logs
1. evidence.json with method and targets

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
