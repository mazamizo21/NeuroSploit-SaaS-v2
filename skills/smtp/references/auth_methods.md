# SMTP Authentication Methods

## Goals
1. Identify supported authentication mechanisms.
2. Flag weak or legacy mechanisms.
3. Record TLS requirements for auth methods.

## Safe Checks
1. Use `smtp-commands` output to enumerate `AUTH` extensions.
2. Capture whether `STARTTLS` is advertised before auth.

## Indicators to Record
1. `AUTH LOGIN` or `PLAIN` on external endpoints without TLS.
2. Missing or misconfigured auth controls.
3. Auth methods advertised without clear TLS requirement.

## Evidence Checklist
1. Auth mechanism list.
2. Notes on TLS requirements and `STARTTLS` support.
3. Banner and capability evidence from server response.
