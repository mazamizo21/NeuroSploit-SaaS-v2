# IMAP Authentication Methods

## Goals
1. Identify supported auth mechanisms.
2. Flag weak or legacy methods.
3. Record TLS requirements for auth methods.

## Safe Checks
1. Use `imap-capabilities` output to enumerate `AUTH=` values.
2. Confirm whether `LOGINDISABLED` is set pre-TLS.

## Indicators to Record
1. `AUTH=PLAIN` or `AUTH=LOGIN` on plaintext ports.
2. Missing or misconfigured TLS requirements.
3. Absence of `LOGINDISABLED` before TLS.

## Evidence Checklist
1. Auth mechanism list.
2. Notes on TLS enforcement and `LOGINDISABLED`.
3. Capability output snippets.
