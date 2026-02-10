# POP3 Authentication Methods

## Goals
1. Identify supported auth mechanisms.
2. Flag weak or legacy methods.
3. Record TLS requirements for auth methods.

## Safe Checks
1. Use `pop3-capabilities` output to enumerate `SASL` or `AUTH` values.
2. Confirm whether `STLS` is available before auth.

## Indicators to Record
1. Plain auth on plaintext ports.
2. Missing or misconfigured TLS requirements.
3. Auth methods advertised without `STLS`.

## Evidence Checklist
1. Auth mechanism list.
2. Notes on TLS enforcement and `STLS`.
3. Capability output snippets.
