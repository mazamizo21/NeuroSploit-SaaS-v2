# SMTP Capabilities

## Goals
1. Capture EHLO extensions and supported commands.
2. Identify auth mechanisms and size limits.
3. Confirm TLS and message size posture.

## Safe Checks
1. Use `nmap --script smtp-commands`.
2. Use manual `EHLO` only with explicit scope and low rate.

## Indicators to Record
1. `STARTTLS` support.
2. `AUTH` mechanisms.
3. `SIZE` limits and `8BITMIME` support.
4. `PIPELINING`, `CHUNKING`, or other notable extensions.

## Evidence Checklist
1. Script output captured.
2. Summary of SMTP extensions.
3. Banner and server identity evidence.
