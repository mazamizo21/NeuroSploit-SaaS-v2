# POP3 Capabilities

## Goals
1. Capture POP3 capability list.
2. Identify extensions and auth mechanisms.
3. Confirm STLS and login posture.

## Safe Checks
1. Use `nmap --script pop3-capabilities`.
2. Avoid login unless explicitly authorized.

## Indicators to Record
1. `STLS` capability.
2. `SASL` or `AUTH` mechanisms.
3. Notable extensions such as `UIDL` or `TOP`.

## Evidence Checklist
1. Script output captured.
2. Summary of POP3 capabilities.
3. Banner and capability evidence.
