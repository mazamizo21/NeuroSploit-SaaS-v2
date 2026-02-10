# IMAP Capabilities

## Goals
1. Capture IMAP capability list.
2. Identify extensions and auth mechanisms.
3. Confirm STARTTLS and login controls.

## Safe Checks
1. Use `nmap --script imap-capabilities`.
2. Avoid login unless explicitly authorized.

## Indicators to Record
1. `STARTTLS` capability.
2. `AUTH=PLAIN` or `AUTH=LOGIN`.
3. `LOGINDISABLED` in plaintext mode.
4. Notable extensions such as `ID`, `IDLE`, or `ENABLE`.

## Evidence Checklist
1. Script output captured.
2. Summary of IMAP capabilities.
3. Banner and capability evidence.
