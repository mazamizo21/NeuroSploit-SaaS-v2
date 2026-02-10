# SSH Authentication Methods

## Goals
1. Identify enabled authentication methods.
2. Flag risky methods on internet-exposed endpoints.
3. Record whether multi-factor or keyboard-interactive is required.

## Safe Checks
1. Use `nmap --script ssh-auth-methods`.
2. Record supported methods such as `publickey`, `password`, `keyboard-interactive`.

## Indicators to Record
1. Password authentication enabled on external endpoints.
2. Deprecated methods.
3. No banner indicating required MFA where expected.

## Evidence Checklist
1. Script output captured.
2. Summary of auth methods.
3. Notes on MFA or keyboard-interactive requirements.
