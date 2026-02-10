# SMB Dialects and Signing

## Goals
1. Identify supported SMB dialects and signing requirements.
2. Flag SMBv1 exposure and weak signing posture.
3. Record encryption support when available.

## Safe Checks
1. Use `nmap` scripts: `smb-protocols` and `smb2-security-mode`.
2. Record SMB signing as required, enabled, or disabled.

## Indicators to Record
1. SMBv1 enabled.
2. SMB signing not required on servers handling sensitive data.
3. Guest access enabled.
4. SMB encryption disabled where required.

## Evidence Checklist
1. Script output captured.
2. Summary of dialects and signing requirements.
3. Notes on encryption or guest access posture.
