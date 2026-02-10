# Windows Hardening Checklist (Read-Only)

## Checks
1. Defender/EDR status and tamper protection enabled.
2. Firewall profile enabled (Domain/Private/Public) with inbound defaults.
3. BitLocker status and recovery key protection.
4. Local admin password solution (LAPS) presence.
5. SMB signing required and SMBv1 disabled.
6. NTLM restrictions and LMCompatibilityLevel hardened.
7. RDP exposure limited and NLA enforced if RDP is enabled.
8. UAC level set to high and local admin elevation prompts enabled.
9. Attack Surface Reduction or application allowlisting in use.
10. Local admin group membership minimized and documented.

## Evidence Capture
1. Control status summaries and policy flags.
2. Security policy exports or registry values showing hardening settings.
- Configuration snippets showing enabled/disabled states.
