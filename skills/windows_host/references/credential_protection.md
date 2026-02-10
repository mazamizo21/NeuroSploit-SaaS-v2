# Windows Credential Protection (Authorized Validation)

## Checks
1. Credential Guard status and virtualization-based security.
2. LSA protection (RunAsPPL) enabled.
3. WDigest disabled and cleartext logon settings.
4. NTLMv1 disabled and NTLM restrictions enforced where feasible.
5. LSASS memory access protections and protected process settings.
6. Remote credential delegation settings (RDP, WinRM) hardened.

## Evidence Capture
1. Registry or policy evidence for credential protection features.
2. GPO or security policy snapshots for NTLM and delegation settings.
