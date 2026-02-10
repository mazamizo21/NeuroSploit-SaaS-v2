# Advanced Techniques

## Example Script Selection
- Choose the Impacket example script based on the access path you need (e.g., `wmiexec.py`, `smbexec.py`, `psexec.py`, `atexec.py`, `dcomexec.py`, `secretsdump.py`, `ntlmrelayx.py`, `GetADUsers.py`, `GetNPUsers.py`, `lookupsid.py`).
- Prefer non-service execution paths when available; use service-creation tools only with explicit approval.

## Authentication Modes
- Use the credential mode supported by the script (NTLM password, NT hash, or Kerberos tickets) and keep the auth method recorded with outputs.

## Evidence
- Capture command outputs and note the specific script + auth mode used.
