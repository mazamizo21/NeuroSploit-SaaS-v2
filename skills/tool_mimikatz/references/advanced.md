# Advanced Techniques

## Credential & Ticket Operations
- Elevate privileges first (`privilege::debug`) before reading LSASS-backed secrets.
- Use `sekurlsa::logonpasswords` for credential material and `sekurlsa::tickets /export` for TGT/TGS extraction.
- Use `kerberos::list /export` to collect Kerberos tickets and `kerberos::ptt` for ticket injection when authorized.

## Evidence
- Record the specific module/command used and capture output artifacts securely.
