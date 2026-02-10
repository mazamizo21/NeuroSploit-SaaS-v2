# Advanced Techniques

## Auth & Transport
- Use `-H` for pass-the-hash auth when NTLM is allowed, and `-S` for SSL/TLS endpoints.
- Use `-s` to load a local script directory (PowerShell helpers) and `-e` for a local files directory when staging tools.

## Session Discipline
- Keep transcript logs of executed commands and file transfers for evidence.
- Prefer minimal command sets to avoid excessive host impact.
