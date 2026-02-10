# Advanced Techniques

## IPv6 Coercion Workflow
- Mitm6 abuses IPv6 (RA + DNS) to coerce clients in IPv4 networks; use it only on explicitly in-scope domains.
- Pair mitm6 with an NTLM relay tool (e.g., `ntlmrelayx.py`) to validate captured auth in a controlled way.

## Scope Controls
- Use domain scoping options to restrict spoofing to the engagement domain and keep logs of any coerced hosts.

## Evidence
- Record target hostnames, coerced traffic timestamps, and any relay results.
