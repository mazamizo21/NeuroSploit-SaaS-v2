# sqlmap Toolcard

## Overview
- Summary: sqlmap automates detection and exploitation of SQL injection, supporting multiple techniques (boolean, error, union, stacked, time‑based) and DBMS fingerprinting.

## Advanced Techniques
- Use `-hh` for advanced options and fine‑grained tuning.
- Increase test depth with `--level` and risk with `--risk` only when authorized.
- Use `--tamper` scripts to bypass basic WAF filtering when needed.

## Safe Defaults
- Rate limits: keep concurrency low and use `--delay` for fragile targets.
- Scope rules: explicit target only

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- Kali tool page: https://www.kali.org/tools/sqlmap/
