# sqlsus Toolcard

## Overview
- Summary: sqlsus is an open source SQL injection tool focused on MySQL.

## Advanced Techniques
- Use only after injection is confirmed and scope is explicit.
- Prefer minimal proof-of-impact checks and avoid destructive actions.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Do not execute exploit chains by default; treat output as triage input.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.kali.org/tools/sqlsus/
