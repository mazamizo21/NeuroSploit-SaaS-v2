# sqlcmd Toolcard

## Overview
- Summary: sqlcmd is the command-line utility for SQL Server using the modern go-sqlcmd implementation.

## Advanced Techniques
- Use `-Q` for one-shot read-only queries.
- Use `-C` and encryption flags where applicable.

## Safe Defaults
- Rate limits: avoid repeated auth attempts on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: db_access.json

## References
- https://github.com/microsoft/go-sqlcmd
