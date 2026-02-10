# mysql Toolcard

## Overview
- Summary: mysql is the official command-line client for connecting to MySQL and MariaDB servers.

## Advanced Techniques
- Use option files or login paths to avoid passwords on the command line.
- Run read-only metadata queries to enumerate databases and user grants.

## Safe Defaults
- Rate limits: avoid repeated auth attempts on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: db_access.json

## References
- https://dev.mysql.com/doc/refman/en/mysql.html
