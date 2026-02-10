# MySQL Privilege Review

## Goals
1. Identify overly permissive users and grants.
2. Confirm least-privilege access.
3. Record anonymous or wildcard access.

## Safe Checks
1. `SHOW GRANTS FOR CURRENT_USER;`
2. `SELECT user, host, account_locked FROM mysql.user;` (authorized)
3. `SHOW VARIABLES LIKE 'validate_password%';`

## Indicators to Record
1. Accounts with `ALL PRIVILEGES` on `*.*`.
2. Anonymous users or wildcard hosts.
3. Weak password policy.
4. Users with `GRANT OPTION` without need.

## Evidence Checklist
1. Grants list.
2. Account summary (redacted).
3. Host patterns and privilege flags.
