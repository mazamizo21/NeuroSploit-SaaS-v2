# Windows Escalation Vectors (Evidence-Only)

## Goals
1. Identify common escalation paths without exploitation.
2. Document service and permission weaknesses.
3. Record token privileges and group memberships.

## Safe Checks
1. Unquoted service paths.
2. Weak service permissions.
3. AlwaysInstallElevated policy.
4. Token privileges and group memberships.
5. Writable service binaries or DLL search order issues.

## Evidence Checklist
1. Misconfiguration list with evidence.
2. Service permission summary.
3. Token privilege evidence.
