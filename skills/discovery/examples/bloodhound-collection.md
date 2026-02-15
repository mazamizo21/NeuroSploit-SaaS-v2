# BloodHound Data Collection

## Scenario
Domain user access on MEGACORP.LOCAL, need to map AD attack paths.

## Collection
```bash
$ bloodhound-python -u jsmith -p 'W1nt3r2025!' -d megacorp.local -dc dc01.megacorp.local -c all --zip

INFO: Found AD domain: megacorp.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.megacorp.local
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 247 computers
INFO: Found 1823 users
INFO: Found 156 groups
INFO: Found 12 trusts
INFO: Found 89 GPOs
INFO: Found 34 OUs
INFO: Found 18 containers
INFO: Done in 00M 45S
INFO: Compressing output into 20250115153022_bloodhound.zip
```

## High-Value Findings from BloodHound

### Shortest Path to Domain Admin
```
jsmith (Domain User)
  → MemberOf: IT Helpdesk
    → GenericWrite on: svc_web (service account)
      → svc_web has SPN → Targeted Kerberoast
        → svc_web: MemberOf: Server Operators
          → Server Operators: Service control on DC01
            → Modify service → SYSTEM on DC → DCSync
```

### Kerberoastable Users (High Value)
| Account | SPN | Group Membership |
|---------|-----|-----------------|
| svc_sql | MSSQLSvc/sql01:1433 | IT Operations |
| svc_web | HTTP/intranet | Server Operators |
| svc_backup | CIFS/file01 | Backup Operators |

### AS-REP Roastable Users
| Account | Last Logon | Notes |
|---------|------------|-------|
| old_admin | 2023-06-15 | Stale account, DONT_REQ_PREAUTH set |

### Unconstrained Delegation
| Computer | Notes |
|----------|-------|
| WEB01$ | Unconstrained delegation — PrinterBug/coercion target |

## Next Steps
→ **credential_access skill**: Kerberoast svc_web (path to DA)
→ **privilege_escalation skill**: Abuse GenericWrite on svc_web (set SPN for targeted Kerberoast)
→ **lateral_movement skill**: PrinterBug → Unconstrained delegation on WEB01
