# Domain Discovery Checklist

## Goals
- Identify domain/forest names, domain controllers, sites, and trusts.
- Capture naming contexts and key LDAP base DNs.

## Lightweight Steps
- RootDSE query to capture naming contexts and supported LDAP features.
- SMB/NetBIOS domain info to confirm domain name and role.
- Enumerate DC hostnames and IPs with minimal queries.

## Capture
- `ad_summary.json` should include: domain, forest, dc_list, sites, trusts.
- Record the exact commands and outputs in `evidence.json`.
