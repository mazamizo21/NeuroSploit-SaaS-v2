# DNS Authority and SOA

## Goals
1. Identify authoritative name servers.
2. Capture SOA details for reporting and change tracking.
3. Record TTLs and serial changes.

## Safe Checks
1. `dig NS example.com +noall +answer`
2. `dig SOA example.com +noall +answer`

## Evidence Checklist
1. NS list and TTLs.
2. SOA record fields (primary NS, admin email, serial, refresh).
3. Notes on mismatched serials across name servers.
