# DNS Zone Transfer Checks

## Scope Gate
Attempt AXFR only against explicitly authorized name servers.

## Safe Checks
1. `dig AXFR example.com @ns1.example.com`
2. Stop immediately if refused.

## Indicators to Record
1. Successful transfer with record count.
2. Transfer refused or blocked.
3. Partial transfers or truncated responses.

## Evidence Checklist
1. Raw AXFR output if successful.
2. Record count summary.
3. Name server response codes and timestamps.
