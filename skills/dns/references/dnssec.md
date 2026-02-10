# DNSSEC Posture

## Goals
1. Determine whether DNSSEC is enabled.
2. Capture DS and DNSKEY records where available.
3. Record validation status and errors.

## Safe Checks
1. `dig +dnssec example.com`
2. `dig DNSKEY example.com +noall +answer`
3. `dig DS example.com +noall +answer`

## Indicators to Record
1. DNSSEC enabled or missing.
2. Mismatched or missing DS records.
3. Validation failures or bogus responses.

## Evidence Checklist
1. DNSKEY and DS record outputs.
2. Notes on validation failures.
3. Resolver used and query timestamps.
