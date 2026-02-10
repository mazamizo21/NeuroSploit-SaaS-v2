# Email Security Records

## Goals
1. Validate SPF, DKIM, and DMARC records.
2. Identify weak or missing policies.
3. Record alignment and reporting configuration.

## Safe Checks
1. `dig TXT example.com +noall +answer`
2. `dig TXT _dmarc.example.com +noall +answer`
3. Check DKIM selectors if provided.

## Indicators to Record
1. SPF with `~all` or `?all`.
2. DMARC `p=none` or missing.
3. Missing DKIM for key selectors.
4. Misaligned SPF/DKIM identifiers or missing reporting addresses.

## Evidence Checklist
1. Raw TXT records.
2. Summary of SPF, DKIM, DMARC policy posture.
3. Alignment notes and reporting addresses.
