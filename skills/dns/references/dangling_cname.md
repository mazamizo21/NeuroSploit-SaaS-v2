# Dangling CNAME Checks

## Goals
1. Identify CNAMEs pointing to decommissioned services.
2. Reduce false positives by validating target resolution.
3. Record provider-specific evidence for takeover risk.

## Safe Checks
1. Resolve CNAME targets and check for NXDOMAIN.
2. Verify provider-specific error banners if accessible.
3. Confirm ownership status when possible (no changes).

## Indicators to Record
1. CNAME pointing to unresolvable target.
2. Target resolves but serves default provider error page.
3. No associated resource present for the provider (document evidence only).

## Evidence Checklist
1. CNAME record and resolution status.
2. Validation notes and timestamps.
3. Provider error page evidence or resolution logs.
