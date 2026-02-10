# Safe Scanning Patterns

## Goals
1. Run low-impact validation without disrupting services.
2. Keep a clear record of scope and rate limits.
3. Avoid destructive payloads on external targets.

## Safe Checks
1. Use low `-rate` for fuzzers.
2. Limit wordlists to common paths and avoid destructive payloads.
3. Prefer GET/HEAD requests for validation.
4. Back off on 429/503 and record throttling.

## Indicators to Record
1. Rate limits used and concurrency settings.
2. Any throttling or blocking responses.
3. Error rates or timeouts indicating stress.

## Evidence Checklist
1. Tool command lines.
2. Response summaries (status code counts, sample errors).
3. Notes on throttling or block pages.
