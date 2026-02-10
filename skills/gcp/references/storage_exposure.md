# GCP Storage Exposure

## Goals
1. Identify publicly exposed buckets and risky ACLs.
2. Capture encryption and logging posture where visible.
3. Record uniform bucket-level access and retention policies.

## Safe Checks
1. `gcloud storage buckets list --format=json`
2. `gcloud storage buckets describe gs://<bucket> --format=json` (authorized)

## Indicators to Record
1. Buckets accessible by `allUsers` or `allAuthenticatedUsers`.
2. Missing uniform bucket-level access.
3. Logging disabled for sensitive buckets.

## Evidence Checklist
1. Bucket list and locations.
2. Public access settings.
3. Encryption, retention, and logging evidence.
