# GCP Service Account Posture

## Goals
1. Identify service accounts and key management posture.
2. Flag long-lived keys or broad role assignments.
3. Record workload identity or keyless usage where possible.

## Safe Checks
1. `gcloud iam service-accounts list --format=json`
2. `gcloud iam service-accounts keys list` (authorized)

## Indicators to Record
1. User-managed keys without rotation metadata.
2. Service accounts with `roles/owner` or `roles/editor`.
3. Service accounts with keys older than policy thresholds.

## Evidence Checklist
1. Service account count.
2. Key count and rotation notes (if available).
3. Notes on workload identity or keyless usage.
