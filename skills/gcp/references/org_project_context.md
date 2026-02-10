# GCP Organization and Project Context

## Goals
1. Confirm active account and project scope.
2. Record organization or folder context when available.
3. Capture default project and billing context if permitted.

## Safe Checks
1. `gcloud auth list`
2. `gcloud projects list --format=json`
3. `gcloud organizations list` (if authorized)
4. `gcloud config list --format=json`

## Evidence Checklist
1. Active account email.
2. Project count and IDs.
3. Organization ID (if available).
4. Active project and configuration details.
